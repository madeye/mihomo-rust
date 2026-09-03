//! Shared raw HTTP/2 stream plumbing for the h2 transport and sing-h2mux.

use bytes::Bytes;
use http::StatusCode;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const DRIVER_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Accepted response status for a lazily resolved HTTP/2 body.
#[derive(Clone, Copy)]
pub enum StatusPolicy {
    Success,
    Exact(StatusCode),
}

enum RecvInner {
    Pending(h2::client::ResponseFuture),
    Ready(h2::RecvStream),
    Failed,
}

/// Receive half of a client-initiated h2 request, resolved lazily on first
/// read so servers that wait for request DATA cannot deadlock setup.
pub struct RecvState {
    inner: RecvInner,
    timeout: Option<Pin<Box<tokio::time::Sleep>>>,
    status: StatusPolicy,
    label: &'static str,
}

impl RecvState {
    pub fn new(response: h2::client::ResponseFuture) -> Self {
        Self {
            inner: RecvInner::Pending(response),
            timeout: None,
            status: StatusPolicy::Success,
            label: "h2",
        }
    }

    pub fn with_timeout(
        response: h2::client::ResponseFuture,
        timeout: Duration,
        status: StatusPolicy,
        label: &'static str,
    ) -> Self {
        Self {
            inner: RecvInner::Pending(response),
            timeout: Some(Box::pin(tokio::time::sleep(timeout))),
            status,
            label,
        }
    }

    fn accepts(&self, status: StatusCode) -> bool {
        match self.status {
            StatusPolicy::Success => status.is_success(),
            StatusPolicy::Exact(expected) => status == expected,
        }
    }

    /// Drive the response future far enough that [`Self::stream`] returns the
    /// body. Once this resolves `Ready(Ok(()))`, the body is retained.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            RecvInner::Ready(_) => return Poll::Ready(Ok(())),
            RecvInner::Failed => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("{}: response stream already failed", self.label),
                )))
            }
            RecvInner::Pending(future) => match Pin::new(future).poll(cx) {
                Poll::Pending => {}
                Poll::Ready(Ok(response)) => {
                    let status = response.status();
                    if !self.accepts(status) {
                        self.inner = RecvInner::Failed;
                        return Poll::Ready(Err(io::Error::other(format!(
                            "{}: unexpected response status {status}",
                            self.label
                        ))));
                    }
                    self.inner = RecvInner::Ready(response.into_body());
                    self.timeout = None;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => {
                    self.inner = RecvInner::Failed;
                    return Poll::Ready(Err(io::Error::other(error)));
                }
            },
        }

        if let Some(timeout) = &mut self.timeout {
            if timeout.as_mut().poll(cx).is_ready() {
                self.inner = RecvInner::Failed;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{}: response timeout", self.label),
                )));
            }
        }
        Poll::Pending
    }

    pub fn stream(&mut self) -> Option<&mut h2::RecvStream> {
        match &mut self.inner {
            RecvInner::Ready(stream) => Some(stream),
            _ => None,
        }
    }

    async fn drain(mut self) {
        if std::future::poll_fn(|cx| self.poll_ready(cx))
            .await
            .is_err()
        {
            return;
        }
        let Some(stream) = self.stream() else {
            return;
        };
        while let Some(item) = stream.data().await {
            match item {
                Ok(bytes) => {
                    let _ = stream.flow_control().release_capacity(bytes.len());
                }
                Err(_) => return,
            }
        }
    }
}

/// Per-poll cap on the bytes copied into `pending_write`.  Without a cap,
/// a large write under backpressure re-copies the whole shrinking
/// remainder on every `write_all` resubmission (a 1 MiB write through a
/// 64 KiB window costs ~16 allocations / ~8 MiB of memcpy); capping the
/// stash bounds every copy to one window's worth.  64 KiB is chosen to
/// exceed h2's default 65535-byte initial window, so writes that fit the
/// default window keep their single-poll behaviour.
const WRITE_STASH_CAP: usize = 64 * 1024;

/// Raw bidirectional bytes over one HTTP/2 request/response pair.
pub struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: Option<RecvState>,
    read_buf: Bytes,
    /// Payload stashed while a `poll_write` waits for h2 send-window
    /// capacity — at most [`WRITE_STASH_CAP`] bytes, i.e. possibly only a
    /// prefix of the caller's buffer.  Only retained across a
    /// `Poll::Pending` return — every `Ready` return (including a partial
    /// one) clears it, because after `Ready(Ok(n))` the caller may legally
    /// submit a different buffer (issue #423).  Only granted capacity is
    /// ever handed to the connection, so a peer that stops reading applies
    /// real backpressure instead of growing h2's internal buffer.  A
    /// payload still stashed at half-close (the parked write was cancelled)
    /// is flushed together with the closing EOS frame by
    /// [`Self::best_effort_eos`], never discarded; that flush is the one
    /// place bytes reach h2 beyond the granted window, and [`WRITE_STASH_CAP`]
    /// bounds it to a single capped stash.
    pending_write: Option<Bytes>,
    remote_no_error_is_eof: bool,
    eos_sent: bool,
    conn_abort: Option<tokio::task::AbortHandle>,
}

impl H2Stream {
    pub fn new(send: h2::SendStream<Bytes>, recv: RecvState) -> Self {
        Self {
            send,
            recv: Some(recv),
            read_buf: Bytes::new(),
            pending_write: None,
            remote_no_error_is_eof: false,
            eos_sent: false,
            conn_abort: None,
        }
    }

    pub fn with_conn_abort(mut self, handle: tokio::task::AbortHandle) -> Self {
        self.conn_abort = Some(handle);
        self
    }

    pub fn with_remote_no_error_eof(mut self) -> Self {
        self.remote_no_error_is_eof = true;
        self
    }

    fn best_effort_eos(&mut self) {
        if !self.eos_sent {
            self.eos_sent = true;
            // Flush any payload stashed by a write cancelled at its Pending
            // await before half-closing — sending an empty EOS over it would
            // silently truncate the stream (mirrors GunStream::poll_shutdown
            // in grpc.rs).  Only a cancelled write leaves `pending_write`
            // set: the changed-buffer guard clears it before returning
            // `InvalidInput`, so this never resurrects rejected bytes.
            // `send_data` queues beyond the granted flow-control window
            // inside h2, so this stays a single non-blocking best-effort
            // call, bounded to one stashed payload (at most
            // `WRITE_STASH_CAP` bytes).
            let data = self.pending_write.take().unwrap_or_default();
            let _ = self.send.send_data(data, true);
        }
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        self.best_effort_eos();
        let Some(abort_handle) = self.conn_abort.take() else {
            return;
        };
        let recv = self.recv.take();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            abort_handle.abort();
            return;
        };
        runtime.spawn(async move {
            if let Some(recv) = recv {
                let _ = tokio::time::timeout(DRIVER_DRAIN_TIMEOUT, recv.drain()).await;
            } else {
                tokio::task::yield_now().await;
            }
            abort_handle.abort();
        });
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // A zero-capacity buffer yields Ready(Ok(())) per the tokio
        // AsyncRead docs (a Pending here would leave `read(&mut [])`
        // parked forever).
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !this.read_buf.is_empty() {
                let count = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf[..count]);
                let _ = this.read_buf.split_to(count);
                return Poll::Ready(Ok(()));
            }
            let recv = this.recv.as_mut().expect("receive state present");
            match recv.poll_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            let recv = recv.stream().expect("poll_ready resolved Ok");
            match recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(error))) => {
                    if this.remote_no_error_is_eof
                        && error.is_reset()
                        && error.is_remote()
                        && error.reason() == Some(h2::Reason::NO_ERROR)
                    {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                Poll::Ready(Some(Ok(bytes))) => {
                    let _ = recv.flow_control().release_capacity(bytes.len());
                    this.read_buf = bytes;
                }
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        // Stash the payload exactly once per parked write.  If
        // pending_write is set, the previous poll returned Pending and
        // capacity has been reserved — do not copy or reserve again.
        // A Pending poll must be retried with the same buffer; reject a
        // changed buffer rather than silently sending stale bytes under
        // its reported length.  The stash may be a capped prefix of the
        // caller's buffer, so compare it against the new buffer's prefix
        // of the stash's length.  This guard applies to the Pending path
        // only: pending_write never survives a Ready return, so after a
        // partial `Ready(Ok(n))` the caller is free to submit anything
        // (issue #423).
        if let Some(data) = &this.pending_write {
            if buf.len() < data.len() || &buf[..data.len()] != data.as_ref() {
                // Hand the stale stash's reservation back to the
                // connection along with the stash itself: this error
                // taints the stream, so nothing will ever send those
                // bytes, and leaving the reservation requested would pin
                // window capacity on the connection for good.
                this.send.reserve_capacity(0);
                this.pending_write = None;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "h2: write buffer changed after Pending; \
                     AsyncWrite requires retrying with the same buffer",
                )));
            }
        } else {
            // Stash (and therefore accept) at most WRITE_STASH_CAP bytes
            // per poll so `write_all`-style resubmissions of a large
            // buffer copy bounded chunks instead of the whole remainder.
            let stash_len = buf.len().min(WRITE_STASH_CAP);
            let data = Bytes::copy_from_slice(&buf[..stash_len]);
            this.send.reserve_capacity(data.len());
            this.pending_write = Some(data);
        }
        match this.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2: send stream closed",
                )))
            }
            Poll::Ready(Some(Err(error))) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::other(error)))
            }
            Poll::Ready(Some(Ok(capacity))) => {
                let data = this.pending_write.take().expect("set above");
                // poll_capacity may grant less than the reserved amount
                // (the peer's flow-control window); send only the
                // granted prefix and report a short write.
                let allowed = capacity.min(data.len());
                if allowed == 0 {
                    // Unreachable: poll_capacity yields Some(Ok(n)) with
                    // n > 0, and pending_write is never stashed empty.
                    // Re-stash and re-register the waker defensively so a
                    // future code change cannot park this task forever.
                    debug_assert!(allowed > 0, "h2: zero capacity grant with pending data");
                    this.pending_write = Some(data);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let chunk = data.slice(..allowed);
                if let Err(error) = this.send.send_data(chunk, false) {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                if allowed < data.len() {
                    // Short write: the unsent remainder is dropped (the
                    // caller re-submits it — or a different buffer — on
                    // the next write), so hand its reservation back to
                    // the connection instead of pinning window capacity
                    // for bytes that may never arrive.  reserve_capacity
                    // sets a target on top of already-buffered data, so 0
                    // keeps what send_data just queued.
                    this.send.reserve_capacity(0);
                }
                Poll::Ready(Ok(allowed))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().best_effort_eos();
        Poll::Ready(Ok(()))
    }
}

impl Unpin for H2Stream {}

/// Stalled-h2-server harness shared with the `h2_test` integration suite
/// (single source in `tests/support/h2_stalled.rs`, see its module docs).
#[cfg(test)]
#[path = "../tests/support/h2_stalled.rs"]
mod h2_stalled;

#[cfg(test)]
mod tests {
    use super::h2_stalled::{stalled_h2_parts, STALLED_PAYLOAD_LEN};
    use super::*;
    use std::future::poll_fn;
    use tokio::io::AsyncWriteExt as _;

    async fn stalled_h2_stream() -> (H2Stream, tokio::task::JoinHandle<()>) {
        let (send_stream, response, server) = stalled_h2_parts().await;
        (H2Stream::new(send_stream, RecvState::new(response)), server)
    }

    /// Poll `poll_write` exactly once, surfacing `Pending` as `None` instead
    /// of parking the test.
    async fn poll_write_once(stream: &mut H2Stream, buf: &[u8]) -> Option<io::Result<usize>> {
        poll_fn(|cx| {
            Poll::Ready(match Pin::new(&mut *stream).poll_write(cx, buf) {
                Poll::Pending => None,
                Poll::Ready(result) => Some(result),
            })
        })
        .await
    }

    /// Issue #423: `pending_write` must not survive a partial
    /// `Ready(Ok(n))`.  After a short write the caller may legally submit a
    /// *different* buffer; the changed-buffer guard applies only to retries
    /// after `Pending`.
    #[tokio::test]
    async fn partial_write_then_different_buffer_is_accepted() {
        let (mut stream, _server) = stalled_h2_stream().await;
        let payload = vec![b'a'; STALLED_PAYLOAD_LEN];

        // Drive the first logical write to its first Ready(Ok(n)).  The send
        // window (at most 64 KiB) cannot cover the payload, so the write is
        // necessarily partial.  Deadline-bounded so a regression that never
        // yields Ready fails with a diagnostic instead of hanging CI.
        let sent = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match poll_write_once(&mut stream, &payload).await {
                    // Capacity not assigned yet — let the connection task run.
                    None => tokio::task::yield_now().await,
                    Some(Ok(n)) => break n,
                    Some(Err(error)) => panic!("unexpected write error: {error}"),
                }
            }
        })
        .await
        .expect("first write must reach Ready(Ok(n)) once capacity is assigned");
        assert!(sent < payload.len(), "expected a partial write");

        // Submit a buffer with different contents.  Before the fix this
        // tripped the identity guard and failed with InvalidInput; it must
        // be treated as a fresh logical write.
        let decoy = vec![b'b'; 64 * 1024];
        loop {
            match poll_write_once(&mut stream, &decoy).await {
                // Parked on flow control — expected once the window is gone.
                None => break,
                Some(Ok(n)) => {
                    assert!(n > 0, "poll_write must not return Ok(0) for data");
                }
                Some(Err(error)) => {
                    panic!("a different buffer after a partial write must be accepted: {error}")
                }
            }
        }
    }

    /// The stash is capped at [`WRITE_STASH_CAP`], so a parked large write
    /// retried with the same *full* remainder (longer than the stash) must
    /// keep parking: the changed-buffer guard compares the stash against
    /// the retry buffer's prefix of the stash's length, not the whole
    /// buffer.  Before the cap the two were always the same length, so an
    /// exact comparison sufficed; with the cap an exact comparison would
    /// falsely reject every `write_all` resubmission of a > 64 KiB buffer.
    #[tokio::test]
    async fn capped_stash_accepts_same_full_buffer_retry() {
        let (mut stream, _server) = stalled_h2_stream().await;
        let payload = vec![b'a'; STALLED_PAYLOAD_LEN];

        // Exhaust the send window (at most 65535 bytes accepted), leaving a
        // remainder strictly longer than WRITE_STASH_CAP parked in
        // pending_write as a capped prefix.  A poll is treated as parked
        // only after several consecutive Pendings with yields in between,
        // so a capacity grant split across connection-task runs cannot
        // race the assertions below.
        let sent = tokio::time::timeout(Duration::from_secs(5), async {
            let mut sent = 0usize;
            let mut idle_polls = 0usize;
            loop {
                match poll_write_once(&mut stream, &payload[sent..]).await {
                    None => {
                        idle_polls += 1;
                        if sent > 0 && idle_polls >= 3 {
                            break sent;
                        }
                        tokio::task::yield_now().await;
                    }
                    Some(Ok(n)) => {
                        sent += n;
                        idle_polls = 0;
                    }
                    Some(Err(error)) => panic!("unexpected write error: {error}"),
                }
            }
        })
        .await
        .expect("the stalled window must park the write, not spin forever");
        let remainder = &payload[sent..];
        assert!(
            remainder.len() > WRITE_STASH_CAP,
            "setup: the parked remainder must exceed the stash cap"
        );

        // Contract-abiding retry with the same (uncapped) remainder: must
        // stay Pending, never trip the changed-buffer guard.
        for _ in 0..3 {
            let polled = poll_write_once(&mut stream, remainder).await;
            assert!(
                polled.is_none(),
                "same-buffer retry of a capped stash must stay Pending, got {polled:?}"
            );
        }
    }

    /// A large write against a peer with plenty of window is accepted in
    /// at most [`WRITE_STASH_CAP`]-byte chunks per poll, so `write_all`
    /// resubmissions copy bounded chunks instead of re-copying the whole
    /// shrinking remainder each time.
    #[tokio::test]
    async fn large_write_accepts_at_most_stash_cap_per_poll() {
        const PAYLOAD_LEN: usize = 1024 * 1024;

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        // Server with windows large enough to cover the whole payload, so
        // only the stash cap can bound a single accept.  It drains the
        // request body while keeping the connection driven.
        let server = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .initial_window_size(2 * 1024 * 1024)
                .initial_connection_window_size(2 * 1024 * 1024)
                .handshake::<_, Bytes>(server_io)
                .await
                .expect("server handshake");
            let (request, respond) = connection
                .accept()
                .await
                .expect("one request")
                .expect("accept ok");
            let mut body = request.into_body();
            let drain = async {
                let mut total = 0usize;
                while let Some(data) = body.data().await {
                    let bytes = data.expect("body data");
                    total += bytes.len();
                    let _ = body.flow_control().release_capacity(bytes.len());
                }
                total
            };
            let drive = async {
                while connection.accept().await.is_some() {}
                std::future::pending::<()>().await;
            };
            let total = tokio::select! {
                total = drain => total,
                () = drive => unreachable!("drive never resolves"),
            };
            assert_eq!(total, PAYLOAD_LEN, "server must receive every byte");
            drop(respond); // kept alive until here so the stream is not reset
        });

        let (send_request, connection) = h2::client::handshake(client_io)
            .await
            .expect("client handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost")
            .body(())
            .expect("static request");
        let mut send_request = send_request.ready().await.expect("send_request ready");
        let (response, send_stream) = send_request
            .send_request(request, false)
            .expect("send_request");
        let mut stream = H2Stream::new(send_stream, RecvState::new(response));

        let payload = vec![b'z'; PAYLOAD_LEN];
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut sent = 0usize;
            while sent < payload.len() {
                match poll_write_once(&mut stream, &payload[sent..]).await {
                    None => tokio::task::yield_now().await,
                    Some(Ok(n)) => {
                        assert!(
                            n <= WRITE_STASH_CAP,
                            "a single poll accepted {n} bytes, more than the stash cap"
                        );
                        sent += n;
                    }
                    Some(Err(error)) => panic!("unexpected write error: {error}"),
                }
            }
        })
        .await
        .expect("the whole payload must be accepted against an open window");

        // Half-close so the server's body drain sees end-of-stream.
        poll_fn(|cx| Pin::new(&mut stream).poll_shutdown(cx))
            .await
            .expect("shutdown");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server must finish draining")
            .expect("server task");
    }

    /// Open one client stream against a server that accepts the request,
    /// responds 200, and then *hoards* request-body flow-control capacity:
    /// it consumes DATA frames without releasing the receive window until
    /// the returned release sender fires, after which it drains the body to
    /// end-of-stream and hands the collected bytes back through the returned
    /// receiver.  Keeping the window shut parks `poll_write` in the
    /// `Pending` + stashed-payload state.
    async fn hoarding_h2_stream() -> (
        H2Stream,
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<Vec<u8>>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let (release_tx, mut release_rx) = tokio::sync::oneshot::channel::<()>();
        let (body_tx, body_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

        tokio::spawn(async move {
            let Ok(mut conn) = h2::server::handshake(server_io).await else {
                return;
            };
            let Some(Ok((request, mut respond))) = conn.accept().await else {
                return;
            };
            // Drive connection-level frames in the background.
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let _ = respond.send_response(http::Response::new(()), false);

            let mut body = request.into_body();
            let mut received = Vec::new();
            // Hoard: consume DATA but never release capacity, so the
            // client's send window (65535 initial) empties and stays empty.
            loop {
                tokio::select! {
                    chunk = body.data() => match chunk {
                        Some(Ok(chunk)) => received.extend_from_slice(&chunk),
                        Some(Err(_)) => return, // reset — client went away
                        None => {
                            let _ = body_tx.send(received);
                            return;
                        }
                    },
                    _ = &mut release_rx => break,
                }
            }
            // Reopen the window, then drain to end-of-stream.
            let _ = body.flow_control().release_capacity(received.len());
            loop {
                match body.data().await {
                    Some(Ok(chunk)) => {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        received.extend_from_slice(&chunk);
                    }
                    Some(Err(_)) => return,
                    None => {
                        let _ = body_tx.send(received);
                        return;
                    }
                }
            }
        });

        let (send_request, connection) = h2::client::handshake(client_io)
            .await
            .expect("client handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost")
            .body(())
            .expect("static request");
        let mut send_request = send_request.ready().await.expect("send_request ready");
        let (response, send_stream) = send_request
            .send_request(request, false)
            .expect("send_request");

        (
            H2Stream::new(send_stream, RecvState::new(response)),
            release_tx,
            body_rx,
        )
    }

    /// Drive writes against `stream` until exactly `payload.len()` bytes have
    /// been accepted (the h2 window may grant capacity piecemeal).
    async fn write_all_yielding(stream: &mut H2Stream, payload: &[u8]) {
        let mut sent = 0;
        while sent < payload.len() {
            match poll_write_once(stream, &payload[sent..]).await {
                // Capacity not assigned yet — let the connection task run.
                None => tokio::task::yield_now().await,
                Some(Ok(n)) => sent += n,
                Some(Err(error)) => panic!("window-filling write failed: {error}"),
            }
        }
    }

    /// `poll_shutdown` must flush a payload stashed by a cancelled write
    /// together with the closing EOS frame instead of silently discarding it
    /// behind an empty DATA+EOS (follow-up to the #440 review; mirrors
    /// `grpc_shutdown_flushes_stashed_frame_before_eos` for GunStream).
    #[tokio::test]
    async fn shutdown_flushes_stashed_pending_write() {
        let (mut stream, release_tx, body_rx) = hoarding_h2_stream().await;

        // Exhaust the 65535-byte initial send window…
        let fill = vec![b'a'; 65535];
        write_all_yielding(&mut stream, &fill).await;

        // …so this write parks on flow control with its payload stashed.
        let tail = b"tail-after-cancelled-write";
        assert!(
            poll_write_once(&mut stream, tail).await.is_none(),
            "tail write must park on flow control"
        );
        assert!(stream.pending_write.is_some(), "payload must be stashed");

        // The parked write is never retried (cancellation); shutdown must
        // flush the stashed payload, not drop it.
        stream.shutdown().await.expect("shutdown");
        assert!(
            stream.pending_write.is_none(),
            "shutdown must consume the stashed payload"
        );

        release_tx.send(()).expect("server task alive");
        let received = tokio::time::timeout(Duration::from_secs(5), body_rx)
            .await
            .expect("server must observe end-of-stream")
            .expect("server sent collected body");

        let mut expected = fill;
        expected.extend_from_slice(tail);
        assert_eq!(
            received, expected,
            "stashed payload must be delivered before EOS"
        );
    }

    /// Companion: a payload cleared by the changed-buffer `InvalidInput`
    /// rejection must NOT be resurrected by a later shutdown — only a frame
    /// stashed by a cancelled write gets flushed.
    #[tokio::test]
    async fn shutdown_after_rejected_buffer_does_not_resurrect_payload() {
        let (mut stream, release_tx, body_rx) = hoarding_h2_stream().await;

        let fill = vec![b'a'; 65535];
        write_all_yielding(&mut stream, &fill).await;

        assert!(
            poll_write_once(&mut stream, b"stashed-then-rejected")
                .await
                .is_none(),
            "write must park on flow control"
        );

        // Retrying with a different buffer trips the guard and clears the
        // stash.
        let error = match poll_write_once(&mut stream, b"different-buffer").await {
            Some(Err(error)) => error,
            other => panic!("changed buffer after Pending must be rejected, got {other:?}"),
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        stream.shutdown().await.expect("shutdown");
        release_tx.send(()).expect("server task alive");
        let received = tokio::time::timeout(Duration::from_secs(5), body_rx)
            .await
            .expect("server must observe end-of-stream")
            .expect("server sent collected body");
        assert_eq!(
            received, fill,
            "a payload cleared by the changed-buffer rejection must not reappear at shutdown"
        );
    }

    /// Dropping an `H2Stream` half-closes the request body with a clean
    /// `end_of_stream` DATA frame instead of resetting the stream, so bytes
    /// already accepted by the peer are not torn down retroactively.  This
    /// pins the behaviour for both the plain `network: h2` transport and
    /// h2mux, which share this type (issue #423, follow-up to #417).
    #[tokio::test]
    async fn drop_sends_end_of_stream_not_reset() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .handshake::<_, Bytes>(server_io)
                .await
                .expect("server handshake");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("one request")
                .expect("accept ok");
            let mut body = request.into_body();
            respond
                .send_response(http::Response::new(()), true)
                .expect("send response");

            // Read the request body to completion while a second future
            // keeps the connection driven (RecvStream does not drive IO).
            let read_body = async {
                let mut received = Vec::new();
                loop {
                    match body.data().await {
                        Some(Ok(bytes)) => {
                            let _ = body.flow_control().release_capacity(bytes.len());
                            received.extend_from_slice(&bytes);
                        }
                        Some(Err(error)) => return Err(error),
                        None => return Ok(received),
                    }
                }
            };
            let drive = async {
                while connection.accept().await.is_some() {}
                std::future::pending::<()>().await;
            };
            tokio::select! {
                body_result = read_body => {
                    let received = body_result.expect("drop must end the stream cleanly, not reset it");
                    assert_eq!(received, b"hello", "bytes written before drop must survive");
                }
                () = drive => unreachable!("drive never resolves"),
            }
        });

        let (send_request, connection) = h2::client::handshake(client_io)
            .await
            .expect("client handshake");
        let driver_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let abort_handle = driver_task.abort_handle();
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost")
            .body(())
            .expect("static request");
        let mut send_request = send_request.ready().await.expect("send_request ready");
        let (response, send_stream) = send_request
            .send_request(request, false)
            .expect("send_request");
        let mut stream =
            H2Stream::new(send_stream, RecvState::new(response)).with_conn_abort(abort_handle);

        stream.write_all(b"hello").await.expect("write");
        drop(stream);

        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server must observe end-of-stream")
            .expect("server task");
        let driver_error = tokio::time::timeout(Duration::from_secs(5), driver_task)
            .await
            .expect("driver must be aborted after response drain")
            .expect_err("driver task must end by abort");
        assert!(driver_error.is_cancelled());
    }
}
