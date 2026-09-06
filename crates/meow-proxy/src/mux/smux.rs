//! smux protocol (sagernet/smux fork wire format — protocol version 1),
//! client side.
//!
//! This is NOT the upstream xtaci layout: sing-mux/sing-box use the
//! sagernet fork whose frames are: ver=1, cmd, len u16 LE, stream_id u32 LE, data
//! (8-byte header, little-endian) and whose version 1 has no window-update
//! (UPD) flow control — a v1 write just splits into MaxFrameSize frames.
//! Commands: SYN=0, FIN=1, PSH=2, NOP=3; client stream IDs are odd
//! (1, 3, 5, ...).  Matches sing-mux's smux usage (DefaultConfig +
//! KeepAliveDisabled): Version=1, MaxFrameSize=32768, MaxStreamBuffer=64 KiB,
//! MaxReceiveBuffer=4 MiB.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::{CancellationToken, PollSender};

const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const SMUX_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 8;

/// Largest frame payload — sagernet smux MaxFrameSize default (u16 length).
const MAX_FRAME_SIZE: usize = 32768;
/// Per-stream channel depth.  The 4 MiB `receive_budget` semaphore bounds
/// memory; the channel depth only controls how many frames buffer before a
/// stalled consumer parks delivery and pauses the connection read —
/// session-wide flow control with TCP window semantics, matching muxcool's
/// `deliver_now` / `Parked` pattern (issue #425): the reader never blocks
/// on a stream queue, so a consumer stalled mid-write cannot deadlock
/// writers sharing the session.  Consumers wake the reader (the `space`
/// Notify) whenever they drain a queue or drop a stream.
const STREAM_QUEUE: usize = 32;
/// Sagernet's default session-wide receive budget.
const MAX_RECEIVE_BUFFER: usize = 4 * 1024 * 1024;
/// Bounded outbound queue; stream writes wait when the physical writer lags.
const OUTBOUND_QUEUE: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    cmd: u8,
    stream_id: u32,
    data: Bytes,
}

impl Frame {
    #[cfg(test)]
    fn encode(&self) -> Bytes {
        encode_frame(self.cmd, self.stream_id, &self.data)
    }

    fn decode_header(buf: &[u8]) -> io::Result<(u8, usize, u32)> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "smux frame header too short",
            ));
        }
        if buf[0] != SMUX_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported smux version: {}", buf[0]),
            ));
        }
        let cmd = buf[1];
        let length = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        let stream_id = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Ok((cmd, length, stream_id))
    }
}

fn encode_frame(cmd: u8, stream_id: u32, data: &[u8]) -> Bytes {
    // The u16 length field caps single frames; poll_write limits writes to
    // MAX_FRAME_SIZE, so this only guards future call sites.
    debug_assert!(
        data.len() <= u16::MAX as usize,
        "smux frame payload exceeds u16 length"
    );
    let mut out = BytesMut::with_capacity(FRAME_HEADER_LEN + data.len());
    out.put_u8(SMUX_VERSION);
    out.put_u8(cmd);
    out.put_u16_le(data.len() as u16);
    out.put_u32_le(stream_id);
    out.put_slice(data);
    out.freeze()
}

struct InboundChunk {
    data: Bytes,
    /// Releases session receive capacity when the stream consumes or drops
    /// this chunk.
    _permit: Option<OwnedSemaphorePermit>,
}

/// One inbound chunk parked because its stream's queue is full.  At most
/// one exists at a time: parking pauses the connection read (session-wide
/// flow control, TCP window semantics), so no further frames pile up.  The
/// reader retries without blocking — it never blocks on a stream queue, so
/// a consumer stalled mid-write cannot deadlock writers sharing the
/// session.
struct Parked {
    tx: mpsc::Sender<InboundChunk>,
    chunk: InboundChunk,
}

/// Try to hand one chunk to a stream without blocking: on a full queue the
/// chunk parks, on a closed channel (stream gone) it is moot.
fn deliver_now(tx: Option<mpsc::Sender<InboundChunk>>, chunk: InboundChunk) -> Option<Parked> {
    let tx = tx?;
    match tx.try_send(chunk) {
        Err(mpsc::error::TrySendError::Full(chunk)) => Some(Parked { tx, chunk }),
        Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => None,
    }
}

/// Retry a parked delivery: succeeds the moment the consumer drained its
/// queue, or the channel closed because the consumer dropped the stream.
fn retry_parked(parked: &mut Option<Parked>) {
    if let Some(mut p) = parked.take() {
        match p.tx.try_send(p.chunk) {
            Err(mpsc::error::TrySendError::Full(chunk)) => {
                p.chunk = chunk;
                *parked = Some(p);
            }
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

/// Fires the session's space Notify when dropped: wakes a reader parked on
/// the full inbound queue once the stream (and its receiver) is gone, so
/// the parked delivery fails fast and reading resumes.  Kept as a field
/// declared after the receiver so the channel closes before the notify
/// fires.
struct SpaceWake(Arc<Notify>);

impl Drop for SpaceWake {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

/// One outbound writer request.  Flush requests travel the SAME bounded
/// channel as data frames so a flush can never overtake frames the
/// requesting stream queued earlier (FIFO guarantee).  `Clone` keeps
/// `PollSender<OutMsg>` usable (its item type must be `Clone`).
#[derive(Clone)]
enum OutMsg {
    Frame(Bytes),
    /// Acknowledge after the physical transport's buffered data reached
    /// the wire.  `Arc` keeps the item `Clone` for `PollSender`.
    Flush(Arc<oneshot::Sender<()>>),
}

struct SessionState {
    /// Streams keyed by stream ID; dropping the sender EOFs the stream.
    streams: Mutex<HashMap<u32, mpsc::Sender<InboundChunk>>>,
    dead: AtomicBool,
    /// Fired by stream consumers whenever they drain their inbound queue
    /// (or drop the stream): wakes a reader parked on a full queue.
    /// notify_one keeps a permit for the arm-before-check pattern in the
    /// reader loop, so no wake is lost.
    space: Arc<Notify>,
}

/// smux session over one physical connection (client role).
pub struct Session {
    state: Arc<SessionState>,
    writer_tx: mpsc::Sender<OutMsg>,
    cancel: CancellationToken,
    next_stream_id: AtomicU32,
}

impl Session {
    /// True once the session is dead (reader/writer task ended or the
    /// physical connection failed).
    pub fn is_dead(&self) -> bool {
        self.state.dead.load(Ordering::SeqCst)
    }

    /// Start an smux client session over the IO.  A reader task owns the
    /// read half; a writer task serialises outbound frames.
    pub fn client<S>(io: S) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(io);
        let (writer_tx, mut writer_rx) = mpsc::channel::<OutMsg>(OUTBOUND_QUEUE);
        let state = Arc::new(SessionState {
            streams: Mutex::new(HashMap::new()),
            dead: AtomicBool::new(false),
            space: Arc::new(Notify::new()),
        });
        let receive_budget = Arc::new(Semaphore::new(MAX_RECEIVE_BUFFER));
        let cancel = CancellationToken::new();

        // Writer task: outbound frames are already encoded, so the hot path
        // performs no second allocation or payload copy.
        let writer_state = Arc::clone(&state);
        let writer_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                let msg = tokio::select! {
                    _ = writer_cancel.cancelled() => break,
                    msg = writer_rx.recv() => match msg {
                        Some(msg) => msg,
                        None => break,
                    },
                };
                match msg {
                    OutMsg::Frame(frame) => {
                        let result = tokio::select! {
                            _ = writer_cancel.cancelled() => break,
                            result = writer.write_all(&frame) => result,
                        };
                        if result.is_err() {
                            break;
                        }
                    }
                    OutMsg::Flush(ack) => {
                        // FIFO: every frame queued before this request
                        // was received first (same channel) and is
                        // already written — flush the transport now.
                        // Cancellation must break out even of a stalled
                        // flush, otherwise a dropped session could keep
                        // the writer task (and the socket) alive.
                        let result = tokio::select! {
                            _ = writer_cancel.cancelled() => break,
                            result = writer.flush() => result,
                        };
                        if result.is_err() {
                            break;
                        }
                        // The channel delivered the sole Arc reference;
                        // unwrap and ack.  A stray clone would still
                        // resolve the receiver (with an error) when
                        // this one drops, never hanging the stream.
                        let _ = Arc::try_unwrap(ack).map(|sender| sender.send(()));
                    }
                }
            }
            writer_state.mark_dead().await;
            writer_cancel.cancel();
        });

        // Reader task: parse frames, route PSH/FIN to streams.  Inbound
        // delivery never blocks the reader: a frame that hits a full
        // stream queue parks (at most one) and pauses the connection read
        // — session-wide flow control with TCP window semantics — while
        // the writer task keeps servicing outbound frames.
        let reader_state = Arc::clone(&state);
        let reader_cancel = cancel.clone();
        let reader_space = Arc::clone(&state.space);
        tokio::spawn(async move {
            let mut header = [0u8; FRAME_HEADER_LEN];
            let mut parked: Option<Parked> = None;
            'reader: loop {
                while parked.is_some() {
                    // Armed before the retry so a drain in the gap between
                    // them is not lost: notify_one stores a permit when no
                    // waiter is registered yet, and this future consumes it.
                    let space_fut = reader_space.notified();
                    retry_parked(&mut parked);
                    if parked.is_some() {
                        tokio::select! {
                            _ = reader_cancel.cancelled() => break 'reader,
                            _ = space_fut => {}
                        }
                    }
                }
                let header_result = tokio::select! {
                    _ = reader_cancel.cancelled() => break 'reader,
                    result = reader.read_exact(&mut header) => result,
                };
                if header_result.is_err() {
                    break 'reader;
                }
                let Ok((cmd, length, stream_id)) = Frame::decode_header(&header) else {
                    break 'reader;
                };
                let permit = if cmd == CMD_PSH && length > 0 {
                    let permits = length as u32;
                    match tokio::select! {
                        _ = reader_cancel.cancelled() => break 'reader,
                        result = Arc::clone(&receive_budget).acquire_many_owned(permits) => result,
                    } {
                        Ok(permit) => Some(permit),
                        Err(_) => break 'reader,
                    }
                } else {
                    None
                };
                let mut payload = vec![0u8; length];
                if !payload.is_empty() {
                    let payload_result = tokio::select! {
                        _ = reader_cancel.cancelled() => break 'reader,
                        result = reader.read_exact(&mut payload) => result,
                    };
                    if payload_result.is_err() {
                        break 'reader;
                    }
                }
                match reader_state
                    .handle_frame(
                        cmd,
                        stream_id,
                        InboundChunk {
                            data: Bytes::from(payload),
                            _permit: permit,
                        },
                    )
                    .await
                {
                    Ok(Some(p)) => parked = Some(p),
                    Ok(None) => {}
                    Err(_) => break 'reader,
                }
            }
            reader_state.mark_dead().await;
            reader_cancel.cancel();
        });

        Ok(Self {
            state,
            writer_tx,
            cancel,
            next_stream_id: AtomicU32::new(1),
        })
    }

    /// Open a new stream.  Client IDs count up by 2 from 1.
    pub async fn open_stream(self: &Arc<Self>) -> io::Result<SmuxStream> {
        if self.is_dead() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux session is closed",
            ));
        }
        let id = self.next_stream_id.fetch_add(2, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        self.state.streams.lock().await.insert(id, tx);
        // The guard removes the map entry if this future is cancelled
        // while waiting for outbound capacity — otherwise the id stays
        // consumed and the entry lingers until a server FIN.
        let mut guard = MapEntryGuard {
            state: Arc::clone(&self.state),
            id,
            armed: true,
        };
        if self
            .writer_tx
            .send(OutMsg::Frame(encode_frame(CMD_SYN, id, &[])))
            .await
            .is_err()
        {
            drop(guard);
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux writer gone",
            ));
        }
        guard.disarm();
        Ok(SmuxStream {
            id,
            session: Arc::clone(self),
            poll_sender: PollSender::new(self.writer_tx.clone()),
            rx,
            pending: None,
            eof: false,
            fin_sent: false,
            shutdown_frame: None,
            flush_rx: None,
            write_since_flush: false,
            wake: SpaceWake(Arc::clone(&self.state.space)),
        })
    }
}

/// Removes a stream-map entry when dropped while armed — the
/// cancellation-safe counterpart of `open_stream`'s insert-then-send.
struct MapEntryGuard {
    state: Arc<SessionState>,
    id: u32,
    armed: bool,
}

impl MapEntryGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for MapEntryGuard {
    fn drop(&mut self) {
        if self.armed {
            let state = Arc::clone(&self.state);
            let id = self.id;
            // Detached: drop cannot await the map lock.
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    state.streams.lock().await.remove(&id);
                });
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.state.dead.store(true, Ordering::SeqCst);
        self.cancel.cancel();
    }
}

impl SessionState {
    async fn mark_dead(&self) {
        if !self.dead.swap(true, Ordering::SeqCst) {
            // Close every stream.  The read side distinguishes this physical
            // failure from a peer FIN by consulting `Session::is_dead`.
            self.streams.lock().await.clear();
        }
    }

    async fn handle_frame(
        &self,
        cmd: u8,
        stream_id: u32,
        chunk: InboundChunk,
    ) -> io::Result<Option<Parked>> {
        match cmd {
            CMD_PSH => {
                // Data for an unknown stream is dropped rather than killing
                // the session — an intentional divergence from xtaci (which
                // closes the connection on protocol violation): the server
                // may legitimately race a FIN (peer closed, stream removed)
                // against in-flight PSH frames.
                let tx = self.streams.lock().await.get(&stream_id).cloned();
                Ok(deliver_now(tx, chunk))
            }
            CMD_FIN => {
                // Peer half-closed: EOF the read side by dropping the sender.
                self.streams.lock().await.remove(&stream_id);
                Ok(None)
            }
            CMD_NOP => Ok(None),
            // v1 has no UPD; a server-initiated SYN is unexpected in
            // client-only usage and unsupported commands are protocol errors.
            CMD_SYN => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "smux: unexpected SYN from server (client-only usage)",
            )),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("smux: unknown command {other}"),
            )),
        }
    }
}

/// One multiplexed stream (AsyncRead + AsyncWrite).
pub struct SmuxStream {
    id: u32,
    session: Arc<Session>,
    poll_sender: PollSender<OutMsg>,
    rx: mpsc::Receiver<InboundChunk>,
    /// Unread remainder of the last chunk handed to poll_read.
    pending: Option<InboundChunk>,
    eof: bool,
    fin_sent: bool,
    shutdown_frame: Option<Bytes>,
    /// Pending flush acknowledgement; see `poll_flush`.
    flush_rx: Option<oneshot::Receiver<()>>,
    /// Set when a data frame is queued after the current flush request was
    /// sent: the flush ack then no longer covers every write, so
    /// `poll_flush` must send another request once the pending one lands.
    write_since_flush: bool,
    /// Acts through Drop (wakes a reader parked on the full inbound queue
    /// once the receiver is gone); never read.
    #[allow(dead_code, reason = "SpaceWake acts through Drop, not reads")]
    wake: SpaceWake,
}

impl SmuxStream {
    fn best_effort_fin(&mut self) {
        if self.fin_sent {
            return;
        }
        let frame = encode_frame(CMD_FIN, self.id, &[]);
        match self
            .session
            .writer_tx
            .try_send(OutMsg::Frame(frame.clone()))
        {
            Ok(()) => self.fin_sent = true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // The outbound channel is full: queue the FIN
                // asynchronously instead of dropping it.  Mark fin_sent
                // now so a later poll_shutdown/drop does not double-send.
                self.fin_sent = true;
                let sender = self.session.writer_tx.clone();
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(async move {
                        let _ = sender.send(OutMsg::Frame(frame)).await;
                    });
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                // Session is gone; the connection is closing anyway.
                self.fin_sent = true;
            }
        }
    }
}

impl Drop for SmuxStream {
    fn drop(&mut self) {
        self.best_effort_fin();
        // Remove the stream-map entry explicitly.  smux servers (notably
        // sing-box) may not echo a FIN for a stream the client abandoned,
        // so waiting for CMD_FIN would leak the entry for the session's
        // lifetime.  The detached spawn mirrors MapEntryGuard's pattern:
        // cleanup must not wait on outbound channel capacity.
        let state = Arc::clone(&self.session.state);
        let id = self.id;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                state.streams.lock().await.remove(&id);
            });
        }
    }
}

impl AsyncRead for SmuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Every progress path returns Ready immediately: returning Pending
        // after writing into the caller's ReadBuf would lose those bytes
        // (the buffer is recreated on the next poll), violating the
        // AsyncRead contract.  A zero-capacity buffer yields Ready(Ok(()))
        // per the tokio AsyncRead docs (a Pending here would leave
        // `read(&mut [])` parked forever).
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(mut chunk) = this.pending.take() {
            let n = chunk.data.len().min(buf.remaining());
            buf.put_slice(&chunk.data[..n]);
            chunk.data.advance(n);
            if !chunk.data.is_empty() {
                this.pending = Some(chunk);
            }
            Poll::Ready(Ok(()))
        } else if this.eof {
            Poll::Ready(Ok(()))
        } else {
            loop {
                match this.rx.poll_recv(cx) {
                    Poll::Ready(Some(mut chunk)) => {
                        // The channel slot just freed: wake a reader parked
                        // on this stream's full queue (notify_one keeps a
                        // permit when no waiter is registered yet, so the
                        // wake is never lost).
                        this.session.state.space.notify_one();
                        if chunk.data.is_empty() {
                            // Zero-length PSH frames carry no payload (flush /
                            // ack signals from the peer); returning Ready with
                            // an empty ReadBuf would read as EOF to consumers.
                            continue;
                        }
                        let n = chunk.data.len().min(buf.remaining());
                        buf.put_slice(&chunk.data[..n]);
                        chunk.data.advance(n);
                        if !chunk.data.is_empty() {
                            this.pending = Some(chunk);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(None) => {
                        // The channel closed (peer FIN or session death):
                        // wake so a parked delivery observes the closed
                        // channel instead of waiting for a drain that will
                        // never come.
                        this.session.state.space.notify_one();
                        this.eof = true;
                        if this.session.is_dead() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "smux session closed",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.session.is_dead() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux session closed",
            )));
        }
        let written = buf.len().min(MAX_FRAME_SIZE);
        match this.poll_sender.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error.to_string()))),
            Poll::Ready(Ok(())) => {
                let frame = encode_frame(CMD_PSH, this.id, &buf[..written]);
                this.poll_sender
                    .send_item(OutMsg::Frame(frame))
                    .map_err(|error| io::Error::other(error.to_string()))?;
                this.write_since_flush = true;
                Poll::Ready(Ok(written))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // A flush request travels the writer channel behind every frame
        // this stream queued earlier, so the acknowledgement means those
        // bytes reached the physical transport (matters for buffered
        // outer transports like WebSocket).
        if let Some(rx) = &mut this.flush_rx {
            match Pin::new(rx).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    this.flush_rx = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "smux writer gone",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    this.flush_rx = None;
                    if !this.write_since_flush {
                        return Poll::Ready(Ok(()));
                    }
                    // Data was queued after the flush request went out:
                    // fall through and send another flush so the ack
                    // covers those writes too.
                }
            }
        }
        match this.poll_sender.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error.to_string()))),
            Poll::Ready(Ok(())) => {
                let (tx, rx) = oneshot::channel();
                this.poll_sender
                    .send_item(OutMsg::Flush(Arc::new(tx)))
                    .map_err(|error| io::Error::other(error.to_string()))?;
                // Every write queued before this request is now covered.
                this.write_since_flush = false;
                // Poll the fresh receiver once to register the waker
                // before parking.
                let mut rx = rx;
                match Pin::new(&mut rx).poll(cx) {
                    Poll::Pending => {
                        this.flush_rx = Some(rx);
                        Poll::Pending
                    }
                    Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "smux writer gone",
                    ))),
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.fin_sent {
            return Poll::Ready(Ok(()));
        }
        let frame = this
            .shutdown_frame
            .take()
            .unwrap_or_else(|| encode_frame(CMD_FIN, this.id, &[]));
        match this.poll_sender.poll_reserve(cx) {
            Poll::Pending => {
                this.shutdown_frame = Some(frame);
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error.to_string()))),
            Poll::Ready(Ok(())) => {
                this.poll_sender
                    .send_item(OutMsg::Frame(frame))
                    .map_err(|error| io::Error::other(error.to_string()))?;
                this.fin_sent = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn frame_wire_layout_matches_sagernet_smux() {
        // SYN on stream 1: [ver=1][cmd=SYN][len=0 u16 LE][sid=1 u32 LE].
        let frame = Frame {
            cmd: CMD_SYN,
            stream_id: 1,
            data: Bytes::new(),
        };
        let buf = frame.encode();
        assert_eq!(&buf[..], &[0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);

        // PSH with 3 bytes on stream 3.
        let frame = Frame {
            cmd: CMD_PSH,
            stream_id: 3,
            data: Bytes::from_static(b"abc"),
        };
        let buf = frame.encode();
        assert_eq!(
            &buf[..],
            &[0x01, 0x02, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, b'a', b'b', b'c']
        );

        let (cmd, length, sid) = Frame::decode_header(&buf[..FRAME_HEADER_LEN]).unwrap();
        assert_eq!(cmd, CMD_PSH);
        assert_eq!(length, 3);
        assert_eq!(sid, 3);
    }

    /// Minimal smux server over a duplex pipe (same sagernet v1 codec):
    /// echoes PSH payloads back on the same stream and answers FIN with FIN.
    async fn run_echo_server<S>(mut io: S) -> tokio::task::JoinHandle<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            let mut header = [0u8; FRAME_HEADER_LEN];
            loop {
                if io.read_exact(&mut header).await.is_err() {
                    return;
                }
                let Ok((cmd, length, stream_id)) = Frame::decode_header(&header) else {
                    return;
                };
                let mut payload = vec![0u8; length];
                if !payload.is_empty() && io.read_exact(&mut payload).await.is_err() {
                    return;
                }
                match cmd {
                    CMD_PSH => {
                        let echoed = payload.clone();
                        let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN + echoed.len());
                        buf.put_u8(SMUX_VERSION);
                        buf.put_u8(CMD_PSH);
                        buf.put_u16_le(echoed.len() as u16);
                        buf.put_u32_le(stream_id);
                        buf.put_slice(&echoed);
                        if io.write_all(&buf).await.is_err() {
                            return;
                        }
                    }
                    CMD_FIN => {
                        let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN);
                        buf.put_u8(SMUX_VERSION);
                        buf.put_u8(CMD_FIN);
                        buf.put_u16_le(0);
                        buf.put_u32_le(stream_id);
                        if io.write_all(&buf).await.is_err() {
                            return;
                        }
                    }
                    _ => {}
                }
            }
        })
    }

    #[tokio::test]
    async fn open_stream_echo_round_trip() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();

        stream.write_all(b"hello smux").await.unwrap();
        let mut resp = [0u8; 10];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"hello smux");
    }

    #[tokio::test]
    async fn two_streams_multiplex_independently() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).unwrap());

        let mut a = session.open_stream().await.unwrap();
        let mut b = session.open_stream().await.unwrap();

        a.write_all(b"AAA").await.unwrap();
        b.write_all(b"BBB").await.unwrap();
        let mut buf = [0u8; 3];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"AAA");
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"BBB");
    }

    /// Regression (issue #425): a full stream queue parks the delivery and
    /// pauses the connection read instead of blocking the reader on a
    /// stream channel.  Draining the queue (the space Notify) delivers the
    /// parked chunk and resumes the session.
    #[tokio::test]
    async fn full_stream_queue_parks_and_draining_resumes() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut a = session.open_stream().await.unwrap();
        let mut b = session.open_stream().await.unwrap();

        // Fill A's queue exactly, then one more A chunk (the parked one),
        // then one chunk for B which must stay unread while paused.
        let mut wire = Vec::new();
        for _ in 0..STREAM_QUEUE {
            wire.extend_from_slice(&encode_frame(CMD_PSH, a.id, b"x"));
        }
        wire.extend_from_slice(&encode_frame(CMD_PSH, a.id, b"p"));
        wire.extend_from_slice(&encode_frame(CMD_PSH, b.id, b"y"));
        server_io.write_all(&wire).await.unwrap();

        // The session is paused: B sees nothing while A's consumer idles.
        let mut one = [0u8; 1];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), b.read(&mut one))
                .await
                .is_err(),
            "the connection read must pause while a stream queue is full"
        );
        // The pause is read-side only: writers sharing the session keep
        // flowing (a consumer stalled mid-write cannot deadlock them).
        tokio::time::timeout(std::time::Duration::from_secs(1), a.write_all(b"ping"))
            .await
            .expect("stream writes must not stall while a queue is parked")
            .unwrap();

        // Draining A delivers the parked chunk and resumes reading, so
        // B's chunk flows.
        let mut drain = vec![0u8; STREAM_QUEUE + 1];
        tokio::time::timeout(std::time::Duration::from_secs(1), a.read_exact(&mut drain))
            .await
            .expect("draining must not hang")
            .unwrap();
        assert_eq!(&drain[..STREAM_QUEUE], &[b'x'; STREAM_QUEUE]);
        assert_eq!(drain[STREAM_QUEUE], b'p');
        tokio::time::timeout(std::time::Duration::from_secs(1), b.read(&mut one))
            .await
            .expect("reading must resume after the consumer drains")
            .unwrap();
        assert_eq!(&one, b"y");
    }

    /// Regression (issue #425): dropping a stream whose full queue parked
    /// the reader must unblock the session — the SpaceWake fires, the
    /// parked delivery observes the closed channel, and reading resumes.
    #[tokio::test]
    async fn dropping_stalled_stream_resumes_session() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let session = Arc::new(Session::client(client_io).unwrap());
        let a = session.open_stream().await.unwrap();
        let mut b = session.open_stream().await.unwrap();

        let mut wire = Vec::new();
        for _ in 0..STREAM_QUEUE {
            wire.extend_from_slice(&encode_frame(CMD_PSH, a.id, b"x"));
        }
        wire.extend_from_slice(&encode_frame(CMD_PSH, a.id, b"p"));
        wire.extend_from_slice(&encode_frame(CMD_PSH, b.id, b"y"));
        server_io.write_all(&wire).await.unwrap();

        let mut one = [0u8; 1];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), b.read(&mut one))
                .await
                .is_err(),
            "the connection read must pause while a stream queue is full"
        );

        drop(a);
        tokio::time::timeout(std::time::Duration::from_secs(1), b.read(&mut one))
            .await
            .expect("reading must resume after the stalled stream drops")
            .unwrap();
        assert_eq!(&one, b"y");
    }

    #[tokio::test]
    async fn large_write_splits_into_max_frame_chunks() {
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();

        // 2.5 × MaxFrameSize — must arrive as 3 PSH frames and echo back
        // byte-identical.
        let payload = vec![0x5au8; MAX_FRAME_SIZE * 2 + MAX_FRAME_SIZE / 2];
        stream.write_all(&payload).await.unwrap();
        let mut resp = vec![0u8; payload.len()];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, payload);
    }

    /// A zero-length PSH frame carries no payload (flush / ack signal):
    /// it must be skipped, not delivered as an empty read, which consumers
    /// (the tunnel relay) treat as EOF.
    #[tokio::test]
    async fn zero_length_psh_frame_does_not_read_as_eof() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();
        let server = tokio::spawn(async move {
            let mut hdr = [0u8; FRAME_HEADER_LEN];
            server_io.read_exact(&mut hdr).await.unwrap(); // client SYN
            let stream_id = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
            server_io
                .write_all(&encode_frame(CMD_PSH, stream_id, &[]))
                .await
                .unwrap();
            server_io
                .write_all(&encode_frame(CMD_PSH, stream_id, b"ok"))
                .await
                .unwrap();
        });
        stream.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 4];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("read must not hang")
            .expect("zero-length PSH must not read as EOF");
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"ok");
        drop(stream);
        drop(session);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn half_close_sends_fin_and_eofs_peer() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _server = run_echo_server(server_io).await;
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();

        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        assert_eq!(&resp[..], b"ping");
    }

    #[tokio::test]
    async fn physical_eof_is_reported_as_an_error() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();
        let server = tokio::spawn(async move {
            let mut syn = [0u8; FRAME_HEADER_LEN];
            server_io.read_exact(&mut syn).await.unwrap();
        });
        server.await.unwrap();

        let mut buf = [0u8; 1];
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("physical EOF must wake the stream")
            .expect_err("physical EOF must not look like a clean FIN");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn poll_flush_round_trips_through_writer() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut io = server_io;
            let mut buf = [0u8; 64];
            let _ = io.read(&mut buf).await;
        });
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();
        stream.write_all(b"abc").await.unwrap();
        // The flush request travels the writer channel behind the data
        // frames and is acknowledged only after the transport flushed.
        tokio::time::timeout(std::time::Duration::from_secs(1), stream.flush())
            .await
            .expect("flush must complete")
            .unwrap();
        drop(stream);
        drop(session);
        server.await.unwrap();
    }

    /// IO with independent write and flush gates: the writer can be
    /// parked inside `poll_flush` while later writes are queued, which is
    /// the exact interleaving that exposes a flush-contract bug.
    struct FlushGatedIo {
        inner: tokio::io::DuplexStream,
        write_open: Arc<AtomicBool>,
        flush_open: Arc<AtomicBool>,
        write_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
        flush_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
        write_polled: Arc<AtomicBool>,
        flush_polled: Arc<AtomicBool>,
    }

    impl AsyncRead for FlushGatedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for FlushGatedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.write_open.load(Ordering::SeqCst) {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            this.write_polled.store(true, Ordering::SeqCst);
            *this.write_waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.flush_open.load(Ordering::SeqCst) {
                return Pin::new(&mut this.inner).poll_flush(cx);
            }
            this.flush_polled.store(true, Ordering::SeqCst);
            *this.flush_waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// Regression: a second flush issued while a first flush is still
    /// pending must cover data written after the first flush request.
    /// Current code returns the first flush's ack and silently leaves the
    /// later data unflushed.
    #[tokio::test]
    async fn second_flush_must_cover_data_written_while_first_flush_pending() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let write_open = Arc::new(AtomicBool::new(true));
        let flush_open = Arc::new(AtomicBool::new(false));
        let write_waker = Arc::new(std::sync::Mutex::new(None));
        let flush_waker = Arc::new(std::sync::Mutex::new(None));
        let write_polled = Arc::new(AtomicBool::new(false));
        let flush_polled = Arc::new(AtomicBool::new(false));
        let session = Arc::new(
            Session::client(FlushGatedIo {
                inner: client_io,
                write_open: Arc::clone(&write_open),
                flush_open: Arc::clone(&flush_open),
                write_waker: Arc::clone(&write_waker),
                flush_waker: Arc::clone(&flush_waker),
                write_polled: Arc::clone(&write_polled),
                flush_polled: Arc::clone(&flush_polled),
            })
            .unwrap(),
        );
        let mut stream = session.open_stream().await.unwrap();

        // D1 is written and the first flush request is queued behind it.
        stream.write_all(b"abc").await.unwrap();
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let first_poll = Pin::new(&mut stream).poll_flush(&mut cx);
        assert!(first_poll.is_pending(), "first flush must be pending");

        // Wait until the writer is parked inside the transport flush.
        for _ in 0..100 {
            if flush_polled.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            flush_polled.load(Ordering::SeqCst),
            "writer must be parked in poll_flush"
        );

        // D2 is queued AFTER the first flush request.
        stream.write_all(b"def").await.unwrap();

        // Before releasing the first flush, close the write gate so the
        // writer will block when it later tries to write D2.
        write_open.store(false, Ordering::SeqCst);

        // Release the first flush.
        flush_open.store(true, Ordering::SeqCst);
        if let Some(w) = flush_waker.lock().unwrap().take() {
            w.wake();
        }

        // The second flush must NOT complete while D2 is still unflushed:
        // the first flush's ack only covers D1.
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let second_poll = Pin::new(&mut stream).poll_flush(&mut cx);
        assert!(
            second_poll.is_pending(),
            "second flush must stay pending until D2 is flushed"
        );

        // Release the write gate: the writer drains D2, and only then may
        // the second flush complete.
        write_open.store(true, Ordering::SeqCst);
        if let Some(w) = write_waker.lock().unwrap().take() {
            w.wake();
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            std::future::poll_fn(|cx| Pin::new(&mut stream).poll_flush(cx)),
        )
        .await
        .expect("second flush must not hang")
        .expect("second flush must succeed");

        // The transport must have received both D1 and D2.
        let mut hdr = [0u8; FRAME_HEADER_LEN];
        server_io.read_exact(&mut hdr).await.unwrap();
        let (cmd, length, _sid) = Frame::decode_header(&hdr).unwrap();
        assert_eq!(cmd, CMD_SYN, "first frame must be the stream SYN");
        assert_eq!(length, 0);
        server_io.read_exact(&mut hdr).await.unwrap();
        let (cmd, length, _sid) = Frame::decode_header(&hdr).unwrap();
        assert_eq!(cmd, CMD_PSH, "second frame must be D1");
        let mut payload = vec![0u8; length];
        server_io.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"abc");
        server_io.read_exact(&mut hdr).await.unwrap();
        let (cmd, length, _sid) = Frame::decode_header(&hdr).unwrap();
        assert_eq!(cmd, CMD_PSH, "third frame must be D2");
        let mut payload = vec![0u8; length];
        server_io.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"def");

        // Cleanup: release the write gate and drain.
        write_open.store(true, Ordering::SeqCst);
        if let Some(w) = write_waker.lock().unwrap().take() {
            w.wake();
        }
        drop(stream);
        drop(session);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let mut buf = [0u8; 64];
            loop {
                match server_io.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        })
        .await;
    }

    /// IO whose write half stays Pending until the test releases it —
    /// parks the session writer deterministically so the bounded
    /// outbound channel can be filled (a plain small duplex cannot: the
    /// writer drains it too fast, and duplex(0) reads EOF instantly).
    /// `polled` records that the write half parked, so tests can top
    /// the channel up AFTER the writer stopped consuming; the stored
    /// waker lets the test wake the parked write on release.
    struct GatedIo {
        inner: tokio::io::DuplexStream,
        open: Arc<AtomicBool>,
        waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
        polled: Arc<AtomicBool>,
    }

    impl AsyncRead for GatedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for GatedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.open.load(Ordering::SeqCst) {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            this.polled.store(true, Ordering::SeqCst);
            *this.waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// Regression: an open cancelled while the outbound channel is full
    /// must not leave its stream-map entry behind.
    #[tokio::test]
    async fn cancelled_open_removes_stream_map_entry() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let open = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(std::sync::Mutex::new(None));
        let polled = Arc::new(AtomicBool::new(false));
        let session = Arc::new(
            Session::client(GatedIo {
                inner: client_io,
                open: Arc::clone(&open),
                waker: Arc::clone(&waker),
                polled: Arc::clone(&polled),
            })
            .unwrap(),
        );
        // Park the writer on a first frame (gate closed), then keep the
        // queue topped up: the parked write consumed one slot that must
        // be refilled for the SYN send to stay Pending.
        let filler = OutMsg::Frame(encode_frame(CMD_PSH, 0xFFFF, &[1]));
        session.writer_tx.try_send(filler.clone()).unwrap();
        while session.writer_tx.capacity() > 0 {
            session.writer_tx.try_send(filler.clone()).unwrap();
        }
        loop {
            while session.writer_tx.capacity() > 0 {
                session.writer_tx.try_send(filler.clone()).unwrap();
            }
            if polled.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        let opened =
            tokio::time::timeout(std::time::Duration::from_millis(50), session.open_stream()).await;
        assert!(opened.is_err(), "open must wait for outbound capacity");
        // The cancellation guard removes the entry asynchronously.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            session.state.streams.lock().await.is_empty(),
            "the cancelled open must not leave its stream-map entry"
        );
        // Release the parked write and drain so the session can shut
        // down cleanly.
        open.store(true, Ordering::SeqCst);
        if let Some(w) = waker.lock().unwrap().take() {
            w.wake();
        }
        let drain = tokio::spawn(async move {
            let mut io = server_io;
            let mut buf = [0u8; 64];
            loop {
                match io.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        });
        drop(session);
        drain.await.unwrap();
    }

    /// Regression: dropping a stream while the outbound channel is full
    /// must not silently lose the FIN frame.  `best_effort_fin` uses
    /// `try_send`; when the channel is full the FIN is dropped and the
    /// server never learns the stream closed.
    #[tokio::test]
    async fn dropped_stream_under_backpressure_still_sends_fin() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let open = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(std::sync::Mutex::new(None));
        let polled = Arc::new(AtomicBool::new(false));
        let session = Arc::new(
            Session::client(GatedIo {
                inner: client_io,
                open: Arc::clone(&open),
                waker: Arc::clone(&waker),
                polled: Arc::clone(&polled),
            })
            .unwrap(),
        );
        // Open a stream first: its SYN is queued and the writer parks on
        // it (gate closed).
        let stream = session.open_stream().await.unwrap();
        let sid = stream.id;
        // Keep the channel topped up so the FIN try_send must fail.
        let filler = OutMsg::Frame(encode_frame(CMD_PSH, 0xFFFF, &[1]));
        while session.writer_tx.capacity() > 0 {
            session.writer_tx.try_send(filler.clone()).unwrap();
        }
        loop {
            while session.writer_tx.capacity() > 0 {
                session.writer_tx.try_send(filler.clone()).unwrap();
            }
            if polled.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        // Drop the stream while the channel is full: try_send(FIN) fails.
        drop(stream);
        // Release the writer and collect every frame the server sees.
        open.store(true, Ordering::SeqCst);
        if let Some(w) = waker.lock().unwrap().take() {
            w.wake();
        }
        let mut seen_fin_for_sid = false;
        let mut io = server_io;
        let mut hdr = [0u8; FRAME_HEADER_LEN];
        let mut payload = [0u8; 64];
        let drain = async {
            loop {
                if io.read_exact(&mut hdr).await.is_err() {
                    break;
                }
                let Ok((cmd, length, frame_sid)) = Frame::decode_header(&hdr) else {
                    break;
                };
                if length > 0 && io.read_exact(&mut payload[..length]).await.is_err() {
                    break;
                }
                if cmd == CMD_FIN && frame_sid == sid {
                    seen_fin_for_sid = true;
                }
            }
        };
        // The writer drains the channel and then idles; EOF never comes
        // while the session is alive, so bound the observation window.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), drain).await;
        assert!(
            seen_fin_for_sid,
            "server must receive FIN for the dropped stream even under backpressure"
        );
        drop(session);
    }

    #[tokio::test]
    async fn outbound_queue_applies_backpressure() {
        let (client_io, _server_io) = tokio::io::duplex(1);
        let session = Arc::new(Session::client(client_io).unwrap());
        let mut stream = session.open_stream().await.unwrap();
        let payload = vec![0x5a; MAX_FRAME_SIZE * (OUTBOUND_QUEUE + 2)];

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.write_all(&payload),
        )
        .await;
        assert!(
            result.is_err(),
            "a blocked physical writer must backpressure streams"
        );
    }

    struct DropTrackedIo {
        inner: tokio::io::DuplexStream,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for DropTrackedIo {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl AsyncRead for DropTrackedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DropTrackedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn dropping_idle_session_releases_physical_io() {
        let (client_io, _server_io) = tokio::io::duplex(64 * 1024);
        let dropped = Arc::new(AtomicBool::new(false));
        let session = Session::client(DropTrackedIo {
            inner: client_io,
            dropped: Arc::clone(&dropped),
        })
        .unwrap();
        drop(session);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping an idle session must stop its tasks and release the fd");
    }
}
