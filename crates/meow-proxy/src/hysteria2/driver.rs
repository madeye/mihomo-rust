//! The quiche connection driver: a single task owning the UDP socket and the
//! `quiche::Connection`. It runs the QUIC event loop and bridges quiche's
//! synchronous state machine to the async `DuplexStream` (proxied TCP) and
//! `UdpSession` (proxied UDP) handles.
//!
//! The app never touches quiche. It sends [`Cmd`]s (open a TCP stream, write,
//! shut down, register/send UDP) and receives stream data / datagrams over
//! per-handle channels. Read-side backpressure is real: the driver pulls from a
//! quiche stream only while the handle's inbound channel has room, so a stalled
//! consumer throttles the peer through QUIC flow control. `read_notify` wakes
//! the driver when a handle drains its channel.

use super::auth::Auth;
use super::obfs::{HopState, Salamander};
use super::proto::{self, UdpMessage};
use super::tcp::{DuplexStream, WRITE_BUFFER_BYTES};
use super::{Config, Error, Result};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, Notify, OwnedSemaphorePermit, Semaphore};

/// App → driver commands.
pub(crate) enum Cmd {
    OpenTcp {
        first_frame: Vec<u8>,
        fast_open: bool,
        reply: oneshot::Sender<Result<DuplexStream>>,
    },
    Write {
        id: u64,
        data: Vec<u8>,
        permit: OwnedSemaphorePermit,
    },
    RegisterUdp {
        reply: oneshot::Sender<(u32, mpsc::Receiver<UdpMessage>)>,
    },
    UnregisterUdp {
        session_id: u32,
    },
    SendUdp {
        session_id: u32,
        addr: String,
        data: Vec<u8>,
    },
}

/// Driver → `DuplexStream` read items.
pub(crate) enum ReadItem {
    Data(Vec<u8>),
    Eof,
    Err(std::io::ErrorKind),
}

/// Handle the app keeps to talk to a live connection.
pub(crate) struct ConnHandle {
    pub(crate) cmd_tx: mpsc::Sender<Cmd>,
    pub(crate) udp_enabled: bool,
    closed: Arc<AtomicBool>,
    _task: DriverTask,
}

/// Own the task before the first await, including during authentication.
struct DriverTask(tokio::task::JoinHandle<()>);

impl Drop for DriverTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl ConnHandle {
    pub(crate) fn is_active(&self) -> bool {
        !self.closed.load(Ordering::Relaxed) && !self.cmd_tx.is_closed()
    }
}

const CMD_CHANNEL_CAP: usize = 256;
const STREAM_READ_CHANNEL_CAP: usize = 16;
const UDP_SESSION_QUEUE: usize = 64;
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Id 0 is the HTTP/3 auth request; proxy bidi streams start at 4, step 4.
const FIRST_PROXY_STREAM_ID: u64 = 4;

struct StreamState {
    read_tx: mpsc::Sender<ReadItem>,
    out_buf: VecDeque<WriteChunk>,
    capacity: Arc<Semaphore>,
    connected: Option<oneshot::Sender<Result<()>>>,
    fast_open: bool,
    failure: Option<std::io::ErrorKind>,
    shutdown: Arc<AtomicBool>,
    out_fin_sent: bool,
    /// Every stream strips the TCP response before forwarding payload; a
    /// non-fast-open dial additionally waits for it before returning.
    expect_response: bool,
    resp_buf: Vec<u8>,
    /// Decoded payload chunks waiting for `read_tx` capacity.
    inbound_pending: VecDeque<Vec<u8>>,
    eof_pending: bool,
    eof_sent: bool,
    read_closed: bool,
}

struct WriteChunk {
    data: Vec<u8>,
    offset: usize,
    // Returning this permit makes the corresponding bytes writable again.
    _permit: Option<OwnedSemaphorePermit>,
}

impl StreamState {
    fn new(
        read_tx: mpsc::Sender<ReadItem>,
        first_frame: Vec<u8>,
        fast_open: bool,
        capacity: Arc<Semaphore>,
        connected: oneshot::Sender<Result<()>>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            read_tx,
            out_buf: VecDeque::from([WriteChunk {
                data: first_frame,
                offset: 0,
                _permit: None,
            }]),
            capacity,
            connected: Some(connected),
            fast_open,
            failure: None,
            shutdown,
            out_fin_sent: false,
            expect_response: true,
            resp_buf: Vec::new(),
            inbound_pending: VecDeque::new(),
            eof_pending: false,
            eof_sent: false,
            read_closed: false,
        }
    }

    fn finished(&self) -> bool {
        self.out_fin_sent && (self.eof_sent || self.read_closed)
    }

    fn connected(&mut self, result: Result<()>) {
        if let Some(reply) = self.connected.take() {
            let _ = reply.send(result);
        }
    }

    fn fail(&mut self, kind: std::io::ErrorKind, error: Error) {
        if self.failure.is_some() {
            return;
        }
        self.failure = Some(kind);
        self.capacity.close();
        self.out_buf.clear();
        self.out_fin_sent = true;
        self.eof_pending = true;
        self.connected(Err(error));
    }
}

impl Drop for StreamState {
    fn drop(&mut self) {
        self.capacity.close();
    }
}

/// Driver state that is NOT the `quiche::Connection`, so helpers can borrow it
/// alongside `&mut conn`.
struct State {
    socket: UdpSocket,
    local: SocketAddr,
    obfs: Option<Salamander>,
    hop: Option<HopState>,
    cmd_tx: mpsc::WeakSender<Cmd>,
    cmd_rx: mpsc::Receiver<Cmd>,
    read_notify: Arc<Notify>,
    streams: HashMap<u64, StreamState>,
    next_stream_id: u64,
    udp_sessions: HashMap<u32, mpsc::Sender<UdpMessage>>,
    next_udp_session_id: u32,
    next_packet_id: u16,
    closed: Arc<AtomicBool>,
}

struct AuthCtx {
    auth: String,
    rx_bps: u64,
}

/// Spawn a driver for a freshly created (pre-handshake) `quiche::Connection`.
/// Resolves once authentication succeeds, returning a live handle.
pub(crate) async fn spawn(
    cfg: &Config,
    socket: UdpSocket,
    local: SocketAddr,
    peer: SocketAddr,
    conn: quiche::Connection,
) -> Result<ConnHandle> {
    let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CHANNEL_CAP);
    let read_notify = Arc::new(Notify::new());
    let closed = Arc::new(AtomicBool::new(false));
    let obfs =
        (!cfg.obfs_password.is_empty()).then(|| Salamander::new(cfg.obfs_password.as_bytes()));
    let hop = HopState::new(
        peer,
        &cfg.hop_ports,
        cfg.hop_interval_min_secs,
        cfg.hop_interval_max_secs,
    )?;

    let state = State {
        socket,
        local,
        obfs,
        hop,
        cmd_tx: cmd_tx.downgrade(),
        cmd_rx,
        read_notify,
        streams: HashMap::new(),
        next_stream_id: FIRST_PROXY_STREAM_ID,
        udp_sessions: HashMap::new(),
        next_udp_session_id: 0,
        next_packet_id: 0,
        closed: Arc::clone(&closed),
    };

    let (ready_tx, ready_rx) = oneshot::channel::<Result<bool>>();
    let auth = AuthCtx {
        auth: cfg.auth.clone(),
        rx_bps: cfg.rx_bps,
    };
    let closed_task = Arc::clone(&closed);
    let task = DriverTask(tokio::spawn(async move {
        run(state, conn, auth, ready_tx).await;
        closed_task.store(true, Ordering::Relaxed);
    }));

    let udp_enabled = ready_rx
        .await
        .map_err(|_| Error::Quic("connection driver exited before ready".into()))??;

    Ok(ConnHandle {
        cmd_tx,
        udp_enabled,
        closed,
        _task: task,
    })
}

async fn run(
    mut st: State,
    mut conn: quiche::Connection,
    auth: AuthCtx,
    ready_tx: oneshot::Sender<Result<bool>>,
) {
    let mut ready_tx = Some(ready_tx);
    let mut handshake: Option<Auth> = None;
    let mut auth_done = false;
    let mut recv_buf = vec![0u8; 65535];
    let mut send_buf = vec![0u8; 1500];
    let mut keep_alive = tokio::time::interval_at(
        tokio::time::Instant::now() + KEEP_ALIVE_INTERVAL,
        KEEP_ALIVE_INTERVAL,
    );
    keep_alive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    if let Err(e) = flush_send(&mut st, &mut conn, &mut send_buf).await {
        fail(
            &mut ready_tx,
            &mut st,
            Error::Quic(format!("initial send: {e}")),
        );
        return;
    }

    loop {
        let timeout = conn.timeout();
        tokio::select! {
            r = st.socket.recv_from(&mut recv_buf) => {
                match r {
                    Ok((n, from)) => {
                        if let Some(mut dgram) = deobfs(&st, &recv_buf[..n]) {
                            let from = st.hop.as_ref().map_or(from, |h| h.normalize_source(from));
                            let info = quiche::RecvInfo { from, to: st.local };
                            if let Err(e) = conn.recv(&mut dgram, info) {
                                tracing::debug!("hysteria2 could not receive QUIC packet: {e}");
                            }
                        }
                    }
                    Err(e) => { fail(&mut ready_tx, &mut st, Error::Io(e)); break; }
                }
            }
            maybe = st.cmd_rx.recv() => {
                match maybe {
                    Some(cmd) => handle_cmd(&mut st, &mut conn, cmd),
                    None => { let _ = conn.close(true, 0x0, b"done"); }
                }
            }
            _ = sleep_opt(timeout) => { conn.on_timeout(); }
            _ = st.read_notify.notified() => {}
            _ = keep_alive.tick(), if auth_done => {
                let _ = conn.send_ack_eliciting();
            }
        }

        if conn.is_established() && handshake.is_none() && !auth_done {
            match Auth::new(&auth.auth, auth.rx_bps) {
                Ok(state) => {
                    handshake = Some(state);
                }
                Err(e) => {
                    fail(&mut ready_tx, &mut st, e);
                    break;
                }
            }
        }

        if !auth_done {
            if let Some(handshake) = handshake.as_mut() {
                match handshake.poll(&mut conn) {
                    Ok(Some(enabled)) => {
                        auth_done = true;
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(Ok(enabled));
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        fail(&mut ready_tx, &mut st, e);
                        break;
                    }
                }
            }
        }

        cleanup_streams(&mut st, &mut conn);
        if auth_done {
            pump_reads(&mut st, &mut conn);
            pump_datagrams(&mut st, &mut conn);
        }
        pump_writes(&mut st, &mut conn);
        cleanup_streams(&mut st, &mut conn);

        if let Err(e) = flush_send(&mut st, &mut conn, &mut send_buf).await {
            tracing::debug!("hysteria2 quiche send failed: {e}");
            break;
        }
        if conn.is_closed() {
            break;
        }
    }

    fail(&mut ready_tx, &mut st, Error::Closed);
    // Only a received QUIC FIN is a clean EOF. Closing channels here makes
    // the stream report connection failure after any already queued data.
    st.streams.clear();
    st.udp_sessions.clear();
    st.closed.store(true, Ordering::Relaxed);
}

fn handle_cmd(st: &mut State, conn: &mut quiche::Connection, cmd: Cmd) {
    match cmd {
        Cmd::OpenTcp {
            first_frame,
            fast_open,
            reply,
        } => {
            let id = st.next_stream_id;
            st.next_stream_id += 4;
            let (read_tx, read_rx) = mpsc::channel(STREAM_READ_CHANNEL_CAP);
            let (connected_tx, connected_rx) = oneshot::channel();
            let capacity = Arc::new(Semaphore::new(WRITE_BUFFER_BYTES as usize));
            let shutdown = Arc::new(AtomicBool::new(false));
            let Some(cmd_tx) = st.cmd_tx.upgrade() else {
                let _ = reply.send(Err(Error::Closed));
                return;
            };
            st.streams.insert(
                id,
                StreamState::new(
                    read_tx,
                    first_frame,
                    fast_open,
                    Arc::clone(&capacity),
                    connected_tx,
                    Arc::clone(&shutdown),
                ),
            );
            let stream = DuplexStream::new(
                id,
                read_rx,
                Arc::clone(&st.read_notify),
                cmd_tx,
                capacity,
                connected_rx,
                shutdown,
            );
            let _ = reply.send(Ok(stream));
        }
        Cmd::Write { id, data, permit } => {
            if let Some(s) = st.streams.get_mut(&id) {
                if s.failure.is_none() {
                    s.out_buf.push_back(WriteChunk {
                        data,
                        offset: 0,
                        _permit: Some(permit),
                    });
                }
            }
        }
        Cmd::RegisterUdp { reply } => {
            let session_id = st.next_udp_session_id;
            st.next_udp_session_id = st.next_udp_session_id.wrapping_add(1);
            let (tx, rx) = mpsc::channel(UDP_SESSION_QUEUE);
            st.udp_sessions.insert(session_id, tx);
            let _ = reply.send((session_id, rx));
        }
        Cmd::UnregisterUdp { session_id } => {
            st.udp_sessions.remove(&session_id);
        }
        Cmd::SendUdp {
            session_id,
            addr,
            data,
        } => send_udp(st, conn, session_id, &addr, &data),
    }
}

fn pump_writes(st: &mut State, conn: &mut quiche::Connection) {
    for (&id, s) in &mut st.streams {
        // Do NOT pre-check `stream_capacity`: a stream is not created until the
        // first `stream_send`, and capacity on an unopened stream is 0. Send
        // the buffered bytes directly; quiche opens the stream and accepts as
        // much as flow control allows, returning the count.
        while let Some(chunk) = s.out_buf.front_mut() {
            match conn.stream_send(id, &chunk.data[chunk.offset..], false) {
                Ok(0) | Err(quiche::Error::Done | quiche::Error::StreamLimit) => break,
                Ok(w) => {
                    chunk.offset += w;
                    if chunk.offset == chunk.data.len() {
                        s.out_buf.pop_front();
                    }
                }
                Err(e) => {
                    tracing::debug!("hysteria2 stream {id} send failed: {e}");
                    s.fail(
                        std::io::ErrorKind::BrokenPipe,
                        Error::Quic(format!("stream send: {e}")),
                    );
                    let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
                    let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, 0);
                    break;
                }
            }
        }
        if s.out_buf.is_empty() && s.fast_open && s.failure.is_none() {
            s.connected(Ok(()));
        }
        if s.out_buf.is_empty() && s.shutdown.load(Ordering::Acquire) && !s.out_fin_sent {
            match conn.stream_send(id, &[], true) {
                Err(quiche::Error::Done | quiche::Error::StreamLimit) => {}
                Ok(_) => s.out_fin_sent = true,
                Err(e) => s.fail(
                    std::io::ErrorKind::BrokenPipe,
                    Error::Quic(format!("stream finish: {e}")),
                ),
            }
        }
        let _ = flush_pending(s);
    }
}

fn pump_reads(st: &mut State, conn: &mut quiche::Connection) {
    for s in st.streams.values_mut() {
        let _ = flush_pending(s);
    }
    let ids: Vec<u64> = conn.readable().collect();
    let mut buf = [0u8; 16384];
    for id in ids {
        if let Some(s) = st.streams.get_mut(&id) {
            if !flush_pending(s) || s.failure.is_some() {
                continue;
            }
            loop {
                match conn.stream_recv(id, &mut buf) {
                    Ok((n, fin)) => {
                        if n > 0 {
                            ingest(s, &buf[..n]);
                        }
                        if fin {
                            if s.expect_response {
                                s.fail(
                                    std::io::ErrorKind::UnexpectedEof,
                                    Error::protocol("truncated TCP response"),
                                );
                            } else {
                                s.eof_pending = true;
                            }
                        }
                        if !flush_pending(s) {
                            break;
                        }
                        if fin || s.failure.is_some() {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        s.fail(
                            std::io::ErrorKind::ConnectionReset,
                            Error::Quic(format!("stream receive: {e}")),
                        );
                        let _ = flush_pending(s);
                        break;
                    }
                }
            }
        } else {
            // Unknown / uni stream (e.g. an h3 control stream): drain and drop
            // so flow control keeps moving. We no longer drive h3 post-auth.
            loop {
                match conn.stream_recv(id, &mut buf) {
                    Ok((_, fin)) if !fin => {}
                    _ => break,
                }
            }
        }
    }
}

/// Feed received stream bytes into a proxy stream, parsing the hysteria2 TCP
/// response before forwarding payload on either kind of stream.
fn ingest(s: &mut StreamState, bytes: &[u8]) {
    if s.expect_response {
        s.resp_buf.extend_from_slice(bytes);
        match proto::parse_tcp_response(&s.resp_buf) {
            Ok(Some(consumed)) => {
                let leftover = s.resp_buf.split_off(consumed);
                s.resp_buf = Vec::new();
                s.expect_response = false;
                s.connected(Ok(()));
                if !leftover.is_empty() {
                    s.inbound_pending.push_back(leftover);
                }
            }
            Ok(None) => {}
            Err(e) => {
                s.inbound_pending.clear();
                s.fail(std::io::ErrorKind::InvalidData, e);
            }
        }
    } else {
        s.inbound_pending.push_back(bytes.to_vec());
    }
}

/// Try to move buffered inbound chunks to the consumer. Returns `false` when the
/// consumer's channel is full (stop reading this stream — QUIC flow control then
/// throttles the peer until `read_notify` fires).
fn flush_pending(s: &mut StreamState) -> bool {
    while let Some(item) = s.inbound_pending.pop_front() {
        match s.read_tx.try_send(ReadItem::Data(item)) {
            Ok(()) => {}
            Err(TrySendError::Full(ReadItem::Data(item))) => {
                s.inbound_pending.push_front(item);
                return false;
            }
            Err(TrySendError::Full(_)) => unreachable!("only Data is sent here"),
            Err(TrySendError::Closed(_)) => {
                s.inbound_pending.clear();
                s.read_closed = true;
                return true;
            }
        }
    }
    if s.eof_pending && !s.eof_sent && !s.read_closed {
        let terminal = s.failure.map_or(ReadItem::Eof, ReadItem::Err);
        match s.read_tx.try_send(terminal) {
            Ok(()) => s.eof_sent = true,
            Err(TrySendError::Full(_)) => return false,
            Err(TrySendError::Closed(_)) => s.read_closed = true,
        }
    }
    true
}

fn pump_datagrams(st: &mut State, conn: &mut quiche::Connection) {
    let mut buf = [0u8; 65535];
    while let Ok(n) = conn.dgram_recv(&mut buf) {
        tracing::trace!(bytes = n, "hysteria2 received QUIC datagram");
        match proto::decode_udp_message(&buf[..n]) {
            Ok(msg) => {
                tracing::trace!(
                    session_id = msg.session_id,
                    packet_id = msg.packet_id,
                    frag_id = msg.frag_id,
                    frag_count = msg.frag_count,
                    "hysteria2 decoded UDP fragment"
                );
                if let Some(tx) = st.udp_sessions.get(&msg.session_id) {
                    let _ = tx.try_send(msg);
                }
            }
            Err(e) => tracing::debug!("dropping malformed hysteria2 UDP datagram: {e}"),
        }
    }
}

fn send_udp(
    st: &mut State,
    conn: &mut quiche::Connection,
    session_id: u32,
    addr: &str,
    data: &[u8],
) {
    let max = conn.dgram_max_writable_len().unwrap_or(0);
    tracing::trace!(
        session_id,
        bytes = data.len(),
        max,
        "hysteria2 sending UDP packet"
    );
    let Ok(header) = proto::udp_header_len(addr) else {
        return;
    };
    let payload_limit = max.saturating_sub(header);
    if payload_limit == 0 {
        return;
    }
    let packet_id = st.next_packet_id;
    st.next_packet_id = st.next_packet_id.wrapping_add(1);

    if data.len() <= payload_limit {
        send_one_udp(
            conn,
            &UdpMessage {
                session_id,
                packet_id,
                frag_id: 0,
                frag_count: 1,
                addr: addr.to_string(),
                data: data.to_vec(),
            },
        );
        return;
    }
    let frag_count = data.len().div_ceil(payload_limit);
    if frag_count > u8::MAX as usize {
        return;
    }
    for (i, chunk) in data.chunks(payload_limit).enumerate() {
        send_one_udp(
            conn,
            &UdpMessage {
                session_id,
                packet_id,
                frag_id: i as u8,
                frag_count: frag_count as u8,
                addr: addr.to_string(),
                data: chunk.to_vec(),
            },
        );
    }
}

fn send_one_udp(conn: &mut quiche::Connection, msg: &UdpMessage) {
    if let Ok(encoded) = proto::encode_udp_message(msg) {
        if let Err(e) = conn.dgram_send(&encoded) {
            tracing::debug!("hysteria2 could not queue UDP datagram: {e}");
        }
    }
}

fn cleanup_streams(st: &mut State, conn: &mut quiche::Connection) {
    let done: Vec<u64> = st
        .streams
        .iter()
        .filter(|(_, s)| {
            s.finished()
                || (s.read_tx.is_closed()
                    && (!s.shutdown.load(Ordering::Acquire) || s.out_fin_sent))
        })
        .map(|(&id, _)| id)
        .collect();
    for id in done {
        if let Some(s) = st.streams.remove(&id) {
            if !s.shutdown.load(Ordering::Acquire) || s.failure.is_some() {
                let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, 0);
            }
        }
        let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
    }
}

/// Drain quiche's send queue to the socket, applying obfs and port-hopping.
async fn flush_send(
    st: &mut State,
    conn: &mut quiche::Connection,
    out: &mut [u8],
) -> std::io::Result<()> {
    loop {
        let (write, info) = match conn.send(out) {
            Ok(v) => v,
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => {
                return Err(std::io::Error::other(format!("quiche send: {e}")));
            }
        };
        let dest = match st.hop.as_mut() {
            Some(hop) => hop.outgoing(),
            None => info.to,
        };
        let payload = match st.obfs.as_ref() {
            Some(obfs) => obfs.encode(&out[..write]),
            None => out[..write].to_vec(),
        };
        tracing::trace!(
            bytes = payload.len(),
            queued = conn.dgram_send_queue_len(),
            "hysteria2 transmitting QUIC packet"
        );
        st.socket.send_to(&payload, dest).await?;
    }
}

fn deobfs(st: &State, raw: &[u8]) -> Option<Vec<u8>> {
    match st.obfs.as_ref() {
        Some(obfs) => obfs.decode(raw),
        None => Some(raw.to_vec()),
    }
}

async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

fn fail(ready_tx: &mut Option<oneshot::Sender<Result<bool>>>, _st: &mut State, err: Error) {
    if let Some(tx) = ready_tx.take() {
        let _ = tx.send(Err(err));
    }
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
