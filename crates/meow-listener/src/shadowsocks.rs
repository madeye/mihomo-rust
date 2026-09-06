//! Shadowsocks encrypted-server inbound listener.
//!
//! Terminates SS encryption on an inbound TCP (and, with `udp: true`, UDP)
//! flow, reads the SOCKS target address from the decrypted header, and hands
//! the decrypted stream to the tunnel via [`route_inbound_tcp`]. Mirrors
//! upstream mihomo's `type: shadowsocks` listener.
//!
//! The cipher / AEAD decryption is delegated to the `shadowsocks` crate's
//! server-side [`ProxyListener`] / [`ProxyServerStream`] (the same crate the
//! outbound `ss` adapter uses on the client side), so this module contains no
//! crypto of its own — only accept-loop orchestration, target-address →
//! `Metadata` mapping, and the optional simple-obfs wrapper injection.
//!
//! # obfs injection
//!
//! `simple-obfs` wraps the *raw* TCP stream before SS decryption (it is the
//! outer layer). [`ProxyListener::accept_map`] lets us hand the accepted
//! `TcpStream` to a closure that applies the obfs codec before
//! `ProxyServerStream` reads the SS header — exactly the right order. The
//! obfs mode is fixed per listener, so the accept loop is monomorphised per
//! concrete stream type (`TcpStream` / `HttpObfsServer` / `TlsObfsServer`)
//! rather than type-erased, keeping the relay hot path dispatch-free.

use meow_common::{ConnType, Metadata, Network};
use meow_transport::simple_obfs::server::{HttpObfsServer, TlsObfsServer};
use meow_tunnel::{route_inbound_tcp, Tunnel};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::net::TcpListener as SsTcpListener;
use shadowsocks::relay::tcprelay::{ProxyListener, ProxyServerStream};
use shadowsocks::relay::Address;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::DEFAULT_HANDSHAKE_TIMEOUT;

/// `simple-obfs` mode for the SS listener (mirrors `meow_config::ObfsMode`
/// without pulling meow-config into this crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsObfsMode {
    Http,
    Tls,
}

/// Convenience alias for the listener-wide obfs setting.
type ObfsKind = Option<SsObfsMode>;

/// Default cap on in-flight inbound connections (and, with `udp: true`,
/// concurrent UDP flows) per listener when the listener config doesn't set
/// `max-connections` (mirrors `mixed::DEFAULT_MAX_CONNECTIONS` — kept as a
/// separate constant rather than an import so `listener-shadowsocks` stays
/// usable without `listener-mixed` enabled, same rationale as tproxy's
/// copy). `0` explicitly disables the cap.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

pub struct ShadowsocksListener {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    name: String,
    svr_cfg: Arc<ServerConfig>,
    /// Raw password + cipher kept separately so the UDP relay can rebuild a
    /// `ServerConfig` bound to the *resolved* TCP port (the TCP listener may
    /// bind `port: 0` and receive an ephemeral port; UDP must share that port).
    password: String,
    method: CipherKind,
    ctx: shadowsocks::context::SharedContext,
    udp: bool,
    obfs: ObfsKind,
    max_connections: usize,
}

impl ShadowsocksListener {
    /// Build a listener. `cipher` must be a string the `shadowsocks` crate
    /// recognises (e.g. `aes-256-gcm`, `2022-blake3-aes-256-gcm`, `chacha20-ietf-poly1305`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tunnel: Tunnel,
        listen_addr: SocketAddr,
        name: String,
        cipher: &str,
        password: &str,
        udp: bool,
        obfs: ObfsKind,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let method = cipher.parse::<CipherKind>().map_err(|_| {
            meow_common::MeowError::Config(format!("ss listener: unknown cipher '{cipher}'"))
        })?;
        let svr_cfg = ServerConfig::new(listen_addr, password, method).map_err(|e| {
            meow_common::MeowError::Config(format!("ss listener: invalid config: {e}"))
        })?;
        let ctx = Context::new_shared(ServerType::Server);
        Ok(Self {
            tunnel,
            listen_addr,
            name,
            svr_cfg: Arc::new(svr_cfg),
            password: password.to_string(),
            method,
            ctx,
            udp,
            obfs,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        })
    }

    /// Override the concurrent-inbound cap (default
    /// [`DEFAULT_MAX_CONNECTIONS`]). `0` disables the cap. The same value
    /// caps the UDP relay's concurrent `(peer, target)` flows.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Serve on an already-bound TCP socket. The caller binds first (so a
    /// `port: 0` ephemeral listener resolves to its OS-assigned port before
    /// the API snapshot is taken) and hands the socket over.
    pub async fn run_on(
        &self,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bound = listener.local_addr().unwrap_or(self.listen_addr);
        info!(
            "Shadowsocks listener '{}' on {} (cipher={}, udp={}, obfs={:?})",
            self.name,
            bound,
            self.svr_cfg.method(),
            self.udp,
            self.obfs,
        );

        let proxy_listener = {
            // Convert the already-bound tokio listener into the shadowsocks
            // crate's listener wrapper (preserves the OS-assigned port for
            // `port: 0` ephemeral listeners). AcceptOpts::default() keeps the
            // system TCP defaults (no TFO/MPTCP forcing).
            let ss_listener =
                SsTcpListener::from_listener(listener, shadowsocks::net::AcceptOpts::default())?;
            ProxyListener::from_listener(Arc::clone(&self.ctx), ss_listener, self.svr_cfg.as_ref())
        };

        // UDP relay: simple-obfs is TCP-only, so UDP is skipped (with a warn)
        // when obfs is configured. Otherwise bind a `ProxySocket` on the same
        // resolved port and run the (peer, target) flow table in a background
        // task. The TCP accept loop below drives the task's lifetime by
        // outliving it (both run for the process lifetime).
        if self.udp {
            if self.obfs.is_some() {
                warn!(
                    "ss listener '{}': simple-obfs is TCP-only; UDP relay disabled",
                    self.name
                );
            } else {
                let udp_cfg = ServerConfig::new(bound, self.password.clone(), self.method)
                    .map_err(|e| meow_common::MeowError::Config(format!("ss udp bind: {e}")))?;
                let udp_sock = shadowsocks::ProxySocket::bind(Arc::clone(&self.ctx), &udp_cfg)
                    .await
                    .map_err(|e| format!("ss listener '{}': udp bind failed: {e}", self.name))?;
                info!(
                    "Shadowsocks listener '{}' UDP on {} (cipher={})",
                    self.name, bound, self.method
                );
                let tunnel = self.tunnel.clone();
                let name = self.name.clone();
                let in_port = bound.port();
                let max_flows = self.max_connections;
                tokio::spawn(async move {
                    run_udp_relay(tunnel, udp_sock, name, in_port, max_flows).await;
                });
            }
        }

        let sem: Option<Arc<Semaphore>> =
            (self.max_connections > 0).then(|| Arc::new(Semaphore::new(self.max_connections)));

        // simple-obfs wraps the *raw* TCP stream before SS decryption (it is
        // the outer layer). `ProxyListener::accept_map` lets us hand the
        // accepted TcpStream to a closure that applies the obfs codec first.
        // The obfs mode is fixed per listener, so the accept loop is
        // monomorphised per concrete stream type (no dyn dispatch on the relay
        // hot path). UDP is TCP-only for obfs and was warned about above.
        let in_port = bound.port();
        match self.obfs {
            None => {
                // No obfs: the accepted stream is a bare TcpStream.
                self.accept_loop::<TcpStream, _>(proxy_listener, |t| t, sem, in_port)
                    .await
            }
            Some(SsObfsMode::Http) => {
                self.accept_loop::<HttpObfsServer<TcpStream>, _>(
                    proxy_listener,
                    HttpObfsServer::new,
                    sem,
                    in_port,
                )
                .await
            }
            Some(SsObfsMode::Tls) => {
                self.accept_loop::<TlsObfsServer<TcpStream>, _>(
                    proxy_listener,
                    TlsObfsServer::new,
                    sem,
                    in_port,
                )
                .await
            }
        }
    }

    /// Generic accept loop. `map` wraps each accepted `TcpStream` (e.g. in an
    /// obfs codec) before `ProxyServerStream` decrypts the SS header. The
    /// closure is `Fn + Clone` so it can be handed to `accept_map` per
    /// iteration; it captures nothing for the obfs modes we support, so the
    /// clone is free.
    async fn accept_loop<S, F>(
        &self,
        pl: ProxyListener,
        map: F,
        sem: Option<Arc<Semaphore>>,
        in_port: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
        F: Fn(TcpStream) -> S + Clone + Send + Sync + 'static,
    {
        let mut warned_saturated = false;
        loop {
            // Acquire a concurrency slot (back-pressures the listen queue when
            // the cap is reached), mirroring MixedListener.
            let permit = if let Some(sem) = &sem {
                let sem = Arc::clone(sem);
                if sem.available_permits() == 0 && !warned_saturated {
                    warn!(
                        "ss listener '{}' saturated at {} concurrent connections; new clients will queue",
                        self.name, self.max_connections
                    );
                    warned_saturated = true;
                }
                match sem.acquire_owned().await {
                    Ok(p) => {
                        if warned_saturated {
                            debug!("ss listener '{}' has free capacity again", self.name);
                            warned_saturated = false;
                        }
                        Some(p)
                    }
                    Err(_) => return Ok(()), // semaphore closed → shutdown
                }
            } else {
                None
            };

            let (ss, peer) = match pl.accept_map(map.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("ss listener '{}' accept error: {}", self.name, e);
                    drop(permit);
                    continue;
                }
            };

            let tunnel = self.tunnel.clone();
            let name = self.name.clone();
            tokio::spawn(async move {
                handle_ss_conn(ss, peer, tunnel, name, in_port).await;
                drop(permit);
            });
        }
    }
}

/// Per-connection handler: SS handshake (decrypt + read target address) then
/// route+relay. Generic over the inner stream type `S` (bare `TcpStream` or
/// an obfs wrapper) so the relay is monomorphised per concrete type.
async fn handle_ss_conn<S: AsyncRead + AsyncWrite + Unpin + Send + Sync>(
    mut ss: ProxyServerStream<S>,
    peer: SocketAddr,
    tunnel: Tunnel,
    in_name: String,
    in_port: u16,
) {
    // ProxyServerStream::handshake decrypts the SS header and returns the
    // SOCKS target address. Bound the wait so a silent peer can't hold a
    // concurrency slot forever.
    let target = match tokio::time::timeout(DEFAULT_HANDSHAKE_TIMEOUT, ss.handshake()).await {
        Ok(Ok(addr)) => addr,
        Ok(Err(e)) => {
            debug!("ss listener handshake from {peer} failed: {e}");
            return;
        }
        Err(_) => {
            debug!("ss listener handshake from {peer} timed out");
            return;
        }
    };

    let metadata = build_metadata(peer, &target, &in_name, in_port);
    debug!("ss listener {} -> {}", peer, metadata.remote_address());

    let inner = tunnel.inner();
    route_inbound_tcp(inner, &mut ss, metadata, &[]).await;
}

/// Map an SS target `Address` + peer into a `Metadata` for the tunnel.
fn build_metadata(peer: SocketAddr, target: &Address, in_name: &str, in_port: u16) -> Metadata {
    let (host, dst_ip, dst_port) = match target {
        Address::DomainNameAddress(d, port) => (d.to_lowercase(), None, *port),
        Address::SocketAddress(sa) => (String::new(), Some(sa.ip()), sa.port()),
    };
    Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Shadowsocks,
        src_ip: Some(peer.ip()),
        src_port: peer.port(),
        dst_ip,
        dst_port,
        host: host.into(),
        in_name: in_name.into(),
        in_port,
        ..Default::default()
    }
}

// ──────────────────────────────── UDP relay ────────────────────────────────
//
// The SS UDP relay shares one `ProxySocket` (the decrypted inbound socket)
// across all SS clients. Each decrypted datagram carries a `(peer, target)`
// pair: `peer` is the SS client's source address, `target` is the SOCKS
// destination encoded in the SS header. We maintain a flat
// `HashMap<(peer, target), Flow>` so datagrams from different clients (or to
// different destinations from the same client) get distinct outbound conns —
// mirroring the SOCKS5-UDP per-destination NAT, but keyed by both endpoints
// since the socket is shared.
//
// Idle eviction reuses `meow_tunnel::udp::DEFAULT_UDP_IDLE`; a flow whose
// neither direction has touched `last_activity_ms` within the idle window is
// dropped, aborting its reply task and freeing the outbound conn.

use meow_common::atomic::{AtomicU, Uint};
use meow_common::{with_dial_timeout, ProxyPacketConn};
use meow_tunnel::udp::DEFAULT_UDP_IDLE;
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend};
use std::collections::HashMap;
use std::time::Duration;
use tokio::task::AbortHandle;

use crate::monotonic_ms;

const UDP_NAT_SWEEP: Duration = Duration::from_secs(30);

/// One `(peer, target)` outbound flow.
struct UdpFlow {
    conn: Arc<dyn ProxyPacketConn>,
    last_activity_ms: Arc<AtomicU>,
    /// Reply task (server→client); aborted when the flow is evicted.
    reply_task: AbortHandle,
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.reply_task.abort();
    }
}

/// Run the SS UDP relay: decrypt inbound datagrams, route each through the
/// tunnel (rule match → `dial_udp`), and relay replies back encrypted to the
/// originating peer. Runs until the socket errors out (process lifetime).
///
/// `max_flows` caps the concurrent `(peer, target)` flow table (`0` =
/// uncapped), mirroring the TCP accept loop's `max_connections` — each flow
/// holds a 64 KiB reply buffer, a task, and an outbound socket, so an
/// unbounded table is a memory/FD exhaustion vector on an internet-exposed
/// listener. Saturated new flows are dropped with a warn-once log (recovery
/// logs at debug), exactly like the TCP saturation path.
///
/// Generic over the inner socket type `S` so the concrete type returned by
/// `ProxySocket::bind` (`ShadowUdpSocket`) flows in by inference — the relay
/// logic is identical for any `DatagramSend + DatagramReceive` socket.
async fn run_udp_relay<S>(
    tunnel: Tunnel,
    sock: shadowsocks::ProxySocket<S>,
    in_name: String,
    in_port: u16,
    max_flows: usize,
) where
    S: DatagramSend + DatagramReceive + Send + Sync + 'static,
{
    let sock = Arc::new(sock);
    let mut flows: HashMap<(SocketAddr, SocketAddr), UdpFlow> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut sweeper = tokio::time::interval(UDP_NAT_SWEEP);
    sweeper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let idle_ms = DEFAULT_UDP_IDLE.as_millis() as u64;
    let mut warned_saturated = false;

    loop {
        tokio::select! {
            biased;
            r = sock.recv_from(&mut buf) => {
                let (n, peer, target, _recv_total) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("ss udp '{}' recv error: {e}", in_name);
                        continue;
                    }
                };
                let payload = &buf[..n];
                match handle_ss_udp_datagram(&tunnel, &sock, &mut flows, payload, peer, &target, &in_name, in_port, max_flows).await {
                    Ok(true) => {}
                    Ok(false) => {
                        if !warned_saturated {
                            warn!(
                                "ss udp '{}' flow table saturated at {} flows; new flows are dropped until idle eviction",
                                in_name, max_flows
                            );
                            warned_saturated = true;
                        }
                    }
                    Err(e) => debug!("ss udp '{}' datagram from {peer}: {e}", in_name),
                }
            }
            _ = sweeper.tick() => {
                let now = monotonic_ms() as Uint;
                flows.retain(|_, f| {
                    let last = f.last_activity_ms.load(std::sync::atomic::Ordering::Relaxed);
                    #[allow(
                        clippy::useless_conversion,
                        reason = "identity on 64-bit; u32→u64 widening on mips32"
                    )]
                    let elapsed = u64::from(now.wrapping_sub(last));
                    elapsed < idle_ms
                });
                if warned_saturated && (max_flows == 0 || flows.len() < max_flows) {
                    debug!("ss udp '{}' flow table has free capacity again", in_name);
                    warned_saturated = false;
                }
            }
        }
    }
}

/// Decrypt is already done by `ProxySocket`; here we resolve the target,
/// route, and forward through the (possibly new) per-flow outbound conn.
///
/// Returns `Ok(true)` when the datagram was handled (existing or new flow),
/// `Ok(false)` when it was dropped because the flow table is at `max_flows`
/// (new-flow cap only — datagrams for existing flows always pass), and
/// `Err` with a reason for per-datagram failures.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors socks5_udp::handle_client_datagram's parameter set plus the shared socket and flow cap"
)]
async fn handle_ss_udp_datagram<S>(
    tunnel: &Tunnel,
    sock: &Arc<shadowsocks::ProxySocket<S>>,
    flows: &mut HashMap<(SocketAddr, SocketAddr), UdpFlow>,
    payload: &[u8],
    peer: SocketAddr,
    target: &Address,
    in_name: &str,
    in_port: u16,
    max_flows: usize,
) -> Result<bool, String>
where
    S: DatagramSend + DatagramReceive + Send + Sync + 'static,
{
    let inner = tunnel.inner();
    let (host, dst_ip, dst_port) = match target {
        Address::DomainNameAddress(d, port) => (d.to_lowercase(), None, *port),
        Address::SocketAddress(sa) => (String::new(), Some(sa.ip()), sa.port()),
    };

    let mut metadata = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Shadowsocks,
        src_ip: Some(peer.ip()),
        src_port: peer.port(),
        dst_ip,
        dst_port,
        host: host.into(),
        in_name: in_name.into(),
        in_port,
        ..Default::default()
    };

    inner.pre_handle_metadata(&mut metadata);
    inner.pre_resolve(&mut metadata).await;
    if metadata.dst_ip.is_none() && !metadata.host.is_empty() {
        metadata.dst_ip = inner.resolver.resolve_ip_real(&metadata.host).await;
    }
    let Some(dst_ip) = metadata.dst_ip else {
        return Err(format!(
            "dst_ip not resolved for {}",
            metadata.remote_address()
        ));
    };
    let dst_addr = SocketAddr::new(dst_ip, metadata.dst_port);
    let key = (peer, dst_addr);

    // Fast path: existing flow.
    if let Some(flow) = flows.get(&key) {
        flow.conn
            .write_packet(payload, &dst_addr)
            .await
            .map_err(|e| format!("udp write {dst_addr}: {e}"))?;
        flow.last_activity_ms
            .store(monotonic_ms() as Uint, std::sync::atomic::Ordering::Relaxed);
        return Ok(true);
    }

    // Flow-table cap: a new flow costs a 64 KiB reply buffer, a task, and an
    // outbound socket; without a cap any password holder could exhaust
    // memory/FDs between idle sweeps. `0` disables the cap.
    if max_flows > 0 && flows.len() >= max_flows {
        return Ok(false);
    }

    // Client UDP follows the configured routing policy, including port 53.
    let Some((proxy, _rule, _payload)) = inner.resolve_proxy(&metadata) else {
        return Err(format!(
            "no matching rule for {}",
            metadata.remote_address()
        ));
    };

    let conn: Arc<dyn ProxyPacketConn> = Arc::from(
        with_dial_timeout(proxy.name(), proxy.dial_udp(&metadata))
            .await
            .map_err(|e| format!("dial_udp via {}: {e}", proxy.name()))?,
    );
    conn.write_packet(payload, &dst_addr)
        .await
        .map_err(|e| format!("udp initial write {dst_addr}: {e}"))?;

    let last_activity_ms = Arc::new(AtomicU::new(monotonic_ms() as Uint));
    let reply_task = {
        let sock = Arc::clone(sock);
        let conn = Arc::clone(&conn);
        let last_activity_ms = Arc::clone(&last_activity_ms);
        // Echo back the original target Address (domain or IP) so the SS
        // client can correlate replies by the same address type it sent.
        let reply_addr = target.clone();
        tokio::spawn(async move {
            let mut rbuf = vec![0u8; 65535];
            while let Ok((m, _src)) = conn.read_packet(&mut rbuf).await {
                if sock.send_to(peer, &reply_addr, &rbuf[..m]).await.is_err() {
                    break;
                }
                last_activity_ms
                    .store(monotonic_ms() as Uint, std::sync::atomic::Ordering::Relaxed);
            }
        })
        .abort_handle()
    };

    flows.insert(
        key,
        UdpFlow {
            conn,
            last_activity_ms,
            reply_task,
        },
    );
    Ok(true)
}

#[cfg(test)]
mod routing_tests {
    use super::*;

    #[tokio::test]
    async fn udp_port_53_obeys_reject_rule() {
        let tunnel = crate::test_rule_tunnel();
        let config = shadowsocks::config::ServerConfig::new(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            "synthetic-test-password",
            "aes-256-gcm".parse().unwrap(),
        )
        .unwrap();
        let context =
            shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Server);
        let sock = Arc::new(
            shadowsocks::ProxySocket::bind(context, &config)
                .await
                .unwrap(),
        );
        let mut flows = HashMap::new();
        let peer = "127.0.0.1:12345".parse().unwrap();
        for port in [53, 5353] {
            let dst = SocketAddr::from(([127, 0, 0, 1], port));
            assert!(handle_ss_udp_datagram(
                &tunnel,
                &sock,
                &mut flows,
                b"not a DNS query",
                peer,
                &Address::SocketAddress(dst),
                "ss",
                8388,
                8,
            )
            .await
            .unwrap());
            assert!(
                flows[&(peer, dst)].conn.local_addr().is_err(),
                "must use REJECT, not DIRECT"
            );
        }
    }
}
