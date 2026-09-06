mod firewall;
mod orig_dest;

use crate::sniffer::SnifferRuntime;
use firewall::FirewallGuard;
use meow_common::{with_dial_timeout, ConnType, Metadata, Network};
use meow_tunnel::{copy_bidirectional_buf_tracked, Tunnel, RELAY_BUF_SIZE};
use smallvec::smallvec;
use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Default cap on in-flight inbound connections per listener when the
/// listener config doesn't set `max-connections` (mirrors
/// `mixed::DEFAULT_MAX_CONNECTIONS` — kept as a separate constant rather than
/// an import so `listener-tproxy` stays usable without `listener-mixed`
/// enabled). `0` explicitly disables the cap.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

pub struct TProxyListener {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    routing_mark: Option<u32>,
    name: String,
    max_connections: usize,
}

impl TProxyListener {
    pub fn new(
        tunnel: Tunnel,
        listen_addr: SocketAddr,
        enable_sni: bool,
        routing_mark: Option<u32>,
        name: String,
    ) -> Self {
        // Deprecated `enable_sni` knob: synthesise a minimal sniffer config.
        let sniffer = if enable_sni {
            warn!(
                "`enable_sni` is deprecated; migrate to the top-level `sniffer:` block. \
                Accepting as `sniffer.enable: true, sniff.TLS.ports: [443]` for this release. \
                Will be removed in a future version."
            );
            let cfg = meow_common::SnifferConfig {
                enable: true,
                tls_ports: vec![443],
                http_ports: Vec::new(),
                ..Default::default()
            };
            Some(Arc::new(SnifferRuntime::new(cfg)))
        } else {
            None
        };
        Self {
            tunnel,
            listen_addr,
            sniffer,
            routing_mark,
            name,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }

    pub fn with_sniffer(mut self, sniffer: Arc<SnifferRuntime>) -> Self {
        if sniffer.is_enabled() {
            self.sniffer = Some(sniffer);
        }
        self
    }

    /// Override the cap on in-flight inbound connections (default
    /// [`DEFAULT_MAX_CONNECTIONS`]). `0` disables the cap.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Bind first so a port-0 listen can resolve to the OS-assigned port
        // before firewall rules are installed against it.
        let listener = TcpListener::bind(self.listen_addr).await?;
        self.run_on(listener).await
    }

    /// Serve on an already-bound socket, letting the caller resolve a
    /// `port: 0` ephemeral listener to its OS-assigned port first. Firewall
    /// redirect rules are installed against the socket's actual local port,
    /// so ephemeral listeners redirect correctly.
    pub async fn run_on(
        self,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Collect upstream proxy server IPs for firewall bypass
        let bypass_ips = collect_proxy_server_ips(&self.tunnel);

        let bound_addr = listener.local_addr().unwrap_or(self.listen_addr);

        // Set up firewall redirect rules (tears down on drop)
        let _firewall = FirewallGuard::setup(bound_addr.port(), self.routing_mark, &bypass_ips)?;

        if self.max_connections == 0 {
            info!(
                "TProxy listener '{}' started on {} (max_connections=unlimited)",
                self.name, bound_addr
            );
        } else {
            info!(
                "TProxy listener '{}' started on {} (max_connections={})",
                self.name, bound_addr, self.max_connections
            );
        }

        // Scope decision for the pf path (#248): the managed ruleset
        // intercepts loopback-traversing IPv4 TCP only; steering real
        // outbound (en0) traffic stays a manual, documented pf detour rather
        // than something meow rewrites the host's pf config for. Surface that
        // at startup so "tproxy is on but my browser isn't proxied" is
        // explained by the log, not a silent surprise.
        #[cfg(target_os = "macos")]
        info!(
            "TProxy on macOS intercepts loopback IPv4 TCP only; real outbound \
             traffic needs the manual route-to detour (docs/tproxy-macos.md) — \
             for full transparent proxying use the TUN inbound (docs/tun.md)"
        );

        let tunnel = self.tunnel;
        let sniffer = self.sniffer;
        let name = self.name;
        let max_connections = self.max_connections;
        bounded_accept_loop(listener, max_connections, name.clone(), {
            move |stream, src_addr| {
                let tunnel = tunnel.clone();
                let sniffer = sniffer.clone();
                let name = name.clone();
                async move {
                    if let Err(e) =
                        handle_tproxy_conn(tunnel, stream, src_addr, bound_addr, sniffer, name)
                            .await
                    {
                        debug!("TProxy connection error from {src_addr}: {e}");
                    }
                }
            }
        })
        .await
    }
}

/// Accept loop bounded by an optional `max_connections` semaphore: a permit
/// is acquired *before* `accept()` (back-pressuring the TCP listen queue
/// instead of spawning unboundedly and bloating RSS — issue #435) and
/// released once `handle`'s future completes. `max_connections == 0`
/// disables the cap.
///
/// Extracted as a free function generic over the per-connection handler so
/// the concurrency-cap invariant can be pinned by a unit test (see `tests`
/// below) without needing a live firewall/redirect setup, which
/// [`TProxyListener::run_on`] requires before reaching this loop.
async fn bounded_accept_loop<F, Fut>(
    listener: TcpListener,
    max_connections: usize,
    name: String,
    mut handle: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: FnMut(TcpStream, SocketAddr) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let conn_limit: Option<Arc<Semaphore>> = if max_connections > 0 {
        Some(Arc::new(Semaphore::new(max_connections)))
    } else {
        None
    };
    let mut warned_saturated = false;

    loop {
        let permit = if let Some(sem) = &conn_limit {
            let sem = Arc::clone(sem);
            if sem.available_permits() == 0 && !warned_saturated {
                warn!(
                    "TProxy listener '{}' saturated at {} concurrent connections; new clients will queue",
                    name, max_connections
                );
                warned_saturated = true;
            }
            match sem.acquire_owned().await {
                Ok(p) => {
                    if warned_saturated {
                        debug!("TProxy listener '{}' has free capacity again", name);
                        warned_saturated = false;
                    }
                    Some(p)
                }
                Err(_) => return Ok(()), // semaphore closed → shutdown
            }
        } else {
            None
        };

        // Log-and-continue on accept errors (matching mixed.rs) rather than
        // propagating: a transient EMFILE/ECONNABORTED must not tear down
        // `run_on`'s `_firewall` guard and take the redirect rules with it.
        // Logged at error! (not debug!) so fd-exhaustion events are visible
        // at default log levels, mirroring mixed.rs's accept-error handling.
        let (stream, src_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("TProxy listener '{}' accept error: {e}", name);
                drop(permit);
                continue;
            }
        };

        let fut = handle(stream, src_addr);
        tokio::spawn(async move {
            fut.await;
            drop(permit);
        });
    }
}

/// Collect all upstream proxy server IPs from the tunnel's proxy map.
/// These IPs must be excluded from firewall redirection to prevent loops.
fn collect_proxy_server_ips(tunnel: &Tunnel) -> Vec<IpAddr> {
    let route = tunnel.route_snapshot();
    let proxies = &route.proxies;
    let mut ips = HashSet::new();

    for proxy in proxies.values() {
        let addr_str = proxy.addr();
        if addr_str.is_empty() {
            continue;
        }

        // Try parsing as ip:port directly
        if let Ok(sock) = addr_str.parse::<SocketAddr>() {
            ips.insert(sock.ip());
            continue;
        }

        // Try parsing as just an IP
        if let Ok(ip) = addr_str.parse::<IpAddr>() {
            ips.insert(ip);
            continue;
        }

        // Try DNS resolution for host:port
        if let Ok(resolved) = addr_str.to_socket_addrs() {
            for sock in resolved {
                ips.insert(sock.ip());
            }
        }
    }

    let result: Vec<IpAddr> = ips.into_iter().collect();
    info!(
        "Collected {} upstream proxy IPs for firewall bypass: {:?}",
        result.len(),
        result
    );
    result
}

async fn handle_tproxy_conn(
    tunnel: Tunnel,
    mut stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Recover the original destination address
    let orig_dst = orig_dest::get_original_dst(&stream, listen_addr)?;

    // Skip connections where original dest equals listen addr (self-connection)
    if orig_dst == listen_addr {
        return Err("original destination is the listen address (loop detected)".into());
    }

    // Build initial metadata with IP-literal host for sniffer / DNS-snoop.
    let mut metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::TProxy,
        src_ip: Some(src_addr.ip()),
        src_port: src_addr.port(),
        dst_ip: Some(orig_dst.ip()),
        dst_port: orig_dst.port(),
        in_name: name.into(),
        in_port: listen_addr.port(),
        ..Default::default()
    };

    // Recover hostname:
    // 1. SnifferRuntime (TLS SNI or HTTP Host) — replaces the old enable_sni path
    // 2. Fall back to DNS snooping reverse lookup (IP → domain from recent DNS queries)
    if let Some(rt) = sniffer.as_deref() {
        rt.sniff(&stream, &mut metadata).await;
    }

    let mut hostname = metadata.sniff_host.clone();
    if hostname.is_empty() {
        if let Some(domain) = tunnel.resolver().reverse_lookup(orig_dst.ip()) {
            hostname = domain;
        }
    }

    // Prefer sniff_host for display but fall back to DNS-snooped hostname.
    metadata.host = hostname;

    debug!(
        "TProxy {} -> {} (host: {})",
        src_addr,
        orig_dst,
        if metadata.host.is_empty() {
            "<none>"
        } else {
            &metadata.host
        }
    );

    let inner = tunnel.inner();
    let admission = inner.tcp_admission();
    let Some((proxy, rule_name, rule_payload)) = inner.resolve_proxy(&metadata) else {
        return Err("no matching rule".into());
    };

    info!(
        "{} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    let Some(_guard) = admission.track(
        metadata.pure(),
        rule_name,
        rule_payload,
        smallvec![Arc::from(proxy.name())],
    ) else {
        return Ok(());
    };

    // Relay buffers on the future's stack — zero per-relay heap allocation (ADR-0011 T6).
    let mut relay_buf_up = [0u8; RELAY_BUF_SIZE];
    let mut relay_buf_dn = [0u8; RELAY_BUF_SIZE];

    _guard
        .run_until_closed(async {
            match with_dial_timeout(proxy.name(), proxy.dial_tcp(&metadata)).await {
                Ok(mut remote) => {
                    let up = Arc::clone(_guard.counters());
                    let dn = Arc::clone(_guard.counters());
                    match copy_bidirectional_buf_tracked(
                        &mut stream,
                        &mut remote,
                        &mut relay_buf_up,
                        &mut relay_buf_dn,
                        |n| {
                            inner
                                .stats
                                .record_upload(&up, n as meow_common::atomic::Int);
                        },
                        |n| {
                            inner
                                .stats
                                .record_download(&dn, n as meow_common::atomic::Int);
                        },
                    )
                    .await
                    {
                        Ok((up, down)) => {
                            debug!("TProxy relay closed: up={up} down={down}");
                        }
                        Err(e) => debug!("TProxy relay error: {e}"),
                    }
                }
                Err(e) => warn!("TProxy dial error: {e}"),
            }
        })
        .await;
    // _guard drops here, removing the entry from Statistics.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::{mpsc, Notify};

    /// Regression test for issue #435: a `max_connections: N` cap must never
    /// let more than `N` handler futures run concurrently, even when far more
    /// than `N` clients connect at once.
    ///
    /// The handler blocks on a shared `Notify` until told to proceed, so the
    /// test can deterministically observe the in-flight count saturate at
    /// exactly `N` (rather than racing against real work durations).
    #[tokio::test]
    async fn accept_loop_never_exceeds_max_connections() {
        const CAP: usize = 3;
        const CLIENTS: usize = 10;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        // Signalled once `CAP` handlers are simultaneously in flight, so the
        // driver knows saturation was actually reached before releasing them.
        let saturated = Arc::new(Notify::new());

        let in_flight_h = Arc::clone(&in_flight);
        let max_observed_h = Arc::clone(&max_observed);
        let release_h = Arc::clone(&release);
        let saturated_h = Arc::clone(&saturated);

        let loop_task = tokio::spawn(async move {
            bounded_accept_loop(
                listener,
                CAP,
                "test-tproxy".to_string(),
                move |stream, _src| {
                    let in_flight = Arc::clone(&in_flight_h);
                    let max_observed = Arc::clone(&max_observed_h);
                    let release = Arc::clone(&release_h);
                    let saturated = Arc::clone(&saturated_h);
                    async move {
                        drop(stream);
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        max_observed.fetch_max(now, Ordering::SeqCst);
                        if now == CAP {
                            saturated.notify_one();
                        }
                        release.notified().await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                    }
                },
            )
            .await
        });

        // Dial all clients up front; only CAP permits exist, so at most CAP
        // handlers can be in flight no matter how many connections arrive.
        let (done_tx, mut done_rx) = mpsc::channel::<()>(CLIENTS);
        for _ in 0..CLIENTS {
            let done_tx = done_tx.clone();
            tokio::spawn(async move {
                let _ = TcpStream::connect(addr).await;
                let _ = done_tx.send(()).await;
            });
        }
        drop(done_tx);

        // Wait until the cap is actually saturated before asserting on it.
        tokio::time::timeout(Duration::from_secs(5), saturated.notified())
            .await
            .expect("cap was never saturated");
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            CAP,
            "in-flight count should sit exactly at the cap once saturated"
        );

        // Release handlers one at a time; the in-flight count must never
        // exceed CAP as the remaining queued clients get admitted.
        for _ in 0..CLIENTS {
            release.notify_one();
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert!(
                in_flight.load(Ordering::SeqCst) <= CAP,
                "in-flight count exceeded the configured cap"
            );
        }

        // Drain remaining client-side completions (best-effort; some may
        // have failed to dial if the OS backlog was briefly full).
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            for _ in 0..CLIENTS {
                done_rx.recv().await;
            }
        })
        .await;

        loop_task.abort();
        assert_eq!(
            max_observed.load(Ordering::SeqCst),
            CAP,
            "cap should have been reached but never exceeded"
        );
    }

    /// Regression test for the `max_connections == 0` sentinel: it must
    /// disable the cap entirely (no semaphore), letting far more handler
    /// futures run concurrently than any small numeric cap would allow.
    #[tokio::test]
    async fn accept_loop_unbounded_when_max_connections_is_zero() {
        // Deliberately larger than any small cap (e.g. the CAP=3 used by
        // `accept_loop_never_exceeds_max_connections`) so saturating this
        // many concurrent handlers proves `0` truly means unbounded rather
        // than merely "a bigger-than-3 limit".
        const CLIENTS: usize = 20;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        // Signalled once all CLIENTS handlers are simultaneously in flight,
        // proving no cap ever throttled admission below that count.
        let all_in_flight = Arc::new(Notify::new());

        let in_flight_h = Arc::clone(&in_flight);
        let max_observed_h = Arc::clone(&max_observed);
        let release_h = Arc::clone(&release);
        let all_in_flight_h = Arc::clone(&all_in_flight);

        let loop_task = tokio::spawn(async move {
            bounded_accept_loop(
                listener,
                0, // unlimited sentinel
                "test-tproxy-unbounded".to_string(),
                move |stream, _src| {
                    let in_flight = Arc::clone(&in_flight_h);
                    let max_observed = Arc::clone(&max_observed_h);
                    let release = Arc::clone(&release_h);
                    let all_in_flight = Arc::clone(&all_in_flight_h);
                    async move {
                        drop(stream);
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        max_observed.fetch_max(now, Ordering::SeqCst);
                        if now == CLIENTS {
                            all_in_flight.notify_one();
                        }
                        release.notified().await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                    }
                },
            )
            .await
        });

        let (done_tx, mut done_rx) = mpsc::channel::<()>(CLIENTS);
        for _ in 0..CLIENTS {
            let done_tx = done_tx.clone();
            tokio::spawn(async move {
                let _ = TcpStream::connect(addr).await;
                let _ = done_tx.send(()).await;
            });
        }
        drop(done_tx);

        // With no cap, all CLIENTS handlers must be able to run at once —
        // none should be blocked waiting for a permit.
        tokio::time::timeout(Duration::from_secs(5), all_in_flight.notified())
            .await
            .expect("all handlers should have been admitted concurrently with max_connections=0");
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            CLIENTS,
            "unbounded accept loop should admit every connection without queuing"
        );

        release.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            for _ in 0..CLIENTS {
                done_rx.recv().await;
            }
        })
        .await;

        loop_task.abort();
        assert_eq!(
            max_observed.load(Ordering::SeqCst),
            CLIENTS,
            "max_connections=0 must allow more concurrent handlers than any small cap"
        );
    }

    #[test]
    fn default_max_connections_matches_mixed_listener_default() {
        // Kept as separate constants (see DEFAULT_MAX_CONNECTIONS doc comment)
        // but they must stay numerically in sync with the config default of
        // 256 (`meow_config`'s `raw.max_connections.unwrap_or(256)`).
        assert_eq!(DEFAULT_MAX_CONNECTIONS, 256);
    }
}
