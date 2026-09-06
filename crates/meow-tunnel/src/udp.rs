use crate::tunnel::TunnelInner;
use dashmap::DashMap;
use meow_common::atomic::AtomicU;
use meow_common::{with_dial_timeout, Metadata, ProxyPacketConn};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Idle timeout before a UDP NAT session is swept. Matches upstream mihomo-go.
pub const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(60);

/// How often the sweeper scans for expired sessions.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// NAT table entry for UDP sessions.
// M2 layout change (ADR-0011 T3):
//   proxy_name: String (24 B) → Arc<str> (16 B fat-ptr, −8 B per struct
//   instance). Note this is *not* interning: the slow path in `handle_udp`
//   builds a fresh `Arc::from(proxy.name())` per dial, so two sessions using
//   the same proxy each hold their own heap allocation, not a shared one.
pub struct UdpSession {
    pub conn: Box<dyn ProxyPacketConn>,
    pub proxy_name: Arc<str>,
    /// Monotonic millis since process start. Bumped on every fast-path forward
    /// so idle sessions can be evicted by [`spawn_nat_sweeper`].
    last_activity_ms: AtomicU,
}

impl UdpSession {
    pub fn new(conn: Box<dyn ProxyPacketConn>, proxy_name: Arc<str>) -> Self {
        Self {
            conn,
            proxy_name,
            last_activity_ms: AtomicU::new(monotonic_ms() as meow_common::atomic::Uint),
        }
    }

    /// Mark the session active as of now. Called on every outbound fast-path
    /// forward so [`spawn_nat_sweeper`] keeps the entry alive. `pub` so an
    /// out-of-crate reply reader (e.g. the meow-ios FFI, which owns the
    /// inbound read loop) can refresh the same clock on server→app traffic —
    /// otherwise a receive-active / send-quiet session is wrongly swept.
    pub fn touch(&self) {
        self.last_activity_ms.store(
            monotonic_ms() as meow_common::atomic::Uint,
            Ordering::Relaxed,
        );
    }

    /// Time since the last [`touch`](Self::touch). `pub` so an out-of-crate
    /// reply reader can gate its own idle backstop on the same bidirectional
    /// clock the sweeper uses, instead of a one-directional wall-clock timer.
    pub fn idle_for(&self) -> Duration {
        let now = monotonic_ms() as meow_common::atomic::Uint;
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; u32→u64 widening on mips32"
        )]
        Duration::from_millis(u64::from(now.wrapping_sub(last)))
    }
}

fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

// Direction A (ADR-0008 §6): key is a (src, dst) SocketAddr tuple — zero heap
// allocation on the per-packet fast path, replacing the previous String built
// by `format!("{}:{}", src, metadata.remote_address())`.
pub type NatTable = Arc<DashMap<(SocketAddr, SocketAddr), Arc<UdpSession>>>;

pub fn new_nat_table() -> NatTable {
    Arc::new(DashMap::new())
}

/// Spawn the background sweeper that evicts UDP NAT sessions idle for more
/// than `idle`. Scans every `interval`. The task exits when the caller drops
/// the returned `JoinHandle`'s aborter (or the last Arc to the table is
/// dropped and the weak upgrade fails).
pub fn spawn_nat_sweeper(
    nat_table: &NatTable,
    idle: Duration,
    interval: Duration,
) -> JoinHandle<()> {
    let weak = Arc::downgrade(nat_table);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately; skip it.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let Some(table) = weak.upgrade() else {
                debug!("UDP NAT sweeper: table dropped, exiting");
                return;
            };
            let before = table.len();
            if before == 0 {
                continue;
            }
            table.retain(|_key, session| session.idle_for() < idle);
            let evicted = before.saturating_sub(table.len());
            if evicted > 0 {
                debug!(
                    "UDP NAT sweeper: evicted {evicted} idle sessions (remaining {})",
                    table.len()
                );
            }
        }
    })
}

/// Handle a UDP packet: look up or create a NAT session.
pub async fn handle_udp(
    tunnel: &TunnelInner,
    data: &[u8],
    src: SocketAddr,
    mut metadata: Metadata,
) {
    // Fake-IP → host rewrite (no-op outside fake-IP mode aside from a
    // snooping-cache hostname fill-in).
    tunnel.pre_handle_metadata(&mut metadata);

    // Pre-resolve metadata (host -> real IP if rules need it). UDP keeps
    // the eager pre_resolve + resolve_proxy pair (no lazy enrichment): the
    // NAT session key below requires a resolved dst_ip regardless of what
    // the rules demand.
    tunnel.pre_resolve(&mut metadata).await;

    // Rule-demand gating is only an optimization. UDP still requires a real
    // address for its NAT key and outbound packet API, including after a
    // fake-IP was rewritten back to a hostname under domain-only rules.
    if metadata.dst_ip.is_none() && !metadata.host.is_empty() {
        metadata.dst_ip = tunnel.resolver.resolve_ip_real(&metadata.host).await;
    }

    // Build destination SocketAddr for the NAT key.
    // pre_resolve() populates dst_ip for any hostname; if it is still None
    // after that (resolution failure or unresolvable host), we cannot track
    // the session and must discard the packet.
    let Some(dst_ip) = metadata.dst_ip else {
        warn!(
            "UDP {}: dst_ip not resolved after pre_resolve — dropping",
            metadata.remote_address()
        );
        return;
    };
    let dst_addr = SocketAddr::new(dst_ip, metadata.dst_port);
    let key = (src, dst_addr);

    // Fast path: existing session — forward and return.
    //
    // Clone the `Arc<UdpSession>` out and DROP the DashMap guard before the
    // `.await` below. `nat_table.get()` returns a `Ref` that holds a *read*
    // lock on the key's shard for as long as it is alive. Two ways the old
    // `if let Some(session) = nat_table.get(&key)` form deadlocked:
    //   1. The guard was held across `write_packet().await`, so while this task
    //      parked on the upstream round-trip the shard read-lock stayed held,
    //      blocking every same-shard `insert`/`remove`/sweep.
    //   2. On a write error it called `nat_table.remove(&key)` — a *write* lock
    //      on the very shard whose read-lock the `session` guard still held.
    //      A read+write on the same shard from one thread self-deadlocks the
    //      shard's RwLock, parking the worker forever; on the 2-worker iOS
    //      runtime both workers then wedge → total packet stall + dead control
    //      API. Fires whenever an established session's upstream has died and
    //      the app sends another datagram (common for QUIC / long-lived UDP).
    // Holding only the cloned `Arc` keeps the session alive with no lock held.
    let existing = tunnel.nat_table.get(&key).map(|s| Arc::clone(s.value()));
    if let Some(session) = existing {
        if let Err(e) = session.conn.write_packet(data, &dst_addr).await {
            debug!("UDP write error for {} -> {}: {}", src, dst_addr, e);
            // Compare-and-remove: evict only the session that actually failed.
            // While this write was parked a concurrent slow path may have
            // replaced the entry with a fresh healthy session; an
            // unconditional `remove()` would tear that replacement down and
            // force the next packet to redial (issue #432).
            tunnel
                .nat_table
                .remove_if(&key, |_, s| Arc::ptr_eq(s, &session));
        } else {
            session.touch();
        }
        return;
    }

    // Slow path: all client UDP, including port 53, follows routing policy.
    let Some((proxy, rule_name, rule_payload)) = tunnel.resolve_proxy(&metadata) else {
        warn!("no matching rule for UDP {}", metadata.remote_address());
        return;
    };

    info!(
        "UDP {} --> {} match {}({}) using {}",
        src,
        dst_addr,
        rule_name,
        rule_payload,
        proxy.name()
    );

    // Bounded like mihomo's `C.DefaultUDPTimeout`. An unbounded dial here is
    // worse than on TCP: the key is still unclaimed (see below), so every
    // datagram of the flow starts its own stalled dial.
    match with_dial_timeout(proxy.name(), proxy.dial_udp(&metadata)).await {
        Ok(conn) => {
            let session = Arc::new(UdpSession::new(conn, Arc::from(proxy.name())));
            // Claim the key atomically before the first write. The dial above
            // is a long await with the key unclaimed, so two concurrent
            // handle_udp calls for the same brand-new (src, dst) can both
            // reach this point; a blind `insert` here made the second call
            // silently drop — and thereby close — the first session with the
            // reply to its datagram still in flight (issue #432).
            // `entry().or_insert_with()` takes the shard write lock but has no
            // `.await` inside, and the guard is dropped before the write
            // below, so this cannot reintroduce the guard-across-await
            // deadlock fixed in 1454ef2.
            let winner = Arc::clone(
                tunnel
                    .nat_table
                    .entry(key)
                    .or_insert_with(|| Arc::clone(&session))
                    .value(),
            );
            if !Arc::ptr_eq(&winner, &session) {
                // Lost the claim: a concurrent call installed its session
                // first. Close the redundant conn and carry this datagram on
                // the winner, so exactly one upstream flow ever sees traffic.
                debug!(
                    "UDP concurrent session create for {} -> {}: folding into winner",
                    src, dst_addr
                );
                if let Err(e) = session.conn.close() {
                    debug!(
                        "UDP close of redundant conn for {} -> {}: {}",
                        src, dst_addr, e
                    );
                }
            }
            if let Err(e) = winner.conn.write_packet(data, &dst_addr).await {
                warn!("UDP initial write error for {} -> {}: {}", src, dst_addr, e);
                tunnel
                    .nat_table
                    .remove_if(&key, |_, s| Arc::ptr_eq(s, &winner));
            }
        }
        Err(e) => {
            warn!("UDP dial error for {} -> {}: {}", src, dst_addr, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::Tunnel;
    use async_trait::async_trait;
    use meow_common::adapter::ProxyAdapter;
    use meow_common::error::Result as MeowResult;
    use meow_common::{
        AdapterType, DelayHistory, DnsMode, MeowError, Network, Proxy, ProxyConn, ProxyHealth,
        TunnelMode,
    };
    use smol_str::SmolStr;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Mutex;

    fn mk_tunnel() -> Tunnel {
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        Tunnel::new(resolver)
    }

    fn mk_metadata(src: SocketAddr, dst: SocketAddr) -> Metadata {
        Metadata {
            network: Network::Udp,
            src_ip: Some(src.ip()),
            src_port: src.port(),
            dst_ip: Some(dst.ip()),
            dst_port: dst.port(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn udp_port_53_obeys_reject_rule() {
        let tunnel = mk_tunnel();
        tunnel.update_proxies(
            meow_config::rebuild_from_raw(&Default::default())
                .unwrap()
                .0,
        );
        tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
            "REJECT",
        ))]);
        let src = "127.0.0.1:12345".parse().unwrap();
        for port in [53, 5353] {
            let dst = SocketAddr::from(([127, 0, 0, 1], port));
            handle_udp(
                tunnel.inner(),
                b"not a DNS query",
                src,
                mk_metadata(src, dst),
            )
            .await;
            let session = tunnel.inner().nat_table.get(&(src, dst)).unwrap();
            assert_eq!(&*session.proxy_name, "REJECT");
            assert!(
                session.conn.local_addr().is_err(),
                "must not open a DIRECT socket"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn udp_port_53_obeys_proxy_rule_and_global_mode() {
        for mode in [TunnelMode::Rule, TunnelMode::Global] {
            let tunnel = mk_tunnel();
            tunnel.set_mode(mode);
            let proxy = Arc::new(SlowDialProxy::new());
            let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
            proxies.insert("GLOBAL".into(), Arc::clone(&proxy) as Arc<dyn Proxy>);
            tunnel.update_proxies(proxies);
            tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
                "GLOBAL",
            ))]);
            let src = "127.0.0.1:12345".parse().unwrap();
            let dst = "127.0.0.1:53".parse().unwrap();
            handle_udp(tunnel.inner(), b"query", src, mk_metadata(src, dst)).await;
            assert_eq!(proxy.dials.load(Ordering::SeqCst), 1);
            assert_eq!(proxy.conns.lock().unwrap()[0].0.load(Ordering::SeqCst), 1);
        }
    }

    struct NoopPacketConn;

    #[async_trait]
    impl ProxyPacketConn for NoopPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> MeowResult<usize> {
            Ok(buf.len())
        }
        fn local_addr(&self) -> MeowResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MeowResult<()> {
            Ok(())
        }
    }

    fn mk_session() -> Arc<UdpSession> {
        Arc::new(UdpSession::new(Box::new(NoopPacketConn), Arc::from("test")))
    }

    /// A packet conn whose `write_packet` always fails — models an established
    /// UDP session whose upstream relay has died. Used to drive the fast-path
    /// write-error branch in `handle_udp`.
    struct FailingPacketConn;

    #[async_trait]
    impl ProxyPacketConn for FailingPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, _buf: &[u8], _addr: &SocketAddr) -> MeowResult<usize> {
            Err(meow_common::MeowError::Other("upstream dead".into()))
        }
        fn local_addr(&self) -> MeowResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MeowResult<()> {
            Ok(())
        }
    }

    fn mk_key(port: u16) -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::from(([127, 0, 0, 1], port)),
            SocketAddr::from(([8, 8, 8, 8], 53)),
        )
    }

    #[tokio::test(start_paused = false)]
    async fn sweeper_evicts_idle_sessions() {
        let table = new_nat_table();
        table.insert(mk_key(1), mk_session());
        table.insert(mk_key(2), mk_session());
        assert_eq!(table.len(), 2);

        let _handle =
            spawn_nat_sweeper(&table, Duration::from_millis(50), Duration::from_millis(20));

        // Wait past the idle threshold; sweeper runs every 20ms.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(table.len(), 0, "idle sessions should have been swept");
    }

    #[tokio::test(start_paused = false)]
    async fn touched_sessions_are_kept() {
        let table = new_nat_table();
        let session = mk_session();
        table.insert(mk_key(1), Arc::clone(&session));

        let _handle =
            spawn_nat_sweeper(&table, Duration::from_millis(80), Duration::from_millis(20));

        // Touch repeatedly so the session stays young.
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(25)).await;
            session.touch();
        }
        assert_eq!(table.len(), 1, "active session must not be evicted");
    }

    #[tokio::test(start_paused = false)]
    async fn sweeper_exits_when_table_dropped() {
        let table = new_nat_table();
        table.insert(mk_key(1), mk_session());
        let handle = spawn_nat_sweeper(&table, Duration::from_secs(60), Duration::from_millis(20));
        drop(table);
        // Allow the next tick to observe the dropped table.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            handle.is_finished(),
            "sweeper should exit once the table is dropped"
        );
    }

    /// Regression: a fast-path write failure on an existing session must evict
    /// the entry and return promptly. The previous code held the
    /// `nat_table.get()` shard read-guard across `write_packet().await` and then
    /// called `nat_table.remove()` (same-shard write lock) while the read-guard
    /// was still alive — a self-deadlock that hangs forever. The `timeout` here
    /// fails the test instead of hanging CI if that pattern is reintroduced.
    #[tokio::test(start_paused = false)]
    async fn fast_path_write_failure_evicts_without_deadlock() {
        let tunnel = mk_tunnel();

        // Literal-IP destination so pre_resolve is a no-op and the NAT key is
        // deterministic. Insert a session whose upstream write always fails.
        let src = SocketAddr::from(([127, 0, 0, 1], 5555));
        let dst = SocketAddr::from(([198, 51, 100, 7], 443));
        let key = (src, dst);
        tunnel.inner().nat_table.insert(
            key,
            Arc::new(UdpSession::new(
                Box::new(FailingPacketConn),
                Arc::from("test"),
            )),
        );

        tokio::time::timeout(
            Duration::from_secs(2),
            handle_udp(tunnel.inner(), b"ping", src, mk_metadata(src, dst)),
        )
        .await
        .expect("handle_udp must not deadlock on a fast-path write failure");

        assert!(
            tunnel.inner().nat_table.get(&key).is_none(),
            "a session with a dead upstream must be evicted"
        );
    }

    /// Packet conn that records every write and whether it has been closed,
    /// via handles shared with the test body.
    struct RecordingPacketConn {
        writes: Arc<AtomicUsize>,
        closed: Arc<AtomicBool>,
    }

    #[async_trait]
    impl ProxyPacketConn for RecordingPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> MeowResult<usize> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(buf.len())
        }
        fn local_addr(&self) -> MeowResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MeowResult<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Mock proxy whose `dial_udp` sleeps before returning, widening the
    /// dial-then-insert window so two concurrent `handle_udp` calls for the
    /// same (src, dst) both reach the NAT insert. Hands out
    /// [`RecordingPacketConn`]s and keeps their (writes, closed) handles.
    struct SlowDialProxy {
        dials: AtomicUsize,
        conns: Mutex<Vec<(Arc<AtomicUsize>, Arc<AtomicBool>)>>,
        health: ProxyHealth,
    }

    impl SlowDialProxy {
        fn new() -> Self {
            Self {
                dials: AtomicUsize::new(0),
                conns: Mutex::new(Vec::new()),
                health: ProxyHealth::new(),
            }
        }
    }

    #[async_trait]
    impl ProxyAdapter for SlowDialProxy {
        fn name(&self) -> &str {
            "slow-mock"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            true
        }
        async fn dial_tcp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
            Err(MeowError::NotSupported("slow-mock: tcp".into()))
        }
        async fn dial_udp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            let writes = Arc::new(AtomicUsize::new(0));
            let closed = Arc::new(AtomicBool::new(false));
            self.conns
                .lock()
                .unwrap()
                .push((Arc::clone(&writes), Arc::clone(&closed)));
            Ok(Box::new(RecordingPacketConn { writes, closed }))
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    impl Proxy for SlowDialProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            Vec::new()
        }
    }

    /// Regression for issue #432 (slow path): two concurrent `handle_udp`
    /// calls for the same brand-new (src, dst) both miss the NAT table and
    /// both dial (the check-then-act window), but the atomic claim must fold
    /// them into exactly one surviving session — the loser's conn is closed
    /// without ever carrying traffic, and the loser's datagram is re-sent on
    /// the winner. Before the fix the second blind `insert` silently dropped
    /// the first session with its datagram's reply in flight.
    #[tokio::test(start_paused = true)]
    async fn concurrent_first_packets_fold_into_single_session() {
        let tunnel = mk_tunnel();
        tunnel.set_mode(TunnelMode::Global);
        let proxy = Arc::new(SlowDialProxy::new());
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(
            SmolStr::new_static("GLOBAL"),
            Arc::clone(&proxy) as Arc<dyn Proxy>,
        );
        tunnel.update_proxies(proxies);

        let src = SocketAddr::from(([127, 0, 0, 1], 6666));
        let dst = SocketAddr::from(([198, 51, 100, 8], 443));
        let key = (src, dst);

        tokio::join!(
            handle_udp(tunnel.inner(), b"ping-a", src, mk_metadata(src, dst)),
            handle_udp(tunnel.inner(), b"ping-b", src, mk_metadata(src, dst)),
        );

        // Both calls raced past the NAT-miss check before either inserted, so
        // both dialled — the claim must still leave exactly one session.
        assert_eq!(
            proxy.dials.load(Ordering::SeqCst),
            2,
            "test premise: both calls must overlap in the dial window"
        );
        assert_eq!(tunnel.inner().nat_table.len(), 1);
        assert!(tunnel.inner().nat_table.get(&key).is_some());

        let conns = proxy.conns.lock().unwrap();
        let (open, lost): (Vec<_>, Vec<_>) = conns
            .iter()
            .partition(|(_, closed)| !closed.load(Ordering::SeqCst));
        assert_eq!(open.len(), 1, "exactly one conn must survive");
        assert_eq!(lost.len(), 1, "the losing conn must be closed");
        assert_eq!(
            open[0].0.load(Ordering::SeqCst),
            2,
            "both datagrams must be carried on the winning conn"
        );
        assert_eq!(
            lost[0].0.load(Ordering::SeqCst),
            0,
            "the losing conn must never carry traffic"
        );
    }

    /// Conn that, when written to, first installs `replacement` at `key` —
    /// playing the part of a concurrent slow path that dialled a fresh
    /// session while this write was in flight — and then fails the write.
    struct SwapOnFailConn {
        table: NatTable,
        key: (SocketAddr, SocketAddr),
        replacement: Arc<UdpSession>,
    }

    #[async_trait]
    impl ProxyPacketConn for SwapOnFailConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, _buf: &[u8], _addr: &SocketAddr) -> MeowResult<usize> {
            self.table.insert(self.key, Arc::clone(&self.replacement));
            Err(MeowError::Other("upstream dead".into()))
        }
        fn local_addr(&self) -> MeowResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MeowResult<()> {
            Ok(())
        }
    }

    /// Regression for issue #432 (fast path): a write failure on an existing
    /// session must evict only the session that failed. If a concurrent slow
    /// path has already replaced the entry with a fresh healthy session, the
    /// old unconditional `remove(&key)` tore the replacement down and forced
    /// the next packet to redial.
    #[tokio::test]
    async fn fast_path_failure_keeps_concurrent_replacement_session() {
        let tunnel = mk_tunnel();

        let src = SocketAddr::from(([127, 0, 0, 1], 7777));
        let dst = SocketAddr::from(([198, 51, 100, 9], 443));
        let key = (src, dst);

        let replacement = mk_session();
        tunnel.inner().nat_table.insert(
            key,
            Arc::new(UdpSession::new(
                Box::new(SwapOnFailConn {
                    table: Arc::clone(&tunnel.inner().nat_table),
                    key,
                    replacement: Arc::clone(&replacement),
                }),
                Arc::from("test"),
            )),
        );

        handle_udp(tunnel.inner(), b"ping", src, mk_metadata(src, dst)).await;

        let current = tunnel
            .inner()
            .nat_table
            .get(&key)
            .map(|s| Arc::clone(s.value()));
        assert!(
            current.is_some_and(|s| Arc::ptr_eq(&s, &replacement)),
            "the fresh replacement session must survive the failed session's eviction"
        );
    }

    /// A proxy whose dial never resolves — a server that completes the TCP/QUIC
    /// handshake and then goes silent mid-protocol.
    struct StalledDialProxy {
        health: ProxyHealth,
    }

    #[async_trait]
    impl ProxyAdapter for StalledDialProxy {
        fn name(&self) -> &str {
            "stalled-mock"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            true
        }
        async fn dial_tcp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
            std::future::pending().await
        }
        async fn dial_udp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
            std::future::pending().await
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    impl Proxy for StalledDialProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            Vec::new()
        }
    }

    /// A dial that never completes must not park the caller forever. Without
    /// the `DIAL_TIMEOUT` bound this test hangs: every datagram of the flow
    /// spawns another immortal task, since the NAT key is only claimed after
    /// the dial returns.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_dial_gives_up_instead_of_parking_the_flow() {
        let tunnel = mk_tunnel();
        tunnel.set_mode(TunnelMode::Global);
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(
            SmolStr::new_static("GLOBAL"),
            Arc::new(StalledDialProxy {
                health: ProxyHealth::new(),
            }) as Arc<dyn Proxy>,
        );
        tunnel.update_proxies(proxies);

        let src = SocketAddr::from(([127, 0, 0, 1], 8888));
        let dst = SocketAddr::from(([198, 51, 100, 10], 443));

        let start = tokio::time::Instant::now();
        handle_udp(tunnel.inner(), b"ping", src, mk_metadata(src, dst)).await;

        assert_eq!(start.elapsed(), meow_common::DIAL_TIMEOUT);
        assert!(
            tunnel.inner().nat_table.is_empty(),
            "a dial that never completed must not leave a session behind"
        );
    }
}
