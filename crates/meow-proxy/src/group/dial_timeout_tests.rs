use super::fallback::FallbackGroup;
use super::urltest::UrlTestGroup;
use async_trait::async_trait;
use meow_common::DIAL_TIMEOUT;
use meow_common::{
    with_dial_timeout, AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter,
    ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use std::sync::Arc;
use std::time::Duration;

struct SlowProxy {
    health: ProxyHealth,
    kind: AdapterType,
}
#[async_trait]
impl ProxyAdapter for SlowProxy {
    fn name(&self) -> &str {
        "slow-node"
    }
    fn adapter_type(&self) -> AdapterType {
        self.kind
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        true
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
    async fn dial_tcp(&self, _: &Metadata) -> Result<Box<dyn ProxyConn>> {
        tokio::time::sleep(Duration::from_secs(10)).await;
        Err(MeowError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "native handshake timed out",
        )))
    }
    async fn dial_udp(&self, _: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        tokio::time::sleep(Duration::from_secs(10)).await;
        Err(MeowError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "native handshake timed out",
        )))
    }
}
impl Proxy for SlowProxy {
    fn alive(&self) -> bool {
        self.health.alive()
    }
    fn alive_for_url(&self, _: &str) -> bool {
        self.alive()
    }
    fn last_delay(&self) -> u16 {
        1
    }
    fn last_delay_for_url(&self, _: &str) -> u16 {
        1
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        vec![]
    }
}

fn group_with_member(kind: &str, member: Arc<dyn Proxy>) -> Arc<dyn Proxy> {
    match kind {
        "fallback" => Arc::new(FallbackGroup::new("fallback", vec![member])),
        "urltest" => Arc::new(UrlTestGroup::new("urltest", vec![member], 0)),
        "nested" => Arc::new(FallbackGroup::new(
            "outer",
            vec![Arc::new(UrlTestGroup::new("inner", vec![member], 0))],
        )),
        _ => unreachable!(),
    }
}

async fn dial(group: &dyn Proxy, udp: bool) -> Result<()> {
    let metadata = Metadata::default();
    if udp {
        group.dial_udp(&metadata).await.map(|_| ())
    } else {
        group.dial_tcp(&metadata).await.map(|_| ())
    }
}

async fn time_out(group: &dyn Proxy, udp: bool) {
    let started = tokio::time::Instant::now();
    let err = with_dial_timeout(group.name(), dial(group, udp))
        .await
        .unwrap_err();
    assert!(matches!(err, MeowError::Io(ref err) if err.kind() == std::io::ErrorKind::TimedOut));
    assert_eq!(started.elapsed(), DIAL_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn native_timeouts_still_mark_members_dead() {
    for kind in ["fallback", "urltest"] {
        for udp in [false, true] {
            let slow = Arc::new(SlowProxy {
                health: ProxyHealth::new(),
                kind: AdapterType::Hysteria2,
            });
            let group = group_with_member(kind, Arc::clone(&slow) as Arc<dyn Proxy>);
            let results =
                futures::future::join_all((0..5).map(|_| dial(group.as_ref(), udp))).await;
            assert!(results.iter().all(Result::is_err));
            assert!(!slow.alive(), "{kind} udp={udp}");
        }
    }
}

#[tokio::test(start_paused = true)]
async fn global_timeouts_count_once_and_track_the_selected_member() {
    for kind in ["fallback", "urltest", "nested"] {
        for udp in [false, true] {
            let slow = Arc::new(SlowProxy {
                health: ProxyHealth::new(),
                kind: AdapterType::Hysteria2,
            });
            let group = group_with_member(kind, Arc::clone(&slow) as Arc<dyn Proxy>);
            // Four overlapping expired dials must stay below the threshold.
            futures::future::join_all((0..4).map(|_| time_out(group.as_ref(), udp))).await;
            assert!(
                slow.alive(),
                "counted an expired dial twice: {kind}, udp={udp}"
            );
            time_out(group.as_ref(), udp).await;
            assert!(
                !slow.alive(),
                "expiry skipped failure tracking: {kind}, udp={udp}"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn early_cancellation_does_not_count_as_a_node_failure() {
    for kind in ["fallback", "urltest"] {
        let slow = Arc::new(SlowProxy {
            health: ProxyHealth::new(),
            kind: AdapterType::Hysteria2,
        });
        let group = group_with_member(kind, Arc::clone(&slow) as Arc<dyn Proxy>);
        for _ in 0..5 {
            tokio::time::timeout(
                Duration::from_secs(1),
                with_dial_timeout(group.name(), dial(group.as_ref(), false)),
            )
            .await
            .unwrap_err();
        }
        futures::future::join_all((0..4).map(|_| time_out(group.as_ref(), false))).await;
        assert!(
            slow.alive(),
            "early cancellation counted toward escalation: {kind}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn expired_direct_dials_remain_exempt() {
    let slow = Arc::new(SlowProxy {
        health: ProxyHealth::new(),
        kind: AdapterType::Direct,
    });
    let group = group_with_member("fallback", Arc::clone(&slow) as Arc<dyn Proxy>);
    futures::future::join_all((0..5).map(|_| time_out(group.as_ref(), false))).await;
    assert!(slow.alive());
}
