//! Inbound protocol listeners for the meow-rs proxy kernel.
//!
//! Mixed, HTTP, SOCKS5, and TProxy acceptors, plus an optional TUN device
//! inbound (feature `listener-tun`).

pub mod sniffer;

pub const DEFAULT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Process-wide monotonic timestamp in milliseconds. Used by UDP flow tables
/// (SOCKS5-UDP and the shadowsocks listener) for idle eviction. The `START`
/// instant is lazily initialized on the first call and never changes.
#[cfg(any(feature = "listener-socks5", feature = "listener-shadowsocks"))]
pub(crate) fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

#[cfg(feature = "listener-http")]
pub mod http_proxy;
#[cfg(feature = "listener-mixed")]
pub mod mixed;
#[cfg(feature = "listener-shadowsocks")]
pub mod shadowsocks;
#[cfg(feature = "listener-socks5")]
pub mod socks5;
#[cfg(feature = "listener-socks5")]
mod socks5_udp;
#[cfg(feature = "listener-tproxy")]
pub mod tproxy;
#[cfg(feature = "listener-tun")]
pub mod tun;

#[cfg(feature = "listener-mixed")]
pub use mixed::MixedListener;
#[cfg(feature = "listener-shadowsocks")]
pub use shadowsocks::{ShadowsocksListener, SsObfsMode};
pub use sniffer::SnifferRuntime;
#[cfg(feature = "listener-tproxy")]
pub use tproxy::TProxyListener;
#[cfg(feature = "listener-tun")]
pub use tun::{TunListener, TunListenerConfig, TunReady, TunRouteScope};

#[cfg(all(
    test,
    any(
        feature = "listener-socks5",
        feature = "listener-tun",
        feature = "listener-shadowsocks"
    )
))]
fn test_rule_tunnel() -> meow_tunnel::Tunnel {
    let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
        vec![],
        vec![],
        meow_common::DnsMode::Normal,
        meow_trie::DomainTrie::new(),
        false,
        true,
    ));
    let tunnel = meow_tunnel::Tunnel::new(resolver);
    tunnel.update_proxies(
        meow_config::rebuild_from_raw(&Default::default())
            .unwrap()
            .0,
    );
    tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
        "REJECT",
    ))]);
    tunnel
}
