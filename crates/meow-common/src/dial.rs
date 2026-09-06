//! Global ceiling on a single outbound dial.
//!
//! Every inbound path (tunnel TCP/UDP, HTTP CONNECT, TProxy, SOCKS5-UDP, TUN,
//! the shadowsocks listener) hands its connection to a proxy adapter and awaits
//! [`ProxyAdapter::dial_tcp`]/[`dial_udp`]. Those futures are unbounded: a
//! server that completes the TCP handshake and then stalls mid-protocol —
//! blackholed VLESS/Trojan, a QUIC path that never validates, a relay chain
//! stuck on hop 2 — parks the caller forever, pinning the inbound socket, its
//! NAT/session slot, and (for group members) the health state that would
//! otherwise mark the node dead.
//!
//! mihomo bounds the same calls with `C.DefaultTCPTimeout` /
//! `C.DefaultUDPTimeout` (5 s each) around `proxy.DialContext` and
//! `proxy.ListenPacketContext` in `tunnel.handleTCPConn`. [`DIAL_TIMEOUT`] is
//! the meow-rs equivalent.
//!
//! [`ProxyAdapter::dial_tcp`]: crate::adapter::ProxyAdapter::dial_tcp
//! [`dial_udp`]: crate::adapter::ProxyAdapter::dial_udp

use std::future::Future;
use std::io;
use std::time::Duration;
use tokio::time::Instant;

use crate::error::{MeowError, Result};

/// Ceiling on one outbound dial: the adapter's own name resolution, TCP
/// connect, and whatever handshake its protocol performs before it yields a
/// stream or packet conn. Matches mihomo's `C.DefaultTCPTimeout`.
///
/// This bounds a *dial*, not a connection — an established relay runs for as
/// long as both peers keep it open.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

tokio::task_local! {
    static DIAL_DEADLINE: Instant;
}

/// Deadline of the outbound dial currently being polled on this task.
///
/// Proxy groups capture it before awaiting a member so their cancellation
/// guards can distinguish deadline expiry from an early caller cancellation.
/// The scope follows the dial future; newly spawned tasks do not inherit it.
pub fn dial_deadline() -> Option<Instant> {
    DIAL_DEADLINE.try_with(|deadline| *deadline).ok()
}

/// Run a `dial_tcp`/`dial_udp` future under [`DIAL_TIMEOUT`].
///
/// `via` names the proxy for the error message; it is only formatted on the
/// timeout path.
///
/// Nested calls reuse the original deadline, including time spent on earlier
/// relay hops. Expiry surfaces as [`io::ErrorKind::TimedOut`]. Since timeout
/// drops the pending future, group failure tracking must also handle expiry
/// in a cancellation guard; an ordinary `Err` arm alone cannot observe it.
pub async fn with_dial_timeout<F, T>(via: &str, fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let deadline = dial_deadline().unwrap_or_else(|| Instant::now() + DIAL_TIMEOUT);
    DIAL_DEADLINE
        .scope(deadline, async {
            match tokio::time::timeout_at(deadline, fut).await {
                Ok(result) => result,
                Err(_) => Err(MeowError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "dial via {via} exceeded the {}s deadline",
                        DIAL_TIMEOUT.as_secs()
                    ),
                ))),
            }
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;

    #[tokio::test]
    async fn a_completed_dial_passes_through_untouched() {
        let ok = with_dial_timeout("mock", async { Ok(7u8) }).await.unwrap();
        assert_eq!(ok, 7);
    }

    #[tokio::test]
    async fn a_failed_dial_keeps_its_own_error() {
        let err = with_dial_timeout::<_, ()>("mock", async {
            Err(MeowError::Proxy("connection refused".into()))
        })
        .await
        .unwrap_err();
        assert!(matches!(err, MeowError::Proxy(_)), "got {err:?}");
    }

    /// A server that accepts and then never speaks must not park the caller.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_dial_expires_as_timed_out() {
        let start = tokio::time::Instant::now();
        let err = with_dial_timeout::<_, ()>("🇭🇰 HK-01", pending())
            .await
            .unwrap_err();

        let MeowError::Io(io_err) = err else {
            panic!("expected an io error, got {err:?}");
        };
        assert_eq!(io_err.kind(), io::ErrorKind::TimedOut);
        assert!(io_err.to_string().contains("🇭🇰 HK-01"));
        assert_eq!(start.elapsed(), DIAL_TIMEOUT);
    }

    /// The bound is a ceiling, not a delay: a dial that finishes just under it
    /// is not slowed down, and one that finishes just over it is cut.
    #[tokio::test(start_paused = true)]
    async fn the_bound_is_exclusive_to_slow_dials() {
        let just_in_time = with_dial_timeout("mock", async {
            tokio::time::sleep(DIAL_TIMEOUT - Duration::from_millis(1)).await;
            Ok(())
        })
        .await;
        assert!(just_in_time.is_ok());

        let too_slow = with_dial_timeout("mock", async {
            tokio::time::sleep(DIAL_TIMEOUT + Duration::from_millis(1)).await;
            Ok(())
        })
        .await;
        assert!(too_slow.is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn nested_dials_share_the_original_budget() {
        let start = Instant::now();
        with_dial_timeout::<_, ()>("outer", async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            with_dial_timeout("inner", async {
                assert_eq!(dial_deadline(), Some(start + DIAL_TIMEOUT));
                pending().await
            })
            .await
        })
        .await
        .unwrap_err();
        assert_eq!(start.elapsed(), DIAL_TIMEOUT);
        assert!(
            dial_deadline().is_none(),
            "deadline must not leak out of its scope"
        );
    }
}
