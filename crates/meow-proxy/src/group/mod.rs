use meow_common::atomic::AtomicU;
use meow_common::{AdapterType, ConnType, MeowError, Metadata, Proxy};
use parking_lot::Mutex;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Lock-free traffic-use generation shared by automatic proxy groups. A lazy
/// health-check loop remembers the last generation it probed and sleeps until
/// another dial increments this counter.
pub(super) struct UsageTracker(AtomicU);

impl UsageTracker {
    pub(super) fn new() -> Self {
        Self(AtomicU::new(0))
    }

    pub(super) fn touch(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a use, but only for real user traffic.
    ///
    /// Health-check probes dial with [`ConnType::Tunnel`] — an internal
    /// marker set by `health::url_test` (no production dialer uses the
    /// variant).  Counting probes as uses would defeat lazy mode for
    /// nested groups: a parent group's periodic probes would mark a lazy
    /// child as used and keep its own probe loop awake forever without
    /// any real traffic.
    pub(super) fn touch_user_traffic(&self, metadata: &Metadata) {
        if metadata.conn_type == ConnType::Tunnel {
            return;
        }
        self.touch();
    }

    pub(super) fn generation(&self) -> u64 {
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; u32→u64 widening on targets without 64-bit atomics"
        )]
        u64::from(self.0.load(Ordering::Relaxed))
    }
}

/// Escalation threshold and window, matching mihomo's `GroupBase` defaults
/// (`maxFailedTimes = 5`, `testTimeout = 5000` ms —
/// adapter/outboundgroup/groupbase.go).
const DIAL_FAILURE_THRESHOLD: u32 = 5;
const DIAL_FAILURE_WINDOW: Duration = Duration::from_secs(5);

/// Dial-failure escalation state shared by the automatic groups, modeled on
/// mihomo's `GroupBase.onDialFailed`.
///
/// mihomo's terminal action on escalation is to force a provider health
/// check. The group layer here cannot trigger probes (the health-check loop
/// lives in meow-app), so the local equivalent is to mark the failed member
/// dead: routing stops selecting it immediately, and the next scheduled
/// group probe — guaranteed to run for a lazy group, because a dial bumps
/// the usage generation — revives members that failed only transiently.
pub(super) struct DialFailureTracker {
    state: Mutex<DialFailureState>,
}

struct DialFailureState {
    count: u32,
    first_at: Option<Instant>,
}

impl DialFailureTracker {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(DialFailureState {
                count: 0,
                first_at: None,
            }),
        }
    }

    /// mihomo resets the failure streak on dial success
    /// (`GroupBase.onDialSuccess`).
    pub(super) fn on_success(&self) {
        let mut state = self.state.lock();
        state.count = 0;
        state.first_at = None;
    }

    /// Record a failed dial; returns `true` when the failure should escalate
    /// (the caller then marks the failed member dead).
    pub(super) fn on_failure(&self, err: &MeowError) -> bool {
        // mihomo ignores C.ErrNotSupport failures outright; meow splits that
        // sentinel into `NotSupported` and `UdpNotSupported`. Both describe a
        // member's capabilities, not its health (e.g. a relay chain without
        // UDP support), so neither may count toward marking a member dead.
        if matches!(err, MeowError::NotSupported(_) | MeowError::UdpNotSupported) {
            return false;
        }
        // mihomo escalates immediately on "connection refused" and leaves the
        // streak untouched.
        if err.to_string().contains("refused") {
            return true;
        }
        let mut state = self.state.lock();
        state.count += 1;
        if state.count == 1 {
            state.first_at = Some(Instant::now());
            return false;
        }
        if state
            .first_at
            .is_some_and(|at| Instant::now().duration_since(at) > DIAL_FAILURE_WINDOW)
        {
            // mihomo drops the stale streak and starts a fresh window.
            state.count = 0;
            state.first_at = None;
            return false;
        }
        if state.count >= DIAL_FAILURE_THRESHOLD {
            state.count = 0;
            state.first_at = None;
            return true;
        }
        false
    }
}

/// Shared dial-failure policy for automatic groups, mirroring the exemptions
/// in mihomo's `GroupBase.onDialFailed`: adapter types whose dial errors
/// describe the *target* (Direct / Reject family) are never tracked, and
/// everything else escalates through the group's [`DialFailureTracker`].
/// Escalation marks the failed member dead — see [`DialFailureTracker`] for
/// why this stands in for mihomo's forced health check.
pub(super) fn record_dial_failure(
    group_name: &str,
    tracker: &DialFailureTracker,
    member: &Arc<dyn Proxy>,
    err: &MeowError,
) {
    if matches!(
        member.adapter_type(),
        AdapterType::Direct | AdapterType::Reject | AdapterType::RejectDrop
    ) {
        return;
    }
    if tracker.on_failure(err) {
        debug!(
            "proxy-group '{group_name}': marking member '{}' dead after repeated dial failures",
            member.name()
        );
        member.health().set_alive(false);
    }
}

/// Tracks the selected member even when an outer dial deadline drops the
/// group future before its error arm can run. Capturing the deadline avoids
/// consulting task-local state during destruction. Ordinary cancellation
/// before expiry is not a node failure, and completed dials are counted once.
struct DialAttempt<'a> {
    group_name: &'a str,
    tracker: &'a DialFailureTracker,
    member: &'a Arc<dyn Proxy>,
    deadline: Option<tokio::time::Instant>,
}

impl<'a> DialAttempt<'a> {
    fn new(
        group_name: &'a str,
        tracker: &'a DialFailureTracker,
        member: &'a Arc<dyn Proxy>,
    ) -> Self {
        Self {
            group_name,
            tracker,
            member,
            deadline: meow_common::dial::dial_deadline(),
        }
    }

    fn finish<T>(mut self, result: meow_common::Result<T>) -> meow_common::Result<T> {
        self.deadline = None;
        match &result {
            Ok(_) => self.tracker.on_success(),
            Err(err) => record_dial_failure(self.group_name, self.tracker, self.member, err),
        }
        result
    }
}

impl Drop for DialAttempt<'_> {
    fn drop(&mut self) {
        if self
            .deadline
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            let err = MeowError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "outbound dial deadline elapsed",
            ));
            record_dial_failure(self.group_name, self.tracker, self.member, &err);
        }
    }
}

pub mod dialer_proxy;
pub mod fallback;
pub mod load_balance;
pub mod relay;
pub mod selector;
pub mod selector_store;
pub mod urltest;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::*;

    fn io_err(msg: &str) -> MeowError {
        MeowError::Proxy(msg.into())
    }

    #[test]
    fn five_failures_within_window_escalate() {
        let tracker = DialFailureTracker::new();
        for i in 1..DIAL_FAILURE_THRESHOLD {
            assert!(
                !tracker.on_failure(&io_err("dial timed out")),
                "failure {i} is below the threshold"
            );
        }
        assert!(
            tracker.on_failure(&io_err("dial timed out")),
            "the 5th failure within the window escalates"
        );
        // Escalation resets the streak, so a fresh window starts over.
        assert!(!tracker.on_failure(&io_err("dial timed out")));
    }

    #[test]
    fn connection_refused_escalates_immediately() {
        let tracker = DialFailureTracker::new();
        assert!(tracker.on_failure(&io_err("connection refused")));
    }

    #[test]
    fn connection_refused_leaves_the_streak_intact() {
        // mihomo's refused fast path does not touch failedTimes.
        let tracker = DialFailureTracker::new();
        for _ in 1..DIAL_FAILURE_THRESHOLD {
            tracker.on_failure(&io_err("dial timed out"));
        }
        assert!(tracker.on_failure(&io_err("connection refused")));
        assert!(
            tracker.on_failure(&io_err("dial timed out")),
            "the pre-refused streak still counts toward the threshold"
        );
    }

    #[test]
    fn success_resets_the_streak() {
        let tracker = DialFailureTracker::new();
        for _ in 1..DIAL_FAILURE_THRESHOLD {
            tracker.on_failure(&io_err("dial timed out"));
        }
        tracker.on_success();
        for i in 1..DIAL_FAILURE_THRESHOLD {
            assert!(
                !tracker.on_failure(&io_err("dial timed out")),
                "failure {i} after a success does not escalate"
            );
        }
        assert!(tracker.on_failure(&io_err("dial timed out")));
    }

    #[test]
    fn not_supported_failures_never_escalate() {
        let tracker = DialFailureTracker::new();
        for _ in 0..100 {
            assert!(!tracker.on_failure(&MeowError::NotSupported("udp".into())));
        }
    }

    #[test]
    fn udp_unsupported_failures_never_escalate() {
        let tracker = DialFailureTracker::new();
        for _ in 0..100 {
            assert!(!tracker.on_failure(&MeowError::UdpNotSupported));
        }
    }

    #[test]
    fn window_expiry_drops_the_streak() {
        let tracker = DialFailureTracker::new();
        for _ in 1..DIAL_FAILURE_THRESHOLD {
            tracker.on_failure(&io_err("dial timed out"));
        }
        // Age the window without sleeping in the test.
        tracker.state.lock().first_at =
            Some(Instant::now() - DIAL_FAILURE_WINDOW - Duration::from_millis(50));
        assert!(
            !tracker.on_failure(&io_err("dial timed out")),
            "a streak older than the window is dropped"
        );
        // A fresh window needs a full new streak to escalate.
        for _ in 1..DIAL_FAILURE_THRESHOLD {
            assert!(!tracker.on_failure(&io_err("dial timed out")));
        }
        assert!(tracker.on_failure(&io_err("dial timed out")));
    }
}

#[cfg(test)]
mod dial_timeout_tests;
