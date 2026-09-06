use super::selector_store::SelectorStore;
use super::{DialFailureTracker, UsageTracker};
use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, ProviderSlot, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, ProxySelection, Result,
};
use parking_lot::RwLock;
use smol_str::SmolStr;
use std::sync::Arc;

pub struct UrlTestGroup {
    name: SmolStr,
    static_proxies: Vec<Arc<dyn Proxy>>,
    provider_slots: Vec<ProviderSlot>,
    tolerance: u16,
    /// User-fixed member. This is independent from `fastest`, which remains
    /// the automatic URL-test incumbent.
    fixed: RwLock<Option<SmolStr>>,
    store: Option<Arc<SelectorStore>>,
    test_url: String,
    expected_status: String,
    /// Name of the currently selected proxy; `None` means "not yet picked,
    /// use the first available".  Updated by `pick_for_dial` whenever it
    /// promotes a new best.
    fastest: RwLock<Option<SmolStr>>,
    health: ProxyHealth,
    usage: UsageTracker,
    dial_failures: DialFailureTracker,
}

impl UrlTestGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>, tolerance: u16) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: Vec::new(),
            tolerance,
            fixed: RwLock::new(None),
            store: None,
            test_url: "http://www.gstatic.com/generate_204".to_string(),
            expected_status: String::new(),
            fastest: RwLock::new(None),
            health: ProxyHealth::new(),
            usage: UsageTracker::new(),
            dial_failures: DialFailureTracker::new(),
        }
    }

    pub fn new_with_providers(
        name: &str,
        proxies: Vec<Arc<dyn Proxy>>,
        tolerance: u16,
        slots: Vec<ProviderSlot>,
    ) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: slots,
            tolerance,
            fixed: RwLock::new(None),
            store: None,
            test_url: "http://www.gstatic.com/generate_204".to_string(),
            expected_status: String::new(),
            fastest: RwLock::new(None),
            health: ProxyHealth::new(),
            usage: UsageTracker::new(),
            dial_failures: DialFailureTracker::new(),
        }
    }

    #[must_use]
    pub fn with_runtime_options(
        mut self,
        test_url: String,
        expected_status: String,
        store: Option<Arc<SelectorStore>>,
    ) -> Self {
        self.test_url = test_url;
        self.expected_status = expected_status;
        if let Some(store) = store {
            if let Some(prev) = store.get(&self.name).filter(|v| !v.is_empty()) {
                *self.fixed.write() = Some(SmolStr::from(prev));
            }
            self.store = Some(store);
        }
        self
    }

    fn contains_name(&self, name: &str) -> bool {
        self.static_proxies.iter().any(|p| p.name() == name)
            || self.provider_slots.iter().any(|slot| {
                let guard = slot.read();
                guard.iter().any(|p| p.name() == name)
            })
    }

    fn fixed_proxy_if_alive(&self) -> Option<Arc<dyn Proxy>> {
        let name = self.fixed.read().clone()?;
        for p in &self.static_proxies {
            if p.name() == name && p.alive_for_url(&self.test_url) {
                return Some(Arc::clone(p));
            }
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                if p.name() == name && p.alive_for_url(&self.test_url) {
                    return Some(Arc::clone(p));
                }
            }
        }
        None
    }

    /// Single-pass dial-path selector: walks `static_proxies` + provider
    /// slots once without allocating a unified Vec, updates `self.fastest`
    /// if a strictly-better-by-tolerance alternative exists (or if the
    /// current pick has died), and returns the chosen proxy.
    ///
    /// Previously this was three separate full scans per dial:
    /// `update_fastest` cloned the Vec once, scanned to find best, then
    /// scanned again to read the current proxy's delay/aliveness; then
    /// `fastest_proxy` cloned the Vec a second time to look up by name.
    fn pick_for_dial(&self) -> Option<Arc<dyn Proxy>> {
        if let Some(proxy) = self.fixed_proxy_if_alive() {
            return Some(proxy);
        }
        let current_name: Option<SmolStr> = self.fastest.read().clone();

        let mut best_proxy: Option<Arc<dyn Proxy>> = None;
        let mut best_delay: u16 = u16::MAX;
        let mut current_proxy: Option<Arc<dyn Proxy>> = None;
        let mut current_delay: u16 = u16::MAX;
        let mut current_alive = false;
        let mut first_any: Option<Arc<dyn Proxy>> = None;

        // Inline visit logic to avoid an `FnMut` closure that would conflict
        // with the multiple mutable borrows below.
        macro_rules! visit {
            ($p:expr) => {{
                let p: &Arc<dyn Proxy> = $p;
                if first_any.is_none() {
                    first_any = Some(Arc::clone(p));
                }
                if p.alive() {
                    let d = p.last_delay();
                    if let Some(ref n) = current_name {
                        if p.name() == n.as_str() {
                            current_alive = true;
                            current_delay = d;
                            current_proxy = Some(Arc::clone(p));
                        }
                    }
                    if d > 0 && d < best_delay {
                        best_delay = d;
                        best_proxy = Some(Arc::clone(p));
                    }
                }
            }};
        }

        for p in &self.static_proxies {
            visit!(p);
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                visit!(p);
            }
        }

        if let Some(bp) = best_proxy.as_ref() {
            if best_delay.saturating_add(self.tolerance) < current_delay || !current_alive {
                *self.fastest.write() = Some(SmolStr::from(bp.name()));
                return Some(Arc::clone(bp));
            }
        } else if !current_alive {
            let fb = first_any.clone();
            *self.fastest.write() = fb.as_ref().map(|p| SmolStr::from(p.name()));
            return fb;
        }
        current_proxy.or(best_proxy).or(first_any)
    }

    /// Read-only lookup of whatever `fastest` currently points at — used by
    /// the REST/info methods below.  No Vec allocation; falls back to the
    /// first proxy if `fastest` is unset or names something no longer present.
    fn fastest_proxy(&self) -> Option<Arc<dyn Proxy>> {
        if let Some(proxy) = self.fixed_proxy_if_alive() {
            return Some(proxy);
        }
        let name = self.fastest.read().clone();
        let mut first_any: Option<Arc<dyn Proxy>> = None;
        if let Some(n) = name {
            for p in &self.static_proxies {
                if first_any.is_none() {
                    first_any = Some(Arc::clone(p));
                }
                if p.name() == n {
                    return Some(Arc::clone(p));
                }
            }
            for slot in &self.provider_slots {
                let guard = slot.read();
                for p in guard.iter() {
                    if first_any.is_none() {
                        first_any = Some(Arc::clone(p));
                    }
                    if p.name() == n {
                        return Some(Arc::clone(p));
                    }
                }
            }
            return first_any;
        }
        // No selection yet: return first proxy if any.
        if let Some(p) = self.static_proxies.first() {
            return Some(Arc::clone(p));
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            if let Some(p) = guard.first() {
                return Some(Arc::clone(p));
            }
        }
        None
    }

    fn member_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .static_proxies
            .iter()
            .map(|p| p.name().to_string())
            .collect();
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                out.push(p.name().to_string());
            }
        }
        out
    }
}

#[async_trait]
impl ProxyAdapter for UrlTestGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::UrlTest
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.fastest_proxy().is_some_and(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.usage.touch_user_traffic(metadata);
        let proxy = self
            .pick_for_dial()
            .ok_or_else(|| MeowError::Proxy("no proxy available".into()))?;
        let attempt = super::DialAttempt::new(&self.name, &self.dial_failures, &proxy);
        attempt.finish(proxy.dial_tcp(metadata).await)
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.usage.touch_user_traffic(metadata);
        let proxy = self
            .pick_for_dial()
            .ok_or_else(|| MeowError::Proxy("no proxy available".into()))?;
        let attempt = super::DialAttempt::new(&self.name, &self.dial_failures, &proxy);
        attempt.finish(proxy.dial_udp(metadata).await)
    }

    fn unwrap_proxy(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.usage.touch_user_traffic(metadata);
        self.fastest_proxy()
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for UrlTestGroup {
    fn alive(&self) -> bool {
        self.fastest_proxy().is_some_and(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.fastest_proxy().is_some_and(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.fastest_proxy().map_or(0, |p| p.last_delay())
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.fastest_proxy()
            .map_or(0, |p| p.last_delay_for_url(url))
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.fastest_proxy()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        Some(self.member_names())
    }

    fn current(&self) -> Option<String> {
        self.fastest_proxy().map(|p| p.name().into())
    }

    fn selection(&self) -> Option<&dyn ProxySelection> {
        Some(self)
    }

    fn test_url(&self) -> Option<&str> {
        Some(&self.test_url)
    }

    fn expected_status(&self) -> Option<&str> {
        Some(&self.expected_status)
    }

    fn usage_generation(&self) -> u64 {
        self.usage.generation()
    }
}

#[async_trait]
impl ProxySelection for UrlTestGroup {
    async fn set(&self, name: &str) -> Result<()> {
        if !self.contains_name(name) {
            return Err(MeowError::Proxy("proxy not exist".into()));
        }
        self.force_set(Some(name));
        Ok(())
    }

    fn force_set(&self, name: Option<&str>) {
        *self.fixed.write() = name.map(SmolStr::from);
        if let Some(store) = &self.store {
            store.set(&self.name, name.unwrap_or(""));
        }
    }

    fn fixed(&self) -> Option<String> {
        Some(
            self.fixed
                .read()
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
        )
    }

    fn can_unfix(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::test_support::MockProxy;
    use meow_common::Metadata;

    fn pick(g: &UrlTestGroup) -> String {
        g.pick_for_dial().unwrap().name().to_string()
    }

    #[test]
    fn first_pick_chooses_lowest_delay_among_alive() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let c = MockProxy::new("c");
        a.set_delay(120);
        b.set_delay(30);
        c.set_delay(60);
        let g = UrlTestGroup::new("ut", vec![a, b, c], 0);
        assert_eq!(pick(&g), "b");
    }

    #[test]
    fn tolerance_keeps_current_pick_until_strictly_better() {
        // tolerance = 50: once an incumbent exists, a challenger must beat
        // it by MORE than 50 ms before the selection flips.
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_delay(100);
        b.set_delay(80);
        let a_ref = Arc::clone(&a);
        let g = UrlTestGroup::new("ut", vec![a, b], 50);
        // First pick has no incumbent → goes to the lowest-delay member.
        assert_eq!(pick(&g), "b");

        // a comes in just inside the tolerance band — must stick with b.
        a_ref.set_delay(40);
        assert_eq!(pick(&g), "b", "tolerance prevents flapping");

        // a improves enough to clear the band → must promote.
        a_ref.set_delay(20);
        assert_eq!(pick(&g), "a");
    }

    #[test]
    fn dead_current_forces_repick_even_inside_tolerance() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_delay(50);
        b.set_delay(80);
        let a_ref = Arc::clone(&a);
        let g = UrlTestGroup::new("ut", vec![a, b], 100);
        assert_eq!(pick(&g), "a");
        a_ref.set_alive(false);
        assert_eq!(pick(&g), "b", "current died -> must promote next best");
    }

    #[test]
    fn no_alive_members_returns_first_proxy_as_fallback() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_alive(false);
        b.set_alive(false);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);
        assert_eq!(
            g.pick_for_dial().unwrap().name(),
            "a",
            "graceful degradation: surface a real network error from a, \
             not a 'no proxy' config error"
        );
    }

    #[test]
    fn zero_delay_is_treated_as_unknown_not_best() {
        // last_delay == 0 means "never probed / dead"; the picker must NOT
        // consider it the lowest delay.
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        // a has no recorded delay (last_delay=0), b has 100.
        b.set_delay(100);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);
        assert_eq!(pick(&g), "b", "0-delay proxy must not win");
    }

    #[tokio::test]
    async fn dial_tcp_routes_through_pick() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_delay(100);
        b.set_delay(20);
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);
        assert_eq!(g.usage_generation(), 0, "unused group has no use");
        let _ = g.dial_tcp(&Metadata::default()).await;
        assert_eq!(g.usage_generation(), 1, "dial records group use");
        assert_eq!(a_ref.dials(), 0);
        assert_eq!(b_ref.dials(), 1);
    }

    #[tokio::test]
    async fn user_pin_overrides_fastest_and_can_be_cleared() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_delay(100);
        b.set_delay(10);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);

        ProxySelection::set(&g, "a").await.unwrap();
        assert_eq!(pick(&g), "a");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some("a"));

        ProxySelection::force_set(&g, None);
        assert_eq!(pick(&g), "b");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some(""));
    }

    #[tokio::test]
    async fn dead_url_test_pin_falls_back_without_forgetting_pin() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_alive(false);
        b.set_delay(20);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);

        ProxySelection::set(&g, "a").await.unwrap();
        assert_eq!(pick(&g), "b");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some("a"));
    }

    #[tokio::test]
    async fn repeated_dial_failures_mark_member_dead() {
        // mihomo GroupBase.onDialFailed escalation, applied to the fastest
        // member: five failures within the window mark it dead so routing
        // moves to the next candidate until a probe revives it.
        let a = MockProxy::new_failing("a", AdapterType::Shadowsocks, "dial timed out");
        let b = MockProxy::new_failing("b", AdapterType::Shadowsocks, "dial timed out");
        a.set_delay(10);
        b.set_delay(20);
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);

        for i in 1..5 {
            let _ = g.dial_tcp(&Metadata::default()).await;
            assert!(
                a_ref.alive(),
                "failure {i} is below the escalation threshold"
            );
        }
        let _ = g.dial_tcp(&Metadata::default()).await;
        // The first pick (a) has now failed five times in a row and is dead;
        // the next dial must be routed to b.
        assert!(
            !a_ref.alive(),
            "the repeatedly failing member is marked dead"
        );
        let _ = g.dial_tcp(&Metadata::default()).await;
        assert_eq!(a_ref.dials(), 5, "the dead member no longer receives dials");
        assert_eq!(b_ref.dials(), 1, "routing moved past the dead member");
    }

    #[tokio::test]
    async fn connection_refused_marks_member_dead_immediately() {
        let a = MockProxy::new_failing("a", AdapterType::Shadowsocks, "connection refused");
        a.set_delay(10);
        let a_ref = Arc::clone(&a);
        let b = MockProxy::new("b");
        b.set_delay(20);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);

        let _ = g.dial_tcp(&Metadata::default()).await;
        assert!(!a_ref.alive(), "refused escalates on the first failure");
        assert_eq!(pick(&g), "b", "the refused member is no longer selected");
    }
}
