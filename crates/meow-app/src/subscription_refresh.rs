//! Background subscription auto-refresh loop.
//!
//! Extracted from `main.rs` so downstream FFI callers that build a `Tunnel`
//! directly can wire the same auto-refresh behavior in without
//! reimplementing it.

use meow_config::raw::RawConfig;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{error, info};

/// Poll subscriptions in `raw_config` every 60s; for each subscription whose
/// `interval` has elapsed (or which has never been fetched), download the
/// remote config, replace proxies/groups/rules, rebuild the tunnel, and
/// persist back to `config_path`. Runs forever; spawn as a background task.
pub async fn run_loop(raw_config: Arc<RwLock<RawConfig>>, tunnel: Tunnel, config_path: String) {
    // Same provider-cache directory `load_config` used at startup — trusted
    // rebuilds of the daemon's own config must keep resolving relative
    // rule-provider paths the same way, not hard-fail with `cache_dir: None`
    // (issue #429 follow-up).
    let cache_dir = meow_config::resource_cache_dir_for_config_path(&config_path);
    loop {
        let subs_to_refresh: Vec<(String, String)> = {
            let raw = raw_config.read();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            raw.subscriptions
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter(|s| match (s.interval, s.last_updated) {
                    (_, None) => true,
                    (Some(interval), Some(last)) => now - last >= interval as i64,
                    (None, Some(_)) => false,
                })
                .map(|s| (s.name.clone(), s.url.clone()))
                .collect()
        };

        for (name, url) in subs_to_refresh {
            info!("Auto-refreshing subscription '{}'", name);
            match meow_config::subscription::fetch_subscription(&url).await {
                Ok(mut fetched) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    // Pre-resolve any DNS-sourced ECH configs before taking the
                    // sync write lock — preresolve_ech is async, must not be
                    // held across `parking_lot::RwLock`.
                    meow_config::ech_dns::preresolve_ech(&mut fetched.proxies).await;

                    let snapshot = {
                        let mut raw = raw_config.write();

                        if let Some(ref mut subs) = raw.subscriptions {
                            if let Some(sub) = subs.iter_mut().find(|s| s.name == name) {
                                sub.last_updated = Some(now);
                            }
                        }

                        raw.proxies = Some(fetched.proxies);
                        raw.proxy_groups = Some(fetched.proxy_groups);
                        raw.rules = Some(fetched.rules);

                        raw.clone()
                    };

                    let resolver = Arc::clone(tunnel.resolver());
                    let rebuild = tokio::task::spawn_blocking({
                        let snapshot = snapshot.clone();
                        let cache_dir = cache_dir.clone();
                        move || {
                            meow_config::rebuild_from_raw_with_resolver(
                                &snapshot,
                                Some(resolver),
                                Some(cache_dir.as_path()),
                            )
                        }
                    })
                    .await;

                    match rebuild {
                        Ok(Ok((new_proxies, new_rules))) => {
                            tunnel.update_routing(new_proxies, new_rules);
                            info!("Subscription '{}' refreshed successfully", name);
                            let _ =
                                meow_config::save_raw_config_async(&config_path, &snapshot).await;
                        }
                        Ok(Err(e)) => {
                            error!("Failed to rebuild after refreshing '{}': {}", name, e);
                        }
                        Err(e) => error!(
                            "Failed to join rebuild task after refreshing '{}': {}",
                            name, e
                        ),
                    }
                }
                Err(e) => error!("Failed to refresh subscription '{}': {}", name, e),
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}
