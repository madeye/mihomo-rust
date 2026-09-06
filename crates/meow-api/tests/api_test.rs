use axum::http::{Request, StatusCode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use meow_api::routes::{create_router, AppState};
use meow_common::{DnsMode, Proxy};
use meow_config::raw::{RawConfig, RawProxyGroup, RawSubscription};
use meow_dns::{HostEntry, Resolver};
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use smallvec::smallvec;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::broadcast;
use tower::ServiceExt;

fn test_log_tx() -> broadcast::Sender<meow_api::log_stream::LogMessage> {
    broadcast::channel(16).0
}

fn test_raw_config() -> RawConfig {
    RawConfig {
        mixed_port: Some(7890),
        mode: Some("rule".into()),
        rules: Some(vec![
            "DOMAIN,example.com,DIRECT".into(),
            "MATCH,REJECT".into(),
        ]),
        ..Default::default()
    }
}

fn test_state(raw: RawConfig) -> Arc<AppState> {
    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);

    // Build proxies/rules from raw and apply
    let (proxies, rules) = meow_config::rebuild_from_raw(&raw).unwrap();
    tunnel.update_proxies(proxies);
    tunnel.update_rules(rules);

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    // Leak the tempdir so it persists for the test — fine for tests
    std::mem::forget(dir);

    Arc::new(AppState {
        tunnel,
        secret: None,
        config_path,
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: test_log_tx(),
        config_mutation_lock: tokio::sync::Mutex::new(()),
        proxy_providers: Arc::new(DashMap::new()),
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        listeners: vec![],
        external_ui: None,
        traffic_feed: Default::default(),
    })
}

fn test_state_with_route(raw: RawConfig, named: Vec<(&str, Arc<dyn Proxy>)>) -> Arc<AppState> {
    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);

    let mut proxies = std::collections::HashMap::new();
    for (name, proxy) in named {
        proxies.insert(smol_str::SmolStr::from(name), proxy);
    }
    tunnel.update_proxies(proxies);

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    std::mem::forget(dir);

    Arc::new(AppState {
        tunnel,
        secret: None,
        config_path,
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: test_log_tx(),
        config_mutation_lock: tokio::sync::Mutex::new(()),
        proxy_providers: Arc::new(DashMap::new()),
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        listeners: vec![],
        external_ui: None,
        traffic_feed: Default::default(),
    })
}

fn test_state_default() -> Arc<AppState> {
    test_state(test_raw_config())
}

fn test_state_with_secret(secret: &str) -> Arc<AppState> {
    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let raw = test_raw_config();
    let (proxies, rules) = meow_config::rebuild_from_raw(&raw).unwrap();
    tunnel.update_proxies(proxies);
    tunnel.update_rules(rules);

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    std::mem::forget(dir);

    Arc::new(AppState {
        tunnel,
        secret: Some(secret.to_string()),
        config_path,
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: test_log_tx(),
        config_mutation_lock: tokio::sync::Mutex::new(()),
        proxy_providers: Arc::new(DashMap::new()),
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        listeners: vec![],
        external_ui: None,
        traffic_feed: Default::default(),
    })
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ── UI tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn ui_serves_html() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/ui").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("<!DOCTYPE html>"));
    assert!(body.contains("meow-rs"));
}

#[tokio::test]
async fn ui_wildcard_serves_same_html() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/ui/some/path")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("<!DOCTYPE html>"));
}

// issue #223: when `external-ui` is configured, `/ui` serves the static
// directory instead of the built-in panel.
#[tokio::test]
async fn external_ui_serves_static_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("index.html"),
        "<html><body>third-party dashboard</body></html>",
    )
    .unwrap();
    std::fs::write(dir.path().join("app.js"), "console.log('hi')").unwrap();

    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let raw = test_raw_config();
    let (proxies, rules) = meow_config::rebuild_from_raw(&raw).unwrap();
    tunnel.update_proxies(proxies);
    tunnel.update_rules(rules);
    let state = Arc::new(AppState {
        tunnel,
        secret: None,
        config_path: String::new(),
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: test_log_tx(),
        config_mutation_lock: tokio::sync::Mutex::new(()),
        proxy_providers: Arc::new(DashMap::new()),
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        listeners: vec![],
        external_ui: Some(dir.path().to_path_buf()),
        traffic_feed: Default::default(),
    });
    let app = create_router(state);

    // `/ui` resolves index.html in the directory.
    let resp = app
        .clone()
        .oneshot(Request::get("/ui").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("third-party dashboard"));

    // A nested asset is served from the directory.
    let resp = app
        .oneshot(
            Request::get("/ui/app.js")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("console.log"));
}

// ── Existing endpoint tests ──────────────────────────────────────

#[tokio::test]
async fn root_returns_hello() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["hello"], "meow");
}

#[tokio::test]
async fn version_endpoint() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/version")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["version"], format!("v{}", env!("CARGO_PKG_VERSION")));
    assert_eq!(json["meta"], true);
}

#[tokio::test]
async fn get_proxies_contains_builtins() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/proxies")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let proxies = json["proxies"].as_object().unwrap();
    assert!(proxies.contains_key("DIRECT"));
    assert!(proxies.contains_key("REJECT"));
    assert!(proxies.contains_key("REJECT-DROP"));
}

#[tokio::test]
async fn get_proxy_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/proxies/nonexistent")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_proxy_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/proxies/DIRECT")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "DIRECT");
}

#[tokio::test]
async fn get_configs_returns_mode() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/configs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["mode"], "rule");
}

#[tokio::test]
async fn get_configs_returns_default_ipv6_false_when_omitted() {
    // The raw config does not set `ipv6`, so the API must report the runtime
    // default (`false`, matching mihomo/Clash) via `meow_config::effective_ipv6`.
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/configs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(
        json["ipv6"], false,
        "omitted ipv6 must report the runtime default (false)"
    );
}

#[tokio::test]
async fn patch_configs_change_mode() {
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"mode":"direct"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify the mode changed
    let app2 = create_router(state);
    let resp2 = app2
        .oneshot(
            Request::get("/configs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp2).await;
    assert_eq!(json["mode"], "direct");
}

#[tokio::test]
async fn patch_configs_invalid_mode() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"mode":"invalid"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_traffic() {
    let state = test_state_default();
    state.tunnel.statistics().add_upload(123);
    state.tunnel.statistics().add_download(456);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/traffic")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let frame = tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
        .await
        .expect("traffic frame timeout")
        .expect("traffic stream ended")
        .expect("traffic body error");
    let json: serde_json::Value =
        serde_json::from_slice(frame.data_ref().expect("traffic data frame")).unwrap();
    assert_eq!(json["up"], 0);
    assert_eq!(json["down"], 0);
    assert_eq!(json["upTotal"], 123);
    assert_eq!(json["downTotal"], 456);
}

#[tokio::test]
async fn dns_results_returns_searchable_cache_entries() {
    let state = test_state_default();
    state.tunnel.resolver().preload_cache_with_source(
        "dns.google",
        &[
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        ],
        std::time::Duration::from_secs(300),
        Some("8.8.8.8"),
    );
    state.tunnel.resolver().preload_cache_with_source(
        "dns.alidns.com",
        &[
            IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
        ],
        std::time::Duration::from_secs(300),
        Some("223.5.5.5"),
    );

    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/dns/results?search=google&limit=10")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let entries = json.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "dns.google");
    assert_eq!(entries[0]["ips"][0], "8.8.8.8");
    assert_eq!(entries[0]["ips"][1], "8.8.4.4");
    assert_eq!(entries[0]["from_server"], "8.8.8.8");
    assert!(entries[0]["ttl"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn get_connections_empty() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["uploadTotal"], 0);
    assert_eq!(json["downloadTotal"], 0);
    assert!(json["memory"].is_number());
    assert!(json["connections"].as_array().unwrap().is_empty());
}

// ── Rules CRUD tests ─────────────────────────────────────────────

#[tokio::test]
async fn get_rules_returns_initial() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let rules = json["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["type"], "DOMAIN");
    assert_eq!(rules[0]["payload"], "example.com");
    assert_eq!(rules[0]["proxy"], "DIRECT");
    assert_eq!(rules[1]["type"], "MATCH");
}

#[tokio::test]
async fn replace_rules() {
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"rules":["DOMAIN-SUFFIX,google.com,DIRECT","MATCH,REJECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify
    let app2 = create_router(Arc::clone(&state));
    let resp2 = app2
        .oneshot(
            Request::get("/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp2).await;
    let rules = json["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["type"], "DOMAIN-SUFFIX");

    // Also verify raw_config was updated
    let raw = state.raw_config.read();
    let raw_rules = raw.rules.as_ref().unwrap();
    assert_eq!(raw_rules[0], "DOMAIN-SUFFIX,google.com,DIRECT");
}

#[tokio::test]
async fn update_rule_at_index() {
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/rules")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"index":0,"rule":"DOMAIN-KEYWORD,test,REJECT"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    assert_eq!(raw.rules.as_ref().unwrap()[0], "DOMAIN-KEYWORD,test,REJECT");
}

#[tokio::test]
async fn update_rule_out_of_range() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/rules")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"index":99,"rule":"MATCH,DIRECT"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_rule() {
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/rules/0")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    let rules = raw.rules.as_ref().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0], "MATCH,REJECT");
}

#[tokio::test]
async fn delete_rule_out_of_range() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/rules/99")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reorder_rules() {
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules/reorder")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"from":0,"to":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    let rules = raw.rules.as_ref().unwrap();
    // MATCH was at index 1, DOMAIN was at 0; after moving 0→1, MATCH is first
    assert_eq!(rules[0], "MATCH,REJECT");
    assert_eq!(rules[1], "DOMAIN,example.com,DIRECT");
}

#[tokio::test]
async fn reorder_rules_out_of_range() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules/reorder")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"from":0,"to":99}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Proxy Groups CRUD tests ─────────────────────────────────────

#[tokio::test]
async fn get_proxy_groups_empty() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/proxy-groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn create_proxy_group_selector() {
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/proxy-groups")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"MyGroup","type":"select","proxies":["DIRECT","REJECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "MyGroup");

    // Verify in raw config
    let raw = state.raw_config.read();
    let groups = raw.proxy_groups.as_ref().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "MyGroup");
    assert_eq!(groups[0].group_type, "select");
}

#[tokio::test]
async fn rejected_proxy_group_does_not_mutate_raw_config() {
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/proxy-groups")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"Broken","type":"relay","proxies":["DIRECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(state
        .raw_config
        .read()
        .proxy_groups
        .as_ref()
        .is_none_or(Vec::is_empty));
}

#[tokio::test]
async fn create_proxy_group_duplicate_name() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Existing".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/proxy-groups")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"Existing","type":"select","proxies":["DIRECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn get_proxy_groups_with_data() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "TestSelector".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/proxy-groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let groups = json.as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["name"], "TestSelector");
    assert_eq!(groups[0]["type"], "select");
    assert_eq!(groups[0]["proxies"].as_array().unwrap().len(), 2);
    // Selector should have a current selection
    assert!(groups[0]["now"].is_string());
}

#[tokio::test]
async fn get_proxy_groups_expands_provider_backed_runtime_members() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "AUTO".into(),
        group_type: "url-test".into(),
        proxies: None,
        use_providers: Some(vec!["default".into()]),
        ..Default::default()
    }]);

    let node_a = delay_support::TestAdapter::new("node-a", delay_support::DialBehavior::InstantOk)
        .into_proxy();
    let node_b = delay_support::TestAdapter::new("node-b", delay_support::DialBehavior::InstantOk)
        .into_proxy();
    let slot: meow_common::ProviderSlot = Arc::new(RwLock::new(vec![node_a, node_b]));
    let auto: Arc<dyn Proxy> = Arc::new(meow_proxy::UrlTestGroup::new_with_providers(
        "AUTO",
        Vec::new(),
        150,
        vec![slot],
    ));
    let state = test_state_with_route(raw, vec![("AUTO", auto)]);
    let app = create_router(state);

    let resp = app
        .oneshot(
            Request::get("/api/proxy-groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let groups = json.as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["name"], "AUTO");
    assert_eq!(groups[0]["type"], "url-test");
    assert_eq!(groups[0]["now"], "node-a");
    let proxies = groups[0]["proxies"].as_array().unwrap();
    assert_eq!(proxies.len(), 2);
    assert_eq!(proxies[0], "node-a");
    assert_eq!(proxies[1], "node-b");
}

#[tokio::test]
async fn update_proxy_group() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "G1".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/G1")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"G1","type":"select","proxies":["DIRECT","REJECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    let group = &raw.proxy_groups.as_ref().unwrap()[0];
    assert_eq!(group.proxies.as_ref().unwrap().len(), 2);
}

#[tokio::test]
async fn update_proxy_group_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/nonexistent")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"x","type":"select","proxies":["DIRECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_proxy_group() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "ToDelete".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        ..Default::default()
    }]);
    // Add a rule targeting this group
    raw.rules = Some(vec![
        "DOMAIN,test.com,ToDelete".into(),
        "DOMAIN,other.com,DIRECT".into(),
        "MATCH,REJECT".into(),
    ]);
    let state = test_state(raw);
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/proxy-groups/ToDelete")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    // Group should be removed
    assert!(raw.proxy_groups.as_ref().unwrap().is_empty());
    // Rule targeting the deleted group should be removed
    let rules = raw.rules.as_ref().unwrap();
    assert_eq!(rules.len(), 2);
    assert!(!rules.iter().any(|r| r.contains("ToDelete")));
}

#[tokio::test]
async fn delete_proxy_group_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/proxy-groups/nonexistent")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn select_proxy_invalid_target() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Sel".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/Sel/select")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"NONEXISTENT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn select_proxy_group_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/nonexistent/select")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"DIRECT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Subscriptions tests ──────────────────────────────────────────

#[tokio::test]
async fn get_subscriptions_empty() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/subscriptions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_subscriptions_with_data() {
    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "sub1".into(),
        url: "https://example.com/sub".into(),
        interval: Some(3600),
        last_updated: Some(1000000),
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/subscriptions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let subs = json.as_array().unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0]["name"], "sub1");
    assert_eq!(subs[0]["url"], "https://example.com/sub");
    assert_eq!(subs[0]["interval"], 3600);
    assert_eq!(subs[0]["proxy_count"], 0);
}

#[tokio::test]
async fn get_subscriptions_reports_counts() {
    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "mysub".into(),
        url: "https://example.com".into(),
        interval: None,
        last_updated: None,
    }]);
    // Subscription replaces proxies/groups/rules with remote data
    let mut proxy1 = std::collections::HashMap::new();
    proxy1.insert("name".to_string(), serde_yaml::Value::String("S1".into()));
    proxy1.insert("type".to_string(), serde_yaml::Value::String("ss".into()));
    raw.proxies = Some(vec![proxy1]);
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "G".into(),
        group_type: "select".into(),
        proxies: Some(vec!["S1".into()]),
        ..Default::default()
    }]);
    raw.rules = Some(vec!["MATCH,DIRECT".into()]);

    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/subscriptions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json[0]["proxy_count"], 1);
    assert_eq!(json[0]["group_count"], 1);
    assert_eq!(json[0]["rule_count"], 1);
}

#[tokio::test]
async fn delete_subscription_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/subscriptions/nonexistent")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_subscription_clears_data() {
    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "delsub".into(),
        url: "https://example.com".into(),
        interval: None,
        last_updated: None,
    }]);
    let mut proxy1 = std::collections::HashMap::new();
    proxy1.insert("name".to_string(), serde_yaml::Value::String("S1".into()));
    proxy1.insert("type".to_string(), serde_yaml::Value::String("ss".into()));
    raw.proxies = Some(vec![proxy1]);
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "G".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "S1".into()]),
        ..Default::default()
    }]);

    let state = test_state(raw);
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/subscriptions/delsub")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    // Subscription removed
    assert!(raw.subscriptions.as_ref().unwrap().is_empty());
    // Proxies, groups, rules all cleared
    assert!(raw.proxies.as_ref().unwrap().is_empty());
    assert!(raw.proxy_groups.as_ref().unwrap().is_empty());
    assert!(raw.rules.as_ref().unwrap().is_empty());
}

// ── Config save test ─────────────────────────────────────────────

#[tokio::test]
async fn save_config_creates_file() {
    let state = test_state_default();
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/save")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify file was written
    let content = std::fs::read_to_string(&state.config_path).unwrap();
    assert!(content.contains("mixed-port"));
}

#[tokio::test]
async fn save_config_creates_backup() {
    let state = test_state_default();

    // Write initial file
    std::fs::write(&state.config_path, "old content").unwrap();

    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/save")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify backup was created
    let bak_path = format!("{}.bak", state.config_path);
    let bak_content = std::fs::read_to_string(bak_path).unwrap();
    assert_eq!(bak_content, "old content");
}

// ── PUT /proxies/{name} selector switch test ─────────────────────

#[tokio::test]
async fn put_proxy_selector_switch() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "MySelector".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);

    // Switch to REJECT
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/proxies/MySelector")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"REJECT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn put_and_delete_automatic_group_selection() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![
        RawProxyGroup {
            name: "Auto".into(),
            group_type: "url-test".into(),
            proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
            ..Default::default()
        },
        RawProxyGroup {
            name: "Failover".into(),
            group_type: "fallback".into(),
            proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
            ..Default::default()
        },
    ]);
    let state = test_state(raw);
    let app = create_router(state);

    for group in ["Auto", "Failover"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/proxies/{group}"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"name":"REJECT"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let detail = app
            .clone()
            .oneshot(
                Request::get(format!("/group/{group}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_json(detail).await["fixed"], "REJECT");

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/proxies/{group}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let detail = app
            .clone()
            .oneshot(
                Request::get(format!("/group/{group}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_json(detail).await["fixed"], "");
    }
}

#[tokio::test]
async fn group_routes_filter_leaf_proxies() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Choice".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        ..Default::default()
    }]);
    let app = create_router(test_state(raw));
    let groups = app
        .clone()
        .oneshot(
            Request::get("/group")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(groups).await;
    assert!(json["proxies"].get("Choice").is_some());
    assert!(json["proxies"].get("DIRECT").is_none());

    let leaf = app
        .oneshot(
            Request::get("/group/DIRECT")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(leaf.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_proxy_not_a_group() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/proxies/DIRECT")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"something"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // DIRECT is not a SelectorGroup, returns BAD_REQUEST (matching mihomo behavior)
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn select_proxy_roundtrip() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Sel".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        ..Default::default()
    }]);
    let state = test_state(raw);

    // Select REJECT
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/Sel/select")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"REJECT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "select failed");

    // Read back proxy groups
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::get("/api/proxy-groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let groups: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let sel = &groups[0];
    assert_eq!(
        sel["now"], "REJECT",
        "now field should be REJECT after select"
    );
}

// ── Bearer auth middleware ───────────────────────────────────────

#[tokio::test]
async fn auth_middleware_table() {
    use axum::http::header::HeaderValue;

    /// `Authorization` header a case sends.
    enum AuthHeader {
        /// No `Authorization` header at all.
        Absent,
        /// Header value that is valid ASCII.
        Str(&'static str),
        /// Raw bytes, so non-ASCII values can be exercised.
        Raw(&'static [u8]),
    }

    struct Case {
        label: &'static str,
        /// `None` → `AppState.secret` is `None`; `Some(s)` → `Some(s.to_string())`.
        secret: Option<&'static str>,
        method: &'static str,
        path: &'static str,
        auth: AuthHeader,
        /// JSON request body; sets `content-type: application/json` when present.
        body: Option<&'static str>,
        expected: StatusCode,
    }

    let cases = [
        Case {
            label: "unset secret: auth disabled, API request allowed",
            secret: None,
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Absent,
            body: None,
            expected: StatusCode::OK,
        },
        Case {
            label: "empty secret: auth disabled, API request allowed",
            secret: Some(""),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Absent,
            body: None,
            expected: StatusCode::OK,
        },
        Case {
            label: "missing Authorization header rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Absent,
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            label: "wrong token rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Str("Bearer wrongtoken"),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            label: "correct token allows request",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Str("Bearer hunter2"),
            body: None,
            expected: StatusCode::OK,
        },
        Case {
            // /version is deliberately probed here: it proves the gate covers it too.
            label: "lowercase `bearer ` prefix rejected (only `Bearer ` is stripped)",
            secret: Some("hunter2"),
            method: "GET",
            path: "/version",
            auth: AuthHeader::Str("bearer hunter2"),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            label: "non-Bearer scheme rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Str("Basic hunter2"),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            label: "UI routes remain unauthenticated",
            secret: Some("hunter2"),
            method: "GET",
            path: "/ui",
            auth: AuthHeader::Absent,
            body: None,
            expected: StatusCode::OK,
        },
        Case {
            label: "gated write endpoint rejects unauthenticated POST",
            secret: Some("hunter2"),
            method: "POST",
            path: "/rules",
            auth: AuthHeader::Absent,
            body: Some(r#"{"rules":[]}"#),
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            // "Bearer " with nothing after the space: strip_prefix yields "", != secret.
            label: "`Bearer ` with empty value rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Str("Bearer "),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            // "Bearerhunter2" — no "Bearer " prefix, so strip_prefix returns None
            // and the middleware cannot extract a token.
            label: "no space after `Bearer` rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Str("Bearerhunter2"),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
        Case {
            // "Bearer café" — é is 0xC3 0xA9 (two UTF-8 bytes, not valid ASCII).
            // HeaderValue::to_str() returns Err for non-ASCII bytes, so the
            // middleware sees None for the provided token and returns 401.
            label: "multibyte UTF-8 header value rejected",
            secret: Some("hunter2"),
            method: "GET",
            path: "/proxies",
            auth: AuthHeader::Raw(b"Bearer caf\xc3\xa9"),
            body: None,
            expected: StatusCode::UNAUTHORIZED,
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        let state = match case.secret {
            None => test_state_default(),
            Some(secret) => test_state_with_secret(secret),
        };
        let app = create_router(state);

        let mut builder = Request::builder().method(case.method).uri(case.path);
        match case.auth {
            AuthHeader::Absent => {}
            AuthHeader::Str(value) => builder = builder.header("authorization", value),
            AuthHeader::Raw(bytes) => {
                builder = builder.header("authorization", HeaderValue::from_bytes(bytes).unwrap());
            }
        }
        let req = match case.body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
            None => builder.body(axum::body::Body::empty()).unwrap(),
        };

        let status = app.oneshot(req).await.unwrap().status();
        if status != case.expected {
            failures.push(format!(
                "[{}] {} {} → expected {}, got {status}",
                case.label, case.method, case.path, case.expected
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "auth middleware cases failed:\n{}",
        failures.join("\n")
    );
}

// ── Delay endpoints (M1.G-2) ─────────────────────────────────────────

mod delay_support {
    use meow_common::{
        AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn,
        ProxyHealth, ProxyPacketConn, Result,
    };
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[derive(Clone, Debug)]
    pub enum DialBehavior {
        InstantOk,
        SleepThenOk(Duration),
        SleepThenError(Duration),
        ImmediateError,
        /// Used by #29 tests: dial succeeds instantly but the canned HTTP
        /// response returns the given status code. Exercises the
        /// `expected`-param path and the status-line parsing path.
        InstantStatus(u16, &'static str),
    }

    pub struct TestAdapter {
        name: String,
        health: ProxyHealth,
        behavior: DialBehavior,
        pub dial_starts: Arc<Mutex<Vec<Instant>>>,
    }

    impl TestAdapter {
        pub fn new(name: &str, behavior: DialBehavior) -> Self {
            Self {
                name: name.to_string(),
                health: ProxyHealth::new(),
                behavior,
                dial_starts: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn into_proxy(self) -> Arc<dyn Proxy> {
            Arc::new(WrappedTest {
                inner: Arc::new(self),
            })
        }
    }

    /// Canned HTTP responder used so `url_test`'s real `GET` path exercises a
    /// full write/read cycle without needing a kernel socket. Writes are
    /// discarded; reads return a byte-at-a-time slice of the configured
    /// response (default: `HTTP/1.1 204 No Content\r\n\r\n`). Override the
    /// status via `CannedConn::with_status` to drive `expected`-param tests.
    struct CannedConn {
        response: Vec<u8>,
        cursor: usize,
    }
    impl CannedConn {
        fn ok() -> Self {
            Self::with_status(204, "No Content")
        }
        fn with_status(code: u16, reason: &str) -> Self {
            Self {
                response: format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\n\r\n")
                    .into_bytes(),
                cursor: 0,
            }
        }
    }
    impl tokio::io::AsyncRead for CannedConn {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let remaining = self.response.len() - self.cursor;
            if remaining == 0 {
                return std::task::Poll::Ready(Ok(()));
            }
            let n = remaining.min(buf.remaining());
            let start = self.cursor;
            let end = start + n;
            buf.put_slice(&self.response[start..end]);
            self.cursor += n;
            std::task::Poll::Ready(Ok(()))
        }
    }
    impl tokio::io::AsyncWrite for CannedConn {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    impl Unpin for CannedConn {}
    impl ProxyConn for CannedConn {}

    struct NopPacketConn;
    #[async_trait::async_trait]
    impl ProxyPacketConn for NopPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            Err(MeowError::Proxy("nop".into()))
        }
        async fn write_packet(&self, _buf: &[u8], _addr: &SocketAddr) -> Result<usize> {
            Ok(0)
        }
        fn local_addr(&self) -> Result<SocketAddr> {
            Err(MeowError::Proxy("nop".into()))
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl ProxyAdapter for TestAdapter {
        fn name(&self) -> &str {
            &self.name
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            false
        }
        async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
            self.dial_starts.lock().unwrap().push(Instant::now());
            match &self.behavior {
                DialBehavior::InstantOk => Ok(Box::new(CannedConn::ok())),
                DialBehavior::SleepThenOk(d) => {
                    tokio::time::sleep(*d).await;
                    Ok(Box::new(CannedConn::ok()))
                }
                DialBehavior::SleepThenError(d) => {
                    tokio::time::sleep(*d).await;
                    Err(MeowError::Proxy("test sleep-then-error".into()))
                }
                DialBehavior::ImmediateError => Err(MeowError::Proxy("test immediate".into())),
                DialBehavior::InstantStatus(code, reason) => {
                    Ok(Box::new(CannedConn::with_status(*code, reason)))
                }
            }
        }
        async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
            Ok(Box::new(NopPacketConn))
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    /// Forwards the `Proxy` trait to the wrapped `TestAdapter` so the tunnel
    /// registry can store `Arc<dyn Proxy>` directly.
    pub struct WrappedTest {
        inner: Arc<TestAdapter>,
    }

    #[async_trait::async_trait]
    impl ProxyAdapter for WrappedTest {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn adapter_type(&self) -> AdapterType {
            self.inner.adapter_type()
        }
        fn addr(&self) -> &str {
            self.inner.addr()
        }
        fn support_udp(&self) -> bool {
            self.inner.support_udp()
        }
        async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
            self.inner.dial_tcp(metadata).await
        }
        async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
            self.inner.dial_udp(metadata).await
        }
        fn health(&self) -> &ProxyHealth {
            self.inner.health()
        }
    }

    impl Proxy for WrappedTest {
        fn alive(&self) -> bool {
            self.inner.health().alive()
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            self.inner.health().alive()
        }
        fn last_delay(&self) -> u16 {
            self.inner.health().last_delay()
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            self.inner.health().last_delay()
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            self.inner.health().delay_history()
        }
    }

    /// Build an app state whose tunnel holds exactly the given set of named
    /// proxies. Uses the real `Tunnel` so the delay handlers exercise the
    /// production lookup path.
    pub fn state_with_proxies(named: Vec<(&str, Arc<dyn Proxy>)>) -> Arc<super::AppState> {
        use super::*;
        let mut proxies = std::collections::HashMap::new();
        for (name, proxy) in named {
            proxies.insert(smol_str::SmolStr::from(name), proxy);
        }

        let resolver = Arc::new(Resolver::new(
            vec!["8.8.8.8:53".parse().unwrap()],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        tunnel.update_proxies(proxies);

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
        std::mem::forget(dir);

        Arc::new(AppState {
            tunnel,
            secret: None,
            config_path,
            raw_config: Arc::new(RwLock::new(test_raw_config())),
            log_tx: tokio::sync::broadcast::channel(16).0,
            config_mutation_lock: tokio::sync::Mutex::new(()),
            proxy_providers: Arc::new(DashMap::new()),
            rule_providers: Arc::new(RwLock::new(HashMap::new())),
            listeners: vec![],
            external_ui: None,
            traffic_feed: Default::default(),
        })
    }

    /// Build a fallback group that owns the given members. Caller keeps the
    /// member Arcs alive via the returned Vec.
    pub fn fallback_group(name: &str, members: Vec<Arc<dyn Proxy>>) -> Arc<dyn Proxy> {
        Arc::new(meow_proxy::FallbackGroup::new(name, members))
    }

    /// Build a url-test group. Used by E5 to verify the delay probe does not
    /// trigger reselection.
    pub fn url_test_group(name: &str, members: Vec<Arc<dyn Proxy>>) -> Arc<dyn Proxy> {
        Arc::new(meow_proxy::UrlTestGroup::new(name, members, 150))
    }

    /// Same as `state_with_proxies` but configures the auth middleware with a
    /// bearer secret so the delay endpoints can be exercised under the gated
    /// subrouter.
    pub fn state_with_proxies_and_secret(
        named: Vec<(&str, Arc<dyn Proxy>)>,
        secret: &str,
    ) -> Arc<super::AppState> {
        use super::*;
        let mut proxies = std::collections::HashMap::new();
        for (name, proxy) in named {
            proxies.insert(smol_str::SmolStr::from(name), proxy);
        }

        let resolver = Arc::new(Resolver::new(
            vec!["8.8.8.8:53".parse().unwrap()],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        tunnel.update_proxies(proxies);

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
        std::mem::forget(dir);

        Arc::new(AppState {
            tunnel,
            secret: Some(secret.to_string()),
            config_path,
            raw_config: Arc::new(RwLock::new(test_raw_config())),
            log_tx: tokio::sync::broadcast::channel(16).0,
            config_mutation_lock: tokio::sync::Mutex::new(()),
            proxy_providers: Arc::new(DashMap::new()),
            rule_providers: Arc::new(RwLock::new(HashMap::new())),
            listeners: vec![],
            external_ui: None,
            traffic_feed: Default::default(),
        })
    }
}

use delay_support::{
    fallback_group, state_with_proxies, state_with_proxies_and_secret, url_test_group,
    DialBehavior, TestAdapter,
};

fn url_q() -> &'static str {
    "http://www.gstatic.com/generate_204"
}

async fn delay_req(app: axum::Router, path: String) -> axum::response::Response {
    app.oneshot(Request::get(path).body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap()
}

// ── A: single-proxy happy path ───────────────────────────────────────

#[tokio::test]
async fn a1_get_proxy_delay_ok_records_delay() {
    let adapter = TestAdapter::new(
        "T",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let state = state_with_proxies(vec![("T", adapter)]);
    let app = create_router(Arc::clone(&state));
    let resp = delay_req(
        app,
        format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = body_json(resp).await;
    let delay = body["delay"].as_u64().unwrap();
    assert!(delay > 0, "delay must be positive, got {delay}");
    assert_eq!(body.as_object().unwrap().len(), 1, "only the delay key");
    // Verify recorded into history
    let route = state.tunnel.route_snapshot();
    let proxies = &route.proxies;
    let proxy = proxies.get("T").unwrap();
    assert_eq!(proxy.delay_history().len(), 1);
}

// ── B: single-proxy error surface ────────────────────────────────────

/// Error-surface table for the single-proxy delay endpoint: every case shares
/// the same `TestAdapter`/state setup and differs only in the request path and
/// the expected status/body. Cases are labelled and all of them run even when
/// an earlier one fails.
#[tokio::test]
async fn b_series_delay_error_table() {
    struct Case {
        label: &'static str,
        path: String,
        expected_status: StatusCode,
        expected_body: Option<&'static [u8]>,
    }

    let cases = vec![
        Case {
            label: "b1 missing url is 400 Body invalid",
            path: "/proxies/T/delay?timeout=1000".to_string(),
            expected_status: StatusCode::BAD_REQUEST,
            expected_body: Some(br#"{"message":"Body invalid"}"#),
        },
        Case {
            label: "b2 missing timeout is 400 Body invalid",
            path: format!("/proxies/T/delay?url={}", url_q()),
            expected_status: StatusCode::BAD_REQUEST,
            expected_body: Some(br#"{"message":"Body invalid"}"#),
        },
        Case {
            label: "b3 timeout too large is 400 Body invalid",
            path: format!("/proxies/T/delay?url={}&timeout=100000", url_q()),
            expected_status: StatusCode::BAD_REQUEST,
            expected_body: Some(br#"{"message":"Body invalid"}"#),
        },
        Case {
            label: "b4 timeout zero is 400",
            path: format!("/proxies/T/delay?url={}&timeout=0", url_q()),
            expected_status: StatusCode::BAD_REQUEST,
            expected_body: None,
        },
        Case {
            label: "b5 unknown proxy is 404 resource not found",
            path: format!("/proxies/NOPE/delay?url={}&timeout=1000", url_q()),
            expected_status: StatusCode::NOT_FOUND,
            expected_body: Some(br#"{"message":"resource not found"}"#),
        },
    ];

    let mut failures: Vec<String> = Vec::new();
    for case in cases {
        let adapter = TestAdapter::new(
            "T",
            DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
        )
        .into_proxy();
        let state = state_with_proxies(vec![("T", adapter)]);
        let app = create_router(state);
        let resp = delay_req(app, case.path.clone()).await;
        let status = resp.status();
        if status != case.expected_status {
            failures.push(format!(
                "[{}] GET {}: expected status {}, got {status}",
                case.label, case.path, case.expected_status
            ));
        }
        if let Some(expected_body) = case.expected_body {
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            if &bytes[..] != expected_body {
                failures.push(format!(
                    "[{}] GET {}: expected body {}, got {}",
                    case.label,
                    case.path,
                    String::from_utf8_lossy(expected_body),
                    String::from_utf8_lossy(&bytes)
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "delay error-surface cases failed:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn b6_immediate_error_is_503() {
    let adapter = TestAdapter::new("T", DialBehavior::ImmediateError).into_proxy();
    let state = state_with_proxies(vec![("T", adapter)]);
    let app = create_router(state);
    let resp = delay_req(
        app,
        format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        br#"{"message":"An error occurred in the delay test"}"#
    );
}

#[tokio::test]
async fn b7_dial_exceeds_timeout_is_504() {
    // Post-M1.G-2b: `url_test` now distinguishes `UrlTestError::Timeout` from
    // transport errors, so a dial that overshoots the probe budget surfaces
    // as 504 "Timeout" — matching upstream `hub/route/proxies.go::getProxyDelay`
    // which renders `ErrRequestTimeout` → `http.StatusGatewayTimeout`.
    let adapter = TestAdapter::new(
        "T",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(500)),
    )
    .into_proxy();
    let state = state_with_proxies(vec![("T", adapter)]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/proxies/T/delay?url={}&timeout=50", url_q())).await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], br#"{"message":"Timeout"}"#);
}

// ── D: group happy path ──────────────────────────────────────────────

#[tokio::test]
async fn d1_group_delay_ok_all_members_reported() {
    let a = TestAdapter::new(
        "A",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let b = TestAdapter::new(
        "B",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let c = TestAdapter::new(
        "C",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a), Arc::clone(&b), Arc::clone(&c)]);
    let state = state_with_proxies(vec![("A", a), ("B", b), ("C", c), ("G", group)]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = body_json(resp).await;
    let obj = body.as_object().unwrap();
    assert_eq!(obj.len(), 3);
    for k in ["A", "B", "C"] {
        let v = obj.get(k).and_then(serde_json::Value::as_u64).unwrap();
        assert!(v > 0, "member {k} should have positive delay");
    }
}

#[tokio::test]
async fn d2_d3_group_delay_404_table() {
    // (case_label, target_name, expect_body_check)
    //
    // `non_group` (was d2): upstream findProxyByName rejects a *known*
    // non-group name with 404 for the group route — `group.members()` is
    // None. Body message is asserted exactly, as the original d2 did.
    // `unknown_group` (was d3): the name is absent from the proxies map
    // entirely. These are two distinct 404 branches in `get_group_delay`;
    // both must stay covered.
    let cases: [(&str, &str, bool); 2] =
        [("non_group", "A", true), ("unknown_group", "NOPE", false)];

    for (case_label, target_name, expect_body_check) in cases {
        let a = TestAdapter::new("A", DialBehavior::InstantOk).into_proxy();
        let state = state_with_proxies(vec![("A", a)]);
        let app = create_router(state);
        let resp = delay_req(
            app,
            format!("/group/{target_name}/delay?url={}&timeout=1000", url_q()),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "case {case_label}: expected 404"
        );
        if expect_body_check {
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                &bytes[..],
                br#"{"message":"resource not found"}"#,
                "case {case_label}: unexpected error body"
            );
        }
    }
}

#[tokio::test]
async fn d4_group_delay_timeout_hits_504() {
    // Every member sleeps past the group-wide deadline → 504 Timeout.
    let a = TestAdapter::new(
        "A",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(500)),
    )
    .into_proxy();
    let b = TestAdapter::new(
        "B",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(500)),
    )
    .into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a), Arc::clone(&b)]);
    let state = state_with_proxies(vec![("A", a), ("B", b), ("G", group)]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=50", url_q())).await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], br#"{"message":"Timeout"}"#);
}

#[tokio::test]
async fn d5_group_delay_records_into_each_member_history() {
    let a = TestAdapter::new(
        "A",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let b = TestAdapter::new(
        "B",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a), Arc::clone(&b)]);
    let state = state_with_proxies(vec![
        ("A", Arc::clone(&a)),
        ("B", Arc::clone(&b)),
        ("G", group),
    ]);
    let app = create_router(state);
    let _ = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(a.delay_history().len(), 1);
    assert_eq!(b.delay_history().len(), 1);
}

// ── C: auth gating on the two new endpoints ──────────────────────────
//
// Delay endpoints live under the gated `api` subrouter; these cases lock
// that wiring in so a future refactor can't accidentally expose them.

#[tokio::test]
async fn c1_get_proxy_delay_missing_auth_401() {
    let adapter = TestAdapter::new("T", DialBehavior::InstantOk).into_proxy();
    let state = state_with_proxies_and_secret(vec![("T", adapter)], "hunter2");
    let app = create_router(state);
    let resp = delay_req(
        app,
        format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn c2_get_proxy_delay_wrong_auth_401() {
    let adapter = TestAdapter::new("T", DialBehavior::InstantOk).into_proxy();
    let state = state_with_proxies_and_secret(vec![("T", adapter)], "hunter2");
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get(format!("/proxies/T/delay?url={}&timeout=1000", url_q()))
                .header("authorization", "Bearer wrong")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn c3_get_proxy_delay_correct_auth_200() {
    let adapter = TestAdapter::new(
        "T",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let state = state_with_proxies_and_secret(vec![("T", adapter)], "hunter2");
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get(format!("/proxies/T/delay?url={}&timeout=1000", url_q()))
                .header("authorization", "Bearer hunter2")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn c4_get_group_delay_missing_auth_401() {
    let a = TestAdapter::new("A", DialBehavior::InstantOk).into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a)]);
    let state = state_with_proxies_and_secret(vec![("A", a), ("G", group)], "hunter2");
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── E: group endpoint — concurrency and timeout semantics ────────────
//
// Divergence note vs docs/specs/api-delay-endpoints-test-plan.md:
// - E3 (one slow member → partial map with 0 for slow) is **not**
//   implementable without contradicting the spec. Spec §Error cases row
//   3 and §"Timeout semantics — group-wide" both say: any single slow
//   member pushes the entire group probe past the deadline and the
//   endpoint returns 504. There is no "partial results" mode. This is
//   the upstream mihomo contract (see hub/route/groups.go::getGroupDelay
//   — single context.WithTimeout around the whole URLTest call). QA
//   plan's E3 wording pre-dates the final spec lock; skipping it is the
//   correct choice here — covered instead by d4 (all-slow → 504).
// - E4 is a duplicate of d4; not re-added.
// Class A divergence per ADR-0002 (silent-misroute avoidance): the
// group-wide-timeout semantic must be preserved byte-exactly so dashboards
// relying on upstream's error shape don't quietly show stale zeros.
//
// Memory note on timing: tokio::time::pause() virtualises tokio::sleep
// and tokio::time::timeout, but `url_test` uses std::time::Instant which
// is real wall time. Using pause() would collapse measured delays to ~0
// regardless of adapter behaviour. So these tests use real wall time with
// generous slack per feedback_tokio_pause_syscalls.md.

#[tokio::test]
async fn e1_group_delay_dials_all_members_concurrently() {
    // 5 members, each sleeps 100ms. If dispatched in parallel the 5 dial
    // starts must cluster within a narrow window; serial dispatch would
    // space them ~100ms apart.
    let mut starts_vec = Vec::new();
    let mut members: Vec<Arc<dyn meow_common::Proxy>> = Vec::new();
    let mut named: Vec<(&'static str, Arc<dyn meow_common::Proxy>)> = Vec::new();
    let names = ["A", "B", "C", "D", "E"];
    for n in names {
        let adapter = TestAdapter::new(
            n,
            DialBehavior::SleepThenOk(std::time::Duration::from_millis(100)),
        );
        let starts = Arc::clone(&adapter.dial_starts);
        starts_vec.push(starts);
        let p = adapter.into_proxy();
        members.push(Arc::clone(&p));
        named.push((n, p));
    }
    let group = fallback_group("G", members);
    named.push(("G", group));
    let state = state_with_proxies(named);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let mut first_starts: Vec<std::time::Instant> = starts_vec
        .iter()
        .map(|s| *s.lock().unwrap().first().expect("each member dialed once"))
        .collect();
    first_starts.sort();
    let spread = first_starts
        .last()
        .unwrap()
        .duration_since(*first_starts.first().unwrap());
    // 50ms slack is comfortably under the 100ms per-member sleep floor that
    // serial dispatch would produce, and well above any realistic scheduler
    // jitter on CI.
    assert!(
        spread < std::time::Duration::from_millis(50),
        "dial starts should be concurrent, spread was {spread:?}"
    );
}

#[tokio::test]
async fn e1b_group_delay_limits_large_group_inflight_probes() {
    // 17 members with the production group limit of 16. The first 16 may
    // start immediately, but the final member must wait for an earlier probe
    // to finish instead of creating an unbounded burst.
    let mut starts_vec = Vec::new();
    let mut members: Vec<Arc<dyn meow_common::Proxy>> = Vec::new();
    let mut named: Vec<(&str, Arc<dyn meow_common::Proxy>)> = Vec::new();
    let names: Vec<String> = (0..17).map(|i| format!("P{i:02}")).collect();

    for name in &names {
        let adapter = TestAdapter::new(
            name,
            DialBehavior::SleepThenOk(std::time::Duration::from_millis(120)),
        );
        starts_vec.push(Arc::clone(&adapter.dial_starts));
        let p = adapter.into_proxy();
        members.push(Arc::clone(&p));
        named.push((name.as_str(), p));
    }

    let group = fallback_group("G", members);
    named.push(("G", group));
    let state = state_with_proxies(named);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let mut first_starts: Vec<std::time::Instant> = starts_vec
        .iter()
        .map(|s| *s.lock().unwrap().first().expect("each member dialed once"))
        .collect();
    first_starts.sort();
    let spread = first_starts
        .last()
        .unwrap()
        .duration_since(*first_starts.first().unwrap());
    assert!(
        spread >= std::time::Duration::from_millis(80),
        "17th dial should wait behind the 16-probe group limit, spread was {spread:?}"
    );
}

#[tokio::test]
async fn e2_group_delay_total_walltime_bounded_by_timeout() {
    // 3 instant-ok members with a generous budget; total wall time should
    // be well under 100ms. Guards against accidental serial dispatch (which
    // would still be fast here, but guards the floor).
    let a = TestAdapter::new("A", DialBehavior::InstantOk).into_proxy();
    let b = TestAdapter::new("B", DialBehavior::InstantOk).into_proxy();
    let c = TestAdapter::new("C", DialBehavior::InstantOk).into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a), Arc::clone(&b), Arc::clone(&c)]);
    let state = state_with_proxies(vec![("A", a), ("B", b), ("C", c), ("G", group)]);
    let app = create_router(state);
    let start = std::time::Instant::now();
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        elapsed < std::time::Duration::from_millis(200),
        "group probe with 3 instant members should finish fast, took {elapsed:?}"
    );
}

#[tokio::test]
async fn e5_group_delay_url_test_no_reselection() {
    // UrlTestGroup::current() is driven by pick_for_dial(), which is
    // called only from its own dial_tcp — not from the delay endpoint
    // (which walks members directly). Probing the group must NOT change
    // `current`, even if a later member would win a reselection. Locks in
    // the spec's "records, does not reselect" contract.
    // upstream: hub/route/proxies.go::getGroupDelay — it calls
    // group.URLTest which writes history but does not flip `selected`.
    let a = TestAdapter::new(
        "A",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(50)),
    )
    .into_proxy();
    let b = TestAdapter::new(
        "B",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let group = url_test_group("G", vec![Arc::clone(&a), Arc::clone(&b)]);
    assert_eq!(group.current().as_deref(), Some("A"));
    let state = state_with_proxies(vec![("A", a), ("B", b), ("G", Arc::clone(&group))]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        group.current().as_deref(),
        Some("A"),
        "delay probe must not trigger UrlTestGroup reselection"
    );
}

// ── G: routing and mounting ──────────────────────────────────────────

#[tokio::test]
async fn g1_get_proxy_delay_route_is_under_proxies_tree() {
    // Regression guard: the handler must be reachable at /proxies/:name/delay,
    // NOT under /api/proxies/... (which was the wrong tree in an early draft).
    let adapter = TestAdapter::new(
        "T",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let state = state_with_proxies(vec![("T", adapter)]);
    let app = create_router(state);
    let resp = delay_req(
        app,
        format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "correct tree must 200");
}

#[tokio::test]
async fn g2_get_group_delay_route_is_singular_group_not_groups() {
    // Upstream mihomo uses singular `/group/:name/delay`, NOT `/groups/...`.
    // Dashboards expect this exact path — matching it byte-for-byte is the
    // whole point of this feature.
    let a = TestAdapter::new(
        "A",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&a)]);
    let state = state_with_proxies(vec![("A", a), ("G", group)]);
    let app = create_router(state);
    // Singular form reaches the handler.
    let resp_ok = delay_req(
        app.clone(),
        format!("/group/G/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp_ok.status(), StatusCode::OK);
    // Plural form must 404 (route not mounted).
    let resp_miss = delay_req(app, format!("/groups/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp_miss.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn g3_get_proxy_delay_url_encoded_name() {
    // Axum path decodes %20 → space before matching. Proxy name with a space
    // must round-trip.
    let adapter = TestAdapter::new(
        "my proxy",
        DialBehavior::SleepThenOk(std::time::Duration::from_millis(5)),
    )
    .into_proxy();
    let state = state_with_proxies(vec![("my proxy", adapter)]);
    let app = create_router(state);
    let resp = delay_req(
        app,
        format!("/proxies/my%20proxy/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── H: M1.G-2b (task #29) url_test HTTP-GET upgrade ──────────────────
//
// These cover the probe-quality half of M1.G-2. The test `CannedConn`
// responds with a configurable HTTP/1.1 status line, so we can drive the
// `expected`-param path and the "bad status → 503" contract without a
// real socket. Upstream: `hub/route/proxies.go::getProxyDelay` + the
// `httpHealthCheck` helper in `component/proxydialer/http.go`.

#[tokio::test]
async fn h_series_expected_status_table() {
    // Merge of h1..h4: identical setup (one `TestAdapter` whose canned HTTP
    // response carries a configurable status line, probed via
    // `/proxies/T/delay`), varying only the canned status, the `expected`
    // query param, and the resulting HTTP status / body. Every case is
    // labelled and every case runs even if an earlier one fails, so a single
    // run reports all mismatches.
    struct Case {
        label: &'static str,
        canned_status: u16,
        canned_reason: &'static str,
        expected_param: Option<&'static str>,
        want_http: StatusCode,
        want_body: Option<&'static [u8]>,
    }

    const ERR_BODY: &[u8] = br#"{"message":"An error occurred in the delay test"}"#;

    let cases = [
        Case {
            // h1: no `expected` query param; response is 204 -> success.
            label: "h1_default_expected_accepts_2xx",
            canned_status: 204,
            canned_reason: "No Content",
            expected_param: None,
            want_http: StatusCode::OK,
            want_body: None,
        },
        Case {
            // h2: 500 -> default expected (2xx) misses -> transport error -> 503.
            label: "h2_default_expected_rejects_non_2xx",
            canned_status: 500,
            canned_reason: "Server Error",
            expected_param: None,
            want_http: StatusCode::SERVICE_UNAVAILABLE,
            want_body: Some(ERR_BODY),
        },
        Case {
            // h3: 301 is outside 2xx but within the explicit range the caller
            // asked for.
            label: "h3_expected_range_accepts_member",
            canned_status: 301,
            canned_reason: "Moved",
            expected_param: Some("200,301-399"),
            want_http: StatusCode::OK,
            want_body: None,
        },
        Case {
            // h4: 204 is inside 2xx but the caller restricted to 200 exactly.
            label: "h4_expected_range_rejects_out_of_range",
            canned_status: 204,
            canned_reason: "No Content",
            expected_param: Some("200"),
            want_http: StatusCode::SERVICE_UNAVAILABLE,
            want_body: None,
        },
    ];

    let mut failures: Vec<String> = Vec::new();
    for case in &cases {
        let adapter = TestAdapter::new(
            "T",
            DialBehavior::InstantStatus(case.canned_status, case.canned_reason),
        )
        .into_proxy();
        let state = state_with_proxies(vec![("T", adapter)]);
        let app = create_router(state);
        let path = match case.expected_param {
            Some(expected) => format!(
                "/proxies/T/delay?url={}&timeout=1000&expected={expected}",
                url_q()
            ),
            None => format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
        };
        let resp = delay_req(app, path).await;
        let got_http = resp.status();
        if got_http != case.want_http {
            failures.push(format!(
                "[{}] status: want {}, got {got_http}",
                case.label, case.want_http
            ));
        }
        if let Some(want_body) = case.want_body {
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            if &bytes[..] != want_body {
                failures.push(format!(
                    "[{}] body: want {:?}, got {:?}",
                    case.label,
                    String::from_utf8_lossy(want_body),
                    String::from_utf8_lossy(&bytes)
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "delay `expected` cases failed:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn h5_group_member_bad_status_is_zero() {
    // Group member whose HTTP response is 500 records as 0 in the map,
    // alongside a successful member. Matches upstream group behaviour:
    // per-member failures are map-zero, not a top-level error.
    let good = TestAdapter::new("good", DialBehavior::InstantOk).into_proxy();
    let bad = TestAdapter::new("bad", DialBehavior::InstantStatus(500, "Oops")).into_proxy();
    let group = fallback_group("G", vec![Arc::clone(&good), Arc::clone(&bad)]);
    let state = state_with_proxies(vec![("good", good), ("bad", bad), ("G", group)]);
    let app = create_router(state);
    let resp = delay_req(app, format!("/group/G/delay?url={}&timeout=1000", url_q())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["bad"], 0);
    assert!(body["good"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn h6_sleep_then_transport_error_is_503() {
    // Dial takes a real-but-bounded amount of time and then errors — tests
    // that a transport failure which does NOT overshoot the probe budget
    // still produces 503, not 504. Distinguishes the two error axes now
    // that `url_test` classifies them separately (M1.G-2b contract).
    let adapter = TestAdapter::new(
        "T",
        DialBehavior::SleepThenError(std::time::Duration::from_millis(20)),
    )
    .into_proxy();
    let state = state_with_proxies(vec![("T", adapter)]);
    let app = create_router(state);
    let resp = delay_req(
        app,
        format!("/proxies/T/delay?url={}&timeout=1000", url_q()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        br#"{"message":"An error occurred in the delay test"}"#
    );
}

// ── Connection management tests ──────────────────────────────────

/// DELETE /connections/{id} removes the named connection and returns 204.
#[tokio::test]
async fn delete_connection_by_id_returns_204_and_removes_entry() {
    use meow_common::{ConnType, Metadata, Network};
    let state = test_state_default();

    // Inject a synthetic connection directly via the statistics layer so the
    // test does not require a live proxy dial.
    let meta = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Http,
        host: "example.com".into(),
        dst_port: 80,
        ..Default::default()
    };
    let conn_id = state.tunnel.statistics().track_connection(
        meta,
        smol_str::SmolStr::new_static("DOMAIN"),
        smol_str::SmolStr::new_static("example.com"),
        smallvec![Arc::from("DIRECT")],
    );

    // Verify the connection shows up in GET /connections.
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let conns = json["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0]["id"], conn_id.to_string());

    // DELETE the specific connection.
    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/connections/{conn_id}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Confirm it is gone.
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert!(json["connections"].as_array().unwrap().is_empty());
}

/// DELETE /connections (no path param) closes every active connection.
#[tokio::test]
async fn delete_all_connections_clears_all() {
    use meow_common::{ConnType, Metadata, Network};
    let state = test_state_default();

    let stats = state.tunnel.statistics();
    let meta = || Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Http,
        host: "a.test".into(),
        dst_port: 80,
        ..Default::default()
    };
    stats.track_connection(
        meta(),
        smol_str::SmolStr::new_static("MATCH"),
        smol_str::SmolStr::default(),
        smallvec![Arc::from("DIRECT")],
    );
    stats.track_connection(
        meta(),
        smol_str::SmolStr::new_static("MATCH"),
        smol_str::SmolStr::default(),
        smallvec![Arc::from("DIRECT")],
    );

    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert!(json["connections"].as_array().unwrap().is_empty());
}

// ── DNS query endpoint tests ─────────────────────────────────────

/// Build a test state whose resolver has a hosts-trie entry for
/// `test.local → 192.0.2.1` so DNS query tests get a deterministic answer
/// without touching the network.
fn test_state_with_hosts_entry() -> Arc<AppState> {
    use std::net::IpAddr;
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
    hosts.insert("test.local", vec![ip].into());

    let resolver = Arc::new(Resolver::new(
        vec![],
        vec![],
        DnsMode::Normal,
        hosts,
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let mut raw = test_raw_config();
    raw.dns = Some(serde_yaml::from_str("enable: true").unwrap());
    let (proxies, rules) = meow_config::rebuild_from_raw(&raw).unwrap();
    tunnel.update_proxies(proxies);
    tunnel.update_rules(rules);

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    std::mem::forget(dir);

    Arc::new(AppState {
        tunnel,
        secret: None,
        config_path,
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: test_log_tx(),
        config_mutation_lock: tokio::sync::Mutex::new(()),
        proxy_providers: Arc::new(DashMap::new()),
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        listeners: vec![],
        external_ui: None,
        traffic_feed: Default::default(),
    })
}

/// POST /dns/query resolves a hosts-trie entry and returns the IP in the
/// `answer` field.
#[tokio::test]
async fn post_dns_query_returns_known_host() {
    let state = test_state_with_hosts_entry();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dns/query")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"test.local"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "test.local");
    assert_eq!(json["answer"], "192.0.2.1");
}

/// POST /dns/query for an unknown name returns `answer: null`.
#[tokio::test]
async fn post_dns_query_unknown_name_returns_null_answer() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dns/query")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"no-such-host.invalid"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "no-such-host.invalid");
    assert!(json["answer"].is_null());
}

/// GET /dns/query?name=test.local resolves via the hosts trie.
#[tokio::test]
async fn get_dns_query_returns_known_host() {
    let state = test_state_with_hosts_entry();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/dns/query?name=test.local")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["Status"], 0);
    assert_eq!(json["Question"][0]["Name"], "test.local.");
    assert_eq!(json["Answer"][0]["data"], "192.0.2.1");
}

// ── DNS cache flush ───────────────────────────────────────────────

/// POST /cache/dns/flush returns 204.
#[tokio::test]
async fn flush_dns_cache_returns_no_content() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/cache/dns/flush")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// ── Prometheus metrics ────────────────────────────────────────────

/// GET /metrics returns Prometheus text exposition format.
/// Checks: correct content-type prefix and presence of the traffic counter
/// and active-connections gauge metric names.
#[tokio::test]
async fn get_metrics_returns_prometheus_text() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/metrics")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Content-type must start with text/plain (Prometheus scrape requirement).
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/plain"),
        "unexpected content-type: {ct}"
    );

    let body = body_string(resp).await;
    assert!(
        body.contains("meow_traffic_bytes"),
        "missing meow_traffic_bytes in metrics output"
    );
    assert!(
        body.contains("meow_connections_active"),
        "missing meow_connections_active in metrics output"
    );
}

/// GET /connections serialises entries with the documented camelCase shape
/// (id/upload/download/start/chains/rule/rulePayload). Guards the
/// borrow-based `ActiveConnectionsView` serialize path (audit M8), which
/// replaced the per-entry `serde_json::json!` tree.
#[tokio::test]
async fn get_connections_entry_has_camel_case_shape() {
    use meow_common::{ConnType, Metadata, Network};
    let state = test_state_default();

    let meta = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Http,
        host: "example.com".into(),
        dst_port: 80,
        ..Default::default()
    };
    let conn_id = state.tunnel.statistics().track_connection(
        meta,
        smol_str::SmolStr::new_static("DOMAIN"),
        smol_str::SmolStr::new_static("example.com"),
        smallvec![Arc::from("DIRECT")],
    );

    let app = create_router(Arc::clone(&state));
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let conn = &json["connections"].as_array().unwrap()[0];

    assert_eq!(conn["id"], conn_id.to_string());
    assert_eq!(conn["rule"], "DOMAIN");
    assert_eq!(conn["rulePayload"], "example.com", "must stay camelCase");
    assert_eq!(conn["chains"], serde_json::json!(["DIRECT"]));
    assert_eq!(conn["upload"], 0);
    assert_eq!(conn["download"], 0);
    assert!(conn["start"].is_string());
    // issue #241: metadata is now serialised (mihomo-compatible) so panels can
    // render `host:port` as the connection title instead of the rule type.
    let metadata = conn.get("metadata").expect("metadata is serialised");
    assert_eq!(metadata["host"], "example.com");
    assert_eq!(metadata["destinationPort"], 80);
    assert_eq!(metadata["network"], "tcp");
    assert_eq!(metadata["type"], "Http");
    assert!(
        conn.get("rule_payload").is_none(),
        "snake_case key must not appear"
    );
}

// Exercise actual sockets: an empty statistics map alone cannot prove closure.
async fn live_connection(
    state: &Arc<AppState>,
) -> (
    tokio::net::TcpStream,
    tokio::net::TcpStream,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dst = upstream.local_addr().unwrap();
    let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(inbound.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = inbound.accept().await.unwrap();
    let inner = Arc::clone(state.tunnel.inner());
    let task = tokio::spawn(async move {
        meow_tunnel::tcp::handle_tcp(
            &inner,
            Box::new(server),
            meow_common::Metadata {
                dst_ip: Some(dst.ip()),
                dst_port: dst.port(),
                ..Default::default()
            },
        )
        .await;
    });
    let (mut remote, _) = upstream.accept().await.unwrap();
    client.write_all(b"before close").await.unwrap();
    let mut buf = [0; 12];
    remote.read_exact(&mut buf).await.unwrap();
    remote.write_all(&buf).await.unwrap();
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"before close");
    (client, remote, task)
}

async fn assert_socket_closed(stream: &mut tokio::net::TcpStream) {
    use tokio::io::AsyncReadExt;
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut [0; 1]))
        .await
        .expect("connection still open after close request");
    match result {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("expected EOF or RST, got {other:?}"),
    }
}

#[tokio::test]
async fn delete_connection_terminates_only_selected_stream() {
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let (mut client, mut remote, task) = live_connection(&state).await;
    let id = state.tunnel.statistics().active_connections()[0].id;
    let (mut survivor, mut survivor_remote, survivor_task) = live_connection(&state).await;
    let response = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/connections/{id}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_socket_closed(&mut client).await;
    assert_socket_closed(&mut remote).await;
    task.await.unwrap();
    assert_eq!(state.tunnel.statistics().active_connection_count(), 1);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    survivor.write_all(b"ok").await.unwrap();
    let mut buf = [0; 2];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        survivor_remote.read_exact(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&buf, b"ok");
    state.tunnel.statistics().close_all_connections();
    survivor_task.await.unwrap();
}

#[tokio::test]
async fn delete_all_connections_terminates_both_stream_directions() {
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let mut streams = Vec::new();
    for _ in 0..2 {
        streams.push(live_connection(&state).await);
    }
    let response = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    for (mut client, mut remote, task) in streams {
        assert_socket_closed(&mut client).await;
        assert_socket_closed(&mut remote).await;
        task.await.unwrap();
    }
    assert_eq!(state.tunnel.statistics().active_connection_count(), 0);
}

#[tokio::test]
async fn cold_reload_terminates_live_stream_without_drain_delay() {
    let state = test_state(RawConfig {
        rules: Some(vec!["MATCH,DIRECT".into()]),
        ..Default::default()
    });
    let (mut client, mut remote, task) = live_connection(&state).await;
    use base64::Engine as _;
    let payload =
        base64::engine::general_purpose::STANDARD.encode("mode: rule\nrules:\n  - MATCH,REJECT\n");
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        create_router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"payload": payload}).to_string(),
                ))
                .unwrap(),
        ),
    )
    .await
    .expect("cold reload must not wait for live connections to finish")
    .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_socket_closed(&mut client).await;
    assert_socket_closed(&mut remote).await;
    task.await.unwrap();
    let metadata = meow_common::Metadata {
        dst_ip: Some("127.0.0.1".parse().unwrap()),
        dst_port: 12345,
        ..Default::default()
    };
    let (proxy, _, _) = state.tunnel.inner().resolve_proxy(&metadata).unwrap();
    assert_eq!(
        proxy.name(),
        "REJECT",
        "new connections must see the reloaded policy"
    );
}

/// Force the real routing/DNS await to straddle two completed PUT requests.
/// Before #510, this flow registers only after close_all and dials DIRECT
/// using the old IP-CIDR rule, even though the active policy is now REJECT.
#[tokio::test]
async fn cold_reload_rejects_tcp_setup_waiting_for_dns() {
    use base64::Engine as _;
    use hickory_proto::{
        op::Message,
        rr::{rdata::A, RData, Record, RecordType},
    };
    use meow_common::{Metadata, Network};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::time::{timeout, Duration};

    timeout(Duration::from_secs(5), async {
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut state = test_state(RawConfig {
            rules: Some(vec![
                "IP-CIDR,127.0.0.0/8,DIRECT".into(),
                "MATCH,REJECT".into(),
            ]),
            ..Default::default()
        });
        let raw = state.raw_config.read().clone();
        let tunnel = Tunnel::new(Arc::new(Resolver::new(
            vec![dns.local_addr().unwrap()],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            false,
        )));
        let (proxies, rules) = meow_config::rebuild_from_raw(&raw).unwrap();
        tunnel.update_proxies(proxies);
        tunnel.update_rules(rules);
        Arc::get_mut(&mut state).unwrap().tunnel = tunnel;

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = origin.local_addr().unwrap();
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = inbound.accept().await.unwrap();
        let inner = Arc::clone(state.tunnel.inner());
        let task = tokio::spawn(async move {
            meow_tunnel::tcp::handle_tcp(
                &inner,
                Box::new(server),
                Metadata {
                    host: "reload.test".into(),
                    dst_port: destination.port(),
                    network: Network::Tcp,
                    ..Default::default()
                },
            )
            .await;
        });

        let mut packet = [0; 512];
        let (len, peer) = dns.recv_from(&mut packet).await.unwrap();
        let query = Message::from_vec(&packet[..len]).unwrap();
        assert_eq!(query.queries[0].query_type, RecordType::A);
        assert_eq!(state.tunnel.statistics().active_connection_count(), 0);
        let payload = base64::engine::general_purpose::STANDARD
            .encode("mode: rule\nrules:\n  - MATCH,REJECT\n");
        for _ in 0..2 {
            let response = create_router(Arc::clone(&state))
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri("/configs")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(
                            serde_json::json!({"payload": payload}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }

        let mut response = Message::response(query.metadata.id, query.metadata.op_code);
        response.metadata.recursion_desired = true;
        response.metadata.recursion_available = true;
        response
            .add_queries(query.queries.iter().cloned())
            .add_answer(Record::from_rdata(
                query.queries[0].name.clone(),
                60,
                RData::A(A(Ipv4Addr::LOCALHOST)),
            ));
        dns.send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();

        tokio::select! {
            biased;
            _ = origin.accept() => panic!("old-policy TCP setup escaped reload and dialed DIRECT"),
            result = task => result.unwrap(),
        }
        assert_socket_closed(&mut client).await;
        assert_eq!(state.tunnel.statistics().active_connection_count(), 0);
        // A new real connection observes REJECT, rather than being blocked
        // by a forgotten admission flag or using the previous DIRECT rule.
        let mut fresh_client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let (fresh_server, _) = inbound.accept().await.unwrap();
        let metadata = Metadata {
            dst_ip: Some(destination.ip()),
            dst_port: destination.port(),
            network: Network::Tcp,
            ..Default::default()
        };
        let (proxy, _, _) = state.tunnel.inner().resolve_proxy(&metadata).unwrap();
        assert_eq!(proxy.name(), "REJECT");
        let inner = Arc::clone(state.tunnel.inner());
        let fresh_task = tokio::spawn(async move {
            meow_tunnel::tcp::handle_tcp(&inner, Box::new(fresh_server), metadata).await;
        });
        tokio::select! {
            biased;
            _ = origin.accept() => panic!("new TCP setup used the old DIRECT policy"),
            () = assert_socket_closed(&mut fresh_client) => {},
        }
        // REJECT supplies a read EOF; close the upload half too before
        // waiting for the bidirectional relay task to finish.
        drop(fresh_client);
        fresh_task.await.unwrap();
    })
    .await
    .expect("DNS-delayed setup escaped cold reload or admission did not recover");
}
