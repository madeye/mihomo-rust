use axum::{
    body::Body,
    extract::ws::{Message, WebSocketUpgrade},
    extract::{FromRequestParts, Path, Query, Request, State},
    http::{header, request::Parts, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use dashmap::DashMap;
use meow_common::TunnelMode;
use meow_config::{
    proxy_provider::ProxyProvider,
    raw::{RawConfig, RawProxyGroup, RawSubscription},
    rule_provider::RuleProvider,
    NamedListener,
};
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};
use tower_http::cors::CorsLayer;
use tracing::{debug, info, warn};

#[cfg(feature = "listener-tun")]
use meow_listener::TunListener;

use crate::log_stream::{parse_log_level, LogMessage};
use crate::ui;

struct MaybeWebSocket(Option<WebSocketUpgrade>);

impl<S> FromRequestParts<S> for MaybeWebSocket
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let is_websocket = parts
            .headers
            .get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
        if !is_websocket {
            return Ok(Self(None));
        }
        Ok(Self(
            WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .ok(),
        ))
    }
}
#[derive(Default)]
pub struct TrafficFeed {
    sender: std::sync::Mutex<Option<broadcast::Sender<Arc<str>>>>,
}

pub struct AppState {
    pub tunnel: Tunnel,
    /// Optional Bearer token enforced by `require_auth`. `None` or empty disables auth.
    pub secret: Option<String>,
    pub config_path: String,
    pub raw_config: Arc<RwLock<RawConfig>>,
    /// Fan-out channel for log events. Each WS client subscribes a Receiver.
    pub log_tx: broadcast::Sender<LogMessage>,
    /// Live proxy-provider registry — refreshed by background task and PUT endpoint.
    pub proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>>,
    pub rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
    /// Snapshot of active named listeners (read-only, startup-time only in M1).
    pub listeners: Vec<NamedListener>,
    /// Validated directory for a third-party web UI. When `Some`, it is served
    /// at `/ui`; when `None`, the built-in panel is served (issue #223).
    pub external_ui: Option<std::path::PathBuf>,
    /// Serialises `put_configs` and `commit_raw_candidate` so that the
    /// "read-old-config → write-new-config → TUN reconcile" sequence is
    /// executed atomically with respect to other config mutations.  Without
    /// this a concurrent PUT could stop_tun before a sibling's
    /// set_tun_handle has completed, leaving a running TUN device behind an
    /// `enable=false` config.
    pub config_mutation_lock: tokio::sync::Mutex<()>,
    /// Shared on-demand traffic sampler. No timer runs until a client
    /// subscribes to `/traffic`.
    pub traffic_feed: TrafficFeed,
}

/// The API server owns one raw/runtime configuration, so all mutation
/// endpoints share one commit lane. Reads remain independent.
static CONFIG_MUTATION: Mutex<()> = Mutex::const_new(());

impl AppState {
    fn auth_required(&self) -> bool {
        self.secret.as_deref().is_some_and(|s| !s.is_empty())
    }
}

/// Auth middleware for all API routes. Accepts `Authorization: Bearer <secret>`
/// header. For WebSocket upgrade requests, also accepts `?token=<secret>` query
/// param (browser WebSocket clients cannot set custom headers).
async fn require_auth_ws(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HashMap<String, String>>,
    req: Request,
    next: Next,
) -> Response {
    if !state.auth_required() {
        return next.run(req).await;
    }
    let expected = state.secret.as_deref().unwrap_or("");

    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let is_websocket = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let token_param = if is_websocket {
        query.get("token").map(std::string::String::as_str)
    } else {
        None
    };
    let provided = bearer.or(token_param);

    let ok = match provided {
        Some(t) if t.len() == expected.len() => {
            use subtle::ConstantTimeEq;
            t.as_bytes().ct_eq(expected.as_bytes()).into()
        }
        _ => false,
    };
    if ok {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"message": "Unauthorized"})),
        )
            .into_response()
    }
}

pub fn create_router(state: Arc<AppState>) -> Router {
    // WS routes — accept header or ?token= query param for browser dashboard compat.
    // REST API routes gated behind the Bearer middleware (header-only).
    let api = Router::new()
        .route("/", get(hello))
        .route("/version", get(version))
        .route("/proxies", get(get_proxies))
        .route(
            "/proxies/{name}",
            get(get_proxy).put(update_proxy).delete(unfix_proxy),
        )
        .route("/proxies/{name}/delay", get(get_proxy_delay))
        .route("/group", get(get_groups))
        .route("/group/{name}", get(get_group))
        .route("/group/{name}/delay", get(get_group_delay))
        .route(
            "/rules",
            get(get_rules).post(replace_rules).put(update_rule_at_index),
        )
        .route("/rules/{index}", delete(delete_rule))
        .route("/rules/reorder", post(reorder_rules))
        .route("/connections", get(get_connections))
        .route("/connections/{id}", delete(close_connection))
        .route("/connections", delete(close_all_connections))
        .route(
            "/configs",
            get(get_configs).patch(update_configs).put(put_configs),
        )
        .route("/metrics", get(get_metrics))
        .route("/traffic", get(get_traffic))
        .route("/logs", get(get_logs))
        .route("/memory", get(get_memory))
        .route("/dns/results", get(get_dns_results))
        .route("/dns/query", get(dns_query_get).post(dns_query))
        .route("/cache/dns/flush", post(flush_dns_cache))
        .route("/cache/fakeip/flush", post(flush_fakeip_cache))
        // Config save
        .route("/api/config/save", post(save_config))
        // Subscriptions
        .route(
            "/api/subscriptions",
            get(get_subscriptions).post(add_subscription),
        )
        .route("/api/subscriptions/{name}", delete(delete_subscription))
        .route(
            "/api/subscriptions/{name}/refresh",
            post(refresh_subscription),
        )
        // Proxy groups
        .route(
            "/api/proxy-groups",
            get(get_proxy_groups).post(create_proxy_group),
        )
        .route(
            "/api/proxy-groups/{name}",
            put(update_proxy_group).delete(delete_proxy_group),
        )
        .route(
            "/api/proxy-groups/{name}/select",
            put(select_proxy_in_group),
        )
        // Proxy providers
        .route("/providers/proxies", get(get_providers))
        .route(
            "/providers/proxies/{name}",
            get(get_provider).put(refresh_provider),
        )
        .route(
            "/providers/proxies/{name}/healthcheck",
            get(provider_healthcheck),
        )
        .route(
            "/providers/proxies/{provider_name}/{proxy_name}",
            get(get_provider_proxy),
        )
        .route(
            "/providers/proxies/{provider_name}/{proxy_name}/healthcheck",
            get(provider_proxy_healthcheck),
        )
        // Rule providers
        .route("/providers/rules", get(get_rule_providers))
        .route(
            "/providers/rules/{name}",
            get(get_rule_provider).put(refresh_rule_provider),
        )
        // Listeners (read-only list)
        .route("/listeners", get(get_listeners))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth_ws,
        ));

    // Web UI is intentionally unauthenticated so dashboards can load and then
    // present a token prompt; this matches upstream mihomo behaviour.
    //
    // When `external-ui` is configured (issue #223) the static directory is
    // served at `/ui` via tower-http's `ServeDir`; otherwise the built-in
    // single-page panel is served.
    let router = api;
    let router = if let Some(dir) = state.external_ui.clone() {
        // `ServeDir` resolves `index.html` for the directory root and serves
        // any nested asset; `nest_service("/ui", …)` strips the `/ui` prefix so
        // both `/ui` and `/ui/<asset>` resolve. Dashboards (metacubexd, yacd)
        // use hash routing, so no server-side SPA fallback is required.
        router.nest_service("/ui", tower_http::services::ServeDir::new(dir))
    } else {
        router
            .route("/ui", get(ui::serve_ui))
            .route("/ui/{*rest}", get(ui::serve_ui))
    };

    router.layer(CorsLayer::permissive()).with_state(state)
}

// ── Basic endpoints ──────────────────────────────────────────────────

#[derive(Serialize)]
struct HelloResponse {
    hello: &'static str,
}

async fn hello() -> Json<HelloResponse> {
    Json(HelloResponse { hello: "meow" })
}

#[derive(Serialize)]
struct VersionResponse {
    version: String,
    meta: bool,
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: format!("v{}", env!("CARGO_PKG_VERSION")),
        meta: true,
    })
}

#[derive(Serialize)]
struct ProxyInfo {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    alive: bool,
    history: Vec<meow_common::DelayHistory>,
    udp: bool,
    /// Group-only: ordered list of member proxy names.
    #[serde(skip_serializing_if = "Option::is_none")]
    all: Option<Vec<String>>,
    /// Group-only: name of the currently active member.
    #[serde(skip_serializing_if = "Option::is_none")]
    now: Option<String>,
    /// Automatic-group user pin. `Some("")` means automatic mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed: Option<String>,
    #[serde(rename = "testUrl", skip_serializing_if = "Option::is_none")]
    test_url: Option<String>,
    #[serde(rename = "expectedStatus", skip_serializing_if = "Option::is_none")]
    expected_status: Option<String>,
    /// Last measured delay in ms; omitted until a probe has succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    delay: Option<u16>,
}

impl ProxyInfo {
    fn from_proxy(proxy: &Arc<dyn meow_common::Proxy>) -> Self {
        let members = proxy.members();
        let current = proxy.current();
        debug!(
            name = proxy.name(),
            proxy_type = %proxy.adapter_type(),
            member_count = members.as_ref().map(std::vec::Vec::len),
            current = ?current,
            "building ProxyInfo",
        );
        let delay = Some(proxy.last_delay()).filter(|&d| d > 0);
        Self {
            name: proxy.name().to_string(),
            proxy_type: proxy.adapter_type().to_string(),
            alive: proxy.alive(),
            history: proxy.delay_history(),
            udp: proxy.support_udp(),
            all: members,
            now: current,
            fixed: proxy
                .selection()
                .and_then(meow_common::ProxySelection::fixed),
            test_url: proxy.test_url().map(str::to_string),
            expected_status: proxy.expected_status().map(str::to_string),
            delay,
        }
    }
}

#[derive(Serialize)]
struct ProxiesResponse {
    proxies: std::collections::HashMap<String, ProxyInfo>,
}

async fn get_proxies(State(state): State<Arc<AppState>>) -> Json<ProxiesResponse> {
    let route = state.tunnel.route_snapshot();
    let mut result = std::collections::HashMap::new();
    for (name, proxy) in &route.proxies {
        result.insert(name.to_string(), ProxyInfo::from_proxy(proxy));
    }
    Json(ProxiesResponse { proxies: result })
}

async fn get_proxy(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<ProxyInfo>, StatusCode> {
    let route = state.tunnel.route_snapshot();
    let proxy = route
        .proxies
        .get(name.as_str())
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ProxyInfo::from_proxy(proxy)))
}

#[derive(Deserialize)]
struct UpdateProxyRequest {
    name: String,
}

async fn update_proxy(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
    Json(body): Json<UpdateProxyRequest>,
) -> Response {
    let route = state.tunnel.route_snapshot();
    let Some(proxy) = route.proxies.get(group_name.as_str()).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "Resource not found");
    };
    let Some(selection) = proxy.selection() else {
        return msg_err(StatusCode::BAD_REQUEST, "Must be a Selector");
    };
    match selection.set(&body.name).await {
        Ok(()) => {
            info!("Proxy group '{}' switched to '{}'", group_name, body.name);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message": format!("Selector update error: {e}")})),
        )
            .into_response(),
    }
}

async fn unfix_proxy(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
) -> Response {
    let route = state.tunnel.route_snapshot();
    let Some(proxy) = route.proxies.get(group_name.as_str()).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "Resource not found");
    };
    let Some(selection) = proxy.selection() else {
        return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
    };
    if !selection.can_unfix() {
        return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
    }
    selection.force_set(None);
    StatusCode::NO_CONTENT.into_response()
}

async fn get_groups(State(state): State<Arc<AppState>>) -> Json<ProxiesResponse> {
    let route = state.tunnel.route_snapshot();
    let proxies = route
        .proxies
        .iter()
        .filter(|(_, proxy)| proxy.members().is_some())
        .map(|(name, proxy)| (name.to_string(), ProxyInfo::from_proxy(proxy)))
        .collect();
    Json(ProxiesResponse { proxies })
}

async fn get_group(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let route = state.tunnel.route_snapshot();
    match route.proxies.get(name.as_str()) {
        Some(proxy) if proxy.members().is_some() => {
            Json(ProxyInfo::from_proxy(proxy)).into_response()
        }
        _ => msg_err(StatusCode::NOT_FOUND, "Resource not found"),
    }
}

#[derive(Serialize)]
struct RuleInfo<'a> {
    index: usize,
    #[serde(rename = "type")]
    rule_type: &'static str,
    payload: &'a str,
    proxy: &'a str,
    size: i64,
}

#[derive(Serialize)]
struct RulesResponse<'a> {
    rules: Vec<RuleInfo<'a>>,
}

async fn get_rules(State(state): State<Arc<AppState>>) -> Response {
    // Serialise straight off the route snapshot — the old rules_info()
    // accessor built 3 Strings per rule per call (audit #182).
    let route = state.tunnel.route_snapshot();
    let result: Vec<RuleInfo> = route
        .rules
        .iter()
        .enumerate()
        .map(|(index, r)| RuleInfo {
            index,
            rule_type: r.rule_type().as_str(),
            payload: r.payload(),
            proxy: r.adapter(),
            size: -1,
        })
        .collect();
    Json(RulesResponse { rules: result }).into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionsResponse<'a> {
    upload_total: i64,
    download_total: i64,
    memory: u64,
    /// Serialised straight from the live table — no per-connection
    /// `serde_json::Value` tree, no cloned snapshot Vec (audit M8). The
    /// JSON shape (id/upload/download/start/chains/rule/rulePayload) comes
    /// from `ConnectionInfo`'s `Serialize` derive.
    connections: meow_tunnel::statistics::ActiveConnectionsView<'a>,
}

#[derive(Deserialize)]
struct ConnectionsParams {
    interval: Option<String>,
}

/// Floor for the `/connections` WebSocket push interval. Each tick
/// re-serializes the whole connection table while holding DashMap shard
/// read-guards, so a sub-100ms interval is a self-DoS lever on the API
/// worker rather than a useful refresh rate. Out-of-range values are
/// clamped, not rejected: `0` stays a 400 (upstream contract), anything
/// else is a well-formed request that just asked for too much.
const MIN_CONNECTIONS_INTERVAL_MS: u64 = 100;

/// Parse the `interval` query param: `None` on `0` / non-numeric input
/// (rendered as `400 Body invalid` by the caller), otherwise the value in
/// milliseconds, defaulted to 1000 and clamped to
/// [`MIN_CONNECTIONS_INTERVAL_MS`].
fn parse_connections_interval(raw: Option<&str>) -> Option<u64> {
    match raw {
        Some(raw) => match raw.parse::<u64>() {
            Ok(0) | Err(_) => None,
            Ok(value) => Some(value.max(MIN_CONNECTIONS_INTERVAL_MS)),
        },
        None => Some(1000),
    }
}

async fn connections_json(state: &AppState) -> String {
    let stats = state.tunnel.statistics();
    let (up, down) = stats.snapshot();
    let memory = read_rss_bytes().await;
    #[allow(
        clippy::unnecessary_cast,
        reason = "no-op on 64-bit; widens i32 on targets without 64-bit atomics"
    )]
    let upload = up as i64;
    #[allow(
        clippy::unnecessary_cast,
        reason = "no-op on 64-bit; widens i32 on targets without 64-bit atomics"
    )]
    let download = down as i64;
    serde_json::to_string(&ConnectionsResponse {
        upload_total: upload,
        download_total: download,
        memory,
        connections: stats.active_connections_view(),
    })
    .unwrap_or_else(|_| {
        "{\"uploadTotal\":0,\"downloadTotal\":0,\"memory\":0,\"connections\":[]}".into()
    })
}

async fn get_connections(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ConnectionsParams>,
    MaybeWebSocket(ws): MaybeWebSocket,
) -> Response {
    let Some(interval_ms) = parse_connections_interval(params.interval.as_deref()) else {
        return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
    };

    if let Some(ws) = ws {
        return ws.on_upgrade(move |mut socket| async move {
            if socket
                .send(Message::Text(connections_json(&state).await.into()))
                .await
                .is_err()
            {
                return;
            }
            let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if socket
                    .send(Message::Text(connections_json(&state).await.into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    let body = connections_json(&state).await;
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn close_connection(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> StatusCode {
    match uuid::Uuid::parse_str(&id) {
        Ok(uuid) => {
            state.tunnel.statistics().close_connection(uuid);
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

#[derive(Serialize)]
struct ConfigResponse {
    mode: String,
    #[serde(rename = "log-level")]
    log_level: String,
    #[serde(rename = "mixed-port", skip_serializing_if = "Option::is_none")]
    mixed_port: Option<u16>,
    #[serde(rename = "socks-port", skip_serializing_if = "Option::is_none")]
    socks_port: Option<u16>,
    #[serde(rename = "port", skip_serializing_if = "Option::is_none")]
    http_port: Option<u16>,
    #[serde(rename = "redir-port")]
    redir_port: u16,
    #[serde(rename = "tproxy-port")]
    tproxy_port: u16,
    #[serde(
        rename = "external-controller",
        skip_serializing_if = "Option::is_none"
    )]
    external_controller: Option<String>,
    #[serde(rename = "allow-lan")]
    allow_lan: bool,
    #[serde(rename = "bind-address")]
    bind_address: String,
    #[serde(rename = "ipv6")]
    ipv6: bool,
    /// Whether the TUN listener is currently running (issue #326).
    /// Mirrors `tun.enable` from the raw config and reflects actual
    /// runtime state so nyanpasu can correctly render its toggle.
    #[serde(rename = "tun-enable")]
    tun_enable: bool,
}

async fn get_configs(State(state): State<Arc<AppState>>) -> Json<ConfigResponse> {
    let raw = state.raw_config.read();
    Json(ConfigResponse {
        mode: state.tunnel.mode().to_string(),
        log_level: raw.log_level.clone().unwrap_or_else(|| "info".to_string()),
        mixed_port: raw.mixed_port,
        socks_port: raw.socks_port,
        http_port: raw.port,
        redir_port: 0,
        tproxy_port: raw.tproxy_port.unwrap_or(0),
        external_controller: raw.external_controller.clone(),
        allow_lan: raw.allow_lan.unwrap_or(false),
        bind_address: raw
            .bind_address
            .clone()
            .unwrap_or_else(|| "0.0.0.0".to_string()),
        ipv6: meow_config::effective_ipv6(raw.ipv6),
        tun_enable: state.tunnel.has_tun(),
    })
}

#[derive(Deserialize)]
struct UpdateConfigRequest {
    mode: Option<String>,
    #[serde(rename = "log-level")]
    log_level: Option<String>,
}

async fn update_configs(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateConfigRequest>,
) -> Response {
    // Validate both fields first so we never partially apply on error.
    let mode = body.mode.map(|s| s.parse::<TunnelMode>());
    if let Some(Err(_)) = mode {
        return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
    }
    if let Some(ref level) = body.log_level {
        if !matches!(
            level.to_ascii_lowercase().as_str(),
            "debug" | "info" | "warning" | "warn" | "error" | "silent"
        ) {
            return msg_err(StatusCode::BAD_REQUEST, "Body invalid");
        }
    }

    // Both valid — apply atomically.
    let mut raw = state.raw_config.write();
    if let Some(Ok(parsed_mode)) = mode {
        state.tunnel.set_mode(parsed_mode);
        raw.mode = Some(parsed_mode.to_string());
        info!("Mode changed to {}", parsed_mode);
    }
    if let Some(level) = body.log_level {
        if let Err(e) = crate::log_stream::reload_log_level(&level) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"message": e})),
            )
                .into_response();
        }
        raw.log_level = Some(level);
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Serialize)]
struct TrafficResponse {
    up: i64,
    down: i64,
    #[serde(rename = "upTotal")]
    up_total: i64,
    #[serde(rename = "downTotal")]
    down_total: i64,
}

fn traffic_json(state: &AppState) -> String {
    let (up, down, up_total, down_total) = state.tunnel.statistics().traffic_snapshot();
    #[allow(
        clippy::useless_conversion,
        reason = "identity on 64-bit; widens i32 on targets without 64-bit atomics"
    )]
    serde_json::to_string(&TrafficResponse {
        up: up.into(),
        down: down.into(),
        up_total: up_total.into(),
        down_total: down_total.into(),
    })
    .unwrap_or_default()
}

fn subscribe_traffic_feed(state: &Arc<AppState>) -> broadcast::Receiver<Arc<str>> {
    let mut guard = state
        .traffic_feed
        .sender
        .lock()
        .expect("traffic feed lock poisoned");
    if let Some(tx) = guard.as_ref() {
        return tx.subscribe();
    }

    let (tx, rx) = broadcast::channel(2);
    *guard = Some(tx.clone());
    drop(guard);

    // Establish a baseline before the first one-second window. Otherwise all
    // traffic accumulated while nobody was subscribed would be reported as
    // the first frame's instantaneous rate.
    state.tunnel.statistics().sample_traffic();

    let state = Arc::clone(state);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if tx.receiver_count() == 0 {
                let mut guard = state
                    .traffic_feed
                    .sender
                    .lock()
                    .expect("traffic feed lock poisoned");
                if tx.receiver_count() == 0 {
                    *guard = None;
                    break;
                }
            }
            state.tunnel.statistics().sample_traffic();
            let frame: Arc<str> = Arc::from(traffic_json(&state));
            let _ = tx.send(frame);
        }
    });
    rx
}

async fn get_traffic(
    State(state): State<Arc<AppState>>,
    MaybeWebSocket(ws): MaybeWebSocket,
) -> Response {
    let feed = subscribe_traffic_feed(&state);
    if let Some(ws) = ws {
        return ws.on_upgrade(move |mut socket| async move {
            let mut feed = feed;
            loop {
                let frame = match feed.recv().await {
                    Ok(frame) => frame,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if socket
                    .send(Message::Text(frame.as_ref().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    let stream = futures::stream::unfold(feed, |mut feed| async move {
        loop {
            match feed.recv().await {
                Ok(frame) => {
                    return Some((
                        Ok::<String, std::convert::Infallible>(format!("{frame}\n")),
                        feed,
                    ));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .expect("valid traffic stream response")
}

#[derive(Deserialize)]
struct DnsQueryRequest {
    name: String,
    #[serde(rename = "type")]
    qtype: Option<String>,
}

#[derive(Deserialize)]
struct DnsResultsQuery {
    search: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct DnsResultEntry {
    name: String,
    ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_server: Option<String>,
    ttl: u64,
}

async fn get_dns_results(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DnsResultsQuery>,
) -> Json<Vec<DnsResultEntry>> {
    let limit = params.limit.unwrap_or(256).min(1024);
    let results = state
        .tunnel
        .resolver()
        .dns_results(params.search.as_deref(), limit)
        .into_iter()
        .map(|entry| DnsResultEntry {
            name: entry.name,
            ips: entry.ips.into_iter().map(|ip| ip.to_string()).collect(),
            from_server: entry.source,
            ttl: entry.ttl.as_secs(),
        })
        .collect();
    Json(results)
}

async fn dns_query(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DnsQueryRequest>,
) -> Json<serde_json::Value> {
    let resolver = state.tunnel.resolver();
    let result = resolver.resolve_ip(&body.name).await;
    let _ = body.qtype;
    Json(serde_json::json!({ "name": body.name, "answer": result.map(|ip| ip.to_string()) }))
}

// upstream: hub/route/dns.go — GET alias added alongside existing POST.
// Class B per ADR-0002: POST kept for back-compat; GET matches upstream's current form.
async fn dns_query_get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DnsQueryRequest>,
) -> Response {
    let enabled = state
        .raw_config
        .read()
        .dns
        .as_ref()
        .is_some_and(|dns| dns.enable.unwrap_or(false));
    if !enabled {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message": "DNS section is disabled"})),
        )
            .into_response();
    }

    use hickory_proto::rr::RecordType;
    let qtype_text = params.qtype.as_deref().unwrap_or("A").to_ascii_uppercase();
    let Ok(record_type) = qtype_text.parse::<RecordType>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message": "invalid query type"})),
        )
            .into_response();
    };

    let resolver = state.tunnel.resolver();
    let fqdn = if params.name.ends_with('.') {
        params.name.clone()
    } else {
        format!("{}.", params.name)
    };
    let question = serde_json::json!({
        "Name": fqdn,
        "Qtype": u16::from(record_type),
        "Qclass": 1,
    });

    let mut response = serde_json::Map::new();
    response.insert("Status".into(), 0.into());
    response.insert("Question".into(), serde_json::Value::Array(vec![question]));
    response.insert("TC".into(), false.into());
    response.insert("RD".into(), true.into());
    response.insert("RA".into(), true.into());
    response.insert("AD".into(), false.into());
    response.insert("CD".into(), false.into());

    if matches!(record_type, RecordType::A | RecordType::AAAA) {
        let ips = resolver.resolve_ips(&params.name).await.unwrap_or_default();
        let answers: Vec<_> = ips
            .into_iter()
            .filter(|ip| {
                matches!(record_type, RecordType::A) && ip.is_ipv4()
                    || matches!(record_type, RecordType::AAAA) && ip.is_ipv6()
            })
            .map(|ip| {
                serde_json::json!({
                    "name": fqdn,
                    "type": u16::from(record_type),
                    "TTL": 60,
                    "data": ip.to_string(),
                })
            })
            .collect();
        if !answers.is_empty() {
            response.insert("Answer".into(), serde_json::Value::Array(answers));
        }
    } else if let Some(message) = resolver.forward_generic(&params.name, record_type).await {
        let metadata = &message.metadata;
        response.insert("Status".into(), u16::from(metadata.response_code).into());
        response.insert("TC".into(), metadata.truncation.into());
        response.insert("RD".into(), metadata.recursion_desired.into());
        response.insert("RA".into(), metadata.recursion_available.into());
        response.insert("AD".into(), metadata.authentic_data.into());
        response.insert("CD".into(), metadata.checking_disabled.into());
        insert_dns_records(&mut response, "Answer", &message.answers);
        insert_dns_records(&mut response, "Authority", &message.authorities);
        insert_dns_records(&mut response, "Additional", &message.additionals);
    } else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message": "DNS query failed"})),
        )
            .into_response();
    }

    Json(serde_json::Value::Object(response)).into_response()
}

fn insert_dns_records(
    target: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    records: &[hickory_proto::rr::Record],
) {
    if records.is_empty() {
        return;
    }
    target.insert(
        key.to_string(),
        serde_json::Value::Array(
            records
                .iter()
                .map(|record| {
                    serde_json::json!({
                        "name": record.name.to_string(),
                        "type": u16::from(record.record_type()),
                        "TTL": record.ttl,
                        "data": record.data.to_string(),
                    })
                })
                .collect(),
        ),
    );
}

async fn flush_dns_cache(State(state): State<Arc<AppState>>) -> StatusCode {
    state.tunnel.resolver().clear_cache();
    StatusCode::NO_CONTENT
}

/// `POST /cache/fakeip/flush` — clear every fake-IP allocation. Mirrors
/// upstream `hub/route/cache.go::flushFakeIPPool`. Returns 204 on success,
/// 400 with a JSON `{message: ...}` body if persistence flushing fails.
async fn flush_fakeip_cache(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    match state.tunnel.resolver().flush_fake_ip() {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": e.to_string() })),
        )),
    }
}

async fn close_all_connections(State(state): State<Arc<AppState>>) -> StatusCode {
    state.tunnel.statistics().close_all_connections();
    StatusCode::NO_CONTENT
}

// ── Config save ──────────────────────────────────────────────────────

async fn save_config(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let raw = state.raw_config.read().clone();
    meow_config::save_raw_config_async(&state.config_path, &raw)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({"message": "config saved"})))
}

// ── Helper: rebuild proxies/rules from raw and apply to tunnel ───────

/// Pre-resolve DNS-sourced ECH then rebuild proxies/rules from `raw` and
/// apply to the live tunnel. Takes the config *by value* so callers
/// clone-and-drop their `parking_lot` guard before awaiting — those guards
/// are not Send and would otherwise break the axum Handler bound.
async fn apply_raw_to_tunnel(
    mut raw: RawConfig,
    state: &AppState,
) -> Result<(), (StatusCode, String)> {
    let expected_groups: Vec<String> = raw
        .proxy_groups
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|group| group.name.clone())
        .collect();
    if let Some(ps) = raw.proxies.as_mut() {
        meow_config::ech_dns::preresolve_ech(ps).await;
    }
    let providers = state
        .proxy_providers
        .iter()
        .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
        .collect();
    // Same provider-cache directory the daemon loaded its startup config
    // with — this is a trusted rebuild of the daemon's own running config,
    // not an untrusted candidate, so relative rule-provider paths must keep
    // resolving instead of hard-failing with `cache_dir: None` (issue #429
    // follow-up).
    let cache_dir = meow_config::resource_cache_dir_for_config_path(&state.config_path);
    let (proxies, rules) = rebuild_from_raw_with_resolver_async(
        raw,
        Arc::clone(state.tunnel.resolver()),
        providers,
        cache_dir,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if let Some(missing) = expected_groups
        .iter()
        .find(|name| !proxies.contains_key(name.as_str()))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proxy group '{missing}' failed validation"),
        ));
    }
    state.tunnel.update_routing(proxies, rules);
    Ok(())
}

async fn commit_raw_candidate(
    state: &AppState,
    candidate: RawConfig,
) -> Result<(), (StatusCode, String)> {
    apply_raw_to_tunnel(candidate.clone(), state).await?;
    swap_config_and_reconcile_tun(state, candidate).await;
    Ok(())
}

async fn rebuild_from_raw_with_resolver_async(
    raw: RawConfig,
    resolver: Arc<meow_dns::Resolver>,
    providers: HashMap<String, Arc<ProxyProvider>>,
    cache_dir: std::path::PathBuf,
) -> Result<meow_config::RebuildResult, String> {
    tokio::task::spawn_blocking(move || {
        meow_config::rebuild_from_raw_runtime(&raw, Some(resolver), &providers, Some(&cache_dir))
    })
    .await
    .map_err(|e| format!("config rebuild task failed: {e}"))?
    .map_err(|e| e.to_string())
}

// ── Subscriptions ────────────────────────────────────────────────────
// Subscriptions replace local proxies/groups/rules with the remote data as-is.

#[derive(Serialize)]
struct SubscriptionInfo {
    name: String,
    url: String,
    interval: Option<u64>,
    last_updated: Option<i64>,
    proxy_count: usize,
    group_count: usize,
    rule_count: usize,
}

async fn get_subscriptions(State(state): State<Arc<AppState>>) -> Json<Vec<SubscriptionInfo>> {
    let raw = state.raw_config.read();
    let subs = raw.subscriptions.as_deref().unwrap_or(&[]);
    let result: Vec<SubscriptionInfo> = subs
        .iter()
        .map(|s| SubscriptionInfo {
            name: s.name.clone(),
            url: s.url.clone(),
            interval: s.interval,
            last_updated: s.last_updated,
            proxy_count: raw.proxies.as_ref().map_or(0, std::vec::Vec::len),
            group_count: raw.proxy_groups.as_ref().map_or(0, std::vec::Vec::len),
            rule_count: raw.rules.as_ref().map_or(0, std::vec::Vec::len),
        })
        .collect();
    Json(result)
}

#[derive(Deserialize)]
struct AddSubscriptionRequest {
    name: String,
    url: String,
    interval: Option<u64>,
}

async fn add_subscription(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddSubscriptionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let fetched = meow_config::subscription::fetch_subscription(&body.url)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("fetch failed: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let pc = fetched.proxies.len();
    let gc = fetched.proxy_groups.len();
    let rc = fetched.rules.len();

    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();

        if let Some(ref subs) = raw.subscriptions {
            if subs.iter().any(|s| s.name == body.name) {
                return Err((
                    StatusCode::CONFLICT,
                    "subscription name already exists".into(),
                ));
            }
        }

        let sub = RawSubscription {
            name: body.name.clone(),
            url: body.url.clone(),
            interval: body.interval,
            last_updated: Some(now),
        };
        raw.subscriptions.get_or_insert_with(Vec::new).push(sub);

        // Replace proxies, groups, and rules with remote data as-is
        raw.proxies = Some(fetched.proxies);
        raw.proxy_groups = Some(fetched.proxy_groups);
        raw.rules = Some(fetched.rules);

        raw
    };
    commit_raw_candidate(&state, snapshot.clone()).await?;

    // Auto-save so subscription data is cached on disk
    meow_config::save_raw_config_async(&state.config_path, &snapshot)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "message": "subscription added",
        "proxy_count": pc, "group_count": gc, "rule_count": rc
    })))
}

async fn delete_subscription(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();

        if let Some(ref mut subs) = raw.subscriptions {
            let before = subs.len();
            subs.retain(|s| s.name != name);
            if subs.len() == before {
                return Err((StatusCode::NOT_FOUND, "subscription not found".into()));
            }
        } else {
            return Err((StatusCode::NOT_FOUND, "no subscriptions".into()));
        }

        // Clear everything from the remote subscription
        raw.proxies = Some(Vec::new());
        raw.proxy_groups = Some(Vec::new());
        raw.rules = Some(Vec::new());

        raw
    };
    commit_raw_candidate(&state, snapshot.clone()).await?;
    meow_config::save_raw_config_async(&state.config_path, &snapshot)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn refresh_subscription(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let url = {
        let raw = state.raw_config.read();
        raw.subscriptions
            .as_ref()
            .and_then(|subs| subs.iter().find(|s| s.name == name))
            .map(|s| s.url.clone())
            .ok_or_else(|| (StatusCode::NOT_FOUND, "subscription not found".into()))?
    };

    let fetched = meow_config::subscription::fetch_subscription(&url)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("fetch failed: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let pc = fetched.proxies.len();
    let gc = fetched.proxy_groups.len();
    let rc = fetched.rules.len();

    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();

        if let Some(ref mut subs) = raw.subscriptions {
            if let Some(sub) = subs.iter_mut().find(|s| s.name == name) {
                sub.last_updated = Some(now);
            }
        }

        raw.proxies = Some(fetched.proxies);
        raw.proxy_groups = Some(fetched.proxy_groups);
        raw.rules = Some(fetched.rules);

        raw
    };
    commit_raw_candidate(&state, snapshot.clone()).await?;

    // Auto-save so subscription data is cached on disk
    meow_config::save_raw_config_async(&state.config_path, &snapshot)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "message": "subscription refreshed",
        "proxy_count": pc, "group_count": gc, "rule_count": rc
    })))
}

// ── Proxy Groups ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct ProxyGroupInfo {
    name: String,
    #[serde(rename = "type")]
    group_type: String,
    proxies: Vec<String>,
    now: Option<String>,
    url: Option<String>,
    interval: Option<u64>,
    tolerance: Option<u16>,
}

async fn get_proxy_groups(State(state): State<Arc<AppState>>) -> Json<Vec<ProxyGroupInfo>> {
    let raw = state.raw_config.read();
    let groups = raw.proxy_groups.as_deref().unwrap_or(&[]);
    let route = state.tunnel.route_snapshot();
    let tunnel_proxies = &route.proxies;

    let result: Vec<ProxyGroupInfo> = groups
        .iter()
        .map(|g| {
            let runtime = tunnel_proxies.get(g.name.as_str());
            let now = runtime.and_then(|p| p.current());
            let proxies = runtime
                .and_then(|p| p.members())
                .unwrap_or_else(|| g.proxies.clone().unwrap_or_default());
            ProxyGroupInfo {
                name: g.name.clone(),
                group_type: g.group_type.clone(),
                proxies,
                now,
                url: g.url.clone(),
                interval: g.interval,
                tolerance: g.tolerance,
            }
        })
        .collect();
    Json(result)
}

#[derive(Deserialize)]
struct CreateProxyGroupRequest {
    name: String,
    #[serde(rename = "type")]
    group_type: String,
    proxies: Vec<String>,
    url: Option<String>,
    interval: Option<u64>,
    tolerance: Option<u16>,
}

async fn create_proxy_group(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateProxyGroupRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let group_name = body.name.clone();
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        if let Some(ref groups) = raw.proxy_groups {
            if groups.iter().any(|g| g.name == body.name) {
                return Err((StatusCode::CONFLICT, "group name already exists".into()));
            }
        }
        let group = RawProxyGroup {
            name: body.name,
            group_type: body.group_type,
            proxies: Some(body.proxies),
            url: body.url,
            interval: body.interval,
            tolerance: body.tolerance,
            ..Default::default()
        };
        raw.proxy_groups.get_or_insert_with(Vec::new).push(group);
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(Json(
        serde_json::json!({"message": "group created", "name": group_name}),
    ))
}

async fn update_proxy_group(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<CreateProxyGroupRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        let group = raw
            .proxy_groups
            .as_mut()
            .and_then(|groups| groups.iter_mut().find(|g| g.name == name))
            .ok_or_else(|| (StatusCode::NOT_FOUND, "group not found".into()))?;
        group.group_type = body.group_type;
        group.proxies = Some(body.proxies);
        group.url = body.url;
        group.interval = body.interval;
        group.tolerance = body.tolerance;
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_proxy_group(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        if let Some(ref mut groups) = raw.proxy_groups {
            let before = groups.len();
            groups.retain(|g| g.name != name);
            if groups.len() == before {
                return Err((StatusCode::NOT_FOUND, "group not found".into()));
            }
        } else {
            return Err((StatusCode::NOT_FOUND, "no groups".into()));
        }
        if let Some(ref mut rules) = raw.rules {
            rules.retain(|r| {
                let parts: Vec<&str> = r.split(',').collect();
                parts.last().is_none_or(|target| target.trim() != name)
            });
        }
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct SelectProxyRequest {
    name: String,
}

async fn select_proxy_in_group(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
    Json(body): Json<SelectProxyRequest>,
) -> StatusCode {
    let route = state.tunnel.route_snapshot();
    let Some(proxy) = route.proxies.get(group_name.as_str()).cloned() else {
        return StatusCode::NOT_FOUND;
    };
    let Some(selection) = proxy.selection() else {
        return StatusCode::BAD_REQUEST;
    };
    match selection.set(&body.name).await {
        Ok(()) => {
            info!("Proxy group '{}' switched to '{}'", group_name, body.name);
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

// ── Rules CRUD ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ReplaceRulesRequest {
    rules: Vec<String>,
}

async fn replace_rules(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ReplaceRulesRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        raw.rules = Some(body.rules);
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct UpdateRuleRequest {
    index: usize,
    rule: String,
}

async fn update_rule_at_index(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateRuleRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        let rules = raw.rules.get_or_insert_with(Vec::new);
        if body.index >= rules.len() {
            return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
        }
        rules[body.index] = body.rule;
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(index): Path<usize>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        let rules = raw.rules.get_or_insert_with(Vec::new);
        if index >= rules.len() {
            return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
        }
        rules.remove(index);
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ReorderRulesRequest {
    from: usize,
    to: usize,
}

async fn reorder_rules(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ReorderRulesRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _mutation = CONFIG_MUTATION.lock().await;
    let snapshot = {
        let mut raw = state.raw_config.read().clone();
        let rules = raw.rules.get_or_insert_with(Vec::new);
        if body.from >= rules.len() || body.to >= rules.len() {
            return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
        }
        let rule = rules.remove(body.from);
        rules.insert(body.to, rule);
        raw
    };
    commit_raw_candidate(&state, snapshot).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Delay probe endpoints ────────────────────────────────────────────
//
// Matches upstream mihomo `hub/route/proxies.go::getProxyDelay` and
// `hub/route/groups.go::getGroupDelay`. Error bodies are byte-exact copies
// of upstream's `ErrBadRequest` / `ErrNotFound` / `ErrRequestTimeout` /
// `newError("An error occurred in the delay test")`.

#[derive(Deserialize)]
struct DelayParams {
    url: Option<String>,
    timeout: Option<String>,
    expected: Option<String>,
}

#[derive(Serialize)]
struct DelayResp {
    delay: u16,
}

/// `{"message": "..."}` body matching upstream's error render.
fn msg_err(status: StatusCode, message: &'static str) -> Response {
    (status, Json(serde_json::json!({ "message": message }))).into_response()
}

/// Validate `url` and `timeout`. Returns `timeout` as `Duration` on success,
/// or the `400 Body invalid` response on any validation failure — matching
/// upstream's single "ErrBadRequest" shape for all parse errors.
fn parse_delay_params(params: &DelayParams) -> Result<Duration, Box<Response>> {
    // upstream: hub/route/proxies.go::getProxyDelay — url is not strictly
    // validated upstream, but an empty host would panic our prober.
    let url = params.url.as_deref().unwrap_or("").trim();
    if url.is_empty() {
        return Err(Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")));
    }

    // upstream parses `timeout` as int16 and treats parse failure as
    // ErrBadRequest. We reject 0 as well (a zero-budget probe is never useful).
    let timeout_str = params
        .timeout
        .as_deref()
        .ok_or_else(|| Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")))?;
    let timeout_ms: u16 = timeout_str
        .trim()
        .parse()
        .map_err(|_| Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")))?;
    if timeout_ms == 0 {
        return Err(Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")));
    }
    Ok(Duration::from_millis(timeout_ms as u64))
}

/// Probe a single adapter and record the result into its health handle.
/// On success records the measured delay; on any failure records `0` so
/// the proxy's `last_delay` tracks the most recent outcome.
async fn probe_and_record(
    proxy: &Arc<dyn meow_common::Proxy>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
) -> Result<u16, meow_proxy::health::UrlTestError> {
    meow_proxy::health::probe_and_record(proxy, url, expected, timeout).await
}

async fn get_proxy_delay(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(params): Query<DelayParams>,
) -> Response {
    let timeout = match parse_delay_params(&params) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    let url = params.url.as_deref().unwrap_or("").to_string();
    let expected = params.expected.clone();

    let route = state.tunnel.route_snapshot();
    // upstream: hub/route/proxies.go::getProxyDelay — findProxyByName middleware
    let Some(proxy) = route.proxies.get(name.as_str()).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };
    drop(route);

    match probe_and_record(&proxy, &url, expected.as_deref(), timeout).await {
        Ok(delay) => Json(DelayResp { delay }).into_response(),
        // upstream: `render.Status(r, http.StatusGatewayTimeout)` → 504.
        Err(meow_proxy::health::UrlTestError::Timeout) => {
            msg_err(StatusCode::GATEWAY_TIMEOUT, "Timeout")
        }
        // upstream: `newError("An error occurred in the delay test")` → 503.
        Err(meow_proxy::health::UrlTestError::Transport(_)) => msg_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "An error occurred in the delay test",
        ),
    }
}

async fn get_group_delay(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(params): Query<DelayParams>,
) -> Response {
    let route = state.tunnel.route_snapshot();
    let Some(group) = route.proxies.get(name.as_str()).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };
    // upstream: findProxyByName rejects non-groups with 404 for this route.
    let Some(member_names) = group.members() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };

    let timeout = match parse_delay_params(&params) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };

    // mihomo clears a URLTest/Fallback user pin before every group-wide
    // health check. Moved after query validation so a malformed request
    // does not silently clear user state.
    if let Some(selection) = group.selection().filter(|s| s.can_unfix()) {
        selection.force_set(None);
    }

    let url = params.url.as_deref().unwrap_or("").to_string();
    let expected = params.expected.clone();

    // Resolve each member name to an `Arc<dyn Proxy>` *before* dropping the
    // proxies map so the spawned tasks hold their own Arc clones.
    let members: Vec<(String, Arc<dyn meow_common::Proxy>)> = member_names
        .into_iter()
        .filter_map(|n| route.proxies.get(n.as_str()).cloned().map(|p| (n, p)))
        .collect();
    drop(route);

    // upstream: group probe wraps the whole batch in one context.WithTimeout,
    // not per-member. A slow member does not get its own budget.
    let collected = tokio::time::timeout(
        timeout,
        meow_proxy::health::probe_many_bounded_detailed(
            members,
            &url,
            expected.as_deref(),
            timeout,
            meow_proxy::health::GROUP_DELAY_CONCURRENCY,
        ),
    )
    .await;

    let Ok(pairs) = collected else {
        // upstream: 504 "Timeout". Even if some members completed before the
        // deadline, upstream still returns the timeout error — we match.
        return msg_err(StatusCode::GATEWAY_TIMEOUT, "Timeout");
    };

    let mut result: BTreeMap<String, u16> = BTreeMap::new();
    for pair in pairs {
        if matches!(pair.error, Some(meow_proxy::health::UrlTestError::Timeout)) {
            return msg_err(StatusCode::GATEWAY_TIMEOUT, "Timeout");
        }
        result.insert(pair.name, pair.delay);
    }
    Json(result).into_response()
}

// ── Config reload (M1.G-10) ──────────────────────────────────────────
// upstream: hub/server.go::patchConfig
// Class B per ADR-0002: payload must be base64 (upstream inconsistent); YAML parse errors
// always return 400 even with force=true; NOT upstream silent broken-config apply.

/// Spawn a TUN listener from a raw config and wait for device readiness.
/// Returns `Ok(Some(handle))` on success, `Ok(None)` when `tun.enable` is
/// false or the feature is not compiled in, or `Err(msg)` when startup fails
/// (permission denied, device-name conflict, timeout, etc.).
#[cfg(feature = "listener-tun")]
async fn spawn_tun_from_raw(
    tunnel: &Tunnel,
    raw: &RawConfig,
) -> Result<Option<tokio::task::JoinHandle<()>>, String> {
    let tun_cfg = match meow_config::parse_tun_config(raw.tun.as_ref(), raw.max_connections) {
        Ok(c) => c,
        Err(e) => {
            return Err(format!("tun config parse error: {e}"));
        }
    };
    if !tun_cfg.enable {
        return Ok(None);
    }

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let listener = TunListener::new(
        tunnel.clone(),
        crate::tun_config_to_listener_config(&tun_cfg),
        "meow-tun".to_string(),
    )
    .with_readiness_signal(ready_tx);

    let handle = tokio::spawn(async move {
        if let Err(e) = listener.run().await {
            tracing::error!("TUN listener error: {e}");
        }
    });

    // Await the readiness signal so we don't store a dead JoinHandle when
    // device creation fails (e.g. os error 5 / permission denied). The
    // timeout guards against a genuinely stuck startup path; immediate
    // failures are reported through `TunReady::Failed` without delay.
    match tokio::time::timeout(crate::TUN_STARTUP_TIMEOUT, ready_rx).await {
        Ok(Ok(meow_listener::TunReady::Ready)) => {}
        Ok(Ok(meow_listener::TunReady::Failed(msg))) => {
            tracing::error!(
                "TUN listener failed to start: {msg} \
                 (check permissions / admin / CAP_NET_ADMIN)"
            );
            handle.abort();
            return Err(msg);
        }
        Ok(Err(_)) => {
            // Should not happen with ReadyNotifier, but handle defensively.
            tracing::error!("TUN listener readiness signal dropped unexpectedly");
            handle.abort();
            return Err("TUN listener readiness signal dropped unexpectedly".into());
        }
        Err(_) => {
            let msg = format!(
                "TUN listener startup timed out after {} s",
                crate::TUN_STARTUP_TIMEOUT.as_secs()
            );
            tracing::error!("{msg}");
            handle.abort();
            return Err(msg);
        }
    }

    Ok(Some(handle))
}

#[cfg(not(feature = "listener-tun"))]
async fn spawn_tun_from_raw(
    _tunnel: &Tunnel,
    raw: &RawConfig,
) -> Result<Option<tokio::task::JoinHandle<()>>, String> {
    if raw.tun.as_ref().is_some_and(|t| t.enable) {
        // Err (not Ok(None)) so the off→on reconcile path rolls
        // `tun.enable` back — otherwise the stored config would claim TUN
        // is enabled while nothing can ever run.
        return Err("this build lacks the 'listener-tun' feature".into());
    }
    Ok(None)
}

/// Commit `candidate` as the new raw config and reconcile the TUN listener
/// against the `tun.enable` transition. The whole sequence is serialised by
/// `config_mutation_lock` so two concurrent mutations cannot interleave
/// their TUN start/stop operations — without this a disable→stop could run
/// before a sibling enable→start has stored its handle, leaving a running
/// device behind an `enable=false` config.
///
/// On an off→on transition, if the TUN listener fails to start the stored
/// config is rolled back (`tun.enable` set to `false`) to prevent state
/// inconsistency (the HTTP API would report TUN as enabled but nothing is
/// actually running).  The HTTP response is still 204 — the error is
/// logged but not surfaced to the caller.
async fn swap_config_and_reconcile_tun(state: &AppState, candidate: RawConfig) {
    let _guard = state.config_mutation_lock.lock().await;

    let new_enable = candidate.tun.as_ref().is_some_and(|t| t.enable);
    // Snapshot the candidate (only on an off→on transition, before it is
    // moved into the lock) so the parking_lot write guard — which is
    // !Send — is dropped before the first .await below.
    let (old_enable, snapshot) = {
        let mut guard = state.raw_config.write();
        let old = guard.tun.as_ref().is_some_and(|t| t.enable);
        let snapshot = (new_enable && !old).then(|| candidate.clone());
        *guard = candidate;
        (old, snapshot)
    };

    if old_enable == new_enable {
        return;
    }
    if let Some(snapshot) = snapshot {
        // off → on
        match spawn_tun_from_raw(&state.tunnel, &snapshot).await {
            Ok(Some(handle)) => {
                state.tunnel.set_tun_handle(handle).await;
                info!("TUN listener started via config reload");
            }
            Ok(None) => {
                // enable=true but spawn returned no handle — should not
                // happen for this transition, but treat as success.
            }
            Err(e) => {
                // TUN failed to start — roll back tun.enable to false so
                // nyanpasu / the dashboard don't show TUN as active when
                // nothing is actually running.
                warn!("TUN listener failed to start: {e} (config rolled back)");
                if let Some(ref mut tun) = state.raw_config.write().tun {
                    tun.enable = false;
                }
            }
        }
    } else {
        // on → off
        state.tunnel.stop_tun().await;
        info!("TUN listener stopped via config reload");
    }
}

#[derive(Deserialize)]
struct PutConfigsBody {
    path: Option<String>,
    payload: Option<String>,
}

async fn put_configs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<PutConfigsBody>,
) -> Response {
    let force = params.get("force").is_some_and(|v| v == "true");

    let yaml =
        match (body.path, body.payload) {
            (Some(p), _) => match tokio::fs::read_to_string(&p).await {
                Ok(s) => s,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"message": e.to_string()})),
                    )
                        .into_response()
                }
            },
            (_, Some(b64)) => {
                use base64::engine::general_purpose::STANDARD;
                use base64::Engine as _;
                let Ok(bytes) = STANDARD.decode(&b64) else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"message": "payload is not valid base64"})),
                    )
                        .into_response();
                };
                match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"message": "payload is not valid UTF-8"})),
                        )
                            .into_response()
                    }
                }
            }
            _ => return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"message": "request body must contain 'path' or 'payload'"}),
                ),
            )
                .into_response(),
        };

    // YAML syntax check — always 400 even with force=true (per spec)
    let mut raw_config: RawConfig = match serde_yaml::from_str(&yaml) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message": format!("config parse error: {e}")})),
            )
                .into_response()
        }
    };

    // Pre-resolve any DNS-sourced ECH configs into inline base64.
    if let Some(ps) = raw_config.proxies.as_mut() {
        meow_config::ech_dns::preresolve_ech(ps).await;
    }

    let _mutation = CONFIG_MUTATION.lock().await;

    // Semantic rebuild (proxy/rule parsing)
    let resolver = Arc::clone(state.tunnel.resolver());
    let providers = state
        .proxy_providers
        .iter()
        .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
        .collect();
    let cache_dir = meow_config::resource_cache_dir_for_config_path(&state.config_path);
    let (proxies, rules) = match rebuild_from_raw_with_resolver_async(
        raw_config.clone(),
        resolver,
        providers,
        cache_dir,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            if force {
                tracing::error!("config reload forced despite validation error: {e}");
                (Default::default(), Vec::new())
            } else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"message": format!("config validation error: {e}")})),
                )
                    .into_response();
            }
        }
    };

    // Prepare routing before the synchronous admission/cancellation boundary.
    // No old-policy setup can register after this cold reload completes.
    let mode = raw_config
        .mode
        .as_deref()
        .and_then(|mode| mode.parse().ok());
    let dropped = state.tunnel.reload_routing(proxies, rules, mode);
    if dropped > 0 {
        tracing::warn!(
            connections_dropped = dropped,
            "connection closure requested for cold reload"
        );
    }

    swap_config_and_reconcile_tun(&state, raw_config).await;

    StatusCode::NO_CONTENT.into_response()
}

// ── Prometheus metrics (M1.H-2) ──────────────────────────────────────
// upstream: N/A — meow-rs enhancement; Go mihomo has no native /metrics endpoint.

async fn get_metrics(State(_state): State<Arc<AppState>>) -> Response {
    // prometheus-client 0.22 requires AtomicU64/AtomicI64. On targets without
    // 64-bit atomics (e.g. MIPS32) these types don't exist in std, so we
    // return 501. cfg(target_has_atomic) is the correct gate — i686 Windows
    // is 32-bit-pointer but DOES have AtomicU64 via CMPXCHG8B.
    #[cfg(not(target_has_atomic = "64"))]
    {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "metrics require 64-bit atomic support",
        )
            .into_response();
    }

    #[cfg(target_has_atomic = "64")]
    {
        use prometheus_client::encoding::text::encode;
        use prometheus_client::metrics::counter::Counter;
        use prometheus_client::metrics::family::Family;
        use prometheus_client::metrics::gauge::Gauge;
        use prometheus_client::registry::Registry;
        use std::sync::atomic::{AtomicI64, AtomicU64};

        let mut registry = Registry::default();
        let stats = _state.tunnel.statistics();
        let (upload_total, download_total) = stats.snapshot();

        // meow_traffic_bytes — counter{direction}
        let traffic = Family::<Vec<(String, String)>, Counter<u64, AtomicU64>>::default();
        traffic
            .get_or_create(&vec![("direction".to_string(), "upload".to_string())])
            .inc_by(upload_total.max(0) as u64);
        traffic
            .get_or_create(&vec![("direction".to_string(), "download".to_string())])
            .inc_by(download_total.max(0) as u64);
        registry.register(
            "meow_traffic_bytes",
            "Cumulative bytes transferred since process start",
            traffic,
        );

        // meow_connections_active — gauge
        let connections_active = Gauge::<i64, AtomicI64>::default();
        connections_active.set(stats.active_connection_count() as i64);
        registry.register(
            "meow_connections_active",
            "Number of currently open connections",
            connections_active,
        );

        // meow_proxy_alive and meow_proxy_delay_ms — gauge{proxy_name,adapter_type}
        let proxy_alive = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
        let proxy_delay = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
        let route = _state.tunnel.route_snapshot();
        for (name, proxy) in &route.proxies {
            let labels = vec![
                ("proxy_name".to_string(), name.to_string()),
                ("adapter_type".to_string(), proxy.adapter_type().to_string()),
            ];
            proxy_alive
                .get_or_create(&labels)
                .set(if proxy.alive() { 1 } else { 0 });
            // Omit delay series entirely when no health check has run (empty history).
            // NOT -1, NOT 0 — absence is the correct Prometheus signal for "unknown".
            if !proxy.delay_history().is_empty() {
                proxy_delay
                    .get_or_create(&labels)
                    .set(proxy.last_delay() as i64);
            }
        }
        registry.register(
            "meow_proxy_alive",
            "Proxy alive status (1=alive, 0=dead)",
            proxy_alive,
        );
        registry.register(
            "meow_proxy_delay_ms",
            "Last measured proxy round-trip delay in milliseconds",
            proxy_delay,
        );

        // meow_rules_matched — counter{rule_type,action}
        let rules_matched = Family::<Vec<(String, String)>, Counter<u64, AtomicU64>>::default();
        for ((rule_type, action), count) in stats.rule_match.snapshot() {
            rules_matched
                .get_or_create(&vec![
                    ("rule_type".to_string(), rule_type.to_string()),
                    ("action".to_string(), action.to_string()),
                ])
                .inc_by(count);
        }
        registry.register(
            "meow_rules_matched",
            "Cumulative rule matches by type and action",
            rules_matched,
        );

        // meow_memory_rss_bytes — gauge
        let memory_rss = Gauge::<i64, AtomicI64>::default();
        memory_rss.set(read_rss_bytes().await as i64);
        registry.register(
            "meow_memory_rss_bytes",
            "Current process RSS in bytes",
            memory_rss,
        );

        // meow_info — gauge{version,mode} always = 1
        let info = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
        info.get_or_create(&vec![
            ("version".to_string(), env!("CARGO_PKG_VERSION").to_string()),
            ("mode".to_string(), _state.tunnel.mode().to_string()),
        ])
        .set(1);
        registry.register("meow_info", "meow-rs runtime info", info);

        let mut body = String::new();
        encode(&mut body, &registry).expect("prometheus text encoding is infallible");
        (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response()
    }
}

// ── WebSocket: log stream ────────────────────────────────────────────

#[derive(Deserialize)]
struct LogsParams {
    level: Option<String>,
    format: Option<String>,
}

fn parse_requested_log_level(
    value: Option<&str>,
) -> Result<crate::log_stream::LogLevel, Box<Response>> {
    let value = value.unwrap_or("info");
    match value.to_ascii_lowercase().as_str() {
        "debug" | "info" | "warning" | "warn" | "error" | "silent" => Ok(parse_log_level(value)),
        _ => Err(Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid"))),
    }
}

fn log_json(msg: &LogMessage, structured: bool) -> String {
    if !structured {
        return serde_json::json!({"type": msg.level.as_str(), "payload": msg.payload}).to_string();
    }
    let level = if msg.level.as_str() == "warning" {
        "warn"
    } else {
        msg.level.as_str()
    };
    let t = msg.time.time();
    serde_json::json!({
        "time": format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second()),
        "level": level,
        "message": msg.payload,
        "fields": [],
    })
    .to_string()
}

// upstream: hub/route/logs.go::getLogs
async fn get_logs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LogsParams>,
    MaybeWebSocket(ws): MaybeWebSocket,
) -> Response {
    let level = match parse_requested_log_level(params.level.as_deref()) {
        Ok(level) => level,
        Err(response) => return *response,
    };
    let structured = params.format.as_deref() == Some("structured");
    let mut rx = state.log_tx.subscribe();
    if let Some(ws) = ws {
        return ws.on_upgrade(move |mut socket| async move {
            loop {
                match rx.recv().await {
                    Ok(msg) if msg.level >= level => {
                        if socket
                            .send(Message::Text(log_json(&msg, structured).into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    let stream = futures::stream::unfold(rx, move |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(msg) if msg.level >= level => {
                    return Some((
                        Ok::<String, std::convert::Infallible>(format!(
                            "{}\n",
                            log_json(&msg, structured)
                        )),
                        rx,
                    ));
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .expect("valid log stream response")
}

// ── WebSocket: memory stream ─────────────────────────────────────────

// upstream: hub/route/memory.go
//
// One process-wide sampler task reads RSS + limit and serialises the JSON
// frame once per tick; every connected socket forwards the shared string
// (audit M8 — previously each socket sampled and serialised independently,
// per-socket per-tick). The sampler starts with the first subscriber and
// exits once the last socket disconnects, so an idle API server pays nothing.
// Model: the log websocket's single-serialisation broadcast fan-out.
static MEMORY_FEED: std::sync::Mutex<Option<broadcast::Sender<Arc<str>>>> =
    std::sync::Mutex::new(None);

fn subscribe_memory_feed() -> broadcast::Receiver<Arc<str>> {
    let mut guard = MEMORY_FEED.lock().expect("memory feed lock poisoned");
    if let Some(tx) = guard.as_ref() {
        // Sampler still alive (it clears the slot under this lock on exit).
        return tx.subscribe();
    }
    let (tx, rx) = broadcast::channel(2);
    *guard = Some(tx.clone());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            if tx.receiver_count() == 0 {
                // Re-check under the lock so a subscriber arriving right now
                // either sees the live sender or a cleared slot — never a
                // sender whose sampler has already exited.
                let mut guard = MEMORY_FEED.lock().expect("memory feed lock poisoned");
                if tx.receiver_count() == 0 {
                    *guard = None;
                    break;
                }
            }
            let inuse = read_rss_bytes().await;
            let oslimit = read_os_memory_limit().await;
            let msg: Arc<str> = Arc::from(format!("{{\"inuse\":{inuse},\"oslimit\":{oslimit}}}"));
            let _ = tx.send(msg);
        }
    });
    rx
}

async fn get_memory(
    State(_state): State<Arc<AppState>>,
    MaybeWebSocket(ws): MaybeWebSocket,
) -> Response {
    let first: Arc<str> = Arc::from("{\"inuse\":0,\"oslimit\":0}");
    if let Some(ws) = ws {
        return ws.on_upgrade(move |mut socket| async move {
            if socket
                .send(Message::Text(first.as_ref().into()))
                .await
                .is_err()
            {
                return;
            }
            let mut feed = subscribe_memory_feed();
            loop {
                let msg = match feed.recv().await {
                    Ok(msg) => msg,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if socket
                    .send(Message::Text(msg.as_ref().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    let feed = subscribe_memory_feed();
    let stream = futures::stream::unfold((Some(first), feed), |(first, mut feed)| async move {
        if let Some(first) = first {
            return Some((
                Ok::<String, std::convert::Infallible>(format!("{first}\n")),
                (None, feed),
            ));
        }
        loop {
            match feed.recv().await {
                Ok(msg) => {
                    return Some((
                        Ok::<String, std::convert::Infallible>(format!("{msg}\n")),
                        (None, feed),
                    ));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .expect("valid memory stream response")
}

async fn read_rss_bytes() -> u64 {
    tokio::task::spawn_blocking(|| {
        use sysinfo::{Pid, ProcessesToUpdate, System};
        let pid = Pid::from_u32(std::process::id());
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), false);
        sys.process(pid).map_or(0, sysinfo::Process::memory)
    })
    .await
    .unwrap_or(0)
}

async fn read_os_memory_limit() -> u64 {
    #[cfg(target_os = "linux")]
    {
        read_os_memory_limit_linux().await
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(target_os = "linux")]
async fn read_os_memory_limit_linux() -> u64 {
    // Try cgroup v2 memory limit first, fall back to rlimit.
    if let Ok(s) = tokio::fs::read_to_string("/sys/fs/cgroup/memory.max").await {
        if let Ok(n) = s.trim().parse::<u64>() {
            return n;
        }
    }
    // rlimit RLIMIT_AS (virtual address space) as a proxy; RLIMIT_RSS is deprecated.
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_AS, &mut rl) == 0 && rl.rlim_cur != libc::RLIM_INFINITY {
            #[cfg(target_pointer_width = "32")]
            {
                return rl.rlim_cur as u64;
            }
            #[cfg(not(target_pointer_width = "32"))]
            {
                return rl.rlim_cur;
            }
        }
    }
    0
}

// ── Proxy providers ───────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderInfo {
    name: String,
    #[serde(rename = "type")]
    provider_type: String,
    vehicle_type: String,
    proxies: Vec<ProxyInfo>,
    #[serde(rename = "testUrl")]
    test_url: String,
    #[serde(rename = "expectedStatus")]
    expected_status: String,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

fn unix_rfc3339(seconds: u64) -> Option<String> {
    use time::format_description::well_known::Rfc3339;
    (seconds > 0)
        .then(|| time::OffsetDateTime::from_unix_timestamp(seconds as i64).ok())
        .flatten()
        .and_then(|time| time.format(&Rfc3339).ok())
}

fn provider_to_info(name: &str, provider: &ProxyProvider) -> ProviderInfo {
    let proxies = provider
        .proxies()
        .iter()
        .map(ProxyInfo::from_proxy)
        .collect();
    ProviderInfo {
        name: name.to_string(),
        provider_type: "Proxy".to_string(),
        vehicle_type: provider.vehicle_type.to_string(),
        proxies,
        test_url: provider
            .health_check
            .as_ref()
            .map_or_else(String::new, |hc| hc.url.clone()),
        expected_status: provider
            .health_check
            .as_ref()
            .map_or_else(String::new, |hc| hc.expected_status.clone()),
        updated_at: unix_rfc3339(provider.updated_at_secs()),
    }
}

async fn get_providers(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut map = serde_json::Map::new();
    for entry in state.proxy_providers.iter() {
        let info = provider_to_info(entry.key(), entry.value());
        map.insert(
            entry.key().clone(),
            serde_json::to_value(info).unwrap_or_default(),
        );
    }
    Json(serde_json::json!({ "providers": map }))
}

async fn get_provider(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    match state.proxy_providers.get(&name) {
        Some(entry) => Json(provider_to_info(&name, entry.value())).into_response(),
        None => msg_err(StatusCode::NOT_FOUND, "resource not found"),
    }
}

async fn refresh_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    let provider = match state.proxy_providers.get(&name) {
        Some(entry) => Arc::clone(entry.value()),
        None => return msg_err(StatusCode::NOT_FOUND, "resource not found"),
    };
    match provider.refresh().await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"message": e})),
        )
            .into_response(),
    }
}

/// Trigger a health check for all proxies in the named provider.
/// Accepts the same `url` and `timeout` query params as `GET /proxies/:name/delay`.
async fn provider_healthcheck(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    let provider = match state.proxy_providers.get(&name) {
        Some(entry) => Arc::clone(entry.value()),
        None => return msg_err(StatusCode::NOT_FOUND, "resource not found"),
    };

    let Some(health) = provider.health_check.as_ref() else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let timeout = Duration::from_millis(health.timeout.max(1));
    let url = health.url.clone();
    let expected = (!health.expected_status.is_empty()).then(|| health.expected_status.clone());

    let members = provider
        .proxies()
        .into_iter()
        .map(|proxy| (proxy.name().to_string(), proxy))
        .collect();

    let _ = meow_proxy::health::probe_many_bounded(
        members,
        &url,
        expected.as_deref(),
        timeout,
        meow_proxy::health::PROVIDER_HEALTHCHECK_CONCURRENCY,
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}

async fn get_provider_proxy(
    State(state): State<Arc<AppState>>,
    Path((provider_name, proxy_name)): Path<(String, String)>,
) -> Response {
    let Some(provider) = state.proxy_providers.get(&provider_name) else {
        return msg_err(StatusCode::NOT_FOUND, "Resource not found");
    };
    match provider
        .proxies()
        .into_iter()
        .find(|p| p.name() == proxy_name)
    {
        Some(proxy) => Json(ProxyInfo::from_proxy(&proxy)).into_response(),
        None => msg_err(StatusCode::NOT_FOUND, "Resource not found"),
    }
}

async fn provider_proxy_healthcheck(
    State(state): State<Arc<AppState>>,
    Path((provider_name, proxy_name)): Path<(String, String)>,
    Query(params): Query<DelayParams>,
) -> Response {
    let timeout = match parse_delay_params(&params) {
        Ok(timeout) => timeout,
        Err(response) => return *response,
    };
    let Some(provider) = state.proxy_providers.get(&provider_name) else {
        return msg_err(StatusCode::NOT_FOUND, "Resource not found");
    };
    let Some(proxy) = provider
        .proxies()
        .into_iter()
        .find(|p| p.name() == proxy_name)
    else {
        return msg_err(StatusCode::NOT_FOUND, "Resource not found");
    };
    match probe_and_record(
        &proxy,
        params.url.as_deref().unwrap_or(""),
        params.expected.as_deref(),
        timeout,
    )
    .await
    {
        Ok(delay) => Json(DelayResp { delay }).into_response(),
        Err(meow_proxy::health::UrlTestError::Timeout) => {
            msg_err(StatusCode::GATEWAY_TIMEOUT, "Timeout")
        }
        Err(meow_proxy::health::UrlTestError::Transport(_)) => msg_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "An error occurred in the delay test",
        ),
    }
}

// ── Rule Providers ────────────────────────────────────────────────────

#[derive(Serialize)]
struct RuleProviderInfo {
    name: String,
    #[serde(rename = "type")]
    provider_type: String,
    behavior: String,
    format: String,
    #[serde(rename = "ruleCount")]
    rule_count: usize,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    #[serde(rename = "vehicleType")]
    vehicle_type: String,
}

impl RuleProviderInfo {
    fn from_provider(p: &Arc<RuleProvider>, format: Option<&str>) -> Self {
        let vehicle_type = match p.provider_type {
            meow_config::rule_provider::ProviderType::Http => "HTTP",
            meow_config::rule_provider::ProviderType::File => "File",
            meow_config::rule_provider::ProviderType::Inline => "Inline",
        };
        Self {
            name: p.name.clone(),
            provider_type: "Rule".to_string(),
            behavior: p.behavior.to_string(),
            format: format.unwrap_or("yaml").to_string(),
            rule_count: p.rule_count(),
            updated_at: unix_rfc3339(p.updated_at_secs()).unwrap_or_default(),
            vehicle_type: vehicle_type.to_string(),
        }
    }
}

#[derive(Serialize)]
struct RuleProvidersResponse {
    providers: HashMap<String, RuleProviderInfo>,
}

async fn get_rule_providers(State(state): State<Arc<AppState>>) -> Json<RuleProvidersResponse> {
    let providers = state.rule_providers.read();
    let raw = state.raw_config.read();
    let map: HashMap<String, RuleProviderInfo> = providers
        .iter()
        .map(|(name, p): (&String, &Arc<RuleProvider>)| {
            let format = raw
                .rule_providers
                .as_ref()
                .and_then(|all| all.get(name))
                .and_then(|provider| provider.format.as_deref());
            (name.clone(), RuleProviderInfo::from_provider(p, format))
        })
        .collect();
    Json(RuleProvidersResponse { providers: map })
}

async fn get_rule_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<RuleProviderInfo>, StatusCode> {
    let providers = state.rule_providers.read();
    let p = providers.get(&name).ok_or(StatusCode::NOT_FOUND)?;
    let raw = state.raw_config.read();
    let format = raw
        .rule_providers
        .as_ref()
        .and_then(|all| all.get(&name))
        .and_then(|provider| provider.format.as_deref());
    Ok(Json(RuleProviderInfo::from_provider(p, format)))
}

async fn refresh_rule_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> StatusCode {
    let provider = {
        let providers = state.rule_providers.read();
        providers.get(&name).cloned()
    };
    let Some(p) = provider else {
        return StatusCode::NOT_FOUND;
    };
    let ctx = meow_rules::ParserContext::empty();
    match p.refresh(&ctx).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::warn!(provider = %name, "rule-provider refresh failed: {:#}", e);
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

// ── Listeners ─────────────────────────────────────────────────────────

async fn get_listeners(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let items: Vec<serde_json::Value> = state
        .listeners
        .iter()
        .map(|l| {
            serde_json::json!({
                "name": l.name,
                "type": l.spec.type_name(),
                "port": l.port,
                "listen": l.listen,
            })
        })
        .collect();
    Json(serde_json::json!(items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connections_interval_rejects_zero_and_garbage() {
        // `0` and non-numeric input stay a 400 at the handler — the parser
        // signals both with `None`.
        assert_eq!(parse_connections_interval(Some("0")), None);
        assert_eq!(parse_connections_interval(Some("abc")), None);
        assert_eq!(parse_connections_interval(Some("-1")), None);
        assert_eq!(parse_connections_interval(Some("")), None);
    }

    #[test]
    fn connections_interval_clamps_to_floor() {
        assert_eq!(parse_connections_interval(Some("1")), Some(100));
        assert_eq!(parse_connections_interval(Some("99")), Some(100));
        assert_eq!(parse_connections_interval(Some("100")), Some(100));
    }

    #[test]
    fn connections_interval_passes_through_above_floor() {
        assert_eq!(parse_connections_interval(Some("101")), Some(101));
        assert_eq!(parse_connections_interval(Some("5000")), Some(5000));
        assert_eq!(parse_connections_interval(None), Some(1000));
    }
}
