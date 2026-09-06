# Spec: Config reload API (M1.G-10)

Status: Approved (architect 2026-04-11)
Owner: pm
Tracks roadmap item: **M1.G-10**
Depends on: none — this is an API surface change that touches config loading,
not a new protocol.
See also: roadmap M3 "hot config reload without dropping connections" — this
M1 spec is the cold-reload endpoint; M3 upgrades it to hot-reload.
Upstream reference: `hub/server.go::patchConfig`, `component/profile/profile.go`.

Scope amendment (2026-09-05, [#510](https://github.com/meow-rs/meow-rs/issues/510)):
retain immediate cold-reload cancellation from #509 and fix the TCP admission
boundary and routing snapshot publication. The original five-second drain
design and test-plan C3/C4 are **superseded**, not completed. Listener lifecycle
reconciliation and connection-preserving hot reload remain separate M3 work.

The current boundary is the start of TCP routing, after inbound handshake and
sniffing. Setup captures a generation before reading mode/rules/proxies. It
registers under a read lock only if that generation is still current. Reload
builds and compiles the candidate first, then holds the matching write lock to
advance the generation, cancel tracked TCP flows, and publish rules/proxies
as one `Arc<RouteTable>` plus the requested mode. No lock spans DNS awaits or
relay. A DNS-delayed setup is rejected when it returns; cancellation of DNS
itself and inbound handshakes is not promised. A handshake that reaches routing
after the boundary uses the new configuration.

`connections_dropped` counts closure requests for registered TCP flows, not
completed socket teardowns or rejected unregistered setups. UDP sessions are
outside this boundary. Ordinary listener bindings/authentication and DNS
runtime are not rebuilt by PUT; TUN reconciliation currently compares only
`tun.enable`. These configuration-application gaps remain separate work.

## Motivation

The REST API has no way to reload configuration at runtime — operators must
restart the process to apply config changes. The `PUT /configs` endpoint is a
standard part of the Clash/mihomo API surface that dashboard tools (Yacd,
MetaCubeXD) call after a user edits configuration. Without it, dashboard
config editors are broken.

The implemented **cold reload** cancels tracked TCP flows and replaces routing
configuration. Connection-preserving hot reload is M3. Full listener teardown
from the original M1 design was never implemented.

## Scope

In scope:

1. `PUT /configs` accepts either a JSON body with a `path` field (reload from
   file) or a `payload` field (inline YAML as a base64-encoded string).
2. `?force=true` query parameter: if set, write the new config to disk and
   restart even if the config has parse errors. If unset and config is invalid,
   return 400 and leave current config unchanged.
3. Config validation (parse + schema check) before teardown of current config.
4. Immediately cancel registered TCP flows and reject older routing setups
   across one synchronized configuration-publication boundary.
5. Response: `204 No Content` on success; `400 Bad Request` with error
   message body on parse failure (when `?force=false`).
6. Auth: `require_auth` middleware — same as all other mutating REST endpoints.
7. `GET /configs` — returns the currently active config as JSON (partial:
   returns the subset of fields exposed by existing `/configs` GET if it
   exists, else add this endpoint). See §GET /configs.

Out of scope:

- **Hot-reload** (no dropped connections) — M3.
- **Partial config update (PATCH)** — full config replacement only in M1.
- **Config version history / rollback** — M3+.
- **Reload of individual sub-sections** — full replacement only.
- **Persisting config changes to disk** — when `path` is given, the file is
  re-read but not modified. When `payload` is given, the config is used in
  memory and optionally written to the current config path.

## User-facing API

### PUT /configs

**Request (load from file path):**
```http
PUT /configs HTTP/1.1
Authorization: Bearer <secret>
Content-Type: application/json

{"path": "/etc/meow/config.yaml"}
```

**Request (load from inline payload):**
```http
PUT /configs HTTP/1.1
Authorization: Bearer <secret>
Content-Type: application/json

{"payload": "cG9ydDogNzg5MAo="}
```
Where `payload` is the YAML config string, base64-encoded (standard encoding,
no line breaks).

**Query parameter:**
- `?force=true` — skip **semantic** validation (e.g., unknown proxy group names,
  duplicate listener ports) and apply the config anyway, logging each validation
  error as `error!`. Does NOT bypass **syntactic** (YAML parse) errors —
  a malformed YAML body returns 400 even with `?force=true`. Default: `false`.

**Response (success):** `204 No Content`

**Response (parse error, force=false):**
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"message": "config parse error: dns.nameserver[0]: invalid URL 'bad://host'"}
```

**Response (bad request body):** `400 Bad Request`
```json
{"message": "request body must contain 'path' or 'payload'"}
```

### GET /configs

Returns the currently active configuration as JSON. Upstream exposes the
full parsed config; M1 exposes the fields present in `RawConfig` that are
already serialisable. **Only non-null fields are included** — fields that are
`None` (not configured by the user) are omitted via
`#[serde(skip_serializing_if = "Option::is_none")]`. This avoids leaking
implementation-internal `Option` layout as explicit `null` values in the API.

```http
GET /configs HTTP/1.1
Authorization: Bearer <secret>
```

```json
{
  "port": 7890,
  "socks-port": 1080,
  "mixed-port": 7891,
  "allow-lan": false,
  "bind-address": "127.0.0.1",
  "mode": "rule",
  "log-level": "info",
  "ipv6": false
}
```

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Upstream `payload` field contains raw YAML string (not base64) in some dashboard versions — inconsistent | B | We require base64 in M1 for clean JSON embedding. Clients that send raw YAML get 400 with a helpful message. |
| 2 | `?force=true` — upstream silently applies broken config; M1 logs errors prominently | B | We log each parse error as `error!` before proceeding under force. Same end result. |
| 3 | GET /configs — upstream returns full Go struct including runtime state | B | M1 returns `RawConfig` fields only (static config, no runtime state). Runtime state is available via /proxies, /rules, /connections. |
| 4 | In-flight connections dropped on reload — upstream attempts graceful handover | A | Cold reload is intentional M1 simplification. Documented prominently in response headers and logs. NOT a silent drop. |

## Internal design

### Reload flow

```rust
// routes.rs

pub async fn put_configs(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<PutConfigsBody>,
) -> Result<StatusCode, ApiError> {
    let force = params.get("force").map(|v| v == "true").unwrap_or(false);

    // 1. Load raw YAML
    let yaml = match body {
        PutConfigsBody { path: Some(p), .. } => tokio::fs::read_to_string(&p).await?,
        PutConfigsBody { payload: Some(b64), .. } => {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine as _;
            String::from_utf8(STANDARD.decode(&b64)?)?
        }
        _ => return Err(ApiError::bad_request("must provide 'path' or 'payload'")),
    };

    // 2. Parse (YAML syntax) — always returns 400 on parse failure, even with force=true
    let raw_config = match parse_raw_config(&yaml) {
        Ok(cfg) => cfg,
        Err(e) => return Err(ApiError::bad_request(format!("config parse error: {e}"))),
    };

    // 3. Semantic validation — skipped when force=true
    if !force {
        if let Err(e) = validate_config(&raw_config) {
            return Err(ApiError::bad_request(format!("config validation error: {e}")));
        }
    } else {
        // Log validation errors but proceed anyway
        if let Err(e) = validate_config(&raw_config) {
            tracing::error!("config reload forced despite validation error: {e}");
        }
    }

    // 4. Reload
    state.reload(raw_config).await;
    Ok(StatusCode::NO_CONTENT)
}
```

### Original AppState::reload design (superseded by the scope amendment)

```rust
impl AppState {
    pub async fn reload(&self, config: Config) {
        // 1. Stop listeners (close listener sockets)
        // 2. Wait for active connections to drain (timeout: 5s)
        //    — after timeout, force-close remaining
        // 3. Reinitialize tunnel with new config
        // 4. Restart listeners
        // 5. Update self.raw_config
    }
}
```

**Historical drain timeout**: 5 seconds, not configurable in M1. After 5s, force-close
remaining connections with a structured log:

```rust
warn!(connections_dropped = N, "connections force-closed after reload drain timeout");
```

The `connections_dropped` field is a structured key so operators can alert on
non-zero values (e.g., Prometheus log scraping or Grafana Loki). Do NOT use
an unstructured string like `"N connections dropped"` — the count must be
machine-readable.

**AppState mutability**: `AppState` is currently `Arc`-shared and immutable.
Reload requires atomic swap of the tunnel.

> **Superseded by [#327](https://github.com/madeye/meow-rs/issues/327)** —
> `arc-swap` was dropped from the workspace over unproven memory-ordering
> correctness on weak-memory ARM. Use
> `parking_lot::RwLock<Arc<Tunnel>>` instead: handlers do
> `Arc::clone(&state.tunnel.read())` (guard dropped immediately, `Arc` safe
> to hold across `.await`). The original design below is kept for the record.

Use `arc_swap::ArcSwap<Tunnel>`:

```rust
// AppState
pub struct AppState {
    pub tunnel: Arc<ArcSwap<Tunnel>>,
    // ...
}
```

`ArcSwap` provides **wait-free reads** on the hot path (every request handler
calls `state.tunnel.load()` to get an `Arc<Tunnel>`) and an atomic store on
reload. This avoids adding a `RwLock` read-lock acquisition to every handler.

Add to `crates/meow-api/Cargo.toml`:
```toml
arc-swap = "1"
```

Hot-path usage in handlers:
```rust
let tunnel = state.tunnel.load();
// use tunnel (Arc<Tunnel>) — no lock held
```

Reload:
```rust
let new_tunnel = Arc::new(Tunnel::new(new_config));
state.tunnel.store(new_tunnel);
```

### Base64 crate

Add `base64 = "0.22"` to `meow-api/Cargo.toml`. Standard alphabet, no
line breaks. This matches what dashboard tools encode (MetaCubeXD, Yacd).

## Acceptance criteria

1. `PUT /configs` with valid `path` → 204; new routing config active.
   Rebinding listeners to changed ports remains a separate M3 requirement.
2. `PUT /configs` with valid `payload` (base64 YAML) → 204; same effect.
3. `PUT /configs` with invalid YAML → 400 with error message body;
   current config unchanged.
4. `PUT /configs?force=true` with valid YAML but semantic errors (e.g., unknown
   proxy group) → 204; validation errors logged as `error!`; process continues.
4b. `PUT /configs?force=true` with **invalid YAML** (syntax error) → 400;
   force flag does NOT override parse errors.
5. `PUT /configs` without auth token → 401.
6. `PUT /configs` body with neither `path` nor `payload` → 400.
7. `GET /configs` → 200 with JSON representation of current config fields.
8. `GET /configs` → field values match current running config (e.g., `port`
   matches the actually-listening port).
9. In-flight connections logged as "dropped" on reload; not silently closed.
   Minimum: a `warn!` with connection count before forced close.
10. After reload, new connections routed correctly by new config rules.

## Test plan (starting point — qa owns final shape)

**Unit (`routes.rs`):**

- `put_configs_path_valid_returns_204` — mock AppState with reload handler;
  valid YAML path → 204. Upstream: `hub/server.go::patchConfig`.
  NOT 200, NOT restart required.
- `put_configs_payload_base64_decoded_and_applied` — base64-encode valid YAML;
  PUT with payload → 204.
- `put_configs_invalid_yaml_returns_400` — malformed YAML → 400; body
  contains parse error message. NOT 500. NOT silent success.
- `put_configs_force_semantic_error_returns_204` — `?force=true` + valid YAML
  with semantic validation error → 204; validation errors logged as `error!`.
  Upstream: `hub/server.go::patchConfig` force path. NOT 400.
- `put_configs_force_parse_error_returns_400` — `?force=true` + malformed YAML
  → 400. Force flag does NOT override YAML parse failures. NOT 204.
- `put_configs_no_auth_returns_401` — no Bearer token → 401.
- `put_configs_empty_body_returns_400` — neither path nor payload → 400 with
  message.
- `get_configs_returns_current_config` — 200 with JSON; `port` field matches
  configured value.

**Integration:**

- `config_reload_switches_port` — start with `mixed-port: 7890`; PUT new
  config with `mixed-port: 7891`; assert old port closed, new port listening.
  NOT old port still accepting. NOT new port unopened.

## Original implementation checklist (historical; see scope amendment)

- [ ] Add `arc-swap = "1"` and `base64 = "0.22"` to `crates/meow-api/Cargo.toml`.
- [ ] Wrap `tunnel` in `Arc<ArcSwap<Tunnel>>` in `AppState`; update all handlers
      to use `state.tunnel.load()` (wait-free, no lock).
- [ ] Add `PutConfigsBody` struct (serde `path`, `payload` fields).
- [ ] Implement `put_configs` and `get_configs` handlers in `routes.rs`.
      `get_configs` serializes `RawConfig` with `skip_serializing_if = "Option::is_none"`.
- [ ] Register `PUT /configs` and `GET /configs` routes.
- [ ] Implement `AppState::reload()`: stop listeners → drain 5s → swap ArcSwap<Tunnel>
      → restart listeners. Log `connections_dropped=N` at `warn!`.
- [ ] Use `base64::engine::general_purpose::STANDARD.decode()` for payload decoding.
- [ ] Update `docs/roadmap.md` M1.G-10 row with merged PR link.

## Resolved questions (architect sign-off 2026-04-11)

1. **AppState::reload() ownership**: use `ArcSwap<Tunnel>` (not `Arc<RwLock<Tunnel>>`).
   `ArcSwap` provides wait-free reads on the hot path and atomic store on reload.
   No supervisor channel needed. Add `arc-swap = "1"` to `meow-api/Cargo.toml`.

2. **`?force=true` semantics**: `force=true` skips only **semantic** validation
   (unknown group names, duplicate ports, etc.). YAML parse errors are always
   returned as 400 — a malformed YAML body cannot be "forced" through.

3. **`GET /configs` field scope**: return only non-null fields. Use
   `#[serde(skip_serializing_if = "Option::is_none")]` on all `Option<_>` fields
   in `RawConfig`. Upstream returns a subset; explicit `null` values in the API
   response are an implementation detail leak.
