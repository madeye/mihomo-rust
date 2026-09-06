# Test Plan: Config reload API — PUT /configs and GET /configs (M1.G-10)

Status: **draft** — owner: pm. Last updated: 2026-04-18.
Tracks: task #23. Companion to `docs/specs/api-config-reload.md`.

Scope amendment (2026-09-05, [#510](https://github.com/meow-rs/meow-rs/issues/510)):
the current acceptance scope is immediate TCP cancellation plus a synchronized
routing/registration boundary, not listener teardown or five-second draining.
**C3/C4 are superseded, not fulfilled.** C1/C2 and F1 remain deferred to listener
reconciliation/M3; the ArcSwap-specific cases were superseded by #327. The
historical case list below does not override these amendments.

Current regressions run in the existing `meow-tunnel --lib`, `api_test`, and
`http_connection_close` suites, which are already included in CI:

| Case | Evidence |
|------|----------|
| DNS-delayed setup crosses two completed PUT requests | Release a real loopback DNS answer afterward; the old DIRECT destination must never be dialed, inbound must receive EOF/RST, and a fresh connection must obey REJECT. |
| Plain HTTP setup crosses publication | Pause rule matching before registration, reload, and resume; the old DIRECT origin must never be contacted and the client receives EOF. |
| Registration races closure | A setup either registers before cancellation and observes its close signal, or is rejected without an entry. Repeated reloads of the same config cannot admit an old setup. |
| Candidate preparation and snapshot publication | Pause rule compilation; readers still see the entire old snapshot and old flows remain registered. After publication, new rules and proxies agree; non-cold updates preserve flows. |
| Immediate cancellation | Existing #509 live-stream regression observes EOF/RST in both directions without a five-second wait. |

Admission begins at TCP routing, after handshake/sniffing. A pending DNS query
need not be cancelled immediately, but cannot register or dial with its old
decision after returning. UDP flow cancellation and listener/DNS configuration
reconciliation are outside this PR's acceptance scope.

This is the QA-owned acceptance test plan. The spec's `§Test plan` section
is the PM's starting point; this document is the final shape engineer should
implement against. If the spec and this document disagree, **this document
wins for test cases** — flag the discrepancy so the spec can be updated.

Divergence-comment convention per memory (`feedback_spec_divergence_comments.md`):
inline `Upstream: file::fn` + `NOT X` lines on bullets that exercise a
divergence. ADR-0002 Class cite (A or B) per `feedback_adr_0002_class_cite.md`.

## Scope and guardrails

**In scope:**

- `PUT /configs` — path-based reload, payload-based reload (base64 YAML),
  `?force` semantics, auth enforcement, 400/204/401 response codes.
- `GET /configs` — current config serialisation, `Option::None` field omission.
- `AppState::reload()` — drain timeout, `connections_dropped` structured log,
  listener teardown and restart.
- `ArcSwap<Tunnel>` correctness — wait-free read path, atomic store on reload.
- M1 scope boundary: cold reload only; hot-reload is M3.
- All four divergences from upstream `hub/server.go::patchConfig`.

**Out of scope (forbidden per spec §Out of scope):**

- Hot-reload (no dropped connections) — M3.
- PATCH partial config update — M1 replaces full config only.
- Config version history / rollback — M3+.
- Persisting PUT payload to disk — payload is memory-only unless engineer
  explicitly implements optional persistence; not in M1 spec.
- Dashboard UI compatibility testing — not our test surface.

## File layout expected

```
crates/meow-api/src/
  routes.rs            # MODIFIED: put_configs, get_configs handlers + routes
  state.rs             # MODIFIED: ArcSwap<Tunnel>, reload() method
Cargo.toml             # MODIFIED: arc-swap = "1", base64 = "0.22"
crates/meow-api/tests/
  config_reload_test.rs  # NEW: handler unit tests (axum test client)
  config_reload_integration_test.rs  # NEW: full restart-reload integration test
```

## Divergence table

Following ADR-0002 classification format:

| # | Case | Class | Note |
|---|------|:-----:|------|
| 1 | `payload` field — upstream some dashboard versions send raw YAML string | B | We require base64. Raw YAML in payload field returns 400 with helpful message. Upstream: `hub/server.go::patchConfig` — raw string accepted. NOT silent corrupt decode. |
| 2 | `?force=true` — upstream silently applies broken config, no prominent log | B | We log each validation error as `error!` before proceeding. Upstream: `patchConfig` force path — no prominent logging. Same end result, more observable. |
| 3 | `GET /configs` — upstream returns full Go runtime struct including state | B | M1 returns `RawConfig` fields only (static config). Runtime state via /proxies, /rules, /connections. Upstream: `hub/server.go::getConfigs`. NOT null fields for absent Options. |
| 4 | In-flight connections dropped on reload — upstream attempts graceful handover | A | Cold reload is intentional M1 simplification. Connections logged before force-close. Upstream: `hub/server.go` graceful tunnel swap. NOT silent drop — Class A per ADR-0002: operators must see what was dropped. |

---

## Case list

### A. `PUT /configs` handler unit tests (`crates/meow-api/tests/config_reload_test.rs`)

All cases use an axum test client with a mock `AppState` that records reload
calls. No real listeners spawned. Use `#[tokio::test]`.

| # | Case | Asserts |
|---|------|---------|
| A1 | `put_configs_path_valid_returns_204` | POST valid YAML path that exists on disk. Assert `204 No Content`. Assert `AppState::reload` called once. <br/> Upstream: `hub/server.go::patchConfig` — 204 on success. NOT 200. |
| A2 | `put_configs_payload_base64_valid_returns_204` | `{"payload": "<base64 of valid YAML>"}`. Assert 204. Assert decoded YAML passed to reload. |
| A3 | `put_configs_payload_base64_decoded_correctly` **[guard-rail]** | Encode `"port: 7890\n"` as base64. Assert the YAML string passed to `parse_raw_config` is exactly `"port: 7890\n"`. Guards that base64 decode is not double-decoded or truncated. |
| A4 | `put_configs_invalid_yaml_syntax_returns_400` | `{"payload": "<base64 of 'port: {bad: yaml: ['>"}`. Assert `400`. Assert response body JSON `{"message": "config parse error: ..."}`. Assert `AppState::reload` NOT called. <br/> Upstream: `hub/server.go::patchConfig` — returns error on parse fail. NOT 500. NOT 204. |
| A5 | `put_configs_invalid_yaml_error_body_is_json` **[guard-rail]** | Same bad YAML. Assert `Content-Type: application/json` header present on 400 response. Assert body parseable as `{"message": string}`. |
| A6 | `put_configs_force_true_semantic_error_returns_204` | `?force=true`, valid YAML with semantic error (e.g., proxy group referencing non-existent proxy name). Assert 204. Assert `error!` log emitted with validation error text. Assert reload called. <br/> Upstream: `hub/server.go::patchConfig` force path — proceeds without logging. <br/> NOT 400 — force bypasses semantic validation. |
| A7 | `put_configs_force_true_parse_error_still_400` | `?force=true`, malformed YAML syntax. Assert 400. Assert reload NOT called. <br/> Upstream: `patchConfig` — force flag applied to both parse and semantic errors (force can push a parse-broken config). <br/> NOT 204 — Class B per ADR-0002 §force semantics: we never apply parse-broken config even under force. |
| A8 | `put_configs_no_auth_returns_401` | No `Authorization` header, `secret` configured. Assert 401. Assert reload NOT called. |
| A9 | `put_configs_wrong_secret_returns_401` | Wrong Bearer token. Assert 401. |
| A10 | `put_configs_body_neither_path_nor_payload_returns_400` | `{}` body. Assert 400 with message containing `"path"` and `"payload"`. |
| A11 | `put_configs_body_both_path_and_payload_uses_path` **[guard-rail]** | Body with both `path` and `payload`. Assert 400 or that exactly one is used (per engineer's implementation choice — document which in PR). Guards against ambiguous-body silent behavior. |
| A12 | `put_configs_payload_not_valid_base64_returns_400` | `{"payload": "not!!base64%%"}`. Assert 400 with message indicating decode failure. NOT panic. <br/> Upstream: Go `base64.StdEncoding.DecodeString` — returns error. We match but surface it as 400. |
| A13 | `put_configs_path_nonexistent_file_returns_400` | `{"path": "/tmp/does_not_exist_abc123.yaml"}`. Assert 400 with file-not-found message. NOT 500. NOT panic. |
| A14 | `put_configs_no_auth_configured_admits_without_token` **[guard-rail]** | `secret` not configured (empty). `PUT /configs` with no auth header. Assert 204 (no auth required). Guards that auth gate is absent when no secret set, matching behavior of all other endpoints. |

### B. `GET /configs` handler unit tests

| # | Case | Asserts |
|---|------|---------|
| B1 | `get_configs_returns_200_with_json` | `GET /configs`. Assert 200. Assert `Content-Type: application/json`. |
| B2 | `get_configs_port_matches_configured_value` | App configured with `mixed-port: 7890`. Assert response JSON contains `"mixed-port": 7890`. |
| B3 | `get_configs_absent_option_fields_omitted` | Config with no `socks-port`. Assert response JSON does NOT contain `"socks-port"` key (not `"socks-port": null`). <br/> Upstream: `hub/server.go::getConfigs` — includes null fields. <br/> NOT explicit null — Class B per ADR-0002: null Option fields are an internal implementation detail. |
| B4 | `get_configs_requires_auth_when_secret_set` | `GET /configs` with no auth, secret configured. Assert 401. |
| B5 | `get_configs_mode_field_reflects_current_mode` | Config with `mode: rule`. Assert `"mode": "rule"` in response. Regression guard that mode is serialised from active config, not a hardcoded default. |
| B6 | `get_configs_after_reload_reflects_new_config` **[guard-rail]** | Start with `mixed-port: 7890`. Reload to `mixed-port: 7891`. `GET /configs`. Assert `"mixed-port": 7891`. Guards that GET reflects post-reload state, not stale pre-reload config. |

### C. Original `AppState::reload()` unit tests (see amendment above)

These test the reload lifecycle in isolation with mock listeners and a
controlled connection count.

| # | Case | Asserts |
|---|------|---------|
| C1 | `reload_stops_old_listeners` | Mock listener tracking `is_stopped` flag. Call `reload()`. Assert all old mock listeners stopped. |
| C2 | `reload_starts_new_listeners_with_new_config` | Reload with config changing port. Assert new listeners started on new port. Assert old port not re-opened. |
| C3 | `reload_drains_connections_before_force_close` | Inject 3 mock connections with 100ms lifetime. Call `reload()`. Assert reload completes after connections finish (< 5s drain timeout). Assert `connections_dropped = 0` in log. |
| C4 | `reload_force_closes_connections_after_drain_timeout` | Inject a mock connection that never closes. Call `reload()`. Assert force-close occurs after 5s. Assert structured log `connections_dropped = 1` at `warn!` level. <br/> Upstream: `hub/server.go` — no drain timeout; immediate swap. <br/> NOT silent close — Class A per ADR-0002: operators must see dropped count. |
| C5 | `reload_connections_dropped_log_is_structured` **[guard-rail]** | Same as C4. Assert log contains field `connections_dropped` as a numeric key, NOT as part of an unstructured string like `"1 connections dropped"`. Engineers must use `warn!(connections_dropped = N, "...")` not `warn!("N connections dropped")`. |
| C6 | `reload_swaps_arc_swap_atomically` | Assert that after `reload()`, `state.tunnel.load()` returns the new tunnel, not the old one. |
| C7 | `reload_does_not_block_hot_path_reads` **[guard-rail]** | While reload is in progress (between drain and swap), assert `state.tunnel.load()` returns in O(1) without acquiring a lock. This is a structural test: verify `ArcSwap` is used (grep for `ArcSwap` in `state.rs`), not a `RwLock`. |

### D. `ArcSwap` correctness tests

| # | Case | Asserts |
|---|------|---------|
| D1 | `arc_swap_reader_sees_new_tunnel_after_store` | `ArcSwap::store(new_tunnel)` then `load()`. Assert `load()` returns the new tunnel. |
| D2 | `arc_swap_concurrent_reads_during_store` **[guard-rail]** | Spawn 10 reader tasks, each calling `load()` in a tight loop. Concurrently call `store(new_tunnel)`. Assert no panic, no data race. All readers eventually see the new tunnel. This is a smoke test, not a formal proof — `tokio::test` with `#[should_not_panic]` semantics. |

### E. M1 scope boundary tests

| # | Case | Asserts |
|---|------|---------|
| E1 | `put_configs_drops_connections_not_hot_reload` | Start a long-lived proxied connection. Call `PUT /configs` with valid new config. Assert the existing connection is closed (receives EOF or RST within the drain window + 5s). Assert new connections work after reload. <br/> Upstream: `hub/server.go` — hot swap, connections not dropped. <br/> NOT hot-reload — Class A per ADR-0002: M1 intentionally drops connections; operators are warned in docs. |
| E2 | `no_patch_endpoint_exists` **[guard-rail]** | `PATCH /configs`. Assert 405 Method Not Allowed (or 404). Partial config update is M3. |

### F. Integration test — full restart-reload cycle (`config_reload_integration_test.rs`)

`#[tokio::test]`, spawns a real meow-rs process in-process via
`AppState` + real listeners on loopback. Linux and macOS.

| # | Case | Asserts |
|---|------|---------|
| F1 | `config_reload_switches_listener_port` | Start with `mixed-port: 18090`. PUT new config with `mixed-port: 18091`. Assert port 18090 no longer accepts new connections (connection refused). Assert port 18091 accepts new connections. NOT both ports open simultaneously. |
| F2 | `config_reload_updates_rules` | Start with rule `MATCH,Direct`. Reload config with rule `MATCH,Reject`. Connect via proxy after reload. Assert connection rejected. Guards that tunnel rule set is replaced, not merged. |
| F3 | `config_reload_idempotent` **[guard-rail]** | Reload the same config twice in succession. Assert no panic, no port-already-in-use error, final state identical to a single reload. |

### G. Base64 and payload edge cases

| # | Case | Asserts |
|---|------|---------|
| G1 | `payload_standard_base64_alphabet` | YAML encoded with standard alphabet (`+`, `/`, `=` padding). Assert decoded correctly. |
| G2 | `payload_url_safe_base64_rejected` **[guard-rail]** | YAML encoded with URL-safe alphabet (`-`, `_`). Assert 400 with decode-error message. We use standard alphabet only (matching MetaCubeXD / Yacd). Engineer must NOT silently accept URL-safe. |
| G3 | `payload_with_line_breaks_rejected` **[guard-rail]** | Base64 string with `\n` line breaks (MIME-style). Assert 400. Standard encoding, no line breaks per spec. |
| G4 | `payload_empty_base64_returns_400` | `{"payload": ""}`. Assert 400. Empty payload decodes to empty string, not valid YAML config. |

---

## Deferred / not tested here

- Hot-reload (connection preservation across reload) — M3.
- PATCH partial config update — M3.
- Config rollback on reload failure — M3+.
- Prometheus metric `config_reloads_total` counter — M1.H-2 (separate spec).
- Throughput of reload path — not on the hot path; no benchmark needed.

---

## Exit criteria for this test plan

- All §A–G cases pass on `ubuntu-latest` and `macos-latest` in CI.
- `connections_dropped` structured log verified by §C5 (code review gate,
  not regex-on-log-output — too brittle).
- `GET /configs` never emits `null` values for absent fields (§B3 guard).
- `ArcSwap` usage confirmed structurally in §C7 (not `RwLock`).
- After reload, `cargo test --test config_reload_integration_test` green.

## CI wiring required

Add to `.github/workflows/test.yml`:

1. `cargo test -p meow-api --test config_reload_test` — §A–D, §G cases.
   Add to both `ubuntu-latest` and `macos-latest` jobs.
2. `cargo test -p meow-api --test config_reload_integration_test` — §E–F
   integration cases. Linux only for TProxy-adjacent cases; F1–F3 run on both.

## Open questions for engineer

1. **Both `path` and `payload` in body (§A11).** The spec doesn't specify
   precedence. Recommend: return 400 for ambiguous body to force clients to
   send exactly one. If the engineer instead picks `path`-first, document it
   explicitly and update §A11 assertion.
2. **Drain timeout configurability.** Spec fixes at 5s, not configurable in M1.
   If engineer wants to make it configurable, it must be a `RawConfig` field
   with a default of 5s — do not hard-code without a named constant.
3. **`GET /configs` serialisation completeness.** Spec says "fields present in
   `RawConfig` that are already serialisable." Confirm which fields in `RawConfig`
   still lack `#[derive(Serialize)]` at implementation time. Missing fields are
   acceptable for M1 — document them in a code comment so M2 can add them.
4. **URL-safe base64 (§G2).** Confirm the `base64 = "0.22"` API used is
   `STANDARD` (not `URL_SAFE`). This is a one-line choice at decode callsite
   but must be explicit in the PR.
