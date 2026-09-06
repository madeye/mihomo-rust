# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

meow-rs is a Rust implementation of the [mihomo](https://github.com/MetaCubeX/mihomo) (Clash Meta) proxy kernel. It provides rule-based tunneling with support for multiple proxy protocols (Shadowsocks, Trojan, Direct, Reject), transparent proxy (nftables/pf), DNS with snooping (IP→domain reverse table), and a REST API for runtime control. Licensed under MIT.

## Build Commands

```bash
# Build (requires Rust 1.89+, pinned via workspace rust-version)
cargo build --release

# Run with config
./target/release/meow -f config.yaml

# Test config validity
./target/release/meow -f config.yaml -t

# Run all unit tests
cargo test --lib

# Run specific integration/test suites
cargo test --test rules_test           # 100 rule matching tests
cargo test --test trojan_integration   # embedded mock server, no external deps
cargo test --test shadowsocks_integration  # requires ssserver (see below)
bash tests/test_tproxy_qemu.sh             # Docker-based tproxy e2e tests

# Install ssserver for SS integration tests
cargo install shadowsocks-rust --features "stream-cipher aead-cipher-2022" --locked

# Run tests for a single crate
cargo test -p meow-dns --lib

# Lint
cargo clippy --all-targets
```

## Architecture

```
Listeners (HTTP/SOCKS5/Mixed/TProxy/TUN)
        |
        v
    Tunnel (routing engine)  <-->  DNS Resolver (Snooping/Cache/FakeIP)
        |                                   ^
    Rule Matching Engine                    |
        |                            DNS Server (:1053)
        v
  Proxy Adapters / Groups  --->  Transport (TLS/WS/gRPC/H2/ECH)  --->  Remote
        ^
        |  (periodic probes)
  Health Check Task

  REST API + Web UI (Axum)  --->  Runtime control
  Subscription Refresh      --->  Auto-update proxy lists
```

### Workspace Crates

The workspace has 14 crates (see also [ADR-0009](docs/adr/0009-cleanup-scope.md) for crate-boundary policy):

| Crate | Purpose |
|-------|---------|
| `meow-common` | Core traits and types (`ProxyAdapter`, `Rule`, `Metadata`, `ConnContext`) — the "contracts" crate |
| `meow-trie` | Domain trie for efficient pattern matching |
| `meow-anytls` | Vendored fork of `anytls-rs` (lib name `anytls_rs`); MIT-licensed, in-tree to provide `Stream::close()` (see [#262](https://github.com/madeye/meow-rs/issues/262)). Pulled in only by `meow-proxy`'s opt-in `anytls` feature |
| `meow-lwip` | Vendored fork of `lwip` (madeye/lwip); MIT/Apache-2.0 bindings over BSD-3 lwIP C sources, in-tree because crates.io forbids `git` deps. Lib name `lwip`; pulled in only by `meow-listener`'s `listener-tun` feature |
| `meow-transport` | Composable stream-transport layers (TLS, WebSocket, gRPC, HTTP/2, HTTP Upgrade) — protocol-agnostic, no dep on other meow-rs crates (see [ADR-0001](docs/adr/0001-meow-transport-crate.md)) |
| `meow-proxy` | Proxy protocol implementations (SS, Trojan, VLESS, Direct, Reject), groups (Selector, URLTest, Fallback, LoadBalance, Relay), and health probing |
| `meow-rules` | Rule matching engine and parser (domain, IP-CIDR, GeoIP, process, logic composition) |
| `meow-dns` | DNS resolver, cache, DNS snooping (IP→domain reverse table), UDP server |
| `meow-tunnel` | Core routing engine: TCP/UDP relay, rule matching dispatch, connection statistics |
| `meow-listener` | Inbound protocol handlers (Mixed/HTTP/SOCKS5/TProxy, plus TUN behind the opt-in `listener-tun` feature) |
| `meow-config` | YAML configuration parsing into typed structs |
| `meow-api` | REST API server (Axum) for proxies, rules, connections, configs, traffic, DNS query |
| `meow-app` | CLI entry point (`main.rs`) — wires config → tunnel → listeners → DNS → API → health checks → subscription refresh |
| `meow-bench` | Standalone benchmark binary (throughput, latency, connection-rate, DNS, memory, binary-size) |

### Startup Flow

`meow-app/src/main.rs` → parse CLI args → `meow_config::load_config()` → create `Tunnel` → spawn health checks for fallback/url-test groups → spawn DNS server, API server, listeners (Mixed/SOCKS/HTTP/TProxy) as tokio tasks → await SIGINT/SIGTERM.

### Transparent-proxy gateway

The built-in TProxy listener firewall (`meow-listener/src/tproxy/firewall.rs`) is `output`-chain/REDIRECT-based and only covers the **host's own** traffic — it is *not* a forwarding LAN gateway. To proxy *other* devices' traffic you add prerouting rules + a DNS hijack yourself. Helper scripts automate this: `scripts/tproxy-gateway-linux.sh` (nftables) and `scripts/tproxy-gateway-macos.sh` (pf, experimental). Full setup, DNS-mode (fake-ip vs redir-host) trade-offs, and systemd wiring are in [docs/tproxy-gateway.md](docs/tproxy-gateway.md). macOS *local* tproxy (managed pf anchor + manual `route-to lo0` for real outbound traffic, IPv4 TCP only) is documented in [docs/tproxy-macos.md](docs/tproxy-macos.md). Note: the top-level `tproxy-port` hard-binds `127.0.0.1`; a gateway must declare the listener via `listeners:` with a non-loopback `listen`.

### TUN inbound (Windows transparent proxy)

The `tun:` config section (issue #326, feature `listener-tun`, in the `full` bundle) provides transparent proxying via an L3 device — the only transparent option on Windows, also usable on Linux/macOS. Implementation: `meow-listener/src/tun/` (tun-rs device + lwIP userspace stack + route_manager auto-route). On Windows the device is Wintun (`wintun.dll` sidecar or the official DLL embedded in the binary). v1 is fake-IP-scoped: `auto-route` routes only the fake-ip range into the device, which makes routing loops structurally impossible (outbound dials go to real IPs) at the cost of not capturing IP-literal traffic. TCP accept is post-handshake and waits for the first payload before `handle_tcp`; UDP is one packet-level netstack socket demuxed by a listener-owned flow table (per-flow tasks mirroring the SOCKS5-UDP routing, idle-evicted after `udp-timeout`); `dns-hijack` answers UDP :53 via `DnsServer::handle_query`. Setup guide: [docs/tun.md](docs/tun.md).

### Key Patterns

- **`ProxyAdapter` trait** (`meow-common/src/adapter.rs`) — all proxy protocols implement this async trait for TCP connect and UDP relay
- **`Rule` trait** (`meow-common/src/rule.rs`) — all rule types implement this for matching against `Metadata`
- **Proxy groups** (`meow-proxy/src/group/`) — Selector, URLTest, Fallback wrap multiple adapters with selection strategies
- **Tunnel** (`meow-tunnel/src/tunnel.rs`) — central `Arc`-shared routing engine; holds proxies, rules, DNS resolver, connection stats

### Adding New Proxy Protocols

1. Implement `ProxyAdapter` trait in a new file under `meow-proxy/src/`
2. Add the adapter type variant to `AdapterType` enum in `meow-common/src/adapter_type.rs`
3. Register parsing in `meow-config/src/lib.rs` proxy config section

### Adding New Rule Types

1. Implement `Rule` trait in `meow-rules/src/`
2. Add the rule type variant to `RuleType` enum in `meow-common/src/rule.rs`
3. Register parsing in `meow-rules/src/parser.rs`

## Lint Policy

Workspace-wide clippy lints are declared in the root `Cargo.toml` `[workspace.lints.clippy]` table; every member crate opts in via `[lints] workspace = true`. See [ADR-0010](docs/adr/0010-m1-hygiene-and-gates.md) for the full rationale and [ADR-0010 Addendum A](docs/adr/0010-m1-hygiene-and-gates-addendum.md) for the allocation-focused additions.

Curated lint set (all `warn` unless noted):

**Readability / style** — `uninlined_format_args`, `redundant_closure`, `redundant_closure_for_method_calls`, `redundant_clone`, `cloned_instead_of_copied`, `manual_let_else`, `map_unwrap_or`, `semicolon_if_nothing_returned`, `explicit_iter_loop`, `needless_pass_by_value`, `match_same_arms`, `if_not_else`, `unnecessary_wraps`

**Allocation / footprint** (addendum A1, feeds M2 baseline) — `clone_on_ref_ptr`, `needless_collect`, `format_push_string`, `string_add`, `useless_format`, `large_enum_variant`, `large_types_passed_by_value`, `unnecessary_box_returns`, `vec_init_then_push`

Explicitly suppressed workspace-wide (too noisy without benefit): `module_name_repetitions`, `struct_excessive_bools`, `too_many_lines`, `missing_errors_doc`, `missing_panics_doc`.

When a specific site cannot be fixed cleanly, use `#[allow(clippy::lint_name, reason = "…")]` inline — no silent allows.

## Regression Bar

Run before every commit and push:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo test -p meow-listener --all-features --lib udp_port_53

# Mirrors the "Unit + integration tests (default features)" CI step. `--lib`
# alone is not enough: it skips every `--test` target, so a broken integration
# test (e.g. the ADR-0001 guard in `crate_invariants_test`) passes locally and
# lands `main` red.
cargo test --lib --bin meow \
  --test socks5_udp_user \
  --test common_test --test dns_cache_test --test config_test \
  --test statistics_test --test rules_test --test api_test \
  --test raii_guard_test --test http_connection_close \
  --test config_persistence_test --test systemd_config_test \
  --test trojan_integration --test vless_config_test --test vless_integration \
  --test v2ray_plugin_integration --test pre_resolve_test \
  --test tls_test --test ws_test --test crate_invariants_test \
  --test crate_publish_metadata_test
```

Keep the target list in sync with `.github/workflows/test.yml`; a new `tests/`
file that CI runs but this list omits is invisible to the local bar.

The three-way clippy check (default / no-default-features / all-features) is enforced in CI via `.github/workflows/test.yml` (added in M1, per ADR-0010 §3).

M1 exit integration gates (run before closing M1):
```bash
cargo test --test rules_test
cargo test --test trojan_integration
cargo test --test shadowsocks_integration
```
Docker-based tproxy QEMU test (`bash tests/test_tproxy_qemu.sh`) is CI-only; do not block local work on it.

## Architecture Invariants

These invariants apply to any PR that touches the listed types or subsystems. A PR that violates them must include an ADR amendment or a measured justification in the commit body.

### Footprint / performance axes (ADR-0006, -0007, -0008, -0011)

Four ADRs define the quantitative bar for this codebase:

| ADR | Axis | Gate |
|-----|------|------|
| [ADR-0006](docs/adr/0006-performance-targets.md) | Throughput + latency (W1–W5 workloads) | Median ≥ 0.98× baseline at M2 open |
| [ADR-0007](docs/adr/0007-binary-size-caps.md) | Stripped binary size | Hard caps by profile + target; no breach |
| [ADR-0008](docs/adr/0008-zero-alloc-invariants.md) | Hot-path allocation count | HP-1/HP-2/HP-3 reproducers never increase |
| [ADR-0011](docs/adr/0011-m2-footprint-targets.md) | Key-type struct sizes | Per-type targets; byte delta mandatory in commit body |

Any PR touching these types **must** include before/after byte counts (from `-Zprint-type-sizes`) in the commit body:

- `Metadata` (`crates/meow-common/src/metadata.rs`) — M2 baseline 272 B struct / heap via SmolStr
- `ConnectionInfo` (`crates/meow-tunnel/src/statistics.rs`) — M2 exit 120 B
- `UdpSession` (`crates/meow-tunnel/src/udp.rs`) — M2 exit 40 B
- DNS `CacheEntry` / `ReverseEntry` (`crates/meow-dns/src/cache.rs`) — M2 exit 72 B per `CacheEntry` (the LRU `.val`; full `LruEntry` slot incl. key + links is ~104 B on macOS)

Any PR touching relay code (`crates/meow-tunnel/src/relay.rs`, `tcp.rs`, or call sites in `meow-listener`) must preserve the zero-per-relay-setup-allocation invariant: relay buffers are stack-allocated in the caller's async frame, not heap-allocated per call.

### Benchmark baselines (docs/benchmarks/)

See [docs/benchmarks/index.md](docs/benchmarks/index.md) for a collated table of M2 deltas and pointers to all baseline documents. The full M2 exit gauntlet results live in `docs/benchmarks/m2-exit-summary.md` (produced by QA at M2 close).

## Key Dependencies

- **Async runtime**: tokio (multi-threaded)
- **Proxy protocols**: `shadowsocks` crate for SS; TLS for Trojan/VLESS/VMess/HTTP/SOCKS5 goes through `meow_transport::tls::TlsLayer`
- **TLS/crypto backend**: BoringSSL is the single crypto library. `meow-transport`'s `tls` feature *is* BoringSSL (`boring`/`tokio-boring`; `boring-tls` is a no-op alias); health probes, the internal HTTP fetcher (`meow-config/src/internal_http.rs`, which replaced `reqwest`), DoT/DoH, and the vendored anytls client (via its `TlsConnect` hook) all reuse the same `TlsLayer`. Hysteria2's QUIC uses `quiche` with the `boringssl-boring-crate` feature, so it links the SAME vendored BoringSSL — no rustls, no second crypto lib. **`boring` is pinned to `=4.22.0`** because that is the version quiche's boring-crate feature accepts (`^4.3`); a single `links = "boringssl"` copy is shared. rustls survives only as a dev-dependency for the loopback TLS test servers. `boring-sys` needs cmake + a C++ compiler on every build
- **DNS**: `hickory-resolver`/`hickory-server`/`hickory-proto`
- **Web framework**: axum + tower
- **GeoIP**: `maxminddb`
