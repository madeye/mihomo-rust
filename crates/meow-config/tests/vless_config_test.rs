//! Config parser tests for `type: vless` proxies (§D from the test plan).
//!
//! All tests run under the default feature set (`vless` + `vless-vision`).
//!
//! # Test plan coverage (D-series)
//!
//! | ID | Description |
//! |----|-------------|
//! | D1  | `parse_vless_minimal_ok`                         — required-only fields load |
//! | D2  | `parse_vless_all_fields_roundtrip`               — all documented fields |
//! | D3  | `parse_vless_flow_empty_string_ok`               — `flow: ""` → no error |
//! | D4  | `parse_vless_flow_absent_ok`                     — absent flow → no error |
//! | D5  | `parse_vless_flow_vision_ok`                     — vision + tls → no error |
//! | D6  | `parse_vless_flow_unknown_hard_errors`           — unknown flow → hard error |
//! | D7  | `parse_vless_flow_deprecated_direct_hard_errors` — xtls-rprx-direct → hard error |
//! | D8  | `parse_vless_flow_deprecated_splice_hard_errors` — xtls-rprx-splice → hard error |
//! | D9  | `parse_vless_reality_opts_*`                     — REALITY config validation |
//! | D10 | `parse_vless_tls_false_plain_warns_once`         — tls: false warns + loads |
//! | D11 | `parse_vless_tls_false_no_duplicate_warn`        — warn fires once per load (not globally) |
//! | D12 | `parse_vless_vision_without_tls_hard_errors`     — vision + no TLS → hard error |
//! | D13 | `parse_vless_vision_with_grpc_transport_ok`      — vision + grpc (TLS-enforcing) → ok |
//! | D14 | `parse_vless_encryption_non_none_hard_errors`    — encryption: aes-128-gcm → hard error |
//! | D15 | `parse_vless_encryption_empty_string_accepted`   — encryption: "" → ok |
//! | D16 | `parse_vless_mux_enabled_loads_with_sing_mux`   — smux loads (h2mux default) |
//! | D17 | `parse_vless_vision_udp_true_warns_once`         — vision + udp warns + loads |
//! | D18 | `parse_vless_uuid_hex_and_dashed_both_accepted`  — both UUID forms ok |
//! | D19 | `parse_vless_uuid_invalid_hard_errors`           — bad uuid → hard error |
//! | D20 | `parse_vless_server_domain_over_255_errors`      — server > 255 bytes → hard error |

use std::sync::{Arc, Mutex};

use meow_config::load_config_from_str;
use tracing_subscriber::fmt::MakeWriter;

// ─── Warn-capture helper ─────────────────────────────────────────────────────

/// A `MakeWriter` that captures all log lines into a `Vec<String>`.
#[derive(Clone)]
struct CapWriter {
    lines: Arc<Mutex<Vec<String>>>,
    buf: Arc<Mutex<String>>,
}

impl CapWriter {
    fn new() -> Self {
        Self {
            lines: Arc::new(Mutex::new(Vec::new())),
            buf: Arc::new(Mutex::new(String::new())),
        }
    }

    fn captured(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
}

impl std::io::Write for CapWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(data).to_string();
        let mut b = self.buf.lock().unwrap();
        b.push_str(&s);
        if b.contains('\n') {
            let mut log = self.lines.lock().unwrap();
            for line in b.split('\n') {
                let t = line.trim();
                if !t.is_empty() {
                    log.push(t.to_string());
                }
            }
            b.clear();
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

/// Capture tracing WARN lines emitted while `fut` runs; return `(result, captured)`.
async fn with_warn_capture_async<Fut, R>(fut: Fut) -> (R, Vec<String>)
where
    Fut: std::future::Future<Output = R>,
{
    let cap = CapWriter::new();
    let cap_clone = cap.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(cap)
        .with_ansi(false)
        .with_level(true)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);
    let result = fut.await;
    drop(_guard);
    (result, cap_clone.captured())
}

// ─── Base YAML helpers ───────────────────────────────────────────────────────

const MINIMAL_VLESS: &str = r#"
proxies:
  - name: test-vless
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
"#;

// ─── D1: minimal required fields ─────────────────────────────────────────────

/// D1: `parse_vless_minimal_ok`
///
/// Minimal valid VLESS config (name, type, server, port, uuid) loads without error.
#[tokio::test]
async fn parse_vless_minimal_ok() {
    let config = load_config_from_str(MINIMAL_VLESS)
        .await
        .expect("minimal VLESS must load");
    assert!(
        config.proxies.contains_key("test-vless"),
        "proxy 'test-vless' must be registered"
    );
}

// ─── D2: all documented fields ────────────────────────────────────────────────

/// D2: `parse_vless_all_fields_roundtrip`
///
/// All documented fields parse without error.
#[tokio::test]
async fn parse_vless_all_fields_roundtrip() {
    let yaml = r#"
proxies:
  - name: full-vless
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: "xtls-rprx-vision"
    udp: true
    servername: cdn.example.com
    skip-cert-verify: false
    alpn:
      - h2
      - http/1.1
    network: ws
    ws-opts:
      path: /vless
      headers:
        Host: example.com
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("all-fields VLESS must load");
    assert!(config.proxies.contains_key("full-vless"));
}

// ─── D3: flow: "" → ok ────────────────────────────────────────────────────────

/// D3: `parse_vless_flow_empty_string_ok`
///
/// `flow: ""` is equivalent to no flow — must not hard-error.
#[tokio::test]
async fn parse_vless_flow_empty_string_ok() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: ""
"#;
    load_config_from_str(yaml)
        .await
        .expect("flow: empty string must parse OK");
}

// ─── D4: no flow key → ok ─────────────────────────────────────────────────────

/// D4: `parse_vless_flow_absent_ok`
///
/// Absent `flow:` key is identical to `flow: ""` — no error.
#[tokio::test]
async fn parse_vless_flow_absent_ok() {
    load_config_from_str(MINIMAL_VLESS)
        .await
        .expect("absent flow must parse OK");
}

// ─── D5: flow: xtls-rprx-vision + tls: true → ok ─────────────────────────────

/// D5: `parse_vless_flow_vision_ok`
///
/// `flow: "xtls-rprx-vision"` with `tls: true` parses successfully.
/// Acceptance criterion #5.
#[tokio::test]
async fn parse_vless_flow_vision_ok() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: "xtls-rprx-vision"
"#;
    load_config_from_str(yaml)
        .await
        .expect("flow: xtls-rprx-vision with tls: true must parse OK");
}

// ─── D6: unknown flow → hard error (proxy skipped) ───────────────────────────

/// D6: `parse_vless_flow_unknown_hard_errors`
///
/// Unknown flow string → proxy parse error; proxy is absent from config.
/// The config loader warns-and-skips (does not crash the full config load).
/// upstream: `adapter/outbound/vless.go` ignores unknown flows.
/// NOT accepted — Class A per ADR-0002: unknown flow may skip security processing.
#[tokio::test]
async fn parse_vless_flow_unknown_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: "xtls-rprx-unknown"
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with unknown flow must be skipped (not registered)"
    );
}

// ─── D7: flow: xtls-rprx-direct → proxy skipped ──────────────────────────────

/// D7: `parse_vless_flow_deprecated_direct_hard_errors`
///
/// `flow: "xtls-rprx-direct"` → proxy parse error; proxy absent from config.
/// upstream: `adapter/outbound/vless.go` accepts this as a deprecated alias.
/// NOT accepted — Class A per ADR-0002: security regression vs Vision.
#[tokio::test]
async fn parse_vless_flow_deprecated_direct_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: "xtls-rprx-direct"
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with xtls-rprx-direct flow must be skipped (deprecated — Class A)"
    );
}

// ─── D8: flow: xtls-rprx-splice → proxy skipped ──────────────────────────────

/// D8: `parse_vless_flow_deprecated_splice_hard_errors`
///
/// `flow: "xtls-rprx-splice"` → proxy parse error; proxy absent from config.
/// upstream: `adapter/outbound/vless.go` accepts as deprecated.
/// NOT accepted — Class A per ADR-0002.
#[tokio::test]
async fn parse_vless_flow_deprecated_splice_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: "xtls-rprx-splice"
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with xtls-rprx-splice flow must be skipped (deprecated — Class A)"
    );
}

// ─── D9: reality-opts parsing ────────────────────────────────────────────────

/// D9: `parse_vless_reality_opts_requires_fingerprint`
///
/// Reality is tied to a uTLS fingerprint upstream; require the field at config
/// time so the user cannot accidentally get plain TLS semantics.
#[tokio::test]
async fn parse_vless_reality_opts_requires_fingerprint() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    reality-opts:
      public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with reality-opts but no client-fingerprint must be skipped"
    );
}

#[tokio::test]
async fn parse_vless_reality_opts_requires_tls_true() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    client-fingerprint: chrome
    reality-opts:
      public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with reality-opts but tls=false must be skipped"
    );
}

#[tokio::test]
async fn parse_vless_reality_opts_invalid_public_key_skipped() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    client-fingerprint: chrome
    reality-opts:
      public-key: abc123
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with invalid REALITY public key must be skipped"
    );
}

#[tokio::test]
async fn parse_vless_reality_opts_invalid_short_id_skipped() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    client-fingerprint: chrome
    reality-opts:
      public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE
      short-id: 001122334455667788
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with >8-byte REALITY short-id must be skipped"
    );
}

/// REALITY must load on any build that has the `vless` feature — it no longer
/// needs `boring-tls`. Release targets where boring-sys cannot be compiled
/// (armv7/i686 musl, MIPS, windows-gnu, iOS) used to warn-and-skip every
/// REALITY proxy, which read as "vless just doesn't work" (issue #377).
#[tokio::test]
async fn parse_vless_reality_opts_valid_loads_without_boring_tls() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    client-fingerprint: chrome
    reality-opts:
      public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE
      short-id: 0011223344556677
      support-x25519mlkem768: false
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("valid REALITY VLESS config must load");
    assert!(
        config.proxies.contains_key("v"),
        "valid REALITY VLESS proxy must be registered"
    );
}

/// Subscription generators (e.g. Clash Verge) emit `short-id: null` when the
/// server has no short-id; mihomo treats it as absent and the node works.
/// Rejecting the explicit null silently dropped every such VLESS node (#388).
#[tokio::test]
async fn parse_vless_reality_opts_null_short_id_treated_as_absent() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    client-fingerprint: chrome
    reality-opts:
      public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE
      short-id: null
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("REALITY VLESS config with null short-id must load");
    assert!(
        config.proxies.contains_key("v"),
        "REALITY VLESS proxy with `short-id: null` must be registered, not dropped"
    );
}

/// An unquoted all-decimal `short-id` (e.g. `short-id: 1234`) parses as a
/// YAML integer, not a string. mihomo's weakly-typed decoder coerces it back
/// to its decimal digits before hex-decoding, so the identical subscription
/// works there; without matching coercion the node is silently dropped (#408).
/// The coercion also emits a warn telling the operator to quote the value
/// if they meant the literal digits (leading zeros are otherwise lost).
#[tokio::test]
async fn parse_vless_reality_opts_numeric_short_id_coerced_to_string() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    client-fingerprint: chrome
    reality-opts:
      public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE
      short-id: 1234
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    let config = result.expect("REALITY VLESS config with unquoted numeric short-id must load");
    assert!(
        config.proxies.contains_key("v"),
        "REALITY VLESS proxy with unquoted numeric short-id must be registered, not dropped"
    );
    let warn_count = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.contains("short-id") && l.contains("quote"))
        .count();
    assert!(
        warn_count >= 1,
        "a WARN about the coerced numeric short-id (with a quoting hint) must be emitted; \
         captured lines: {lines:?}"
    );
}

/// `short-id: 0x1f` parses as the YAML integer 31 (not the hex string "1f").
/// Pin the exact (lossy) coercion mihomo's decoder performs: the integer is
/// reformatted to its decimal string ("31") and hex-decoded from there, same
/// as a literal `short-id: "31"` would be — a real footgun for anyone who
/// wrote `0x1f` expecting it to be read as hex digits "1f". The coercion
/// must warn so operators who meant the literal digits know to quote the
/// value instead of leaving it as a bare YAML number.
#[tokio::test]
async fn parse_vless_reality_opts_hex_literal_short_id_decimal_coerced() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    client-fingerprint: chrome
    reality-opts:
      public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE
      short-id: 0x1f
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    let config = result.expect("REALITY VLESS config with `0x1f` short-id must load");
    assert!(
        config.proxies.contains_key("v"),
        "REALITY VLESS proxy with `short-id: 0x1f` must be registered, not dropped"
    );
    let warn_count = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.contains("short-id") && l.contains("quote"))
        .count();
    assert!(
        warn_count >= 1,
        "a WARN about the coerced `0x1f` short-id (with a quoting hint) must be emitted; \
         captured lines: {lines:?}"
    );
}

/// A leading-zero all-decimal `short-id` (e.g. `short-id: 0012`, unquoted)
/// is NOT reinterpreted as a YAML number by this parser: the core-schema
/// int resolver only matches decimal scalars without a leading zero (plain
/// `0` aside), so `0012` parses as the plain string `"0012"` and takes the
/// pre-existing `as_str()` branch untouched — the leading zero, and thus the
/// exact hex-decoded bytes (`0x00 0x12`), are preserved with no coercion and
/// no warning. This pins that (verified) behavior so a future serde_yaml/
/// resolver change that started collapsing such literals to numbers would
/// be caught here rather than silently reintroducing the byte-loss bug the
/// review finding described.
#[tokio::test]
async fn parse_vless_reality_opts_leading_zero_short_id_preserved_no_warn() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    client-fingerprint: chrome
    reality-opts:
      public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE
      short-id: 0012
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    let config = result.expect("REALITY VLESS config with leading-zero string short-id must load");
    assert!(
        config.proxies.contains_key("v"),
        "REALITY VLESS proxy with leading-zero short-id must be registered, not dropped"
    );
    let warn_count = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.contains("short-id"))
        .count();
    assert_eq!(
        warn_count, 0,
        "`short-id: 0012` parses as a string already (leading zero preserved), so no \
         numeric-coercion warning should fire; captured lines: {lines:?}"
    );
}

// ─── D10: tls: false + plain VLESS → warn once, loads ok ─────────────────────

/// D10: `parse_vless_tls_false_plain_warns_once`
///
/// `tls: false` with plain VLESS → struct loads OK, at least one warn with "tls"
/// or "plaintext".
/// Class B per ADR-0002: same destination, absent crypto.
/// upstream: `adapter/outbound/vless.go` silently passes through.
/// NOT hard-error — user gets a working connection, just unencrypted.
#[tokio::test]
async fn parse_vless_tls_false_plain_warns_once() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: false
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    result.expect("tls: false must not be a hard error");
    let warn_count = lines
        .iter()
        .filter(|l| {
            l.contains("WARN")
                && (l.to_lowercase().contains("tls") || l.to_lowercase().contains("plaintext"))
        })
        .count();
    assert!(
        warn_count >= 1,
        "at least one WARN about plaintext must be emitted; captured lines: {lines:?}"
    );
}

// ─── D11: tls: false warn fires per load, not globally ───────────────────────

/// D11: `parse_vless_tls_false_no_duplicate_warn`
///
/// Load the same YAML twice; assert warn fires once per `load_config_from_str` call,
/// not suppressed after the first process-lifetime occurrence.
/// Guards against accidental `std::sync::Once` suppression.
/// Class B per ADR-0002.
#[tokio::test]
async fn parse_vless_tls_false_no_duplicate_warn() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: false
"#;

    // First load
    let (r1, lines1) = with_warn_capture_async(load_config_from_str(yaml)).await;
    r1.expect("first load ok");
    let c1 = lines1
        .iter()
        .filter(|l| {
            l.contains("WARN")
                && (l.to_lowercase().contains("tls") || l.to_lowercase().contains("plaintext"))
        })
        .count();

    // Second load
    let (r2, lines2) = with_warn_capture_async(load_config_from_str(yaml)).await;
    r2.expect("second load ok");
    let c2 = lines2
        .iter()
        .filter(|l| {
            l.contains("WARN")
                && (l.to_lowercase().contains("tls") || l.to_lowercase().contains("plaintext"))
        })
        .count();

    assert!(
        c1 >= 1,
        "warn must fire on first load; first-load lines: {lines1:?}"
    );
    assert!(
        c2 >= 1,
        "warn must fire on second load too (not suppressed globally); second-load lines: {lines2:?}"
    );
}

// ─── D12: vision + no TLS → proxy skipped ────────────────────────────────────

/// D12: `parse_vless_vision_without_tls_hard_errors`
///
/// `flow: "xtls-rprx-vision"` with `tls: false` and no TLS-enforcing transport →
/// proxy parse error; proxy absent from config.
/// Class A per ADR-0002: Vision without outer TLS is a no-op the user did not intend.
#[tokio::test]
async fn parse_vless_vision_without_tls_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: false
    flow: "xtls-rprx-vision"
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with vision + no TLS must be skipped (Vision without TLS is a no-op — Class A)"
    );
}

// ─── D13: vision + grpc (TLS-enforcing) → ok ─────────────────────────────────

/// D13: `parse_vless_vision_with_grpc_transport_ok`
///
/// `flow: "xtls-rprx-vision"` + `tls: false` + `network: grpc` → parses OK.
/// gRPC implies TLS at the transport level; the Vision-requires-TLS gate must
/// accept grpc as a TLS-enforcing network.
/// Acceptance criterion #9: "or a transport that enforces TLS, such as `network: grpc`".
#[tokio::test]
async fn parse_vless_vision_with_grpc_transport_ok() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: false
    network: grpc
    flow: "xtls-rprx-vision"
"#;
    load_config_from_str(yaml)
        .await
        .expect("vision + grpc (TLS-enforcing) must parse OK without tls: true");
}

// ─── D14: encryption: non-none → proxy skipped ───────────────────────────────

/// D14: `parse_vless_encryption_non_none_hard_errors`
///
/// `encryption: "aes-128-gcm"` → proxy parse error; proxy absent from config.
/// upstream: also errors on non-"none" values — this is a match, not a divergence.
#[tokio::test]
async fn parse_vless_encryption_non_none_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    encryption: "aes-128-gcm"
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with non-none encryption must be skipped"
    );
}

// ─── D15: encryption: "" → ok ────────────────────────────────────────────────

/// D15: `parse_vless_encryption_empty_string_accepted`
///
/// `encryption: ""` is equivalent to `"none"` per spec — must parse OK.
#[tokio::test]
async fn parse_vless_encryption_empty_string_accepted() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    encryption: ""
"#;
    load_config_from_str(yaml)
        .await
        .expect("encryption: empty string must be accepted");
}

/// D15b: `parse_vless_encryption_issue_301`
///
/// The post-quantum `encryption: mlkem768x25519plus…` line from the issue #301
/// 3x-ui config — using the reporter's exact key, whose base64 has non-canonical
/// trailing bits (Go decodes it; strict decoders would not). The proxy builds
/// with the `vless-encryption` feature and is skipped (with a feature-pointing
/// error) without it.
///
/// (REALITY is exercised separately — `reality-opts` additionally needs the
/// `boring-tls` feature, which the shipping app build enables.)
#[tokio::test]
async fn parse_vless_encryption_issue_301() {
    let yaml = r#"
proxies:
  - name: vpn26
    type: vless
    server: vpn26.abc.com
    port: 443
    uuid: 55f4ad8f-7ab1-4786-9130-d107e0b9dcdb
    udp: true
    tls: true
    servername: aws.amazon.com
    network: tcp
    encryption: mlkem768x25519plus.native.0rtt.DA7B2WRj7X2zGFwMelbIbcaoUrpLjzoPpmydYW8NvQW
    client-fingerprint: chrome
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip if feature absent)");

    #[cfg(feature = "vless-encryption")]
    assert!(
        config.proxies.contains_key("vpn26"),
        "issue #301 encryption config must build a proxy with the vless-encryption feature"
    );
    #[cfg(not(feature = "vless-encryption"))]
    assert!(
        !config.proxies.contains_key("vpn26"),
        "mlkem768x25519plus encryption must be skipped without the vless-encryption feature"
    );
}

// ─── D16: mux enabled → sing-mux attached ────────────────────────────────────

/// D16: `parse_vless_mux_enabled_loads_with_sing_mux`
///
/// `smux: { enabled: true }` → parse succeeds and the adapter is wired for
/// sing-mux multiplexing (default protocol h2mux, matching mihomo).  No mux
/// warn is emitted — the feature is implemented.
/// Interop note: server must be sing-box / mihomo based (Xray-only servers
/// speak Mux.Cool, not this protocol).
#[cfg(feature = "mux")]
#[tokio::test]
async fn parse_vless_mux_enabled_loads_with_sing_mux() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    smux:
      enabled: true
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    result.expect("mux enabled must not be a hard error");
    let mux_warns = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.to_lowercase().contains("mux"))
        .count();
    assert_eq!(
        mux_warns, 0,
        "mux is implemented: no mux warn expected; captured lines: {lines:?}"
    );
}

/// D16b: explicit `protocol: h2mux` → accepted without warn.
#[cfg(feature = "mux")]
#[tokio::test]
async fn parse_vless_mux_h2mux_accepted() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    mux:
      enabled: true
      protocol: h2mux
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    result.expect("h2mux mux must load");
    let mux_warns = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.to_lowercase().contains("mux"))
        .count();
    assert_eq!(
        mux_warns, 0,
        "h2mux is implemented: no warn expected; captured lines: {lines:?}"
    );
}

/// D16e: unknown mux protocol → proxy rejected with a loud warn (meow's
/// warn+skip parse semantics; mihomo hard-errors on the same input).
#[cfg(feature = "mux")]
#[tokio::test]
async fn parse_vless_mux_unknown_protocol_rejects_proxy() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    mux:
      enabled: true
      protocol: not-a-protocol
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    let config = result.expect("unknown mux protocol must not fail the whole config");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with unknown mux protocol must be skipped"
    );
    let warns = lines
        .iter()
        .filter(|l| l.contains("unknown mux protocol"))
        .count();
    assert!(
        warns >= 1,
        "expected an unknown-mux-protocol warn; {lines:?}"
    );
}

/// D16f: `protocol: muxcool` on VLESS → accepted (Xray Mux.Cool).
#[cfg(feature = "mux")]
#[tokio::test]
async fn parse_vless_mux_muxcool_accepted() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    mux:
      enabled: true
      protocol: muxcool
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    let config = result.expect("muxcool mux must load");
    assert!(
        config.proxies.contains_key("v"),
        "muxcool proxy must be kept"
    );
    let mux_warns = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.to_lowercase().contains("mux"))
        .count();
    assert_eq!(mux_warns, 0, "muxcool is implemented: no warn expected");
}

/// D16f2 (issue #424): `flow: xtls-rprx-vision` + `protocol: muxcool` on
/// VLESS → accepted. Xray's own Mux.Cool signaling rides inside the VLESS
/// request that Vision splices, and this combination is live-tested against
/// a real Xray node (docs/specs/proxy-mux.md "Test Plan" items 2-3); only
/// the sing-mux protocols (smux/yamux/h2mux) are incompatible with Vision.
#[cfg(all(feature = "mux", feature = "vless-vision"))]
#[tokio::test]
async fn parse_vless_vision_muxcool_accepted() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: "xtls-rprx-vision"
    mux:
      enabled: true
      protocol: muxcool
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    let config = result.expect("vision + muxcool must load (issue #424)");
    assert!(
        config.proxies.contains_key("v"),
        "vision + muxcool proxy must be kept"
    );
    let mux_warns = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.to_lowercase().contains("mux"))
        .count();
    assert_eq!(
        mux_warns, 0,
        "vision + muxcool is implemented: no warn expected; captured lines: {lines:?}"
    );
}

/// D16f3 (issue #424): `flow: xtls-rprx-vision` + a sing-mux protocol
/// (default h2mux) on VLESS → hard error. sing-box and Xray both reject
/// XTLS + sing-mux; this remains gated even though `protocol: muxcool` is
/// now accepted above.
#[cfg(all(feature = "mux", feature = "vless-vision"))]
#[tokio::test]
async fn parse_vless_vision_singmux_rejected() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: "xtls-rprx-vision"
    mux:
      enabled: true
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    let config = result.expect("invalid proxy must not fail the whole config");
    assert!(
        !config.proxies.contains_key("v"),
        "vision + sing-mux (h2mux default) node must be skipped"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("incompatible with sing-mux")),
        "expected a sing-mux incompatibility warn; {lines:?}"
    );
}

/// D16g: `protocol: muxcool` on Trojan → rejected (VLESS/VMess-only protocol;
/// trojan's CommandMux is smux, not Mux.Cool frames).
#[cfg(all(feature = "mux", feature = "trojan"))]
#[tokio::test]
async fn parse_trojan_mux_muxcool_rejected() {
    let yaml = r#"
proxies:
  - name: t
    type: trojan
    server: example.com
    port: 443
    password: pw
    mux:
      enabled: true
      protocol: muxcool
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    let config = result.expect("invalid proxy must not fail the whole config");
    assert!(
        !config.proxies.contains_key("t"),
        "trojan node with muxcool must be skipped"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("muxcool") && l.contains("VLESS")),
        "expected a VLESS/VMess-only warn; {lines:?}"
    );
}

/// D16h: sing-mux on Shadowsocks → accepted (default h2mux).
#[cfg(all(feature = "mux", feature = "ss"))]
#[tokio::test]
async fn parse_ss_mux_singmux_accepted() {
    let yaml = r#"
proxies:
  - name: s
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: pw
    mux:
      enabled: true
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    let config = result.expect("ss mux must load");
    assert!(config.proxies.contains_key("s"), "ss proxy must be kept");
    let mux_warns = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.to_lowercase().contains("mux"))
        .count();
    assert_eq!(mux_warns, 0, "ss sing-mux is implemented: no warn expected");
}

/// D16h2: the canonical mihomo `smux:` key on Shadowsocks → accepted
/// (same block as the legacy `mux:` alias, which stays covered above).
#[cfg(all(feature = "mux", feature = "ss"))]
#[tokio::test]
async fn parse_ss_smux_key_accepted() {
    let yaml = r#"
proxies:
  - name: s
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: pw
    smux:
      enabled: true
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    let config = result.expect("ss smux: must load");
    assert!(config.proxies.contains_key("s"), "ss proxy must be kept");
    let mux_warns = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.to_lowercase().contains("mux"))
        .count();
    assert_eq!(mux_warns, 0, "smux: key is canonical: no warn expected");
}

/// D16i: `protocol: muxcool` on Shadowsocks → rejected (VLESS/VMess-only).
#[cfg(all(feature = "mux", feature = "ss"))]
#[tokio::test]
async fn parse_ss_mux_muxcool_rejected() {
    let yaml = r#"
proxies:
  - name: s
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: pw
    mux:
      enabled: true
      protocol: muxcool
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    let config = result.expect("invalid proxy must not fail the whole config");
    assert!(
        !config.proxies.contains_key("s"),
        "ss node with muxcool must be skipped"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("muxcool") && l.contains("VLESS")),
        "expected a VLESS/VMess-only warn; {lines:?}"
    );
}

/// D16j / D16j2 / D16k: VMess mux blocks that must load with no mux warn.
///
/// * D16j  — sing-mux via the legacy `mux:` alias (default protocol h2mux).
/// * D16j2 — the canonical mihomo `smux:` key (same block as the legacy alias).
/// * D16k  — `protocol: muxcool`: CommandMux 0x03 is the VMess request
///   header's native mux signaling; sing-vmess routes it to
///   `HandleMuxConnection`.
///
/// Every case runs even if an earlier one fails; failures are reported
/// together with their label.
#[cfg(all(feature = "mux", feature = "vmess"))]
#[tokio::test]
async fn parse_vmess_mux_protocol_table() {
    const CASES: &[(&str, &str)] = &[
        (
            "D16j: sing-mux via the legacy `mux:` alias (default h2mux)",
            "    mux:\n      enabled: true\n",
        ),
        (
            "D16j2: the canonical mihomo `smux:` key",
            "    smux:\n      enabled: true\n",
        ),
        (
            "D16k: `protocol: muxcool` (VMess CommandMux 0x03)",
            "    mux:\n      enabled: true\n      protocol: muxcool\n",
        ),
    ];

    let mut failures: Vec<String> = Vec::new();
    for (label, mux_block) in CASES {
        let yaml = format!(
            "proxies:\n  - name: m\n    type: vmess\n    server: example.com\n    \
             port: 443\n    uuid: b831381d-6324-4d53-ad4f-8cda48b30811\n    \
             cipher: auto\n{mux_block}"
        );
        let (result, lines) = with_warn_capture_async(load_config_from_str(&yaml)).await;
        match result {
            Err(e) => failures.push(format!("{label}: config must load, got error: {e}")),
            Ok(config) => {
                if !config.proxies.contains_key("m") {
                    failures.push(format!("{label}: vmess proxy must be kept; {lines:?}"));
                }
                let mux_warns = lines
                    .iter()
                    .filter(|l| l.contains("WARN") && l.to_lowercase().contains("mux"))
                    .count();
                if mux_warns != 0 {
                    failures.push(format!(
                        "{label}: implemented, no mux warn expected, got {mux_warns}; {lines:?}"
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "vmess mux cases failed:\n{}",
        failures.join("\n")
    );
}

/// No-mux builds: an enabled `mux:` block must warn loudly instead of
/// being silently ignored.
#[cfg(not(feature = "mux"))]
#[tokio::test]
async fn parse_vless_mux_enabled_without_feature_warns() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    mux:
      enabled: true
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    result.expect("mux config must still load without the feature");
    let warns = lines
        .iter()
        .filter(|l| l.contains("compiled without the `mux` feature"))
        .count();
    assert!(warns >= 1, "expected a no-mux warn; {lines:?}");
}

/// D16f: `only-tcp: true` → accepted (UDP stays on the plain proxy path).
#[cfg(feature = "mux")]
#[tokio::test]
async fn parse_vless_mux_only_tcp_accepted() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    mux:
      enabled: true
      only-tcp: true
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    result.expect("only-tcp mux must load");
    let mux_warns = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.to_lowercase().contains("mux"))
        .count();
    assert_eq!(mux_warns, 0, "no warn expected; captured lines: {lines:?}");
}

/// D16g: `statistic` / `brutal-opts` → accepted with a warn each
/// (upstream fields meow-rs does not implement).
#[cfg(feature = "mux")]
#[tokio::test]
async fn parse_vless_mux_unsupported_fields_warn_and_ignore() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    mux:
      enabled: true
      statistic: true
      brutal-opts:
        enabled: true
        up: 100
        down: 100
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    result.expect("unsupported mux fields must not be a hard error");
    // The config may be parsed more than once during load; assert each
    // unsupported field warned at least once.
    let statistic = lines
        .iter()
        .filter(|l| l.contains("mux option 'statistic'"))
        .count();
    let brutal = lines
        .iter()
        .filter(|l| l.contains("mux option 'brutal-opts'"))
        .count();
    assert!(
        statistic >= 1 && brutal >= 1,
        "expected one warn per unsupported field; {lines:?}"
    );
}

/// D16c: explicit `protocol: yamux` → accepted without warn.
#[cfg(feature = "mux")]
#[tokio::test]
async fn parse_vless_mux_yamux_accepted() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    mux:
      enabled: true
      protocol: yamux
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    result.expect("yamux mux must load");
    let mux_warns = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.to_lowercase().contains("mux"))
        .count();
    assert_eq!(
        mux_warns, 0,
        "yamux is implemented: no warn expected; captured lines: {lines:?}"
    );
}

/// D16d: `mux: { enabled: false }` → plain VLESS, no mux, no warn.
#[cfg(feature = "mux")]
#[tokio::test]
async fn parse_vless_mux_disabled_loads_plain() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    mux:
      enabled: false
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    result.expect("mux disabled must load");
    let mux_warns = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.to_lowercase().contains("mux"))
        .count();
    assert_eq!(
        mux_warns, 0,
        "no mux warn expected; captured lines: {lines:?}"
    );
}

// ─── D17: vision + udp: true → warn + loads ──────────────────────────────────

/// D17: `parse_vless_vision_udp_true_warns_once`
///
/// `flow: "xtls-rprx-vision"` + `udp: true` + `tls: true` → parse succeeds;
/// at least one warn mentioning both "UDP" and "Vision" (or lowercase equivalents).
/// Class B per ADR-0002 row #7: Vision is TCP-only; UDP uses plain VLESS.
/// NOT hard-error: crypto and routing are unchanged on the UDP path.
/// upstream: upstream UDP also silently uses plain VLESS; we warn once at load.
#[tokio::test]
async fn parse_vless_vision_udp_true_warns_once() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: "xtls-rprx-vision"
    udp: true
"#;
    let (result, lines) = with_warn_capture_async(load_config_from_str(yaml)).await;
    result.expect("vision + udp must not be a hard error");
    let warn_count = lines
        .iter()
        .filter(|l| {
            l.contains("WARN")
                && (l.to_lowercase().contains("udp") || l.to_lowercase().contains("vision"))
        })
        .count();
    assert!(
        warn_count >= 1,
        "at least one WARN about UDP/Vision must be emitted; captured lines: {lines:?}"
    );
}

// ─── D18: UUID dashed and hex-only both accepted ──────────────────────────────

/// D18: `parse_vless_uuid_hex_and_dashed_both_accepted`
///
/// UUID in dashed form and hex-only form both parse without error.
/// guard-rail: accidental rejection of one form would break many real configs.
#[tokio::test]
async fn parse_vless_uuid_hex_and_dashed_both_accepted() {
    // Dashed form (standard)
    let yaml_dashed = r#"
proxies:
  - name: dashed
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
"#;
    // Hex-only form (no dashes)
    let yaml_hex = r#"
proxies:
  - name: hex
    type: vless
    server: example.com
    port: 443
    uuid: b831381d63244d53ad4f8cda48b30811
"#;
    load_config_from_str(yaml_dashed)
        .await
        .expect("dashed UUID must be accepted");
    load_config_from_str(yaml_hex)
        .await
        .expect("hex-only UUID must be accepted");
}

// ─── D19: invalid UUID → proxy skipped ───────────────────────────────────────

/// D19: `parse_vless_uuid_invalid_hard_errors`
///
/// `uuid: "not-a-uuid"` → proxy parse error; proxy absent from config.
/// guard-rail: an invalid UUID would produce a zeroed or garbage auth ID with no diagnostic.
#[tokio::test]
async fn parse_vless_uuid_invalid_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: "not-a-uuid"
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with invalid uuid must be skipped"
    );
}

// ─── D20: server > 255 bytes → proxy skipped ─────────────────────────────────

/// D20: `parse_vless_server_domain_over_255_errors`
///
/// `server:` is a 256-char hostname → proxy parse error; proxy absent from config.
/// Class A per ADR-0002: wrong destination, no diagnostic on silent truncate.
/// upstream: `transport/vless/encoding.go` does not enforce this limit.
/// NOT silent truncation — 256-byte domain in ATYP 0x02 wraps to 0 bytes, wrong destination.
#[tokio::test]
async fn parse_vless_server_domain_over_255_errors() {
    let long_server = "a".repeat(256);
    let yaml = format!(
        r#"
proxies:
  - name: v
    type: vless
    server: "{long_server}"
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
"#
    );
    let config = load_config_from_str(&yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with server > 255 bytes must be skipped (Class A)"
    );
}

// ─── XHTTP (SplitHTTP) transport config tests ────────────────────────────────

#[tokio::test]
async fn parse_vless_xhttp_minimal_ok() {
    let yaml = r#"
proxies:
  - name: vless-xhttp
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: xhttp
"#;
    let config = load_config_from_str(yaml).await.expect("config must parse");
    assert!(config.proxies.contains_key("vless-xhttp"));
}

#[tokio::test]
async fn parse_vless_xhttp_full_opts_ok() {
    let yaml = r#"
proxies:
  - name: vless-xhttp-full
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: xhttp
    xhttp-opts:
      path: /testpath
      host: xhttp.example.com
      mode: stream-one
      no-grpc-header: true
      x-padding-bytes: 200-800
      headers:
        X-Custom: Hello
"#;
    let config = load_config_from_str(yaml).await.expect("config must parse");
    assert!(config.proxies.contains_key("vless-xhttp-full"));
}

#[tokio::test]
async fn parse_vless_xhttp_unsupported_mode_skipped() {
    let yaml = r#"
proxies:
  - name: vless-xhttp-bad-mode
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: xhttp
    xhttp-opts:
      mode: packet-up
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("vless-xhttp-bad-mode"),
        "proxy with unsupported xhttp mode must be skipped"
    );
}

#[tokio::test]
async fn parse_vless_xhttp_invalid_padding_range_skipped() {
    let yaml = r#"
proxies:
  - name: vless-xhttp-bad-pad
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: xhttp
    xhttp-opts:
      x-padding-bytes: 900-100
"#;
    let config = load_config_from_str(yaml)
        .await
        .expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("vless-xhttp-bad-pad"),
        "proxy with inverted padding range must be skipped"
    );
}
