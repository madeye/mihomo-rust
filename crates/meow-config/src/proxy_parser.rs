use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
#[cfg(feature = "ss")]
use meow_proxy::ShadowsocksAdapter;
#[cfg(feature = "trojan")]
use meow_proxy::TrojanAdapter;
use meow_proxy::{
    DirectAdapter, FallbackGroup, HttpAdapter, LbStrategy, LoadBalanceGroup, RelayGroup,
    SelectorGroup, Socks5Adapter, UrlTestGroup,
};
#[cfg(feature = "vless")]
use meow_proxy::{TransportChain, VlessAdapter, VlessFlow};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::sync::Arc;

fn required_port(
    config: &HashMap<String, serde_yaml::Value>,
    context: &str,
) -> std::result::Result<u16, String> {
    let raw = config
        .get("port")
        .and_then(serde_yaml::Value::as_u64)
        .ok_or_else(|| format!("{context}: missing port"))?;
    let port = u16::try_from(raw).map_err(|_| format!("{context}: port {raw} exceeds 65535"))?;
    if port == 0 {
        return Err(format!("{context}: port must be non-zero"));
    }
    Ok(port)
}

/// Wraps a ProxyAdapter to implement the full Proxy trait
pub struct WrappedProxy {
    adapter: Box<dyn ProxyAdapter>,
}

impl WrappedProxy {
    pub fn new(adapter: Box<dyn ProxyAdapter>) -> Self {
        Self { adapter }
    }
}

#[async_trait]
impl ProxyAdapter for WrappedProxy {
    fn name(&self) -> &str {
        self.adapter.name()
    }
    fn adapter_type(&self) -> AdapterType {
        self.adapter.adapter_type()
    }
    fn addr(&self) -> &str {
        self.adapter.addr()
    }
    fn support_udp(&self) -> bool {
        self.adapter.support_udp()
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.adapter.dial_tcp(metadata).await
    }
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.adapter.dial_udp(metadata).await
    }
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        self.adapter.connect_over(stream, metadata).await
    }

    fn health(&self) -> &ProxyHealth {
        self.adapter.health()
    }
}

impl Proxy for WrappedProxy {
    fn alive(&self) -> bool {
        self.adapter.health().alive()
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        self.adapter.health().alive()
    }
    fn last_delay(&self) -> u16 {
        self.adapter.health().last_delay()
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        self.adapter.health().last_delay()
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        self.adapter.health().delay_history()
    }
}

pub fn parse_proxy(
    config: &HashMap<String, serde_yaml::Value>,
    ipv6: bool,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let dialer: std::sync::Arc<dyn meow_proxy::dialer::TcpDialer> =
        std::sync::Arc::new(meow_proxy::dialer::DirectDialer);
    parse_proxy_with_dialer(config, &dialer, ipv6)
}

/// Like [parse_proxy] but injects a custom [meow_proxy::dialer::TcpDialer]
/// into every adapter. Used by apply_dialer_proxies to inject a
/// [meow_proxy::dialer::ProxyDialer] so that dialer-proxy chaining works
/// for all protocols without requiring connect_over.
pub fn parse_proxy_with_dialer(
    config: &HashMap<String, serde_yaml::Value>,
    dialer: &std::sync::Arc<dyn meow_proxy::dialer::TcpDialer>,
    ipv6: bool,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let name = config
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("missing proxy name")?;
    let proxy_type = config
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or("missing proxy type")?;

    match proxy_type {
        #[cfg(feature = "ss")]
        "ss" => {
            let server = config
                .get("server")
                .and_then(|v| v.as_str())
                .ok_or("missing server")?;
            let port = required_port(config, "ss")?;
            let password = config
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or("missing password")?;
            let cipher = config
                .get("cipher")
                .and_then(|v| v.as_str())
                .ok_or("missing cipher")?;
            let udp = config
                .get("udp")
                .and_then(serde_yaml::Value::as_bool)
                .unwrap_or(false);
            let plugin = config.get("plugin").and_then(|v| v.as_str());
            let plugin_opts_str = config.get("plugin-opts").and_then(serialize_plugin_opts);

            // A SIP003 *external* plugin is a local subprocess spawned by
            // `ShadowsocksAdapter::new`, and the adapter deliberately dials it
            // over loopback without the pluggable dialer.  Bail out *before*
            // constructing so the re-parse in `apply_dialer_proxies` does not
            // spawn a second copy of the plugin process (the first one stays
            // alive as long as any group still holds the original Arc), and so
            // the user learns their `dialer-proxy` has no effect here.
            if dialer.is_proxy() && is_external_sip003_plugin(plugin) {
                return Err(format!(
                    "ss[{name}]: `dialer-proxy` is not supported with the external \
                     SIP003 plugin '{}' — the plugin runs as a local subprocess and \
                     is always reached over loopback",
                    plugin.unwrap_or_default()
                ));
            }

            #[cfg_attr(not(feature = "mux"), allow(unused_mut))]
            let mut adapter = ShadowsocksAdapter::new(
                name,
                server,
                port,
                password,
                cipher,
                udp,
                plugin,
                plugin_opts_str.as_deref(),
                Arc::clone(dialer),
            )
            .map_err(|e| format!("ss: {e}"))?;
            #[cfg(feature = "mux")]
            if let Some(mux_options) = parse_mux_options(name, config)? {
                // muxcool rides VLESS CommandMux; shadowsocks has no
                // equivalent signaling — reject loudly instead of speaking
                // garbage frames to the server.
                if mux_options.protocol == meow_proxy::mux::Protocol::MuxCool {
                    return Err(format!(
                        "{name}: mux protocol 'muxcool' is VLESS/VMess-only; \
                         use smux/yamux/h2mux for shadowsocks nodes"
                    ));
                }
                adapter = adapter.with_mux(mux_options);
            }
            #[cfg(not(feature = "mux"))]
            parse_mux_options(name, config)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        #[cfg(feature = "trojan")]
        "trojan" => {
            let server = config
                .get("server")
                .and_then(|v| v.as_str())
                .ok_or("missing server")?;
            let port = required_port(config, "trojan")?;
            let password = config
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or("missing password")?;
            let sni = config.get("sni").and_then(|v| v.as_str()).unwrap_or("");
            let skip_verify = config
                .get("skip-cert-verify")
                .and_then(serde_yaml::Value::as_bool)
                .unwrap_or(false);
            let udp = config
                .get("udp")
                .and_then(serde_yaml::Value::as_bool)
                .unwrap_or(false);

            #[cfg_attr(not(feature = "mux"), allow(unused_mut))]
            let mut adapter = TrojanAdapter::new(
                name,
                server,
                port,
                password,
                sni,
                skip_verify,
                udp,
                Arc::clone(dialer),
            );
            #[cfg(feature = "mux")]
            if let Some(mux_options) = parse_mux_options(name, config)? {
                // muxcool rides VLESS CommandMux; trojan has no equivalent
                // signaling (its CommandMux=0x7f is smux) — reject loudly
                // instead of speaking garbage frames to the server.
                if mux_options.protocol == meow_proxy::mux::Protocol::MuxCool {
                    return Err(format!(
                        "{name}: mux protocol 'muxcool' is VLESS/VMess-only; \
                         use smux/yamux/h2mux for trojan nodes"
                    ));
                }
                adapter = adapter.with_mux(mux_options);
            }
            #[cfg(not(feature = "mux"))]
            parse_mux_options(name, config)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        #[cfg(feature = "vless")]
        "vless" => {
            let adapter = parse_vless(name, config, dialer)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        "http" => {
            let adapter = parse_http(name, config, dialer)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        "socks5" => {
            let adapter = parse_socks5(name, config, dialer)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        "direct" => {
            reject_unthreaded_dialer(name, "direct", dialer)?;
            let adapter = parse_direct(name, config, ipv6)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        #[cfg(feature = "anytls")]
        "anytls" => {
            reject_unthreaded_dialer(name, "anytls", dialer)?;
            let adapter = parse_anytls(name, config)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        #[cfg(feature = "hysteria2")]
        "hysteria2" => {
            reject_unthreaded_dialer(name, "hysteria2", dialer)?;
            let adapter = parse_hysteria2(name, config)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        #[cfg(feature = "vmess")]
        "vmess" => {
            let adapter = parse_vmess(name, config, dialer)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        #[cfg(feature = "snell")]
        "snell" => {
            let adapter = parse_snell(name, config, dialer)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        #[cfg(not(feature = "ss"))]
        "ss" => Err(feature_gated_proxy_type("ss")),
        #[cfg(not(feature = "trojan"))]
        "trojan" => Err(feature_gated_proxy_type("trojan")),
        #[cfg(not(feature = "vless"))]
        "vless" => Err(feature_gated_proxy_type("vless")),
        #[cfg(not(feature = "anytls"))]
        "anytls" => Err(feature_gated_proxy_type("anytls")),
        #[cfg(not(feature = "hysteria2"))]
        "hysteria2" => Err(feature_gated_proxy_type("hysteria2")),
        #[cfg(not(feature = "vmess"))]
        "vmess" => Err(feature_gated_proxy_type("vmess")),
        #[cfg(not(feature = "snell"))]
        "snell" => Err(feature_gated_proxy_type("snell")),
        _ => Err(format!("unsupported proxy type: {proxy_type}")),
    }
}

/// Whether `plugin` names a SIP003 plugin that runs as an external subprocess
/// (as opposed to one of the built-in, in-process plugin implementations).
///
/// Mirrors the dispatch in `ShadowsocksAdapter::new`: anything not recognised
/// as built-in is handed to `Plugin::start`, which spawns a child process.
#[cfg(feature = "ss")]
fn is_external_sip003_plugin(plugin: Option<&str>) -> bool {
    let Some(plugin) = plugin.filter(|p| !p.is_empty()) else {
        return false;
    };
    if meow_proxy::shadowsocks_adapter::is_builtin_obfs_plugin(plugin) {
        return false;
    }
    if plugin == "v2ray-plugin" {
        return false;
    }
    // Mirror `ShadowsocksAdapter::new` exactly: its `ech-tls-tunnel` arm is
    // feature-gated, so without the feature the plugin falls through to the
    // external-subprocess branch and must be classified external here too —
    // otherwise an injected dialer would be accepted and silently ignored.
    #[cfg(feature = "ech-tls-tunnel")]
    if plugin == "ech-tls-tunnel" {
        return false;
    }
    true
}

/// Reject a `ProxyDialer` for adapter types that do not thread it through.
///
/// `anytls` dials via `meow_common::connect_tcp_host` internally and
/// `hysteria2` owns its QUIC socket; `direct` is a raw egress by definition.
/// None of them can honour an injected dialer, so accepting one here would
/// silently drop the user's `dialer-proxy` and egress from the real source
/// path — a Class A silent divergence (ADR-0002).  Returning `Err` instead
/// lets `apply_dialer_proxies` fall back to the relay-based
/// `DialerProxyAdapter` wrapper, which fails loudly at dial time rather
/// than pretending the chain was applied or dialing direct.
///
/// A `DirectDialer` is always accepted: it is the no-op default, so nothing
/// is lost by ignoring it.
fn reject_unthreaded_dialer(
    name: &str,
    proxy_type: &str,
    dialer: &std::sync::Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<(), String> {
    if dialer.is_proxy() {
        return Err(format!(
            "{proxy_type}[{name}]: `dialer-proxy` is not supported for this \
             proxy type (its underlying connection is not established through \
             the pluggable TCP dialer)"
        ));
    }
    Ok(())
}

/// Error for a proxy type this codebase implements but which was compiled out
/// of the running binary. The generic "unsupported proxy type" message made
/// users think the protocol was missing entirely, when the actual fix is to
/// use a full-featured build (issue #390).
#[cfg(not(all(
    feature = "ss",
    feature = "trojan",
    feature = "vless",
    feature = "anytls",
    feature = "hysteria2",
    feature = "vmess",
    feature = "snell"
)))]
fn feature_gated_proxy_type(proxy_type: &str) -> String {
    format!(
        "proxy type '{proxy_type}' is not compiled into this build; \
         use an official release binary or rebuild with `--features full` \
         (or `--features {proxy_type}`)"
    )
}

/// Parse a `type: snell` proxy block.
///
/// Mihomo-compatible Snell outbound. v3 uses the legacy Snell AEAD stream;
/// v4/v5 use the newer Snell v4 TCP wire (v5 is client-side compatible).
///
/// YAML schema (mihomo-compatible):
///
/// ```yaml
/// - name: my-snell
///   type: snell
///   server: 1.2.3.4
///   port: 443
///   psk: shared-secret
///   version: 4         # optional; default 4. Accepts 3, 4, 5, "v3", "v4", "v5".
///   udp: true          # optional; UDP-over-TCP relay.
///   reuse: true        # optional; CommandConnectV2 + connection pool.
///   obfs-opts:         # optional
///     mode: http       # off (default) | http | tls
///     host: bing.com   # falls back to server when missing
/// ```
///
/// # Hard errors (Class A per ADR-0002)
///
/// - missing `server`, `port`, or `psk` — required by the protocol.
/// - `port == 0` — never a valid endpoint.
/// - empty `psk` — caught by [`meow_proxy::SnellAdapter::new`].
/// - `version` ∈ {1, 2} — this adapter does not implement those wires.
/// - `obfs-opts.mode` is not one of off / http / tls.
#[cfg(feature = "snell")]
fn parse_snell(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<meow_proxy::SnellAdapter, String> {
    use meow_proxy::{SnellAdapter, SnellObfs, SnellVersion};

    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("snell[{name}]: missing server"))?;
    let port = required_port(config, &format!("snell[{name}]"))?;
    let psk = config
        .get("psk")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("snell[{name}]: missing psk"))?;

    let udp = config
        .get("udp")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let reuse = config
        .get("reuse")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);

    // ── Version parsing ──────────────────────────────────────────────────
    let version = match config.get("version") {
        None => SnellVersion::V4,
        Some(v) => {
            // Accept ints (1..=5) or strings ("v4", "5", ...).
            let label = if let Some(n) = v.as_u64() {
                n.to_string()
            } else if let Some(s) = v.as_str() {
                s.to_string()
            } else {
                return Err(format!(
                    "snell[{name}]: version must be an integer or string (3, 4 or 5)"
                ));
            };
            match label.trim().to_ascii_lowercase().as_str() {
                "3" | "v3" => SnellVersion::V3,
                "" | "4" | "v4" => SnellVersion::V4,
                "5" | "v5" => SnellVersion::V5,
                "1" | "2" | "v1" | "v2" => {
                    return Err(format!(
                        "snell[{name}]: version '{label}' is not supported; \
                         this adapter implements Snell v3 / v4 / v5 only"
                    ));
                }
                other => {
                    return Err(format!(
                        "snell[{name}]: unknown version '{other}'; valid: 3, 4, 5"
                    ));
                }
            }
        }
    };

    // ── Obfs opts ────────────────────────────────────────────────────────
    let obfs = if let Some(opts) = config.get("obfs-opts") {
        let mode = opts
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("off")
            .to_ascii_lowercase();
        let host = opts
            .get("host")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map_or_else(|| server.to_string(), std::string::ToString::to_string);
        match mode.as_str() {
            "off" | "none" | "" => SnellObfs::None,
            "http" => SnellObfs::Http { host },
            "tls" => SnellObfs::Tls { server: host },
            other => {
                return Err(format!(
                    "snell[{name}]: obfs-opts.mode '{other}' invalid; expected one of off, http, tls"
                ));
            }
        }
    } else {
        SnellObfs::None
    };

    SnellAdapter::new(
        name,
        server,
        port,
        psk,
        obfs,
        version,
        udp,
        reuse,
        Arc::clone(dialer),
    )
    .map_err(|e| format!("snell[{name}]: {e}"))
}

/// Parse a `type: http` proxy config block into an `HttpAdapter`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `username` set without `password` (or vice versa) — orphaned credential.
///
/// # Notes
///
/// `headers:` entries are injected into the CONNECT request only.
///
/// upstream: `adapter/outbound/http.go`
fn parse_http(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<HttpAdapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("http: missing server")?;
    let port = required_port(config, "http")?;
    let tls = config
        .get("tls")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);

    // Both username and password must be set, or neither (Class A).
    let username = config.get("username").and_then(|v| v.as_str());
    let password = config.get("password").and_then(|v| v.as_str());
    let auth = match (username, password) {
        (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
        (None, None) => None,
        _ => {
            return Err("http: both 'username' and 'password' must be set, or neither".to_string())
        }
    };

    // Parse optional headers map.
    let extra_headers: Vec<(String, String)> = config
        .get("headers")
        .and_then(|v| v.as_mapping())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.as_str()?.to_string(), v.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();

    Ok(HttpAdapter::new(
        name,
        server,
        port,
        auth,
        tls,
        skip_cert_verify,
        extra_headers,
        Arc::clone(dialer),
    ))
}

/// Parse a `type: socks5` proxy config block into a `Socks5Adapter`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `username` set without `password` (or vice versa) — orphaned credential.
///
/// `udp: true` enables SOCKS5 UDP ASSOCIATE (HTTP/3 / QUIC relay).
///
/// upstream: `adapter/outbound/socks5.go`
fn parse_socks5(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<Socks5Adapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("socks5: missing server")?;
    let port = required_port(config, "socks5")?;
    let tls = config
        .get("tls")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);

    // Both username and password must be set, or neither (Class A).
    let username = config.get("username").and_then(|v| v.as_str());
    let password = config.get("password").and_then(|v| v.as_str());
    let auth = match (username, password) {
        (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
        (None, None) => None,
        _ => {
            return Err(
                "socks5: both 'username' and 'password' must be set, or neither".to_string(),
            )
        }
    };

    let udp = config
        .get("udp")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);

    Ok(Socks5Adapter::new(
        name,
        server,
        port,
        auth,
        tls,
        skip_cert_verify,
        Arc::clone(dialer),
    )
    .with_udp(udp))
}

/// Parse a `type: direct` proxy block into a [`DirectAdapter`].
///
/// Accepts an optional `dns:` field — a single `host:port` string or a list
/// of them — that scopes hostname resolution for this proxy to the given DNS
/// servers (plain UDP). Closes #67: lets users route a subset of direct
/// traffic through a different DNS than the global resolver (e.g. a LAN
/// resolver for `*.local` while the global resolver handles WAN).
///
/// `dns:` entries must include an explicit port (`:53` is conventional).
/// Hard error (Class A per ADR-0002) on an unparseable address — silently
/// falling back to the global resolver would surprise the user by leaking
/// queries.
fn parse_direct(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
    ipv6: bool,
) -> std::result::Result<DirectAdapter, String> {
    use meow_common::DnsMode;
    use meow_dns::Resolver;
    use meow_trie::DomainTrie;
    use std::net::{IpAddr, SocketAddr};

    let mut adapter = DirectAdapter::new();

    // Optional `connect-timeout:` (seconds) — per-proxy counterpart of the
    // global `tcp-connect-timeout:` that covers the built-in DIRECT. Hard
    // error on a non-integer (Class A per ADR-0002): silently ignoring it
    // would leave the connect unbounded when the user asked for a bound.
    if let Some(v) = config.get("connect-timeout") {
        let secs = v.as_u64().ok_or_else(|| {
            format!("direct[{name}]: connect-timeout must be a non-negative integer (seconds)")
        })?;
        adapter = adapter.with_connect_timeout(std::time::Duration::from_secs(secs));
    }

    if let Some(v) = config.get("dns") {
        let entries: Vec<String> = match v {
            serde_yaml::Value::String(s) => vec![s.clone()],
            serde_yaml::Value::Sequence(seq) => seq
                .iter()
                .map(|e| {
                    e.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| format!("direct[{name}]: dns entries must be strings"))
                })
                .collect::<std::result::Result<_, _>>()?,
            _ => {
                return Err(format!(
                    "direct[{name}]: dns must be a string or list of strings"
                ));
            }
        };

        let mut servers: Vec<SocketAddr> = Vec::with_capacity(entries.len());
        for entry in &entries {
            // Accept `IP` (default port 53), `IP:53`, or bracketed IPv6.
            let parsed = if let Ok(sa) = entry.parse::<SocketAddr>() {
                sa
            } else if let Ok(ip) = entry.parse::<IpAddr>() {
                SocketAddr::new(ip, 53)
            } else {
                return Err(format!(
                    "direct[{name}]: dns entry '{entry}' is not a valid IP or host:port"
                ));
            };
            servers.push(parsed);
        }

        if servers.is_empty() {
            return Err(format!("direct[{name}]: dns list is empty"));
        }

        let resolver = Arc::new(Resolver::new(
            servers,
            Vec::new(),
            DnsMode::Normal,
            DomainTrie::new(),
            false,
            ipv6,
        ));
        adapter = adapter.with_resolver(resolver);
    }

    Ok(adapter)
}

/// Parse a `type: anytls` proxy block into an [`AnytlsAdapter`].
///
/// Required fields: `server`, `port`, `password`. Optional: `sni`,
/// `skip-cert-verify`, `udp`. Closes the parser side of issue #75; the wire
/// protocol itself is provided by the `anytls-rs` crate.
///
/// `udp` defaults to `false`, matching mihomo's `AnyTLSOption.UDP` (the
/// adapter then relays datagrams over udp-over-tcp v2).
///
/// # Hard errors (Class A per ADR-0002)
///
/// - missing `server`, `port`, or `password` — required by the protocol.
/// - `port == 0` — never a valid endpoint.
///
/// upstream: `adapter/outbound/anytls.go`
#[cfg(feature = "anytls")]
fn parse_anytls(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<meow_proxy::AnytlsAdapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("anytls[{name}]: missing server"))?;
    let port = required_port(config, &format!("anytls[{name}]"))?;
    let password = config
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("anytls[{name}]: missing password"))?;
    let sni = config.get("sni").and_then(|v| v.as_str());
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let udp = config
        .get("udp")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);

    meow_proxy::AnytlsAdapter::new(name, server, port, password, sni, skip_cert_verify, udp)
}

/// Parse a `type: hysteria2` proxy block.
///
/// Required fields: `server`, `password`, and a port source — either `port`
/// or a concrete `ports` hopping range (mihomo accepts either, and airport
/// subscriptions commonly omit `port` when `ports` is set; issue #377).
/// Optional fields follow the mihomo surface supported by the in-tree Rust
/// backend: `up`, `down`, `obfs: salamander`, `obfs-password`, `ports`,
/// `hop-interval`, `sni`, `skip-cert-verify`, `fingerprint`, `udp`, and
/// `fast-open`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - missing `server` or `password`.
/// - no usable port: `port` absent (or 0) and `ports` absent or wildcard.
/// - `port == 0` with no `ports` (mihomo: "invalid port").
/// - empty `password` — caught downstream by `Hy2Adapter::new`.
/// - unsupported security/transport options (`gecko`, mTLS, ECH, realm).
///
/// upstream: `adapter/outbound/hysteria2.go`
#[cfg(feature = "hysteria2")]
fn parse_hysteria2(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<meow_proxy::Hy2Adapter, String> {
    use meow_proxy::{Hy2HopInterval, Hy2Obfs, Hy2Options};

    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("hysteria2[{name}]: missing server"))?;
    let ports = optional_nonempty_str(config, "ports");
    if let Some(ports) = &ports {
        validate_hy2_ports(name, ports)?;
    }
    let port = hy2_dial_port(name, config, ports.as_deref())?;
    let password = config
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("hysteria2[{name}]: missing password"))?;
    let sni = config.get("sni").and_then(|v| v.as_str());
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let udp = config
        .get("udp")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(true);
    let up_bps = parse_hy2_bandwidth_field(name, "up", config.get("up"))?;
    let down_bps = parse_hy2_bandwidth_field(name, "down", config.get("down"))?;

    let obfs_raw = optional_nonempty_str(config, "obfs");
    let obfs = match obfs_raw.as_deref() {
        None => None,
        Some("salamander") => Some(Hy2Obfs::Salamander),
        Some("gecko") => {
            return Err(format!(
                "hysteria2[{name}]: obfs 'gecko' is not supported by the Rust backend"
            ));
        }
        Some(other) => return Err(format!("hysteria2[{name}]: unknown obfs type: {other}")),
    };
    let obfs_password = optional_nonempty_str(config, "obfs-password");
    if obfs.is_some() && obfs_password.is_none() {
        return Err(format!("hysteria2[{name}]: missing obfs-password"));
    }

    let hop_interval = parse_hy2_hop_interval(name, config.get("hop-interval"))?;
    let fingerprint = parse_hy2_fingerprint(name, config.get("fingerprint"))?;
    let fast_open = config
        .get("fast-open")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(true);
    validate_hy2_alpn(name, config.get("alpn"))?;
    reject_unsupported_hy2_options(name, config)?;

    meow_proxy::Hy2Adapter::new(Hy2Options {
        name: name.to_string(),
        server: server.to_string(),
        port,
        password: password.to_string(),
        sni: sni.map(str::to_string),
        skip_cert_verify,
        udp,
        up_bps,
        down_bps,
        obfs,
        obfs_password,
        ports,
        hop_interval: hop_interval
            .map(|(min_secs, max_secs)| Hy2HopInterval { min_secs, max_secs }),
        fingerprint,
        fast_open,
    })
}

#[cfg(feature = "hysteria2")]
const HY2_MIN_HOP_INTERVAL_SECS: u64 = 5;
#[cfg(feature = "hysteria2")]
const HY2_DEFAULT_HOP_INTERVAL_SECS: u64 = 30;

#[cfg(feature = "hysteria2")]
fn optional_nonempty_str(config: &HashMap<String, serde_yaml::Value>, key: &str) -> Option<String> {
    config
        .get(key)
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_bandwidth_field(
    name: &str,
    field: &str,
    value: Option<&serde_yaml::Value>,
) -> std::result::Result<u64, String> {
    let Some(value) = value else {
        return Ok(0);
    };
    if let Some(v) = value.as_u64() {
        return Ok(mbps_to_bytes_per_second(v));
    }
    if let Some(s) = value.as_str() {
        return parse_hy2_bandwidth(s).map_err(|e| format!("hysteria2[{name}]: {field}: {e}"));
    }
    Err(format!(
        "hysteria2[{name}]: {field} must be a string like '30 Mbps' or an integer Mbps value"
    ))
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_bandwidth(input: &str) -> std::result::Result<u64, String> {
    static RATE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^(\d+)\s*([KMGTkmgt]?)([Bb])ps$").expect("valid rate regex")
    });

    let s = input.trim();
    if s.is_empty() || s == "0" {
        return Ok(0);
    }
    if let Ok(mbps) = s.parse::<u64>() {
        return Ok(mbps_to_bytes_per_second(mbps));
    }

    let Some(caps) = RATE_RE.captures(s) else {
        return Err(format!(
            "invalid bandwidth '{input}', expected integer Mbps or e.g. '30 Mbps'"
        ));
    };
    let value = caps[1]
        .parse::<u64>()
        .map_err(|e| format!("invalid number: {e}"))?;
    let multiplier = match caps[2].to_ascii_uppercase().as_str() {
        "" => 1,
        "K" => 1_000,
        "M" => 1_000_000,
        "G" => 1_000_000_000,
        "T" => 1_000_000_000_000,
        _ => unreachable!("regex restricts unit prefix"),
    };
    let bytes = value
        .checked_mul(multiplier)
        .ok_or_else(|| "bandwidth overflows u64".to_string())?;
    if &caps[3] == "b" {
        Ok(bytes / 8)
    } else {
        Ok(bytes)
    }
}

#[cfg(feature = "hysteria2")]
fn mbps_to_bytes_per_second(mbps: u64) -> u64 {
    mbps.saturating_mul(1_000_000) / 8
}

/// Resolve the dial port for a hysteria2 outbound. `port` wins when present
/// and non-zero; otherwise the first concrete port in the (already validated)
/// `ports` hopping spec stands in — the hopping socket rewrites every send to
/// the dial port with the current hop port, so the value is a placeholder
/// whenever hopping is active. Mirrors mihomo, which errors only when both
/// `port` and `ports` fail to yield a port (issue #377).
#[cfg(feature = "hysteria2")]
fn hy2_dial_port(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
    ports: Option<&str>,
) -> std::result::Result<u16, String> {
    let explicit = match config.get("port") {
        None => None,
        Some(value) => {
            let raw = value
                .as_u64()
                .ok_or_else(|| format!("hysteria2[{name}]: missing port"))?;
            let port = u16::try_from(raw)
                .map_err(|_| format!("hysteria2[{name}]: port {raw} exceeds 65535"))?;
            if port == 0 && ports.is_none() {
                return Err(format!("hysteria2[{name}]: port must be non-zero"));
            }
            (port != 0).then_some(port)
        }
    };
    if let Some(port) = explicit {
        return Ok(port);
    }
    ports.and_then(first_hy2_port).ok_or_else(|| {
        format!("hysteria2[{name}]: missing port — set 'port' or a concrete 'ports' range")
    })
}

/// First concrete port in a validated `ports` spec; `None` for the `*`/`all`
/// wildcard, which names no dialable port.
#[cfg(feature = "hysteria2")]
fn first_hy2_port(ports: &str) -> Option<u16> {
    let ports = ports.trim();
    if ports == "*" || ports.eq_ignore_ascii_case("all") {
        return None;
    }
    let part = ports.split(',').next()?.trim();
    let first = match part.split_once('-') {
        Some((start, _)) => start.trim(),
        None => part,
    };
    first.parse::<u16>().ok().filter(|p| *p != 0)
}

#[cfg(feature = "hysteria2")]
fn validate_hy2_ports(name: &str, ports: &str) -> std::result::Result<(), String> {
    let ports = ports.trim();
    if ports == "*" || ports.eq_ignore_ascii_case("all") {
        return Ok(());
    }
    for part in ports.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(format!("hysteria2[{name}]: invalid ports '{ports}'"));
        }
        if let Some((start, end)) = part.split_once('-') {
            parse_hy2_port_part(name, start)?;
            parse_hy2_port_part(name, end)?;
        } else {
            parse_hy2_port_part(name, part)?;
        }
    }
    Ok(())
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_port_part(name: &str, value: &str) -> std::result::Result<u16, String> {
    value
        .trim()
        .parse::<u16>()
        .map_err(|e| format!("hysteria2[{name}]: invalid port '{value}': {e}"))
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_hop_interval(
    name: &str,
    value: Option<&serde_yaml::Value>,
) -> std::result::Result<Option<(u64, u64)>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let raw = if let Some(n) = value.as_u64() {
        n.to_string()
    } else {
        value
            .as_str()
            .ok_or_else(|| format!("hysteria2[{name}]: hop-interval must be a number or range"))?
            .trim()
            .to_string()
    };
    if raw.is_empty() {
        return Err(format!("hysteria2[{name}]: hop-interval must not be empty"));
    }
    if raw.contains(',') {
        return Err(format!(
            "hysteria2[{name}]: hop-interval only supports one range"
        ));
    }
    if let Some((start, end)) = raw.split_once('-') {
        let start = parse_hy2_u64(name, "hop-interval", start)?;
        let end = parse_hy2_u64(name, "hop-interval", end)?;
        Ok(Some(normalize_hy2_hop_interval(start, end)))
    } else {
        let start = parse_hy2_u64(name, "hop-interval", &raw)?;
        Ok(Some(normalize_hy2_hop_interval(start, 0)))
    }
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_u64(name: &str, field: &str, value: &str) -> std::result::Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("hysteria2[{name}]: invalid {field} '{value}': {e}"))
}

#[cfg(feature = "hysteria2")]
fn normalize_hy2_hop_interval(start: u64, end: u64) -> (u64, u64) {
    let start = if start == 0 {
        HY2_DEFAULT_HOP_INTERVAL_SECS
    } else {
        start.max(HY2_MIN_HOP_INTERVAL_SECS)
    };
    let end = if end == 0 { start } else { end.max(start) };
    (start, end)
}

#[cfg(feature = "hysteria2")]
fn parse_hy2_fingerprint(
    name: &str,
    value: Option<&serde_yaml::Value>,
) -> std::result::Result<Option<String>, String> {
    let Some(raw) = value.and_then(serde_yaml::Value::as_str) else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let raw = raw.rsplit_once('=').map_or(raw, |(_, fp)| fp.trim());
    let hex: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "hysteria2[{name}]: fingerprint must be a SHA-256 hex digest"
        ));
    }
    Ok(Some(raw.to_string()))
}

#[cfg(feature = "hysteria2")]
fn validate_hy2_alpn(
    name: &str,
    value: Option<&serde_yaml::Value>,
) -> std::result::Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let mut alpns = Vec::new();
    if let Some(items) = value.as_sequence() {
        for item in items {
            let alpn = item
                .as_str()
                .ok_or_else(|| format!("hysteria2[{name}]: alpn entries must be strings"))?;
            alpns.push(alpn);
        }
    } else if let Some(alpn) = value.as_str() {
        alpns.push(alpn);
    } else {
        return Err(format!(
            "hysteria2[{name}]: alpn must be a string or string list"
        ));
    }
    if alpns.iter().any(|alpn| *alpn != "h3") {
        return Err(format!(
            "hysteria2[{name}]: custom alpn is unsupported; only 'h3' is allowed"
        ));
    }
    Ok(())
}

#[cfg(feature = "hysteria2")]
fn reject_unsupported_hy2_options(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<(), String> {
    for key in [
        "certificate",
        "private-key",
        "obfs-min-packet-size",
        "obfs-max-packet-size",
    ] {
        if config.contains_key(key) {
            return Err(format!(
                "hysteria2[{name}]: '{key}' is not supported by the Rust backend"
            ));
        }
    }
    reject_enabled_hy2_map(name, config, "ech-opts")?;
    reject_enabled_hy2_map(name, config, "realm-opts")?;
    reject_nonzero_hy2_option(name, config, "cwnd")?;
    reject_nonzero_hy2_option(name, config, "udp-mtu")?;
    reject_nonzero_hy2_option(name, config, "initial-stream-receive-window")?;
    reject_nonzero_hy2_option(name, config, "max-stream-receive-window")?;
    reject_nonzero_hy2_option(name, config, "initial-connection-receive-window")?;
    reject_nonzero_hy2_option(name, config, "max-connection-receive-window")?;
    if optional_nonempty_str(config, "bbr-profile").is_some() {
        return Err(format!(
            "hysteria2[{name}]: 'bbr-profile' is not supported by the Rust backend"
        ));
    }
    Ok(())
}

#[cfg(feature = "hysteria2")]
fn reject_enabled_hy2_map(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
    key: &str,
) -> std::result::Result<(), String> {
    if let Some(value) = config.get(key) {
        let enabled = value
            .as_mapping()
            .and_then(|map| map.get(serde_yaml::Value::String("enable".into())))
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(true);
        if enabled {
            return Err(format!(
                "hysteria2[{name}]: '{key}' is not supported by the Rust backend"
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "hysteria2")]
fn reject_nonzero_hy2_option(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
    key: &str,
) -> std::result::Result<(), String> {
    if let Some(value) = config.get(key) {
        let nonzero =
            value.as_u64().is_some_and(|v| v != 0) || value.as_i64().is_some_and(|v| v != 0);
        if nonzero {
            return Err(format!(
                "hysteria2[{name}]: '{key}' is not supported by the Rust backend"
            ));
        }
    }
    Ok(())
}

/// Parse the `strategy` field for a `load-balance` group.
///
/// Hard error on unknown values (Class A per ADR-0002): unknown strategy means
/// the user may get different distribution behaviour than intended.
/// upstream: adapter/outbound/loadbalance.go silently falls back to round-robin.
/// NOT silent fallback.
fn parse_lb_strategy(strategy: Option<&str>) -> std::result::Result<LbStrategy, String> {
    match strategy.unwrap_or("round-robin") {
        "round-robin" => Ok(LbStrategy::RoundRobin),
        "consistent-hashing" => Ok(LbStrategy::ConsistentHashing),
        other => Err(format!(
            "load-balance: unknown strategy '{other}'; valid values: \
             'round-robin' (default), 'consistent-hashing'. \
             (upstream: falls back silently to round-robin; we reject — Class A ADR-0002)"
        )),
    }
}

/// Parse a `type: vless` proxy config block into a `VlessAdapter`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `flow: xtls-rprx-direct` / `xtls-rprx-splice` — deprecated and insecure
/// - Unknown `flow` values — may skip expected security processing
/// - `reality-opts` malformed, used without TLS, or missing `client-fingerprint`
/// - `flow: xtls-rprx-vision` + no TLS-enforcing transport
/// - `encryption: <non-empty non-"none">` — unsupported cipher
/// - `uuid` invalid
/// - `server` domain > 255 bytes
/// - `vless-vision` feature absent + `flow: xtls-rprx-vision`
/// - `flow: xtls-rprx-vision` + a `smux`/`mux` block using sing-mux
///   (`protocol: smux`/`yamux`/`h2mux`) — sing-box and Xray reject XTLS +
///   sing-mux (`protocol: muxcool` is fine)
///
/// # Warn-once (Class B per ADR-0002)
///
/// - `tls: false` with plain VLESS — plaintext, but correct destination
/// - `mux: { enabled: true }` — sing-mux multiplexing (server must be sing-box/mihomo)
/// - `flow: xtls-rprx-vision` + `udp: true` — Vision is TCP-only; UDP uses plain VLESS
/// - `reality-opts.short-id` given as a bare YAML number (e.g. `0x1f`) —
///   coerced to its decimal digits before hex-decoding (matching mihomo),
///   which can silently reinterpret the value; quote it to preserve the
///   literal digits
#[cfg(feature = "vless")]
fn parse_vless(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<VlessAdapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("vless: missing server")?;
    let port = required_port(config, "vless")?;
    let uuid_str = config
        .get("uuid")
        .and_then(|v| v.as_str())
        .ok_or("vless: missing uuid")?;
    let uuid_bytes = parse_uuid(uuid_str).map_err(|e| format!("vless: {e}"))?;

    // Validate server domain length (Class A — wrong destination with no diagnostic).
    if server.len() > 255 {
        return Err(format!(
            "vless: server '{}…' domain is {} bytes; max 255 \
             (would be silently truncated — wrong destination, no diagnostic)",
            &server[..server.len().min(20)],
            server.len()
        ));
    }

    let udp = config
        .get("udp")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let tls = config
        .get("tls")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let servername = config
        .get("servername")
        .and_then(|v| v.as_str())
        .unwrap_or(server)
        .to_string();
    let alpn: Vec<String> = config
        .get("alpn")
        .and_then(|v| v.as_sequence())
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
        .collect();
    let network = config
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");
    let client_fingerprint = config.get("client-fingerprint").and_then(|v| v.as_str());

    // ── Reality opts ──────────────────────────────────────────────────────
    let reality = parse_vless_reality_opts(name, config)?;
    if reality.is_some() {
        if !tls {
            return Err("vless: reality-opts requires `tls: true`".into());
        }
        if client_fingerprint.is_none() {
            return Err("vless: REALITY is based on uTLS, please set a client-fingerprint".into());
        }
    }

    // ── VLESS Encryption (`mlkem768x25519plus…`) ──────────────────────────
    // "" / "none" → plain VLESS. The post-quantum Encryption layer is parsed
    // when the `vless-encryption` feature is compiled in; anything else (a real
    // cipher name, or the ML-KEM string on a build without the feature) is a
    // hard error (Class A — silently ignoring it would send unprotected bytes).
    let encryption = config
        .get("encryption")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    #[cfg(feature = "vless-encryption")]
    let vless_encryption = parse_vless_encryption(encryption)?;
    #[cfg(not(feature = "vless-encryption"))]
    parse_vless_encryption(encryption)?;

    // ── client-fingerprint ──────────────────────────────────────────────
    // Passed through to TlsConfig.fingerprint; the TLS layer selects the
    // BoringSSL backend when the `boring-tls` feature is compiled in,
    // otherwise falls back to rustls with a stub warning.

    // ── Flow parsing ──────────────────────────────────────────────────────
    let flow_str = config.get("flow").and_then(|v| v.as_str()).unwrap_or("");

    let flow: Option<VlessFlow> = match flow_str {
        "" => None,

        "xtls-rprx-vision" => {
            // Hard error if vless-vision feature is not compiled in (Class A).
            #[cfg(not(feature = "vless-vision"))]
            {
                return Err(
                    "vless: flow xtls-rprx-vision requires the `vless-vision` Cargo feature; \
                     rebuild with --features vless-vision"
                        .into(),
                );
            }
            #[cfg(feature = "vless-vision")]
            Some(VlessFlow::XtlsRprxVision)
        }

        "xtls-rprx-direct" | "xtls-rprx-splice" => {
            // Class A: upstream accepts these as deprecated aliases; we reject them.
            // upstream: adapter/outbound/vless.go — accepts deprecated flows.
            // NOT warn-ignore — security regression vs Vision if user assumes Vision protection.
            return Err(format!(
                "vless: flow '{flow_str}' is deprecated and insecure; \
                 use `flow: xtls-rprx-vision` instead. \
                 (upstream: adapter/outbound/vless.go accepts this; we reject — Class A ADR-0002)"
            ));
        }

        other => {
            // Class A: unknown flow may skip expected security processing.
            // upstream: adapter/outbound/vless.go ignores unknown flows.
            // NOT warn-ignore — unknown flow value may silently degrade security.
            return Err(format!(
                "vless: unknown flow '{other}'; valid values: '' or 'xtls-rprx-vision'. \
                 (upstream: ignores unknown flows; we reject — Class A ADR-0002)"
            ));
        }
    };

    // ── Gating: Vision requires TLS (or a TLS-enforcing transport) (Class A) ─
    if flow == Some(VlessFlow::XtlsRprxVision) {
        let tls_transport = network == "grpc" || network == "h2";
        if !tls && !tls_transport {
            return Err(
                "vless: flow xtls-rprx-vision requires an encrypting transport; \
                 set `tls: true` or use a TLS-enforcing network (grpc, h2). \
                 Without outer TLS, Vision splice is a no-op and the user has no protection."
                    .into(),
            );
        }
    }

    // ── Warn: tls: false with plain VLESS (Class B) ───────────────────────
    if !tls && flow.is_none() && network != "grpc" && network != "h2" {
        tracing::warn!(
            proxy = %name,
            "vless: tls is false and no TLS-enforcing transport is set; \
             traffic will be plaintext (correct destination, absent crypto). \
             Set `tls: true` to encrypt. (Class B divergence — upstream is silent)"
        );
    }

    // ── mux: sing-mux compatible connection multiplexing ─────────────────
    // Parsed after adapter construction below — see the `with_mux` call.

    // ── Warn: Vision + UDP (Class B) ─────────────────────────────────────
    if flow == Some(VlessFlow::XtlsRprxVision) && udp {
        tracing::warn!(
            proxy = %name,
            "flow: xtls-rprx-vision applies to TCP only; UDP relays on \
             this proxy will use plain VLESS (Vision's inner-TLS splice \
             is not defined for UDP datagrams). (Class B divergence)"
        );
    }

    // ── Build transport chain ──────────────────────────────────────────────
    let mut chain = TransportChain::empty();

    if tls {
        use meow_transport::tls::{TlsConfig, TlsLayer};
        let sni = if servername.is_empty() {
            server.to_string()
        } else {
            servername
        };
        let mut tls_cfg = TlsConfig::new(sni);
        tls_cfg.skip_cert_verify = skip_cert_verify;
        tls_cfg.alpn = default_transport_alpn(network, alpn);
        tls_cfg.fingerprint = client_fingerprint.map(std::string::ToString::to_string);
        tls_cfg.reality = reality;

        // ── ECH opts ────────────────────────────────────────────────────
        // DNS-sourced ECH (`enable: true` without `config:`) is resolved by
        // `ech_dns::preresolve_ech` *before* `parse_proxy` runs, which injects
        // the fetched bytes back into `ech-opts.config` as base64. By the time
        // we get here only the inline-config branch matters; a missing
        // `config:` means pre-resolution failed (already warned) and we just
        // continue without ECH.
        if let Some(ech_opts) = config.get("ech-opts") {
            let ech_enabled = ech_opts
                .get("enable")
                .and_then(serde_yaml::Value::as_bool)
                .unwrap_or(false);
            if ech_enabled {
                use meow_transport::tls::EchOpts;
                if let Some(inline_config) = ech_opts.get("config").and_then(|v| v.as_str()) {
                    use base64::Engine;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(inline_config)
                        .map_err(|e| format!("vless: ech-opts.config base64 decode: {e}"))?;
                    tls_cfg.ech = Some(EchOpts::Config(bytes));
                }
            }
        }

        let tls_layer =
            TlsLayer::new(&tls_cfg).map_err(|e| format!("vless: TLS layer error: {e}"))?;
        chain.push(Box::new(tls_layer));
    }

    match network {
        "tcp" => {} // no extra layer
        "ws" => {
            use meow_transport::ws::{WsConfig, WsLayer};
            let ws_opts = config.get("ws-opts");
            let path = ws_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            // host_header: user-supplied Host, or fall back to server address.
            // WsLayer::new requires Some; normalization is the config layer's job
            // (ADR-0001 §1 — transport never infers values from context).
            let host_header = ws_opts
                .and_then(|o| o.get("headers"))
                .and_then(|h| h.get("Host"))
                .and_then(|v| v.as_str())
                .map_or_else(|| server.to_string(), std::string::ToString::to_string);
            let max_early_data = ws_opts
                .and_then(|o| o.get("max-early-data"))
                .and_then(serde_yaml::Value::as_u64)
                .unwrap_or(0) as usize;
            let early_data_header_name = ws_opts
                .and_then(|o| o.get("early-data-header-name"))
                .and_then(|v| v.as_str())
                .map(std::string::ToString::to_string);
            let ws_cfg = WsConfig {
                path,
                host_header: Some(host_header),
                extra_headers: vec![],
                max_early_data,
                early_data_header_name,
            };
            let ws_layer =
                WsLayer::new(ws_cfg).map_err(|e| format!("vless: ws layer error: {e}"))?;
            chain.push(Box::new(ws_layer));
        }
        "grpc" => {
            use meow_transport::grpc::{GrpcConfig, GrpcLayer};
            let grpc_opts = config.get("grpc-opts");
            let service_name = grpc_opts
                .and_then(|o| o.get("grpc-service-name"))
                .and_then(|v| v.as_str())
                .unwrap_or("GunService")
                .to_string();
            // Authority: mihomo's gun transport sets `Host` to `servername`
            // and only falls back to the dial host when `servername` is empty
            // (adapter/outbound/vless.go). Front-ends that route gRPC by
            // `:authority` are provisioned against that value, so match it
            // rather than always sending the dial host (issue #377). Resolved
            // here per ADR-0001 §1 — the transport never infers it.
            let authority = config
                .get("servername")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(server)
                .to_string();
            let grpc_cfg = GrpcConfig {
                service_name,
                authority,
            };
            chain.push(Box::new(GrpcLayer::new(grpc_cfg)));
        }
        "h2" => {
            use meow_transport::h2::{H2Config, H2Layer};
            let h2_opts = config.get("h2-opts");
            let path = h2_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            // `h2-opts.host` is a list; default to server when absent.
            // Class A: empty host list is rejected — H2Layer asserts non-empty
            // (debug) and upstream requires at least one authority value.
            let hosts: Vec<String> = h2_opts
                .and_then(|o| o.get("host"))
                .and_then(|v| v.as_sequence())
                .map_or_else(
                    || vec![server.to_string()],
                    |seq| {
                        seq.iter()
                            .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
                            .collect()
                    },
                );
            if hosts.is_empty() {
                return Err(format!(
                    "vless: h2-opts.host must not be empty for proxy '{name}' \
                     (H2 requires at least one authority value)"
                ));
            }
            let h2_cfg = H2Config { path, hosts };
            chain.push(Box::new(H2Layer::new(h2_cfg)));
        }
        "httpupgrade" => {
            use meow_transport::httpupgrade::{HttpUpgradeConfig, HttpUpgradeLayer};
            let hu_opts = config.get("http-upgrade-opts");
            let path = hu_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            let host_header = hu_opts
                .and_then(|o| o.get("host"))
                .and_then(|v| v.as_str())
                .map(std::string::ToString::to_string)
                .or_else(|| Some(server.to_string()));
            let extra_headers: Vec<(String, String)> = hu_opts
                .and_then(|o| o.get("headers"))
                .and_then(|h| h.as_mapping())
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| {
                            let key = k.as_str()?.to_string();
                            let val = v.as_str()?.to_string();
                            Some((key, val))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let hu_cfg = HttpUpgradeConfig {
                path,
                host_header,
                extra_headers,
            };
            chain.push(Box::new(HttpUpgradeLayer::new(hu_cfg)));
        }
        "xhttp" => {
            use meow_transport::xhttp::{XhttpConfig, XhttpLayer};
            let xhttp_opts = config.get("xhttp-opts");
            let path = xhttp_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            let hosts: Vec<String> = xhttp_opts.and_then(|o| o.get("host")).map_or_else(
                || vec![server.to_string()],
                |v| {
                    if let Some(s) = v.as_str() {
                        vec![s.to_string()]
                    } else if let Some(seq) = v.as_sequence() {
                        seq.iter()
                            .filter_map(|item| item.as_str().map(std::string::ToString::to_string))
                            .collect()
                    } else {
                        vec![server.to_string()]
                    }
                },
            );
            if hosts.is_empty() {
                return Err(format!(
                    "vless: xhttp-opts.host must not be empty for proxy '{name}'"
                ));
            }
            let mode = xhttp_opts
                .and_then(|o| o.get("mode"))
                .and_then(|v| v.as_str())
                .unwrap_or("stream-one")
                .to_string();
            if !mode.is_empty()
                && !mode.eq_ignore_ascii_case("auto")
                && !mode.eq_ignore_ascii_case("stream-one")
            {
                return Err(format!(
                    "vless: unsupported xhttp mode '{mode}'; only 'stream-one' and 'auto' are supported"
                ));
            }
            let extra_headers: Vec<(String, String)> = xhttp_opts
                .and_then(|o| o.get("headers"))
                .and_then(|h| h.as_mapping())
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| {
                            let key = k.as_str()?.to_string();
                            let val = v.as_str()?.to_string();
                            Some((key, val))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let no_grpc_header = xhttp_opts
                .and_then(|o| o.get("no-grpc-header"))
                .and_then(serde_yaml::Value::as_bool)
                .unwrap_or(false);
            let x_padding_bytes =
                if let Some(padding_val) = xhttp_opts.and_then(|o| o.get("x-padding-bytes")) {
                    if let Some(s) = padding_val.as_str() {
                        let parts: Vec<&str> = s.split('-').collect();
                        if parts.len() == 2 {
                            let min = parts[0].trim().parse::<usize>().map_err(|e| {
                                format!("vless: invalid min in x-padding-bytes '{s}': {e}")
                            })?;
                            let max = parts[1].trim().parse::<usize>().map_err(|e| {
                                format!("vless: invalid max in x-padding-bytes '{s}': {e}")
                            })?;
                            if min > max {
                                return Err(format!(
                                    "vless: x-padding-bytes min ({min}) exceeds max ({max})"
                                ));
                            }
                            Some((min, max))
                        } else {
                            return Err(format!(
                                "vless: invalid x-padding-bytes range '{s}', expected 'min-max'"
                            ));
                        }
                    } else if let Some(seq) = padding_val.as_sequence() {
                        if seq.len() == 2 {
                            let min = seq[0].as_u64().ok_or_else(|| {
                                "vless: invalid min in x-padding-bytes".to_string()
                            })? as usize;
                            let max = seq[1].as_u64().ok_or_else(|| {
                                "vless: invalid max in x-padding-bytes".to_string()
                            })? as usize;
                            if min > max {
                                return Err(format!(
                                    "vless: x-padding-bytes min ({min}) exceeds max ({max})"
                                ));
                            }
                            Some((min, max))
                        } else {
                            return Err(
                                "vless: x-padding-bytes array must have 2 elements".to_string()
                            );
                        }
                    } else {
                        None
                    }
                } else {
                    Some((100, 1000))
                };
            let xhttp_cfg = XhttpConfig {
                path,
                hosts,
                extra_headers,
                mode,
                no_grpc_header,
                x_padding_bytes,
            };
            chain.push(Box::new(XhttpLayer::new(xhttp_cfg)));
        }
        other => {
            return Err(format!(
                "vless: unsupported network '{other}'; valid values: tcp, ws, grpc, h2, httpupgrade, xhttp"
            ));
        }
    }

    #[cfg_attr(not(feature = "vless-encryption"), allow(unused_mut))]
    let mut adapter = VlessAdapter::new(
        name,
        server,
        port,
        uuid_bytes,
        flow,
        udp,
        chain,
        Arc::clone(dialer),
    );
    #[cfg(feature = "vless-encryption")]
    adapter.set_encryption(vless_encryption);

    #[cfg(feature = "mux")]
    if let Some(mux_options) = parse_mux_options(name, config)? {
        // Vision + sing-mux (smux/yamux/h2mux) is rejected by both sing-box
        // and Xray servers: the mux session dials the reserved mux
        // destination and the server tears the Vision-wrapped connection
        // down with no diagnostic — hard error at config time rather than a
        // silent dial failure. Vision + Mux.Cool (`protocol: muxcool`) is
        // the opposite case: Xray's own Mux.Cool signaling rides inside the
        // VLESS request that Vision splices, and this has been live-tested
        // against a real Xray node (see docs/specs/proxy-mux.md "Test Plan"
        // items 2-3, issue #424) — so only the sing-mux protocols are gated
        // here.
        #[cfg(feature = "vless-vision")]
        if flow == Some(VlessFlow::XtlsRprxVision)
            && mux_options.protocol != meow_proxy::mux::Protocol::MuxCool
        {
            return Err(
                "vless: flow xtls-rprx-vision is incompatible with sing-mux \
                 (smux/yamux/h2mux); sing-box and Xray reject XTLS + sing-mux. \
                 Use `protocol: muxcool` for Vision + multiplexing instead."
                    .into(),
            );
        }
        adapter = adapter.with_mux(mux_options);
    }
    #[cfg(not(feature = "mux"))]
    parse_mux_options(name, config)?;

    Ok(adapter)
}

/// Parse the optional mihomo `smux:` block shared by
/// VLESS/Trojan/Shadowsocks/VMess.  `mux:` remains accepted as a legacy alias.
///
/// Two wire protocols are available, picked by `protocol`:
///
/// * sing-mux (smux/yamux/h2mux, default h2mux) — the first proxy request
///   targets the reserved mux destination and streams carry a sing-encoded
///   Socksaddr prefix.  Server must be sing-box / mihomo based.
/// * muxcool — Xray's Mux.Cool (CommandMux 0x03 in the VLESS/VMess request
///   header, frame mux).  Server must be Xray / sing-box based; VLESS and
///   VMess support it (Trojan/Shadowsocks reject it).
///
/// Returns `None` when the block is absent or disabled; `Err` for
/// malformed values.  Only compiled when one of its call sites
/// (trojan / vless / ss / vmess parsing) exists.
#[cfg(all(
    feature = "mux",
    any(
        feature = "trojan",
        feature = "vless",
        feature = "ss",
        feature = "vmess"
    )
))]
fn parse_mux_options(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<Option<meow_proxy::mux::MuxOptions>, String> {
    let Some(mux_cfg) = mux_config_block(name, config)? else {
        return Ok(None);
    };
    let enabled = mux_bool_field(name, mux_cfg, "enabled", false)?;
    if !enabled {
        return Ok(None);
    }
    // Empty protocol maps to h2mux, matching mihomo's default.
    let protocol_str = match mux_cfg.get("protocol") {
        None => "h2mux",
        Some(serde_yaml::Value::String(s)) => s.as_str(),
        Some(other) => {
            return Err(format!(
                "{name}: mux option 'protocol' must be a string, got {other:?}"
            ))
        }
    };
    let Some(protocol) = meow_proxy::mux::Protocol::parse(protocol_str) else {
        // mihomo hard-errors on unknown protocols; do the same so a typo
        // cannot silently speak the wrong wire protocol to the server.
        return Err(format!(
            "{name}: unknown mux protocol '{protocol_str}'; valid values: smux, yamux, h2mux, muxcool"
        ));
    };
    // max-connections=0 AND max-streams=0 means one physical connection
    // per stream (mirrors mihomo/sing-mux exactly) — almost never what an
    // operator wants, so say so.
    let max_connections = mux_usize_field(name, mux_cfg, "max-connections", 4)?;
    let max_streams = mux_usize_field(name, mux_cfg, "max-streams", 4)?;
    if max_connections == 0 && max_streams == 0 {
        tracing::warn!(
            proxy = %name,
            "mux: max-connections and max-streams are both 0 — every stream dials its own \
             physical connection (mirrors mihomo); consider the 4/4/4 defaults"
        );
    }
    // Parsed but unsupported upstream fields: `statistic` (per-connection
    // traffic attribution in mihomo's dialer) and `brutal-opts` (TCP Brutal,
    // Linux-only upstream).  Warn once so operators know the divergence.
    for unsupported in ["statistic", "brutal-opts"] {
        if mux_cfg.get(unsupported).is_some() {
            tracing::warn!(
                proxy = %name,
                "mux option '{}' is not supported in meow-rs and will be ignored",
                unsupported
            );
        }
    }
    Ok(Some(meow_proxy::mux::MuxOptions {
        protocol,
        padding: mux_bool_field(name, mux_cfg, "padding", false)?,
        max_connections,
        min_streams: mux_usize_field(name, mux_cfg, "min-streams", 4)?,
        max_streams,
        only_tcp: mux_bool_field(name, mux_cfg, "only-tcp", false)?,
    }))
}

/// No-mux builds: warn loudly instead of silently ignoring an enabled
/// `smux:`/`mux:` block (operators would otherwise think the node is multiplexed).
/// Only compiled when one of its call sites (trojan / vless / ss / vmess
/// parsing) exists.
#[cfg(all(
    not(feature = "mux"),
    any(
        feature = "trojan",
        feature = "vless",
        feature = "ss",
        feature = "vmess"
    )
))]
fn parse_mux_options(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<(), String> {
    if let Some(mux_cfg) = mux_config_block(name, config)? {
        let enabled = mux_cfg
            .get("enabled")
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(false);
        if enabled {
            tracing::warn!(
                proxy = %name,
                "mux is enabled in config but this build was compiled without the `mux` feature; the option is ignored"
            );
        }
    }
    Ok(())
}

#[cfg(any(
    feature = "trojan",
    feature = "vless",
    feature = "ss",
    feature = "vmess"
))]
fn mux_config_block<'a>(
    name: &str,
    config: &'a HashMap<String, serde_yaml::Value>,
) -> std::result::Result<Option<&'a serde_yaml::Value>, String> {
    let block = match (config.get("smux"), config.get("mux")) {
        (Some(_), Some(_)) => {
            // Migration-friendly: prefer the canonical key and say so,
            // instead of rejecting the node for a likely leftover.
            tracing::warn!(
                proxy = %name,
                "both `smux` and legacy alias `mux` are configured; using the canonical `smux` key"
            );
            config.get("smux")
        }
        (Some(config), None) | (None, Some(config)) => Some(config),
        (None, None) => None,
    };
    let Some(block) = block else {
        return Ok(None);
    };
    // A scalar like `smux: true` must not be treated as "disabled" —
    // the operator clearly tried to enable multiplexing.
    if !block.is_mapping() {
        return Err(format!(
            "{name}: `smux`/`mux` must be a mapping, got {block:?}"
        ));
    }
    Ok(Some(block))
}

#[cfg(all(
    feature = "mux",
    any(
        feature = "trojan",
        feature = "vless",
        feature = "ss",
        feature = "vmess"
    )
))]
fn mux_bool_field(
    name: &str,
    mux_cfg: &serde_yaml::Value,
    key: &str,
    default: bool,
) -> std::result::Result<bool, String> {
    match mux_cfg.get(key) {
        None => Ok(default),
        Some(serde_yaml::Value::Bool(b)) => Ok(*b),
        Some(other) => Err(format!(
            "{name}: mux option '{key}' must be a boolean, got {other:?}"
        )),
    }
}

#[cfg(all(
    feature = "mux",
    any(
        feature = "trojan",
        feature = "vless",
        feature = "ss",
        feature = "vmess"
    )
))]
fn mux_usize_field(
    name: &str,
    mux_cfg: &serde_yaml::Value,
    key: &str,
    default: usize,
) -> std::result::Result<usize, String> {
    match mux_cfg.get(key) {
        None => Ok(default),
        Some(serde_yaml::Value::Number(n)) if n.is_u64() => Ok(n.as_u64().unwrap() as usize),
        Some(other) => Err(format!(
            "{name}: mux option '{key}' must be a non-negative integer, got {other:?}"
        )),
    }
}

/// Parse the VLESS `encryption` field.
///
/// With the `vless-encryption` feature: `""`/`"none"` → `None`, a
/// `mlkem768x25519plus…` string → a shared [`VlessEncryptionClient`], anything
/// else → error.
#[cfg(all(feature = "vless", feature = "vless-encryption"))]
fn parse_vless_encryption(
    encryption: &str,
) -> std::result::Result<Option<std::sync::Arc<meow_proxy::VlessEncryptionClient>>, String> {
    meow_proxy::parse_client_encryption(encryption)
        .map(|opt| opt.map(std::sync::Arc::new))
        .map_err(|e| format!("vless: {e}"))
}

/// Without the feature: accept only `""`/`"none"`; reject everything else with a
/// diagnostic that points at the missing feature for the ML-KEM string.
#[cfg(all(feature = "vless", not(feature = "vless-encryption")))]
fn parse_vless_encryption(encryption: &str) -> std::result::Result<(), String> {
    if encryption.is_empty() || encryption == "none" {
        return Ok(());
    }
    if encryption.starts_with("mlkem768x25519plus") {
        return Err(format!(
            "vless: encryption '{encryption}' (VLESS post-quantum Encryption) requires the \
             `vless-encryption` Cargo feature; rebuild with --features vless-encryption"
        ));
    }
    Err(format!(
        "vless: encryption '{encryption}' is not supported; set `encryption: none`, omit the \
         field, or use `mlkem768x25519plus…` on a build with the `vless-encryption` feature"
    ))
}

/// Decode a base64 raw-url string the way Go's `base64.RawURLEncoding` does:
/// no padding, and (unlike the crate's strict `URL_SAFE_NO_PAD`) tolerant of a
/// final symbol's non-canonical trailing bits. 3x-ui / Xray configs in the wild
/// carry such keys (see issue #301), so strict decoding would wrongly reject
/// otherwise-valid 32-byte X25519 keys.
#[cfg(feature = "vless")]
fn decode_raw_url_base64_lenient(s: &str) -> Option<Vec<u8>> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    use base64::{alphabet, Engine};
    let engine = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    engine.decode(s).ok()
}

/// Default the TLS ALPN by transport when the user configures none:
/// WebSocket CDNs (notably Cloudflare) route on `http/1.1`; gRPC and h2 run
/// on HTTP/2 and many servers — xray REALITY in particular — reject a client
/// that does not offer `h2` (issue #377). An explicit `alpn:` always wins.
/// upstream: mihomo forces `h2` in its gun (gRPC) transport TLS config.
#[cfg(any(feature = "vless", feature = "vmess"))]
fn default_transport_alpn(network: &str, alpn: Vec<String>) -> Vec<String> {
    if !alpn.is_empty() {
        return alpn;
    }
    match network {
        "ws" => vec!["http/1.1".to_string()],
        "grpc" | "h2" | "xhttp" => vec!["h2".to_string()],
        _ => alpn,
    }
}

/// Parse VLESS `reality-opts` into transport-layer REALITY parameters.
///
/// Matches mihomo's wire-facing fields: `public-key` is base64 RawURL X25519,
/// `short-id` is hex-decoded and zero-padded to eight bytes, and
/// `support-x25519mlkem768` is a capability flag. The TLS layer currently
/// offers X25519 only; keeping the flag in config preserves the public surface
/// for future fingerprint-specific ClientHello work.
#[cfg(feature = "vless")]
fn parse_vless_reality_opts(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<Option<meow_transport::tls::RealityConfig>, String> {
    let Some(opts) = config.get("reality-opts") else {
        return Ok(None);
    };

    let public_key_str = opts
        .get("public-key")
        .and_then(serde_yaml::Value::as_str)
        .ok_or_else(|| "vless: reality-opts.public-key is required".to_string())?;

    let public_key_bytes = decode_raw_url_base64_lenient(public_key_str)
        .ok_or_else(|| "vless: invalid REALITY public key".to_string())?;
    if public_key_bytes.len() != 32 {
        return Err("vless: invalid REALITY public key".into());
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&public_key_bytes);

    // Subscription generators (e.g. Clash Verge) emit `short-id: null` when
    // the server has no short-id; mihomo treats it as absent (#388).
    //
    // An all-decimal short-id (e.g. `short-id: 1234`, unquoted) parses as a
    // YAML integer rather than a string, so it must be reformatted back to
    // its decimal digits before hex-decoding — otherwise the `as_str()` arm
    // below rejects it and the node is silently dropped. This mirrors
    // mihomo's weakly-typed decoder, which does the same int-to-decimal-string
    // coercion (`common/structure`'s `decodeString`) before hex-decoding, so
    // a subscription that yields a valid node on mihomo yields one here too
    // (#408). Note this only round-trips cleanly when the short-id happens to
    // be all decimal digits, e.g. `0x1f` parses as the number 31 and becomes
    // `"31"`, not `"1f"` — the same lossy coercion mihomo performs. (An
    // all-decimal literal with a leading zero like `0012` is *not* affected:
    // YAML's core-schema int resolver only matches decimal scalars without a
    // leading zero, so `0012` parses as the plain string `"0012"` and never
    // reaches this branch at all — verified by
    // `parse_vless_reality_opts_leading_zero_short_id_preserved_no_warn`.)
    // We warn on the Number coercion (see below) so operators who wrote a
    // notation like `0x1f` expecting it to be read as literal hex digits
    // know to quote the value instead.
    let short_id_str = match opts.get("short-id") {
        None | Some(serde_yaml::Value::Null) => String::new(),
        Some(serde_yaml::Value::Number(n)) => {
            let coerced = n
                .as_u64()
                .map(|u| u.to_string())
                .or_else(|| n.as_i64().map(|i| i.to_string()))
                .ok_or_else(|| "vless: reality-opts.short-id must be a hex string".to_string())?;
            // A bare numeric short-id (e.g. `short-id: 0x1f`) is reinterpreted
            // through YAML's own notation before we ever see it — `0x1f`
            // arrives here as the decimal integer 31, which then hex-decodes
            // to a different byte than the literal hex digits "1f" would.
            // mihomo's decoder has the same lossy behavior, so we match it
            // for the decoded value, but warn so operators who meant the
            // literal digits know to quote the value instead of leaving it
            // as a bare YAML number.
            tracing::warn!(
                proxy = %name,
                "reality-opts.short-id was given as an unquoted YAML number \
                 and coerced to its decimal digits \"{coerced}\" before hex-decoding; \
                 if you wrote a different notation (e.g. `0x1f`) expecting it to be \
                 read as literal hex digits, quote the value instead \
                 (e.g. short-id: \"1f\")"
            );
            coerced
        }
        Some(value) => value
            .as_str()
            .ok_or_else(|| "vless: reality-opts.short-id must be a hex string".to_string())?
            .to_string(),
    };
    let short_id_vec = parse_reality_short_id(&short_id_str)?;
    let mut short_id = [0u8; 8];
    short_id[..short_id_vec.len()].copy_from_slice(&short_id_vec);

    let support_x25519_mlkem768 = opts
        .get("support-x25519mlkem768")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);

    Ok(Some(meow_transport::tls::RealityConfig {
        public_key,
        short_id,
        support_x25519_mlkem768,
    }))
}

#[cfg(feature = "vless")]
fn parse_reality_short_id(s: &str) -> std::result::Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || s.len() / 2 > 8 {
        return Err("vless: invalid REALITY short ID".into());
    }

    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hex = std::str::from_utf8(chunk)
            .map_err(|_| "vless: invalid REALITY short ID".to_string())?;
        let byte = u8::from_str_radix(hex, 16)
            .map_err(|_| "vless: invalid REALITY short ID".to_string())?;
        out.push(byte);
    }
    Ok(out)
}

/// Parse a UUID string (dashed or hex-only) into a 16-byte array.
///
/// Accepts: `"b831381d-6324-4d53-ad4f-8cda48b30811"` or
///          `"b831381d63244d53ad4f8cda48b30811"`.
#[cfg(feature = "vless")]
fn parse_uuid(s: &str) -> std::result::Result<[u8; 16], String> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(format!(
            "invalid uuid '{}': expected 32 hex chars (with or without dashes), got {}",
            s,
            hex.len()
        ));
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk)
            .map_err(|_| format!("invalid uuid '{s}': non-UTF8 chars"))?;
        bytes[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| format!("invalid uuid '{s}': invalid hex char at byte {i}"))?;
    }
    Ok(bytes)
}

/// Convert a YAML `plugin-opts` value to the SIP003 semicolon-separated format.
/// Accepts either a string (passed through) or a YAML map (serialized as `key=value;...`).
#[cfg(feature = "ss")]
fn serialize_plugin_opts(opts: &serde_yaml::Value) -> Option<String> {
    match opts {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Mapping(map) => {
            let parts: Vec<String> = map
                .iter()
                .filter_map(|(k, v)| {
                    let key = k.as_str()?;
                    let val = match v {
                        serde_yaml::Value::String(s) => s.clone(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        serde_yaml::Value::Number(n) => n.to_string(),
                        _ => return None,
                    };
                    Some(format!("{key}={val}"))
                })
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(";"))
            }
        }
        _ => None,
    }
}

#[cfg(feature = "vmess")]
fn parse_vmess(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
    dialer: &Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<meow_proxy::VmessAdapter, String> {
    use meow_proxy::vmess::header::Security;

    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("vmess: missing server")?;
    let port = required_port(config, "vmess")?;
    let uuid_str = config
        .get("uuid")
        .and_then(|v| v.as_str())
        .ok_or("vmess: missing uuid")?;
    let uuid_bytes = parse_uuid(uuid_str).map_err(|e| format!("vmess: {e}"))?;

    if server.len() > 255 {
        return Err(format!(
            "vmess: server domain is {} bytes; max 255",
            server.len()
        ));
    }

    // alterId: warn-and-coerce to 0
    let alter_id = config
        .get("alterId")
        .and_then(serde_yaml::Value::as_u64)
        .unwrap_or(0);
    if alter_id > 0 {
        tracing::warn!(
            proxy = %name,
            "vmess: alterId={alter_id} is deprecated and coerced to 0; \
             AEAD header mode is always used"
        );
    }

    let cipher_str = config
        .get("cipher")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");
    let security = match cipher_str {
        "auto" => meow_proxy::vmess::header::auto_security(),
        "aes-128-gcm" => Security::Aes128Gcm,
        "chacha20-poly1305" => Security::ChaCha20Poly1305,
        "none" => Security::None,
        "zero" => {
            return Err(
                "vmess: cipher 'zero' is rejected — it disables body encryption \
                 with no visual cue in the config (security gap per ADR-0002)"
                    .into(),
            );
        }
        other => return Err(format!("vmess: unsupported cipher '{other}'")),
    };

    let udp = config
        .get("udp")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let tls = config
        .get("tls")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false);
    let servername = config
        .get("servername")
        .and_then(|v| v.as_str())
        .unwrap_or(server);
    let alpn: Vec<String> = config
        .get("alpn")
        .and_then(|v| v.as_sequence())
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
        .collect();
    let network = config
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");
    let client_fingerprint = config.get("client-fingerprint").and_then(|v| v.as_str());

    // Build transport chain (same pattern as VLESS)
    let mut chain = TransportChain::empty();

    if tls {
        use meow_transport::tls::{TlsConfig, TlsLayer};
        let sni = if servername.is_empty() {
            server.to_string()
        } else {
            servername.to_string()
        };
        let mut tls_cfg = TlsConfig::new(sni);
        tls_cfg.skip_cert_verify = skip_cert_verify;
        tls_cfg.alpn = default_transport_alpn(network, alpn);
        tls_cfg.fingerprint = client_fingerprint.map(std::string::ToString::to_string);
        let tls_layer =
            TlsLayer::new(&tls_cfg).map_err(|e| format!("vmess: TLS layer error: {e}"))?;
        chain.push(Box::new(tls_layer));
    }

    match network {
        "tcp" => {}
        "ws" => {
            use meow_transport::ws::{WsConfig, WsLayer};
            let ws_opts = config.get("ws-opts");
            let path = ws_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            let host_header = ws_opts
                .and_then(|o| o.get("headers"))
                .and_then(|h| h.get("Host"))
                .and_then(|v| v.as_str())
                .map_or_else(|| server.to_string(), std::string::ToString::to_string);
            let max_early_data = ws_opts
                .and_then(|o| o.get("max-early-data"))
                .and_then(serde_yaml::Value::as_u64)
                .unwrap_or(0) as usize;
            let early_data_header_name = ws_opts
                .and_then(|o| o.get("early-data-header-name"))
                .and_then(|v| v.as_str())
                .map(std::string::ToString::to_string);
            let ws_cfg = WsConfig {
                path,
                host_header: Some(host_header),
                extra_headers: vec![],
                max_early_data,
                early_data_header_name,
            };
            let ws_layer =
                WsLayer::new(ws_cfg).map_err(|e| format!("vmess: ws layer error: {e}"))?;
            chain.push(Box::new(ws_layer));
        }
        other => {
            return Err(format!(
                "vmess: unsupported network '{other}'; valid values: tcp, ws"
            ));
        }
    }

    #[cfg_attr(not(feature = "mux"), allow(unused_mut))]
    let mut adapter = meow_proxy::VmessAdapter::new(
        name,
        server,
        port,
        uuid_bytes,
        security,
        udp,
        chain,
        Arc::clone(dialer),
    );
    #[cfg(feature = "mux")]
    if let Some(mux_options) = parse_mux_options(name, config)? {
        adapter = adapter.with_mux(mux_options);
    }
    #[cfg(not(feature = "mux"))]
    parse_mux_options(name, config)?;

    Ok(adapter)
}

pub fn parse_proxy_group(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    providers: &HashMap<String, Arc<crate::proxy_provider::ProxyProvider>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(config, existing_proxies, true, providers, None)
}

/// Variant of [`parse_proxy_group`] that wires a persistent [`meow_proxy::SelectorStore`]
/// into any `type: select` group it builds, so user picks survive restart.
pub fn parse_proxy_group_with_store(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    providers: &HashMap<String, Arc<crate::proxy_provider::ProxyProvider>>,
    store: Option<&Arc<meow_proxy::SelectorStore>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(config, existing_proxies, true, providers, store)
}

/// Lenient variant: unknown members are warned and skipped rather than
/// erroring out. Used by the multi-pass group loop on its final (stall) pass
/// so groups that reference a truly-missing proxy still build with whatever
/// members *did* resolve — matching upstream mihomo's warn-not-fail contract.
pub fn parse_proxy_group_lenient(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    providers: &HashMap<String, Arc<crate::proxy_provider::ProxyProvider>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(config, existing_proxies, false, providers, None)
}

/// Lenient variant with persistent-selector wiring; see
/// [`parse_proxy_group_with_store`].
pub fn parse_proxy_group_lenient_with_store(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    providers: &HashMap<String, Arc<crate::proxy_provider::ProxyProvider>>,
    store: Option<&Arc<meow_proxy::SelectorStore>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(config, existing_proxies, false, providers, store)
}

fn parse_proxy_group_inner(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<SmolStr, Arc<dyn Proxy>>,
    strict: bool,
    providers: &HashMap<String, Arc<crate::proxy_provider::ProxyProvider>>,
    selector_store: Option<&Arc<meow_proxy::SelectorStore>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let mut proxies: Vec<Arc<dyn Proxy>> = Vec::new();

    // include_all_proxies: add all config-defined proxies to static list
    if config.include_all_proxies.unwrap_or(false) {
        for p in existing_proxies.values() {
            proxies.push(Arc::clone(p));
        }
    }

    let proxy_names = config.proxies.as_deref().unwrap_or(&[]);
    for name in proxy_names {
        match existing_proxies.get(name.as_str()) {
            Some(proxy) => proxies.push(Arc::clone(proxy)),
            None if strict => {
                return Err(format!(
                    "group '{}' references unknown proxy '{}'",
                    config.name, name
                ));
            }
            None => {
                tracing::warn!(
                    "Proxy '{}' not found for group '{}', skipping",
                    name,
                    config.name
                );
            }
        }
    }

    // Group-level filter/exclude-filter/exclude-type (issue #358): applies to
    // provider-sourced members only, mirroring mihomo (static `proxies:`
    // members bypass it — upstream never filters compatible providers).
    let group_filter = crate::proxy_provider::GroupFilter::from_raw_group(config)
        .map_err(|e| format!("group '{}': {e}", config.name))?;
    let provider_slot = |p: &Arc<crate::proxy_provider::ProxyProvider>| match &group_filter {
        Some(f) => p.derived_slot(f),
        None => Arc::clone(&p.slot),
    };

    // Collect provider slots: include_all wires every provider; use: wires specific ones.
    let slots: Vec<meow_common::ProviderSlot> = if config.include_all.unwrap_or(false) {
        providers.values().map(&provider_slot).collect()
    } else {
        config
            .use_providers
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter_map(|pname| {
                if let Some(p) = providers.get(pname.as_str()) {
                    Some(provider_slot(p))
                } else {
                    tracing::warn!(
                        "proxy-provider '{}' not found for group '{}', skipping",
                        pname,
                        config.name
                    );
                    None
                }
            })
            .collect()
    };

    if proxies.is_empty() && slots.is_empty() {
        return Err(format!(
            "group '{}' has no valid proxies or providers",
            config.name
        ));
    }

    match config.group_type.as_str() {
        "select" => {
            let mut group = SelectorGroup::new_with_providers(&config.name, proxies, slots);
            if let Some(store) = selector_store {
                group = group.with_store(Arc::clone(store));
            }
            Ok(Arc::new(group))
        }
        "url-test" => {
            let tolerance = config.tolerance.unwrap_or(150);
            let group = UrlTestGroup::new_with_providers(&config.name, proxies, tolerance, slots)
                .with_runtime_options(
                    config
                        .url
                        .clone()
                        .unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string()),
                    config.expected_status.clone().unwrap_or_default(),
                    selector_store.cloned(),
                );
            Ok(Arc::new(group))
        }
        "fallback" => {
            let group = FallbackGroup::new_with_providers(&config.name, proxies, slots)
                .with_runtime_options(
                    config
                        .url
                        .clone()
                        .unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string()),
                    config.expected_status.clone().unwrap_or_default(),
                    selector_store.cloned(),
                );
            Ok(Arc::new(group))
        }
        "load-balance" => {
            let strategy = parse_lb_strategy(config.strategy.as_deref())?;
            Ok(Arc::new(LoadBalanceGroup::new(
                &config.name,
                proxies,
                strategy,
            )))
        }
        "relay" => parse_relay_group(&config.name, proxies, config),
        _ => Err(format!("unsupported group type: {}", config.group_type)),
    }
}

/// Parse a `type: relay` group config block into a `RelayGroup`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `proxies` is empty — upstream panics; we hard-error.
/// - `proxies` has length 1 — upstream silently acts as passthrough; we
///   hard-error with a diagnostic pointing to the correct group type.
///
/// # Warn-once (Class B per ADR-0002)
///
/// - `url` present — ignored; not meaningful for a fixed chain.
/// - `interval` present — ignored; relay has no health-check loop.
///
/// upstream: adapter/outbound/relay.go
fn parse_relay_group(
    name: &str,
    proxies: Vec<Arc<dyn Proxy>>,
    config: &crate::raw::RawProxyGroup,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    // Hard-error: empty proxies list. upstream panics. NOT panic. Class A.
    if proxies.is_empty() {
        return Err(format!(
            "relay group '{name}': proxies list is empty; \
             relay requires at least 2 proxies. \
             (upstream: panics; we reject — Class A ADR-0002)"
        ));
    }

    // Hard-error: single proxy. upstream silently acts as passthrough. Class A.
    if proxies.len() < 2 {
        return Err(format!(
            "relay group '{}': requires at least 2 proxies, got {}; \
             use `type: selector` or `type: direct` for a single proxy. \
             (upstream: silently acts as passthrough; we reject — Class A ADR-0002)",
            name,
            proxies.len()
        ));
    }

    // Warn-once for url and interval (Class B — not meaningful for relay).
    if config.url.is_some() {
        tracing::warn!(
            group = name,
            "relay: 'url' field is not used by relay groups and will be ignored. \
             (upstream: silently ignored; we warn — Class B ADR-0002)"
        );
    }
    if config.interval.is_some() {
        tracing::warn!(
            group = name,
            "relay: 'interval' field is not used by relay groups and will be ignored. \
             (upstream: silently ignored; we warn — Class B ADR-0002)"
        );
    }

    Ok(Arc::new(RelayGroup::new(name, proxies)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::rdata::AAAA;
    use hickory_proto::rr::{RData, Record, RecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use std::net::Ipv6Addr;

    fn parse_proxy(
        config: &HashMap<String, serde_yaml::Value>,
    ) -> std::result::Result<Arc<dyn Proxy>, String> {
        super::parse_proxy(config, true)
    }

    fn proxy_config(yaml: &str) -> HashMap<String, serde_yaml::Value> {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[cfg(feature = "vless")]
    #[test]
    fn lenient_base64_accepts_noncanonical_trailing_bits() {
        // The REALITY public-key from issue #301 has non-canonical base64
        // trailing bits; Go decodes it, and so must we (32-byte X25519 key).
        let key = "OKkD6Wt1lC4-9avJj2t3PkvIDkvcA1Fu0b09QwJ7GGh";
        let decoded = decode_raw_url_base64_lenient(key).expect("must decode");
        assert_eq!(decoded.len(), 32);
        // Garbage is still rejected.
        assert!(decode_raw_url_base64_lenient("!!!not base64!!!").is_none());
    }

    #[cfg(any(feature = "vless", feature = "vmess"))]
    #[test]
    fn default_alpn_follows_transport() {
        // Explicit alpn always wins.
        assert_eq!(
            default_transport_alpn("grpc", vec!["custom".to_string()]),
            vec!["custom".to_string()]
        );
        // ws → http/1.1 (CDN routing); grpc/h2 → h2 (HTTP/2 transports —
        // xray REALITY rejects clients that don't offer it, issue #377).
        assert_eq!(
            default_transport_alpn("ws", Vec::new()),
            vec!["http/1.1".to_string()]
        );
        assert_eq!(
            default_transport_alpn("grpc", Vec::new()),
            vec!["h2".to_string()]
        );
        assert_eq!(
            default_transport_alpn("h2", Vec::new()),
            vec!["h2".to_string()]
        );
        assert_eq!(
            default_transport_alpn("xhttp", Vec::new()),
            vec!["h2".to_string()]
        );
        // Plain TCP keeps ALPN absent.
        assert!(default_transport_alpn("tcp", Vec::new()).is_empty());
    }

    #[test]
    fn parse_proxy_rejects_port_overflow() {
        let cfg = proxy_config("name: bad\ntype: http\nserver: 1.2.3.4\nport: 65536\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("overflowing port must hard-error");
        };
        assert!(err.contains("exceeds 65535"), "msg: {err}");
    }

    #[test]
    fn parse_proxy_rejects_port_zero() {
        let cfg = proxy_config("name: bad\ntype: http\nserver: 1.2.3.4\nport: 0\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("zero port must hard-error");
        };
        assert!(err.contains("port must be non-zero"), "msg: {err}");
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_map() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
mode: websocket
host: example.com
tls: true
"#,
        )
        .unwrap();
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert!(result.contains("mode=websocket"));
        assert!(result.contains("host=example.com"));
        assert!(result.contains("tls=true"));
        // Verify semicolon-separated format
        assert_eq!(result.matches(';').count(), 2);
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_string_passthrough() {
        let yaml = serde_yaml::Value::String("obfs=http;obfs-host=example.com".to_string());
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert_eq!(result, "obfs=http;obfs-host=example.com");
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_none_cases() {
        // Every empty-ish YAML value must serialize to None. `empty mapping`
        // exercises the `parts.is_empty()` branch; `null` exercises the
        // catch-all arm of serialize_plugin_opts.
        let cases: [(&str, serde_yaml::Value); 2] = [
            (
                "empty mapping",
                serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            ),
            ("null", serde_yaml::Value::Null),
        ];
        for (label, yaml) in cases {
            assert!(
                serialize_plugin_opts(&yaml).is_none(),
                "{label}: expected None, got {:?}",
                serialize_plugin_opts(&yaml)
            );
        }
    }

    #[cfg(feature = "ss")]
    #[test]
    fn test_serialize_plugin_opts_number_value() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("port: 8080").unwrap();
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert_eq!(result, "port=8080");
    }

    // ─── direct proxy with per-proxy DNS (issue #67) ─────────────────────────

    fn direct_config(yaml: &str) -> HashMap<String, serde_yaml::Value> {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn parse_direct_without_dns_ok() {
        let cfg = direct_config("name: my-direct\ntype: direct\n");
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[test]
    fn parse_direct_with_single_dns_string() {
        let cfg = direct_config("name: lan\ntype: direct\ndns: 192.168.1.1\n");
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[test]
    fn parse_direct_with_dns_list_and_explicit_port() {
        let cfg = direct_config("name: lan\ntype: direct\ndns:\n  - 192.168.1.1\n  - 8.8.8.8:53\n");
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[tokio::test]
    async fn direct_dns_inherits_disabled_ipv6_policy() {
        let dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = dns.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (len, peer) = dns.recv_from(&mut buf).await.unwrap();
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let query = request.queries[0].clone();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_query(query.clone());
                if query.query_type == RecordType::AAAA {
                    response.add_answer(Record::from_rdata(
                        query.name,
                        60,
                        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                    ));
                }
                dns.send_to(&response.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        let target = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let cfg = proxy_config(&format!(
            "name: direct-v6\ntype: direct\ndns: '{dns_addr}'\n"
        ));
        let proxy = super::parse_proxy(&cfg, false).unwrap();
        let metadata = Metadata {
            host: "v6-only.example".into(),
            dst_port: target.local_addr().unwrap().port(),
            ..Default::default()
        };

        assert!(proxy.dial_tcp(&metadata).await.is_err());
    }

    #[test]
    fn parse_direct_rejects_invalid_dns_entry() {
        let cfg = direct_config("name: bad\ntype: direct\ndns: not-an-ip\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("invalid dns entry must hard-error (Class A)");
        };
        assert!(err.contains("not a valid IP or host:port"), "msg: {err}");
    }

    #[test]
    fn parse_direct_rejects_empty_dns_list() {
        let cfg = direct_config("name: bad\ntype: direct\ndns: []\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("empty dns list must hard-error (Class A)");
        };
        assert!(err.contains("dns list is empty"), "msg: {err}");
    }

    #[test]
    fn parse_direct_with_connect_timeout_wires_adapter() {
        let cfg = direct_config("name: d\ntype: direct\nconnect-timeout: 7\n");
        let adapter = parse_direct("d", &cfg, true).unwrap();
        assert_eq!(
            adapter.connect_timeout(),
            Some(std::time::Duration::from_secs(7))
        );
    }

    #[test]
    fn parse_direct_without_connect_timeout_is_unbounded() {
        let cfg = direct_config("name: d\ntype: direct\n");
        let adapter = parse_direct("d", &cfg, true).unwrap();
        assert_eq!(adapter.connect_timeout(), None);
    }

    #[test]
    fn parse_direct_rejects_non_integer_connect_timeout() {
        let cfg = direct_config("name: bad\ntype: direct\nconnect-timeout: fast\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("non-integer connect-timeout must hard-error (Class A)");
        };
        assert!(err.contains("connect-timeout"), "msg: {err}");
    }

    #[test]
    fn parse_direct_rejects_wrong_dns_type() {
        let cfg = direct_config("name: bad\ntype: direct\ndns: 53\n");
        // Integer 53 is neither a string nor a list — must be rejected.
        let Err(err) = parse_proxy(&cfg) else {
            panic!("scalar non-string dns must hard-error (Class A)");
        };
        assert!(err.contains("dns must be a string or list"), "msg: {err}");
    }

    // ─── anytls proxy parser (issue #75) ─────────────────────────────────────

    #[cfg(feature = "anytls")]
    fn anytls_config(yaml: &str) -> HashMap<String, serde_yaml::Value> {
        serde_yaml::from_str(yaml).unwrap()
    }

    // The upstream `anytls-rs` Client constructor spawns a background pool
    // reaper task synchronously, which requires a live tokio reactor. The
    // production code path always calls parse_proxy from inside the main
    // runtime, but tests have to opt in explicitly with #[tokio::test].

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_minimum_fields_ok() {
        let cfg =
            anytls_config("name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 443\npassword: secret\n");
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_with_sni_and_skip_verify_ok() {
        let cfg = anytls_config(
            "name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 443\npassword: secret\nsni: example.com\nskip-cert-verify: true\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    /// mihomo's `AnyTLSOption.UDP` is `omitempty`/false by default; only an
    /// explicit `udp: true` advertises datagram support to the tunnel.
    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_udp_is_opt_in() {
        let off =
            anytls_config("name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 443\npassword: secret\n");
        assert!(!parse_proxy(&off).unwrap().support_udp());

        let on = anytls_config(
            "name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 443\npassword: secret\nudp: true\n",
        );
        assert!(parse_proxy(&on).unwrap().support_udp());
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_rejects_missing_password() {
        let cfg = anytls_config("name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 443\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("missing password must hard-error (Class A)");
        };
        assert!(err.contains("missing password"), "msg: {err}");
    }

    #[cfg(feature = "anytls")]
    #[tokio::test]
    async fn parse_anytls_rejects_zero_port() {
        let cfg =
            anytls_config("name: jp\ntype: anytls\nserver: 1.2.3.4\nport: 0\npassword: secret\n");
        let Err(err) = parse_proxy(&cfg) else {
            panic!("zero port must hard-error (Class A)");
        };
        assert!(err.contains("port must be non-zero"), "msg: {err}");
    }

    // ─── hysteria2 parser ────────────────────────────────────────────────────

    #[cfg(feature = "hysteria2")]
    fn hy2_config(yaml: &str) -> HashMap<String, serde_yaml::Value> {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_minimum_fields_ok() {
        let cfg = hy2_config(
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 443\npassword: secret\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_rejects_invalid_configs() {
        // (label, yaml, expected error substring)
        let cases: &[(&str, &str, &str)] = &[
            (
                "missing password",
                "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 443\n",
                "missing password",
            ),
            (
                "zero port without ports",
                "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 0\npassword: secret\n",
                "port must be non-zero",
            ),
            (
                "missing both port and ports",
                "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\npassword: secret\n",
                "missing port",
            ),
            (
                "wildcard ports without port",
                "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nports: '*'\npassword: secret\n",
                "missing port",
            ),
            (
                "empty password",
                "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 443\npassword: ''\n",
                "password must not be empty",
            ),
            (
                "gecko obfs (mihomo divergence: unsupported)",
                "name: jp-hy2\n\
                 type: hysteria2\n\
                 server: 1.2.3.4\n\
                 port: 443\n\
                 password: secret\n\
                 obfs: gecko\n\
                 obfs-password: secret\n",
                "gecko",
            ),
            (
                "obfs without obfs-password",
                "name: jp-hy2\n\
                 type: hysteria2\n\
                 server: 1.2.3.4\n\
                 port: 443\n\
                 password: secret\n\
                 obfs: salamander\n",
                "missing obfs-password",
            ),
            (
                "mTLS client certificate (mihomo divergence: unsupported)",
                "name: jp-hy2\n\
                 type: hysteria2\n\
                 server: 1.2.3.4\n\
                 port: 443\n\
                 password: secret\n\
                 certificate: ./client.crt\n",
                "certificate",
            ),
        ];

        // Collect every failure instead of asserting inline so one bad row does
        // not mask the rest of the table.
        let mut failures: Vec<String> = Vec::new();
        for &(label, yaml, expected) in cases {
            match parse_proxy(&hy2_config(yaml)) {
                Ok(_) => failures.push(format!("[{label}] must hard-error (Class A), got Ok")),
                Err(err) if !err.contains(expected) => {
                    failures.push(format!(
                        "[{label}] error must contain {expected:?}, got: {err}"
                    ));
                }
                Err(_) => {}
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_accepts_ports_without_port() {
        // Airport subscriptions commonly set only a hopping range (issue #377);
        // mihomo accepts this, so we do too — first concrete port dials.
        let cfg = hy2_config(
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nports: 20000-30000\npassword: secret\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_accepts_zero_port_with_ports() {
        let cfg = hy2_config(
            "name: jp-hy2\ntype: hysteria2\nserver: 1.2.3.4\nport: 0\nports: '443,8443'\npassword: secret\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_accepts_mihomo_common_fields() {
        let cfg = hy2_config(
            "name: jp-hy2\n\
             type: hysteria2\n\
             server: 1.2.3.4\n\
             port: 443\n\
             password: secret\n\
             udp: true\n\
             up: '30 Mbps'\n\
             down: 100\n\
             obfs: salamander\n\
             obfs-password: obfs-secret\n\
             ports: '443,8443-8444'\n\
             hop-interval: '15-30'\n\
             sni: example.com\n\
             skip-cert-verify: true\n\
             fingerprint: 'SHA256 Fingerprint=00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00'\n\
             alpn:\n\
               - h3\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_bandwidth_matches_mihomo_units() {
        assert_eq!(parse_hy2_bandwidth("8 Mbps").unwrap(), 1_000_000);
        assert_eq!(parse_hy2_bandwidth("8 MBps").unwrap(), 8_000_000);
        assert_eq!(parse_hy2_bandwidth("10").unwrap(), 1_250_000);
        assert_eq!(parse_hy2_bandwidth("").unwrap(), 0);
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn parse_hysteria2_hop_interval_matches_mihomo_floor() {
        assert_eq!(parse_hy2_hop_interval("hy2", None).unwrap(), None);
        assert_eq!(
            parse_hy2_hop_interval("hy2", Some(&serde_yaml::Value::from(0))).unwrap(),
            Some((30, 30))
        );
        assert_eq!(
            parse_hy2_hop_interval("hy2", Some(&serde_yaml::Value::from("1-2"))).unwrap(),
            Some((5, 5))
        );
    }

    // ─── Load-balance strategy parser (F1-F7) ────────────────────────────────

    #[test]
    fn parse_load_balance_default_strategy() {
        // No `strategy:` field → round-robin selected.
        let s = parse_lb_strategy(None).unwrap();
        assert!(matches!(s, LbStrategy::RoundRobin));
    }

    #[test]
    fn parse_load_balance_explicit_round_robin() {
        let s = parse_lb_strategy(Some("round-robin")).unwrap();
        assert!(matches!(s, LbStrategy::RoundRobin));
    }

    #[test]
    fn parse_load_balance_consistent_hashing() {
        let s = parse_lb_strategy(Some("consistent-hashing")).unwrap();
        assert!(matches!(s, LbStrategy::ConsistentHashing));
    }

    #[test]
    fn parse_load_balance_unknown_strategy_hard_errors() {
        // upstream: falls back silently to round-robin.
        // NOT silent fallback. ADR-0002 Class A.
        let err = parse_lb_strategy(Some("sticky")).unwrap_err();
        assert!(
            err.contains("unknown strategy"),
            "error should mention unknown strategy: {err}"
        );
        assert!(
            err.contains("Class A"),
            "error should cite ADR-0002 Class A: {err}"
        );
    }

    #[test]
    fn parse_load_balance_case_insensitive_strategy() {
        // Mixed-case is an unknown value → hard error (consistent with Class A policy).
        // Do not panic.
        let err = parse_lb_strategy(Some("Round-Robin")).unwrap_err();
        assert!(!err.is_empty());
        let err2 = parse_lb_strategy(Some("ROUND-ROBIN")).unwrap_err();
        assert!(!err2.is_empty());
    }

    // ─── Relay parser tests (B1-B5) ─────────────────────────────────────────

    fn make_direct_proxy(_name: &str) -> Arc<dyn Proxy> {
        use meow_proxy::DirectAdapter;
        Arc::new(WrappedProxy::new(Box::new(DirectAdapter::new())))
    }

    fn relay_config(name: &str, proxies: Vec<String>) -> crate::raw::RawProxyGroup {
        crate::raw::RawProxyGroup {
            name: name.to_string(),
            group_type: "relay".to_string(),
            proxies: Some(proxies),
            ..Default::default()
        }
    }

    // B1: single-proxy relay → hard error containing "at least 2"
    // upstream: silently acts as passthrough. NOT passthrough. ADR-0002 Class A.
    #[test]
    fn relay_single_proxy_hard_errors_at_parse() {
        let existing = {
            let mut m = std::collections::HashMap::new();
            m.insert(SmolStr::new_static("DIRECT"), make_direct_proxy("DIRECT"));
            m
        };
        let config = relay_config("r", vec!["DIRECT".to_string()]);
        let err = parse_proxy_group(&config, &existing, &Default::default())
            .err()
            .expect("single-proxy relay must error");
        assert!(
            err.contains("at least 2"),
            "error must mention 'at least 2'; got: {err}"
        );
    }

    // B2: empty proxies list → hard error (NOT parse_proxy_group_inner's generic
    // "no valid proxies" error — relay fires before that path is reached when the
    // YAML list itself is empty/missing).
    // upstream: panics. NOT panic. ADR-0002 Class A.
    #[test]
    fn relay_empty_proxies_hard_errors_at_parse() {
        // Empty existing proxies + empty config proxies list.
        let existing = std::collections::HashMap::new();
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec![]),
            ..Default::default()
        };
        // parse_proxy_group_inner will return "no valid proxies" before reaching
        // relay-specific check (0 proxies ≠ relay-specific error, but still errors).
        // Both paths must return Err.
        assert!(parse_proxy_group(&config, &existing, &Default::default()).is_err());
    }

    // B3: url field on relay group → warn (NOT error)
    // Class B per ADR-0002. We can't easily assert on tracing::warn output in unit
    // tests without a subscriber, so we assert the group parses successfully.
    #[test]
    fn relay_url_field_warns_not_errors() {
        let existing = {
            let mut m = std::collections::HashMap::new();
            m.insert(SmolStr::new_static("DIRECT"), make_direct_proxy("DIRECT"));
            m.insert(SmolStr::new_static("REJECT"), make_direct_proxy("REJECT"));
            m
        };
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            url: Some("https://example.com/test".to_string()),
            ..Default::default()
        };
        // Must NOT error — url is warn-only (Class B).
        parse_proxy_group(&config, &existing, &Default::default())
            .expect("relay with url must not hard-error");
    }

    // B4: interval field on relay group → warn (NOT error)
    #[test]
    fn relay_interval_field_warns_not_errors() {
        let existing = {
            let mut m = std::collections::HashMap::new();
            m.insert(SmolStr::new_static("DIRECT"), make_direct_proxy("DIRECT"));
            m.insert(SmolStr::new_static("REJECT"), make_direct_proxy("REJECT"));
            m
        };
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            interval: Some(300),
            ..Default::default()
        };
        parse_proxy_group(&config, &existing, &Default::default())
            .expect("relay with interval must not hard-error");
    }

    // B5: both url and interval present → two separate warns, still not an error
    #[test]
    fn relay_url_and_interval_warn_not_errors() {
        let existing = {
            let mut m = std::collections::HashMap::new();
            m.insert(SmolStr::new_static("DIRECT"), make_direct_proxy("DIRECT"));
            m.insert(SmolStr::new_static("REJECT"), make_direct_proxy("REJECT"));
            m
        };
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            url: Some("https://example.com/test".to_string()),
            interval: Some(300),
            ..Default::default()
        };
        parse_proxy_group(&config, &existing, &Default::default())
            .expect("relay with url+interval must not hard-error");
    }

    // ─── group-level filter on provider members (issue #358) ────────────────

    #[cfg(feature = "ss")]
    async fn file_provider_with(
        path: &std::path::Path,
        entries: &str,
    ) -> HashMap<String, Arc<crate::proxy_provider::ProxyProvider>> {
        std::fs::write(path, entries).unwrap();
        let raw = crate::raw::RawProxyProvider {
            provider_type: "file".to_string(),
            url: None,
            path: Some(path.to_str().unwrap().to_string()),
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            header: None,
        };
        let cache_dir = path.parent().expect("temp file has a parent dir");
        let provider =
            crate::proxy_provider::ProxyProvider::new("airport", &raw, Some(cache_dir), true)
                .unwrap();
        provider.refresh().await.unwrap();
        let mut providers = HashMap::new();
        providers.insert("airport".to_string(), Arc::new(provider));
        providers
    }

    #[cfg(feature = "ss")]
    const PROVIDER_YAML: &str = "proxies:\n\
        - {name: \"US 1\", type: ss, server: 127.0.0.1, port: 443, cipher: aes-128-gcm, password: p}\n\
        - {name: \"US 2 expat\", type: ss, server: 127.0.0.1, port: 443, cipher: aes-128-gcm, password: p}\n\
        - {name: \"HK 1\", type: ss, server: 127.0.0.1, port: 443, cipher: aes-128-gcm, password: p}\n";

    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn group_filter_applies_to_provider_members() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "US".to_string(),
            group_type: "url-test".to_string(),
            use_providers: Some(vec!["airport".to_string()]),
            filter: Some("(?i)^us".to_string()),
            exclude_filter: Some("expat".to_string()),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &providers).unwrap();
        assert_eq!(group.members().unwrap(), ["US 1"]);
    }

    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn group_without_filter_sees_all_provider_members() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "ALL".to_string(),
            group_type: "select".to_string(),
            use_providers: Some(vec!["airport".to_string()]),
            ..Default::default()
        };
        let group = parse_proxy_group(&config, &HashMap::new(), &providers).unwrap();
        assert_eq!(group.members().unwrap(), ["US 1", "US 2 expat", "HK 1"]);
    }

    #[cfg(feature = "ss")]
    #[tokio::test]
    async fn group_filter_invalid_regex_errors_with_group_name() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let providers = file_provider_with(tmp.path(), PROVIDER_YAML).await;

        let config = crate::raw::RawProxyGroup {
            name: "US".to_string(),
            group_type: "select".to_string(),
            use_providers: Some(vec!["airport".to_string()]),
            filter: Some("(".to_string()),
            ..Default::default()
        };
        let err = parse_proxy_group(&config, &HashMap::new(), &providers)
            .err()
            .expect("invalid filter regex must error");
        assert!(
            err.contains("group 'US'") && err.contains("filter regex error"),
            "unexpected error: {err}"
        );
    }

    // ─── snell proxy parser ───────────────────────────────────────────────────

    #[cfg(feature = "snell")]
    fn snell_config(yaml: &str) -> HashMap<String, serde_yaml::Value> {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_minimal_ok() {
        let cfg = snell_config("name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: secret\n");
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_full_ok() {
        let cfg = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: secret\nversion: 5\nudp: true\nreuse: true\nobfs-opts:\n  mode: http\n  host: bing.com\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_rejects_invalid_fields() {
        // (label, yaml, expected error substring). Every row is a Class A hard
        // error: a required field is missing or invalid, and parsing must fail
        // with a message naming that field.
        let cases: &[(&str, &str, &str)] = &[
            (
                "missing psk",
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\n",
                "missing psk",
            ),
            (
                "missing server",
                "name: sn\ntype: snell\nport: 8388\npsk: secret\n",
                "missing server",
            ),
            (
                "missing port",
                "name: sn\ntype: snell\nserver: 1.2.3.4\npsk: secret\n",
                "missing port",
            ),
            (
                "port zero",
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 0\npsk: secret\n",
                "port must be non-zero",
            ),
            (
                "empty psk (caught by SnellAdapter::new)",
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: ''\n",
                "psk must not be empty",
            ),
        ];

        // Collect every failure instead of asserting inline so one bad row does
        // not mask the rest of the table.
        let mut failures: Vec<String> = Vec::new();
        for &(label, yaml, expected) in cases {
            match parse_proxy(&snell_config(yaml)) {
                Ok(_) => failures.push(format!("[{label}] must hard-error (Class A), got Ok")),
                Err(err) if !err.contains(expected) => {
                    failures.push(format!(
                        "[{label}] error must contain {expected:?}, got: {err}"
                    ));
                }
                Err(_) => {}
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_version_aliases() {
        for yaml in &[
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 3\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: v3\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 4\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: v4\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: V5\n",
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 5\n",
        ] {
            let cfg = snell_config(yaml);
            assert!(parse_proxy(&cfg).is_ok(), "expected Ok for yaml: {yaml}");
        }
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_rejects_unsupported_legacy_versions() {
        for (yaml, ver) in &[
            (
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 1\n",
                "1",
            ),
            (
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: 2\n",
                "2",
            ),
            (
                "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: v2\n",
                "v2",
            ),
        ] {
            let cfg = snell_config(yaml);
            let Err(err) = parse_proxy(&cfg) else {
                panic!("unsupported legacy version {ver} must hard-error (Class A)");
            };
            assert!(
                err.contains("not supported"),
                "version {ver}: expected 'not supported' in msg: {err}"
            );
        }
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_rejects_unknown_version() {
        let cfg_six = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: '6'\n",
        );
        let Err(err) = parse_proxy(&cfg_six) else {
            panic!("unknown version '6' must hard-error (Class A)");
        };
        assert!(err.contains("unknown version"), "msg: {err}");

        let cfg_bool = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nversion: true\n",
        );
        let Err(err) = parse_proxy(&cfg_bool) else {
            panic!("boolean version must hard-error (Class A)");
        };
        assert!(err.contains("must be an integer or string"), "msg: {err}");
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_obfs_modes() {
        let cfg_tls = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nobfs-opts:\n  mode: tls\n",
        );
        assert!(parse_proxy(&cfg_tls).is_ok(), "tls obfs mode must be Ok");

        let cfg_none = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nobfs-opts:\n  mode: none\n",
        );
        assert!(parse_proxy(&cfg_none).is_ok(), "none obfs mode must be Ok");

        let cfg_socks = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nobfs-opts:\n  mode: socks\n",
        );
        let Err(err) = parse_proxy(&cfg_socks) else {
            panic!("invalid obfs mode 'socks' must hard-error (Class A)");
        };
        assert!(err.contains("obfs-opts.mode"), "msg: {err}");
    }

    #[cfg(feature = "snell")]
    #[test]
    fn parse_snell_obfs_host_falls_back_to_server() {
        // obfs-opts with mode: http but no host key → falls back to server value.
        let cfg = snell_config(
            "name: sn\ntype: snell\nserver: 1.2.3.4\nport: 8388\npsk: s\nobfs-opts:\n  mode: http\n",
        );
        assert!(parse_proxy(&cfg).is_ok());
    }
}
