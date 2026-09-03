//! XHTTP (SplitHTTP) transport layer (`xhttp` feature).
//!
//! Tunnels bidirectional streams over HTTP/2 using the Xray-core / mihomo
//! `splithttp` (XHTTP) protocol in `stream-one` mode.
//!
//! upstream: transport/internet/splithttp/dialer.go

use std::time::Duration;

use async_trait::async_trait;
use rand::seq::IndexedRandom as _;
use rand::Rng as _;

use crate::h2_common::{H2Stream, RecvState};
use crate::{Result, Stream, Transport, TransportError};

/// Timeout for acquiring send readiness (`h2.ready()`) during `connect`.
/// Mirrors H2Layer and h2mux's `OPEN_TIMEOUT` (5 s).
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

// ─── Public types ─────────────────────────────────────────────────────────────

/// Configuration for the XHTTP transport layer.
///
/// upstream: `xhttp-opts` YAML key block.
#[derive(Debug, Clone)]
pub struct XhttpConfig {
    /// The `:path` pseudo-header sent with every request.
    ///
    /// upstream: `xhttp-opts.path`; default `"/"`.
    pub path: String,

    /// Candidate `:authority` values. One is chosen uniformly at random per
    /// connection. If empty or absent, falls back to the dial host.
    ///
    /// upstream: `xhttp-opts.host`.
    pub hosts: Vec<String>,

    /// Extra custom HTTP headers sent with the request.
    ///
    /// upstream: `xhttp-opts.headers`.
    pub extra_headers: Vec<(String, String)>,

    /// XHTTP mode. Only `"stream-one"` (default) and `"auto"` (which resolves
    /// to `stream-one` for full-duplex HTTP/2) are supported.
    ///
    /// upstream: `xhttp-opts.mode`.
    pub mode: String,

    /// If true, suppress setting the `Content-Type: application/grpc` header.
    /// Default is `false` (the header is set by default per Xray-core spec).
    ///
    /// upstream: `xhttp-opts.no-grpc-header`.
    pub no_grpc_header: bool,

    /// Range for random padding bytes `(min, max)`.
    /// When set and `max > 0`, a random padding string of length between `min`
    /// and `max` is generated and sent in the `Referer` header as
    /// `<request_uri>?x_padding=<padding>`.
    ///
    /// upstream: `xhttp-opts.x-padding-bytes`; default `Some((100, 1000))`.
    pub x_padding_bytes: Option<(usize, usize)>,
}

impl Default for XhttpConfig {
    fn default() -> Self {
        Self {
            path: "/".into(),
            hosts: vec!["localhost".into()],
            extra_headers: Vec::new(),
            mode: "stream-one".into(),
            no_grpc_header: false,
            x_padding_bytes: Some((100, 1000)),
        }
    }
}

// ─── XhttpLayer ───────────────────────────────────────────────────────────────

/// Transport layer that wraps an inner stream with an XHTTP tunnel.
pub struct XhttpLayer {
    config: XhttpConfig,
}

impl XhttpLayer {
    /// Create an `XhttpLayer` from the given configuration.
    pub fn new(config: XhttpConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for XhttpLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        validate_config(&self.config)?;

        let host = self
            .config
            .hosts
            .choose(&mut rand::rng())
            .cloned()
            .unwrap_or_else(|| "localhost".to_string());

        let mut request_builder = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://{}{}", host, self.config.path));

        // Add Content-Type: application/grpc if not disabled and not already present.
        let has_content_type = self
            .config
            .extra_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
        if !self.config.no_grpc_header && !has_content_type {
            request_builder = request_builder.header("content-type", "application/grpc");
        }

        // Add extra custom headers.
        let has_referer = self
            .config
            .extra_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("referer"));
        for (k, v) in &self.config.extra_headers {
            request_builder = request_builder.header(k.as_str(), v.as_str());
        }

        // Add X-Padding via Referer header if enabled and not already provided.
        if !has_referer {
            if let Some((min, max)) = self.config.x_padding_bytes {
                if max > 0 {
                    let pad_len = if min >= max {
                        min
                    } else {
                        rand::rng().random_range(min..=max)
                    };
                    if pad_len > 0 {
                        let padding = "X".repeat(pad_len);
                        let separator = if self.config.path.contains('?') {
                            '&'
                        } else {
                            '?'
                        };
                        let referer = format!(
                            "https://{}{}{separator}x_padding={padding}",
                            host, self.config.path
                        );
                        request_builder = request_builder.header("referer", referer);
                    }
                }
            }
        }

        let request = request_builder
            .body(())
            .map_err(|e| TransportError::Config(format!("xhttp: invalid request config: {e}")))?;

        // HTTP/2 client handshake over the inner stream.
        let (mut h2, conn) = h2::client::handshake(inner)
            .await
            .map_err(|e| TransportError::Xhttp(e.to_string()))?;

        // Drive the h2 connection in a background task so control frames keep flowing.
        let driver_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let abort_handle = driver_task.abort_handle();

        // Wait for send readiness bounded by OPEN_TIMEOUT.
        h2 = match tokio::time::timeout(OPEN_TIMEOUT, h2.ready()).await {
            Ok(Ok(ready_h2)) => ready_h2,
            Ok(Err(e)) => {
                abort_handle.abort();
                return Err(TransportError::Xhttp(e.to_string()));
            }
            Err(_) => {
                abort_handle.abort();
                return Err(TransportError::Xhttp(
                    "timed out waiting for send readiness (open)".into(),
                ));
            }
        };

        // Open the h2 stream; `end_of_stream = false` — we stream bidirectional data.
        let (response_future, send_stream) = match h2.send_request(request, false) {
            Ok(parts) => parts,
            Err(e) => {
                abort_handle.abort();
                return Err(TransportError::Xhttp(e.to_string()));
            }
        };

        // Do NOT await the response here: upstream's handler reads the
        // client's first DATA frame before it writes response headers.
        // The response is resolved lazily on the first read via RecvState.
        Ok(Box::new(
            H2Stream::new(
                send_stream,
                RecvState::with_timeout(
                    response_future,
                    Duration::from_secs(15),
                    crate::h2_common::StatusPolicy::Success,
                    "xhttp",
                ),
            )
            .with_conn_abort(abort_handle),
        ))
    }
}

// ─── Validation Helpers ───────────────────────────────────────────────────────

fn validate_config(config: &XhttpConfig) -> Result<()> {
    validate_path(&config.path)?;
    if config.hosts.is_empty() {
        return Err(TransportError::Config(
            "xhttp: hosts must not be empty".into(),
        ));
    }
    for host in &config.hosts {
        validate_host(host)?;
    }
    for (name, value) in &config.extra_headers {
        validate_header_name(name)?;
        validate_header_value(name, value)?;
    }
    if !config.mode.is_empty()
        && !config.mode.eq_ignore_ascii_case("auto")
        && !config.mode.eq_ignore_ascii_case("stream-one")
    {
        return Err(TransportError::Config(format!(
            "xhttp: unsupported mode {:?}; only 'stream-one' and 'auto' are supported",
            config.mode
        )));
    }
    if let Some((min, max)) = config.x_padding_bytes {
        if min > max {
            return Err(TransportError::Config(format!(
                "xhttp: invalid x_padding_bytes: min ({min}) cannot exceed max ({max})"
            )));
        }
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        return Err(TransportError::Config(
            "xhttp: path must start with '/'".into(),
        ));
    }
    if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(TransportError::Config(
            "xhttp: path contains whitespace or control bytes".into(),
        ));
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() || host.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(TransportError::Config(
            "xhttp: host contains whitespace or control bytes".into(),
        ));
    }
    Ok(())
}

fn validate_header_name(name: &str) -> Result<()> {
    if name.is_empty() || !name.bytes().all(is_header_token_byte) {
        return Err(TransportError::Config(format!(
            "xhttp: invalid extra header name {name:?}"
        )));
    }
    Ok(())
}

fn validate_header_value(name: &str, value: &str) -> Result<()> {
    if value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(TransportError::Config(format!(
            "xhttp: invalid value for extra header {name:?}"
        )));
    }
    Ok(())
}

fn is_header_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_valid() {
        let config = XhttpConfig::default();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn invalid_path() {
        let config = XhttpConfig {
            path: "no_slash".into(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());

        let config = XhttpConfig {
            path: "/has space".into(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn empty_hosts_rejected() {
        let config = XhttpConfig {
            hosts: vec![],
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn invalid_mode() {
        let config = XhttpConfig {
            mode: "packet-up".into(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());

        let config = XhttpConfig {
            mode: "auto".into(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_ok());

        let config = XhttpConfig {
            mode: "".into(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_ok());

        let config = XhttpConfig {
            mode: "stream-one".into(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn invalid_padding_range() {
        let config = XhttpConfig {
            x_padding_bytes: Some((500, 100)),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());

        let config = XhttpConfig {
            x_padding_bytes: Some((100, 500)),
            ..Default::default()
        };
        assert!(validate_config(&config).is_ok());
    }
    #[test]
    fn invalid_headers() {
        let mut config = XhttpConfig::default();
        config.extra_headers.push(("Bad:Name".into(), "val".into()));
        assert!(validate_config(&config).is_err());

        config.extra_headers.clear();
        config
            .extra_headers
            .push(("Good-Name".into(), "val\r\nbad".into()));
        assert!(validate_config(&config).is_err());

        config.extra_headers.clear();
        config
            .extra_headers
            .push(("Good-Name".into(), "good-value".into()));
        assert!(validate_config(&config).is_ok());
    }
}
