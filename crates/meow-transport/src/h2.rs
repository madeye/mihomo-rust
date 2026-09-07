//! Plain HTTP/2 transport layer (`h2` feature).
//!
//! Unlike the gRPC (gun) layer, this layer tunnels raw bytes over an HTTP/2
//! POST request body without any additional framing.  The `:authority`
//! pseudo-header is chosen uniformly at random from `H2Config::hosts` on every
//! `connect()` call, matching upstream `transport/vmess/h2.go`.
//!
//! upstream: transport/vmess/h2.go

use std::time::Duration;

use async_trait::async_trait;
use rand::seq::IndexedRandom as _;

use crate::h2_common::{H2Stream, RecvState};
use crate::{Result, Stream, Transport, TransportError};

/// Timeout for acquiring send readiness (h2 `poll_ready`) during `connect`.
/// Nothing upstream bounds the dial (`Tunnel::dial_tcp` and the transport
/// chain carry no timeout), so without this a peer whose
/// `SETTINGS_MAX_CONCURRENT_STREAMS` is exhausted — or that simply never
/// settles — could park `connect` forever.  Mirrors h2mux's `OPEN_TIMEOUT`
/// (5 s), which guards the same `ready()` call on the mux path.
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

// ─── Public types ─────────────────────────────────────────────────────────────

/// Configuration for the plain HTTP/2 transport layer.
///
/// upstream: `h2-opts` YAML key block.
#[derive(Debug, Clone)]
pub struct H2Config {
    /// The `:path` pseudo-header sent with every request.
    ///
    /// upstream: `h2-opts.path`; default `"/"`.
    pub path: String,

    /// Candidate `:authority` values.  One is chosen uniformly at random per
    /// connection.
    ///
    /// upstream: `h2-opts.host` (a list).  Must be non-empty; `meow-config`
    /// rejects an empty list at parse time (Class A divergence, hard error).
    pub hosts: Vec<String>,
}
impl Default for H2Config {
    fn default() -> Self {
        Self {
            path: "/".into(),
            hosts: vec!["localhost".into()],
        }
    }
}

// ─── H2Layer ──────────────────────────────────────────────────────────────────

/// Transport layer that wraps an inner stream with a plain HTTP/2 tunnel.
///
/// One HTTP/2 POST request is opened per `connect()` call.  The request body
/// is the outbound data stream; the 200 response body is the inbound stream.
/// No gun/gRPC framing is applied — bytes pass through verbatim.
pub struct H2Layer {
    config: H2Config,
}

impl H2Layer {
    /// Create an `H2Layer` from the given configuration.
    ///
    pub fn new(config: H2Config) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for H2Layer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        // Uniform random host selection per connection.
        // upstream: transport/vmess/h2.go — `cfg.Hosts[randv2.IntN(len(cfg.Hosts))]`
        let Some(host) = self.config.hosts.choose(&mut rand::rng()) else {
            return Err(TransportError::Config("h2: hosts must not be empty".into()));
        };

        // Build and validate the request before opening the h2 connection.
        // Invalid config should fail deterministically instead of depending on
        // whether a peer is available to complete the h2 handshake.
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://{}{}", host, self.config.path))
            .body(())
            .map_err(|e| TransportError::Config(format!("h2: invalid request config: {e}")))?;

        // HTTP/2 client handshake over the inner stream.
        let (mut h2, conn) = h2::client::handshake(inner)
            .await
            .map_err(|e| TransportError::H2(e.to_string()))?;

        // Drive the h2 connection (SETTINGS, WINDOW_UPDATE, PING, …) in a
        // background task so control frames keep flowing while we stream data.
        let driver_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let abort_handle = driver_task.abort_handle();

        // h2 requires poll_ready/ready before send_request: sending
        // without readiness is rejected once MAX_CONCURRENT_STREAMS is
        // exhausted.  Bounded by OPEN_TIMEOUT — see its doc.
        h2 = match tokio::time::timeout(OPEN_TIMEOUT, h2.ready()).await {
            Ok(Ok(ready_h2)) => ready_h2,
            Ok(Err(e)) => {
                abort_handle.abort();
                return Err(TransportError::H2(e.to_string()));
            }
            Err(_) => {
                abort_handle.abort();
                return Err(TransportError::H2(
                    "timed out waiting for send readiness (open)".into(),
                ));
            }
        };

        // Open the h2 stream; `end_of_stream = false` — we will stream data.
        let (response_future, send_stream) = match h2.send_request(request, false) {
            Ok(parts) => parts,
            Err(e) => {
                abort_handle.abort();
                return Err(TransportError::H2(e.to_string()));
            }
        };

        // Do NOT await the response here: upstream's h2 handler reads the
        // client's first DATA frame before it writes anything, so awaiting
        // would deadlock the tunnel (issue #377). The response is resolved on
        // the first read instead — see `h2_common::RecvState`.
        Ok(Box::new(
            H2Stream::new(send_stream, RecvState::new(response_future))
                .with_conn_driver(driver_task),
        ))
    }
}
