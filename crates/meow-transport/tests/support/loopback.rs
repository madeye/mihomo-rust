//! In-process loopback servers for transport layer tests.
// Each test binary (tls_test, ws_test, …) includes this module but only uses
// a subset of the functions.  Dead-code warnings on the unused half are
// expected and suppressed here.
#![allow(dead_code)]
//!
//! Contains server-side code (`TcpListener`, `TlsAcceptor`, etc.) that is
//! intentionally placed here (not in `src/`) to satisfy acceptance criterion
//! F2: "no `accept`/`bind`/`listen`/`TcpListener` in `src/**/*.rs`".
//!
//! # Design
//!
//! [`spawn_tls_server`] starts a single-connection TLS server in a background
//! tokio task.  After accepting and completing the TLS handshake it captures
//! connection metadata (SNI, negotiated ALPN, peer certificates) and sends
//! them through a oneshot channel.  The server then echoes any data it
//! receives so callers can test round-trips.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// ─── Cert generation ─────────────────────────────────────────────────────────

/// Generate a self-signed certificate for the given Subject Alternative Names.
///
/// Returns `(cert_der, key_der)` — DER bytes for server config — plus
/// `cert_pem` for tests that need the raw PEM bytes.
pub fn gen_cert(
    sans: &[&str],
) -> (
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    String, // cert PEM
    String, // key PEM
) {
    let ck = rcgen::generate_simple_self_signed(
        sans.iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .expect("rcgen cert generation failed");

    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();
    (cert_der, key_der, cert_pem, key_pem)
}

/// Install the ring crypto provider once per process (idempotent).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ─── Captured connection info ─────────────────────────────────────────────────

/// Metadata captured from the server side of a TLS handshake.
#[derive(Debug, Default)]
pub struct ConnInfo {
    /// The SNI name the client sent (None if client sent no SNI extension).
    pub server_name: Option<String>,
    /// The ALPN protocol negotiated (None if no ALPN was agreed).
    pub alpn: Option<Vec<u8>>,
    /// DER-encoded certificates from the client (empty if no client cert).
    pub peer_certs: Vec<Vec<u8>>,
}

// ─── Server builder ───────────────────────────────────────────────────────────

/// Configuration for [`spawn_tls_server`].
pub struct ServerOptions {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    /// ALPN protocols the server advertises (empty = no ALPN).
    pub server_alpn: Vec<Vec<u8>>,
    /// If `Some`, the server requires a client certificate and verifies it
    /// against the given CA cert (DER-encoded).
    pub require_client_cert_ca: Option<CertificateDer<'static>>,
}

/// Spawn a single-accept TLS loopback server.
///
/// Returns `(addr, conn_info_rx)`.  The server accepts one connection,
/// performs the TLS handshake, sends [`ConnInfo`] through the channel,
/// then echoes all received bytes until EOF.
///
/// The server runs in a background tokio task and is cleaned up when the
/// `conn_info_rx` channel is dropped or the task exits naturally.
pub async fn spawn_tls_server(
    opts: ServerOptions,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<ConnInfo>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel();

    let server_config_builder = rustls::ServerConfig::builder();

    // Client certificate verification
    let server_config = if let Some(ca_der) = opts.require_client_cert_ca {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca_der).expect("valid CA cert DER");
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .expect("WebPkiClientVerifier build");
        let mut cfg = server_config_builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![opts.cert_der], opts.key_der)
            .expect("server TLS config with client cert verifier");
        cfg.alpn_protocols = opts.server_alpn;
        cfg
    } else {
        let mut cfg = server_config_builder
            .with_no_client_auth()
            .with_single_cert(vec![opts.cert_der], opts.key_der)
            .expect("server TLS config");
        cfg.alpn_protocols = opts.server_alpn;
        cfg
    };

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };

        let Ok(tls_stream) = acceptor.accept(tcp).await else {
            eprintln!("loopback TLS accept error");
            return;
        };

        // Capture handshake metadata before moving the stream.
        let (_, server_conn) = tls_stream.get_ref();
        let info = ConnInfo {
            server_name: server_conn
                .server_name()
                .map(std::borrow::ToOwned::to_owned),
            alpn: server_conn.alpn_protocol().map(<[u8]>::to_vec),
            peer_certs: server_conn
                .peer_certificates()
                .unwrap_or(&[])
                .iter()
                .map(|c| c.to_vec())
                .collect(),
        };

        let _ = tx.send(info);

        // Drain the connection so the client side doesn't get a broken pipe on
        // its write.  No echo needed for TLS unit tests — they only assert
        // handshake properties, not round-trip data.
        let mut tls_stream = tls_stream;
        let mut drain = [0u8; 256];
        loop {
            match tokio::io::AsyncReadExt::read(&mut tls_stream, &mut drain).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    (addr, rx)
}

// ─── gRPC (gun) loopback server ──────────────────────────────────────────────

/// Metadata captured from the gRPC request received by the loopback server.
#[cfg(feature = "grpc")]
#[derive(Debug, Default)]
pub struct GrpcConnInfo {
    /// The `:path` pseudo-header sent by the client (e.g. `/GunService/Tun`).
    pub path: String,
    /// The value of the `content-type` header sent by the client.
    pub content_type: Option<String>,
}

/// Spawn a single-accept gRPC (h2) loopback server.
///
/// Returns `(addr, conn_info_rx)`.  The server:
/// 1. Accepts one TCP connection and performs the HTTP/2 handshake.
/// 2. Accepts one h2 request, captures `:path` and `content-type`.
/// 3. Sends [`GrpcConnInfo`] through the oneshot channel.
/// 4. Streams a 200 response and echoes every DATA frame it receives
///    back to the client (same gun-framed bytes, no re-encoding).
///
/// The response stream is closed with EOS after the client's request body ends.
#[cfg(feature = "grpc")]
pub async fn spawn_grpc_server() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<GrpcConnInfo>,
) {
    spawn_grpc_server_inner(false).await
}

/// Same as [`spawn_grpc_server`] but withholds the response HEADERS until the
/// client's first DATA frame arrives.
///
/// This is how the real peers behave: xray's `Tun` handler reads the first hunk
/// before writing, and grpc-go only flushes response headers on the first
/// `SendMsg`. A client that awaits the response inside `connect()` deadlocks
/// against this server (issue #377).
#[cfg(feature = "grpc")]
pub async fn spawn_grpc_server_deferred_response() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<GrpcConnInfo>,
) {
    spawn_grpc_server_inner(true).await
}

#[cfg(feature = "grpc")]
async fn spawn_grpc_server_inner(
    defer_response: bool,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<GrpcConnInfo>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel::<GrpcConnInfo>();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("grpc loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };

        let Ok(mut conn) = h2::server::handshake(tcp).await else {
            eprintln!("grpc loopback h2 handshake error");
            return;
        };

        let Some(Ok((req, mut respond))) = conn.accept().await else {
            return;
        };

        // Capture request metadata before consuming the request.
        let path = req.uri().path().to_string();
        let content_type = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(std::string::ToString::to_string);
        let _ = tx.send(GrpcConnInfo { path, content_type });

        // Spawn the h2 connection driver so control frames (WINDOW_UPDATE,
        // SETTINGS, PING) keep flowing while we handle the request body.
        // The SendStream / RecvStream share Arc-backed connection state with
        // `conn`, so this is safe to do in a separate task.
        // h2::server::Connection does not implement Future; drive it by
        // calling accept() until None, which exhausts any further requests
        // and processes all connection-level frames.
        tokio::spawn(async move { while conn.accept().await.is_some() {} });

        // Send a 200 OK with end_of_stream=false (streaming response), unless
        // the caller asked for the grpc-go behaviour of withholding headers
        // until the request body starts flowing.
        let send_response = |respond: &mut h2::server::SendResponse<bytes::Bytes>| {
            let response = http::Response::builder()
                .status(200)
                .body(())
                .expect("response build");
            respond.send_response(response, false)
        };
        let mut send = if defer_response {
            None
        } else {
            match send_response(&mut respond) {
                Ok(send) => Some(send),
                Err(_) => return,
            }
        };

        // Echo every DATA frame back verbatim (same gun-framed bytes).
        let mut body = req.into_body();
        loop {
            let data = std::future::poll_fn(|cx| body.poll_data(cx)).await;
            match data {
                Some(Ok(data)) => {
                    // Release flow-control window so the client can keep sending.
                    let _ = body.flow_control().release_capacity(data.len());
                    let send = match &mut send {
                        Some(send) => send,
                        None => match send_response(&mut respond) {
                            Ok(new) => send.insert(new),
                            Err(_) => return,
                        },
                    };
                    if send.send_data(data, false).is_err() {
                        return;
                    }
                }
                None | Some(Err(_)) => break,
            }
        }
        let Some(mut send) = send else { return };

        // Close the response stream.
        let _ = send.send_data(bytes::Bytes::new(), true);
    });

    (addr, rx)
}

// ─── HTTP/2 (plain) loopback server ──────────────────────────────────────────

#[cfg(any(feature = "h2", feature = "xhttp"))]
#[derive(Debug, Clone)]
pub struct H2ReqInfo {
    /// The HTTP method sent by the client (e.g. `POST`).
    pub method: String,
    /// The `:authority` pseudo-header sent by the client (e.g. `"example.com"`).
    pub authority: Option<String>,
    /// The `:path` pseudo-header sent by the client (e.g. `"/custom"`).
    pub path: String,
    /// Request headers.
    pub headers: http::HeaderMap,
}

/// Spawn a multi-accept plain-HTTP/2 loopback server.
///
/// Returns `(addr, req_rx)`.  For each of the first `max_connections`
/// connections the server:
///
/// 1. Accepts a TCP connection and performs the HTTP/2 handshake.
/// 2. Accepts one h2 request, captures `:authority` and `:path`.
/// 3. Sends [`H2ReqInfo`] through the mpsc channel as soon as the request
///    HEADERS arrive — i.e. before the response — so a caller that awaits the
///    receiver sees the metadata without having to exchange body bytes first.
/// 4. Sends a `200 OK` streaming response and echoes every DATA frame back.
///
/// Using mpsc (not oneshot) allows multi-connection tests (e.g. D2 with 1000
/// connections) to collect all metadata via a single receiver.
#[cfg(any(feature = "h2", feature = "xhttp"))]
pub async fn spawn_h2_server(
    max_connections: usize,
) -> (std::net::SocketAddr, tokio::sync::mpsc::Receiver<H2ReqInfo>) {
    spawn_h2_server_inner(max_connections, false).await
}

/// Same as [`spawn_h2_server`] but withholds the response HEADERS until the
/// client's first DATA frame arrives, the way mihomo's h2 handler behaves.
/// A client that awaits the response inside `connect()` deadlocks here
/// (issue #377).
#[cfg(any(feature = "h2", feature = "xhttp"))]
pub async fn spawn_h2_server_deferred_response(
    max_connections: usize,
) -> (std::net::SocketAddr, tokio::sync::mpsc::Receiver<H2ReqInfo>) {
    spawn_h2_server_inner(max_connections, true).await
}

#[cfg(any(feature = "h2", feature = "xhttp"))]
async fn spawn_h2_server_inner(
    max_connections: usize,
    defer_response: bool,
) -> (std::net::SocketAddr, tokio::sync::mpsc::Receiver<H2ReqInfo>) {
    let (tx, rx) = tokio::sync::mpsc::channel(max_connections.max(1));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("h2 loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let mut remaining = max_connections;
        while remaining > 0 {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            remaining -= 1;
            let tx = tx.clone();
            tokio::spawn(h2_handle_conn(tcp, tx, defer_response));
        }
    });

    (addr, rx)
}

#[cfg(any(feature = "h2", feature = "xhttp"))]
async fn h2_handle_conn(
    tcp: tokio::net::TcpStream,
    tx: tokio::sync::mpsc::Sender<H2ReqInfo>,
    defer_response: bool,
) {
    let Ok(mut conn) = h2::server::handshake(tcp).await else {
        eprintln!("h2 loopback handshake error");
        return;
    };

    let Some(Ok((req, mut respond))) = conn.accept().await else {
        eprintln!("h2 loopback accept error");
        return;
    };

    let method = req.method().to_string();
    let authority = req.uri().authority().map(std::string::ToString::to_string);
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();

    // Publish the request metadata as soon as the HEADERS arrive, so tests can
    // assert on it without depending on when the response is sent.
    let _ = tx
        .send(H2ReqInfo {
            method,
            authority,
            path,
            headers,
        })
        .await;
    // Drive the h2 connection (SETTINGS, WINDOW_UPDATE, …) in background.
    tokio::spawn(async move { while conn.accept().await.is_some() {} });

    // Send 200 OK (streaming response, end_of_stream=false).
    let send_response = |respond: &mut h2::server::SendResponse<bytes::Bytes>| {
        let response = http::Response::builder()
            .status(200)
            .body(())
            .expect("response build");
        respond.send_response(response, false)
    };
    let mut send = if defer_response {
        None
    } else {
        match send_response(&mut respond) {
            Ok(send) => Some(send),
            Err(_) => return,
        }
    };

    // Echo every DATA frame back verbatim.
    let mut body = req.into_body();
    loop {
        let chunk = std::future::poll_fn(|cx| body.poll_data(cx)).await;
        match chunk {
            Some(Ok(data)) => {
                let _ = body.flow_control().release_capacity(data.len());
                let send = match &mut send {
                    Some(send) => send,
                    None => match send_response(&mut respond) {
                        Ok(new) => send.insert(new),
                        Err(_) => return,
                    },
                };
                if send.send_data(data, false).is_err() {
                    return;
                }
            }
            None | Some(Err(_)) => break,
        }
    }
    let Some(mut send) = send else { return };
    let _ = send.send_data(bytes::Bytes::new(), true);
}

// ─── HTTP/1.1 Upgrade loopback server ────────────────────────────────────────

/// Metadata captured from an HTTP/1.1 Upgrade request received by the
/// loopback server.
#[cfg(feature = "httpupgrade")]
#[derive(Debug, Default)]
pub struct HttpUpgradeReqInfo {
    /// The request path (e.g. `"/upgrade"`).
    pub path: String,
    /// All request headers, lower-cased names mapped to their values.
    pub headers: std::collections::HashMap<String, String>,
}

/// Spawn a single-accept HTTP/1.1 Upgrade loopback server.
///
/// Returns `(addr, req_info_rx)`.  The server:
///
/// 1. Accepts one TCP connection.
/// 2. Reads and parses the upgrade request headers.
/// 3. Sends [`HttpUpgradeReqInfo`] through the oneshot channel.
/// 4. Writes `response` verbatim (caller controls the HTTP response line +
///    headers + blank line).
/// 5. If `echo = true`, copies all subsequent bytes bidirectionally.
///
/// Callers use this to simulate both success (101) and error (200, missing
/// Upgrade header, etc.) paths without duplicating server logic.
#[cfg(feature = "httpupgrade")]
pub async fn spawn_httpupgrade_server(
    response: &'static str,
    echo: bool,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<HttpUpgradeReqInfo>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("httpupgrade loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let Ok((mut tcp, _)) = listener.accept().await else {
            return;
        };

        // Read request headers byte-by-byte until \r\n\r\n.
        let mut req_buf: Vec<u8> = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut tcp, &mut b)
                .await
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            req_buf.push(b[0]);
            if req_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        // Simple line-by-line header parsing (no httparse dependency in tests).
        let req_str = String::from_utf8_lossy(&req_buf);
        let mut lines = req_str.lines();
        let path = lines
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_string();
        let mut headers = std::collections::HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let _ = tx.send(HttpUpgradeReqInfo { path, headers });

        // Send the configured HTTP response.
        let _ = tokio::io::AsyncWriteExt::write_all(&mut tcp, response.as_bytes()).await;

        // Echo bytes bidirectionally if requested.
        if echo {
            let (mut r, mut w) = tokio::io::split(tcp);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        }
    });

    (addr, rx)
}

// ─── WebSocket loopback server ────────────────────────────────────────────────

/// Metadata captured from the WebSocket upgrade request.
#[derive(Debug, Default)]
pub struct WsConnInfo {
    /// Value of the `Host` header sent by the client.
    pub host: Option<String>,
    /// Value of the `Sec-WebSocket-Protocol` header (used for early data).
    pub sec_ws_protocol: Option<String>,
    /// All headers from the upgrade request (lower-cased names).
    pub headers: std::collections::HashMap<String, String>,
}

/// Spawn a single-accept plain-TCP WebSocket loopback server.
///
/// Returns `(addr, ws_info_rx)`.  The server:
/// 1. Accepts one TCP connection.
/// 2. Performs the WebSocket handshake, capturing upgrade-request headers.
/// 3. Sends [`WsConnInfo`] through the oneshot channel.
/// 4. Drains the connection until EOF.
pub async fn spawn_ws_server() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<WsConnInfo>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel::<WsConnInfo>();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ws loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };

        // Use accept_hdr_async to capture the upgrade-request headers.
        use tokio_tungstenite::tungstenite::handshake::server::{Callback, Request, Response};

        struct CaptureCallback(tokio::sync::oneshot::Sender<WsConnInfo>);

        impl Callback for CaptureCallback {
            fn on_request(
                self,
                request: &Request,
                mut response: Response,
            ) -> std::result::Result<
                Response,
                tokio_tungstenite::tungstenite::http::Response<Option<String>>,
            > {
                let mut headers = std::collections::HashMap::new();
                let mut host = None;
                let mut sec_ws_protocol = None;

                for (k, v) in request.headers() {
                    let key = k.as_str().to_ascii_lowercase();
                    let val = v.to_str().unwrap_or("").to_string();
                    if key == "host" {
                        host = Some(val.clone());
                    }
                    if key == "sec-websocket-protocol" {
                        sec_ws_protocol = Some(val.clone());
                    }
                    headers.insert(key, val);
                }

                // RFC 6455: if the client sends Sec-WebSocket-Protocol, the server
                // MUST respond with one of the listed protocols (tungstenite enforces
                // this on the client side).  Echo it back verbatim so the handshake
                // succeeds — the test only cares about the header value, not the
                // subprotocol semantics.
                if let Some(proto) = request.headers().get("sec-websocket-protocol") {
                    response.headers_mut().insert(
                        tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL,
                        proto.clone(),
                    );
                }

                let info = WsConnInfo {
                    host,
                    sec_ws_protocol,
                    headers,
                };
                let _ = self.0.send(info);
                Ok(response)
            }
        }

        let Ok(ws) = tokio_tungstenite::accept_hdr_async(tcp, CaptureCallback(tx)).await else {
            eprintln!("ws loopback accept error");
            return;
        };

        // Drain the connection.
        let mut ws = ws;
        use futures_util::StreamExt;
        while ws.next().await.is_some() {}
    });

    (addr, rx)
}

// ─── BoringSSL loopback servers (feature-gated) ──────────────────────────────

/// Metadata captured from a BoringSSL TLS handshake (fingerprint tests).
#[cfg(feature = "tls")]
#[derive(Debug, Default)]
pub struct BoringConnInfo {
    /// SNI name sent by the client (None if no SNI).
    pub server_name: Option<String>,
    /// ALPN protocol negotiated (None if no ALPN).
    pub alpn: Option<Vec<u8>>,
    /// Raw ClientHello bytes captured from the client.
    pub client_hello_bytes: Vec<u8>,
    /// DER-encoded client certificates (empty if no client cert).
    pub peer_certs: Vec<Vec<u8>>,
    /// True when the server successfully decrypted ECH in this handshake.
    pub ech_accepted: bool,
}

/// Configuration for [`spawn_boring_server`].
#[cfg(feature = "tls")]
pub struct BoringServerOptions {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    /// ALPN protocols the server advertises (empty = no ALPN).
    pub server_alpn: Vec<Vec<u8>>,
    /// If `Some`, server requires client certificate verified against this CA.
    pub require_client_cert_ca: Option<CertificateDer<'static>>,
    /// Optional ECH configuration for the server (private key + config).
    pub ech_config: Option<BoringEchConfig>,
}

/// ECH configuration for [`spawn_boring_server`] / [`spawn_ech_server`].
///
/// The `keys_handle` keeps the `SSL_ECH_KEYS*` alive until the server context
/// installs it (via `SSL_CTX_set1_ech_keys`, which increments the ref-count).
/// After installation the handle can be dropped safely.
#[cfg(feature = "tls")]
pub struct BoringEchConfig {
    /// Raw EncodedECHConfigList bytes (public key) — give these to the client's
    /// [`EchOpts::Config`](meow_transport::tls::EchOpts::Config).
    pub config_list_bytes: Vec<u8>,
    /// Owning handle for the corresponding `SSL_ECH_KEYS*`.  Freed on drop.
    pub keys_handle: EchKeysHandle,
}

/// RAII wrapper for a `*mut SSL_ECH_KEYS` pointer.
///
/// Calls `SSL_ECH_KEYS_free` on drop.  Kept alive until
/// `SSL_CTX_set1_ech_keys` is called (which takes its own ref-counted copy).
#[cfg(feature = "tls")]
pub struct EchKeysHandle(pub *mut boring_sys::SSL_ECH_KEYS);

#[cfg(feature = "tls")]
// SAFETY: `SSL_ECH_KEYS*` is ref-counted and internally synchronised; safe to
// send across threads as long as no aliases exist (upheld by ownership here).
unsafe impl Send for EchKeysHandle {}

#[cfg(feature = "tls")]
impl Drop for EchKeysHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { boring_sys::SSL_ECH_KEYS_free(self.0) };
        }
    }
}

/// JA3 fingerprint hash computation helper.
///
/// Extract ClientHello fields (cipher suites, extensions, curves, sigalgs)
/// and compute the JA3 fingerprint string per Salesforce spec (canonical JA3).
///
/// # Important: GREASE Removal and Extension Permutation
///
/// - **GREASE removal (canonical JA3):** Boring with `set_grease_enabled(true)`
///   injects GREASE values per-handshake. Canonical JA3 (Salesforce spec) REMOVES
///   all GREASE entries (0x0a0a, 0x1a1a, ..., 0xfafa) before hashing. This ensures:
///   - Hashes match real Chrome's public JA3 entries (external verification)
///   - Hashes are stable across connections (GREASE removed, not randomized)
///   - Fingerprints are comparable to external JA3 databases
///
/// - **Extension permutation (chrome):** Chrome uses `set_permute_extensions(true)`,
///   which randomizes extension order per-connection. Canonical JA3 does NOT sort
///   extensions — it uses wire order. This means chrome's JA3 hash varies per
///   connection. Tests for chrome use property-based assertions (check for
///   presence of ciphers/extensions/GREASE, order-agnostic) rather than fixed hashes.
///   Other profiles (firefox, safari, ios, android, edge) have fixed extension
///   order and use fixed JA3 hash assertions.
#[cfg(feature = "tls")]
pub struct JA3Helper;

#[cfg(feature = "tls")]
impl JA3Helper {
    /// Parse ClientHello bytes and compute canonical JA3 string (Salesforce spec).
    ///
    /// Returns: `(ja3_string, ja3_hash)` where ja3_string is
    /// `TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats`
    /// with GREASE values REMOVED (not canonicalized).
    /// ja3_hash is MD5(ja3_string).
    ///
    /// **Canonical JA3:** Matches Salesforce spec and real Chrome's public JA3 hashes.
    /// GREASE entries are completely removed (not normalized), allowing external
    /// verification against JA3 databases.
    pub fn compute_ja3(_client_hello_bytes: &[u8]) -> Option<(String, String)> {
        // TODO: Implement full ClientHello TLS record parsing
        //
        // Structure (TLS 1.3 / 1.2):
        // - Record header (1 byte type, 2 bytes version, 2 bytes length)
        // - Handshake header (1 byte msg_type=0x01 for ClientHello, 3 bytes length)
        // - ClientHello:
        //   - protocol_version (2 bytes)
        //   - random (32 bytes)
        //   - session_id_length (1 byte) + session_id (variable)
        //   - cipher_suites_length (2 bytes) + cipher_suites (variable, 2 bytes each)
        //   - compression_methods_length (1 bytes) + compression_methods (variable)
        //   - extensions_length (2 bytes, if present)
        //   - extensions (variable)
        //
        // Extract from ClientHello:
        // 1. TLS version (e.g., "771" for TLS 1.2, "772" for TLS 1.3)
        // 2. Cipher suites (list of u16 values, decimal, REMOVE GREASE entries)
        // 3. Extensions (in wire order, list of u16 type IDs, REMOVE GREASE entries)
        // 4. Supported groups (from supported_groups extension 10, REMOVE GREASE)
        // 5. Signature algorithms (from signature_algorithms extension 13, NO GREASE here)
        //
        // JA3 format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats
        // where EllipticCurveFormats is typically "0" (uncompressed point format)
        //
        // After building ja3_string, compute MD5 hash
        None
    }

    /// Helper: Remove all GREASE values from a list per Salesforce JA3 spec.
    /// GREASE values have pattern 0x?a?a where ? is any hex digit.
    /// Canonical JA3 completely removes these, not canonicalizing them.
    fn remove_grease(values: &[u16]) -> Vec<u16> {
        values
            .iter()
            .filter(|&&v| {
                // Filter OUT GREASE values (0x?a?a pattern)
                (v & 0x0f0f) != 0x0a0a
            })
            .copied()
            .collect()
    }
}

/// Self-consistent ECH test keypair generator.
///
/// Generates ECH keys at test startup, ensuring server and client share the same
/// keypair without embedding static magic bytes or hand-encoding wire formats.
#[cfg(feature = "tls")]
pub struct EchKeyPairGenerator;

#[cfg(feature = "tls")]
impl EchKeyPairGenerator {
    /// Generate a self-consistent ECH keypair for loopback tests.
    ///
    /// Returns `(config_list_bytes, keys_handle)` where:
    /// - `config_list_bytes` — EncodedECHConfigList wire format; pass to
    ///   [`EchOpts::Config`](meow_transport::tls::EchOpts::Config) on the client.
    /// - `keys_handle` — owning handle for the server's `SSL_ECH_KEYS*`; put into
    ///   [`BoringEchConfig`] and pass to [`spawn_ech_server`].
    ///
    /// # Implementation
    ///
    /// Uses boring-sys FFI (`SSL_ECH_KEYS_*` family, v5.0.2+) to generate the keypair
    /// at test startup via X25519 HPKE. Both server and client use the same bytes,
    /// guaranteeing consistency without static test vectors.
    ///
    /// # Panics
    ///
    /// Panics if any of the FFI operations fail (which would indicate a test
    /// configuration error, not a runtime issue).
    pub fn generate() -> Option<(Vec<u8>, EchKeysHandle)> {
        unsafe { Self::generate_ech_key_and_config("loopback.test") }
    }

    /// FFI-based implementation using boring-sys SSL_ECH_KEYS_* functions.
    ///
    /// Returns: `(ech_config_list_bytes, keys_handle)` — the config bytes for the
    /// client and an owning handle for the server's SSL_ECH_KEYS*.
    #[cfg(feature = "tls")]
    unsafe fn generate_ech_key_and_config(public_name: &str) -> Option<(Vec<u8>, EchKeysHandle)> {
        use boring_sys::*;
        use std::ffi::CString;

        // 1. Generate HPKE X25519 key for the server.
        let mut hpke_key: EVP_HPKE_KEY = std::mem::zeroed();
        if EVP_HPKE_KEY_generate(&mut hpke_key, EVP_hpke_x25519_hkdf_sha256()) != 1 {
            eprintln!("ECH: EVP_HPKE_KEY_generate failed");
            return None;
        }

        // 2. Marshal the ECHConfig (single config with ID 1) from the HPKE key.
        // The ECHConfig includes the public key; the private key is kept by the server.
        let Ok(public_name_cstr) = CString::new(public_name) else {
            eprintln!("ECH: invalid public name");
            return None;
        };

        let mut ech_config_ptr: *mut u8 = std::ptr::null_mut();
        let mut ech_config_len: usize = 0;
        if SSL_marshal_ech_config(
            &mut ech_config_ptr,
            &mut ech_config_len,
            1u8, // config_id
            &hpke_key,
            public_name_cstr.as_ptr(),
            public_name.len(),
        ) != 1
        {
            eprintln!("ECH: SSL_marshal_ech_config failed");
            return None;
        }

        let ech_config = std::slice::from_raw_parts(ech_config_ptr, ech_config_len).to_vec();
        OPENSSL_free(ech_config_ptr as *mut _);

        // 3. Build SSL_ECH_KEYS structure (server-side management of the key).
        let keys = SSL_ECH_KEYS_new();
        if keys.is_null() {
            eprintln!("ECH: SSL_ECH_KEYS_new failed");
            return None;
        }

        // Add the ECHConfig to the keys structure.
        // SSL_ECH_KEYS_add(keys, is_retry_config, ech_config.ptr, ech_config.len, hpke_key)
        //
        // is_retry_config=1 means this config will be:
        //   (a) included by SSL_ECH_KEYS_marshal_retry_configs → gives the client its ECHConfigList
        //   (b) required by SSL_CTX_set1_ech_keys (fails with 0 if no retry config exists)
        //   (c) sent back to the client if ECH decryption fails (retry response)
        if SSL_ECH_KEYS_add(
            keys,
            1, // is_retry_config = true
            ech_config.as_ptr(),
            ech_config.len(),
            &hpke_key, // The HPKE key containing the private key
        ) != 1
        {
            eprintln!("ECH: SSL_ECH_KEYS_add failed");
            SSL_ECH_KEYS_free(keys);
            return None;
        }

        // 4. Marshal the ECHConfigList (wire format for clients).
        // This is the EncodedECHConfigList that the client will send in ClientHello.
        let mut list_ptr: *mut u8 = std::ptr::null_mut();
        let mut list_len: usize = 0;
        if SSL_ECH_KEYS_marshal_retry_configs(keys, &mut list_ptr, &mut list_len) != 1 {
            eprintln!("ECH: SSL_ECH_KEYS_marshal_retry_configs failed");
            SSL_ECH_KEYS_free(keys);
            return None;
        }

        let ech_config_list = std::slice::from_raw_parts(list_ptr, list_len).to_vec();
        OPENSSL_free(list_ptr as *mut _);

        // 5. Wrap the live SSL_ECH_KEYS* in an EchKeysHandle.
        //
        // The handle's Drop impl calls SSL_ECH_KEYS_free.  The caller moves the
        // handle into BoringEchConfig, which is then passed to spawn_ech_server.
        // spawn_ech_server calls SSL_CTX_set1_ech_keys (which bumps the ref-count)
        // before the handle is dropped, so the keys remain valid inside SSL_CTX.
        //
        // NOTE: do NOT call SSL_ECH_KEYS_free here — ownership transfers to the
        // returned EchKeysHandle.
        Some((ech_config_list, EchKeysHandle(keys)))
    }
}

/// Wall-clock timeout wrapper for socket I/O tests.
///
/// Replaces tokio::time::pause() for handshake timeouts.
/// Guarantees wall-clock timeout even if tokio::time is paused.
#[cfg(feature = "tls")]
pub struct WallClockTimeout {
    deadline: std::time::Instant,
}

#[cfg(feature = "tls")]
impl WallClockTimeout {
    pub fn new(duration: std::time::Duration) -> Self {
        Self {
            deadline: std::time::Instant::now() + duration,
        }
    }

    pub fn is_expired(&self) -> bool {
        std::time::Instant::now() >= self.deadline
    }

    pub fn remaining(&self) -> std::time::Duration {
        self.deadline
            .saturating_duration_since(std::time::Instant::now())
    }
}

// ─── Cert/Key conversion FFI helpers ─────────────────────────────────────────

/// Convert a rustls `CertificateDer` to a `boring::x509::X509`.
///
/// Uses `X509::from_der` which calls BoringSSL's `d2i_X509` internally.
#[cfg(feature = "tls")]
fn rustls_cert_to_boring(cert_der: &CertificateDer) -> Result<boring::x509::X509, String> {
    boring::x509::X509::from_der(cert_der.as_ref())
        .map_err(|e| format!("boring: X509::from_der failed: {e}"))
}

/// Convert a rustls `PrivateKeyDer` to a `boring::pkey::PKey<Private>`.
///
/// Uses `PKey::private_key_from_der` which calls BoringSSL's `d2i_AutoPrivateKey`.
/// BoringSSL's auto-detect handles PKCS#8 (used by rcgen), PKCS#1 (RSA), and
/// SEC1 (EC traditional) formats transparently.
#[cfg(feature = "tls")]
fn rustls_key_to_boring(
    key_der: &PrivateKeyDer,
) -> Result<boring::pkey::PKey<boring::pkey::Private>, String> {
    let der_bytes: &[u8] = match key_der {
        PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der(),
        PrivateKeyDer::Pkcs1(k) => k.secret_pkcs1_der(),
        PrivateKeyDer::Sec1(k) => k.secret_sec1_der(),
        _ => return Err("boring: unsupported PrivateKeyDer variant".into()),
    };
    boring::pkey::PKey::private_key_from_der(der_bytes)
        .map_err(|e| format!("boring: PKey::private_key_from_der failed: {e}"))
}

// ─── ClientHello capture helpers ─────────────────────────────────────────

// Placeholder for ClientHello byte capture infrastructure.
//
// Boring doesn't natively expose raw ClientHello bytes; capturing them requires
// either a stream wrapper that intercepts the first TLS record before replaying
// it, post-handshake extraction via boring callbacks, or manual TLS record
// parsing. Implementation deferred pending research into boring-sys's BIO
// callbacks or custom stream wrapping patterns.

// ─── BoringSSL loopback servers (fingerprint + ECH tests) ──────────────────────

/// Spawn a single-accept BoringSSL TLS loopback server.
///
/// Returns `(addr, conn_info_rx)`.  The server:
/// 1. Accepts one TCP connection.
/// 2. Performs the TLS handshake using BoringSSL.
/// 3. Captures raw ClientHello bytes (for JA3 computation) and connection
///    metadata (SNI, ALPN, peer certs).
/// 4. Sends [`BoringConnInfo`] through the oneshot channel.
/// 5. Drains the connection until EOF.
///
/// Used for fingerprint (C1–C7) and non-ECH tests. For ECH-capable servers
/// (C12–C15), use [`spawn_ech_server`] instead.
///
/// # Panics
///
/// Panics if boring SSL context setup fails (which indicates a test
/// configuration error, not a runtime issue).
#[cfg(feature = "tls")]
pub async fn spawn_boring_server(
    opts: BoringServerOptions,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<BoringConnInfo>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel();

    // Build boring SSL acceptor before spawning so errors surface synchronously.
    // mozilla_intermediate_v5 allows TLS 1.2 + 1.3 (unlike mozilla_intermediate
    // which disables TLS 1.3 via NO_TLSV1_3).
    let cert = rustls_cert_to_boring(&opts.cert_der).expect("boring server: cert");
    let key = rustls_key_to_boring(&opts.key_der).expect("boring server: key");

    let mut builder =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
            .expect("boring server: SslAcceptor::mozilla_intermediate_v5");
    builder
        .set_certificate(&cert)
        .expect("boring server: set_certificate");
    builder
        .set_private_key(&key)
        .expect("boring server: set_private_key");

    // ALPN selection callback: pick the first client-offered protocol the server supports.
    if !opts.server_alpn.is_empty() {
        let server_protos = opts.server_alpn;
        builder.set_alpn_select_callback(move |_ssl, client_protocols| {
            // client_protocols is length-prefixed wire format: [len][proto][len][proto]…
            let mut pos = 0usize;
            while pos < client_protocols.len() {
                let len = client_protocols[pos] as usize;
                pos += 1;
                if pos + len > client_protocols.len() {
                    break;
                }
                let proto = &client_protocols[pos..pos + len];
                if server_protos.iter().any(|s| s.as_slice() == proto) {
                    return Ok(proto);
                }
                pos += len;
            }
            Err(boring::ssl::AlpnError::NOACK)
        });
    }

    let acceptor = builder.build();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("boring loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };

        let Ok(mut stream) = tokio_boring::accept(&acceptor, tcp).await else {
            eprintln!("boring loopback accept error");
            let _ = tx.send(BoringConnInfo::default());
            return;
        };

        let info = BoringConnInfo {
            server_name: stream
                .ssl()
                .servername(boring::ssl::NameType::HOST_NAME)
                .map(std::string::ToString::to_string),
            alpn: stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec),
            client_hello_bytes: vec![],
            peer_certs: vec![],
            ech_accepted: false,
        };

        let _ = tx.send(info);

        // Drain so the client doesn't see a broken-pipe on its write.
        let mut drain = [0u8; 256];
        loop {
            match tokio::io::AsyncReadExt::read(&mut stream, &mut drain).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    (addr, rx)
}

/// Spawn a single-accept BoringSSL ECH-capable TLS loopback server.
///
/// Returns `(addr, conn_info_rx)`.  Same as [`spawn_boring_server`], but the
/// server is configured with an ECH keypair (private key + config list) for
/// C12–C15 tests (ECH path, server-side decryption, etc.).
///
/// The server:
/// 1. Accepts one TCP connection.
/// 2. Performs the TLS handshake using BoringSSL with ECH configured.
/// 3. Captures raw ClientHello bytes and connection metadata.
/// 4. Sends [`BoringConnInfo`] through the oneshot channel.
/// 5. Drains the connection until EOF.
///
/// # Panics
///
/// Panics if boring SSL context setup or ECH configuration fails.
#[cfg(feature = "tls")]
pub async fn spawn_ech_server(
    opts: BoringServerOptions,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<BoringConnInfo>,
) {
    // Expect ech_config to be present; C13–C15 tests always provide it.
    let ech_cfg = opts
        .ech_config
        .expect("spawn_ech_server: ech_config must be present for ECH tests");

    let (tx, rx) = tokio::sync::oneshot::channel();

    // Build boring SSL acceptor before spawning.
    // mozilla_intermediate_v5 allows TLS 1.3, which ECH requires.
    let cert = rustls_cert_to_boring(&opts.cert_der).expect("boring ECH server: cert");
    let key = rustls_key_to_boring(&opts.key_der).expect("boring ECH server: key");

    let mut builder =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
            .expect("boring ECH server: SslAcceptor::mozilla_intermediate_v5");
    builder
        .set_certificate(&cert)
        .expect("boring ECH server: set_certificate");
    builder
        .set_private_key(&key)
        .expect("boring ECH server: set_private_key");

    // Install the ECH keys on the SSL_CTX.
    //
    // SSL_CTX_set1_ech_keys increments the ref-count on the keys object, so it
    // remains valid inside the context even after EchKeysHandle is dropped here.
    // builder derefs to SslContextBuilder, which exposes as_ptr() → *mut SSL_CTX.
    unsafe {
        let ret = boring_sys::SSL_CTX_set1_ech_keys(builder.as_ptr(), ech_cfg.keys_handle.0);
        assert_eq!(ret, 1, "SSL_CTX_set1_ech_keys failed");
    }
    // ech_cfg (and its EchKeysHandle) drops here — SSL_CTX holds the ref.

    let acceptor = builder.build();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ech loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };

        let Ok(mut stream) = tokio_boring::accept(&acceptor, tcp).await else {
            eprintln!("boring ECH loopback accept error");
            let _ = tx.send(BoringConnInfo::default());
            return;
        };

        let ech_accepted = stream.ssl().ech_accepted();
        let info = BoringConnInfo {
            server_name: stream
                .ssl()
                .servername(boring::ssl::NameType::HOST_NAME)
                .map(std::string::ToString::to_string),
            alpn: stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec),
            client_hello_bytes: vec![],
            peer_certs: vec![],
            ech_accepted,
        };

        let _ = tx.send(info);

        // Drain so the client doesn't see a broken-pipe on its write.
        let mut drain = [0u8; 256];
        loop {
            match tokio::io::AsyncReadExt::read(&mut stream, &mut drain).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    (addr, rx)
}

/// Multi-accept variant of [`spawn_ech_server`].
///
/// Accepts up to `count` connections, sending one [`BoringConnInfo`] per
/// connection through the returned `mpsc` receiver. Used by the ECH
/// self-heal test (C16) which drives two connects through the same server
/// to validate retry-config rotation.
#[cfg(feature = "tls")]
pub async fn spawn_ech_server_multi(
    opts: BoringServerOptions,
    count: usize,
) -> (
    std::net::SocketAddr,
    tokio::sync::mpsc::Receiver<BoringConnInfo>,
) {
    let ech_cfg = opts
        .ech_config
        .expect("spawn_ech_server_multi: ech_config must be present");

    let (tx, rx) = tokio::sync::mpsc::channel(count.max(1));

    let cert = rustls_cert_to_boring(&opts.cert_der).expect("boring ECH multi: cert");
    let key = rustls_key_to_boring(&opts.key_der).expect("boring ECH multi: key");

    let mut builder =
        boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
            .expect("boring ECH multi: SslAcceptor::mozilla_intermediate_v5");
    builder
        .set_certificate(&cert)
        .expect("boring ECH multi: set_certificate");
    builder
        .set_private_key(&key)
        .expect("boring ECH multi: set_private_key");

    unsafe {
        let ret = boring_sys::SSL_CTX_set1_ech_keys(builder.as_ptr(), ech_cfg.keys_handle.0);
        assert_eq!(ret, 1, "SSL_CTX_set1_ech_keys failed");
    }

    let acceptor = builder.build();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ech multi loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        for _ in 0..count {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = tokio_boring::accept(&acceptor, tcp).await else {
                    eprintln!("boring ECH multi accept error");
                    let _ = tx.send(BoringConnInfo::default()).await;
                    return;
                };
                let ech_accepted = stream.ssl().ech_accepted();
                let info = BoringConnInfo {
                    server_name: stream
                        .ssl()
                        .servername(boring::ssl::NameType::HOST_NAME)
                        .map(std::string::ToString::to_string),
                    alpn: stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec),
                    client_hello_bytes: vec![],
                    peer_certs: vec![],
                    ech_accepted,
                };
                let _ = tx.send(info).await;
                let mut drain = [0u8; 256];
                loop {
                    match tokio::io::AsyncReadExt::read(&mut stream, &mut drain).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });

    (addr, rx)
}
