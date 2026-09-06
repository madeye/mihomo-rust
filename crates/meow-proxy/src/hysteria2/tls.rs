//! quiche QUIC configuration for the hysteria2 client, built on BoringSSL.
//!
//! quiche links the same vendored BoringSSL as `meow-transport` (via the
//! `boring` crate), so this reuses `boring::ssl::SslContextBuilder` for the
//! server-certificate trust decision — a SHA-256 leaf pin, `insecure` (no
//! verification), or normal chain and hostname validation against the Mozilla
//! CA bundle — and hands the builder to quiche.

use super::{Config, Error, Result};
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
use boring::x509::X509StoreContextRef;
use sha2::{Digest, Sha256};
use std::time::Duration;

const ALPN_H3: &[u8] = b"h3";
const STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024;
const CONN_RECEIVE_WINDOW: u64 = STREAM_RECEIVE_WINDOW * 5 / 2;
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_STREAMS: u64 = 1024;
const DGRAM_QUEUE_LEN: usize = 1024;

/// Build a client `quiche::Config` for the given hysteria2 config.
pub fn build_quiche_config(config: &Config) -> Result<quiche::Config> {
    let mut ssl = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| Error::tls(format!("boring SslContextBuilder: {e}")))?;

    let pin = parse_sha256_pin(&config.pin_sha256)?;
    match server_cert_verifier(config.insecure, pin) {
        CertVerifier::Pin(expected) => {
            ssl.set_verify_callback(SslVerifyMode::PEER, move |_preverify_ok, ctx| {
                leaf_matches_pin(ctx, &expected)
            });
        }
        CertVerifier::Insecure => ssl.set_verify(SslVerifyMode::NONE),
        CertVerifier::WebPki => {
            seed_roots(&mut ssl)?;
            ssl.set_verify(SslVerifyMode::PEER);
        }
    }

    // quiche installs the SNI as the verify-param hostname per connection and
    // only touches the verify mode through `verify_peer`, which the client
    // never calls, so the choice above is what BoringSSL enforces.
    let mut quic = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl)
        .map_err(|e| Error::tls(format!("quiche config: {e}")))?;

    quic.set_application_protos(&[ALPN_H3])
        .map_err(|e| Error::tls(format!("quiche alpn: {e}")))?;
    quic.set_max_idle_timeout(u64::try_from(MAX_IDLE_TIMEOUT.as_millis()).unwrap_or(u64::MAX));
    quic.set_initial_max_data(CONN_RECEIVE_WINDOW);
    quic.set_initial_max_stream_data_bidi_local(STREAM_RECEIVE_WINDOW);
    quic.set_initial_max_stream_data_bidi_remote(STREAM_RECEIVE_WINDOW);
    quic.set_initial_max_stream_data_uni(STREAM_RECEIVE_WINDOW);
    quic.set_initial_max_streams_bidi(MAX_CONCURRENT_STREAMS);
    quic.set_initial_max_streams_uni(MAX_CONCURRENT_STREAMS);
    // hysteria2 disables the QUIC bit greasing.
    quic.grease(false);
    // UDP relay rides QUIC datagrams.
    quic.enable_dgram(true, DGRAM_QUEUE_LEN, DGRAM_QUEUE_LEN);

    Ok(quic)
}

/// How the server certificate is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertVerifier {
    /// Trust exactly the certificate whose DER SHA-256 digest matches.
    Pin([u8; 32]),
    /// `skip-cert-verify` without a pin: accept anything.
    Insecure,
    /// Chain and hostname validation against the bundled Mozilla roots.
    WebPki,
}

/// Pick the certificate verifier for a client config.
///
/// A configured fingerprint remains mandatory even when `insecure` is set.
///
/// A leaf pin replaces chain and hostname validation in meow-rs, matching
/// mihomo's leaf-fingerprint path and allowing self-signed certificates.
/// Hysteria's CLI differs: its pin is an additional leaf check, while its
/// `insecure` setting independently controls chain and hostname validation.
fn server_cert_verifier(insecure: bool, pin: Option<[u8; 32]>) -> CertVerifier {
    match (pin, insecure) {
        (Some(expected), _) => CertVerifier::Pin(expected),
        (None, true) => CertVerifier::Insecure,
        (None, false) => CertVerifier::WebPki,
    }
}

/// BoringSSL verify callback for a leaf pin (`fingerprint` / `pin-sha256`).
///
/// BoringSSL invokes the callback once per chain position and once per
/// verification error, passing its own verdict as `preverify_ok`. That verdict
/// is ignored: a pinned self-signed certificate fails chain building, and the
/// SNI need not match either. Positions above the leaf are accepted so
/// verification reaches depth 0, where only the end-entity digest decides.
/// Unrelated certificates appended to the chain therefore cannot satisfy the
/// pin. Possession of the private key is still proven: BoringSSL checks the
/// `CertificateVerify` signature independently of this callback.
fn leaf_matches_pin(ctx: &mut X509StoreContextRef, expected: &[u8; 32]) -> bool {
    if ctx.error_depth() != 0 {
        return true;
    }
    let leaf = ctx
        .chain()
        .and_then(|chain| chain.get(0))
        .or_else(|| ctx.current_cert());
    let Some(leaf) = leaf else {
        return false;
    };
    let Ok(der) = leaf.to_der() else {
        return false;
    };
    Sha256::digest(&der).as_slice() == expected
}

/// Seed the BoringSSL verify store with the Mozilla CA bundle (mirrors
/// `meow-transport`'s BoringSSL backend). The default store is empty.
fn seed_roots(ssl: &mut SslContextBuilder) -> Result<()> {
    let mut store = boring::x509::store::X509StoreBuilder::new()
        .map_err(|e| Error::tls(format!("X509StoreBuilder: {e}")))?;
    for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        let x509 = boring::x509::X509::from_der(cert.as_ref())
            .map_err(|e| Error::tls(format!("root cert parse: {e}")))?;
        store
            .add_cert(x509)
            .map_err(|e| Error::tls(format!("root store add_cert: {e}")))?;
    }
    ssl.set_cert_store_builder(store);
    Ok(())
}

fn parse_sha256_pin(raw: &str) -> Result<Option<[u8; 32]>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let without_prefix = raw
        .strip_prefix("sha256=")
        .or_else(|| raw.strip_prefix("SHA256="))
        .unwrap_or(raw);
    let normalized: String = without_prefix
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .flat_map(char::to_lowercase)
        .collect();
    if normalized.len() != 64 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::config(
            "pin-sha256/fingerprint must be a SHA-256 hex digest",
        ));
    }
    let decoded = hex::decode(normalized)
        .map_err(|e| Error::config(format!("invalid SHA-256 fingerprint: {e}")))?;
    let mut pin = [0u8; 32];
    pin.copy_from_slice(&decoded);
    Ok(Some(pin))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::pkey::{PKey, Private};
    use boring::x509::X509;
    use tokio::net::UdpSocket;

    #[test]
    fn parses_sha256_pin_variants() {
        let raw = "sha256=AA:BB cc";
        let mut padded = String::from(raw);
        padded.push_str(&"00".repeat(29));
        let pin = parse_sha256_pin(&padded).unwrap().unwrap();
        assert_eq!(pin[0], 0xaa);
        assert_eq!(pin[1], 0xbb);
        assert_eq!(pin[2], 0xcc);
    }

    #[test]
    fn rejects_invalid_sha256_pin() {
        assert!(parse_sha256_pin("abc").is_err());
    }

    #[test]
    fn builds_config_for_insecure() {
        let cfg = Config {
            insecure: true,
            ..Config::default()
        };
        assert!(build_quiche_config(&cfg).is_ok());
    }

    /// `skip-cert-verify: true` alongside a `fingerprint` used to win, quietly
    /// turning a pinned config into an unauthenticated one. The stricter
    /// setting must survive (mihomo applies the pin last, for the same reason).
    #[test]
    fn a_pin_overrides_skip_cert_verify() {
        assert_eq!(
            server_cert_verifier(true, Some([0x22; 32])),
            CertVerifier::Pin([0x22; 32])
        );
        assert_eq!(
            server_cert_verifier(false, Some([0x22; 32])),
            CertVerifier::Pin([0x22; 32])
        );
    }

    #[test]
    fn skip_cert_verify_without_a_pin_accepts_anything() {
        assert_eq!(server_cert_verifier(true, None), CertVerifier::Insecure);
    }

    #[test]
    fn plain_config_keeps_the_webpki_roots() {
        assert_eq!(server_cert_verifier(false, None), CertVerifier::WebPki);
    }

    /// A self-signed certificate and its `fingerprint`, as a hysteria2 server
    /// set up by the upstream install script would present.
    struct SelfSigned {
        cert: X509,
        key: PKey<Private>,
        pin: String,
    }

    fn self_signed(name: &str) -> SelfSigned {
        let ck = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
        SelfSigned {
            cert: X509::from_der(ck.cert.der()).unwrap(),
            key: PKey::private_key_from_der(&ck.key_pair.serialize_der()).unwrap(),
            pin: hex::encode(Sha256::digest(ck.cert.der())),
        }
    }

    /// Server TLS context presenting `leaf`, optionally with an unrelated
    /// certificate appended to the chain.
    fn server_ssl(leaf: &SelfSigned, appended: Option<&SelfSigned>) -> SslContextBuilder {
        let mut ssl = SslContextBuilder::new(SslMethod::tls()).unwrap();
        ssl.set_certificate(&leaf.cert).unwrap();
        ssl.set_private_key(&leaf.key).unwrap();
        if let Some(extra) = appended {
            ssl.add_extra_chain_cert(extra.cert.clone()).unwrap();
        }
        ssl
    }

    fn client_config(server_name: &str, insecure: bool, pin: &str) -> Config {
        Config {
            server_name: server_name.into(),
            insecure,
            pin_sha256: pin.into(),
            ..Config::default()
        }
    }

    async fn flush(
        conn: &mut quiche::Connection,
        socket: &UdpSocket,
    ) -> std::result::Result<(), String> {
        let mut out = [0u8; 1500];
        loop {
            match conn.send(&mut out) {
                Ok((n, info)) => {
                    socket
                        .send_to(&out[..n], info.to)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(e) => return Err(format!("send: {e}")),
            }
        }
    }

    /// Drive a real QUIC handshake between the production client config and a
    /// local quiche server presenting `server_ssl`'s certificate. Returns the
    /// client's verdict: the whole BoringSSL path (certificate *and*
    /// `CertificateVerify` signature), not just the digest comparison.
    async fn handshake(
        client_cfg: &Config,
        server_ssl: SslContextBuilder,
    ) -> std::result::Result<(), String> {
        tokio::time::timeout(
            Duration::from_secs(10),
            handshake_inner(client_cfg, server_ssl),
        )
        .await
        .map_err(|_| "local QUIC handshake must finish".to_string())?
    }

    async fn handshake_inner(
        client_cfg: &Config,
        server_ssl: SslContextBuilder,
    ) -> std::result::Result<(), String> {
        let mut server_config =
            quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, server_ssl)
                .map_err(|e| e.to_string())?;
        server_config.set_application_protos(&[ALPN_H3]).unwrap();
        server_config.set_max_idle_timeout(5_000);
        server_config.set_initial_max_data(1 << 20);
        server_config.set_initial_max_streams_bidi(16);
        server_config.set_initial_max_streams_uni(16);
        server_config.set_initial_max_stream_data_bidi_remote(64 * 1024);
        server_config.set_initial_max_stream_data_uni(64 * 1024);

        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        let mut client_config = build_quiche_config(client_cfg).map_err(|e| e.to_string())?;
        let scid = quiche::ConnectionId::from_ref(&[7u8; quiche::MAX_CONN_ID_LEN]);
        let mut client = quiche::connect(
            Some(&client_cfg.server_name),
            &scid,
            client_addr,
            server_addr,
            &mut client_config,
        )
        .map_err(|e| e.to_string())?;
        let mut server: Option<quiche::Connection> = None;
        let mut sbuf = [0u8; 65535];
        let mut cbuf = [0u8; 65535];

        loop {
            flush(&mut client, &client_sock).await?;
            if let Some(conn) = server.as_mut() {
                flush(conn, &server_sock).await?;
            }
            if client.is_established() {
                return Ok(());
            }
            if client.is_closed() || client.local_error().is_some() || client.peer_error().is_some()
            {
                return Err(format!(
                    "client closed: local={:?} peer={:?}",
                    client.local_error(),
                    client.peer_error()
                ));
            }
            let wait = client
                .timeout()
                .into_iter()
                .chain(server.as_ref().and_then(quiche::Connection::timeout))
                .min()
                .unwrap_or(Duration::from_millis(100));
            tokio::select! {
                r = server_sock.recv_from(&mut sbuf) => {
                    let (n, from) = r.map_err(|e| e.to_string())?;
                    if server.is_none() {
                        let hdr = quiche::Header::from_slice(&mut sbuf[..n], quiche::MAX_CONN_ID_LEN)
                            .map_err(|e| e.to_string())?;
                        let conn = quiche::accept(&hdr.dcid, None, server_addr, from, &mut server_config)
                            .map_err(|e| e.to_string())?;
                        server = Some(conn);
                    }
                    let conn = server.as_mut().unwrap();
                    let _ = conn.recv(&mut sbuf[..n], quiche::RecvInfo { from, to: server_addr });
                }
                r = client_sock.recv_from(&mut cbuf) => {
                    let (n, from) = r.map_err(|e| e.to_string())?;
                    // A rejected certificate surfaces here as `TlsFail` and
                    // sets the client's local error.
                    let _ = client.recv(&mut cbuf[..n], quiche::RecvInfo { from, to: client_addr });
                }
                () = tokio::time::sleep(wait) => {
                    client.on_timeout();
                    if let Some(conn) = server.as_mut() {
                        conn.on_timeout();
                    }
                }
            }
        }
    }

    /// The point of pinning: a self-signed server plus the matching
    /// `fingerprint` completes a handshake whatever `skip-cert-verify` says, a
    /// wrong fingerprint aborts it even with `skip-cert-verify`, and without a
    /// pin the two insecure settings keep their usual meaning.
    #[tokio::test]
    async fn production_quic_config_pin_matrix() {
        let server = self_signed("hy2.example");
        for (insecure, pin, expected) in [
            (false, server.pin.clone(), true),
            (true, server.pin.clone(), true),
            (false, "11".repeat(32), false),
            (true, "11".repeat(32), false),
            (false, String::new(), false),
            (true, String::new(), true),
        ] {
            let result = handshake(
                &client_config("hy2.example", insecure, &pin),
                server_ssl(&server, None),
            )
            .await;
            assert_eq!(
                result.is_ok(),
                expected,
                "insecure={insecure}, pin={}, result={result:?}",
                !pin.is_empty()
            );
            if let Err(e) = &result {
                assert!(is_tls_alert(e), "expected a TLS alert, got {e}");
            }
        }
    }

    /// A refused certificate closes the connection with a CRYPTO_ERROR
    /// (0x0100 + the TLS alert), not an application or transport error.
    fn is_tls_alert(err: &str) -> bool {
        err.split("error_code: ")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|code| code.parse::<u64>().ok())
            .is_some_and(|code| (0x100..0x200).contains(&code))
    }

    /// The pin is the trust decision: it also replaces hostname validation,
    /// as in mihomo's leaf-fingerprint path.
    #[tokio::test]
    async fn a_pin_replaces_hostname_validation() {
        let server = self_signed("hy2.example");
        handshake(
            &client_config("other.example", false, &server.pin),
            server_ssl(&server, None),
        )
        .await
        .expect("a pinned certificate is trusted regardless of the SNI");
    }

    /// Only the end-entity certificate is compared: an unrelated certificate
    /// appended to the chain cannot satisfy the pin.
    #[tokio::test]
    async fn appending_pinned_certificate_does_not_authenticate_another_leaf() {
        let pinned = self_signed("hy2.example");
        let other = self_signed("hy2.example");
        let result = handshake(
            &client_config("hy2.example", true, &pinned.pin),
            server_ssl(&other, Some(&pinned)),
        )
        .await;
        let err = result.expect_err("an unrelated leaf must be rejected");
        assert!(is_tls_alert(&err), "expected a TLS alert, got {err}");
    }
}
