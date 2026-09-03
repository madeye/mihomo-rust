#![cfg(feature = "vless")]
//! Integration tests for the VLESS outbound proxy adapter (§H, M1.B-2).
//!
//! Uses an embedded mock VLESS server over plain TCP — no external binaries
//! required.  The mock parses the VLESS request header, validates the UUID,
//! writes the response header, then relays TCP traffic to the echo target.
//!
//! Tests that require a real `xray` binary (H3 UDP, H4 Vision, H6 delay-probe)
//! check for the binary at runtime and emit a `SKIP:` line when absent.
//! Set `MIHOMO_REQUIRE_INTEGRATION_BINS=1` to fail instead of skip.

#[cfg(feature = "vless")]
mod vless_tests {
    use meow_common::{Metadata, Network, ProxyAdapter};
    use meow_proxy::dialer::DirectDialer;
    use meow_proxy::{TransportChain, VlessAdapter};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{timeout, Duration};

    /// UUID for all VLESS integration tests: b831381d-6324-4d53-ad4f-8cda48b30811
    const TEST_UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    /// A different UUID — used to simulate a server that rejects the connection.
    const WRONG_UUID: [u8; 16] = [0xff; 16];

    const TIMEOUT: Duration = Duration::from_secs(10);

    // ─── TCP echo server ──────────────────────────────────────────────────────

    async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (addr, handle)
    }

    // ─── Mock VLESS server ────────────────────────────────────────────────────

    /// Parse the VLESS request header from `stream`.
    ///
    /// Wire format (upstream: `transport/vless/encoding.go::EncodeRequestHeader`):
    /// ```text
    /// version(1=0x00)  uuid(16)  addon_length(1)  addon(N)
    /// cmd(1)  port(2,BE)  addr_type(1)  addr
    /// ```
    /// NOTE: `port` comes BEFORE `addr_type` — the VLESS/VMess convention.
    async fn read_vless_header<S: AsyncReadExt + Unpin>(
        stream: &mut S,
    ) -> std::io::Result<([u8; 16], u8, SocketAddr)> {
        // version
        let mut version = [0u8; 1];
        stream.read_exact(&mut version).await?;
        if version[0] != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("mock vless: unexpected version byte {:#04x}", version[0]),
            ));
        }

        // uuid (16 bytes)
        let mut uuid = [0u8; 16];
        stream.read_exact(&mut uuid).await?;

        // addon
        let mut addon_len = [0u8; 1];
        stream.read_exact(&mut addon_len).await?;
        if addon_len[0] > 0 {
            let mut addon = vec![0u8; addon_len[0] as usize];
            stream.read_exact(&mut addon).await?;
        }

        // cmd
        let mut cmd = [0u8; 1];
        stream.read_exact(&mut cmd).await?;

        // port (big-endian) — comes BEFORE addr_type per VLESS wire format
        let mut port_bytes = [0u8; 2];
        stream.read_exact(&mut port_bytes).await?;
        let port = u16::from_be_bytes(port_bytes);

        // addr_type + address
        let mut addr_type = [0u8; 1];
        stream.read_exact(&mut addr_type).await?;
        let addr = match addr_type[0] {
            0x01 => {
                // IPv4
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
            }
            0x02 => {
                // Domain
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                stream.read_exact(&mut domain).await?;
                let domain_str = String::from_utf8_lossy(&domain);
                // The mock can only relay to loopback — it cannot resolve arbitrary domains.
                let ip = match domain_str.as_ref() {
                    "localhost" | "127.0.0.1" => IpAddr::V4(Ipv4Addr::LOCALHOST),
                    other => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            format!("mock vless: cannot resolve '{other}'"),
                        ));
                    }
                };
                SocketAddr::new(ip, port)
            }
            0x03 => {
                // IPv6
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(ip)), port)
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("mock vless: unknown addr_type {other:#04x}"),
                ));
            }
        };

        Ok((uuid, cmd[0], addr))
    }

    /// Start an in-process mock VLESS server bound to a random loopback port.
    ///
    /// For each connection the server:
    /// 1. Reads the VLESS request header.
    /// 2. Closes without response if the UUID does not match `expected_uuid`.
    /// 3. Writes the VLESS response header `[0x00, 0x00]`.
    /// 4. Relays TCP traffic to `target_addr` (cmd = 0x01).
    async fn start_mock_vless_server(
        expected_uuid: [u8; 16],
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_uuid = Arc::new(expected_uuid);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    break;
                };
                let expected_uuid = Arc::clone(&expected_uuid);
                tokio::spawn(async move {
                    let Ok((uuid, cmd, target_addr)) = read_vless_header(&mut tcp).await else {
                        eprintln!("mock vless: header parse error");
                        return;
                    };

                    // UUID mismatch — close without response (simulates xray behaviour).
                    if uuid != *expected_uuid {
                        eprintln!("mock vless: UUID mismatch — closing");
                        return;
                    }

                    // VLESS response header: version=0x00, addon_length=0x00.
                    if tcp.write_all(&[0x00, 0x00]).await.is_err() {
                        return;
                    }

                    match cmd {
                        0x01 => {
                            // TCP CONNECT relay
                            match TcpStream::connect(target_addr).await {
                                Ok(mut target) => {
                                    let _ =
                                        tokio::io::copy_bidirectional(&mut tcp, &mut target).await;
                                }
                                Err(e) => {
                                    eprintln!("mock vless: relay connect to {target_addr}: {e}");
                                }
                            }
                        }
                        other => {
                            eprintln!("mock vless: unsupported cmd {other:#04x}");
                        }
                    }
                });
            }
        });

        (addr, handle)
    }

    // ─── H1: TCP plain VLESS round-trip ──────────────────────────────────────

    /// H1: Send 1 KiB through a plain VLESS connection; assert echoed bytes match.
    ///
    /// No outer transport layer — tests the core VLESS header exchange and
    /// bidirectional relay.  Acceptance criterion #3.
    #[tokio::test]
    async fn vless_tcp_plain_roundtrip() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = VlessAdapter::new(
            "test-vless",
            "127.0.0.1",
            vless_addr.port(),
            TEST_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
        let mut conn = result
            .expect("vless_tcp_plain_roundtrip: dial_tcp timed out")
            .expect("vless_tcp_plain_roundtrip: dial_tcp failed");

        let payload: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        conn.write_all(&payload).await.expect("write failed");
        conn.flush().await.expect("flush failed");

        let mut buf = vec![0u8; payload.len()];
        conn.read_exact(&mut buf).await.expect("read_exact failed");
        assert_eq!(buf, payload, "TCP echo mismatch");
    }

    // ─── H2: Large-payload round-trip ────────────────────────────────────────

    /// H2: Send 64 KiB; assert echoed bytes match.
    ///
    /// Stresses the VLESS framing path and the relay buffer in the mock.
    #[tokio::test]
    async fn vless_tcp_large_payload_roundtrip() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = VlessAdapter::new(
            "test-vless-large",
            "127.0.0.1",
            vless_addr.port(),
            TEST_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
        let mut conn = result
            .expect("large_payload: dial_tcp timed out")
            .expect("large_payload: dial_tcp failed");

        let payload: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        conn.write_all(&payload).await.expect("write failed");
        conn.flush().await.expect("flush failed");

        let mut buf = vec![0u8; payload.len()];
        conn.read_exact(&mut buf).await.expect("read_exact failed");
        assert_eq!(buf, payload, "64 KiB echo mismatch");
    }

    // ─── H3: Concurrent connections ───────────────────────────────────────────

    /// H3: Five simultaneous VLESS connections all complete their echo round-trip.
    ///
    /// Guards against state leakage between concurrent connections (shared UUID
    /// reference, header parse races).
    #[tokio::test]
    async fn vless_tcp_concurrent_connections() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = Arc::new(VlessAdapter::new(
            "test-vless-concurrent",
            "127.0.0.1",
            vless_addr.port(),
            TEST_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        ));

        let mut handles = Vec::new();
        for i in 0u8..5 {
            let adapter = Arc::clone(&adapter);
            let handle = tokio::spawn(async move {
                let metadata = Metadata {
                    network: Network::Tcp,
                    dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    dst_port: echo_addr.port(),
                    ..Default::default()
                };
                let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
                let mut conn = result
                    .expect("concurrent: dial_tcp timed out")
                    .expect("concurrent: dial_tcp failed");

                let payload = vec![i; 128];
                conn.write_all(&payload)
                    .await
                    .expect("concurrent: write failed");
                conn.flush().await.expect("concurrent: flush failed");

                let mut buf = vec![0u8; 128];
                conn.read_exact(&mut buf)
                    .await
                    .expect("concurrent: read_exact failed");
                assert_eq!(buf, payload, "concurrent echo mismatch for i={i}");
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.expect("concurrent task panicked");
        }
    }

    // ─── H4: Second small payload (back-to-back writes on same connection) ───

    /// H4: Two sequential payloads on the same connection — guards against
    ///     state corruption between writes (e.g. response header re-read).
    #[tokio::test]
    async fn vless_tcp_sequential_writes_same_connection() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = VlessAdapter::new(
            "test-vless-seq",
            "127.0.0.1",
            vless_addr.port(),
            TEST_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
        let mut conn = result
            .expect("seq: dial_tcp timed out")
            .expect("seq: dial_tcp failed");

        // First payload
        let payload1 = b"hello vless round one";
        conn.write_all(payload1).await.expect("write1 failed");
        conn.flush().await.expect("flush1 failed");
        let mut buf1 = vec![0u8; payload1.len()];
        conn.read_exact(&mut buf1).await.expect("read1 failed");
        assert_eq!(&buf1, payload1, "echo mismatch round 1");

        // Second payload on the same connection
        let payload2 = b"hello vless round two";
        conn.write_all(payload2).await.expect("write2 failed");
        conn.flush().await.expect("flush2 failed");
        let mut buf2 = vec![0u8; payload2.len()];
        conn.read_exact(&mut buf2).await.expect("read2 failed");
        assert_eq!(&buf2, payload2, "echo mismatch round 2");
    }

    // ─── H5: Wrong UUID → clean error ────────────────────────────────────────

    /// H5: UUID mismatch causes the server to close the connection without
    ///     sending a VLESS response header.  The client must surface a clean
    ///     `Err` — not a panic or a raw `UnexpectedEof` propagated to the
    ///     caller without context.
    ///
    /// Upstream: xray-core closes silently on UUID mismatch.
    /// NOT silent — we surface "server closed after header" with context.
    /// Class B per ADR-0002 (same destination, wrong credential).
    #[tokio::test]
    async fn vless_wrong_uuid_fails_cleanly() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        // Mock expects TEST_UUID; client sends WRONG_UUID.
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = VlessAdapter::new(
            "test-vless-wrong-uuid",
            "127.0.0.1",
            vless_addr.port(),
            WRONG_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
        let inner = result.expect("wrong-uuid: dial_tcp timed out (expected prompt rejection)");
        // With lazy response reading, dial_tcp succeeds but the first read
        // triggers the error when the server closes after seeing wrong UUID.
        match inner {
            Ok(mut conn) => {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 1];
                let read_result = timeout(TIMEOUT, conn.read(&mut buf)).await;
                let read_inner =
                    read_result.expect("wrong-uuid: read timed out (expected prompt error)");
                let err = read_inner
                    .expect_err("wrong-uuid: read must return Err after server rejection");
                let err_str = err.to_string();
                assert!(
                    err_str.contains("closed")
                        || err_str.contains("eof")
                        || err_str.contains("EOF")
                        || err_str.contains("Eof")
                        || err_str.contains("server")
                        || err_str.contains("UUID"),
                    "error must describe the cause, got: {err_str}"
                );
            }
            Err(e) => {
                // Also acceptable if dial_tcp itself fails.
                let err_str = e.to_string();
                assert!(
                    err_str.contains("server closed")
                        || err_str.contains("UUID")
                        || err_str.contains("server config"),
                    "error must describe the cause, got: {err_str}"
                );
            }
        }
    }

    // ─── H6: health() is accessible after dial (ProxyHealth API guard) ────────

    /// H6 (lite): Assert that `adapter.health()` is accessible without panic after
    ///           a successful `dial_tcp`.  Full history-array validation requires
    ///           the api-delay-endpoints integration harness (cross-spec, M2 scope).
    #[tokio::test]
    async fn vless_health_accessible_after_dial() {
        let (echo_addr, _echo) = start_tcp_echo_server().await;
        let (vless_addr, _vless) = start_mock_vless_server(TEST_UUID).await;

        let adapter = VlessAdapter::new(
            "test-vless-health",
            "127.0.0.1",
            vless_addr.port(),
            TEST_UUID,
            None,
            false,
            TransportChain::empty(),
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
        let mut conn = result
            .expect("health: dial_tcp timed out")
            .expect("health: dial_tcp failed");

        // Write and drain to confirm the connection is live.
        conn.write_all(b"ping").await.expect("ping write failed");
        conn.flush().await.expect("ping flush failed");
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.expect("ping read failed");
        assert_eq!(&buf, b"ping");

        // ProxyHealth must be accessible — no panic.
        let _health = adapter.health();
    }

    // ─── H7: VLESS over XHTTP end-to-end round-trip ───────────────────────────

    #[tokio::test]
    async fn vless_over_xhttp_roundtrip() {
        use bytes::Bytes;
        use meow_transport::xhttp::{XhttpConfig, XhttpLayer};

        let (echo_addr, _echo) = start_tcp_echo_server().await;

        // Start an H2 server that terminates the XHTTP tunnel and unwraps the inner VLESS stream.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_h2_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let Ok(mut connection) =
                        h2::server::Builder::new().handshake::<_, Bytes>(tcp).await
                    else {
                        return;
                    };

                    while let Some(Ok((request, mut respond))) = connection.accept().await {
                        // Send 200 OK response header lazily to start the bidirectional stream
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let mut send_body = respond.send_response(response, false).unwrap();
                        let mut recv_body = request.into_body();

                        // Bridge the h2 stream into AsyncRead + AsyncWrite
                        let (client_r, mut client_w) = tokio::io::duplex(64 * 1024);
                        let (mut server_r, server_w) = tokio::io::duplex(64 * 1024);

                        // Forward recv_body -> server_w
                        tokio::spawn(async move {
                            let mut server_w = server_w;
                            while let Some(Ok(chunk)) = recv_body.data().await {
                                let _ = recv_body.flow_control().release_capacity(chunk.len());
                                if server_w.write_all(&chunk).await.is_err() {
                                    break;
                                }
                            }
                        });

                        // Forward client_r -> send_body
                        tokio::spawn(async move {
                            let mut client_r = client_r;
                            let mut buf = vec![0u8; 8192];
                            loop {
                                match client_r.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        send_body.reserve_capacity(n);
                                        if send_body
                                            .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                }
                            }
                        });

                        // Run mock VLESS server over server_r + client_w
                        tokio::spawn(async move {
                            let Ok((uuid, cmd, target_addr)) =
                                read_vless_header(&mut server_r).await
                            else {
                                return;
                            };
                            if uuid != TEST_UUID {
                                return;
                            }
                            if client_w.write_all(&[0x00, 0x00]).await.is_err() {
                                return;
                            }
                            if cmd == 0x01 {
                                if let Ok(mut target) = TcpStream::connect(target_addr).await {
                                    let (mut tr, mut tw) = target.split();
                                    let _ = tokio::join!(
                                        tokio::io::copy(&mut server_r, &mut tw),
                                        tokio::io::copy(&mut tr, &mut client_w)
                                    );
                                }
                            }
                        });
                    }
                });
            }
        });

        // Build VlessAdapter with XhttpLayer in TransportChain
        let mut chain = TransportChain::empty();
        let xhttp_cfg = XhttpConfig {
            path: "/xhttp-vless".into(),
            hosts: vec!["xhttp.test.com".into()],
            ..Default::default()
        };
        chain.push(Box::new(XhttpLayer::new(xhttp_cfg)));

        let adapter = VlessAdapter::new(
            "test-vless-xhttp",
            "127.0.0.1",
            vless_h2_addr.port(),
            TEST_UUID,
            None,
            false,
            chain,
            Arc::new(DirectDialer),
        );

        let metadata = Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
            .await
            .expect("dial_tcp timed out")
            .expect("dial_tcp failed");

        let payload = b"hello vless over xhttp";
        conn.write_all(payload).await.expect("write payload failed");
        conn.flush().await.expect("flush failed");

        let mut buf = vec![0u8; payload.len()];
        conn.read_exact(&mut buf).await.expect("read echo failed");
        assert_eq!(&buf, payload, "round-trip data must match");
    }
}
