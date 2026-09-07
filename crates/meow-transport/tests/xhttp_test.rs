//! Integration tests for the XHTTP (`xhttp`) transport layer.
//!
//! All tests require `--features xhttp` (enforced via `required-features` in
//! `Cargo.toml`).

mod support;

use std::collections::HashSet;
use std::time::Duration;

use meow_transport::xhttp::{XhttpConfig, XhttpLayer};
use meow_transport::{Transport, TransportError};
use support::loopback::{
    spawn_h2_server, spawn_h2_server_deferred_response, spawn_h2_server_with_body_result,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn assert_xhttp_config_error(case: &str, config: XhttpConfig, expected: &str) {
    let (client, server) = tokio::io::duplex(64);
    drop(server);
    let layer = XhttpLayer::new(config);
    let Err(err) = layer.connect(Box::new(client)).await else {
        panic!("[{case}] invalid xhttp config unexpectedly connected");
    };
    match err {
        TransportError::Config(msg) => {
            assert!(
                msg.contains(expected),
                "[{case}] expected config error containing {expected:?}, got: {msg}"
            );
        }
        other => panic!("[{case}] expected TransportError::Config, got: {other:?}"),
    }
}

/// D1: Full loopback echo test over XHTTP (1 MiB bidirectional).
#[tokio::test]
async fn xhttp_round_trip_1mib() {
    const PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MiB

    let (addr, mut rx) = spawn_h2_server(1).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = XhttpLayer::new(XhttpConfig {
        path: "/xhttp-test?ed=1".into(),
        hosts: vec!["example.com".into()],
        x_padding_bytes: Some((128, 128)),
        ..Default::default()
    });
    let stream = layer.connect(Box::new(tcp)).await.expect("xhttp connect");

    let req_info = rx.recv().await.expect("server received request info");
    assert_eq!(req_info.method, "POST");
    assert_eq!(req_info.scheme.as_deref(), Some("https"));
    assert_eq!(req_info.path_and_query, "/xhttp-test/?ed=1");
    assert_eq!(req_info.authority.as_deref(), Some("example.com"));
    assert_eq!(
        req_info
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/grpc")
    );
    let referer = req_info
        .headers
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .expect("default padding Referer");
    let padding = referer
        .strip_prefix("https://example.com/xhttp-test/?x_padding=")
        .expect("Referer must replace the original query with x_padding");
    assert_eq!(padding.len(), 128);
    assert!(padding.bytes().all(|b| b == b'X'));
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    let send_buf: Vec<u8> = (0u8..=255).cycle().take(PAYLOAD_SIZE).collect();
    let send_clone = send_buf.clone();

    // Write task: send all bytes then signal EOS (shutdown).
    let write_task = tokio::spawn(async move {
        write_half
            .write_all(&send_clone)
            .await
            .expect("write_all 1 MiB");
        write_half.shutdown().await.expect("shutdown");
    });

    // Read until EOF — server echoes all bytes before closing its response stream.
    let mut recv_buf = Vec::with_capacity(PAYLOAD_SIZE);
    read_half
        .read_to_end(&mut recv_buf)
        .await
        .expect("read_to_end 1 MiB");

    write_task.await.expect("write task");

    assert_eq!(
        recv_buf.len(),
        PAYLOAD_SIZE,
        "received byte count must match sent byte count"
    );
    assert_eq!(recv_buf, send_buf, "round-trip bytes must be identical");
}

/// D2: Multiple hosts selection is uniform.
#[tokio::test]
async fn xhttp_host_selection_is_uniform() {
    let num_conns = 60usize;
    let (addr, mut rx) = spawn_h2_server(num_conns).await;

    let layer = XhttpLayer::new(XhttpConfig {
        path: "/".into(),
        hosts: vec![
            "a.com".into(),
            "b.com".into(),
            "c.com".into(),
            "d.com".into(),
        ],
        ..Default::default()
    });

    let mut seen = HashSet::new();

    for _ in 0..num_conns {
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .expect("tcp connect");

        let _stream = layer.connect(Box::new(tcp)).await.expect("xhttp connect");

        let info = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout waiting for h2 req info")
            .expect("server channel closed");
        if let Some(auth) = info.authority {
            seen.insert(auth);
        }
    }

    assert_eq!(
        seen.len(),
        4,
        "all 4 hosts must have been selected across {num_conns} connections; seen: {seen:?}"
    );
}

/// D3: Custom headers and no-grpc-header options.
#[tokio::test]
async fn xhttp_headers_and_no_grpc_header() {
    let (addr, mut rx) = spawn_h2_server(1).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = XhttpLayer::new(XhttpConfig {
        path: "/custom".into(),
        hosts: vec!["custom.host".into()],
        extra_headers: vec![("x-custom-test".into(), "val123".into())],
        no_grpc_header: true,
        x_padding_bytes: None,
        ..Default::default()
    });

    let stream = layer.connect(Box::new(tcp)).await.expect("xhttp connect");

    let req_info = rx.recv().await.expect("server received request info");
    assert_eq!(req_info.method, "POST");
    assert_eq!(req_info.scheme.as_deref(), Some("https"));
    assert_eq!(req_info.path_and_query, "/custom/");
    assert_eq!(req_info.authority.as_deref(), Some("custom.host"));
    assert_eq!(
        req_info
            .headers
            .get("x-custom-test")
            .and_then(|v| v.to_str().ok()),
        Some("val123")
    );
    assert!(req_info.headers.get("content-type").is_none());
    assert!(req_info.headers.get("referer").is_none());

    drop(stream);
}

/// D4: Deferred response does not deadlock (issue #377).
#[tokio::test]
async fn xhttp_round_trip_with_deferred_response() {
    let (addr, mut rx) = spawn_h2_server_deferred_response(1).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = XhttpLayer::new(XhttpConfig {
        path: "/deferred".into(),
        hosts: vec!["deferred.host".into()],
        ..Default::default()
    });

    // connect() must return immediately without waiting for server response
    let mut stream = layer.connect(Box::new(tcp)).await.expect("xhttp connect");

    let _info = rx.recv().await.expect("recv H2ReqInfo");

    // Write first data frame to unlock the server
    stream.write_all(b"ping").await.expect("write ping");

    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.expect("read pong");
    assert_eq!(&buf, b"ping");
}

/// D5: Dropping the stream preserves queued payload and sends clean EOS.
#[tokio::test]
async fn xhttp_drop_sends_clean_eos() {
    let (addr, body_rx) = spawn_h2_server_with_body_result().await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = XhttpLayer::new(XhttpConfig::default());
    let mut stream = layer.connect(Box::new(tcp)).await.expect("xhttp connect");

    stream
        .write_all(b"payload-before-drop")
        .await
        .expect("write");
    drop(stream);

    let received = tokio::time::timeout(Duration::from_secs(5), body_rx)
        .await
        .expect("server must observe request-body termination")
        .expect("server must report body result")
        .expect("drop must send clean EOS instead of resetting the stream");
    assert_eq!(received, b"payload-before-drop");
}

/// D6: Config validation errors.
#[tokio::test]
async fn xhttp_config_validation() {
    assert_xhttp_config_error(
        "empty_hosts",
        XhttpConfig {
            hosts: vec![],
            ..Default::default()
        },
        "hosts must not be empty",
    )
    .await;

    assert_xhttp_config_error(
        "invalid_path",
        XhttpConfig {
            path: "relative".into(),
            ..Default::default()
        },
        "path must start with '/'",
    )
    .await;

    assert_xhttp_config_error(
        "invalid_mode",
        XhttpConfig {
            mode: "packet-up".into(),
            ..Default::default()
        },
        "unsupported mode",
    )
    .await;

    assert_xhttp_config_error(
        "invalid_padding",
        XhttpConfig {
            x_padding_bytes: Some((500, 100)),
            ..Default::default()
        },
        "min (500) cannot exceed max (100)",
    )
    .await;
}

/// A peer that never sends response headers must not retain the driver forever.
#[tokio::test]
async fn xhttp_drop_bounds_stalled_driver_lifetime() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local address");
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.expect("accept");
        let mut bytes = Vec::new();
        tcp.read_to_end(&mut bytes)
            .await
            .expect("client closes TCP");
        assert!(bytes.starts_with(b"PRI * HTTP/2.0"));
    });
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let stream = XhttpLayer::new(XhttpConfig::default())
        .connect(Box::new(tcp))
        .await
        .expect("lazy XHTTP connect");
    drop(stream);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("stalled driver must terminate after drop")
        .expect("server task");
}
