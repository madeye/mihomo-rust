//! Integration tests for the XHTTP (`xhttp`) transport layer.
//!
//! All tests require `--features xhttp` (enforced via `required-features` in
//! `Cargo.toml`).

mod support;

use std::collections::HashSet;
use std::time::Duration;

use meow_transport::xhttp::{XhttpConfig, XhttpLayer};
use meow_transport::{Transport, TransportError};
use support::loopback::{spawn_h2_server, spawn_h2_server_deferred_response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn assert_xhttp_config_error(case: &str, config: XhttpConfig, expected: &str) {
    let (client, _server) = tokio::io::duplex(64);
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
        path: "/xhttp-test".into(),
        hosts: vec!["example.com".into()],
        ..Default::default()
    });
    let stream = layer.connect(Box::new(tcp)).await.expect("xhttp connect");

    let req_info = rx.recv().await.expect("server received request info");
    assert_eq!(req_info.method, "POST");
    assert_eq!(req_info.path, "/xhttp-test");
    assert_eq!(req_info.authority.as_deref(), Some("example.com"));
    assert_eq!(
        req_info
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/grpc")
    );
    assert!(req_info.headers.contains_key("referer"));

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
    assert_eq!(req_info.path, "/custom");
    assert_eq!(req_info.authority.as_deref(), Some("custom.host"));
    assert_eq!(
        req_info
            .headers
            .get("x-custom-test")
            .and_then(|v| v.to_str().ok()),
        Some("val123")
    );
    // no_grpc_header = true => content-type should not be application/grpc
    assert!(req_info.headers.get("content-type").is_none());
    // x_padding_bytes = None => no referer header generated
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

/// D5: Dropping stream aborts the background connection driver.
#[tokio::test]
async fn xhttp_drop_aborts_driver() {
    let (addr, _rx) = spawn_h2_server(1).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = XhttpLayer::new(XhttpConfig::default());
    let stream = layer.connect(Box::new(tcp)).await.expect("xhttp connect");

    // Drop the stream
    drop(stream);

    // Yield to let tokio run any aborted task cleanup
    tokio::time::sleep(Duration::from_millis(50)).await;
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
