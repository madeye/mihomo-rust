//! Integration tests for the plain HTTP/2 (`h2`) transport layer.
//!
//! All tests require `--features h2` (enforced via `required-features` in
//! `Cargo.toml`).
//!
//! # Test plan coverage (D-series)
//!
//! | ID | Description |
//! |----|-------------|
//! | D1 | `h2_round_trip_1mib`              — loopback echo, 1 MiB, byte equality |
//! | D2 | `h2_host_selection_is_uniform`    — 1000 connections × 4 hosts, every host seen |
//! | D3 | `h2_single_host_no_randomness_needed` — single host, 10 conns, no panic |
//! | D4 | `h2_path_forwarded`               — `:path` pseudo-header matches config |
//! | D5 | `h2_round_trip_with_deferred_response` — server withholds response HEADERS until the first client DATA frame (issue #377) |
//! | D6 | `h2_pending_write_retried_with_same_buffer_keeps_parking` — a parked write retried with the same remainder keeps parking |
//! | D7 | `h2_pending_write_retried_with_changed_buffer_is_rejected` — a parked write retried with different bytes is rejected, not sent stale |

mod support;

use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use meow_transport::h2::{H2Config, H2Layer};
use meow_transport::h2_common::{H2Stream, RecvState};
use meow_transport::Transport;
use meow_transport::TransportError;
use support::h2_stalled::{stalled_h2_parts, STALLED_PAYLOAD_LEN};
use support::loopback::{spawn_h2_server, spawn_h2_server_deferred_response};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

async fn assert_h2_config_error(case: &str, config: H2Config, expected: &str) {
    let (client, _server) = tokio::io::duplex(64);
    let layer = H2Layer::new(config);
    let Err(err) = layer.connect(Box::new(client)).await else {
        panic!("[{case}] invalid h2 config unexpectedly connected");
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

/// D1: `h2_round_trip_1mib`
///
/// Full loopback through the h2 server; write and read halves run concurrently
/// via `tokio::io::split` to avoid deadlocking on h2 flow-control.
#[tokio::test]
async fn h2_round_trip_1mib() {
    const PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MiB

    let (addr, _rx) = spawn_h2_server(1).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = H2Layer::new(H2Config {
        path: "/".into(),
        hosts: vec!["example.com".into()],
    });
    let stream = layer.connect(Box::new(tcp)).await.expect("h2 connect");

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

/// D2: `h2_host_selection_is_uniform`
///
/// 1000 sequential connections with `hosts = ["a","b","c","d"]`.  After all
/// connections complete, every host must have been selected at least once.
///
/// Cheap deflake of "stuck on index 0" without asserting distribution shape.
/// upstream: transport/vmess/h2.go — `cfg.Hosts[randv2.IntN(len(cfg.Hosts))]`
#[tokio::test]
async fn h2_host_selection_is_uniform() {
    let num_conns = 1000usize;
    let (addr, mut rx) = spawn_h2_server(num_conns).await;

    let layer = H2Layer::new(H2Config {
        path: "/".into(),
        hosts: vec!["a".into(), "b".into(), "c".into(), "d".into()],
    });

    let mut seen = std::collections::HashSet::new();

    for _ in 0..num_conns {
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .expect("tcp connect");
        // connect() only returns after the server has sent the 200 response,
        // which it sends AFTER the channel send — so rx.recv() is safe here.
        let _stream = layer.connect(Box::new(tcp)).await.expect("h2 connect");
        let info = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout waiting for h2 req info")
            .expect("h2 server channel closed unexpectedly");
        if let Some(auth) = info.authority {
            seen.insert(auth);
        }
        // Drop the stream — server may see an abrupt close, that is expected.
    }

    assert!(
        seen.contains("a"),
        "host 'a' not seen after {num_conns} connections"
    );
    assert!(
        seen.contains("b"),
        "host 'b' not seen after {num_conns} connections"
    );
    assert!(
        seen.contains("c"),
        "host 'c' not seen after {num_conns} connections"
    );
    assert!(
        seen.contains("d"),
        "host 'd' not seen after {num_conns} connections"
    );
}

/// D3: `h2_single_host_no_randomness_needed`
///
/// Single-element host list; 10 connections; every connection selects
/// `"example.com"`.  Guards against a modulo-by-zero or index-out-of-bounds
/// panic in the host-selection path.
#[tokio::test]
async fn h2_single_host_no_randomness_needed() {
    let (addr, mut rx) = spawn_h2_server(10).await;

    let layer = H2Layer::new(H2Config {
        path: "/".into(),
        hosts: vec!["example.com".into()],
    });

    for _ in 0..10 {
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .expect("tcp connect");
        let _stream = layer.connect(Box::new(tcp)).await.expect("h2 connect");
        let info = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(
            info.authority.as_deref(),
            Some("example.com"),
            "single host must always be selected — no random variation"
        );
    }
}

/// D4: `h2_path_forwarded`
///
/// Asserts that the `:path` pseudo-header equals the value in `H2Config.path`.
#[tokio::test]
async fn h2_path_forwarded() {
    let (addr, mut rx) = spawn_h2_server(1).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = H2Layer::new(H2Config {
        path: "/custom".into(),
        hosts: vec!["example.com".into()],
    });
    let _stream = layer.connect(Box::new(tcp)).await.expect("h2 connect");

    let info = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert_eq!(
        info.path_and_query, "/custom",
        ":path must match configured H2Config.path"
    );
}

/// Config validation rejects bad `H2Config` before any handshake bytes are
/// written: empty host list, CRLF injection in `path`, and an invalid host.
#[tokio::test]
async fn h2_rejects_invalid_config_table() {
    let cases: [(&str, H2Config, &str); 3] = [
        (
            "empty hosts",
            H2Config {
                path: "/".into(),
                hosts: vec![],
            },
            "hosts",
        ),
        (
            "crlf injection in path",
            H2Config {
                path: "/ok\r\nx: y".into(),
                hosts: vec!["example.com".into()],
            },
            "invalid request config",
        ),
        (
            "invalid host with space",
            H2Config {
                path: "/".into(),
                hosts: vec!["bad host".into()],
            },
            "invalid request config",
        ),
    ];

    for (case, config, expected) in cases {
        assert_h2_config_error(case, config, expected).await;
    }
}

// ─── D5: Response HEADERS withheld until the first client DATA frame ──────────

/// D5: `h2_round_trip_with_deferred_response`
///
/// Regression test for issue #377 (h2 half of the gRPC deadlock). The peer's
/// handler reads the client's first DATA frame before writing anything, so
/// `H2Layer::connect` must not await the response — it has to return once the
/// request HEADERS are queued and resolve the response on the first read.
#[tokio::test]
async fn h2_round_trip_with_deferred_response() {
    let (addr, _info_rx) = spawn_h2_server_deferred_response(1).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = H2Layer::new(H2Config {
        path: "/".into(),
        hosts: vec!["example.com".into()],
    });
    let mut stream = tokio::time::timeout(Duration::from_secs(5), layer.connect(Box::new(tcp)))
        .await
        .expect("connect must not block on the server's response")
        .expect("h2 connect");

    stream.write_all(b"ping").await.expect("write");
    stream.flush().await.expect("flush");

    let mut got = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut got))
        .await
        .expect("echo must arrive once the server answers")
        .expect("read_exact");
    assert_eq!(
        &got, b"ping",
        "round-trip bytes must survive the deferred response"
    );
}

// ─── D6/D7: write-cancellation contract on the shared H2 stream ──────────────

/// Open one client stream against a stalled server (harness shared with the
/// `h2_common` unit tests via `support::h2_stalled`): the request body is
/// never read, so the client's send window is never replenished and the
/// write parks with the payload stashed in the stream's `pending_write`.
async fn stalled_h2_stream() -> (H2Stream, tokio::task::JoinHandle<()>) {
    let (send_stream, response, server) = stalled_h2_parts().await;
    (H2Stream::new(send_stream, RecvState::new(response)), server)
}

/// Drive `poll_write` until the send window is exhausted; returns how many
/// bytes of `payload` the peer accepted before the write parked.
async fn write_until_pending(stream: &mut H2Stream, payload: &[u8]) -> usize {
    let mut sent = 0usize;
    loop {
        let progress = poll_fn(|cx| {
            Poll::Ready(
                match Pin::new(&mut *stream).poll_write(cx, &payload[sent..]) {
                    Poll::Pending => None,
                    Poll::Ready(Ok(n)) => Some(n),
                    Poll::Ready(Err(e)) => panic!("unexpected write error: {e}"),
                },
            )
        })
        .await;
        match progress {
            Some(n) => {
                sent += n;
                assert!(
                    sent < payload.len(),
                    "the peer accepted the whole payload; the write never parked"
                );
            }
            None => return sent,
        }
    }
}

/// D6: retrying a parked write with the same remainder is the contract-
/// abiding case and must keep parking, not trip the changed-buffer guard.
#[tokio::test]
async fn h2_pending_write_retried_with_same_buffer_keeps_parking() {
    let (mut stream, _server) = stalled_h2_stream().await;
    let payload = vec![b'a'; STALLED_PAYLOAD_LEN];
    let sent = write_until_pending(&mut stream, &payload).await;

    for _ in 0..3 {
        let polled = poll_fn(|cx| {
            Poll::Ready(
                match Pin::new(&mut stream).poll_write(cx, &payload[sent..]) {
                    Poll::Pending => None,
                    other => Some(other),
                },
            )
        })
        .await;
        assert!(
            polled.is_none(),
            "same-buffer retry must stay Pending, got {polled:?}"
        );
    }
}

/// D7: a parked write retried with *different* bytes must be rejected.
/// Sending the stashed payload under the new buffer's reported length would
/// put stale bytes on the wire and silently drop the caller's (issue seen in
/// the mux stack, cf. #407).
#[tokio::test]
async fn h2_pending_write_retried_with_changed_buffer_is_rejected() {
    let (mut stream, _server) = stalled_h2_stream().await;
    let payload = vec![b'a'; STALLED_PAYLOAD_LEN];
    let sent = write_until_pending(&mut stream, &payload).await;

    // Same length as the stashed remainder: the guard must compare content,
    // not just size.  One-shot poll (Pending surfaces as None) so a guard
    // regression to accept-and-park fails the test instead of hanging it.
    let decoy = vec![b'b'; STALLED_PAYLOAD_LEN - sent];
    let error = poll_fn(|cx| {
        Poll::Ready(match Pin::new(&mut stream).poll_write(cx, &decoy) {
            Poll::Pending => None,
            Poll::Ready(result) => Some(result),
        })
    })
    .await
    .expect("the changed-buffer guard must resolve in one poll, not park")
    .expect_err("a changed buffer must be rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("write buffer changed"),
        "unexpected error: {error}"
    );
}
