/// Regression test for commit 0f95043 — aborted `handle_tcp` must not leak
/// a `Statistics` entry.
///
/// Before the fix, `close_connection` was the last line of `handle_tcp`.  Any
/// abort (task cancel, iOS idle sweeper, JoinHandle::abort) skipped that line,
/// leaving the entry in `Statistics.connections` forever.  The RAII
/// `ConnectionGuard` ensures `close_connection` runs on every exit path
/// including `Future` cancellation.
///
/// Test structure:
///   1. Spin up a local echo server (keeps the relay alive by holding the far
///      side of the connection open — no data sent, so the relay blocks).
///   2. Build a `Tunnel` in Direct mode and open a real loopback TCP pair.
///      Give one half to `handle_tcp` as the inbound client stream.
///   3. Poll `Statistics.active_connection_count()` until the entry appears
///      (the relay has registered the connection).
///   4. Abort the task via `JoinHandle::abort()`.
///   5. Assert the count returns to 0 within a 200ms wall-clock slack window.
///
/// Note: this test uses wall time + sleep (NOT `tokio::time::pause`) because
/// `Statistics` uses `DashMap` and the relay path may touch real kernel syscalls
/// (TCP sockets, `DuplexStream` internals) that `pause()` does not virtualise.
use meow_common::{ConnType, Metadata, Network};
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::{tcp::handle_tcp, Tunnel};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Build a minimal `Tunnel` in `Direct` mode.
fn direct_tunnel() -> Tunnel {
    let hosts = DomainTrie::new();
    let resolver = Arc::new(Resolver::new(
        vec![],
        vec![],
        meow_common::DnsMode::Normal,
        hosts,
        false,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    tunnel.set_mode(meow_common::TunnelMode::Direct);
    tunnel
}

/// Bind a loopback listener, accept one connection, and return both halves.
///
/// Returns `(server_side, client_side)`.  The server side is what `handle_tcp`
/// receives as the inbound client stream.  The client side is held by the test
/// to keep the peer alive (and thus block the relay).
async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accept_res, connect_res) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    let (server, _) = accept_res.unwrap();
    let client = connect_res.unwrap();
    (server, client)
}

/// Spawn a local TCP listener that accepts one connection and holds it open
/// (sends nothing, reads nothing).  Returns the bound `SocketAddr`.
///
/// `handle_tcp` in Direct mode will dial this address; `copy_bidirectional`
/// will then block waiting for data from either side, giving us a stable
/// window in which to abort the task.
async fn spawn_idle_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Accept and hold the connection without reading or writing.
        // The task is implicitly dropped when the test finishes.
        let Ok((_stream, _)) = listener.accept().await else {
            return;
        };
        // Sleep long enough that the relay stays blocked for the test duration.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });
    addr
}

#[tokio::test]
async fn aborted_handle_tcp_does_not_leak_statistics_entry() {
    // 1. Idle remote server — relay will block in copy_bidirectional waiting
    //    for data that never arrives.
    let remote_addr = spawn_idle_server().await;

    // 2. Build tunnel and inbound loopback pair.
    let tunnel = direct_tunnel();
    let (server_stream, mut _client_stream) = loopback_pair().await;

    // 3. Metadata pointing at the idle server.
    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        dst_ip: Some(remote_addr.ip()),
        dst_port: remote_addr.port(),
        ..Default::default()
    };

    let stats = Arc::clone(tunnel.statistics());
    let inner = Arc::clone(tunnel.inner());

    // 4. Spawn handle_tcp — it will dial the idle server, register in stats,
    //    then block in copy_bidirectional.
    let handle = tokio::spawn(async move {
        handle_tcp(&inner, Box::new(server_stream), metadata).await;
    });

    // 5. Poll until the entry appears (up to 1 s).  The dial + registration
    //    should complete in well under 100 ms on loopback.
    let registered = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if stats.active_connection_count() > 0 {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    };
    assert!(
        registered,
        "handle_tcp did not register a Statistics entry within 1s"
    );
    assert_eq!(
        stats.active_connection_count(),
        1,
        "expected exactly one active connection before abort"
    );

    // 6. Abort the task — this cancels the future mid-relay.
    handle.abort();

    // 7. Wait up to 200ms for the RAII guard to fire (wall-clock slack, not
    //    tokio::time::pause — see [[feedback_tokio_pause_syscalls]]).
    let cleaned = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        loop {
            if stats.active_connection_count() == 0 {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    };
    assert!(
        cleaned,
        "Statistics entry not removed within 200ms after JoinHandle::abort — \
         RAII guard may have regressed (commit 0f95043)"
    );

    // Close the client side so the server task can clean up.
    let _ = _client_stream.shutdown().await;
}

#[tokio::test]
async fn close_connection_cancels_pending_proxy_handshake() {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let tunnel = direct_tunnel();
        let raw = meow_config::raw::RawConfig {
            rules: Some(vec!["MATCH,REJECT-DROP".into()]),
            ..Default::default()
        };
        let (proxies, rules) = meow_config::rebuild_from_raw(&raw).unwrap();
        tunnel.update_proxies(proxies);
        tunnel.update_rules(rules);
        tunnel.set_mode(meow_common::TunnelMode::Rule);
        let (server, mut client) = loopback_pair().await;
        let inner = Arc::clone(tunnel.inner());
        let task = tokio::spawn(async move {
            handle_tcp(
                &inner,
                Box::new(server),
                Metadata {
                    network: Network::Tcp,
                    dst_ip: Some("127.0.0.1".parse().unwrap()),
                    dst_port: 12345,
                    ..Default::default()
                },
            )
            .await;
        });
        // REJECT-DROP's dial stalls for 60 s, keeping us in the dial phase.
        while tunnel.statistics().active_connection_count() == 0 {
            tokio::task::yield_now().await;
        }
        assert!(!task.is_finished());
        let id = tunnel.statistics().active_connections()[0].id;
        tunnel.statistics().close_connection(id);
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
        task.await.unwrap();
    })
    .await
    .expect("close request failed to cancel pending dial");
}

#[tokio::test]
async fn close_connection_cancels_blocked_prefix_write() {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let tunnel = direct_tunnel();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dst = upstream.local_addr().unwrap();
        let (mut server, mut client) = loopback_pair().await;
        let inner = Arc::clone(tunnel.inner());
        let task = tokio::spawn(async move {
            // Larger than the loopback TCP buffers: the peer reads one byte,
            // leaving write_all pending before the relay can start.
            let prefix = vec![b'x'; 16 * 1024 * 1024];
            meow_tunnel::route_inbound_tcp(
                &inner,
                &mut server,
                Metadata {
                    dst_ip: Some(dst.ip()),
                    dst_port: dst.port(),
                    ..Default::default()
                },
                &prefix,
            )
            .await;
        });
        let (mut remote, _) = upstream.accept().await.unwrap();
        assert_eq!(remote.read_u8().await.unwrap(), b'x');
        let info = tunnel.statistics().active_connections().pop().unwrap();
        assert_eq!(
            info.counters.upload_bytes(),
            0,
            "prefix write must still be pending"
        );
        tunnel.statistics().close_connection(info.id);
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
        task.await.unwrap();
        assert_eq!(
            info.counters.upload_bytes(),
            0,
            "cancelled prefix must not complete"
        );
    })
    .await
    .expect("close request failed to cancel prefix write");
}
