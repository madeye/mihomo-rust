//! The TCP authentication identity must accompany each UDP destination.
#![cfg(feature = "listener-socks5")]
mod common;

use meow_common::{AuthConfig, Credentials, TunnelMode};
use meow_rules::{final_rule::FinalRule, in_user::InUserRule};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

// Exercises the heap-backed SmolStr case as well as identity propagation.
const USER: &str = "authenticated-udp-user-longer-than-23-bytes";

async fn associate(tunnel: meow_tunnel::Tunnel, authenticate: bool) -> (TcpStream, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (server, peer) = listener.accept().await.unwrap();
    tokio::spawn(async move {
        let auth = AuthConfig::new(
            Arc::new(Credentials::new(
                [(USER.to_owned(), "test-password".to_owned())].into(),
            )),
            vec![],
        );
        meow_listener::socks5::handle_socks5(
            &tunnel,
            server,
            peer,
            None,
            authenticate.then_some(&auth),
            "socks",
            addr.port(),
        )
        .await;
    });
    let method = if authenticate { 2 } else { 0 };
    client.write_all(&[5, 1, method]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, method]);
    if authenticate {
        let mut auth = vec![1, USER.len() as u8];
        auth.extend_from_slice(USER.as_bytes());
        auth.push(13);
        auth.extend_from_slice(b"test-password");
        client.write_all(&auth).await.unwrap();
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, 0]);
    }
    client
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut bound = [0; 10];
    client.read_exact(&mut bound).await.unwrap();
    assert_eq!(&bound[..4], &[5, 0, 0, 1]);
    let relay = SocketAddr::from((
        [bound[4], bound[5], bound[6], bound[7]],
        u16::from_be_bytes([bound[8], bound[9]]),
    ));
    (client, relay)
}

async fn check_policy(authenticate: bool) {
    let tunnel = common::direct_tunnel();
    tunnel.set_mode(TunnelMode::Rule);
    tunnel.update_proxies(
        meow_config::rebuild_from_raw(&Default::default())
            .unwrap()
            .0,
    );
    tunnel.update_rules(vec![
        Box::new(InUserRule::new(USER, "REJECT").unwrap()),
        Box::new(FinalRule::new("DIRECT")),
    ]);
    let (_control, relay) = associate(tunnel.clone(), authenticate).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0; 64];
    // New destinations must inherit the same identity; reuse must keep it.
    for _ in 0..2 {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap();
        let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
        packet.extend_from_slice(&addr.port().to_be_bytes());
        packet.extend_from_slice(b"payload");
        for _ in 0..2 {
            client.send_to(&packet, relay).await.unwrap();
            if authenticate {
                assert!(
                    timeout(Duration::from_millis(150), target.recv_from(&mut buf))
                        .await
                        .is_err(),
                    "IN-USER,REJECT must prevent delivery"
                );
            } else {
                let (n, peer) = timeout(Duration::from_secs(2), target.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&buf[..n], b"payload");
                target.send_to(&buf[..n], peer).await.unwrap();
                let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&buf[10..n], b"payload");
            }
        }
    }
    let expected = if authenticate {
        ("IN-USER", "REJECT")
    } else {
        ("MATCH", "DIRECT")
    };
    assert_eq!(
        tunnel.statistics().rule_match.snapshot(),
        vec![(expected, 2)]
    );
}

#[tokio::test]
async fn authenticated_udp_obeys_in_user_reject() {
    timeout(Duration::from_secs(5), check_policy(true))
        .await
        .unwrap();
}

#[tokio::test]
async fn unauthenticated_udp_does_not_match_in_user() {
    timeout(Duration::from_secs(5), check_policy(false))
        .await
        .unwrap();
}
