//! Plain HTTP has its own dial/write/relay path and must honour closure too.
#![cfg(feature = "listener-http")]
mod common;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn close_stalled_plain_http_response_terminates_sockets() {
    timeout(Duration::from_secs(5), async {
        let tunnel = common::direct_tunnel();
        let stats = std::sync::Arc::clone(tunnel.statistics());
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = origin.local_addr().unwrap();
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_addr = inbound.local_addr().unwrap();
        let mut client = TcpStream::connect(inbound_addr).await.unwrap();
        let (server, peer) = inbound.accept().await.unwrap();
        let task = tokio::spawn(async move {
            meow_listener::http_proxy::handle_http(
                &tunnel,
                server,
                peer,
                None,
                None,
                "http",
                inbound_addr.port(),
            )
            .await;
        });
        client
            .write_all(
                format!("GET http://{destination}/ HTTP/1.1\r\nHost: {destination}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let (mut remote, _) = origin.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(remote.read_u8().await.unwrap());
        }
        assert!(header.starts_with(b"GET / HTTP/1.1\r\n"));
        let id = stats.active_connections()[0].id;
        stats.close_connection(id);
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(remote.read(&mut [0; 1]).await.unwrap(), 0);
        task.await.unwrap();
        assert_eq!(stats.active_connection_count(), 0);
    })
    .await
    .expect("plain HTTP ignored the close request");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_reload_rejects_plain_http_setup_before_registration() {
    use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType, TunnelMode};
    use std::sync::Mutex;
    use tokio::sync::oneshot;

    // Pause the eager match callback to exercise the gap between route
    // selection and registration independently of the DNS-based API test.
    struct PausedMatch {
        started: Mutex<Option<oneshot::Sender<()>>>,
        resume: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl Rule for PausedMatch {
        fn rule_type(&self) -> RuleType {
            RuleType::GeoIp
        }
        fn adapter(&self) -> &str {
            "DIRECT"
        }
        fn payload(&self) -> &str {
            "test"
        }
        fn match_metadata(&self, _: &Metadata, _: &RuleMatchHelper) -> bool {
            if let Some(started) = self.started.lock().unwrap().take() {
                started.send(()).unwrap();
                self.resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            true
        }
    }

    timeout(Duration::from_secs(5), async {
        let tunnel = common::direct_tunnel();
        tunnel.set_mode(TunnelMode::Rule);
        let (started_tx, started_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        tunnel.update_rules(vec![Box::new(PausedMatch {
            started: Mutex::new(Some(started_tx)),
            resume: Mutex::new(resume_rx),
        })]);
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = origin.local_addr().unwrap();
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_addr = inbound.local_addr().unwrap();
        let mut client = TcpStream::connect(inbound_addr).await.unwrap();
        let (server, peer) = inbound.accept().await.unwrap();
        let handler_tunnel = tunnel.clone();
        let task = tokio::spawn(async move {
            meow_listener::http_proxy::handle_http(
                &handler_tunnel,
                server,
                peer,
                None,
                None,
                "http",
                inbound_addr.port(),
            )
            .await;
        });
        client
            .write_all(
                format!("GET http://{destination}/ HTTP/1.1\r\nHost: {destination}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        started_rx.await.unwrap();
        assert_eq!(tunnel.statistics().active_connection_count(), 0);
        let raw = meow_config::raw::RawConfig {
            rules: Some(vec!["MATCH,REJECT".into()]),
            ..Default::default()
        };
        let (proxies, rules) = meow_config::rebuild_from_raw(&raw).unwrap();
        assert_eq!(tunnel.reload_routing(proxies, rules, None), 0);
        resume_tx.send(()).unwrap();
        tokio::select! {
            biased;
            _ = origin.accept() => panic!("old-policy HTTP request dialed after reload"),
            result = task => result.unwrap(),
        }
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(tunnel.statistics().active_connection_count(), 0);
    })
    .await
    .expect("plain HTTP setup escaped reload");
}
