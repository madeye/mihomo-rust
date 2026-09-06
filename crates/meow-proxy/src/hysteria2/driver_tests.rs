//! Portable QUIC peer for lifecycle, flow-control and TCP response regressions.
use super::*;
use crate::hysteria2::ReconnectableClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

const TARGET: &str = "target:80";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn raw_udp_round_trip_without_http3_datagrams() {
    let peer = peer(true, Some(0), 16).await;
    let client = peer.client(true);
    let mut udp = timeout(TEST_TIMEOUT, client.udp()).await.unwrap().unwrap();
    for size in [1, 64, 4096] {
        let payload = vec![42; size];
        udp.send(&payload, TARGET).unwrap();
        let (received, addr) = timeout(TEST_TIMEOUT, udp.recv()).await.unwrap().unwrap();
        assert_eq!(received, payload);
        assert_eq!(addr, TARGET);
    }
}

struct Peer {
    addr: SocketAddr,
    read_payload: Arc<AtomicBool>,
    stop_writes: Arc<AtomicBool>,
    auth_seen: mpsc::UnboundedReceiver<SocketAddr>,
    task: DriverTask,
}

impl Peer {
    fn client(&self, fast_open: bool) -> ReconnectableClient {
        ReconnectableClient::new(Config {
            server_addr: self.addr.to_string(),
            server_name: "localhost".into(),
            insecure: true,
            fast_open,
            ..Config::default()
        })
    }
}

async fn peer(authenticate: bool, response: Option<u8>, stream_limit: u64) -> Peer {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
    ssl.set_certificate(&boring::x509::X509::from_der(key.cert.der()).unwrap())
        .unwrap();
    ssl.set_private_key(
        &boring::pkey::PKey::private_key_from_der(&key.key_pair.serialize_der()).unwrap(),
    )
    .unwrap();
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_max_idle_timeout(30_000);
    config.set_initial_max_streams_bidi(stream_limit);
    config.set_initial_max_streams_uni(16);
    config.set_initial_max_data(1 << 20);
    config.set_initial_max_stream_data_bidi_remote(64 * 1024);
    config.set_initial_max_stream_data_uni(64 * 1024);
    config.enable_dgram(true, 64, 64);
    // Echo complete client datagrams even when this peer's connection ID
    // makes the outgoing packet header slightly larger than the incoming one.
    config.set_max_send_udp_payload_size(1500);
    let read_payload = Arc::new(AtomicBool::new(true));
    let read_enabled = Arc::clone(&read_payload);
    let stop_writes = Arc::new(AtomicBool::new(false));
    let stop_requested = Arc::clone(&stop_writes);
    let (auth_tx, auth_seen) = mpsc::unbounded_channel();
    let task = DriverTask(tokio::spawn(async move {
        let mut incoming = vec![0; 65535];
        let (n, remote) = socket.recv_from(&mut incoming).await.unwrap();
        let header =
            quiche::Header::from_slice(&mut incoming[..n], quiche::MAX_CONN_ID_LEN).unwrap();
        let mut conn = quiche::accept(&header.dcid, None, local, remote, &mut config).unwrap();
        conn.recv(
            &mut incoming[..n],
            quiche::RecvInfo {
                from: remote,
                to: local,
            },
        )
        .unwrap();
        let mut h3 = None;
        let mut authenticated = false;
        let mut requests: HashMap<u64, Vec<u8>> = HashMap::new();
        let mut established = std::collections::HashSet::new();
        let mut pending: HashMap<u64, VecDeque<u8>> = HashMap::new();
        let mut finished = std::collections::HashSet::new();
        let mut out = [0; 1500];
        loop {
            if conn.is_established() && h3.is_none() {
                h3 = Some(
                    quiche::h3::Connection::with_transport(
                        &mut conn,
                        &quiche::h3::Config::new().unwrap(),
                    )
                    .unwrap(),
                );
            }
            if !authenticated {
                if let Some(h3) = h3.as_mut() {
                    loop {
                        match h3.poll(&mut conn) {
                            Ok((id, quiche::h3::Event::Headers { .. })) => {
                                let _ = auth_tx.send(remote);
                                if authenticate {
                                    h3.send_response(
                                        &mut conn,
                                        id,
                                        &[
                                            quiche::h3::Header::new(b":status", b"233"),
                                            quiche::h3::Header::new(b"hysteria-udp", b"true"),
                                        ],
                                        true,
                                    )
                                    .unwrap();
                                    authenticated = true;
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => panic!("peer auth: {e}"),
                        }
                    }
                }
            }
            if authenticated {
                // Hysteria uses raw QUIC datagrams. Advertising HTTP/3
                // datagrams starts a competing receiver in quic-go.
                if let Some(settings) = h3.as_ref().unwrap().peer_settings_raw() {
                    assert!(!settings.iter().any(|&(id, value)| id == 0x33 && value == 1));
                }
                while let Ok(n) = conn.dgram_recv(&mut incoming) {
                    conn.dgram_send(&incoming[..n]).unwrap();
                }
                if stop_requested.swap(false, Ordering::Relaxed) {
                    for &id in &established {
                        let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 42);
                    }
                }
                for id in conn.readable() {
                    if established.contains(&id) && !read_enabled.load(Ordering::Relaxed) {
                        continue;
                    }
                    let mut bytes = [0; 16384];
                    loop {
                        match conn.stream_recv(id, &mut bytes) {
                            Ok((n, fin)) => {
                                if id != 0 && id % 4 == 0 {
                                    let payload = if established.contains(&id) {
                                        bytes[..n].to_vec()
                                    } else {
                                        let request = requests.entry(id).or_default();
                                        request.extend_from_slice(&bytes[..n]);
                                        let expected =
                                            proto::encode_tcp_request(TARGET, &[]).unwrap();
                                        if request.len() < expected.len() {
                                            break;
                                        }
                                        assert_eq!(&request[..expected.len()], expected);
                                        established.insert(id);
                                        if let Some(status) = response {
                                            pending.entry(id).or_default().extend([status, 0, 0]);
                                        }
                                        request.split_off(expected.len())
                                    };
                                    pending.entry(id).or_default().extend(payload);
                                    if fin {
                                        finished.insert(id);
                                    }
                                }
                                if fin {
                                    break;
                                }
                                if established.contains(&id)
                                    && !read_enabled.load(Ordering::Relaxed)
                                {
                                    break;
                                }
                            }
                            Err(quiche::Error::Done) => break,
                            Err(quiche::Error::StreamReset(_)) => {
                                let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, 0);
                                pending.remove(&id);
                                break;
                            }
                            Err(e) => panic!("peer receive: {e}"),
                        }
                    }
                }
                for (&id, data) in &mut pending {
                    while !data.is_empty() {
                        match conn.stream_send(id, data.make_contiguous(), false) {
                            Ok(n) => {
                                data.drain(..n);
                            }
                            Err(quiche::Error::Done) => break,
                            Err(quiche::Error::StreamStopped(_)) => {
                                data.clear();
                                break;
                            }
                            Err(e) => panic!("peer send: {e}"),
                        }
                    }
                    if data.is_empty() && finished.remove(&id) {
                        conn.stream_send(id, &[], true).unwrap();
                    }
                }
            }
            while let Ok((n, info)) = conn.send(&mut out) {
                socket.send_to(&out[..n], info.to).await.unwrap();
            }
            if conn.is_closed() {
                break;
            }
            tokio::select! {
                packet = socket.recv_from(&mut incoming) => {
                    let (n, from) = packet.unwrap();
                    let _ = conn.recv(&mut incoming[..n], quiche::RecvInfo { from, to: local });
                }
                _ = sleep_opt(conn.timeout()) => conn.on_timeout(),
                _ = sleep(Duration::from_millis(5)) => {}
            }
        }
    }));
    Peer {
        addr: local,
        read_payload,
        stop_writes,
        auth_seen,
        task,
    }
}

async fn round_trip(stream: &mut DuplexStream) {
    timeout(TEST_TIMEOUT, async {
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn terminal_write_failure_reaches_both_halves() {
    let peer = peer(true, Some(0), 16).await;
    let client = peer.client(false);
    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    peer.stop_writes.store(true, Ordering::Relaxed);
    let error = timeout(TEST_TIMEOUT, async {
        loop {
            if let Err(error) = stream.write_all(b"hello").await {
                break error;
            }
            if let Err(error) = stream.flush().await {
                break error;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    let mut bytes = Vec::new();
    let error = timeout(TEST_TIMEOUT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn write_budget_survives_draining_the_command_channel() {
    let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
    let (read_tx, read_rx) = mpsc::channel(16);
    let (connected_tx, connected_rx) = oneshot::channel();
    let capacity = Arc::new(Semaphore::new(WRITE_BUFFER_BYTES as usize));
    let mut stream = DuplexStream::new(
        4,
        read_rx,
        Arc::new(Notify::new()),
        cmd_tx,
        Arc::clone(&capacity),
        connected_rx,
        Arc::new(AtomicBool::new(false)),
    );
    connected_tx.send(Ok(())).unwrap();
    stream.wait_connected().await.unwrap();
    let mut queued = Vec::new();
    for _ in 0..4 {
        assert_eq!(stream.write(&[0; 16384]).await.unwrap(), 16384);
        // Draining the bounded channel must NOT release the byte budget.
        queued.push(cmd_rx.recv().await.unwrap());
    }
    assert_eq!(capacity.available_permits(), 0);
    assert!(timeout(Duration::from_millis(20), stream.write(b"x"))
        .await
        .is_err());
    assert!(timeout(Duration::from_millis(20), stream.flush())
        .await
        .is_err());
    queued.clear();
    timeout(TEST_TIMEOUT, stream.flush())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(capacity.available_permits(), WRITE_BUFFER_BYTES as usize);
    drop(read_tx);
}

#[tokio::test]
async fn stream_limit_retries_the_intact_tcp_request() {
    let peer = peer(true, Some(0), 1).await;
    let client = peer.client(false);
    let mut first = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    round_trip(&mut first).await;
    let second = client.tcp_connect(TARGET);
    tokio::pin!(second);
    assert!(timeout(Duration::from_millis(100), &mut second)
        .await
        .is_err());
    drop(first);
    let mut second = timeout(TEST_TIMEOUT, second).await.unwrap().unwrap();
    round_trip(&mut second).await;
    assert!(!peer.task.0.is_finished());
}

#[tokio::test]
async fn non_fast_open_waits_and_reports_remote_errors() {
    let peer = peer(true, None, 16).await;
    let client = peer.client(false);
    assert!(
        timeout(Duration::from_millis(150), client.tcp_connect(TARGET))
            .await
            .is_err()
    );
    // A peer supports one QUIC connection: use a fresh peer for the fast-open case.
    let fast_peer = self::peer(true, None, 16).await;
    let fast_client = fast_peer.client(true);
    let _stream = timeout(TEST_TIMEOUT, fast_client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();

    let rejected = self::peer(true, Some(1), 16).await;
    let client = rejected.client(false);
    let result = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap();
    assert!(
        matches!(result, Err(Error::Protocol(message)) if message.contains("remote TCP error"))
    );
}

#[tokio::test]
async fn stalled_peer_backpressures_and_resuming_preserves_payload() {
    let peer = peer(true, Some(0), 16).await;
    peer.read_payload.store(false, Ordering::Relaxed);
    let client = peer.client(false);
    let stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let payload = vec![0x5a; 2 * 1024 * 1024];
    let mut writing = tokio::spawn(async move {
        writer.write_all(&payload).await.unwrap();
        writer.shutdown().await.unwrap();
    });
    assert!(timeout(Duration::from_millis(200), &mut writing)
        .await
        .is_err());
    peer.read_payload.store(true, Ordering::Relaxed);
    let reading = async {
        let mut echoed = Vec::new();
        reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, vec![0x5a; 2 * 1024 * 1024]);
    };
    timeout(Duration::from_secs(15), async {
        tokio::join!(reading, async {
            writing.await.unwrap();
        });
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn non_fast_open_response_timeout_is_bounded() {
    let peer = peer(true, None, 16).await;
    let client = peer.client(false);
    let result = timeout(Duration::from_secs(12), client.tcp_connect(TARGET))
        .await
        .expect("TCP response wait exceeded the client deadline");
    assert!(matches!(result, Err(Error::Quic(message)) if message.contains("TCP connect timeout")));
}

#[tokio::test]
async fn keepalive_preserves_an_idle_tcp_stream() {
    let peer = peer(true, Some(0), 16).await;
    let client = peer.client(false);
    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    round_trip(&mut stream).await;
    // quiche uses std::time::Instant, so Tokio's virtual clock cannot exercise
    // its 30-second idle timeout. This intentionally crosses it in real time.
    sleep(Duration::from_secs(32)).await;
    round_trip(&mut stream).await;
}

async fn assert_socket_released(addr: SocketAddr) {
    timeout(TEST_TIMEOUT, async {
        loop {
            if UdpSocket::bind(addr).await.is_ok() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("driver retained its UDP socket");
}

#[tokio::test]
async fn cancelling_authentication_releases_the_driver_socket() {
    let mut peer = peer(false, None, 16).await;
    let client = peer.client(false);
    let dial = tokio::spawn(async move { client.tcp_connect(TARGET).await });
    let addr = timeout(TEST_TIMEOUT, peer.auth_seen.recv())
        .await
        .unwrap()
        .unwrap();
    dial.abort();
    assert!(matches!(dial.await, Err(error) if error.is_cancelled()));
    assert_socket_released(addr).await;
}

#[tokio::test]
async fn dropping_the_client_releases_an_authenticated_driver() {
    let mut peer = peer(true, Some(0), 16).await;
    let client = peer.client(false);
    let mut stream = timeout(TEST_TIMEOUT, client.tcp_connect(TARGET))
        .await
        .unwrap()
        .unwrap();
    let addr = peer.auth_seen.recv().await.unwrap();
    drop(client);
    assert_socket_released(addr).await;
    let error = timeout(TEST_TIMEOUT, stream.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
}
