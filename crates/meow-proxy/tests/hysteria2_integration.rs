#![cfg(feature = "hysteria2")]

use meow_common::{Metadata, Network, ProxyAdapter, ProxyPacketConn};
use meow_proxy::{Hy2Adapter, Hy2Options};
use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{sleep, timeout, Duration, Instant};

const IMAGE_HYSTERIA: &str = "tobyxdd/hysteria:v2.9.2";
const PASSWORD: &str = "test-hysteria2-password";
const T: Duration = Duration::from_secs(30);

fn docker_required() -> bool {
    std::env::var_os("MEOW_REQUIRE_DOCKER").is_some()
        || std::env::var_os("MIHOMO_REQUIRE_INTEGRATION_BINS").is_some()
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn skip_or_panic(reason: impl AsRef<str>) -> bool {
    let reason = reason.as_ref();
    if docker_required() {
        panic!("{reason}");
    }
    eprintln!("skipping hysteria2 docker integration test: {reason}");
    false
}

fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

struct HysteriaServer {
    _dir: TempDir,
    child: std::process::Child,
    log_path: PathBuf,
}

impl HysteriaServer {
    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for HysteriaServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_server_files(dir: &Path, port: u16) -> PathBuf {
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "server.key",
            "-out",
            "server.crt",
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ])
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| {
            panic!("openssl must be available for hysteria2 integration test: {e}")
        });
    assert!(status.success(), "openssl certificate generation failed");

    let cert = dir.join("server.crt");
    let key = dir.join("server.key");
    let config_path = dir.join("config.yaml");
    let config = format!(
        concat!(
            "listen: 127.0.0.1:{port}\n",
            "tls:\n",
            "  cert: {cert}\n",
            "  key: {key}\n",
            "auth:\n",
            "  type: password\n",
            "  password: {password}\n",
            "disableUDP: false\n",
            "masquerade:\n",
            "  type: string\n",
            "  string:\n",
            "    content: meow-rs hysteria2 integration\n",
            "    headers:\n",
            "      content-type: text/plain\n",
            "    statusCode: 200\n",
        ),
        port = port,
        cert = cert.display(),
        key = key.display(),
        password = PASSWORD,
    );
    std::fs::write(&config_path, config).unwrap();
    config_path
}

fn ensure_hysteria_binary(dir: &Path) -> Option<PathBuf> {
    // Allow the same pinned release binary to be supplied locally when the
    // Docker registry is unavailable. CI still uses IMAGE_HYSTERIA by default.
    if let Some(path) = std::env::var_os("MEOW_HYSTERIA_BIN") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let bin = dir.join("hysteria");
    if bin.exists() {
        return Some(bin);
    }

    let pull = Command::new("docker")
        .args(["pull", IMAGE_HYSTERIA])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if pull.is_err() || !pull.unwrap_or_default().success() {
        return None;
    }

    let extract_name = format!("meow-hy2-extract-{}", std::process::id());
    let _ = Command::new("docker")
        .args(["rm", "-f", &extract_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let create = Command::new("docker")
        .args(["create", "--name", &extract_name, IMAGE_HYSTERIA])
        .output()
        .ok()?;
    if !create.status.success() {
        return None;
    }

    let copy = Command::new("docker")
        .args([
            "cp",
            &format!("{extract_name}:/usr/local/bin/hysteria"),
            &bin.to_string_lossy(),
        ])
        .output()
        .ok()?;
    let _ = Command::new("docker")
        .args(["rm", "-f", &extract_name])
        .status();
    if !copy.status.success() {
        return None;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&bin) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&bin, perms);
        }
    }
    Some(bin)
}

fn start_hysteria_server(port: u16) -> Option<HysteriaServer> {
    // The Docker image only yields a Linux binary; any platform can run with a
    // native binary supplied through MEOW_HYSTERIA_BIN.
    if !cfg!(target_os = "linux") && std::env::var_os("MEOW_HYSTERIA_BIN").is_none() {
        skip_or_panic("test requires Linux or MEOW_HYSTERIA_BIN");
        return None;
    }
    if std::env::var_os("MEOW_HYSTERIA_BIN").is_none() && !docker_available() {
        skip_or_panic("docker daemon is not available");
        return None;
    }

    let dir = TempDir::new().unwrap();
    let Some(hysteria_bin) = ensure_hysteria_binary(dir.path()) else {
        skip_or_panic("failed to locate hysteria server binary");
        return None;
    };
    let config_path = write_server_files(dir.path(), port);
    let log_path = dir.path().join("server.log");
    let log_file = match File::create(&log_path) {
        Ok(file) => file,
        Err(e) => {
            skip_or_panic(format!("failed to create hysteria server log file: {e}"));
            return None;
        }
    };

    // Run hysteria in-process on the test host. The quiche client dials the
    // server over loopback; running the server on the host (rather than via
    // `docker --network container:…`) keeps the QUIC path simple in nested
    // container environments (e.g. Gitpod).
    let stdout = log_file.try_clone().map_or(Stdio::null(), Stdio::from);
    let child = match Command::new(&hysteria_bin)
        .args([
            "server",
            "--disable-update-check",
            "--log-level",
            "debug",
            "-c",
            &config_path.to_string_lossy(),
        ])
        .stdout(stdout)
        .stderr(Stdio::from(log_file))
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            skip_or_panic(format!("failed to start hysteria server process: {e}"));
            return None;
        }
    };

    Some(HysteriaServer {
        _dir: dir,
        child,
        log_path,
    })
}

async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
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

async fn start_tcp_banner_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(b"server banner").await;
            });
        }
    });
    (addr, handle)
}

async fn start_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            tracing::debug!(bytes = n, "UDP echo target received packet");
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    (addr, handle)
}

fn adapter(port: u16) -> Hy2Adapter {
    Hy2Adapter::new(Hy2Options {
        name: "docker-hy2".into(),
        server: "127.0.0.1".into(),
        port,
        password: PASSWORD.into(),
        sni: Some("localhost".into()),
        skip_cert_verify: true,
        udp: true,
        up_bps: 10_000_000,
        down_bps: 10_000_000,
        obfs: None,
        obfs_password: None,
        ports: None,
        hop_interval: None,
        fingerprint: None,
        fast_open: true,
    })
    .expect("hysteria2 adapter must build")
}

fn metadata_for(addr: SocketAddr, network: Network) -> Metadata {
    Metadata {
        network,
        host: addr.ip().to_string().into(),
        dst_port: addr.port(),
        ..Default::default()
    }
}

async fn dial_tcp_with_retry(
    adapter: &Hy2Adapter,
    metadata: &Metadata,
) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
    let deadline = Instant::now() + T;
    loop {
        match adapter.dial_tcp(metadata).await {
            Ok(conn) => return Ok(conn),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => {}
        }
        sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hysteria2_docker_tcp_and_udp_round_trip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let server_port = free_udp_port();
    let Some(server) = start_hysteria_server(server_port) else {
        return;
    };
    sleep(Duration::from_millis(500)).await;
    let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;
    let (tcp_banner, _tcp_banner_h) = start_tcp_banner_server().await;
    let (udp_echo, _udp_h) = start_udp_echo_server().await;
    let adapter = adapter(server_port);

    // Fast Open must send the TCP request while dialing, even when the local
    // client has no bytes to write. Otherwise server-speaks-first protocols
    // deadlock before their banner reaches the client.
    let banner_metadata = metadata_for(tcp_banner, Network::Tcp);
    let mut banner_conn = timeout(T, dial_tcp_with_retry(&adapter, &banner_metadata))
        .await
        .expect("hysteria2 banner TCP dial timed out")
        .unwrap_or_else(|e| panic!("hysteria2 banner TCP dial failed: {e}\n{}", server.logs()));
    let mut banner = [0u8; 13];
    timeout(T, banner_conn.read_exact(&mut banner))
        .await
        .expect("server-first banner read timed out")
        .expect("server-first banner read failed");
    assert_eq!(&banner, b"server banner");

    let tcp_metadata = metadata_for(tcp_echo, Network::Tcp);
    let mut conn = match timeout(T, dial_tcp_with_retry(&adapter, &tcp_metadata)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => panic!("hysteria2 TCP dial failed: {e}\n{}", server.logs()),
        Err(_) => panic!("hysteria2 TCP dial timed out\n{}", server.logs()),
    };

    let tcp_payload = b"meow hysteria2 tcp";
    timeout(T, conn.write_all(tcp_payload))
        .await
        .expect("tcp write timed out")
        .expect("tcp write failed");
    timeout(T, conn.flush())
        .await
        .expect("tcp flush timed out")
        .expect("tcp flush failed");
    let mut tcp_buf = vec![0u8; tcp_payload.len()];
    timeout(T, conn.read_exact(&mut tcp_buf))
        .await
        .expect("tcp read timed out")
        .expect("tcp read failed");
    assert_eq!(&tcp_buf, tcp_payload);

    let udp_metadata = metadata_for(udp_echo, Network::Udp);
    let packet_conn: Box<dyn ProxyPacketConn> = timeout(T, adapter.dial_udp(&udp_metadata))
        .await
        .expect("udp associate timed out")
        .unwrap_or_else(|e| panic!("udp associate failed: {e}\n{}", server.logs()));
    // Exercise many packets across sizes. This is the regression guard for the
    // HTTP/3-datagram bug: when the client advertised SETTINGS_H3_DATAGRAM,
    // quic-go started an HTTP/3 datagram receiver that stole the raw QUIC relay
    // datagrams, so nearly every UDP packet was lost. A single lucky packet
    // could still slip through by racing that receiver, hence the repetition.
    //
    // Every payload here fits in one QUIC DATAGRAM, which is what hysteria2's
    // UDP relay delivers reliably. A UDP message large enough to be fragmented
    // over several DATAGRAMs is best-effort: QUIC datagrams are not
    // retransmitted, and against a real v2.6+ server the oversized return
    // fragments are dropped while the path MTU is still being probed. The
    // client's fragmentation and reassembly are covered deterministically by
    // the driver unit test `raw_udp_round_trip_without_http3_datagrams`, which
    // round-trips a 4096-byte payload through an in-process echo peer.
    for (i, size) in [17, 64, 512, 1100].into_iter().cycle().take(16).enumerate() {
        let udp_payload = vec![i as u8; size];
        timeout(T, packet_conn.write_packet(&udp_payload, &udp_echo))
            .await
            .expect("udp write timed out")
            .expect("udp write failed");
        let mut udp_buf = [0u8; 4096];
        let (n, src) = timeout(T, packet_conn.read_packet(&mut udp_buf))
            .await
            .unwrap_or_else(|e| panic!("udp read {i} timed out: {e}\n{}", server.logs()))
            .expect("udp read failed");
        assert_eq!(src, udp_echo);
        assert_eq!(&udp_buf[..n], udp_payload);
    }
}
