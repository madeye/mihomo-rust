//! Hysteria2 outbound proxy adapter.
//!
//! The wire protocol, HTTP/3 authentication, TCP stream framing, UDP datagrams,
//! Salamander obfuscation and port hopping live in the in-tree `hysteria2`
//! module. This module adapts that client to meow-rs' `ProxyAdapter` contracts.

use async_trait::async_trait;
use bytes::Bytes;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use smol_str::SmolStr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::debug;

const UDP_COMMAND_QUEUE: usize = 128;
const UDP_PACKET_QUEUE: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hy2Obfs {
    Salamander,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hy2HopInterval {
    pub min_secs: u64,
    pub max_secs: u64,
}

#[derive(Debug, Clone)]
pub struct Hy2Options {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub udp: bool,
    pub up_bps: u64,
    pub down_bps: u64,
    pub obfs: Option<Hy2Obfs>,
    pub obfs_password: Option<String>,
    pub ports: Option<String>,
    pub hop_interval: Option<Hy2HopInterval>,
    pub fingerprint: Option<String>,
    pub fast_open: bool,
}

impl Hy2Options {
    fn into_hysteria_config(
        self,
    ) -> std::result::Result<(String, bool, crate::hysteria2::Config), String> {
        if self.password.is_empty() {
            return Err(format!(
                "hysteria2[{}]: password must not be empty",
                self.name
            ));
        }
        if self.port == 0 {
            return Err(format!("hysteria2[{}]: port must be non-zero", self.name));
        }

        // Both set: the pin wins (see `hysteria2::tls::server_cert_verifier`).
        // Say so once at load rather than let a user believe verification is
        // off when it is not.
        if self.skip_cert_verify && self.fingerprint.is_some() {
            tracing::warn!(
                "hysteria2[{}]: skip-cert-verify is ignored because fingerprint is set; \
                 the certificate is still pinned",
                self.name
            );
        }

        let obfs_password = match self.obfs {
            Some(Hy2Obfs::Salamander) => self.obfs_password.unwrap_or_default(),
            None => String::new(),
        };
        let hop_interval = self.hop_interval.unwrap_or(Hy2HopInterval {
            min_secs: 0,
            max_secs: 0,
        });
        let addr = hy2_server_addr(&self.server, self.port);
        let cfg = crate::hysteria2::Config {
            server_addr: addr.clone(),
            server_name: self.sni.unwrap_or_default(),
            auth: self.password,
            insecure: self.skip_cert_verify,
            rx_bps: self.down_bps,
            obfs_password,
            hop_ports: self.ports.unwrap_or_default(),
            hop_interval_min_secs: hop_interval.min_secs,
            hop_interval_max_secs: hop_interval.max_secs,
            pin_sha256: self.fingerprint.unwrap_or_default(),
            fast_open: self.fast_open,
        };
        Ok((addr, self.udp, cfg))
    }
}

pub struct Hy2Adapter {
    name: SmolStr,
    addr: String,
    support_udp: bool,
    health: ProxyHealth,
    client: Arc<crate::hysteria2::ReconnectableClient>,
}

impl Hy2Adapter {
    pub fn new(options: Hy2Options) -> std::result::Result<Self, String> {
        let name = options.name.clone();
        let (addr, support_udp, cfg) = options.into_hysteria_config()?;
        Ok(Self {
            name: SmolStr::from(name),
            addr,
            support_udp,
            health: ProxyHealth::new(),
            client: Arc::new(crate::hysteria2::ReconnectableClient::new(cfg)),
        })
    }
}

fn hy2_server_addr(server: &str, port: u16) -> String {
    if let Ok(ip) = server.parse::<IpAddr>() {
        return SocketAddr::new(ip, port).to_string();
    }
    format!("{server}:{port}")
}

fn target_from_metadata(metadata: &Metadata) -> Result<String> {
    if metadata.dst_port == 0 {
        return Err(MeowError::Proxy(
            "hysteria2: metadata has no destination port".into(),
        ));
    }
    if !metadata.host.is_empty() {
        if let Ok(ip) = metadata.host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, metadata.dst_port).to_string());
        }
        return Ok(format!("{}:{}", metadata.host, metadata.dst_port));
    }
    if let Some(ip) = metadata.dst_ip {
        return Ok(SocketAddr::new(ip, metadata.dst_port).to_string());
    }
    Err(MeowError::Proxy(
        "hysteria2: metadata has no destination".into(),
    ))
}

fn hy2_error(context: &str, err: crate::hysteria2::Error) -> MeowError {
    match err {
        crate::hysteria2::Error::Io(e) => MeowError::Io(e),
        other => MeowError::Proxy(format!("hysteria2 {context}: {other}")),
    }
}

struct Hy2Conn {
    inner: std::sync::Mutex<Pin<Box<crate::hysteria2::DuplexStream>>>,
    remote: String,
}

impl Hy2Conn {
    fn new(stream: crate::hysteria2::DuplexStream, remote: String) -> Self {
        Self {
            inner: std::sync::Mutex::new(Box::pin(stream)),
            remote,
        }
    }
}

impl AsyncRead for Hy2Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Ok(mut inner) = self.inner.lock() else {
            return Poll::Ready(Err(std::io::Error::other(
                "hysteria2 stream mutex poisoned",
            )));
        };
        inner.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for Hy2Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let Ok(mut inner) = self.inner.lock() else {
            return Poll::Ready(Err(std::io::Error::other(
                "hysteria2 stream mutex poisoned",
            )));
        };
        inner.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Ok(mut inner) = self.inner.lock() else {
            return Poll::Ready(Err(std::io::Error::other(
                "hysteria2 stream mutex poisoned",
            )));
        };
        inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Ok(mut inner) = self.inner.lock() else {
            return Poll::Ready(Err(std::io::Error::other(
                "hysteria2 stream mutex poisoned",
            )));
        };
        inner.as_mut().poll_shutdown(cx)
    }
}

impl Unpin for Hy2Conn {}

impl ProxyConn for Hy2Conn {
    fn remote_destination(&self) -> String {
        self.remote.clone()
    }
}

enum UdpCommand {
    Send {
        data: Bytes,
        addr: String,
        done: oneshot::Sender<Result<usize>>,
    },
    Close,
}

pub struct Hy2PacketConn {
    commands: mpsc::Sender<UdpCommand>,
    packets: Mutex<mpsc::Receiver<Result<(Bytes, SocketAddr)>>>,
}

impl Hy2PacketConn {
    fn new(session: crate::hysteria2::UdpSession) -> Self {
        let (command_tx, command_rx) = mpsc::channel(UDP_COMMAND_QUEUE);
        let (packet_tx, packet_rx) = mpsc::channel(UDP_PACKET_QUEUE);
        tokio::spawn(run_udp_session(session, command_rx, packet_tx));
        Self {
            commands: command_tx,
            packets: Mutex::new(packet_rx),
        }
    }
}

async fn run_udp_session(
    mut session: crate::hysteria2::UdpSession,
    mut commands: mpsc::Receiver<UdpCommand>,
    packets: mpsc::Sender<Result<(Bytes, SocketAddr)>>,
) {
    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(UdpCommand::Send { data, addr, done }) => {
                        let len = data.len();
                        let result = session
                            .send(&data, &addr)
                            .map(|()| len)
                            .map_err(|e| hy2_error("udp send", e));
                        let _ = done.send(result);
                    }
                    Some(UdpCommand::Close) | None => return,
                }
            }
            received = session.recv() => {
                match received {
                    Ok((data, addr)) => {
                        let parsed = addr.parse::<SocketAddr>().map_err(|e| {
                            MeowError::Proxy(format!("hysteria2 udp: invalid source address '{addr}': {e}"))
                        });
                        let packet = parsed.map(|src| (Bytes::from(data), src));
                        if packets.send(packet).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = packets.send(Err(hy2_error("udp recv", e))).await;
                        return;
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ProxyPacketConn for Hy2PacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut packets = self.packets.lock().await;
        match packets.recv().await {
            Some(Ok((data, addr))) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok((n, addr))
            }
            Some(Err(e)) => Err(e),
            None => Err(MeowError::Proxy("hysteria2 udp: session closed".into())),
        }
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        let (done_tx, done_rx) = oneshot::channel();
        self.commands
            .send(UdpCommand::Send {
                data: Bytes::copy_from_slice(buf),
                addr: addr.to_string(),
                done: done_tx,
            })
            .await
            .map_err(|_| MeowError::Proxy("hysteria2 udp: session closed".into()))?;
        done_rx
            .await
            .map_err(|_| MeowError::Proxy("hysteria2 udp: send task stopped".into()))?
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn close(&self) -> Result<()> {
        let _ = self.commands.try_send(UdpCommand::Close);
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for Hy2Adapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Hysteria2
    }

    fn addr(&self) -> &str {
        &self.addr
    }

    fn support_udp(&self) -> bool {
        self.support_udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let target = target_from_metadata(metadata)?;
        debug!("Hysteria2 connecting to {} via {}", target, self.addr);
        let stream = self
            .client
            .tcp_connect(&target)
            .await
            .map_err(|e| hy2_error("tcp connect", e))?;
        Ok(Box::new(Hy2Conn::new(stream, target)))
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.support_udp {
            return Err(MeowError::NotSupported(
                "Hysteria2 UDP is disabled for this proxy".into(),
            ));
        }
        debug!(
            "Hysteria2 UDP-associating for {} via {}",
            metadata.remote_address(),
            self.addr
        );
        let session = self
            .client
            .udp()
            .await
            .map_err(|e| hy2_error("udp associate", e))?;
        Ok(Box::new(Hy2PacketConn::new(session)))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_options() -> Hy2Options {
        Hy2Options {
            name: "hy2".into(),
            server: "example.com".into(),
            port: 443,
            password: "secret".into(),
            sni: None,
            skip_cert_verify: false,
            udp: true,
            up_bps: 0,
            down_bps: 0,
            obfs: None,
            obfs_password: None,
            ports: None,
            hop_interval: None,
            fingerprint: None,
            fast_open: true,
        }
    }

    #[test]
    fn adapter_constructor_rejects_empty_password() {
        let options = Hy2Options {
            password: String::new(),
            ..base_options()
        };
        let Err(err) = Hy2Adapter::new(options) else {
            panic!("must fail");
        };
        assert!(err.contains("password must not be empty"));
    }

    #[test]
    fn adapter_constructor_builds_hysteria_config() {
        let adapter = Hy2Adapter::new(Hy2Options {
            server: "127.0.0.1".into(),
            sni: Some("example.com".into()),
            up_bps: 10,
            down_bps: 20,
            obfs: Some(Hy2Obfs::Salamander),
            obfs_password: Some("obfs-secret".into()),
            ports: Some("443,8443".into()),
            hop_interval: Some(Hy2HopInterval {
                min_secs: 15,
                max_secs: 30,
            }),
            fingerprint: Some("00".repeat(32)),
            ..base_options()
        })
        .unwrap();
        assert_eq!(adapter.name(), "hy2");
        assert_eq!(adapter.addr(), "127.0.0.1:443");
        assert!(adapter.support_udp());
    }

    #[test]
    fn target_prefers_host() {
        let md = Metadata {
            host: "example.com".into(),
            dst_ip: Some("127.0.0.1".parse().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        assert_eq!(target_from_metadata(&md).unwrap(), "example.com:443");
    }

    #[test]
    fn target_formats_ipv6_socket_addr() {
        let md = Metadata {
            dst_ip: Some("::1".parse().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        assert_eq!(target_from_metadata(&md).unwrap(), "[::1]:443");
    }

    #[test]
    fn target_brackets_ipv6_host_literal() {
        let md = Metadata {
            host: "::1".into(),
            dst_port: 443,
            ..Default::default()
        };
        assert_eq!(target_from_metadata(&md).unwrap(), "[::1]:443");
    }
}
