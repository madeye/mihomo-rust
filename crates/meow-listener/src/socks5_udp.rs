//! SOCKS5 inbound `CMD UDP ASSOCIATE` (RFC 1928 §7) — relays client UDP
//! (incl. QUIC / HTTP/3) through the tunnel's routing engine.
//!
//! Lifecycle: the association is bound to the TCP control connection. We bind a
//! UDP relay socket on the same local IP the client reached us on, return its
//! address in the reply, then relay until the control connection closes (at
//! which point this future returns and every per-destination outbound conn +
//! reply task is dropped).
//!
//! Routing mirrors `meow_tunnel::udp::handle_udp`: fake-IP rewrite → pre-resolve
//! → rule match → `dial_udp`. A small per-association
//! NAT (`dst -> session`) dedups outbound conns; each session has a reply task
//! that reads server→client datagrams and writes them back wrapped in the
//! SOCKS5 UDP header.

use meow_common::atomic::AtomicU;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use meow_common::{with_dial_timeout, ConnType, Metadata, Network, ProxyPacketConn};
use meow_tunnel::Tunnel;
use smallvec::SmallVec;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use crate::monotonic_ms;

const SOCKS5_VERSION: u8 = 0x05;
const REP_SUCCESS: u8 = 0x00;
const RESERVED: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const NAT_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Per-destination outbound session within one association.
struct Session {
    conn: Arc<dyn ProxyPacketConn>,
    last_activity_ms: Arc<AtomicU>,
    /// Reply task (server→client); aborted when the session is dropped.
    reply_task: tokio::task::AbortHandle,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.reply_task.abort();
    }
}

/// Handle a SOCKS5 UDP ASSOCIATE request. `control` is the TCP control
/// connection (request already consumed by the caller). An advertised source
/// endpoint is honored when compatible with the authenticated TCP peer;
/// otherwise the first valid UDP datagram locks the association endpoint.
/// `inbound` carries the listener identity and authenticated username for the
/// association. Cloning its SmolStr fields never allocates per datagram.
pub async fn handle_udp_associate(
    tunnel: &Tunnel,
    mut control: TcpStream,
    src_addr: SocketAddr,
    requested_ip: Option<IpAddr>,
    requested_port: u16,
    inbound: &Metadata,
) -> io::Result<()> {
    // Bind the relay on the same local IP the client reached us on, so the
    // address we hand back is reachable by the client.
    let local_ip = control.local_addr()?.ip();
    let relay = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
    let bnd = relay.local_addr()?;

    write_associate_reply(&mut control, bnd).await?;
    debug!("SOCKS5 UDP ASSOCIATE from {src_addr}: relay bound on {bnd}");

    let mut nat: HashMap<SocketAddr, Session> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut ctrl_buf = [0u8; 16];
    let requested_ip = requested_ip.filter(|ip| !ip.is_unspecified());
    let mut client_endpoint = match (requested_ip, requested_port) {
        (Some(ip), port) if ip == src_addr.ip() && port != 0 => Some(SocketAddr::new(ip, port)),
        (None, port) if port != 0 => Some(SocketAddr::new(src_addr.ip(), port)),
        _ => None,
    };
    let mut sweeper = tokio::time::interval(NAT_SWEEP_INTERVAL);
    sweeper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // The association ends when the control connection closes.
            r = control.read(&mut ctrl_buf) => {
                match r {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {} // ignore unexpected control-channel bytes
                }
            }
            r = relay.recv_from(&mut buf) => {
                let (n, client) = match r {
                    Ok(v) => v,
                    Err(e) => { debug!("SOCKS5 UDP recv error: {e}"); continue; }
                };
                if client.ip() != src_addr.ip() {
                    debug!("SOCKS5 UDP ignoring source {client}: TCP peer is {src_addr}");
                    continue;
                }
                match client_endpoint {
                    Some(expected) if client != expected => {
                        debug!("SOCKS5 UDP ignoring source {client}: association is bound to {expected}");
                        continue;
                    }
                    None => {
                        // Do not let a malformed packet claim the association.
                        if let Err(e) = parse_udp_request(&buf[..n]) {
                            debug!("SOCKS5 UDP datagram from {client}: {e}");
                            continue;
                        }
                        client_endpoint = Some(client);
                    }
                    Some(_) => {}
                }
                if let Err(e) =
                    handle_client_datagram(tunnel, &relay, &mut nat, &buf[..n], client, inbound).await
                {
                    debug!("SOCKS5 UDP datagram from {client}: {e}");
                }
            }
            _ = sweeper.tick() => {
                let idle_ms = meow_tunnel::udp::DEFAULT_UDP_IDLE.as_millis() as u64;
                nat.retain(|_, session| {
                    let now = monotonic_ms() as meow_common::atomic::Uint;
                    let last = session.last_activity_ms.load(Ordering::Relaxed);
                    #[allow(
                        clippy::useless_conversion,
                        reason = "identity on 64-bit; u32→u64 widening on mips32"
                    )]
                    let elapsed = u64::from(now.wrapping_sub(last));
                    elapsed < idle_ms
                });
            }
        }
    }

    debug!(
        "SOCKS5 UDP ASSOCIATE from {src_addr} closed; tearing down {} sessions",
        nat.len()
    );
    Ok(())
}

/// Parse one inbound datagram, route it, and forward it through the (possibly
/// newly-created) per-destination outbound session.
async fn handle_client_datagram(
    tunnel: &Tunnel,
    relay: &Arc<UdpSocket>,
    nat: &mut HashMap<SocketAddr, Session>,
    datagram: &[u8],
    client: SocketAddr,
    inbound: &Metadata,
) -> Result<(), String> {
    let (dst_ip, host, dst_port, data_off) = parse_udp_request(datagram)?;

    let mut metadata = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Socks5,
        src_ip: Some(client.ip()),
        src_port: client.port(),
        dst_ip,
        dst_port,
        host: Metadata::lower_host(&host),
        in_name: inbound.in_name.clone(),
        in_port: inbound.in_port,
        in_user: inbound.in_user.clone(),
        ..Default::default()
    };

    let inner = tunnel.inner();
    inner.pre_handle_metadata(&mut metadata);
    // UDP keeps the eager pre_resolve (no lazy enrichment): the relay needs
    // a resolved dst_ip for its session bookkeeping regardless of what the
    // rules demand.
    inner.pre_resolve(&mut metadata).await;
    if metadata.dst_ip.is_none() && !metadata.host.is_empty() {
        metadata.dst_ip = inner.resolver.resolve_ip_real(&metadata.host).await;
    }

    let Some(dst_ip) = metadata.dst_ip else {
        return Err(format!(
            "dst_ip not resolved for {}",
            metadata.remote_address()
        ));
    };
    let dst_addr = SocketAddr::new(dst_ip, metadata.dst_port);
    let payload = &datagram[data_off..];

    // Fast path: existing session for this destination.
    if let Some(session) = nat.get(&dst_addr) {
        session
            .conn
            .write_packet(payload, &dst_addr)
            .await
            .map_err(|e| format!("udp write {dst_addr}: {e}"))?;
        session.last_activity_ms.store(
            monotonic_ms() as meow_common::atomic::Uint,
            Ordering::Relaxed,
        );
        return Ok(());
    }

    // Client UDP follows the configured routing policy, including port 53.
    let Some((proxy, _rule, _payload)) = inner.resolve_proxy(&metadata) else {
        return Err(format!(
            "no matching rule for {}",
            metadata.remote_address()
        ));
    };

    let conn: Arc<dyn ProxyPacketConn> = Arc::from(
        with_dial_timeout(proxy.name(), proxy.dial_udp(&metadata))
            .await
            .map_err(|e| format!("dial_udp via {}: {e}", proxy.name()))?,
    );

    conn.write_packet(payload, &dst_addr)
        .await
        .map_err(|e| format!("udp initial write {dst_addr}: {e}"))?;

    // Reply task: server→client. Wraps each datagram in the SOCKS5 UDP header
    // and sends it back to the client's UDP source address.
    let last_activity_ms = Arc::new(AtomicU::new(monotonic_ms() as meow_common::atomic::Uint));
    let reply_task = {
        let relay = Arc::clone(relay);
        let conn = Arc::clone(&conn);
        let last_activity_ms = Arc::clone(&last_activity_ms);
        tokio::spawn(async move {
            let mut rbuf = vec![0u8; 65535];
            while let Ok((m, src)) = conn.read_packet(&mut rbuf).await {
                let mut out: SmallVec<[u8; 1500]> = SmallVec::new();
                encode_udp_header(&mut out, &src);
                out.extend_from_slice(&rbuf[..m]);
                if relay.send_to(&out, client).await.is_err() {
                    break;
                }
                last_activity_ms.store(
                    monotonic_ms() as meow_common::atomic::Uint,
                    Ordering::Relaxed,
                );
            }
        })
        .abort_handle()
    };

    nat.insert(
        dst_addr,
        Session {
            conn,
            last_activity_ms,
            reply_task,
        },
    );
    Ok(())
}

/// Write the `CMD UDP ASSOCIATE` success reply carrying the relay endpoint.
async fn write_associate_reply(control: &mut TcpStream, bnd: SocketAddr) -> io::Result<()> {
    let mut reply: SmallVec<[u8; 22]> = SmallVec::new();
    reply.extend_from_slice(&[SOCKS5_VERSION, REP_SUCCESS, RESERVED]);
    match bnd.ip() {
        IpAddr::V4(v4) => {
            reply.push(ATYP_IPV4);
            reply.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            reply.push(ATYP_IPV6);
            reply.extend_from_slice(&v6.octets());
        }
    }
    reply.extend_from_slice(&bnd.port().to_be_bytes());
    control.write_all(&reply).await?;
    Ok(())
}

/// Parse a SOCKS5 UDP request header (RFC 1928 §7):
/// `RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT DATA`. Returns
/// `(dst_ip, host, port, data_offset)` — exactly one of `dst_ip`/`host` is set.
fn parse_udp_request(buf: &[u8]) -> Result<(Option<IpAddr>, String, u16, usize), String> {
    if buf.len() < 4 {
        return Err("short UDP request".into());
    }
    // RSV(2) ignored. FRAG must be 0 — we don't reassemble fragments.
    if buf[2] != 0 {
        return Err("fragmented UDP datagram not supported".into());
    }
    let atyp = buf[3];
    let mut pos = 4;
    let (dst_ip, host) = match atyp {
        ATYP_IPV4 => {
            if buf.len() < pos + 4 + 2 {
                return Err("truncated v4 UDP request".into());
            }
            let ip = IpAddr::from([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
            pos += 4;
            (Some(ip), String::new())
        }
        ATYP_IPV6 => {
            if buf.len() < pos + 16 + 2 {
                return Err("truncated v6 UDP request".into());
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[pos..pos + 16]);
            pos += 16;
            (Some(IpAddr::from(o)), String::new())
        }
        ATYP_DOMAIN => {
            let dlen = *buf.get(4).ok_or("missing domain length")? as usize;
            pos = 5;
            if buf.len() < pos + dlen + 2 {
                return Err("truncated domain UDP request".into());
            }
            let host = std::str::from_utf8(&buf[pos..pos + dlen])
                .map_err(|_| "non-utf8 domain".to_string())?
                .to_string();
            pos += dlen;
            (None, host)
        }
        other => return Err(format!("unknown atyp {other:#04x}")),
    };
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Ok((dst_ip, host, port, pos))
}

/// Encode a SOCKS5 UDP reply header for `addr` (RFC 1928 §7):
/// `RSV(2)=0 FRAG(1)=0 ATYP SRC.ADDR SRC.PORT`. DATA is appended by the caller.
fn encode_udp_header(out: &mut SmallVec<[u8; 1500]>, addr: &SocketAddr) {
    out.extend_from_slice(&[0, 0, 0]); // RSV(2) + FRAG(1)
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_port_53_obeys_reject_rule() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tokio::time::timeout(Duration::from_secs(2), async {
            let tunnel = crate::test_rule_tunnel();
            let stats = Arc::clone(tunnel.statistics());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut control = TcpStream::connect(addr).await.unwrap();
            let (server, peer) = listener.accept().await.unwrap();
            let task = tokio::spawn(async move {
                crate::socks5::handle_socks5(
                    &tunnel,
                    server,
                    peer,
                    None,
                    None,
                    "socks",
                    addr.port(),
                )
                .await;
            });
            control.write_all(&[5, 1, 0]).await.unwrap();
            let mut greeting = [0; 2];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 0]);
            control
                .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut bound = [0; 10];
            control.read_exact(&mut bound).await.unwrap();
            assert_eq!(&bound[..4], &[5, 0, 0, 1]);
            let relay = SocketAddr::from((
                [bound[4], bound[5], bound[6], bound[7]],
                u16::from_be_bytes([bound[8], bound[9]]),
            ));
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for port in [53, 5353] {
                let mut packet = SmallVec::new();
                encode_udp_header(&mut packet, &SocketAddr::from(([127, 0, 0, 1], port)));
                packet.extend_from_slice(b"not a DNS query");
                client.send_to(&packet, relay).await.unwrap();
            }
            while stats.rule_match.snapshot() != vec![(("MATCH", "REJECT"), 2)] {
                tokio::task::yield_now().await;
            }
            drop(control);
            task.await.unwrap();
        })
        .await
        .expect("both destinations must reach MATCH,REJECT");
    }

    /// (label, datagram, expected ip, expected host, expected port, expected payload)
    type ParseUdpRequestCase = (
        &'static str,
        &'static [u8],
        Option<IpAddr>,
        &'static str,
        u16,
        &'static [u8],
    );

    #[test]
    fn parse_udp_request_cases() {
        let cases: &[ParseUdpRequestCase] = &[
            (
                "ipv4",
                // RSV FRAG ATYP=1 1.2.3.4 :443 "hi"
                &[0, 0, 0, ATYP_IPV4, 1, 2, 3, 4, 0x01, 0xBB, b'h', b'i'],
                Some(IpAddr::from([1, 2, 3, 4])),
                "",
                443,
                b"hi",
            ),
            (
                "domain",
                // RSV FRAG ATYP=3 len=3 "a.b" :53 "q"
                &[0, 0, 0, ATYP_DOMAIN, 3, b'a', b'.', b'b', 0x00, 0x35, b'q'],
                None,
                "a.b",
                53,
                b"q",
            ),
        ];
        for (label, dg, want_ip, want_host, want_port, want_payload) in cases {
            let (ip, host, port, off) =
                parse_udp_request(dg).unwrap_or_else(|e| panic!("{label}: parse failed: {e}"));
            assert_eq!(ip, *want_ip, "{label}: ip");
            assert_eq!(host, *want_host, "{label}: host");
            assert_eq!(port, *want_port, "{label}: port");
            assert_eq!(&dg[off..], *want_payload, "{label}: payload");
        }
    }

    #[test]
    fn parse_udp_request_rejects_fragment_and_short() {
        assert!(parse_udp_request(&[0, 0, 1, ATYP_IPV4, 1, 2, 3, 4, 0, 80]).is_err());
        assert!(parse_udp_request(&[0, 0]).is_err());
    }

    #[test]
    fn encode_udp_header_roundtrips_with_request_parser() {
        let mut out: SmallVec<[u8; 1500]> = SmallVec::new();
        let src: SocketAddr = "9.9.9.9:53".parse().unwrap();
        encode_udp_header(&mut out, &src);
        out.extend_from_slice(b"data");
        let (ip, _host, port, off) = parse_udp_request(&out).unwrap();
        assert_eq!(ip, Some(src.ip()));
        assert_eq!(port, src.port());
        assert_eq!(&out[off..], b"data");
    }
}
