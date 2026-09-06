//! Per-flow UDP handling for the TUN inbound.
//!
//! lwIP surfaces UDP as one packet-level socket yielding
//! `(payload, src, dst)` tuples — there are no per-flow streams and no
//! built-in NAT, so this module owns the flow table: the reader loop
//! dispatches datagrams to per-flow tasks keyed by the (src, dst) tuple,
//! and each flow task dials the outbound once, pumps both directions, and
//! evicts itself after `udp-timeout` of silence.
//!
//! Routing mirrors `meow_tunnel::udp::handle_udp`: fake-IP rewrite →
//! pre-resolve → port-53 handling → rule match → `dial_udp`. Port 53 is
//! special two ways: with `dns-hijack` enabled each query is answered
//! in-process by `DnsServer::handle_query` — statelessly, no flow entry
//! (required for fake-IP mode — point the OS resolver at any address
//! inside the routed range); without it the flow follows ordinary routing
//! rules, including REJECT and proxy selection.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use ipnet::Ipv4Net;
use lwip::UdpSocket;
use meow_common::{with_dial_timeout, ConnType, Metadata, Network};
use meow_dns::server::{hex_prefix, DnsServer};
use meow_tunnel::Tunnel;
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};
use tracing::{debug, info};

/// One datagram payload cap. UDP over IPv4 tops out below 64 KiB.
const DATAGRAM_BUF: usize = 65535;
/// Per-flow upstream queue — buffers datagrams while the flow task is
/// still routing/dialing; overflow is dropped (UDP semantics).
const FLOW_QUEUE: usize = 64;
/// Queue feeding the single stack-writer task (the netstack write half is
/// a `Sink` and cannot be cloned into per-flow tasks).
const REPLY_QUEUE: usize = 512;
/// Sweep dead flow-table entries every this many datagrams.
const SWEEP_INTERVAL: u32 = 256;

/// `(payload, packet source, packet destination)` — the netstack `UdpMsg`
/// layout, so a reply to a flow is sent as `(payload, dst, src)`.
type ReplyMsg = (Vec<u8>, SocketAddr, SocketAddr);

pub(super) async fn run_udp(
    tunnel: Tunnel,
    socket: Box<UdpSocket>,
    dns_hijack: bool,
    udp_timeout: Duration,
    in_name: String,
    tun_net: Ipv4Net,
) {
    let (write_half, mut read_half) = socket.split();

    let (reply_tx, mut reply_rx) = mpsc::channel::<ReplyMsg>(REPLY_QUEUE);
    tokio::spawn(async move {
        while let Some((data, src, dst)) = reply_rx.recv().await {
            // `send_to(data, src, dst)`: appear as `src`, deliver to `dst`.
            if let Err(e) = write_half.send_to(&data, &src, &dst) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    continue;
                }
                debug!("tun UDP write half closed: {e}");
                break;
            }
        }
    });

    // Flow table, touched only by this loop. A flow task signals its own
    // death by closing its queue; the entry is evicted lazily — on the next
    // datagram for the tuple or by the periodic sweep below.
    let mut flows: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut sweep_countdown = SWEEP_INTERVAL;

    while let Some((data, src, dst)) = read_half.next().await {
        if dns_hijack && dst.port() == 53 {
            let resolver = Arc::clone(tunnel.resolver());
            let reply_tx = reply_tx.clone();
            debug!(
                "tun dns-hijack: recv {} bytes from {src} to {dst} | {}",
                data.len(),
                hex_prefix(&data, 48),
            );
            tokio::spawn(async move {
                match DnsServer::handle_query(&data, &resolver).await {
                    Ok(response) => {
                        debug!(
                            "tun dns-hijack: reply {} bytes -> {src} | {}",
                            response.len(),
                            hex_prefix(&response, 48),
                        );
                        let _ = reply_tx.send((response, dst, src)).await;
                    }
                    Err(e) => debug!("tun dns-hijack: unanswerable query from {src}: {e}"),
                }
            });
            continue;
        }

        if is_looping_dst(dst.ip(), tun_net) {
            debug!("tun UDP: dropping non-routable dst {dst} (from {src})");
            continue;
        }

        sweep_countdown -= 1;
        if sweep_countdown == 0 {
            sweep_countdown = SWEEP_INTERVAL;
            flows.retain(|_, tx| !tx.is_closed());
        }

        let key = (src, dst);
        let data = match flows.get(&key) {
            Some(tx) => match tx.try_send(data) {
                // Delivered — or queue full: the flow is alive but slow,
                // so the datagram is dropped (UDP semantics).
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                // Flow task ended (idle timeout or error): evict and fall
                // through to re-create the flow with this datagram.
                Err(mpsc::error::TrySendError::Closed(data)) => {
                    flows.remove(&key);
                    data
                }
            },
            None => data,
        };

        let (tx, rx) = mpsc::channel(FLOW_QUEUE);
        tx.try_send(data).expect("fresh flow queue has capacity");
        flows.insert(key, tx);
        tokio::spawn(flow_task(
            tunnel.clone(),
            rx,
            reply_tx.clone(),
            src,
            dst,
            udp_timeout,
            in_name.clone(),
        ));
    }
}

async fn flow_task(
    tunnel: Tunnel,
    rx: mpsc::Receiver<Vec<u8>>,
    reply_tx: mpsc::Sender<ReplyMsg>,
    src: SocketAddr,
    dst: SocketAddr,
    udp_timeout: Duration,
    in_name: String,
) {
    if let Err(e) = relay_flow(&tunnel, rx, reply_tx, src, dst, udp_timeout, &in_name).await {
        debug!("tun UDP {src} -> {dst}: {e}");
    }
}

/// Route the flow, dial the outbound, then pump datagrams both ways until
/// `udp_timeout` passes with no traffic in either direction.
async fn relay_flow(
    tunnel: &Tunnel,
    mut rx: mpsc::Receiver<Vec<u8>>,
    reply_tx: mpsc::Sender<ReplyMsg>,
    src: SocketAddr,
    dst: SocketAddr,
    udp_timeout: Duration,
    in_name: &str,
) -> Result<(), String> {
    let mut metadata = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Tun,
        src_ip: Some(src.ip()),
        src_port: src.port(),
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        in_name: in_name.into(),
        ..Default::default()
    };

    let inner = tunnel.inner();
    inner.pre_handle_metadata(&mut metadata);
    // UDP keeps the eager pre_resolve (no lazy enrichment): the outbound
    // packet API below needs a resolved dst_ip regardless of what the rules
    // demand — including after a fake-IP was rewritten back to a hostname.
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

    // Non-hijacked client traffic follows the same policy on every port.
    let Some((proxy, rule_name, rule_payload)) = inner.resolve_proxy(&metadata) else {
        return Err(format!(
            "no matching rule for {}",
            metadata.remote_address()
        ));
    };
    info!(
        "UDP {} --> {} match {}({}) using {}",
        src,
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    let conn = with_dial_timeout(proxy.name(), proxy.dial_udp(&metadata))
        .await
        .map_err(|e| format!("dial_udp via {}: {e}", proxy.name()))?;

    // Single-task pump: select over upstream datagrams (queued by the
    // reader loop), downstream packets, and the idle deadline. Reply
    // source addresses are not rewritten: the tun flow is locked to one
    // (src, dst) tuple, so every reply is delivered as coming from `dst`.
    // A downstream read cancelled by another branch may drop the current
    // datagram: the property holds for VlessUdpReader / MuxPacketConn
    // (which persist progress), but `relay_flow` is generic over
    // `Box<dyn ProxyPacketConn>` and Direct / Shadowsocks / Trojan UDP
    // conns do not carry that invariant.  This is acceptable under UDP
    // delivery semantics.
    let mut buf = vec![0u8; DATAGRAM_BUF];
    let idle = sleep(udp_timeout);
    tokio::pin!(idle);
    let result = loop {
        tokio::select! {
            () = &mut idle => break Ok(()), // idle-timeout eviction
            queued = rx.recv() => match queued {
                Some(data) => {
                    if let Err(e) = conn.write_packet(&data, &dst_addr).await {
                        break Err(format!("upstream write {dst_addr}: {e}"));
                    }
                    idle.as_mut().reset(Instant::now() + udp_timeout);
                }
                None => break Ok(()), // reader loop gone — listener shutdown
            },
            received = conn.read_packet(&mut buf) => match received {
                Ok((n, _from)) => {
                    if reply_tx.send((buf[..n].to_vec(), dst, src)).await.is_err() {
                        break Ok(()); // stack writer gone — listener shutdown
                    }
                    idle.as_mut().reset(Instant::now() + udp_timeout);
                }
                Err(e) => break Err(format!("downstream read: {e}")),
            },
        }
    };

    let _ = conn.close();
    result
}

/// True when a dial to `dst` could only route back into the TUN device —
/// its own subnet (on-link, including the device address and the subnet
/// broadcast), the IPv4 limited broadcast, or multicast. Relaying such a
/// destination re-enters the device and spawns a fresh flow from a new
/// source port each round: an amplification loop. Windows NetBIOS
/// name-service broadcasts to the subnet broadcast address (e.g.
/// `172.19.0.3:137` for the default `172.19.0.1/30`) trigger exactly this,
/// exhausting ephemeral ports within seconds of TUN start.
pub(super) fn is_looping_dst(dst: std::net::IpAddr, tun_net: Ipv4Net) -> bool {
    match dst {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || tun_net.contains(&v4),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::is_looping_dst;
    use ipnet::Ipv4Net;
    use std::net::IpAddr;

    #[tokio::test]
    async fn udp_port_53_obeys_reject_rule_without_hijack() {
        let tunnel = crate::test_rule_tunnel();
        for port in [53, 5353] {
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            let (reply_tx, _reply_rx) = tokio::sync::mpsc::channel(1);
            let result = super::relay_flow(
                &tunnel,
                rx,
                reply_tx,
                "127.0.0.1:12345".parse().unwrap(),
                ([127, 0, 0, 1], port).into(),
                std::time::Duration::from_millis(100),
                "tun",
            )
            .await;
            assert!(result.unwrap_err().contains("rejected"));
        }
    }

    fn net() -> Ipv4Net {
        "172.19.0.1/30".parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn drops_tun_subnet_broadcast_and_multicast() {
        // The NetBIOS storm case: subnet broadcast of the /30.
        assert!(is_looping_dst(ip("172.19.0.3"), net()));
        // The device's own address and anything else on-link.
        assert!(is_looping_dst(ip("172.19.0.1"), net()));
        assert!(is_looping_dst(ip("172.19.0.2"), net()));
        // Limited broadcast and multicast (mDNS/SSDP/LLMNR).
        assert!(is_looping_dst(ip("255.255.255.255"), net()));
        assert!(is_looping_dst(ip("224.0.0.251"), net()));
        assert!(is_looping_dst(ip("ff02::fb"), net()));
    }

    #[test]
    fn keeps_routable_destinations() {
        // Fake-IP range traffic — the whole point of the TUN.
        assert!(!is_looping_dst(ip("198.18.0.5"), net()));
        // Ordinary unicast, v4 and v6.
        assert!(!is_looping_dst(ip("8.8.8.8"), net()));
        assert!(!is_looping_dst(ip("2001:db8::1"), net()));
        // Just outside the /30.
        assert!(!is_looping_dst(ip("172.19.0.4"), net()));
    }
}
