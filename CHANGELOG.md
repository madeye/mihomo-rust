# Changelog

All notable changes to meow-rs are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes are mirrored onto the GitHub Release for each tag; this file is
the canonical, in-repo source a release is cut from.

## [Unreleased]

### Changed

- **BoringSSL is now the only crypto library; rustls is gone from the runtime.**
  Two changes land together. First, every TLS handshake moved off rustls onto
  BoringSSL (`meow_transport::tls::TlsLayer`): proxy handshakes (Trojan, VLESS,
  VMess, HTTP/SOCKS5-over-TLS, SS plugins, ECH tunnel, AnyTLS), URL-test health
  probes, DoT/DoH upstreams, and every internal HTTP(S) fetch (`reqwest`
  removed; the in-tree client gained direct dialing through the host
  resolver/`SocketProtector` hooks, custom headers, and a Content-Length
  precheck). Second, the **Hysteria2 outbound was ported from quinn (rustls) to
  quiche**, Cloudflare's BoringSSL-native QUIC + HTTP/3 stack, using quiche's
  `boringssl-boring-crate` feature so it links the SAME vendored BoringSSL as
  the TLS layer. rustls, tokio-rustls, quinn, h3, h3-quinn, reqwest,
  and webpki-roots are no longer runtime dependencies; rustls remains only as a
  dev-dependency for the loopback TLS test servers.
  **Build change:** the `boring` crate is pinned to `=4.22.0`, the version
  quiche's boring-crate feature accepts (`^4.3`), so that quiche and
  meow-transport share one `links = "boringssl"` copy. 4.22 carries every ECH
  and uTLS API the transport backend uses; `boring-sys` (cmake + a C++ compiler)
  is a hard build requirement on every target. The `boring-tls`/`ech` features
  are no-op aliases. The Hysteria2 quiche client is a single driver task that
  bridges quiche's synchronous state machine to the async `DuplexStream` (TCP)
  and `UdpSession` (UDP datagrams) with real QUIC-flow-control backpressure;
  Salamander obfs and port-hopping are applied on the driver's own UDP socket.
  Observable runtime differences: BoringSSL's default ClientHello replaces
  rustls' for proxies without `client-fingerprint`; TLS session resumption is
  per BoringSSL `SSL_CTX` (64-entry cache); the QUIC ClientHello is now quiche's.

- **`ipv6` is now effective end-to-end and keeps the `false` default.** The
  `ipv6` flag previously only gated a handful of code paths — the resolver
  queried A and AAAA regardless — so the documented `false` default and
  `GET /configs` disagreed with the actual runtime behaviour. The flag now
  drives the whole resolution pipeline: with `ipv6: false` (the default,
  matching mihomo/Clash) AAAA lookups are skipped and the resolver answers
  IPv4-only; with `ipv6: true` dual-stack domains are queried for both A and
  AAAA (concurrently, with IPv4 tried first as a connection fallback) and
  `DirectAdapter` can fall back to IPv6 when IPv4 connectivity fails. The
  default literal is now centralized in `meow_config::effective_ipv6`
  (previously scattered across six `unwrap_or(...)` sites), and the parser,
  `GET /configs`, and `website/guide/configuration.md` all agree on `false`.
  **Operators who relied on the old always-dual-stack behaviour of an
  omitted `ipv6` key must now set `ipv6: true` explicitly.**

- DNS dual-stack resolution (`resolve_ips` / `lookup_ip_with_ipv6_inner`) now
  queries A and AAAA **concurrently** when IPv6 is enabled, collecting both
  address families with IPv4 ordered first. `DirectAdapter::dial_tcp` iterates
  the full address list, so an IPv4 connect failure no longer discards the IPv6
  candidate — IPv6 remains a connection fallback.

### Fixed

- Hysteria2 authentication no longer advertises HTTP/3 datagrams, preventing
  the server's HTTP/3 receiver from consuming raw QUIC UDP relay packets.
  The TProxy test image now includes the mandatory BoringSSL build toolchain.
- Internal HTTP downloads strip authentication and cookie headers when a
  redirect changes origin, and reject bodies that do not match Content-Length
  before replacing provider caches.
- Hysteria2 bounds queued TCP writes by bytes, retries exhausted QUIC stream
  limits without discarding requests, and propagates terminal stream errors.
  Restored idle keepalive and the remote response wait for `fast-open: false`;
  cancelling authentication or dropping a client releases its driver socket.
- **Auto-created `GLOBAL` selectors now default to the config's primary
  outbound.** Global mode always dispatches through `GLOBAL`, but the implicit
  selector previously sorted every registry key and used the first one when no
  choice was stored. That made global mode silently select `DIRECT` or route
  through an alphabetically-first quota/expiry pseudo-node. The generated
  selector still lists every proxy for mihomo-compatible dashboards, while its
  first member is now the final valid `MATCH` target, falling back to the first
  declared group or leaf proxy. Explicit user-defined `GLOBAL` groups remain
  unchanged.

- **`merge_family` no longer revives an expired sibling family.** When a new
  A answer merged into an entry whose AAAA had already expired, the old code
  unconditionally marked AAAA as `queried`, which `family_hit()` then read as a
  fresh `NoData`, suppressing re-resolution of AAAA. The sibling is now only
  carried forward when its own answer is still fresh; an expired sibling stays
  a `Miss` so the resolver re-queries it on demand.

- **`resolve_ips` no longer short-circuits when one family is cached.** A
  single-family cache entry (e.g. A already fresh, AAAA still `Miss`) no longer
  prevents the missing family from being queried. Only already-fresh families
  are dropped from the query set; the missing required family is always
  fetched, preserving `DirectAdapter`'s cross-family fallback.

- **`GET /configs` reports the same `ipv6` default the runtime uses.** The API
  previously reported `ipv6: false` for an unset config while the runtime
  actually queried AAAA anyway, causing UIs/controllers to display a state the
  resolver ignored. Both sides now share `meow_config::effective_ipv6` and
  default to `false` — and the reported value is the one actually enforced.

- **A fast NXDOMAIN no longer suppresses a slow positive answer.** Within a
  single nameserver tier, the first definitive negative (NODATA/NXDOMAIN) is
  now held for a short grace period while the remaining upstreams keep racing;
  a positive answer arriving later always wins. This restores correct
  behaviour for split-horizon / multi-upstream configurations. Network errors
  (`Err`) are not treated as definitive and never short-circuit the pool.

- **Single-flight broadcast misses no longer surface as SERVFAIL.** A
  subscriber that attached just after the publisher sent (and removed its
  inflight slot) previously received `Closed` and could be judged `Failed`.
  `lookup_real_with_ttl` now re-reads the cache on a missed broadcast, so the
  already-merged result is served instead of a transient SERVFAIL.

- **DoH response bodies are now size-capped.** `doh_exchange` previously
  `read_to_end`-ed an unbounded buffer, letting a misbehaving or hostile
  upstream drive unbounded heap growth. Responses are now rejected once they
  exceed the DNS message maximum (65535 B) plus HTTP header headroom.

- **`snapshot()` hides IPs of an expired family.** When one family is still
  fresh and the other has expired, only the fresh family's IPs appear in the
  cache snapshot panel.

- **Hosts-table AAAA answers follow the global `ipv6` switch.** An AAAA query
  for a domain present in the hosts trie is gated by `ipv6` exactly like every
  other AAAA path: with `ipv6: false` it returns NODATA even when the hosts
  file carries an IPv6 address for the domain (the entry remains reachable for
  A queries and for `ipv6: true` configs). This keeps the global toggle a
  single, predictable switch — dual-stack operators who pin addresses in
  `hosts:` must enable `ipv6: true` for the v6 entries to be served.
