use crate::sniffer::SnifferRuntime;
use base64::Engine;
use meow_common::{with_dial_timeout, AuthConfig, ConnType, Metadata, Network};
use meow_tunnel::{copy_bidirectional_buf_tracked, route_inbound_tcp, Tunnel, RELAY_BUF_SIZE};
use smallvec::smallvec;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub async fn handle_http(
    tunnel: &Tunnel,
    mut stream: TcpStream,
    src_addr: SocketAddr,
    sniffer: Option<&SnifferRuntime>,
    auth: Option<&AuthConfig>,
    in_name: &str,
    in_port: u16,
) {
    if let Err(e) = handle_http_inner(
        tunnel,
        &mut stream,
        src_addr,
        sniffer,
        auth,
        in_name,
        in_port,
    )
    .await
    {
        debug!("HTTP proxy error from {}: {}", src_addr, e);
    }
}

async fn handle_http_inner(
    tunnel: &Tunnel,
    stream: &mut TcpStream,
    src_addr: SocketAddr,
    sniffer: Option<&SnifferRuntime>,
    auth: Option<&AuthConfig>,
    in_name: &str,
    in_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read the HTTP request line and headers in chunks until we find
    // \r\n\r\n. Reading one byte at a time costs ~100 syscalls per CONNECT;
    // chunked reads cap the syscall count at ceil(headers / 1024).
    //
    // Bytes that arrive past the marker (e.g. POST body in a single TCP
    // segment) are sliced off into `leftover` so the relay path can re-emit
    // them after sending the rewritten request line.
    const CHUNK: usize = 1024;
    const MAX_HEADERS: usize = 8192;
    let mut request_buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; CHUNK];
    let mut validated = 0usize;
    let read_headers = async {
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before headers complete",
                ));
            }
            // Overlap the previous tail by 3 bytes so a marker straddling two
            // reads (e.g. "\r\n\r" then "\n…") is still detected.
            let search_start = request_buf.len().saturating_sub(3);
            request_buf.extend_from_slice(&chunk[..n]);
            let header_end = find_crlf_crlf(&request_buf[search_start..])
                .map(|relative| search_start + relative + 4);
            let bytes_to_validate = header_end.unwrap_or(request_buf.len());
            // Resume one byte back: the only byte a previous pass could leave
            // undecided is a trailing CR waiting for its LF. Rescanning from 0
            // would make a dribbled head quadratic.
            if bare_line_ending_from(
                &request_buf[..bytes_to_validate],
                validated.saturating_sub(1),
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bare CR or LF in request headers",
                ));
            }
            validated = bytes_to_validate;
            if let Some(header_end) = header_end {
                if header_end > MAX_HEADERS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request headers too large",
                    ));
                }
                return Ok(header_end);
            }
            if request_buf.len() > MAX_HEADERS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request headers too large",
                ));
            }
        }
    };
    let header_end =
        match tokio::time::timeout(crate::DEFAULT_HANDSHAKE_TIMEOUT, read_headers).await {
            Err(_) => return Err("HTTP proxy handshake timed out".into()),
            Ok(Err(error)) if error.kind() == io::ErrorKind::InvalidData => {
                write_bad_request(stream).await?;
                return Err(error.into());
            }
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(header_end)) => header_end,
        };
    let leftover: Vec<u8> = request_buf[header_end..].to_vec();
    request_buf.truncate(header_end);

    let request = match parse_request_head(&request_buf) {
        Ok(request) => request,
        Err(error) => {
            write_bad_request(stream).await?;
            return Err(error.into());
        }
    };

    // Auth check: verify Proxy-Authorization before dispatching.
    let in_user: Option<String> = if let Some(auth) = auth
        .filter(|a| !a.credentials.is_empty())
        .filter(|a| !a.should_skip(&src_addr.ip()))
    {
        match parse_proxy_authorization(&request.headers) {
            None => {
                stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"meow-rs\"\r\n\
                          Connection: close\r\n\
                          Content-Length: 0\r\n\r\n",
                    )
                    .await?;
                return Err("proxy authentication required".into());
            }
            Some((username, password)) => {
                if !auth.credentials.verify(&username, &password) {
                    stream
                        .write_all(
                            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                              Proxy-Authenticate: Basic realm=\"meow-rs\"\r\n\
                              Connection: close\r\n\
                              Content-Length: 0\r\n\r\n",
                        )
                        .await?;
                    return Err(format!("HTTP auth failed for user {username:?}").into());
                }
                Some(username)
            }
        }
    } else {
        None
    };

    let method = request.method;
    let target = request.target;

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTPS CONNECT
        let (host, port) = parse_host_port(target, 443);

        let mut metadata = Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Https,
            src_ip: Some(src_addr.ip()),
            src_port: src_addr.port(),
            // When the CONNECT target is an IP literal (common for the Netflix
            // OCA video CDN and other SNI-less clients), populate dst_ip so
            // IP-CIDR / GEOIP rules can match — mirrors the SOCKS5 IPv4/IPv6
            // ATYP path. Without this the connection falls through to MATCH.
            dst_ip: host_to_ip(host),
            host: Metadata::lower_host(host),
            dst_port: port,
            in_name: in_name.into(),
            in_port,
            in_user: in_user.as_deref().map(Into::into),
            ..Default::default()
        };

        debug!("HTTP CONNECT to {}:{}", host, port);

        // Send 200 Connection Established — the client will then send its
        // application data (e.g., TLS ClientHello) which we can peek at.
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;

        // Sniff TLS SNI from the client's TLS ClientHello (if applicable).
        if let Some(rt) = sniffer {
            rt.sniff(stream, &mut metadata).await;
        }

        // Hand off to the shared inbound routing+relay path. `leftover`
        // holds any application bytes the client pipelined ahead of the
        // 200 OK (RFC 7230 forbids this but real clients do it); the shared
        // path re-emits them to the remote before the bidirectional copy.
        let inner = tunnel.inner();
        route_inbound_tcp(inner, stream, metadata, &leftover).await;
    } else {
        // Plain HTTP proxy (GET/POST/etc via proxy)
        let url = target;
        let (host, port) = parse_url_host_port(url);

        let mut metadata = Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Http,
            src_ip: Some(src_addr.ip()),
            src_port: src_addr.port(),
            // Same IP-literal handling as the CONNECT path above, so plain
            // HTTP proxied to a raw IP still matches IP-CIDR / GEOIP rules.
            dst_ip: host_to_ip(host),
            host: Metadata::lower_host(host),
            dst_port: port,
            in_name: in_name.into(),
            in_port,
            in_user: in_user.as_deref().map(Into::into),
            ..Default::default()
        };

        // For plain HTTP, sniff_http on the already-read buffer so IP-literal
        // destinations still benefit from Host-header routing.
        if let Some(rt) = sniffer {
            if let Some(sniffed) = meow_common::sniffer::sniff_http(&request_buf) {
                rt.maybe_apply_sniff(&sniffed, &mut metadata);
            }
        }

        debug!("HTTP {} to {}:{}", method, host, port);

        let inner = tunnel.inner();
        inner.pre_handle_metadata(&mut metadata);
        let admission = inner.tcp_admission();
        let Some((proxy, rule_name, rule_payload)) = inner.resolve_proxy_lazy(&mut metadata).await
        else {
            write_bad_gateway(stream).await?;
            return Err("no matching rule".into());
        };

        info!(
            "{} --> {} match {}({}) using {}",
            metadata.source_address(),
            metadata.remote_address(),
            rule_name,
            rule_payload,
            proxy.name()
        );

        let Some(_guard) = admission.track(
            metadata.pure(),
            rule_name,
            rule_payload,
            smallvec![Arc::from(proxy.name())],
        ) else {
            return Ok(());
        };

        _guard
            .run_until_closed(async {
                match with_dial_timeout(proxy.name(), proxy.dial_tcp(&metadata)).await {
                    Ok(mut remote) => {
                        // Rewrite the request line: remove the absolute URI scheme+host,
                        // keep the path. Rebuild headers without Proxy-* headers while
                        // preserving all other field bytes exactly.
                        let path = extract_path_from_url(url);
                        let rewritten = rewrite_plain_request(&request, path);

                        // Force a one-request upstream exchange. The bounded client
                        // wrapper forwards exactly this request body, holds any
                        // pipelined request back, and marks the final response close.
                        remote.write_all(&rewritten).await?;
                        let up = Arc::clone(_guard.counters());
                        let dn = Arc::clone(_guard.counters());
                        // Relay scratch buffers live on this plain-HTTP path's stack —
                        // zero per-relay heap allocation (ADR-0008). Declared here
                        // (not at the top of handle_http_inner) so the dominant CONNECT
                        // path, which relays via the shared `route_inbound_tcp` helper
                        // and its own stack buffers, does not carry these 8 KiB.
                        let mut relay_buf_up = [0u8; RELAY_BUF_SIZE];
                        let mut relay_buf_dn = [0u8; RELAY_BUF_SIZE];
                        // Keep the response-head scratch out of `handle_http_inner`'s
                        // async frame. CONNECT is the dominant path and must not pay
                        // for storage used only by plain HTTP exchanges.
                        let pass_upstream_shutdown = AtomicBool::new(false);
                        let mut client = Box::new(SingleRequestClient::new(
                            stream,
                            &leftover,
                            request.body_kind,
                            request.upgrade_requested,
                            &pass_upstream_shutdown,
                        ));
                        // Client EOF should finish the upload direction and arm the
                        // relay linger, but it must not half-close an encrypted proxy
                        // transport before the origin has produced its response. A
                        // validated 101 switches this gate to ordinary tunnel
                        // half-close semantics.
                        let mut remote = ShutdownGate::new(remote, &pass_upstream_shutdown);

                        match copy_bidirectional_buf_tracked(
                            &mut *client,
                            &mut remote,
                            &mut relay_buf_up,
                            &mut relay_buf_dn,
                            |n| {
                                inner
                                    .stats
                                    .record_upload(&up, n as meow_common::atomic::Int);
                            },
                            |n| {
                                inner
                                    .stats
                                    .record_download(&dn, n as meow_common::atomic::Int);
                            },
                        )
                        .await
                        {
                            Ok((up, down)) => {
                                debug!("HTTP single-request relay closed: up={up} down={down}");
                            }
                            Err(e) => {
                                debug!("HTTP single-request relay error: {}", e);
                                // A response head the proxy rejects (oversized,
                                // malformed, invalid status line) aborts the relay
                                // before anything reached the client. Turn that into
                                // an explicit 502 rather than a silent connection
                                // close; once response bytes have flowed, appending
                                // an error would corrupt the stream instead.
                                let sent_response_bytes = client.sent_response_bytes;
                                drop(client);
                                if !sent_response_bytes {
                                    let _ = write_bad_gateway(stream).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("{}:{} HTTP dial error: {}", host, port, e);
                        write_bad_gateway(stream).await?;
                    }
                }
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            })
            .await
            .unwrap_or(Ok(()))?;
        // _guard drops here, removing the entry from Statistics.
    }

    Ok(())
}

/// Locate `b"\r\n\r\n"` in `buf` and return the index of the first `\r`.
fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Return true once a CR or LF can no longer be part of a CRLF pair. A final
/// CR is left undecided because its LF may arrive in the next socket read.
fn has_bare_line_ending(buf: &[u8]) -> bool {
    bare_line_ending_from(buf, 0)
}

/// [`has_bare_line_ending`] resuming at `start`. Bytes before `start` are still
/// read as context — the predicate for index `i` inspects `buf[i - 1]` and
/// `buf[i + 1]` — so a caller that already scanned a prefix passes the index of
/// its last (possibly undecided) byte rather than 0.
fn bare_line_ending_from(buf: &[u8], start: usize) -> bool {
    if start >= buf.len() {
        return false;
    }
    buf[start..].iter().enumerate().any(|(offset, byte)| {
        let index = start + offset;
        match *byte {
            b'\n' => index == 0 || buf[index - 1] != b'\r',
            b'\r' => index + 1 < buf.len() && buf[index + 1] != b'\n',
            _ => false,
        }
    })
}

#[derive(Debug)]
struct HeaderField<'a> {
    name: &'a [u8],
    value: &'a [u8],
    raw: &'a [u8],
}

/// Header fields stay heap-backed on purpose. `RequestHead` is held across the
/// dial await, so it sits in the per-connection future frame — inlining 32
/// fields would add ~1.5 KiB there for every connection, CONNECT included,
/// which costs more than the one allocation it saves (ADR-0011).
#[derive(Debug)]
struct RequestHead<'a> {
    method: &'a str,
    target: &'a str,
    version: &'a str,
    headers: Vec<HeaderField<'a>>,
    body_kind: RequestBodyKind,
    upgrade_requested: bool,
}

/// Split a header block on CRLF without allocating a line vector.
struct CrlfLines<'a> {
    remaining: Option<&'a [u8]>,
}

impl<'a> Iterator for CrlfLines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let remaining = self.remaining?;
        match remaining.windows(2).position(|window| window == b"\r\n") {
            Some(end) => {
                self.remaining = Some(&remaining[end + 2..]);
                Some(&remaining[..end])
            }
            None => {
                self.remaining = None;
                Some(remaining)
            }
        }
    }
}

fn parse_request_head(head: &[u8]) -> Result<RequestHead<'_>, &'static str> {
    if !head.ends_with(b"\r\n\r\n") || has_bare_line_ending(head) {
        return Err("invalid HTTP line ending");
    }

    let mut lines = CrlfLines {
        remaining: Some(&head[..head.len() - 4]),
    };
    let request_line = lines.next().ok_or("empty HTTP request")?;
    let request_line =
        std::str::from_utf8(request_line).map_err(|_| "non-ASCII HTTP request line")?;
    if !request_line.is_ascii() {
        return Err("non-ASCII HTTP request line");
    }
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty()
        || target.is_empty()
        || version.is_empty()
        || parts.next().is_some()
        || !method.as_bytes().iter().copied().all(is_tchar)
        || !target.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err("invalid HTTP request line");
    }

    let mut headers = Vec::new();
    for line in lines {
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or("HTTP header missing colon")?;
        let (name, value_with_colon) = line.split_at(colon);
        if name.is_empty() || !name.iter().copied().all(is_tchar) {
            return Err("invalid HTTP header name");
        }
        let value = &value_with_colon[1..];
        if !value
            .iter()
            .all(|byte| *byte == b'\t' || (*byte >= 0x20 && *byte != 0x7f))
        {
            return Err("invalid HTTP header value");
        }
        headers.push(HeaderField {
            name,
            value,
            raw: line,
        });
    }
    let body_kind = validate_message_framing(&headers, version)?;
    validate_connection_options(&headers)?;
    let upgrade_requested = validate_upgrade_request(&headers, body_kind, version)?;

    Ok(RequestHead {
        method,
        target,
        version,
        headers,
        body_kind,
        upgrade_requested,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestBodyKind {
    None,
    ContentLength(u64),
    Chunked,
}

fn validate_message_framing(
    headers: &[HeaderField<'_>],
    version: &str,
) -> Result<RequestBodyKind, &'static str> {
    let mut content_length = None;
    let mut has_content_length = false;
    let mut transfer_codings = Vec::new();

    for header in headers {
        if header.name.eq_ignore_ascii_case(b"content-length") {
            has_content_length = true;
            for value in header.value.split(|byte| *byte == b',') {
                let value = trim_ows(value);
                if value.is_empty() {
                    return Err("invalid Content-Length");
                }
                let parsed = value.iter().try_fold(0u64, |length, byte| {
                    byte.is_ascii_digit()
                        .then(|| length.checked_mul(10)?.checked_add(u64::from(*byte - b'0')))
                        .flatten()
                });
                let parsed = parsed.ok_or("invalid Content-Length")?;
                if content_length.is_some_and(|length| length != parsed) {
                    return Err("conflicting Content-Length values");
                }
                content_length = Some(parsed);
            }
        } else if header.name.eq_ignore_ascii_case(b"transfer-encoding") {
            parse_transfer_codings(header.value, &mut transfer_codings)?;
        }
    }

    if has_content_length && !transfer_codings.is_empty() {
        return Err("Transfer-Encoding with Content-Length is ambiguous");
    }
    if !transfer_codings.is_empty() {
        // RFC 9112 §6.1: Transfer-Encoding must not be sent on an HTTP/1.0
        // message. Recipients that ignore it there read no body at all and
        // treat the chunked payload as a new request — a desync primitive.
        if version == "HTTP/1.0" {
            return Err("Transfer-Encoding on an HTTP/1.0 request");
        }
        let chunked_count = transfer_codings
            .iter()
            .filter(|coding| coding.name.eq_ignore_ascii_case(b"chunked"))
            .count();
        if chunked_count != 1
            || !transfer_codings.last().is_some_and(|coding| {
                coding.name.eq_ignore_ascii_case(b"chunked") && !coding.has_parameters
            })
        {
            return Err("invalid request Transfer-Encoding");
        }
        return Ok(RequestBodyKind::Chunked);
    }
    Ok(content_length.map_or(RequestBodyKind::None, RequestBodyKind::ContentLength))
}

#[derive(Debug)]
struct TransferCoding<'a> {
    name: &'a [u8],
    has_parameters: bool,
}

/// Parse the RFC 9110 transfer-coding list without treating commas inside a
/// quoted parameter value as list separators.
fn parse_transfer_codings<'a>(
    value: &'a [u8],
    codings: &mut Vec<TransferCoding<'a>>,
) -> Result<(), &'static str> {
    let mut cursor = 0;
    skip_ows(value, &mut cursor);

    loop {
        let name = parse_token(value, &mut cursor).ok_or("invalid Transfer-Encoding")?;
        let mut has_parameters = false;

        loop {
            skip_ows(value, &mut cursor);
            if value.get(cursor) != Some(&b';') {
                break;
            }
            has_parameters = true;
            cursor += 1;
            skip_ows(value, &mut cursor);
            parse_token(value, &mut cursor).ok_or("invalid Transfer-Encoding parameter")?;
            skip_ows(value, &mut cursor);
            if value.get(cursor) != Some(&b'=') {
                return Err("invalid Transfer-Encoding parameter");
            }
            cursor += 1;
            skip_ows(value, &mut cursor);
            if value.get(cursor) == Some(&b'"') {
                parse_quoted_string(value, &mut cursor)?;
            } else {
                parse_token(value, &mut cursor)
                    .ok_or("invalid Transfer-Encoding parameter value")?;
            }
        }

        codings.push(TransferCoding {
            name,
            has_parameters,
        });
        skip_ows(value, &mut cursor);
        match value.get(cursor) {
            None => return Ok(()),
            Some(b',') => {
                cursor += 1;
                skip_ows(value, &mut cursor);
                if cursor == value.len() {
                    return Err("invalid Transfer-Encoding");
                }
            }
            _ => return Err("invalid Transfer-Encoding"),
        }
    }
}

fn parse_token<'a>(value: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let start = *cursor;
    while value.get(*cursor).is_some_and(|byte| is_tchar(*byte)) {
        *cursor += 1;
    }
    (*cursor != start).then_some(&value[start..*cursor])
}

fn parse_quoted_string(value: &[u8], cursor: &mut usize) -> Result<(), &'static str> {
    debug_assert_eq!(value.get(*cursor), Some(&b'"'));
    *cursor += 1;
    loop {
        match value.get(*cursor).copied() {
            Some(b'"') => {
                *cursor += 1;
                return Ok(());
            }
            Some(b'\\') => {
                *cursor += 1;
                let escaped = value
                    .get(*cursor)
                    .copied()
                    .ok_or("unterminated Transfer-Encoding quoted string")?;
                if !matches!(escaped, b'\t' | b' '..=b'~' | 0x80..=0xff) {
                    return Err("invalid Transfer-Encoding quoted pair");
                }
                *cursor += 1;
            }
            Some(b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff) => {
                *cursor += 1;
            }
            Some(_) => return Err("invalid Transfer-Encoding quoted string"),
            None => return Err("unterminated Transfer-Encoding quoted string"),
        }
    }
}

fn skip_ows(value: &[u8], cursor: &mut usize) {
    while value
        .get(*cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        *cursor += 1;
    }
}

const CONNECTION_CLOSE_HEADER: &[u8] = b"Connection: close\r\n";
const CONNECTION_UPGRADE_HEADER: &[u8] = b"Connection: upgrade\r\n";
const MAX_RESPONSE_HEADERS: usize = 8192;
const RESPONSE_BUFFER_SIZE: usize = MAX_RESPONSE_HEADERS + CONNECTION_UPGRADE_HEADER.len();
const MAX_CHUNK_LINE: usize = 8192;
const MAX_TRAILERS: usize = 8192;
const CLIENT_DISCARD_BUFFER_SIZE: usize = 1024;
const MAX_DISCARDED_CLIENT_BYTES: usize = 64 * 1024;
const MAX_HELD_UPGRADE_BYTES: usize = 64 * 1024;

/// Preserve the upstream write half when the client finishes its request.
///
/// Some outbound adapters translate `poll_shutdown` into a protocol-level
/// close (for example TLS `close_notify`). The HTTP relay still needs the
/// client-to-origin direction to reach `Cycle::Done` so its half-close linger
/// can reap a silent origin, but closing the adapter here can prevent that
/// origin from sending the response. The owned stream is dropped normally
/// when the response finishes or the linger expires. A successful upgrade (or
/// a declined upgrade whose final response head has arrived) opens the gate so
/// the connection resumes ordinary tunnel half-close behavior.
struct ShutdownGate<'gate, T> {
    inner: T,
    pass_shutdown: &'gate AtomicBool,
}

impl<'gate, T> ShutdownGate<'gate, T> {
    fn new(inner: T, pass_shutdown: &'gate AtomicBool) -> Self {
        Self {
            inner,
            pass_shutdown,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ShutdownGate<'_, T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, destination)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ShutdownGate<'_, T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, source)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pass_shutdown.load(Ordering::Acquire) {
            Pin::new(&mut this.inner).poll_shutdown(cx)
        } else {
            // Withholding the protocol-level close must not also withhold the
            // flush that `poll_shutdown` implies. The relay goes straight from
            // reader EOF to `poll_shutdown` without flushing, so a buffering
            // transport (TLS, WebSocket) may still hold tail request-body
            // bytes that would otherwise be silently discarded.
            Pin::new(&mut this.inner).poll_flush(cx)
        }
    }
}

struct SingleRequestClient<'stream, 'buffered, 'gate> {
    client: &'stream mut TcpStream,
    buffered: &'buffered [u8],
    buffered_pos: usize,
    body: RequestBodyDecoder,
    client_eof: bool,
    discarded_client_bytes: usize,
    discard_buf: [u8; CLIENT_DISCARD_BUFFER_SIZE],
    held: Vec<u8>,
    held_pos: usize,
    response_done: bool,
    response_buf: [u8; RESPONSE_BUFFER_SIZE],
    response_len: usize,
    response_pos: usize,
    response_state: ResponseWriteState,
    sent_response_bytes: bool,
    upgrade_requested: bool,
    upgrade_declined: bool,
    pass_upstream_shutdown: &'gate AtomicBool,
}

impl<'stream, 'buffered, 'gate> SingleRequestClient<'stream, 'buffered, 'gate> {
    fn new(
        client: &'stream mut TcpStream,
        buffered: &'buffered [u8],
        body_kind: RequestBodyKind,
        upgrade_requested: bool,
        pass_upstream_shutdown: &'gate AtomicBool,
    ) -> Self {
        Self {
            client,
            buffered,
            buffered_pos: 0,
            body: RequestBodyDecoder::new(body_kind),
            client_eof: false,
            discarded_client_bytes: 0,
            discard_buf: [0; CLIENT_DISCARD_BUFFER_SIZE],
            held: Vec::new(),
            held_pos: 0,
            response_done: false,
            response_buf: [0; RESPONSE_BUFFER_SIZE],
            response_len: 0,
            response_pos: 0,
            response_state: ResponseWriteState::Head,
            sent_response_bytes: false,
            upgrade_requested,
            upgrade_declined: false,
            pass_upstream_shutdown,
        }
    }

    fn poll_drain_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.response_pos < self.response_len {
            match Pin::new(&mut *self.client)
                .poll_write(cx, &self.response_buf[self.response_pos..self.response_len])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero bytes to HTTP proxy client",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    self.response_pos += written;
                    self.sent_response_bytes = true;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.response_len = 0;
        self.response_pos = 0;
        self.response_state = match self.response_state {
            ResponseWriteState::InterimPending => ResponseWriteState::Head,
            ResponseWriteState::FinalPending => {
                if self.upgrade_declined {
                    // A non-101 response can otherwise leave both sides
                    // waiting on an upstream keep-alive connection: the
                    // client was promised close semantics, but the upgrade
                    // request could not also ask the origin to close. Once
                    // the final head is delivered, half-close the request
                    // side so the origin finishes and closes its response.
                    self.pass_upstream_shutdown.store(true, Ordering::Release);
                    cx.waker().wake_by_ref();
                }
                ResponseWriteState::Streaming
            }
            ResponseWriteState::UpgradePending => {
                self.pass_upstream_shutdown.store(true, Ordering::Release);
                cx.waker().wake_by_ref();
                ResponseWriteState::Upgraded
            }
            state => state,
        };
        Poll::Ready(Ok(()))
    }

    fn prepare_response_head(&mut self) -> io::Result<()> {
        if has_bare_line_ending(&self.response_buf[..self.response_len]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bare CR or LF in upstream response headers",
            ));
        }
        let status = parse_response_status(&self.response_buf[..self.response_len])?;
        self.response_pos = 0;
        if (100..200).contains(&status) && status != 101 {
            // Interim heads previously passed through verbatim, leaking
            // origin hop-by-hop fields (Connection, Keep-Alive, nominated
            // headers) that contradict the close semantics of the final head.
            self.response_len = rewrite_response_head_in_place(
                &mut self.response_buf,
                self.response_len,
                ResponseConnection::Interim,
            )?;
            self.response_state = ResponseWriteState::InterimPending;
            return Ok(());
        }

        if status == 101 {
            if !self.upgrade_requested || !self.body.is_done() {
                return Err(invalid_data("unexpected upstream 101 response"));
            }
            validate_upgrade_response(&self.response_buf[..self.response_len])?;
            self.response_len = rewrite_response_head_in_place(
                &mut self.response_buf,
                self.response_len,
                ResponseConnection::Upgrade,
            )?;
            self.response_state = ResponseWriteState::UpgradePending;
        } else {
            self.upgrade_declined = self.upgrade_requested;
            self.response_len = rewrite_response_head_in_place(
                &mut self.response_buf,
                self.response_len,
                ResponseConnection::Close,
            )?;
            self.response_state = ResponseWriteState::FinalPending;
        }
        Ok(())
    }

    fn record_discarded_client_bytes(&mut self, count: usize) -> io::Result<()> {
        self.discarded_client_bytes = self
            .discarded_client_bytes
            .checked_add(count)
            .ok_or_else(|| invalid_data("discarded client bytes overflow"))?;
        if self.discarded_client_bytes > MAX_DISCARDED_CLIENT_BYTES {
            return Err(invalid_data(
                "too many client bytes after the request boundary",
            ));
        }
        Ok(())
    }

    /// Drain bytes after the framed request without forwarding them upstream.
    ///
    /// Before the response completes, reaching the client's FIN lets the
    /// upload relay direction finish and arms its idle linger. After the
    /// response completes, drain everything already queued and finish as soon
    /// as the socket becomes idle so ordinary keep-alive clients close
    /// promptly. The total discard cap prevents an attacker from turning this
    /// cleanup path into an unbounded read loop.
    fn poll_discard_after_body(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.buffered_pos < self.buffered.len() {
            let discarded = self.buffered.len() - self.buffered_pos;
            if let Err(error) = self.record_discarded_client_bytes(discarded) {
                return Poll::Ready(Err(error));
            }
            self.buffered_pos = self.buffered.len();
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.client_eof {
            return Poll::Ready(Ok(()));
        }
        if self.discarded_client_bytes == MAX_DISCARDED_CLIENT_BYTES {
            return Poll::Ready(Err(invalid_data(
                "too many client bytes after the request boundary",
            )));
        }

        let available =
            (MAX_DISCARDED_CLIENT_BYTES - self.discarded_client_bytes).min(self.discard_buf.len());
        let mut discard = ReadBuf::new(&mut self.discard_buf[..available]);
        match Pin::new(&mut *self.client).poll_read(cx, &mut discard) {
            Poll::Ready(Ok(())) if discard.filled().is_empty() => {
                self.client_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(())) => {
                let count = discard.filled().len();
                if let Err(error) = self.record_discarded_client_bytes(count) {
                    return Poll::Ready(Err(error));
                }
                // The socket returned data rather than registering our waker.
                // Re-poll on a fresh task turn to keep draining without an
                // unbounded loop in one `poll_read` call.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending if self.response_done => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Consume early client protocol bytes into a bounded hold while the
    /// origin decides the Upgrade. Reading them (rather than leaving them in
    /// the kernel receive queue) keeps the client's FIN observable, so an
    /// abandoned handshake still completes the upload relay direction and
    /// arms the half-close linger instead of pinning the connection on a
    /// silent origin forever. The held bytes are replayed by `poll_read` only
    /// after a validated `101`; a declined upgrade drops them unforwarded.
    fn poll_hold_before_upgrade(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.client_eof {
            return Poll::Ready(Ok(()));
        }
        let capacity = MAX_HELD_UPGRADE_BYTES - self.held.len();
        if capacity == 0 {
            return Poll::Ready(Err(invalid_data(
                "too many client bytes before the upgrade decision",
            )));
        }

        let available = capacity.min(self.discard_buf.len());
        let mut staged = ReadBuf::new(&mut self.discard_buf[..available]);
        match Pin::new(&mut *self.client).poll_read(cx, &mut staged) {
            Poll::Ready(Ok(())) if staged.filled().is_empty() => {
                self.client_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(())) => {
                self.held.extend_from_slice(staged.filled());
                // The socket returned data rather than registering our waker.
                // Re-poll on a fresh task turn to keep the FIN observable
                // without an unbounded loop in one `poll_read` call.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for SingleRequestClient<'_, '_, '_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let initially_filled = destination.filled().len();

        loop {
            if this.response_state == ResponseWriteState::Upgraded {
                if this.buffered_pos < this.buffered.len() {
                    let available = destination
                        .remaining()
                        .min(this.buffered.len() - this.buffered_pos);
                    destination.put_slice(
                        &this.buffered[this.buffered_pos..this.buffered_pos + available],
                    );
                    this.buffered_pos += available;
                    return Poll::Ready(Ok(()));
                }
                if this.held_pos < this.held.len() {
                    let available = destination.remaining().min(this.held.len() - this.held_pos);
                    destination.put_slice(&this.held[this.held_pos..this.held_pos + available]);
                    this.held_pos += available;
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut *this.client).poll_read(cx, destination);
            }
            if this.upgrade_declined && this.response_state == ResponseWriteState::Streaming {
                return Poll::Ready(Ok(()));
            }

            // A final response may legitimately end before the client sends
            // the declared request body (for example, an early 413). Once the
            // upstream response has closed, stop the upload direction too so
            // the relay does not retain the connection until its half-close
            // linger expires while waiting for body bytes that are no longer
            // useful.
            if this.response_done && !this.body.is_done() {
                return Poll::Ready(Ok(()));
            }
            if this.body.is_done() {
                if destination.filled().len() != initially_filled {
                    return Poll::Ready(Ok(()));
                }
                if this.upgrade_requested
                    && matches!(
                        this.response_state,
                        ResponseWriteState::Head
                            | ResponseWriteState::InterimPending
                            | ResponseWriteState::UpgradePending
                    )
                {
                    return this.poll_hold_before_upgrade(cx);
                }
                return this.poll_discard_after_body(cx);
            }
            if destination.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            if this.buffered_pos < this.buffered.len() {
                let available = destination
                    .remaining()
                    .min(this.buffered.len() - this.buffered_pos);
                let source = &this.buffered[this.buffered_pos..this.buffered_pos + available];
                let consumed = match this.body.consume_slice(source) {
                    Ok(consumed) => consumed,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                destination.put_slice(&source[..consumed]);
                this.buffered_pos += consumed;
                continue;
            }

            let mut socket_read = destination.take(destination.remaining());
            match Pin::new(&mut *this.client).poll_read(cx, &mut socket_read) {
                Poll::Ready(Ok(())) if socket_read.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "request body ended before its framing boundary",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    let initialized = socket_read.initialized().len();
                    let filled = socket_read.filled().len();
                    let consumed = match this.body.consume_slice(socket_read.filled()) {
                        Ok(consumed) => consumed,
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    let discarded = filled - consumed;
                    // `take` does not propagate the child ReadBuf's initialized
                    // length back to its parent. Record it before advancing so
                    // this adapter remains correct even if called with an
                    // initially-uninitialized destination.
                    unsafe { destination.assume_init(initialized) };
                    if let Err(error) = this.record_discarded_client_bytes(discarded) {
                        return Poll::Ready(Err(error));
                    }
                    destination.advance(consumed);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending if destination.filled().len() != initially_filled => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SingleRequestClient<'_, '_, '_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            match this.response_state {
                ResponseWriteState::InterimPending
                | ResponseWriteState::FinalPending
                | ResponseWriteState::UpgradePending => match this.poll_drain_response(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                },
                ResponseWriteState::Streaming | ResponseWriteState::Upgraded => {
                    return Pin::new(&mut *this.client).poll_write(cx, source);
                }
                ResponseWriteState::Head => {
                    if source.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    let available = MAX_RESPONSE_HEADERS.saturating_sub(this.response_len);
                    if available == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "upstream response headers are too large",
                        )));
                    }
                    let old_len = this.response_len;
                    let copied = available.min(source.len());
                    this.response_buf[old_len..old_len + copied].copy_from_slice(&source[..copied]);
                    this.response_len += copied;

                    let search_start = old_len.saturating_sub(3);
                    if let Some(marker) =
                        find_crlf_crlf(&this.response_buf[search_start..this.response_len])
                            .map(|relative| search_start + relative)
                    {
                        let head_end = marker + 4;
                        let consumed = head_end - old_len;
                        this.response_len = head_end;
                        if let Err(error) = this.prepare_response_head() {
                            return Poll::Ready(Err(error));
                        }
                        return Poll::Ready(Ok(consumed));
                    }
                    return Poll::Ready(Ok(copied));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(
            this.response_state,
            ResponseWriteState::InterimPending
                | ResponseWriteState::FinalPending
                | ResponseWriteState::UpgradePending
        ) {
            match this.poll_drain_response(cx) {
                Poll::Ready(Ok(())) => {}
                result => return result,
            }
        }
        Pin::new(&mut *this.client).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(
            this.response_state,
            ResponseWriteState::InterimPending
                | ResponseWriteState::FinalPending
                | ResponseWriteState::UpgradePending
        ) {
            match this.poll_drain_response(cx) {
                Poll::Ready(Ok(())) => {}
                result => return result,
            }
        }
        if this.response_state == ResponseWriteState::Head {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream closed before its final response headers completed",
            )));
        }
        if !this.response_done {
            this.response_done = true;
            cx.waker().wake_by_ref();
        }
        Pin::new(&mut *this.client).poll_shutdown(cx)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResponseWriteState {
    Head,
    InterimPending,
    FinalPending,
    UpgradePending,
    Streaming,
    Upgraded,
}

enum RequestBodyDecoder {
    ContentLength(u64),
    Chunked(ChunkState),
    Done,
}

impl RequestBodyDecoder {
    fn new(kind: RequestBodyKind) -> Self {
        match kind {
            RequestBodyKind::None | RequestBodyKind::ContentLength(0) => Self::Done,
            RequestBodyKind::ContentLength(length) => Self::ContentLength(length),
            RequestBodyKind::Chunked => Self::Chunked(ChunkState::size_line()),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self, Self::Done)
    }

    fn consume(&mut self, byte: u8) -> io::Result<()> {
        match self {
            Self::ContentLength(remaining) => {
                *remaining -= 1;
                if *remaining == 0 {
                    *self = Self::Done;
                }
                Ok(())
            }
            Self::Chunked(state) => {
                if state.consume(byte)? {
                    *self = Self::Done;
                }
                Ok(())
            }
            Self::Done => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bytes arrived after the request body boundary",
            )),
        }
    }

    /// Consume body bytes from `bytes`, stopping at the framing boundary.
    /// Returns how many bytes belong to the body. Content-Length bodies
    /// advance in bulk; only chunked framing needs the per-byte state machine.
    fn consume_slice(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Self::ContentLength(remaining) = self {
            let consumed = u64::min(*remaining, bytes.len() as u64) as usize;
            *remaining -= consumed as u64;
            if *remaining == 0 {
                *self = Self::Done;
            }
            return Ok(consumed);
        }
        let mut consumed = 0;
        for &byte in bytes {
            self.consume(byte)?;
            consumed += 1;
            if self.is_done() {
                break;
            }
        }
        Ok(consumed)
    }
}

enum ChunkState {
    SizeLine {
        size: u64,
        digits: usize,
        in_extensions: bool,
        saw_cr: bool,
        line_bytes: usize,
    },
    Data(u64),
    DataCr,
    DataLf,
    Trailers {
        line_bytes: usize,
        total_bytes: usize,
        saw_cr: bool,
    },
}

impl ChunkState {
    fn size_line() -> Self {
        Self::SizeLine {
            size: 0,
            digits: 0,
            in_extensions: false,
            saw_cr: false,
            line_bytes: 0,
        }
    }

    /// Consume one raw chunked-body byte. `true` marks the terminating empty
    /// trailer line. Input is prefetched in 4 KiB blocks, so this byte-level
    /// state machine does not cause byte-at-a-time socket reads or allocation.
    fn consume(&mut self, byte: u8) -> io::Result<bool> {
        let mut next = None;
        match self {
            Self::SizeLine {
                size,
                digits,
                in_extensions,
                saw_cr,
                line_bytes,
            } => {
                *line_bytes += 1;
                if *line_bytes > MAX_CHUNK_LINE {
                    return Err(invalid_data("chunk size line is too large"));
                }
                if *saw_cr {
                    if byte != b'\n' {
                        return Err(invalid_data("chunk size CR is not followed by LF"));
                    }
                    if *digits == 0 {
                        return Err(invalid_data("empty chunk size"));
                    }
                    next = Some(if *size == 0 {
                        Self::Trailers {
                            line_bytes: 0,
                            total_bytes: 0,
                            saw_cr: false,
                        }
                    } else {
                        Self::Data(*size)
                    });
                } else if byte == b'\r' {
                    *saw_cr = true;
                } else if byte == b'\n' {
                    return Err(invalid_data("chunk size contains a bare LF"));
                } else if !*in_extensions {
                    if let Some(digit) = hex_value(byte) {
                        *digits += 1;
                        *size = size
                            .checked_mul(16)
                            .and_then(|value| value.checked_add(u64::from(digit)))
                            .ok_or_else(|| invalid_data("chunk size is too large"))?;
                    } else if byte == b';' && *digits != 0 {
                        *in_extensions = true;
                    } else {
                        return Err(invalid_data("invalid chunk size"));
                    }
                } else if !is_field_value_byte(byte) {
                    return Err(invalid_data("invalid chunk extension"));
                }
            }
            Self::Data(remaining) => {
                *remaining -= 1;
                if *remaining == 0 {
                    next = Some(Self::DataCr);
                }
            }
            Self::DataCr => {
                if byte != b'\r' {
                    return Err(invalid_data("chunk data is not followed by CRLF"));
                }
                next = Some(Self::DataLf);
            }
            Self::DataLf => {
                if byte != b'\n' {
                    return Err(invalid_data("chunk data is not followed by CRLF"));
                }
                next = Some(Self::size_line());
            }
            Self::Trailers {
                line_bytes,
                total_bytes,
                saw_cr,
            } => {
                *total_bytes += 1;
                if *total_bytes > MAX_TRAILERS {
                    return Err(invalid_data("chunked trailers are too large"));
                }
                if *saw_cr {
                    if byte != b'\n' {
                        return Err(invalid_data("trailer CR is not followed by LF"));
                    }
                    if *line_bytes == 0 {
                        return Ok(true);
                    }
                    *line_bytes = 0;
                    *saw_cr = false;
                } else if byte == b'\r' {
                    *saw_cr = true;
                } else if byte == b'\n' {
                    return Err(invalid_data("chunked trailers contain a bare LF"));
                } else if is_field_value_byte(byte) {
                    *line_bytes += 1;
                } else {
                    return Err(invalid_data("invalid chunked trailer byte"));
                }
            }
        }
        if let Some(next) = next {
            *self = next;
        }
        Ok(false)
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_field_value_byte(byte: u8) -> bool {
    byte == b'\t' || (byte >= b' ' && byte != 0x7f)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn parse_response_status(head: &[u8]) -> io::Result<u16> {
    let line_end = head
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| invalid_data("upstream response is missing a status line"))?;
    let mut parts = head[..line_end].split(|byte| *byte == b' ');
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !matches!(version, b"HTTP/1.0" | b"HTTP/1.1")
        || status.len() != 3
        || !status.iter().all(u8::is_ascii_digit)
    {
        return Err(invalid_data("invalid upstream HTTP status line"));
    }
    Ok(status
        .iter()
        .fold(0u16, |value, digit| value * 10 + u16::from(*digit - b'0')))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResponseConnection {
    Interim,
    Close,
    Upgrade,
}

/// Walk the CRLF-delimited header lines of a response head, yielding the
/// byte ranges of each field name and value. Returns the status-line end
/// (the index of its CR) once the walk completes.
fn for_each_response_header<F>(head: &[u8], mut visit: F) -> io::Result<usize>
where
    F: FnMut(std::ops::Range<usize>, std::ops::Range<usize>) -> io::Result<()>,
{
    let status_end = head
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| invalid_data("upstream response is missing a status line"))?;
    let mut read = status_end + 2;
    while read + 2 <= head.len() {
        let relative_end = head[read..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| invalid_data("malformed upstream response header"))?;
        let line_end = read + relative_end;
        if line_end == read {
            break;
        }
        let colon = head[read..line_end]
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| invalid_data("upstream response header is missing a colon"))?;
        visit(read..read + colon, read + colon + 1..line_end)?;
        read = line_end + 2;
    }
    Ok(status_end)
}

/// Byte ranges (into the response head) of every non-empty Connection option,
/// collected in one pass so drop checks stay linear in the head size.
type NominatedOptions = smallvec::SmallVec<[(u16, u16); 8]>;

fn collect_connection_options(head: &[u8]) -> io::Result<NominatedOptions> {
    let mut nominated = NominatedOptions::new();
    for_each_response_header(head, |name, value| {
        if head[name].eq_ignore_ascii_case(b"connection") {
            let mut option_start = value.start;
            for index in value.start..=value.end {
                if index != value.end && head[index] != b',' {
                    continue;
                }
                let mut start = option_start;
                let mut end = index;
                while start < end && matches!(head[start], b' ' | b'\t') {
                    start += 1;
                }
                while end > start && matches!(head[end - 1], b' ' | b'\t') {
                    end -= 1;
                }
                if start < end {
                    nominated.push((start as u16, end as u16));
                }
                option_start = index + 1;
            }
        }
        Ok(())
    })?;
    Ok(nominated)
}

fn rewrite_response_head_in_place(
    buf: &mut [u8],
    head_len: usize,
    connection: ResponseConnection,
) -> io::Result<usize> {
    let nominated = collect_connection_options(&buf[..head_len])?;
    let mut drop_lines = [0u8; MAX_RESPONSE_HEADERS.div_ceil(8)];

    let head = &buf[..head_len];
    let status_end = for_each_response_header(head, |name_range, value_range| {
        let read = name_range.start;
        let name = &head[name_range];
        if name.is_empty() || !name.iter().copied().all(is_tchar) {
            return Err(invalid_data("invalid upstream response header name"));
        }
        if name.eq_ignore_ascii_case(b"connection") {
            validate_response_connection_options(&head[value_range])?;
        }
        let preserve_upgrade =
            connection == ResponseConnection::Upgrade && name.eq_ignore_ascii_case(b"upgrade");
        let is_nominated = nominated
            .iter()
            .any(|&(start, end)| head[start as usize..end as usize].eq_ignore_ascii_case(name));
        let drop = name.eq_ignore_ascii_case(b"connection")
            || name.eq_ignore_ascii_case(b"proxy-connection")
            || name.eq_ignore_ascii_case(b"keep-alive")
            || (name.eq_ignore_ascii_case(b"upgrade") && !preserve_upgrade)
            || (connection == ResponseConnection::Upgrade
                && (name.eq_ignore_ascii_case(b"content-length")
                    || name.eq_ignore_ascii_case(b"transfer-encoding")))
            || (is_nominated && !preserve_upgrade);
        if drop {
            drop_lines[read / 8] |= 1 << (read % 8);
        }
        Ok(())
    })?;
    let mut read;

    let mut write = status_end + 2;
    read = status_end + 2;
    while read + 2 <= head_len {
        let relative_end = buf[read..head_len]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| invalid_data("malformed upstream response header"))?;
        let line_end = read + relative_end;
        if line_end == read {
            break;
        }
        if drop_lines[read / 8] & (1 << (read % 8)) == 0 {
            buf.copy_within(read..line_end + 2, write);
            write += line_end + 2 - read;
        }
        read = line_end + 2;
    }

    let connection_header: &[u8] = match connection {
        // An interim response never carries connection semantics of its own;
        // the final response head states them.
        ResponseConnection::Interim => b"",
        ResponseConnection::Close => CONNECTION_CLOSE_HEADER,
        ResponseConnection::Upgrade => CONNECTION_UPGRADE_HEADER,
    };
    let required = write + connection_header.len() + 2;
    if required > buf.len() {
        return Err(invalid_data(
            "rewritten upstream response headers are too large",
        ));
    }
    buf[write..write + connection_header.len()].copy_from_slice(connection_header);
    write += connection_header.len();
    buf[write..write + 2].copy_from_slice(b"\r\n");
    Ok(write + 2)
}

fn validate_upgrade_response(head: &[u8]) -> io::Result<()> {
    if !response_connection_nominates(head, b"upgrade")? {
        return Err(invalid_data(
            "upstream 101 response is missing Connection: upgrade",
        ));
    }

    let mut saw_protocol = false;
    for_each_response_header(head, |name, value| {
        if head[name].eq_ignore_ascii_case(b"upgrade") {
            validate_upgrade_protocol_list(&head[value], &mut saw_protocol)
                .map_err(invalid_data)?;
        }
        Ok(())
    })?;
    if !saw_protocol {
        return Err(invalid_data(
            "upstream 101 response is missing an Upgrade protocol",
        ));
    }
    Ok(())
}

fn response_connection_nominates(head: &[u8], candidate: &[u8]) -> io::Result<bool> {
    let mut nominates = false;
    for_each_response_header(head, |name, value| {
        if head[name].eq_ignore_ascii_case(b"connection") {
            for option in head[value].split(|byte| *byte == b',') {
                let option = trim_ows(option);
                if !option.is_empty() && option.eq_ignore_ascii_case(candidate) {
                    nominates = true;
                }
            }
        }
        Ok(())
    })?;
    Ok(nominates)
}

fn validate_response_connection_options(value: &[u8]) -> io::Result<()> {
    for option in value.split(|byte| *byte == b',') {
        let option = trim_ows(option);
        // RFC 9110 section 5.6.1.2 requires recipients to accept and ignore a
        // reasonable number of empty list elements, including a trailing comma.
        if option.is_empty() {
            continue;
        }
        if !option.iter().copied().all(is_tchar) {
            return Err(invalid_data("invalid upstream Connection header"));
        }
        if option.eq_ignore_ascii_case(b"content-length")
            || option.eq_ignore_ascii_case(b"transfer-encoding")
        {
            return Err(invalid_data(
                "upstream Connection header names an HTTP framing field",
            ));
        }
    }
    Ok(())
}

fn validate_connection_options(headers: &[HeaderField<'_>]) -> Result<(), &'static str> {
    for header in headers {
        if !header.name.eq_ignore_ascii_case(b"connection") {
            continue;
        }
        for option in header.value.split(|byte| *byte == b',') {
            let option = trim_ows(option);
            if option.is_empty() {
                continue;
            }
            if !option.iter().copied().all(is_tchar) {
                return Err("invalid Connection header");
            }
            if option.eq_ignore_ascii_case(b"content-length")
                || option.eq_ignore_ascii_case(b"transfer-encoding")
                || option.eq_ignore_ascii_case(b"host")
            {
                return Err("Connection header names an HTTP framing field");
            }
        }
    }
    Ok(())
}

fn connection_nominates(headers: &[HeaderField<'_>], name: &[u8]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case(b"connection")
            && header
                .value
                .split(|byte| *byte == b',')
                .any(|option| trim_ows(option).eq_ignore_ascii_case(name))
    })
}

fn validate_upgrade_request(
    headers: &[HeaderField<'_>],
    body_kind: RequestBodyKind,
    version: &str,
) -> Result<bool, &'static str> {
    if !connection_nominates(headers, b"upgrade") {
        return Ok(false);
    }
    if version != "HTTP/1.1" {
        return Err("HTTP Upgrade requires HTTP/1.1");
    }
    if !matches!(
        body_kind,
        RequestBodyKind::None | RequestBodyKind::ContentLength(0)
    ) {
        // Holding bytes beyond a variable request-body boundary until the 101
        // decision would require a second body-sized staging buffer. WebSocket
        // and the other deployed HTTP/1.1 upgrades use a bodyless handshake.
        return Err("HTTP Upgrade request must not have a body");
    }

    let mut saw_protocol = false;
    for header in headers {
        if header.name.eq_ignore_ascii_case(b"upgrade") {
            validate_upgrade_protocol_list(header.value, &mut saw_protocol)?;
        }
    }
    if !saw_protocol {
        return Err("Connection: upgrade requires an Upgrade protocol");
    }
    Ok(true)
}

fn validate_upgrade_protocol_list(
    value: &[u8],
    saw_protocol: &mut bool,
) -> Result<(), &'static str> {
    for protocol in value.split(|byte| *byte == b',') {
        let protocol = trim_ows(protocol);
        // Upgrade is a list field, so RFC 9110 section 5.6.1.2 permits empty
        // elements. At least one real protocol is still required overall.
        if protocol.is_empty() {
            continue;
        }
        let mut parts = protocol.split(|byte| *byte == b'/');
        let name = parts.next().unwrap_or_default();
        let version = parts.next();
        if name.is_empty()
            || !name.iter().copied().all(is_tchar)
            || version
                .is_some_and(|version| version.is_empty() || !version.iter().copied().all(is_tchar))
            || parts.next().is_some()
        {
            return Err("invalid Upgrade protocol");
        }
        *saw_protocol = true;
    }
    Ok(())
}

fn rewrite_plain_request(request: &RequestHead<'_>, path: &str) -> Vec<u8> {
    // Exact hint: request line + every forwarded field with its CRLF + the
    // canonical Content-Length + the terminating CRLF. Over-counting the few
    // dropped fields beats the reallocations an under-sized hint costs.
    let headers_len: usize = request
        .headers
        .iter()
        .map(|header| header.raw.len() + 2)
        .sum();
    let mut rewritten = Vec::with_capacity(
        request.method.len()
            + path.len()
            + request.version.len()
            + 4
            + headers_len
            + 32
            + CONNECTION_CLOSE_HEADER.len(),
    );
    rewritten.extend_from_slice(request.method.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(path.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(request.version.as_bytes());
    rewritten.extend_from_slice(b"\r\n");
    for header in &request.headers {
        let is_upgrade = header.name.eq_ignore_ascii_case(b"upgrade");
        if header.name.eq_ignore_ascii_case(b"proxy-connection")
            || header.name.eq_ignore_ascii_case(b"proxy-authorization")
            // Re-emitted below in canonical form.
            || header.name.eq_ignore_ascii_case(b"content-length")
            || header.name.eq_ignore_ascii_case(b"connection")
            || header.name.eq_ignore_ascii_case(b"keep-alive")
            || (is_upgrade && !request.upgrade_requested)
            || (connection_nominates(&request.headers, header.name)
                && !(request.upgrade_requested && is_upgrade))
        {
            continue;
        }
        rewritten.extend_from_slice(header.raw);
        rewritten.extend_from_slice(b"\r\n");
    }
    // RFC 9112 §6.3.5: a recipient forwarding a message whose Content-Length
    // was duplicated or list-form must replace it with one valid field, so the
    // next hop cannot read a different length than this one did.
    if let RequestBodyKind::ContentLength(content_length) = request.body_kind {
        use std::io::Write as _;
        let _ = write!(rewritten, "Content-Length: {content_length}\r\n");
    }
    rewritten.extend_from_slice(if request.upgrade_requested {
        CONNECTION_UPGRADE_HEADER
    } else {
        CONNECTION_CLOSE_HEADER
    });
    rewritten.extend_from_slice(b"\r\n");
    rewritten
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

async fn write_bad_request(stream: &mut TcpStream) -> io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 400 Bad Request\r\n\
              Connection: close\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await
}

async fn write_bad_gateway(stream: &mut TcpStream) -> io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 502 Bad Gateway\r\n\
              Connection: close\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await
}

/// Parse an HTTP host token as an IP literal, returning `Some(ip)` when it is
/// one. Strips the surrounding brackets of an IPv6 literal (`[2606:..]`) so it
/// parses; returns `None` for hostnames, which are resolved later by the
/// adapter. Used to populate `Metadata::dst_ip` so IP-CIDR / GEOIP rules match
/// IP-literal destinations (e.g. Netflix OCA video servers connected by raw IP).
fn host_to_ip(host: &str) -> Option<IpAddr> {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<IpAddr>()
        .ok()
}

fn parse_host_port(target: &str, default_port: u16) -> (&str, u16) {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host, port);
        }
    }
    (target, default_port)
}

/// Parse host and port from an absolute HTTP or WebSocket URL.
fn parse_url_host_port(url: &str) -> (&str, u16) {
    // Strip scheme
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("ws://"))
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    // Take the authority part (before first /)
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    let default_port = if url.starts_with("https://") { 443 } else { 80 };
    parse_host_port(authority, default_port)
}

/// Extract the path from an absolute HTTP or WebSocket URL.
fn extract_path_from_url(url: &str) -> &str {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("ws://"))
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    without_scheme
        .find('/')
        .map_or("/", |i| &without_scheme[i..])
}

/// Parse `Proxy-Authorization: Basic <base64>` from parsed request headers.
/// Returns `(username, password)` on success.
fn parse_proxy_authorization(headers: &[HeaderField<'_>]) -> Option<(String, String)> {
    for header in headers {
        if !header.name.eq_ignore_ascii_case(b"proxy-authorization") {
            continue;
        }
        let value = trim_ows(header.value);
        let separator = value.iter().position(|byte| matches!(byte, b' ' | b'\t'))?;
        if !value[..separator].eq_ignore_ascii_case(b"basic") {
            return None;
        }
        let encoded = std::str::from_utf8(trim_ows(&value[separator..])).ok()?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        let (user, pass) = decoded_str.split_once(':')?;
        return Some((user.to_string(), pass.to_string()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::task::Waker;

    #[derive(Default)]
    struct FlushProbe {
        flushed: bool,
        shutdown: bool,
    }

    impl AsyncWrite for FlushProbe {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            source: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(source.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().flushed = true;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().shutdown = true;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn shutdown_gate_flushes_while_withholding_the_close() {
        // The relay goes straight from reader EOF to poll_shutdown without a
        // flush; a gated shutdown must still drain a buffering transport or
        // tail request-body bytes are lost.
        let pass_shutdown = AtomicBool::new(false);
        let mut gate = ShutdownGate::new(FlushProbe::default(), &pass_shutdown);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut gate).poll_shutdown(&mut cx).is_ready());
        assert!(
            gate.inner.flushed,
            "gated shutdown must flush the transport"
        );
        assert!(
            !gate.inner.shutdown,
            "gated shutdown must not close the transport"
        );

        pass_shutdown.store(true, Ordering::Release);
        assert!(Pin::new(&mut gate).poll_shutdown(&mut cx).is_ready());
        assert!(gate.inner.shutdown, "open gate must pass the shutdown");
    }

    #[test]
    fn host_to_ip_parses_ipv4_literal() {
        // Regression: Netflix OCA servers are connected by raw IP via CONNECT.
        // dst_ip must be populated so IP-CIDR rules (e.g. 23.246.0.0/18) match
        // instead of falling through to MATCH.
        assert_eq!(
            host_to_ip("23.246.15.143"),
            Some(IpAddr::V4(Ipv4Addr::new(23, 246, 15, 143)))
        );
    }

    #[test]
    fn host_to_ip_parses_bracketed_ipv6_literal() {
        assert_eq!(
            host_to_ip("[2606:2800:220:1:248:1893:25c8:1946]"),
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946
            )))
        );
    }

    #[test]
    fn host_to_ip_returns_none_for_hostname() {
        // Hostnames stay None — resolved later by the adapter / pre_resolve.
        assert_eq!(host_to_ip("www.netflix.com"), None);
        assert_eq!(host_to_ip("nflxvideo.net"), None);
    }

    #[test]
    fn strict_parser_rejects_bare_lf_and_bare_cr() {
        assert!(parse_request_head(
            b"GET http://example.com/ HTTP/1.1\r\nX-A: 1\nContent-Length: 0\r\n\r\n"
        )
        .is_err());
        assert!(parse_request_head(
            b"GET http://example.com/ HTTP/1.1\r\nX-A: 1\rContent-Length: 0\r\n\r\n"
        )
        .is_err());
        assert!(parse_request_head(
            b"GET http://example.com/ HTTP/1.1\r\nX-A: 1\n\nX-Dropped: yes\r\n\r\n"
        )
        .is_err());
    }

    #[test]
    fn rewrite_preserves_obs_text_and_sets_close_semantics() {
        let request = parse_request_head(
            b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nX-Word: caf\xe9\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic dTpw\r\n\r\n",
        )
        .unwrap();
        let rewritten = rewrite_plain_request(&request, "/path");
        assert_eq!(
            rewritten,
            b"GET /path HTTP/1.1\r\nHost: example.com\r\nX-Word: caf\xe9\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn rewrite_removes_connection_nominated_headers() {
        let request = parse_request_head(
            b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nConnection: X-Hop, keep-alive\r\nX-Hop: secret\r\nKeep-Alive: timeout=5\r\nX-End-To-End: kept\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            rewrite_plain_request(&request, "/path"),
            b"GET /path HTTP/1.1\r\nHost: example.com\r\nX-End-To-End: kept\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn upgrade_rewrite_preserves_only_upgrade_hop_fields() {
        let request = parse_request_head(
            b"GET http://example.com/chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade, X-Hop\r\nUpgrade: websocket\r\nX-Hop: secret\r\n\r\n",
        )
        .unwrap();
        assert!(request.upgrade_requested);
        assert_eq!(
            rewrite_plain_request(&request, "/chat"),
            b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n"
        );

        let response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, X-Hop\r\nUpgrade: websocket\r\nX-Hop: secret\r\nContent-Length: 99\r\n\r\n";
        validate_upgrade_response(response).unwrap();
        let mut buffer = [0u8; RESPONSE_BUFFER_SIZE];
        buffer[..response.len()].copy_from_slice(response);
        let rewritten = rewrite_response_head_in_place(
            &mut buffer,
            response.len(),
            ResponseConnection::Upgrade,
        )
        .unwrap();
        assert_eq!(
            &buffer[..rewritten],
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n"
        );
    }

    #[test]
    fn parser_rejects_malformed_upgrade_handshakes() {
        for request in [
            b"GET http://example.com/ HTTP/1.1\r\nConnection: Upgrade\r\n\r\n".as_slice(),
            b"POST http://example.com/ HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 1\r\n\r\n",
            b"GET http://example.com/ HTTP/1.0\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: web/socket/extra\r\n\r\n",
        ] {
            assert!(parse_request_head(request).is_err());
        }

        assert!(validate_upgrade_response(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        )
        .is_err());
        assert!(validate_upgrade_response(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n"
        )
        .is_err());
    }

    #[test]
    fn connection_lists_accept_empty_elements() {
        let request = parse_request_head(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: , close,\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            rewrite_plain_request(&request, "/"),
            b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );

        let response = b"HTTP/1.1 200 OK\r\nConnection: close,\r\nContent-Length: 2\r\n\r\n";
        let mut buffer = [0u8; RESPONSE_BUFFER_SIZE];
        buffer[..response.len()].copy_from_slice(response);
        let rewritten =
            rewrite_response_head_in_place(&mut buffer, response.len(), ResponseConnection::Close)
                .unwrap();
        assert_eq!(
            &buffer[..rewritten],
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn response_connection_cannot_nominate_framing_headers() {
        for framing in [b"Content-Length".as_slice(), b"Transfer-Encoding"] {
            let response = [
                b"HTTP/1.1 200 OK\r\nConnection: ".as_slice(),
                framing,
                b"\r\nContent-Length: 2\r\n\r\n",
            ]
            .concat();
            let mut buffer = [0u8; RESPONSE_BUFFER_SIZE];
            buffer[..response.len()].copy_from_slice(&response);
            assert!(rewrite_response_head_in_place(
                &mut buffer,
                response.len(),
                ResponseConnection::Close,
            )
            .is_err());
        }
    }

    #[test]
    fn strict_parser_returns_request_body_kind() {
        let fixed =
            parse_request_head(b"POST http://example.com/ HTTP/1.1\r\nContent-Length: 11\r\n\r\n")
                .unwrap();
        assert_eq!(fixed.body_kind, RequestBodyKind::ContentLength(11));

        let chunked = parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: gzip; level=1, chunked\r\n\r\n",
        )
        .unwrap();
        assert_eq!(chunked.body_kind, RequestBodyKind::Chunked);
    }

    #[test]
    fn parser_rejects_ambiguous_message_framing() {
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n"
        )
        .is_err());
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"
        )
        .is_err());
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"
        )
        .is_err());
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nContent-Length: 5, 5\r\nContent-Length: 5\r\n\r\n"
        )
        .is_ok());
    }

    #[test]
    fn transfer_encoding_is_rejected_on_http_1_0() {
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"
        )
        .is_err());
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.0\r\nTransfer-Encoding: gzip; level=1, chunked\r\n\r\n"
        )
        .is_err());
        // The same request is legitimate on HTTP/1.1, and an HTTP/1.0 request
        // without a transfer coding is untouched.
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        )
        .is_ok());
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.0\r\nContent-Length: 3\r\n\r\n"
        )
        .is_ok());
    }

    #[test]
    fn duplicated_content_length_is_forwarded_canonically() {
        let request = parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5, 5\r\nX-Tail: 1\r\nContent-Length: 5\r\n\r\n",
        )
        .unwrap();
        assert_eq!(request.body_kind, RequestBodyKind::ContentLength(5));
        assert_eq!(
            rewrite_plain_request(&request, "/"),
            b"POST / HTTP/1.1\r\nHost: example.com\r\nX-Tail: 1\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn bodyless_request_forwards_no_content_length() {
        let request =
            parse_request_head(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .unwrap();
        assert_eq!(request.body_kind, RequestBodyKind::None);
        assert_eq!(
            rewrite_plain_request(&request, "/"),
            b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn resumed_bare_line_ending_scan_matches_a_full_scan() {
        // A trailing CR is the only byte a pass can leave undecided, so a scan
        // resumed at `len - 1` must reach the same verdict as scanning from 0.
        for head in [
            b"GET / HTTP/1.1\r\nX-A: 1\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nX-A: 1\n\r\n",
            b"GET / HTTP/1.1\r\nX-A: 1\r\r\n",
            b"\nGET / HTTP/1.1\r\n\r\n",
        ] {
            for split in 0..head.len() {
                let first = has_bare_line_ending(&head[..split]);
                let resumed = first || bare_line_ending_from(head, split.saturating_sub(1));
                assert_eq!(
                    resumed,
                    has_bare_line_ending(head),
                    "split {split} disagreed for {head:?}"
                );
            }
        }
    }

    #[test]
    fn parser_accepts_parameterized_transfer_codings() {
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: gzip; level=1, chunked\r\n\r\n"
        )
        .is_ok());
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: custom ; note = \"a,b\\\"c\", chunked\r\n\r\n"
        )
        .is_ok());
    }

    #[test]
    fn parser_rejects_malformed_transfer_coding_parameters() {
        for value in [
            b"gzip; level, chunked".as_slice(),
            b"gzip; level=, chunked",
            b"gzip; note=\"unterminated, chunked",
            b"gzip; note=\"bad\\",
            b"gzip,,chunked",
            b"gzip,",
        ] {
            let mut codings = Vec::new();
            assert!(
                parse_transfer_codings(value, &mut codings).is_err(),
                "unexpectedly accepted {value:?}"
            );
        }
        assert!(parse_request_head(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked; extension=yes\r\n\r\n"
        )
        .is_err());
    }

    #[test]
    fn parse_proxy_authorization_ignores_obs_text_value_without_panic() {
        let request =
            parse_request_head(b"GET http://example.com/ HTTP/1.1\r\nX-Word: caf\xe9\r\n\r\n")
                .unwrap();
        assert_eq!(parse_proxy_authorization(&request.headers), None);
    }
}
