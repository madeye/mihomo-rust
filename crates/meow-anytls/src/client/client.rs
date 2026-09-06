//! AnyTLS Client implementation

use crate::client::{SessionPool, SessionPoolConfig};
use crate::padding::{PaddingFactory, SharedPaddingFactory};
use crate::session::{Session, SessionHeartbeatConfig};
use crate::util::{
    AnyTlsError, Result, TlsConnect, configure_tcp_stream, hash_password, send_authentication,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::time::Duration;

/// Client manages connections to AnyTLS servers
///
/// TLS is supplied by the host through [`TlsConnect`]; the client dials TCP,
/// hands the socket to the hook, and speaks AnyTLS over whatever stream
/// comes back.
pub struct Client {
    password_hash: [u8; 32],
    server_addr: String,
    tls: Arc<dyn TlsConnect>,
    /// Padding factory in force for this server, shared with every session the
    /// client opens so an `UpdatePaddingScheme` push outlives the session that
    /// received it.
    padding: SharedPaddingFactory,
    session_pool: Arc<SessionPool>,
    pool_config: SessionPoolConfig,
}

impl Client {
    /// Create a new client with default session pool configuration
    pub fn new(
        password: &str,
        server_addr: String,
        tls: Arc<dyn TlsConnect>,
        padding: Arc<PaddingFactory>,
    ) -> Self {
        Self::with_pool_config(
            password,
            server_addr,
            tls,
            padding,
            crate::client::SessionPoolConfig::default(),
        )
    }

    /// Create a new client with custom session pool configuration
    pub fn with_pool_config(
        password: &str,
        server_addr: String,
        tls: Arc<dyn TlsConnect>,
        padding: Arc<PaddingFactory>,
        pool_config: crate::client::SessionPoolConfig,
    ) -> Self {
        let password_hash = hash_password(password);
        let session_pool = Arc::new(SessionPool::with_config(pool_config.clone()));

        tracing::debug!("[Client] Creating new client for server: {}", server_addr);

        Self {
            password_hash,
            server_addr,
            tls,
            padding: padding.into_shared(),
            session_pool,
            pool_config,
        }
    }

    /// Create a new stream by establishing or reusing a session
    /// Returns (stream, session) so the caller can use session.write_data_frame for writing
    pub async fn create_proxy_stream(
        &self,
        destination: (String, u16),
    ) -> Result<(Arc<crate::session::Stream>, Arc<crate::session::Session>)> {
        tracing::debug!(
            "[Client] create_proxy_stream: {}:{}",
            destination.0,
            destination.1
        );

        // Get or create a session
        let session = self.create_stream().await?;
        tracing::debug!("[Client] Got session for proxy stream");

        // Open a new stream in the session
        let (stream, synack_rx) = session.open_stream().await?;
        let mut guard = crate::session::stream::OpeningStreamGuard::new(Arc::clone(&stream));
        tracing::debug!(
            "[Client] Opened stream {} in session, waiting for SYNACK",
            stream.id()
        );

        // Write destination address to stream (SOCKS5 format)
        // Use session's write_data_frame to send data without needing to unwrap Arc<Stream>
        tracing::debug!(
            "[Client] Writing destination address to stream {}: {}:{}",
            stream.id(),
            destination.0,
            destination.1
        );

        // Prepare the SOCKS5 address bytes
        let (addr, port) = destination;
        let mut addr_bytes = Vec::new();

        if let Ok(ipv4) = addr.parse::<Ipv4Addr>() {
            // IPv4
            tracing::trace!("[Client] Writing IPv4 address: {:?}", ipv4);
            addr_bytes.push(0x01); // ATYP_IPV4
            addr_bytes.extend_from_slice(&ipv4.octets());
        } else if let Ok(ipv6) = addr.parse::<Ipv6Addr>() {
            // IPv6
            tracing::trace!("[Client] Writing IPv6 address: {:?}", ipv6);
            addr_bytes.push(0x04); // ATYP_IPV6
            addr_bytes.extend_from_slice(&ipv6.octets());
        } else {
            // Domain name
            tracing::trace!("[Client] Writing domain name: {}", addr);
            let domain_bytes = addr.as_bytes();
            if domain_bytes.len() > 255 {
                return Err(AnyTlsError::Protocol("Domain name too long".to_string()));
            }
            addr_bytes.push(0x03); // ATYP_DOMAIN
            addr_bytes.push(domain_bytes.len() as u8);
            addr_bytes.extend_from_slice(domain_bytes);
        }

        // Write port (2 bytes, big-endian)
        tracing::trace!("[Client] Writing port: {}", port);
        addr_bytes.extend_from_slice(&port.to_be_bytes());

        // Use session's write_data_frame to send the address bytes
        // This avoids the need to unwrap Arc<Stream> which fails when multiple references exist
        let stream_id = stream.id();
        use bytes::Bytes;
        tracing::debug!(
            "[Client] Writing destination address ({} bytes) to stream {}",
            addr_bytes.len(),
            stream_id
        );

        // Disable buffering before writing first data frame
        // This is critical: in Go version, buffering is disabled when proxy writes SocksAddr
        // This ensures buffered Settings frame is flushed along with the first data
        session.disable_buffering();
        tracing::debug!("[Client] Buffering disabled, buffer will be flushed");

        session
            .write_data_frame(stream_id, Bytes::from(addr_bytes))
            .await?;

        tracing::debug!(
            "[Client] Successfully wrote destination address to stream {}",
            stream_id
        );
        tracing::debug!(
            "[Client] Waiting for SYNACK from server for stream {}...",
            stream_id
        );

        // Wait for SYNACK with timeout (30 seconds default)
        const DEFAULT_SYNACK_TIMEOUT: Duration = Duration::from_secs(30);

        match tokio::time::timeout(DEFAULT_SYNACK_TIMEOUT, synack_rx).await {
            Ok(Ok(Ok(()))) => {
                guard.disarm();
                tracing::debug!(
                    "[Client] SYNACK received for stream {} - stream ready",
                    stream_id
                );
                Ok((stream, session))
            }
            Ok(Ok(Err(e))) => {
                tracing::error!("[Client] SYNACK error for stream {}: {}", stream_id, e);
                let error_msg = e.to_string();
                let error = AnyTlsError::Protocol(error_msg.clone());
                stream.close_with_error(error).await;
                Err(AnyTlsError::Protocol(error_msg))
            }
            Ok(Err(_)) => {
                tracing::error!("[Client] SYNACK channel closed for stream {}", stream_id);
                let error = AnyTlsError::Protocol("SYNACK channel closed".into());
                stream.close_with_error(error).await;
                Err(AnyTlsError::Protocol("SYNACK channel closed".into()))
            }
            Err(_) => {
                tracing::error!(
                    "[Client] SYNACK timeout for stream {} after {}s",
                    stream_id,
                    DEFAULT_SYNACK_TIMEOUT.as_secs()
                );
                let error_msg =
                    format!("SYNACK timeout after {}s", DEFAULT_SYNACK_TIMEOUT.as_secs());
                let error = AnyTlsError::Protocol(error_msg.clone());
                stream.close_with_error(error).await;
                Err(AnyTlsError::Protocol(error_msg))
            }
        }
    }

    /// Create a new stream by establishing or reusing a session
    pub async fn create_stream(&self) -> Result<Arc<Session>> {
        // Try to get an idle session from pool
        if let Some(session) = self.session_pool.get_idle_session().await {
            tracing::debug!("[Client] Reusing idle session from pool");
            return Ok(session);
        }

        tracing::debug!("[Client] No idle session found, creating new session");
        // Create new session
        self.create_new_session().await
    }

    /// Create a new session with the server
    async fn create_new_session(&self) -> Result<Arc<Session>> {
        tracing::debug!("[Client] Creating new session to {}", self.server_addr);

        // Establish TCP connection
        tracing::trace!(
            "[Client] Connecting TCP to {} (this may trigger DNS lookup)",
            self.server_addr
        );
        // Dial via the socket-protect helper: an installed `TcpDialer`
        // (host-app bridge, e.g. meow-common's resolver + protector stack)
        // takes the whole resolve+connect path; otherwise the fallback
        // applies the `SocketProtector` (Android) around a system-resolver
        // dial, degrading to plain `TcpStream::connect` off-Android. The
        // dialer hook matters inside VPN apps whose system DNS is a fake-IP
        // server — `lookup_host` there returns unroutable fake IPs.
        let tcp_stream = match crate::util::socket_protect::connect_tcp_addr(&self.server_addr)
            .await
        {
            Ok(stream) => stream,
            Err(e) => {
                tracing::error!("[Client] Failed to connect to {}: {}", self.server_addr, e);

                // Provide helpful error messages
                let error_str = format!("{}", e);
                if error_str.contains("lookup")
                    || error_str.contains("DNS")
                    || error_str.contains("Try again")
                {
                    tracing::error!("[Client] DNS resolution failed for '{}'", self.server_addr);
                    tracing::error!("[Client] Troubleshooting steps:");
                    tracing::error!(
                        "[Client]   1. Check if server address is correct: {}",
                        self.server_addr
                    );
                    tracing::error!("[Client]   2. Try using IP address instead of hostname");
                    tracing::error!(
                        "[Client]   3. Test DNS: nslookup $(echo {} | cut -d: -f1)",
                        self.server_addr
                    );
                    tracing::error!(
                        "[Client]   4. Test TCP connection: nc -zv $(echo {} | cut -d: -f1) $(echo {} | cut -d: -f2)",
                        self.server_addr,
                        self.server_addr
                    );
                } else if error_str.contains("Connection refused") {
                    tracing::error!(
                        "[Client] Connection refused. Server may not be running or not listening on {}",
                        self.server_addr
                    );
                } else if error_str.contains("Connection timed out") {
                    tracing::error!(
                        "[Client] Connection timed out. Check network connectivity and firewall settings"
                    );
                }

                return Err(AnyTlsError::Io(e));
            }
        };
        configure_tcp_stream(&tcp_stream, &self.server_addr);

        tracing::debug!(
            "[Client] TCP connection established to {}",
            self.server_addr
        );

        // Perform TLS handshake through the host-supplied hook
        tracing::trace!("[Client] Starting TLS handshake");
        let tls_stream = self.tls.connect(tcp_stream).await.map_err(|e| {
            tracing::error!("[Client] TLS handshake failed: {}", e);
            e
        })?;
        tracing::debug!("[Client] TLS handshake successful");

        // Send authentication
        // Split TLS stream into reader and writer
        let (reader, mut writer) = tokio::io::split(tls_stream);
        tracing::trace!("[Client] Sending authentication");
        let padding = {
            let guard = self.padding.read().await;
            Arc::clone(&guard)
        };
        send_authentication(&mut writer, &self.password_hash, &padding).await?;
        tracing::debug!("[Client] Authentication sent successfully");

        // Create session with reader and writer
        let heartbeat_config = SessionHeartbeatConfig {
            interval: self.pool_config.check_interval,
            timeout: self.pool_config.idle_timeout,
        };
        let session = Arc::new(Session::new_client(
            reader,
            writer,
            Arc::clone(&self.padding),
            Some(heartbeat_config),
        ));

        // Set sequence number for pool ordering (use timestamp-based counter)
        static SEQ_COUNTER: meow_common::atomic::AtomicU = meow_common::atomic::AtomicU::new(0);
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        let seq: u64 = SEQ_COUNTER
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .into();
        session.set_seq(seq);
        tracing::debug!("[Client] Session created with seq={}", seq);

        // Start session (send settings and start loops)
        tracing::trace!("[Client] Starting client session");
        session.clone().start_client().await?;
        tracing::debug!("[Client] Client session started successfully");

        // Store in pool
        self.session_pool.add_idle_session(session.clone()).await;
        tracing::debug!("[Client] Session added to pool");

        Ok(session)
    }

    /// Stop the background cleanup task in the session pool (primarily for tests)
    pub async fn stop_session_pool_cleanup(&self) {
        self.session_pool.stop_cleanup_task().await;
    }
}
