//! Reusable composable stream-transport layers for meow-rs.
//!
//! Each layer wraps an inner [`Box<dyn Stream>`] and produces a new one.
//! Layers compose by chaining [`Transport::connect`] calls:
//!
//! ```text
//! let tcp:  Box<dyn Stream> = tcp_connect(addr).await?;
//! let s     = tls_layer.connect(tcp).await?;
//! let s     = ws_layer.connect(s).await?;
//! // `s` is handed to the VMess/VLESS protocol codec
//! ```
//!
//! Architecture: [ADR-0001](../../docs/adr/0001-meow-transport-crate.md).
//!
//! # Crate boundary invariants (enforced by CI)
//!
//! * No dependency on any other workspace crate (`meow-common`, `meow-proxy`,
//!   `meow-dns`, `meow-config`). This crate is a protocol-agnostic leaf.
//! * No `anyhow::Error` in any public function signature — only [`TransportError`].
//! * No server-side code (`accept`/`bind`/`listen`/`TcpListener`) in `src/`.
//!   Test helpers in `tests/support/` are whitelisted.

use std::any::Any;

use tokio::io::{AsyncRead, AsyncWrite};

pub use error::TransportError;

mod error;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(all(feature = "tls", feature = "reality"))]
mod reality_tls;

#[cfg(feature = "ws")]
pub mod ws;

#[cfg(any(feature = "grpc", feature = "h2", feature = "xhttp"))]
pub mod h2_common;

#[cfg(feature = "grpc")]
pub mod grpc;

#[cfg(feature = "h2")]
pub mod h2;

#[cfg(feature = "httpupgrade")]
pub mod httpupgrade;

#[cfg(feature = "xhttp")]
pub mod xhttp;

/// SIP004 simple-obfs HTTP/TLS obfuscation codec (client +, later, server).
/// Gated by the `simple-obfs` feature; see [`simple_obfs::client`] for the
/// outbound (proxy-client) wrappers used by the SS / Snell adapters.
#[cfg(feature = "simple-obfs")]
pub mod simple_obfs;

/// A duplex byte stream — the currency passed between transport layers.
///
/// Blanket-implemented for every `T: AsyncRead + AsyncWrite + Unpin + Send + Sync`,
/// so `TcpStream`, `TlsStream<…>`, `WebSocketStream<…>`, etc. all qualify.
///
/// `Sync` is required (in addition to ADR-0001's `Send`) so that a
/// `Box<dyn Stream>` can satisfy `ProxyConn` in `meow-proxy`, which
/// requires `Sync` for connection-table access.  All concrete stream types
/// we use (`TcpStream`, `TlsStream`, `WsStream`) are `Sync`; the bound
/// adds no real restriction in practice.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync + Any {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + Any> Stream for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub fn enable_raw_passthrough(stream: &mut dyn Stream) -> bool {
    let read = enable_raw_read_passthrough(stream);
    let write = enable_raw_write_passthrough(stream);
    read || write
}

pub fn enable_raw_read_passthrough(stream: &mut dyn Stream) -> bool {
    #[cfg(all(feature = "tls", feature = "reality"))]
    {
        if let Some(reality) = stream
            .as_any_mut()
            .downcast_mut::<reality_tls::RealityTlsStream>()
        {
            reality.enable_raw_read_passthrough();
            return true;
        }
    }

    let _ = stream;
    false
}

pub fn enable_raw_write_passthrough(stream: &mut dyn Stream) -> bool {
    #[cfg(all(feature = "tls", feature = "reality"))]
    {
        if let Some(reality) = stream
            .as_any_mut()
            .downcast_mut::<reality_tls::RealityTlsStream>()
        {
            reality.enable_raw_write_passthrough();
            return true;
        }
    }

    let _ = stream;
    false
}

/// A transport layer that wraps an inner [`Stream`] and produces a new one.
///
/// Implementations are cheap to clone (typically an `Arc<Config>` inside).
/// The trait is object-safe: `Box<dyn Transport>` is valid.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Wrap `inner` with this transport layer and return the upgraded stream.
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>>;
}

/// Crate-level `Result` alias.  Errors are always [`TransportError`].
pub type Result<T> = std::result::Result<T, TransportError>;
