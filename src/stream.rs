// Copyright (C) 2025-2026 Michael S. Klishin and Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fmt;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::types::ProxyInfo;

/// Connection metadata extracted from a Proxy Protocol header
///
/// Available without the `axum` feature; use
/// [`ProxiedStream::connect_info`] to build one from an accepted stream
#[derive(Debug, Clone)]
pub struct ProxyConnectInfo {
    /// The original client address (from a PP header or a TCP peer)
    pub client_addr: SocketAddr,
    /// The TCP peer address (the proxy's address)
    pub peer_addr: SocketAddr,
    /// Full Proxy Protocol info, if available
    pub proxy_info: Option<ProxyInfo>,
}

/// A TCP stream with Proxy Protocol metadata attached
///
/// Implements `AsyncRead + AsyncWrite`, so it can be wrapped by a TLS
/// acceptor for deployments that terminate TLS at the application
#[derive(Debug)]
pub struct ProxiedStream {
    inner: TcpStream,
    leftover: Cursor<Vec<u8>>,
    proxy_info: Option<ProxyInfo>,
    peer_addr: SocketAddr,
}

impl ProxiedStream {
    pub(crate) fn new(
        inner: TcpStream,
        leftover: Vec<u8>,
        proxy_info: Option<ProxyInfo>,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            inner,
            leftover: Cursor::new(leftover),
            proxy_info,
            peer_addr,
        }
    }

    /// Parsed Proxy Protocol information
    pub fn proxy_info(&self) -> Option<&ProxyInfo> {
        self.proxy_info.as_ref()
    }

    /// Client address from a PP header, falling back to the TCP peer
    pub fn client_addr(&self) -> SocketAddr {
        self.proxy_info
            .as_ref()
            .and_then(|info| info.source_inet())
            .unwrap_or(self.peer_addr)
    }

    /// The raw TCP peer address (the load balancer's IP)
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Access the inner `TcpStream`
    pub fn inner(&self) -> &TcpStream {
        &self.inner
    }

    /// Build a [`ProxyConnectInfo`] snapshot from this stream's metadata
    ///
    /// Useful for extracting connection info before wrapping with TLS
    pub fn connect_info(&self) -> ProxyConnectInfo {
        ProxyConnectInfo {
            client_addr: self.client_addr(),
            peer_addr: self.peer_addr,
            proxy_info: self.proxy_info.clone(),
        }
    }
}

impl ProxyConnectInfo {
    /// Client IP address without the port, for rate limiting and access control
    pub fn client_ip(&self) -> IpAddr {
        self.client_addr.ip()
    }

    /// Whether a Proxy Protocol header was present on this connection
    pub fn is_proxied(&self) -> bool {
        self.proxy_info.is_some()
    }
}

impl fmt::Display for ProxyConnectInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_proxied() {
            write!(f, "{} via {}", self.client_addr, self.peer_addr)
        } else {
            write!(f, "{} (direct)", self.client_addr)
        }
    }
}

impl From<&ProxiedStream> for ProxyConnectInfo {
    fn from(stream: &ProxiedStream) -> Self {
        stream.connect_info()
    }
}

impl From<SocketAddr> for ProxyConnectInfo {
    fn from(addr: SocketAddr) -> Self {
        Self {
            client_addr: addr,
            peer_addr: addr,
            proxy_info: None,
        }
    }
}

impl From<(ProxyInfo, SocketAddr)> for ProxyConnectInfo {
    fn from((info, peer_addr): (ProxyInfo, SocketAddr)) -> Self {
        let client_addr = info.source_inet().unwrap_or(peer_addr);
        Self {
            client_addr,
            peer_addr,
            proxy_info: Some(info),
        }
    }
}

impl AsyncRead for ProxiedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Serve leftover bytes first
        let leftover_data = this.leftover.get_ref();
        let leftover_pos = this.leftover.position() as usize;
        let leftover_remaining = leftover_data.len() - leftover_pos;

        if leftover_remaining > 0 {
            let to_copy = leftover_remaining.min(buf.remaining());
            buf.put_slice(&leftover_data[leftover_pos..leftover_pos + to_copy]);
            this.leftover.set_position((leftover_pos + to_copy) as u64);
            return Poll::Ready(Ok(()));
        }

        // Delegate to inner TcpStream
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxiedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
