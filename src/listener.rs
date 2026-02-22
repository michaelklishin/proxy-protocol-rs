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

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::config::{ProxyProtocolConfig, VersionPreference};
use crate::error::{AcceptError, ParseError};
use crate::parse::parse;
use crate::policy::PolicyDecision;
use crate::stream::ProxiedStream;
use crate::types::Version;

/// TCP listener that strips Proxy Protocol headers from accepted
/// connections
///
/// This listener can only be used with "plain" TCP sockets as it does not handle TLS;
/// the Proxy Protocol header is always sent as plaintext before any
/// TLS handshake, so TLS must be layered on top of the returned
/// [`ProxiedStream`].
///
/// Since `ProxiedStream` implements `AsyncRead + AsyncWrite`, any TLS acceptor such as `tokio-rustls`
/// can wrap it directly
pub struct ProxyProtocolListener {
    inner: TcpListener,
    config: ProxyProtocolConfig,
    handshake_semaphore: Arc<Semaphore>,
}

impl ProxyProtocolListener {
    pub fn new(listener: TcpListener, config: ProxyProtocolConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_pending_handshakes));
        Self {
            inner: listener,
            config,
            handshake_semaphore: semaphore,
        }
    }

    /// Accept a connection, read and strip the PP header, and return
    /// the cleaned stream with metadata
    ///
    /// # Errors
    ///
    /// * [`AcceptError::Io`]: the underlying TCP accept or socket read failed
    /// * [`AcceptError::Rejected`]: the peer was rejected by the configured
    ///   [`ConnPolicy`](crate::policy::ConnPolicy)
    /// * [`AcceptError::HeaderTimeout`]: the Proxy Protocol header was not
    ///   received within the configured time window (timeout)
    /// * [`AcceptError::EmptyConnection`]: the peer connected and immediately
    ///   closed the connection without sending any data
    /// * [`AcceptError::Parse`]: the header bytes could not be parsed
    ///   (malformed, incomplete at EOF, or CRC mismatch)
    /// * [`AcceptError::ValidationFailed`]: the parsed header was rejected by
    ///   the configured [`HeaderValidator`](crate::validator::HeaderValidator)
    /// * [`AcceptError::VersionMismatch`]: the header version does not match
    ///   the configured [`VersionPreference`]
    pub async fn accept(&self) -> Result<ProxiedStream, AcceptError> {
        let (stream, peer_addr) = self.inner.accept().await.map_err(AcceptError::Io)?;

        let decision = self.config.policy.evaluate(peer_addr);
        match decision {
            PolicyDecision::Reject => {
                drop(stream);
                Err(AcceptError::Rejected(peer_addr))
            }
            PolicyDecision::Ignore => Ok(ProxiedStream::new(stream, Vec::new(), None, peer_addr)),
            PolicyDecision::Require | PolicyDecision::Use => {
                let required = decision == PolicyDecision::Require;
                self.read_and_validate(stream, peer_addr, required).await
            }
        }
    }

    async fn read_and_validate(
        &self,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        required: bool,
    ) -> Result<ProxiedStream, AcceptError> {
        // Acquire handshake permit (bounded concurrency)
        let _permit = tokio::time::timeout(
            self.config.header_timeout,
            self.handshake_semaphore.acquire(),
        )
        .await
        .map_err(|_| AcceptError::HeaderTimeout(peer_addr))?
        .map_err(|_| AcceptError::Io(io::Error::other("semaphore closed")))?;

        let deadline = tokio::time::Instant::now() + self.config.header_timeout;
        let mut buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 256];

        loop {
            let n = tokio::time::timeout_at(deadline, stream.read(&mut tmp))
                .await
                .map_err(|_| AcceptError::HeaderTimeout(peer_addr))?
                .map_err(AcceptError::Io)?;

            if n == 0 {
                if buf.is_empty() {
                    return Err(AcceptError::EmptyConnection(peer_addr));
                }
                return Err(AcceptError::Parse(ParseError::Incomplete, peer_addr));
            }
            buf.extend_from_slice(&tmp[..n]);

            match parse(&buf) {
                Ok((info, consumed)) => {
                    match (self.config.version, info.version) {
                        (VersionPreference::V1Only, Version::V2)
                        | (VersionPreference::V2Only, Version::V1) => {
                            return Err(AcceptError::VersionMismatch(peer_addr));
                        }
                        _ => {}
                    }

                    if let Some(validator) = &self.config.validator {
                        validator
                            .validate(&info, peer_addr)
                            .map_err(|e| AcceptError::ValidationFailed(e, peer_addr))?;
                    }

                    let leftover = buf[consumed..].to_vec();
                    return Ok(ProxiedStream::new(stream, leftover, Some(info), peer_addr));
                }
                Err(ParseError::Incomplete) if buf.len() < self.config.max_header_size => {
                    continue;
                }
                Err(ParseError::NotProxyProtocol) if !required => {
                    return Ok(ProxiedStream::new(stream, buf, None, peer_addr));
                }
                Err(e) => {
                    return Err(AcceptError::Parse(e, peer_addr));
                }
            }
        }
    }

    /// Access the inner `TcpListener`
    pub fn inner(&self) -> &TcpListener {
        &self.inner
    }

    /// Returns the local address this listener is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl From<TcpListener> for ProxyProtocolListener {
    fn from(listener: TcpListener) -> Self {
        Self::new(listener, ProxyProtocolConfig::default())
    }
}
