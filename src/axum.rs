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

use crate::error::AcceptError;
use crate::listener::ProxyProtocolListener;
use crate::stream::{ProxiedStream, ProxyConnectInfo};

impl axum::serve::Listener for ProxyProtocolListener {
    type Io = ProxiedStream;
    type Addr = ProxyConnectInfo;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match ProxyProtocolListener::accept(self).await {
                Ok(stream) => {
                    let info = stream.connect_info();
                    return (stream, info);
                }
                Err(e) => {
                    handle_accept_error(e).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        let addr = self.local_addr()?;
        Ok(ProxyConnectInfo {
            client_addr: addr,
            peer_addr: addr,
            proxy_info: None,
        })
    }
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, ProxyProtocolListener>>
    for ProxyConnectInfo
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, ProxyProtocolListener>) -> Self {
        stream.remote_addr().clone()
    }
}

async fn handle_accept_error(e: AcceptError) {
    match e {
        AcceptError::Rejected(addr) => {
            tracing::debug!(peer = %addr, "connection rejected by policy");
        }
        AcceptError::EmptyConnection(addr) => {
            tracing::debug!(peer = %addr, "empty connection (peer disconnected immediately)");
        }
        AcceptError::HeaderTimeout(addr) => {
            tracing::warn!(peer = %addr, "Proxy Protocol header timeout");
        }
        AcceptError::Parse(ref parse_err, addr) => {
            tracing::warn!(peer = %addr, error = %parse_err, "Proxy Protocol parse error");
        }
        AcceptError::ValidationFailed(ref reason, addr) => {
            tracing::warn!(peer = %addr, error = %reason, "Proxy Protocol header validation failed");
        }
        AcceptError::VersionMismatch(addr) => {
            tracing::warn!(peer = %addr, "unwanted Proxy Protocol version");
        }
        AcceptError::Io(ref io_err) => {
            if is_connection_error(io_err) {
                return;
            }
            tracing::error!(error = %io_err, "accept I/O error, retrying in 1s");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionRefused
    )
}
