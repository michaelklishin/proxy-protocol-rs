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

use std::net::SocketAddr;

use crate::types::ProxyInfo;

/// Validate a Proxy Protocol header before the connection is passed
/// to the application
pub trait HeaderValidator: Send + Sync + 'static {
    fn validate(
        &self,
        header: &ProxyInfo,
        peer_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Blanket implementation for closures
impl<F> HeaderValidator for F
where
    F: Fn(&ProxyInfo, SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
        + Send
        + Sync
        + 'static,
{
    fn validate(
        &self,
        header: &ProxyInfo,
        peer_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self(header, peer_addr)
    }
}
