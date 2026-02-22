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

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;

/// Policy applied to incoming connections before reading the PP header
pub trait ConnPolicy: Send + Sync + 'static {
    fn evaluate(&self, peer_addr: SocketAddr) -> PolicyDecision;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyDecision {
    /// Read and parse the PP header; error if absent or malformed
    Require,
    /// Try to read a PP header; if the first bytes don't match, treat as direct
    Use,
    /// Ignore any PP header; pass through unmodified
    Ignore,
    /// Reject the connection immediately
    Reject,
}

/// Require PP headers from all connections
#[derive(Debug, Clone)]
pub struct AcceptAll;

impl ConnPolicy for AcceptAll {
    fn evaluate(&self, _peer_addr: SocketAddr) -> PolicyDecision {
        PolicyDecision::Require
    }
}

/// Require PP headers only from connections in the trusted set; reject all others
#[derive(Debug, Clone)]
pub struct TrustedProxies {
    exact: HashSet<IpAddr>,
    cidrs: Vec<IpNet>,
}

impl TrustedProxies {
    pub fn new(addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            exact: addrs.into_iter().collect(),
            cidrs: Vec::new(),
        }
    }

    pub fn with_cidrs(
        addrs: impl IntoIterator<Item = IpAddr>,
        cidrs: impl IntoIterator<Item = IpNet>,
    ) -> Self {
        Self {
            exact: addrs.into_iter().collect(),
            cidrs: cidrs.into_iter().collect(),
        }
    }

    /// Builds from a mixed set of `IpNet`s, automatically splitting
    /// host-length prefixes (/32 for IPv4, /128 for IPv6) into exact
    /// matches and the rest into CIDR ranges.
    pub fn from_ipnets(nets: impl IntoIterator<Item = IpNet>) -> Self {
        let mut exact = HashSet::new();
        let mut cidrs = Vec::new();
        for net in nets {
            if net.prefix_len() == net.max_prefix_len() {
                exact.insert(net.addr());
            } else {
                cidrs.push(net);
            }
        }
        Self { exact, cidrs }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.exact.contains(&ip) || self.cidrs.iter().any(|net| net.contains(&ip))
    }
}

impl ConnPolicy for TrustedProxies {
    fn evaluate(&self, peer_addr: SocketAddr) -> PolicyDecision {
        if self.contains(peer_addr.ip()) {
            PolicyDecision::Require
        } else {
            PolicyDecision::Reject
        }
    }
}

/// Allow both proxied and direct connections
#[derive(Debug, Clone)]
pub struct MixedMode {
    trusted: TrustedProxies,
}

impl MixedMode {
    pub fn new(trusted: TrustedProxies) -> Self {
        Self { trusted }
    }
}

impl From<TrustedProxies> for MixedMode {
    fn from(trusted: TrustedProxies) -> Self {
        Self::new(trusted)
    }
}

impl ConnPolicy for MixedMode {
    fn evaluate(&self, peer_addr: SocketAddr) -> PolicyDecision {
        if self.trusted.contains(peer_addr.ip()) {
            PolicyDecision::Require
        } else {
            PolicyDecision::Ignore
        }
    }
}

/// Try to read a PP header from every connection, but treat it as optional
///
/// If the first bytes match a Proxy Protocol signature, the header is parsed.
/// If not, the connection is passed through as a direct connection.
/// Unlike `MixedMode`, this does not require a trusted proxy list:
/// it accepts PP from any peer
#[derive(Debug, Clone)]
pub struct OptionalProxy;

impl ConnPolicy for OptionalProxy {
    fn evaluate(&self, _peer_addr: SocketAddr) -> PolicyDecision {
        PolicyDecision::Use
    }
}

/// Blanket implementation for closures
impl<F> ConnPolicy for F
where
    F: Fn(SocketAddr) -> PolicyDecision + Send + Sync + 'static,
{
    fn evaluate(&self, peer_addr: SocketAddr) -> PolicyDecision {
        self(peer_addr)
    }
}
