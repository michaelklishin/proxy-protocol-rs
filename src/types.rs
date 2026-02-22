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
use std::net::{IpAddr, SocketAddr};

/// An address from a Proxy Protocol header
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProxyAddress {
    /// IPv4 or IPv6 socket address (IP + port)
    Inet(SocketAddr),
    /// Unix domain socket path (up to 108 bytes per the v2 spec)
    Unix(Vec<u8>),
}

impl ProxyAddress {
    /// If this is an `Inet` address, return the `SocketAddr`
    pub fn as_inet(&self) -> Option<SocketAddr> {
        match self {
            Self::Inet(addr) => Some(*addr),
            _ => None,
        }
    }

    /// If this is a `Unix` address, return the path bytes
    pub fn as_unix(&self) -> Option<&[u8]> {
        match self {
            Self::Unix(path) => Some(path),
            _ => None,
        }
    }

    /// If this is an `Inet` address, return just the IP
    pub fn ip(&self) -> Option<IpAddr> {
        self.as_inet().map(|a| a.ip())
    }
}

/// Parsed Proxy Protocol header
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyInfo {
    /// Protocol version (V1 or V2)
    pub version: Version,

    /// PROXY (forwarded) or LOCAL (health-check)
    pub command: Command,

    /// Transport family and protocol of the original connection;
    /// `None` for LOCAL commands and UNKNOWN v1 lines
    pub transport: Option<Transport>,

    /// Original source (client) address; `None` for LOCAL commands
    pub source: Option<ProxyAddress>,

    /// Original destination address; `None` for LOCAL commands
    pub destination: Option<ProxyAddress>,

    /// Parsed TLV extensions (v2 only)
    pub tlvs: Tlvs,
}

impl ProxyInfo {
    /// Convenience: source as `SocketAddr` (IPv4/IPv6 only)
    pub fn source_inet(&self) -> Option<SocketAddr> {
        self.source.as_ref().and_then(ProxyAddress::as_inet)
    }

    /// Convenience: destination as `SocketAddr` (IPv4/IPv6 only)
    pub fn destination_inet(&self) -> Option<SocketAddr> {
        self.destination.as_ref().and_then(ProxyAddress::as_inet)
    }

    /// Convenience: source IP address, if Inet
    pub fn source_ip(&self) -> Option<IpAddr> {
        self.source.as_ref().and_then(ProxyAddress::ip)
    }

    /// Convenience: destination IP address, if Inet
    pub fn destination_ip(&self) -> Option<IpAddr> {
        self.destination.as_ref().and_then(ProxyAddress::ip)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Version {
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Command {
    Local,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Transport {
    pub family: AddressFamily,
    pub protocol: TransportProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AddressFamily {
    Inet,
    Inet6,
    Unix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportProtocol {
    Stream,
    Datagram,
}

/// Parsed TLV extensions from a v2 Proxy Protocol header
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Tlvs {
    /// ALPN protocol negotiated (PP2_TYPE_ALPN, 0x01)
    pub alpn: Option<Vec<u8>>,

    /// SNI hostname / authority (PP2_TYPE_AUTHORITY, 0x02)
    pub authority: Option<String>,

    /// CRC32c of the entire header (PP2_TYPE_CRC32C, 0x03)
    pub crc32c: Option<u32>,

    /// Unique connection ID (PP2_TYPE_UNIQUE_ID, 0x05)
    pub unique_id: Option<Vec<u8>>,

    /// Network namespace (PP2_TYPE_NETNS, 0x30)
    pub netns: Option<String>,

    /// SSL/TLS information (PP2_TYPE_SSL, 0x20)
    pub ssl: Option<SslInfo>,

    /// All TLVs preserved as (type_byte, value), including those
    /// already parsed into typed fields above
    pub raw: Vec<(u8, Vec<u8>)>,
}

/// SSL/TLS metadata from the PP2_TYPE_SSL TLV (0x20)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SslInfo {
    /// Client connection flags
    pub client_flags: SslClientFlags,

    /// Whether the client certificate was verified
    pub verified: bool,

    /// TLS version string, e.g. "TLSv1.3"
    pub version: Option<String>,

    /// Cipher suite name
    pub cipher: Option<String>,

    /// Signature algorithm of the client certificate
    pub sig_alg: Option<String>,

    /// Key algorithm of the client certificate
    pub key_alg: Option<String>,

    /// Common Name from the client certificate's DN
    pub cn: Option<String>,

    /// TLS supported group (PP2_SUBTYPE_SSL_GROUP, 0x26)
    pub group: Option<String>,

    /// TLS signature scheme (PP2_SUBTYPE_SSL_SIG_SCHEME, 0x27)
    pub sig_scheme: Option<String>,

    /// DER-encoded client certificate (PP2_SUBTYPE_SSL_CLIENT_CERT, 0x28)
    pub client_cert: Option<Vec<u8>>,
}

bitflags::bitflags! {
    /// Flags from the PP2_TYPE_SSL client field
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    pub struct SslClientFlags: u8 {
        /// Client connected over SSL/TLS
        const SSL       = 0x01;
        /// Client provided a certificate on this connection
        const CERT_CONN = 0x02;
        /// Client provided a certificate during the TLS session
        const CERT_SESS = 0x04;
    }
}

impl fmt::Display for ProxyAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet(addr) => write!(f, "{addr}"),
            Self::Unix(path) => match std::str::from_utf8(path) {
                Ok(s) => write!(f, "{s}"),
                Err(_) => write!(f, "<unix:{} bytes>", path.len()),
            },
        }
    }
}

impl From<SocketAddr> for ProxyAddress {
    fn from(addr: SocketAddr) -> Self {
        Self::Inet(addr)
    }
}

impl From<std::net::SocketAddrV4> for ProxyAddress {
    fn from(addr: std::net::SocketAddrV4) -> Self {
        Self::Inet(SocketAddr::V4(addr))
    }
}

impl From<std::net::SocketAddrV6> for ProxyAddress {
    fn from(addr: std::net::SocketAddrV6) -> Self {
        Self::Inet(SocketAddr::V6(addr))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => write!(f, "v1"),
            Self::V2 => write!(f, "v2"),
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "LOCAL"),
            Self::Proxy => write!(f, "PROXY"),
        }
    }
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet => write!(f, "IPv4"),
            Self::Inet6 => write!(f, "IPv6"),
            Self::Unix => write!(f, "Unix"),
        }
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream => write!(f, "stream"),
            Self::Datagram => write!(f, "datagram"),
        }
    }
}
