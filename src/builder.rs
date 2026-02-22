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

use tokio::io::{self, AsyncWrite, AsyncWriteExt};

use crate::parse::V2_SIGNATURE;
use crate::types::{
    AddressFamily, Command, ProxyAddress, SslInfo, Transport, TransportProtocol, Version,
};

/// Proxy Protocol header builder
#[must_use]
pub struct HeaderBuilder {
    version: Version,
    command: Command,
    transport: Option<Transport>,
    source: Option<ProxyAddress>,
    destination: Option<ProxyAddress>,
    tlv_entries: Vec<(u8, Vec<u8>)>,
    add_crc32c: bool,
}

impl HeaderBuilder {
    /// Create a v2 PROXY header with source and destination addresses
    ///
    /// # Panics
    ///
    /// Panics if source and destination have different address families
    /// (e.g. one IPv4 and one IPv6)
    pub fn v2_proxy(source: SocketAddr, destination: SocketAddr) -> Self {
        assert_eq!(
            source.is_ipv4(),
            destination.is_ipv4(),
            "source and destination must use the same address family"
        );
        let family = if source.is_ipv4() {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        };
        Self {
            version: Version::V2,
            command: Command::Proxy,
            transport: Some(Transport {
                family,
                protocol: TransportProtocol::Stream,
            }),
            source: Some(ProxyAddress::Inet(source)),
            destination: Some(ProxyAddress::Inet(destination)),
            tlv_entries: Vec::new(),
            add_crc32c: false,
        }
    }

    /// Create a v2 LOCAL header (health-check / proxy-to-self)
    pub fn v2_local() -> Self {
        Self {
            version: Version::V2,
            command: Command::Local,
            transport: None,
            source: None,
            destination: None,
            tlv_entries: Vec::new(),
            add_crc32c: false,
        }
    }

    /// Create a v1 PROXY header with source and destination addresses
    ///
    /// # Panics
    ///
    /// Panics if source and destination have different address families
    pub fn v1_proxy(source: SocketAddr, destination: SocketAddr) -> Self {
        assert_eq!(
            source.is_ipv4(),
            destination.is_ipv4(),
            "source and destination must use the same address family"
        );
        let family = if source.is_ipv4() {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        };
        Self {
            version: Version::V1,
            command: Command::Proxy,
            transport: Some(Transport {
                family,
                protocol: TransportProtocol::Stream,
            }),
            source: Some(ProxyAddress::Inet(source)),
            destination: Some(ProxyAddress::Inet(destination)),
            tlv_entries: Vec::new(),
            add_crc32c: false,
        }
    }

    /// Create a v1 UNKNOWN header (no addresses)
    pub fn v1_unknown() -> Self {
        Self {
            version: Version::V1,
            command: Command::Proxy,
            transport: None,
            source: None,
            destination: None,
            tlv_entries: Vec::new(),
            add_crc32c: false,
        }
    }

    /// Create a v2 PROXY header for Unix domain sockets
    pub fn v2_unix(
        source: impl Into<Vec<u8>>,
        destination: impl Into<Vec<u8>>,
        protocol: TransportProtocol,
    ) -> Self {
        Self {
            version: Version::V2,
            command: Command::Proxy,
            transport: Some(Transport {
                family: AddressFamily::Unix,
                protocol,
            }),
            source: Some(ProxyAddress::Unix(source.into())),
            destination: Some(ProxyAddress::Unix(destination.into())),
            tlv_entries: Vec::new(),
            add_crc32c: false,
        }
    }

    /// Override the transport protocol (default is `Stream` for inet headers)
    pub fn with_transport_protocol(mut self, protocol: TransportProtocol) -> Self {
        if let Some(ref mut t) = self.transport {
            t.protocol = protocol;
        }
        self
    }

    /// Add an authority TLV (0x02)
    pub fn with_authority(mut self, authority: impl Into<String>) -> Self {
        let v = authority.into().into_bytes();
        self.tlv_entries.push((0x02, v));
        self
    }

    /// Add a unique ID TLV (0x05)
    ///
    /// # Panics
    ///
    /// Panics if `id` exceeds 128 bytes (the spec maximum for PP2_TYPE_UNIQUE_ID)
    pub fn with_unique_id(mut self, id: impl Into<Vec<u8>>) -> Self {
        let id = id.into();
        assert!(
            id.len() <= 128,
            "unique ID length {} exceeds the 128-byte spec maximum",
            id.len()
        );
        self.tlv_entries.push((0x05, id));
        self
    }

    /// Add an ALPN TLV (0x01)
    pub fn with_alpn(mut self, alpn: impl Into<Vec<u8>>) -> Self {
        self.tlv_entries.push((0x01, alpn.into()));
        self
    }

    /// Add an SSL info TLV (0x20)
    pub fn with_ssl(mut self, ssl: SslInfo) -> Self {
        self.tlv_entries.push((0x20, encode_ssl_tlv_value(&ssl)));
        self
    }

    /// Add a NETNS TLV (0x30)
    pub fn with_netns(mut self, netns: impl Into<String>) -> Self {
        self.tlv_entries.push((0x30, netns.into().into_bytes()));
        self
    }

    /// Add an arbitrary raw TLV
    pub fn with_raw_tlv(mut self, type_byte: u8, value: impl Into<Vec<u8>>) -> Self {
        self.tlv_entries.push((type_byte, value.into()));
        self
    }

    /// Add a NOOP padding TLV (0x04) with `len` zero bytes
    pub fn with_padding(mut self, len: u16) -> Self {
        self.tlv_entries.push((0x04, vec![0u8; len as usize]));
        self
    }

    /// Enable CRC32c checksum TLV; the checksum is computed at build time
    pub fn with_crc32c(mut self) -> Self {
        self.add_crc32c = true;
        self
    }

    /// Encode the header to bytes
    ///
    /// # Panics
    ///
    /// Panics if any single TLV value exceeds 65 535 bytes or if the total v2
    /// payload (addresses + all TLVs) exceeds 65 535 bytes. These are hard
    /// limits of the v2 wire format (u16 length fields).
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        match self.version {
            Version::V1 => self.build_v1(),
            Version::V2 => self.build_v2(),
        }
    }

    /// Write the header directly to an `AsyncWrite` sink
    ///
    /// # Panics
    ///
    /// Same as [`build()`](Self::build): panics if any TLV value or the total
    /// v2 payload exceeds the 65 535-byte protocol limit.
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<usize> {
        let bytes = self.build();
        writer.write_all(&bytes).await?;
        Ok(bytes.len())
    }

    fn build_v1(&self) -> Vec<u8> {
        match (&self.source, &self.destination, &self.transport) {
            (Some(ProxyAddress::Inet(src)), Some(ProxyAddress::Inet(dst)), Some(transport)) => {
                let proto = match transport.family {
                    AddressFamily::Inet => "TCP4",
                    AddressFamily::Inet6 => "TCP6",
                    _ => unreachable!(),
                };
                format!(
                    "PROXY {} {} {} {} {}\r\n",
                    proto,
                    src.ip(),
                    dst.ip(),
                    src.port(),
                    dst.port()
                )
                .into_bytes()
            }
            _ => b"PROXY UNKNOWN\r\n".to_vec(),
        }
    }

    fn build_v2(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // 12-byte signature
        buf.extend_from_slice(V2_SIGNATURE);

        // ver_cmd byte
        let cmd_nibble = match self.command {
            Command::Local => 0x00,
            Command::Proxy => 0x01,
        };
        buf.push(0x20 | cmd_nibble);

        // fam_proto byte
        let (fam, proto) = match &self.transport {
            Some(t) => {
                let f = match t.family {
                    AddressFamily::Inet => 1,
                    AddressFamily::Inet6 => 2,
                    AddressFamily::Unix => 3,
                };
                let p = match t.protocol {
                    TransportProtocol::Stream => 1,
                    TransportProtocol::Datagram => 2,
                };
                (f, p)
            }
            None => (0, 0),
        };
        buf.push((fam << 4) | proto);

        // Placeholder for payload length (2 bytes) — fill in later
        let len_pos = buf.len();
        buf.extend_from_slice(&[0, 0]);

        // Addresses
        match self.command {
            Command::Local => {}
            Command::Proxy => {
                self.encode_addresses(&mut buf);
            }
        }

        // TLV entries
        for (tlv_type, value) in &self.tlv_entries {
            assert!(
                value.len() <= u16::MAX as usize,
                "TLV value length {} exceeds maximum of 65535",
                value.len()
            );
            buf.push(*tlv_type);
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(value);
        }

        // CRC32c TLV (must be last)
        if self.add_crc32c {
            // Append a placeholder CRC TLV: type(0x03) + len(0x0004) + value(0x00000000)
            buf.push(0x03);
            buf.extend_from_slice(&4u16.to_be_bytes());
            buf.extend_from_slice(&[0, 0, 0, 0]);
        }

        // Fill in payload length BEFORE computing CRC so the CRC covers the real length
        let payload_len = buf.len() - 16;
        assert!(
            payload_len <= u16::MAX as usize,
            "v2 payload exceeds maximum size of 65535 bytes ({payload_len} bytes)"
        );
        let payload_len = payload_len as u16;
        buf[len_pos..len_pos + 2].copy_from_slice(&payload_len.to_be_bytes());

        // Now compute and fill in CRC value
        if self.add_crc32c {
            let crc = crc32c::crc32c(&buf);
            let crc_pos = buf.len() - 4;
            buf[crc_pos..crc_pos + 4].copy_from_slice(&crc.to_be_bytes());
        }

        buf
    }

    fn encode_addresses(&self, buf: &mut Vec<u8>) {
        match (&self.source, &self.destination) {
            (Some(ProxyAddress::Inet(src)), Some(ProxyAddress::Inet(dst))) => {
                match (src.ip(), dst.ip()) {
                    (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) => {
                        buf.extend_from_slice(&s.octets());
                        buf.extend_from_slice(&d.octets());
                        buf.extend_from_slice(&src.port().to_be_bytes());
                        buf.extend_from_slice(&dst.port().to_be_bytes());
                    }
                    (std::net::IpAddr::V6(s), std::net::IpAddr::V6(d)) => {
                        buf.extend_from_slice(&s.octets());
                        buf.extend_from_slice(&d.octets());
                        buf.extend_from_slice(&src.port().to_be_bytes());
                        buf.extend_from_slice(&dst.port().to_be_bytes());
                    }
                    _ => {}
                }
            }
            (Some(ProxyAddress::Unix(src)), Some(ProxyAddress::Unix(dst))) => {
                let mut src_field = [0u8; 108];
                let src_len = src.len().min(108);
                src_field[..src_len].copy_from_slice(&src[..src_len]);
                buf.extend_from_slice(&src_field);

                let mut dst_field = [0u8; 108];
                let dst_len = dst.len().min(108);
                dst_field[..dst_len].copy_from_slice(&dst[..dst_len]);
                buf.extend_from_slice(&dst_field);
            }
            _ => {}
        }
    }
}

fn encode_ssl_tlv_value(ssl: &SslInfo) -> Vec<u8> {
    let mut buf = Vec::new();

    // client flags byte
    buf.push(ssl.client_flags.bits());

    // verify: 0 = verified, non-zero = not verified
    let verify: u32 = if ssl.verified { 0 } else { 1 };
    buf.extend_from_slice(&verify.to_be_bytes());

    // Sub-TLVs
    if let Some(ref v) = ssl.version {
        encode_sub_tlv(&mut buf, 0x21, v.as_bytes());
    }
    if let Some(ref v) = ssl.cn {
        encode_sub_tlv(&mut buf, 0x22, v.as_bytes());
    }
    if let Some(ref v) = ssl.cipher {
        encode_sub_tlv(&mut buf, 0x23, v.as_bytes());
    }
    if let Some(ref v) = ssl.sig_alg {
        encode_sub_tlv(&mut buf, 0x24, v.as_bytes());
    }
    if let Some(ref v) = ssl.key_alg {
        encode_sub_tlv(&mut buf, 0x25, v.as_bytes());
    }
    if let Some(ref v) = ssl.group {
        encode_sub_tlv(&mut buf, 0x26, v.as_bytes());
    }
    if let Some(ref v) = ssl.sig_scheme {
        encode_sub_tlv(&mut buf, 0x27, v.as_bytes());
    }
    if let Some(ref v) = ssl.client_cert {
        encode_sub_tlv(&mut buf, 0x28, v);
    }

    buf
}

fn encode_sub_tlv(buf: &mut Vec<u8>, type_byte: u8, value: &[u8]) {
    assert!(
        value.len() <= u16::MAX as usize,
        "sub-TLV value length {} exceeds maximum of 65535",
        value.len()
    );
    buf.push(type_byte);
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
}
