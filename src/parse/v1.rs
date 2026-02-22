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

use std::net::{IpAddr, SocketAddr};

use crate::error::{InvalidReason, ParseError};
use crate::types::{
    AddressFamily, Command, ProxyAddress, ProxyInfo, Tlvs, Transport, TransportProtocol, Version,
};

/// Maximum v1 header length per the HAProxy spec (including \r\n).
/// The worst case is "PROXY TCP6 ffff:...:ffff ffff:...:ffff 65535 65535\r\n" = 107 bytes.
const V1_MAX_LEN: usize = 107;

pub(crate) fn parse_v1(buf: &[u8]) -> Result<(ProxyInfo, usize), ParseError> {
    let search_end = buf.len().min(V1_MAX_LEN);
    let line_end = buf[..search_end]
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(if buf.len() < V1_MAX_LEN {
            ParseError::Incomplete
        } else {
            ParseError::Invalid(InvalidReason::V1TooLong)
        })?;

    let line = std::str::from_utf8(&buf[..line_end])
        .map_err(|_| ParseError::Invalid(InvalidReason::V1NotUtf8))?;

    let consumed = line_end + 2; // include \r\n

    // "PROXY UNKNOWN\r\n" or "PROXY UNKNOWN ...\r\n"
    if let Some(rest) = line.strip_prefix("PROXY UNKNOWN")
        && (rest.is_empty() || rest.starts_with(' '))
    {
        return Ok((
            ProxyInfo {
                version: Version::V1,
                command: Command::Proxy,
                transport: None,
                source: None,
                destination: None,
                tlvs: Tlvs::default(),
            },
            consumed,
        ));
    }

    let mut parts = line.splitn(7, ' ');
    let _proxy = parts.next(); // "PROXY" — already validated by caller

    let transport_str = parts
        .next()
        .ok_or(ParseError::Invalid(InvalidReason::V1InvalidFormat))?;
    let src_ip_str = parts
        .next()
        .ok_or(ParseError::Invalid(InvalidReason::V1InvalidFormat))?;
    let dst_ip_str = parts
        .next()
        .ok_or(ParseError::Invalid(InvalidReason::V1InvalidFormat))?;
    let src_port_str = parts
        .next()
        .ok_or(ParseError::Invalid(InvalidReason::V1InvalidFormat))?;
    let dst_port_str = parts
        .next()
        .ok_or(ParseError::Invalid(InvalidReason::V1InvalidFormat))?;

    // Exactly 6 fields — reject if there are more
    if parts.next().is_some() {
        return Err(ParseError::Invalid(InvalidReason::V1InvalidFormat));
    }

    let (family, protocol) = match transport_str {
        "TCP4" => (AddressFamily::Inet, TransportProtocol::Stream),
        "TCP6" => (AddressFamily::Inet6, TransportProtocol::Stream),
        other => {
            return Err(ParseError::Invalid(InvalidReason::V1UnknownTransport(
                other.to_string(),
            )));
        }
    };

    let src_ip: IpAddr = src_ip_str
        .parse()
        .map_err(|_| ParseError::Invalid(InvalidReason::InvalidIp(src_ip_str.to_string())))?;

    let dst_ip: IpAddr = dst_ip_str
        .parse()
        .map_err(|_| ParseError::Invalid(InvalidReason::InvalidIp(dst_ip_str.to_string())))?;

    // Validate family matches parsed IP
    match (&family, &src_ip) {
        (AddressFamily::Inet, IpAddr::V4(_)) => {}
        (AddressFamily::Inet6, IpAddr::V6(_)) => {}
        _ => {
            return Err(ParseError::Invalid(InvalidReason::InvalidIp(
                src_ip_str.to_string(),
            )));
        }
    }
    match (&family, &dst_ip) {
        (AddressFamily::Inet, IpAddr::V4(_)) => {}
        (AddressFamily::Inet6, IpAddr::V6(_)) => {}
        _ => {
            return Err(ParseError::Invalid(InvalidReason::InvalidIp(
                dst_ip_str.to_string(),
            )));
        }
    }

    let src_port: u16 = src_port_str
        .parse()
        .map_err(|_| ParseError::Invalid(InvalidReason::InvalidPort(src_port_str.to_string())))?;

    let dst_port: u16 = dst_port_str
        .parse()
        .map_err(|_| ParseError::Invalid(InvalidReason::InvalidPort(dst_port_str.to_string())))?;

    Ok((
        ProxyInfo {
            version: Version::V1,
            command: Command::Proxy,
            transport: Some(Transport { family, protocol }),
            source: Some(ProxyAddress::Inet(SocketAddr::new(src_ip, src_port))),
            destination: Some(ProxyAddress::Inet(SocketAddr::new(dst_ip, dst_port))),
            tlvs: Tlvs::default(),
        },
        consumed,
    ))
}
