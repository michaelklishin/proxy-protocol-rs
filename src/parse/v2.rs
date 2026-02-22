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

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{InvalidReason, ParseError};
use crate::types::{
    AddressFamily, Command, ProxyAddress, ProxyInfo, Tlvs, Transport, TransportProtocol, Version,
};

use super::tlv::parse_tlvs;

const V2_HEADER_LEN: usize = 16; // signature(12) + ver_cmd(1) + fam_proto(1) + len(2)

pub(crate) fn parse_v2(buf: &[u8]) -> Result<(ProxyInfo, usize), ParseError> {
    if buf.len() < V2_HEADER_LEN {
        return Err(ParseError::Incomplete);
    }

    let ver_cmd = buf[12];
    let version_nibble = ver_cmd >> 4;
    let command_nibble = ver_cmd & 0x0F;

    if version_nibble != 0x02 {
        return Err(ParseError::Invalid(InvalidReason::UnsupportedVersion(
            version_nibble,
        )));
    }

    let command = match command_nibble {
        0x00 => Command::Local,
        0x01 => Command::Proxy,
        _ => {
            return Err(ParseError::Invalid(InvalidReason::UnknownCommand(
                command_nibble,
            )));
        }
    };

    let fam_proto = buf[13];
    let family_nibble = fam_proto >> 4;
    let proto_nibble = fam_proto & 0x0F;

    let payload_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total_len = V2_HEADER_LEN + payload_len;

    if buf.len() < total_len {
        return Err(ParseError::Incomplete);
    }

    let payload = &buf[V2_HEADER_LEN..total_len];

    let (transport, source, destination, tlv_offset) = match command {
        Command::Local => {
            // LOCAL: no addresses, but the payload may contain TLVs
            (None, None, None, 0)
        }
        Command::Proxy => {
            // UNSPEC (family=0 or proto=0) is only valid with LOCAL.
            // A PROXY command must carry a concrete address family and protocol.
            if family_nibble == 0 || proto_nibble == 0 {
                return Err(ParseError::Invalid(InvalidReason::UnspecWithProxy));
            }
            parse_v2_addresses(family_nibble, proto_nibble, payload)?
        }
    };

    // Parse TLVs from remaining payload.
    // For LOCAL, tolerate malformed payload (the spec says receivers
    // must skip it, but in practice some senders include TLVs).
    let tlvs = if tlv_offset < payload.len() {
        match command {
            Command::Local => parse_tlvs(&payload[tlv_offset..]).unwrap_or_default(),
            Command::Proxy => parse_tlvs(&payload[tlv_offset..])?,
        }
    } else {
        Tlvs::default()
    };

    // Validate CRC32c if present
    if let Some(expected_crc) = tlvs.crc32c {
        let tlv_start = V2_HEADER_LEN + tlv_offset;
        let actual_crc = compute_crc32c(buf, total_len, tlv_start);
        if actual_crc != expected_crc {
            return Err(ParseError::CrcMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }
    }

    Ok((
        ProxyInfo {
            version: Version::V2,
            command,
            transport,
            source,
            destination,
            tlvs,
        },
        total_len,
    ))
}

type AddressParseResult = (
    Option<Transport>,
    Option<ProxyAddress>,
    Option<ProxyAddress>,
    usize,
);

fn parse_v2_addresses(
    family_nibble: u8,
    proto_nibble: u8,
    payload: &[u8],
) -> Result<AddressParseResult, ParseError> {
    // Caller guarantees family and protocol are non-zero for PROXY commands.
    let family = match family_nibble {
        1 => AddressFamily::Inet,
        2 => AddressFamily::Inet6,
        3 => AddressFamily::Unix,
        _ => {
            return Err(ParseError::Invalid(InvalidReason::UnknownFamily(
                family_nibble,
            )));
        }
    };

    let protocol = match proto_nibble {
        1 => TransportProtocol::Stream,
        2 => TransportProtocol::Datagram,
        _ => {
            return Err(ParseError::Invalid(InvalidReason::UnknownProtocol(
                proto_nibble,
            )));
        }
    };

    let transport = Transport { family, protocol };

    match family {
        AddressFamily::Inet => {
            if payload.len() < 12 {
                return Err(ParseError::Invalid(InvalidReason::PayloadOverflow {
                    len: 12,
                    buf_len: payload.len(),
                }));
            }
            let src_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let dst_ip = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
            let src_port = u16::from_be_bytes([payload[8], payload[9]]);
            let dst_port = u16::from_be_bytes([payload[10], payload[11]]);

            Ok((
                Some(transport),
                Some(ProxyAddress::Inet(SocketAddr::new(src_ip.into(), src_port))),
                Some(ProxyAddress::Inet(SocketAddr::new(dst_ip.into(), dst_port))),
                12,
            ))
        }
        AddressFamily::Inet6 => {
            if payload.len() < 36 {
                return Err(ParseError::Invalid(InvalidReason::PayloadOverflow {
                    len: 36,
                    buf_len: payload.len(),
                }));
            }
            let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&payload[..16]).unwrap());
            let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&payload[16..32]).unwrap());
            let src_port = u16::from_be_bytes([payload[32], payload[33]]);
            let dst_port = u16::from_be_bytes([payload[34], payload[35]]);

            Ok((
                Some(transport),
                Some(ProxyAddress::Inet(SocketAddr::new(src_ip.into(), src_port))),
                Some(ProxyAddress::Inet(SocketAddr::new(dst_ip.into(), dst_port))),
                36,
            ))
        }
        AddressFamily::Unix => {
            if payload.len() < 216 {
                return Err(ParseError::Invalid(InvalidReason::PayloadOverflow {
                    len: 216,
                    buf_len: payload.len(),
                }));
            }
            let src_path = extract_unix_path(&payload[..108]);
            let dst_path = extract_unix_path(&payload[108..216]);

            Ok((
                Some(transport),
                Some(ProxyAddress::Unix(src_path)),
                Some(ProxyAddress::Unix(dst_path)),
                216,
            ))
        }
    }
}

/// Extract a null-terminated Unix path from a 108-byte field
fn extract_unix_path(field: &[u8]) -> Vec<u8> {
    match field.iter().position(|&b| b == 0) {
        Some(pos) => field[..pos].to_vec(),
        None => field.to_vec(),
    }
}

/// Compute CRC32c of the full header with the CRC TLV value field zeroed
///
/// Uses a split computation to avoid copying the entire header;
/// `tlv_start` is the absolute offset where TLVs begin (after the 16-byte
/// fixed header + address block)
pub(crate) fn compute_crc32c(buf: &[u8], total_len: usize, tlv_start: usize) -> u32 {
    let header = &buf[..total_len];

    // Find the CRC TLV value offset so we can zero it without allocating.
    let mut pos = tlv_start;
    while pos + 3 <= total_len {
        let tlv_type = header[pos];
        let tlv_len = u16::from_be_bytes([header[pos + 1], header[pos + 2]]) as usize;
        if pos + 3 + tlv_len > total_len {
            break;
        }
        if tlv_type == 0x03 && tlv_len == 4 {
            let crc_value_start = pos + 3;
            // Hash in three pieces: before CRC value, four zero bytes, after CRC value
            let crc = crc32c::crc32c(&header[..crc_value_start]);
            let crc = crc32c::crc32c_append(crc, &[0, 0, 0, 0]);
            return crc32c::crc32c_append(crc, &header[crc_value_start + 4..]);
        }
        pos += 3 + tlv_len;
    }

    // No CRC TLV found — hash the whole thing
    crc32c::crc32c(header)
}
