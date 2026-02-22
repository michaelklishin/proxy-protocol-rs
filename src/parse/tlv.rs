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

use crate::error::{InvalidReason, ParseError};
use crate::types::{SslClientFlags, SslInfo, Tlvs};

fn bytes_to_string(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Parse TLV extensions from a byte slice (the portion of a v2 payload after addresses)
pub(crate) fn parse_tlvs(mut data: &[u8]) -> Result<Tlvs, ParseError> {
    let mut tlvs = Tlvs::default();
    let mut offset = 0;

    while !data.is_empty() {
        if data.len() < 3 {
            return Err(ParseError::Invalid(InvalidReason::MalformedTlv { offset }));
        }

        let tlv_type = data[0];
        let tlv_len = u16::from_be_bytes([data[1], data[2]]) as usize;

        if data.len() < 3 + tlv_len {
            return Err(ParseError::Invalid(InvalidReason::MalformedTlv { offset }));
        }

        let value = &data[3..3 + tlv_len];

        // Store all TLVs in raw (including known ones)
        tlvs.raw.push((tlv_type, value.to_vec()));

        match tlv_type {
            // PP2_TYPE_ALPN
            0x01 => {
                tlvs.alpn = Some(value.to_vec());
            }
            // PP2_TYPE_AUTHORITY
            0x02 => {
                tlvs.authority = Some(bytes_to_string(value));
            }
            // PP2_TYPE_CRC32C (must be exactly 4 bytes per the spec)
            0x03 => {
                if tlv_len != 4 {
                    return Err(ParseError::Invalid(InvalidReason::MalformedTlv { offset }));
                }
                let bytes = <[u8; 4]>::try_from(value).unwrap();
                tlvs.crc32c = Some(u32::from_be_bytes(bytes));
            }
            // PP2_TYPE_NOOP
            0x04 => {}
            // PP2_TYPE_UNIQUE_ID
            0x05 => {
                if tlv_len > 128 {
                    return Err(ParseError::Invalid(InvalidReason::MalformedTlv { offset }));
                }
                tlvs.unique_id = Some(value.to_vec());
            }
            // PP2_TYPE_SSL
            0x20 => {
                if tlv_len < 5 {
                    return Err(ParseError::Invalid(InvalidReason::MalformedTlv { offset }));
                }
                tlvs.ssl = Some(parse_ssl(value, offset + 3)?);
            }
            // PP2_TYPE_NETNS
            0x30 => {
                tlvs.netns = Some(bytes_to_string(value));
            }
            // Unknown TLVs are preserved in raw only (already done above)
            _ => {}
        }

        data = &data[3 + tlv_len..];
        offset += 3 + tlv_len;
    }

    Ok(tlvs)
}

fn parse_ssl(data: &[u8], outer_offset: usize) -> Result<SslInfo, ParseError> {
    let client_byte = data[0];
    let verify = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

    let client_flags = SslClientFlags::from_bits_truncate(client_byte);
    let verified = verify == 0;

    let mut ssl = SslInfo {
        client_flags,
        verified,
        ..Default::default()
    };

    // Parse SSL sub-TLVs
    let mut sub_data = &data[5..];
    let mut sub_offset = outer_offset + 5;
    while !sub_data.is_empty() {
        if sub_data.len() < 3 {
            return Err(ParseError::Invalid(InvalidReason::MalformedTlv {
                offset: sub_offset,
            }));
        }

        let sub_type = sub_data[0];
        let sub_len = u16::from_be_bytes([sub_data[1], sub_data[2]]) as usize;

        if sub_data.len() < 3 + sub_len {
            return Err(ParseError::Invalid(InvalidReason::MalformedTlv {
                offset: sub_offset,
            }));
        }

        let sub_value = &sub_data[3..3 + sub_len];

        match sub_type {
            0x21 => ssl.version = Some(bytes_to_string(sub_value)),
            0x22 => ssl.cn = Some(bytes_to_string(sub_value)),
            0x23 => ssl.cipher = Some(bytes_to_string(sub_value)),
            0x24 => ssl.sig_alg = Some(bytes_to_string(sub_value)),
            0x25 => ssl.key_alg = Some(bytes_to_string(sub_value)),
            0x26 => ssl.group = Some(bytes_to_string(sub_value)),
            0x27 => ssl.sig_scheme = Some(bytes_to_string(sub_value)),
            0x28 => ssl.client_cert = Some(sub_value.to_vec()),
            // Unknown sub-TLVs: skip silently per the spec
            _ => {}
        }

        sub_data = &sub_data[3 + sub_len..];
        sub_offset += 3 + sub_len;
    }

    Ok(ssl)
}
