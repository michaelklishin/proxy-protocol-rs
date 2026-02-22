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

pub(crate) mod tlv;
mod v1;
mod v2;

use crate::error::ParseError;
use crate::types::ProxyInfo;

/// The 12-byte v2 Proxy Protocol signature
pub const V2_SIGNATURE: &[u8; 12] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

/// Parse a Proxy Protocol header (v1 or v2) from a byte slice
///
/// Returns the parsed `ProxyInfo` and the number of bytes consumed.
///
/// # Errors
///
/// - [`ParseError::Incomplete`] — the buffer does not yet contain a full header;
///   the caller should read more data and retry
/// - [`ParseError::NotProxyProtocol`] — the first bytes do not match any Proxy
///   Protocol signature
/// - [`ParseError::Invalid`] — the header is structurally malformed (bad version,
///   unknown command, address family mismatch, truncated TLV, etc)
/// - [`ParseError::CrcMismatch`] — a CRC32c TLV is present and the checksum
///   does not match
#[inline]
#[must_use = "the parsed ProxyInfo contains the client address and metadata"]
pub fn parse(buf: &[u8]) -> Result<(ProxyInfo, usize), ParseError> {
    if buf.is_empty() {
        return Err(ParseError::Incomplete);
    }

    match buf[0] {
        0x0D => {
            if buf.len() < 12 {
                return Err(ParseError::Incomplete);
            }
            if buf[..12] == *V2_SIGNATURE {
                v2::parse_v2(buf)
            } else {
                Err(ParseError::NotProxyProtocol)
            }
        }
        b'P' => {
            if buf.len() < 6 {
                return Err(ParseError::Incomplete);
            }
            if buf.starts_with(b"PROXY ") {
                v1::parse_v1(buf)
            } else {
                Err(ParseError::NotProxyProtocol)
            }
        }
        _ => Err(ParseError::NotProxyProtocol),
    }
}
