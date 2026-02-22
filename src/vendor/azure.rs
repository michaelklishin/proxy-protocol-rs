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

use super::AzureTlvs;
use crate::error::TlvParseError;

/// Sub-type for Azure Private Endpoint LinkID
const PP2_SUBTYPE_AZURE_PRIVATEENDPOINT_LINKID: u8 = 0x01;

/// Parse the value of a PP2_TYPE_AZURE (0xEE) TLV
///
/// Azure uses a flat format: `[subtype(1), uint32_le(4)]`.
/// The total value must be exactly 5 bytes for the known sub-type 0x01
pub(crate) fn parse_azure_tlv(data: &[u8]) -> Result<AzureTlvs, TlvParseError> {
    if data.is_empty() {
        return Err(TlvParseError::MalformedSubTlv { offset: 0 });
    }

    let sub_type = data[0];
    let value = &data[1..];

    let mut azure = AzureTlvs {
        private_endpoint_link_id: None,
        raw: vec![(sub_type, value.to_vec())],
    };

    if sub_type == PP2_SUBTYPE_AZURE_PRIVATEENDPOINT_LINKID {
        if value.len() != 4 {
            return Err(TlvParseError::InvalidValue {
                reason: format!(
                    "Azure Private Endpoint LinkID must be 4 bytes, got {}",
                    value.len()
                ),
            });
        }
        azure.private_endpoint_link_id =
            Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]));
    }

    Ok(azure)
}
