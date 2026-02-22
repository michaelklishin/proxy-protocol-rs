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

use super::AwsTlvs;
use crate::error::TlvParseError;

/// Sub-type for AWS VPC endpoint ID
const PP2_SUBTYPE_AWS_VPCE_ID: u8 = 0x01;

/// Validate a VPCE ID against `[A-Za-z0-9-]*` (matches go-proxyproto)
fn is_valid_vpce_id(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Parse the value of a PP2_TYPE_AWS (0xEA) TLV
///
/// AWS uses a flat format: `[subtype(1), string_data(N)]`
/// where `N = outer_TLV_length - 1`
pub(crate) fn parse_aws_tlv(data: &[u8]) -> Result<AwsTlvs, TlvParseError> {
    if data.is_empty() {
        return Err(TlvParseError::MalformedSubTlv { offset: 0 });
    }

    let sub_type = data[0];
    let value = &data[1..];

    let mut aws = AwsTlvs {
        vpc_endpoint_id: None,
        raw: vec![(sub_type, value.to_vec())],
    };

    if sub_type == PP2_SUBTYPE_AWS_VPCE_ID {
        let vpce = String::from_utf8(value.to_vec()).map_err(|_| TlvParseError::InvalidValue {
            reason: "VPC endpoint ID is not valid UTF-8".to_string(),
        })?;
        if !is_valid_vpce_id(&vpce) {
            return Err(TlvParseError::InvalidValue {
                reason: format!("VPC endpoint ID contains invalid characters: {:?}", vpce),
            });
        }
        aws.vpc_endpoint_id = Some(vpce);
    }

    Ok(aws)
}
