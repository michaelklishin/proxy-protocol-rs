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

#[cfg(feature = "aws")]
mod aws;
#[cfg(feature = "azure")]
mod azure;

#[cfg(any(feature = "aws", feature = "azure", feature = "gcp"))]
use crate::error::TlvParseError;
#[cfg(any(feature = "aws", feature = "azure", feature = "gcp"))]
use crate::types::Tlvs;

/// AWS-specific TLV data from PP2_TYPE_AWS (0xEA)
///
/// The TLV value uses a flat format: `[subtype(1), data(N)]`
/// where the data length is determined by the outer TLV length minus 1
#[cfg(feature = "aws")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsTlvs {
    /// VPC endpoint ID (PP2_SUBTYPE_AWS_VPCE_ID, 0x01)
    ///
    /// Validated against `[A-Za-z0-9-]*` per the AWS NLB spec
    pub vpc_endpoint_id: Option<String>,
    /// Raw value: (sub_type, data_bytes)
    pub raw: Vec<(u8, Vec<u8>)>,
}

/// Azure Private Link TLV data from PP2_TYPE_AZURE (0xEE)
///
/// The TLV value uses a flat format: `[subtype(1), uint32_le(4)]`;
/// the total value must be exactly 5 bytes.
///
/// See <https://docs.microsoft.com/en-us/azure/private-link/private-link-service-overview#getting-connection-information-using-tcp-proxy-v2>
#[cfg(feature = "azure")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureTlvs {
    /// Private Endpoint LinkID (sub-type 0x01, uint32 little-endian)
    pub private_endpoint_link_id: Option<u32>,
    /// Raw value: (sub_type, data_bytes)
    pub raw: Vec<(u8, Vec<u8>)>,
}

/// GCP Private Service Connect TLV data from PP2_TYPE_GCE (0xE0)
///
/// Unlike AWS and Azure, GCP uses a flat 8-byte value (no sub-TLVs);
/// see <https://cloud.google.com/vpc/docs/configure-private-service-connect-producer#proxy-protocol>
#[cfg(feature = "gcp")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcpTlvs {
    /// Private Service Connect connection ID (8-byte big-endian uint64)
    pub psc_connection_id: u64,
}

#[cfg(feature = "aws")]
impl Tlvs {
    pub fn aws(&self) -> Option<Result<AwsTlvs, TlvParseError>> {
        self.raw
            .iter()
            .find(|(t, _)| *t == 0xEA)
            .map(|(_, value)| aws::parse_aws_tlv(value))
    }
}

#[cfg(feature = "azure")]
impl Tlvs {
    pub fn azure(&self) -> Option<Result<AzureTlvs, TlvParseError>> {
        self.raw
            .iter()
            .find(|(t, _)| *t == 0xEE)
            .map(|(_, value)| azure::parse_azure_tlv(value))
    }
}

#[cfg(feature = "gcp")]
impl Tlvs {
    /// Parse the GCP Private Service Connect TLV (0xE0)
    ///
    /// Returns `None` if the TLV is absent, `Some(Err(_))` if the value
    /// is not exactly 8 bytes
    pub fn gcp(&self) -> Option<Result<GcpTlvs, TlvParseError>> {
        self.raw.iter().find(|(t, _)| *t == 0xE0).map(|(_, value)| {
            if value.len() != 8 {
                return Err(TlvParseError::InvalidValue {
                    reason: format!("GCP PSC connection ID must be 8 bytes, got {}", value.len()),
                });
            }
            let psc_connection_id = u64::from_be_bytes(value.as_slice().try_into().unwrap());
            Ok(GcpTlvs { psc_connection_id })
        })
    }
}
