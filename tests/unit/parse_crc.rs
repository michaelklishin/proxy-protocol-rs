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

use proxy_protocol_rs::HeaderBuilder;
use proxy_protocol_rs::parse;

use std::net::SocketAddr;

#[test]
fn valid_crc_roundtrip() {
    let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let dst: SocketAddr = "10.11.12.13:23456".parse().unwrap();

    let header = HeaderBuilder::v2_proxy(src, dst).with_crc32c().build();

    let (info, consumed) = parse(&header).unwrap();
    assert_eq!(consumed, header.len());
    assert!(info.tlvs.crc32c.is_some());
    assert_eq!(info.source_inet().unwrap(), src);
    assert_eq!(info.destination_inet().unwrap(), dst);
}

#[test]
fn corrupted_crc_detected() {
    let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let dst: SocketAddr = "10.11.12.13:23456".parse().unwrap();

    let mut header = HeaderBuilder::v2_proxy(src, dst).with_crc32c().build();

    // Corrupt the CRC value (last 4 bytes before end)
    let len = header.len();
    header[len - 1] ^= 0xFF;

    let result = parse(&header);
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::CrcMismatch { .. })
    ));
}

#[test]
fn absent_crc_succeeds() {
    let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let dst: SocketAddr = "10.11.12.13:23456".parse().unwrap();

    // no CRC
    let header = HeaderBuilder::v2_proxy(src, dst).build();

    let (info, _) = parse(&header).unwrap();
    assert!(info.tlvs.crc32c.is_none());
}

#[test]
fn aws_packet_crc_valid() {
    // Real AWS NLB packet with CRC32c + VPC endpoint ID + NOOP
    let data: Vec<u8> = vec![
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33, 17, 0, 84, 172, 31, 7, 113, 172, 31, 10,
        31, 200, 242, 0, 80, 3, 0, 4, 232, 214, 137, 45, 234, 0, 23, 1, 118, 112, 99, 101, 45, 48,
        56, 100, 50, 98, 102, 49, 53, 102, 97, 99, 53, 48, 48, 49, 99, 57, 4, 0, 36, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
    ];
    let (info, consumed) = parse(&data).unwrap();
    assert_eq!(consumed, data.len());
    assert!(info.tlvs.crc32c.is_some());
}

#[test]
fn crc_with_authority_roundtrip() {
    let src: SocketAddr = "10.0.0.1:8080".parse().unwrap();
    let dst: SocketAddr = "10.0.0.2:443".parse().unwrap();

    let header = HeaderBuilder::v2_proxy(src, dst)
        .with_authority("example.com")
        .with_crc32c()
        .build();

    let (info, _) = parse(&header).unwrap();
    assert!(info.tlvs.crc32c.is_some());
    assert_eq!(info.tlvs.authority.as_deref(), Some("example.com"));
}
