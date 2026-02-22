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

use proxy_protocol_rs::parse;
use proxy_protocol_rs::{
    AddressFamily, Command, ProxyAddress, Transport, TransportProtocol, Version,
};

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Helper: build v2 header bytes from components.
fn v2_header(ver_cmd: u8, fam_proto: u8, payload: &[u8]) -> Vec<u8> {
    let sig: &[u8] = &[13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10];
    let len = (payload.len() as u16).to_be_bytes();
    let mut buf = Vec::new();
    buf.extend_from_slice(sig);
    buf.push(ver_cmd);
    buf.push(fam_proto);
    buf.extend_from_slice(&len);
    buf.extend_from_slice(payload);
    buf
}

#[test]
fn ipv4_stream() {
    // 127.0.0.1:444 -> 192.168.0.1:443
    let data: Vec<u8> = vec![
        // signature
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, // ver = 2, cmd = proxy
        33, // family = inet, proto = stream
        17, // length = 12
        0, 12, // source addr, destination addr
        127, 0, 0, 1, 192, 168, 0, 1, // source port = 444, destination port = 443
        1, 188, 1, 187,
    ];
    let trailing = b"GET / HTTP/1.1\r\n";
    let mut input = data.clone();
    input.extend_from_slice(trailing);

    let (info, consumed) = parse(&input).unwrap();
    assert_eq!(consumed, data.len());
    assert_eq!(info.version, Version::V2);
    assert_eq!(info.command, Command::Proxy);
    assert_eq!(
        info.transport,
        Some(Transport {
            family: AddressFamily::Inet,
            protocol: TransportProtocol::Stream,
        })
    );
    assert_eq!(
        info.source_inet().unwrap(),
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 444)
    );
    assert_eq!(
        info.destination_inet().unwrap(),
        SocketAddr::new(Ipv4Addr::new(192, 168, 0, 1).into(), 443)
    );
}

#[test]
fn ipv4_dgram() {
    // family = inet, proto = dgram (0x12)
    let data: Vec<u8> = vec![
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, // ver = 2, cmd = proxy
        33, // family = inet, proto = dgram
        18, 0, 12, 127, 0, 0, 1, 192, 168, 0, 1, 1, 188, 1, 187,
    ];
    let (info, _) = parse(&data).unwrap();
    assert_eq!(
        info.transport,
        Some(Transport {
            family: AddressFamily::Inet,
            protocol: TransportProtocol::Datagram,
        })
    );
}

#[test]
fn ipv6_stream() {
    // Specific IPv6 addresses
    let data: Vec<u8> = vec![
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, // ver = 2, cmd = proxy
        33, // family = inet6, proto = stream
        33, // length = 36
        0, 36, // source
        21, 156, 16, 144, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // destination
        32, 1, 13, 184, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        // source port = 444, destination port = 443
        1, 188, 1, 187,
    ];
    let (info, _) = parse(&data).unwrap();
    assert_eq!(info.version, Version::V2);
    assert_eq!(info.transport.unwrap().family, AddressFamily::Inet6);
    assert_eq!(
        info.source_inet().unwrap(),
        SocketAddr::new(
            Ipv6Addr::new(0x159c, 0x1090, 0x0001, 0, 0, 0, 0, 0).into(),
            444
        )
    );
    assert_eq!(
        info.destination_inet().unwrap(),
        SocketAddr::new(
            Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 0).into(),
            443
        )
    );
}

#[test]
fn ipv6_dgram() {
    let data: Vec<u8> = vec![
        // family = inet6, proto = dgram
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33, 34, 0, 36, 21, 156, 16, 144, 0, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 32, 1, 13, 184, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 188, 1, 187,
    ];
    let (info, _) = parse(&data).unwrap();
    assert_eq!(
        info.transport.unwrap().protocol,
        TransportProtocol::Datagram
    );
}

#[test]
fn unix_stream() {
    let path = b"/var/pgsql_sock";
    let mut payload = Vec::new();
    // source path: 108 bytes, null-padded
    payload.extend_from_slice(path);
    payload.extend_from_slice(&vec![0u8; 108 - path.len()]);
    // destination path: 108 bytes, null-padded
    payload.extend_from_slice(path);
    payload.extend_from_slice(&vec![0u8; 108 - path.len()]);

    // family = unix(3), proto = stream(1)
    let data = v2_header(0x21, 0x31, &payload);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(
        info.transport,
        Some(Transport {
            family: AddressFamily::Unix,
            protocol: TransportProtocol::Stream,
        })
    );
    assert_eq!(
        info.source.as_ref().unwrap(),
        &ProxyAddress::Unix(path.to_vec())
    );
    assert_eq!(
        info.destination.as_ref().unwrap(),
        &ProxyAddress::Unix(path.to_vec())
    );
}

#[test]
fn unix_dgram() {
    let src_path = b"/run/source.sock";
    let dst_path = b"/run/destination.sock";
    let mut payload = Vec::new();
    payload.extend_from_slice(src_path);
    payload.extend_from_slice(&vec![0u8; 108 - src_path.len()]);
    payload.extend_from_slice(dst_path);
    payload.extend_from_slice(&vec![0u8; 108 - dst_path.len()]);

    // family = unix(3), proto = dgram(2)
    let data = v2_header(0x21, 0x32, &payload);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(
        info.transport.unwrap().protocol,
        TransportProtocol::Datagram
    );
    assert_eq!(
        info.source.as_ref().unwrap(),
        &ProxyAddress::Unix(src_path.to_vec())
    );
    assert_eq!(
        info.destination.as_ref().unwrap(),
        &ProxyAddress::Unix(dst_path.to_vec())
    );
}

#[test]
fn local_zero_payload() {
    // cmd = local, no family/proto
    let data = v2_header(0x20, 0x00, &[]);
    let (info, consumed) = parse(&data).unwrap();
    assert_eq!(consumed, 16);
    assert_eq!(info.version, Version::V2);
    assert_eq!(info.command, Command::Local);
    assert!(info.transport.is_none());
    assert!(info.source.is_none());
    assert!(info.destination.is_none());
}

#[test]
fn local_with_payload_to_skip() {
    // some payload to skip
    let payload = vec![0u8; 20];
    let data = v2_header(0x20, 0x00, &payload);
    let (info, consumed) = parse(&data).unwrap();
    assert_eq!(consumed, 16 + 20);
    assert_eq!(info.command, Command::Local);
}

#[test]
fn proxy_unspec_rejected() {
    // PROXY + family = 0, protocol = 0 is rejected (UNSPEC only valid with LOCAL)
    let data = v2_header(0x21, 0x00, &[]);
    assert!(matches!(
        parse(&data),
        Err(proxy_protocol_rs::ParseError::Invalid(
            proxy_protocol_rs::InvalidReason::UnspecWithProxy
        ))
    ));
}

#[test]
fn proxy_unspec_with_tlvs_rejected() {
    // PROXY + UNSPEC is rejected even if payload contains TLVs
    let mut payload = Vec::new();
    let authority = b"example.com";
    // PP2_TYPE_AUTHORITY
    payload.push(0x02);
    payload.extend_from_slice(&(authority.len() as u16).to_be_bytes());
    payload.extend_from_slice(authority);

    let data = v2_header(0x21, 0x00, &payload);
    assert!(matches!(
        parse(&data),
        Err(proxy_protocol_rs::ParseError::Invalid(
            proxy_protocol_rs::InvalidReason::UnspecWithProxy
        ))
    ));
}

#[test]
fn local_unspec_accepted() {
    // LOCAL + UNSPEC is the normal health-check case
    let data = v2_header(0x20, 0x00, &[]);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(info.command, Command::Local);
    assert!(info.transport.is_none());
    assert!(info.source.is_none());
}

#[test]
fn local_unspec_with_tlvs_accepted() {
    // LOCAL + UNSPEC with TLV payload — TLVs must still be parsed
    let mut payload = Vec::new();
    let authority = b"example.com";
    // PP2_TYPE_AUTHORITY
    payload.push(0x02);
    payload.extend_from_slice(&(authority.len() as u16).to_be_bytes());
    payload.extend_from_slice(authority);

    let data = v2_header(0x20, 0x00, &payload);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(info.command, Command::Local);
    assert!(info.transport.is_none());
    assert_eq!(info.tlvs.authority.as_deref(), Some("example.com"));
}

#[test]
fn with_leftover_data() {
    let mut data: Vec<u8> = vec![
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33, 17, 0, 12, 127, 0, 0, 1, 192, 168, 0, 1,
        1, 188, 1, 187,
    ];
    data.extend_from_slice(b"GET / HTTP/1.1\r\n");
    let (_, consumed) = parse(&data).unwrap();
    assert_eq!(&data[consumed..], b"GET / HTTP/1.1\r\n");
}

#[test]
fn aws_regression_packet() {
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
    assert_eq!(info.version, Version::V2);
    assert_eq!(info.command, Command::Proxy);
    // Verify CRC passed (it would have returned CrcMismatch otherwise)
    assert!(info.tlvs.crc32c.is_some());
}

#[test]
fn error_wrong_version_nibble() {
    // version = 1, not 2
    let data = v2_header(0x10, 0x11, &[0u8; 12]);
    let result = parse(&data);
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::Invalid(
            proxy_protocol_rs::InvalidReason::UnsupportedVersion(_)
        ))
    ));
}

#[test]
fn error_unknown_command() {
    // cmd = 2, invalid
    let data = v2_header(0x22, 0x11, &[0u8; 12]);
    let result = parse(&data);
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::Invalid(
            proxy_protocol_rs::InvalidReason::UnknownCommand(_)
        ))
    ));
}

#[test]
fn error_payload_overflow() {
    // Claim payload_len bigger than actual data
    let sig: &[u8] = &[13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10];
    let mut data = sig.to_vec();
    // ver = 2, cmd = proxy
    data.push(0x21);
    // family = inet, proto = stream
    data.push(0x11);
    // payload_len = 100
    data.extend_from_slice(&100u16.to_be_bytes());
    // only 12 bytes of payload
    data.extend_from_slice(&[0u8; 12]);
    let result = parse(&data);
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::Incomplete)
    ));
}

#[test]
fn incomplete_signature_only() {
    let result = parse(&[13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10]);
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::Incomplete)
    ));
}

#[test]
fn incomplete_partial_signature() {
    let result = parse(&[13, 10, 13, 10, 0]);
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::Incomplete)
    ));
}

#[test]
fn not_pp_http_get() {
    let result = parse(b"GET / HTTP/1.1\r\n");
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::NotProxyProtocol)
    ));
}

#[test]
fn not_pp_tls_client_hello() {
    let result = parse(&[0x16, 0x03, 0x01]);
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::NotProxyProtocol)
    ));
}

#[test]
fn not_pp_single_byte() {
    // Single byte 0x47 ('G') -> NotProxyProtocol (not Incomplete)
    let result = parse(&[0x47]);
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::NotProxyProtocol)
    ));
}

#[test]
fn not_pp_single_byte_0x16() {
    let result = parse(&[0x16]);
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::NotProxyProtocol)
    ));
}

#[test]
fn empty_input() {
    assert!(matches!(
        parse(&[]),
        Err(proxy_protocol_rs::ParseError::Incomplete)
    ));
}

#[test]
fn error_unknown_family() {
    // family nibble = 4 (invalid), proto = stream
    let data = v2_header(0x21, 0x41, &[0u8; 12]);
    assert!(matches!(
        parse(&data),
        Err(proxy_protocol_rs::ParseError::Invalid(
            proxy_protocol_rs::InvalidReason::UnknownFamily(_)
        ))
    ));
}

#[test]
fn error_unknown_protocol() {
    // family = inet, proto nibble = 3 (invalid)
    let data = v2_header(0x21, 0x13, &[0u8; 12]);
    assert!(matches!(
        parse(&data),
        Err(proxy_protocol_rs::ParseError::Invalid(
            proxy_protocol_rs::InvalidReason::UnknownProtocol(_)
        ))
    ));
}

#[test]
fn proxy_with_undefined_family_only_rejected() {
    // family = 0, proto = stream(1): PROXY + partial UNSPEC is rejected
    let data = v2_header(0x21, 0x01, &[]);
    assert!(matches!(
        parse(&data),
        Err(proxy_protocol_rs::ParseError::Invalid(
            proxy_protocol_rs::InvalidReason::UnspecWithProxy
        ))
    ));
}

#[test]
fn proxy_with_undefined_protocol_only_rejected() {
    // family = inet(1), proto = 0: PROXY + partial UNSPEC is rejected
    let data = v2_header(0x21, 0x10, &[]);
    assert!(matches!(
        parse(&data),
        Err(proxy_protocol_rs::ParseError::Invalid(
            proxy_protocol_rs::InvalidReason::UnspecWithProxy
        ))
    ));
}

#[test]
fn ipv4_too_short_payload() {
    // IPv4 stream needs 12 bytes of addresses, provide only 8
    let data = v2_header(0x21, 0x11, &[0u8; 8]);
    assert!(parse(&data).is_err());
}

#[test]
fn ipv6_too_short_payload() {
    // IPv6 stream needs 36 bytes of addresses, provide only 20
    let data = v2_header(0x21, 0x21, &[0u8; 20]);
    assert!(parse(&data).is_err());
}

#[test]
fn unix_too_short_payload() {
    // Unix needs 216 bytes (2 x 108-byte paths), provide only 100
    let data = v2_header(0x21, 0x31, &[0u8; 100]);
    assert!(parse(&data).is_err());
}

#[test]
fn unix_null_terminated_paths() {
    // Verify that null-terminated paths are extracted correctly
    let mut payload = Vec::new();
    // source: "/tmp/s.sock\0" + padding
    let src = b"/tmp/s.sock";
    payload.extend_from_slice(src);
    payload.extend_from_slice(&vec![0u8; 108 - src.len()]);
    // destination: all nulls (empty path)
    payload.extend_from_slice(&[0u8; 108]);

    let data = v2_header(0x21, 0x31, &payload);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(
        info.source.as_ref().unwrap(),
        &ProxyAddress::Unix(b"/tmp/s.sock".to_vec())
    );
    assert_eq!(
        info.destination.as_ref().unwrap(),
        &ProxyAddress::Unix(vec![])
    );
}

#[test]
fn unix_full_108_byte_path_no_null() {
    // A path that fills all 108 bytes with no null terminator
    let path = vec![b'a'; 108];
    let mut payload = Vec::new();
    payload.extend_from_slice(&path);
    payload.extend_from_slice(&path);

    let data = v2_header(0x21, 0x31, &payload);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(
        info.source.as_ref().unwrap(),
        &ProxyAddress::Unix(path.clone())
    );
}

#[test]
fn local_with_inet_family_still_ignores_addresses() {
    // LOCAL + family = inet should still be LOCAL with no addresses
    let data = v2_header(0x20, 0x11, &[0u8; 12]);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(info.command, Command::Local);
    assert!(info.transport.is_none());
    assert!(info.source.is_none());
    assert!(info.destination.is_none());
}

#[test]
fn medium_tlv_payload_2kb() {
    // A v2 header with a ~2KB TLV payload (mirrors go-proxyproto's medium TLV test).
    // Uses a raw vendor TLV (0xE1) with 2048 bytes of data.
    let mut payload = vec![
        // source IP, destination IP
        127, 0, 0, 1, 10, 0, 0, 1, // source port = 8080, destination port = 443
        0x1F, 0x90, 0x01, 0xBB,
    ];
    let tlv_data = vec![0xAA; 2048];
    // application-specific type
    payload.push(0xE1);
    payload.extend_from_slice(&(tlv_data.len() as u16).to_be_bytes());
    payload.extend_from_slice(&tlv_data);

    let data = v2_header(0x21, 0x11, &payload);
    let (info, consumed) = parse(&data).unwrap();
    assert_eq!(consumed, 16 + payload.len());
    assert_eq!(
        info.source_inet().unwrap(),
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080)
    );
    // The raw TLV must be preserved
    let raw_e1: Vec<_> = info.tlvs.raw.iter().filter(|(t, _)| *t == 0xE1).collect();
    assert_eq!(raw_e1.len(), 1);
    assert_eq!(raw_e1[0].1.len(), 2048);
}

#[test]
fn large_tlv_payload_near_max() {
    // A v2 header with TLV payload near the u16 limit (addresses + ~3900 bytes of TLVs).
    // Total payload = 12 (IPv4 addrs) + 3 (TLV header) + 3900 (value) = 3915 bytes.
    let mut payload = vec![
        // source IP
        192, 168, 1, 1, // destination IP
        10, 0, 0, 1, // source port = 80
        0x00, 0x50, // destination port = 443
        0x01, 0xBB,
    ];
    let tlv_data = vec![0xBB; 3900];
    payload.push(0xE2);
    payload.extend_from_slice(&(tlv_data.len() as u16).to_be_bytes());
    payload.extend_from_slice(&tlv_data);

    let data = v2_header(0x21, 0x11, &payload);
    let (info, _) = parse(&data).unwrap();
    let raw_e2: Vec<_> = info.tlvs.raw.iter().filter(|(t, _)| *t == 0xE2).collect();
    assert_eq!(raw_e2.len(), 1);
    assert_eq!(raw_e2[0].1.len(), 3900);
}

#[test]
fn ipv4_with_tlvs_after_addresses() {
    // IPv4 (12 bytes) + an authority TLV
    let mut payload = vec![
        // source IP
        127, 0, 0, 1, // destination IP
        10, 0, 0, 1, // source port = 8080
        0x1F, 0x90, // destination port = 443
        0x01, 0xBB,
    ];
    let authority = b"example.com";
    // PP2_TYPE_AUTHORITY
    payload.push(0x02);
    payload.extend_from_slice(&(authority.len() as u16).to_be_bytes());
    payload.extend_from_slice(authority);

    let data = v2_header(0x21, 0x11, &payload);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(
        info.source_inet().unwrap(),
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080)
    );
    assert_eq!(info.tlvs.authority.as_deref(), Some("example.com"));
}
