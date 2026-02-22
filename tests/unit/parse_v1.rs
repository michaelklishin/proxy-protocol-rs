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
use proxy_protocol_rs::{AddressFamily, Command, Transport, TransportProtocol, Version};

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn tcp4_max_values() {
    let (info, consumed) =
        parse(b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n").unwrap();
    assert_eq!(consumed, 56);
    assert_eq!(info.version, Version::V1);
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
        SocketAddr::new(Ipv4Addr::new(255, 255, 255, 255).into(), 65535)
    );
    assert_eq!(
        info.destination_inet().unwrap(),
        SocketAddr::new(Ipv4Addr::new(255, 255, 255, 255).into(), 65535)
    );
}

#[test]
fn tcp4_typical() {
    let (info, consumed) = parse(b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n").unwrap();
    assert_eq!(consumed, 47);
    assert_eq!(
        info.source_inet().unwrap(),
        "192.168.0.1:56324".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        info.destination_inet().unwrap(),
        "192.168.0.11:443".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn tcp6_full_notation() {
    let input = b"PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
    let (info, _) = parse(input).unwrap();
    assert_eq!(info.version, Version::V1);
    assert_eq!(
        info.transport,
        Some(Transport {
            family: AddressFamily::Inet6,
            protocol: TransportProtocol::Stream,
        })
    );
    let expected_ip: Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
    assert_eq!(
        info.source_inet().unwrap(),
        SocketAddr::new(expected_ip.into(), 65535)
    );
}

#[test]
fn tcp6_compressed() {
    let input = b"PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:0000:0042:0000:8a2e:0370:7335 4124 443\r\n";
    let (info, _) = parse(input).unwrap();
    assert_eq!(
        info.source_inet().unwrap().ip(),
        "2001:db8:0:42:0:8a2e:370:7334"
            .parse::<std::net::IpAddr>()
            .unwrap()
    );
    assert_eq!(info.source_inet().unwrap().port(), 4124);
    assert_eq!(
        info.destination_inet().unwrap().ip(),
        "2001:db8:0:42:0:8a2e:370:7335"
            .parse::<std::net::IpAddr>()
            .unwrap()
    );
    assert_eq!(info.destination_inet().unwrap().port(), 443);
}

#[test]
fn unknown_bare() {
    let (info, consumed) = parse(b"PROXY UNKNOWN\r\n").unwrap();
    assert_eq!(consumed, 15);
    assert_eq!(info.version, Version::V1);
    assert_eq!(info.command, Command::Proxy);
    assert!(info.transport.is_none());
    assert!(info.source.is_none());
    assert!(info.destination.is_none());
}

#[test]
fn unknown_with_trailing_data() {
    let input = b"PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
    let (info, _) = parse(input).unwrap();
    assert_eq!(info.version, Version::V1);
    assert_eq!(info.command, Command::Proxy);
    assert!(info.transport.is_none());
    assert!(info.source.is_none());
}

#[test]
fn unknown_with_trailing_data_short() {
    let (info, consumed) = parse(b"PROXY UNKNOWN 4124 443\r\n").unwrap();
    assert_eq!(consumed, 24);
    assert!(info.transport.is_none());
}

#[test]
fn with_leftover_http() {
    let input = b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n";
    let (info, consumed) = parse(input).unwrap();
    assert_eq!(consumed, 47);
    assert_eq!(&input[consumed..consumed + 3], b"GET");
    assert_eq!(
        info.source_inet().unwrap(),
        "192.168.0.1:56324".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn with_leftover_partial_http() {
    let input = b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r";
    let (info, consumed) = parse(input).unwrap();
    assert_eq!(consumed, 47);
    assert_eq!(&input[consumed..], b"GET / HTTP/1.1\r");
    assert_eq!(
        info.source_inet().unwrap(),
        "192.168.0.1:56324".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn port_zero_allowed() {
    let (info, _) = parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 0 0\r\n").unwrap();
    assert_eq!(info.source_inet().unwrap().port(), 0);
    assert_eq!(info.destination_inet().unwrap().port(), 0);
}

#[test]
fn error_invalid_ip() {
    let result = parse(b"PROXY TCP4 192.1638.0.1 192.168.0.11 56324 443\r\n");
    assert!(result.is_err());
}

#[test]
fn error_invalid_port_overflow() {
    let result = parse(b"PROXY TCP4 192.168.0.1 192.168.0.11 1111111 443\r\n");
    assert!(result.is_err());
}

#[test]
fn error_non_numeric_port() {
    let result = parse(b"PROXY TCP6 2001:db8::1 2001:db8::2 4124 foo\r\n");
    assert!(result.is_err());
}

#[test]
fn error_invalid_ipv6() {
    let result = parse(
        b"PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:00;0:0042:0000:8a2e:0370:7335 4124 443\r\n",
    );
    assert!(result.is_err());
}

#[test]
fn error_missing_fields() {
    let result = parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 80\r\n");
    assert!(result.is_err());
}

#[test]
fn error_tcp4_with_ipv6_address() {
    let result = parse(b"PROXY TCP4 ::1 ::2 80 80\r\n");
    assert!(result.is_err());
}

#[test]
fn error_tcp6_with_ipv4_address() {
    let result = parse(b"PROXY TCP6 1.2.3.4 5.6.7.8 80 80\r\n");
    assert!(result.is_err());
}

#[test]
fn error_unknown_transport() {
    let result = parse(b"PROXY UDP4 1.2.3.4 5.6.7.8 80 90\r\n");
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::Invalid(
            proxy_protocol_rs::InvalidReason::V1UnknownTransport(_)
        ))
    ));
}

#[test]
fn incomplete_no_crlf() {
    let result = parse(b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443");
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::Incomplete)
    ));
}

#[test]
fn incomplete_partial_prefix() {
    let result = parse(b"PROX");
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::Incomplete)
    ));
}

#[test]
fn exactly_107_bytes_accepted() {
    // Spec allows up to 107 bytes including \r\n.
    // "PROXY UNKNOWN" (13 bytes) + 92 spaces + \r\n = 107
    let mut line = b"PROXY UNKNOWN".to_vec();
    line.extend_from_slice(&[b' '; 92]);
    line.extend_from_slice(b"\r\n");
    assert_eq!(line.len(), 107);
    let (info, consumed) = parse(&line).unwrap();
    assert_eq!(consumed, 107);
    assert!(info.transport.is_none());
}

#[test]
fn exceeds_107_bytes_rejected() {
    // 108 bytes: one past the spec maximum
    let mut line = b"PROXY UNKNOWN".to_vec();
    line.extend_from_slice(&[b' '; 93]);
    line.extend_from_slice(b"\r\n");
    assert_eq!(line.len(), 108);
    assert!(matches!(
        parse(&line),
        Err(proxy_protocol_rs::ParseError::Invalid(
            proxy_protocol_rs::InvalidReason::V1TooLong
        ))
    ));
}

#[test]
fn worst_case_107_bytes_tcp6() {
    // The spec worst case: "PROXY TCP6 ffff:...:ffff ffff:...:ffff 65535 65535\r\n"
    let line = b"PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
    assert!(
        line.len() <= 107,
        "worst case should fit in 107 bytes, got {}",
        line.len()
    );
    let (info, _) = parse(line).unwrap();
    assert_eq!(info.source_inet().unwrap().port(), 65535);
    assert_eq!(info.destination_inet().unwrap().port(), 65535);
}

#[test]
fn error_extra_fields_rejected() {
    let result = parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 80 90 extra\r\n");
    assert!(matches!(
        result,
        Err(proxy_protocol_rs::ParseError::Invalid(
            proxy_protocol_rs::InvalidReason::V1InvalidFormat
        ))
    ));
}

#[test]
fn clearly_too_long() {
    let mut line = b"PROXY TCP4 ".to_vec();
    line.extend_from_slice(&[b'1'; 100]);
    line.extend_from_slice(b"\r\n");
    assert!(parse(&line).is_err());
}

#[test]
fn unknown_with_invalid_addresses_ignored() {
    // go-proxyproto: UNKNOWN should ignore all following fields,
    // even completely invalid addresses and ports
    let (info, _) =
        parse(b"PROXY UNKNOWN 999.999.999.999 999.999.999.999 99999 99999\r\n").unwrap();
    assert_eq!(info.version, Version::V1);
    assert_eq!(info.command, Command::Proxy);
    assert!(info.transport.is_none());
    assert!(info.source.is_none());
    assert!(info.destination.is_none());
}

#[test]
fn unknown_with_garbage_trailing_data() {
    // UNKNOWN ignores everything after the keyword
    let (info, consumed) = parse(b"PROXY UNKNOWN not-even-ips\r\n").unwrap();
    assert_eq!(consumed, 28);
    assert!(info.transport.is_none());
    assert!(info.source.is_none());
}

#[test]
fn ipv4_mapped_ipv6_in_tcp6() {
    // ::ffff:127.0.0.1 is an IPv4-mapped IPv6 address. Rust's std::net parses
    // it as an Ipv6Addr, so it should be accepted with TCP6.
    let input = b"PROXY TCP6 ::ffff:127.0.0.1 ::ffff:127.0.0.2 65533 65534\r\n";
    let (info, _) = parse(input).unwrap();
    assert_eq!(info.version, Version::V1);
    assert_eq!(
        info.transport,
        Some(Transport {
            family: AddressFamily::Inet6,
            protocol: TransportProtocol::Stream,
        })
    );
    assert_eq!(info.source_inet().unwrap().port(), 65533);
    assert_eq!(info.destination_inet().unwrap().port(), 65534);
}

#[test]
fn loopback_ipv6() {
    let (info, _) = parse(b"PROXY TCP6 ::1 ::1 80 443\r\n").unwrap();
    assert_eq!(info.source_inet().unwrap().port(), 80);
    assert_eq!(info.destination_inet().unwrap().port(), 443);
}

#[test]
fn error_negative_port() {
    let result = parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 -1 80\r\n");
    assert!(result.is_err());
}

#[test]
fn error_empty_transport() {
    // "PROXY  1.2.3.4 ..." — double space, empty transport field
    let result = parse(b"PROXY  1.2.3.4 5.6.7.8 80 90\r\n");
    assert!(result.is_err());
}
