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

use proptest::prelude::*;
use proxy_protocol_rs::{HeaderBuilder, ParseError, parse};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

proptest! {
    /// The parser must never panic on arbitrary input.
    #[test]
    fn prop_parse_never_panics(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse(&data);
    }

    /// Roundtrip: build v2 IPv4 -> parse -> compare.
    #[test]
    fn prop_v2_ipv4_roundtrip(
        src_ip in any::<Ipv4Addr>(),
        dst_ip in any::<Ipv4Addr>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
    ) {
        let src = SocketAddr::new(src_ip.into(), src_port);
        let dst = SocketAddr::new(dst_ip.into(), dst_port);
        let bytes = HeaderBuilder::v2_proxy(src, dst).build();
        let (info, consumed) = parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(info.source_inet().unwrap(), src);
        assert_eq!(info.destination_inet().unwrap(), dst);
    }

    /// Roundtrip: build v2 IPv6 -> parse -> compare.
    #[test]
    fn prop_v2_ipv6_roundtrip(
        src_ip in any::<Ipv6Addr>(),
        dst_ip in any::<Ipv6Addr>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
    ) {
        let src = SocketAddr::new(src_ip.into(), src_port);
        let dst = SocketAddr::new(dst_ip.into(), dst_port);
        let bytes = HeaderBuilder::v2_proxy(src, dst).build();
        let (info, consumed) = parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(info.source_inet().unwrap(), src);
        assert_eq!(info.destination_inet().unwrap(), dst);
    }

    /// Roundtrip: build v1 IPv4 -> parse -> compare.
    #[test]
    fn prop_v1_roundtrip(
        src_ip in any::<Ipv4Addr>(),
        dst_ip in any::<Ipv4Addr>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
    ) {
        let src = SocketAddr::new(src_ip.into(), src_port);
        let dst = SocketAddr::new(dst_ip.into(), dst_port);
        let bytes = HeaderBuilder::v1_proxy(src, dst).build();
        let (info, consumed) = parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(info.source_inet().unwrap(), src);
        assert_eq!(info.destination_inet().unwrap(), dst);
    }

    /// Roundtrip: build v1 IPv6 -> parse -> compare.
    #[test]
    fn prop_v1_ipv6_roundtrip(
        src_ip in any::<Ipv6Addr>(),
        dst_ip in any::<Ipv6Addr>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
    ) {
        let src = SocketAddr::new(src_ip.into(), src_port);
        let dst = SocketAddr::new(dst_ip.into(), dst_port);
        let bytes = HeaderBuilder::v1_proxy(src, dst).build();
        let (info, consumed) = parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(info.source_inet().unwrap(), src);
        assert_eq!(info.destination_inet().unwrap(), dst);
    }

    /// Truncated v2 headers must return Incomplete.
    #[test]
    fn prop_truncated_v2_is_incomplete(
        src_ip in any::<Ipv4Addr>(),
        dst_ip in any::<Ipv4Addr>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        cut_point in 1usize..28,
    ) {
        let src = SocketAddr::new(src_ip.into(), src_port);
        let dst = SocketAddr::new(dst_ip.into(), dst_port);
        let full = HeaderBuilder::v2_proxy(src, dst).build();
        let cut = cut_point.min(full.len() - 1);
        let truncated = &full[..cut];
        match parse(truncated) {
            Err(ParseError::Incomplete) => {} // expected
            other => panic!("expected Incomplete at cut_point={cut}, got {other:?}"),
        }
    }

    /// Non-PP first byte is NotProxyProtocol, even for 1-byte buffers.
    #[test]
    fn prop_non_pp_first_byte(
        byte in any::<u8>().prop_filter("not PP start", |b| *b != 0x0D && *b != b'P'),
    ) {
        match parse(&[byte]) {
            Err(ParseError::NotProxyProtocol) => {}
            other => panic!("expected NotProxyProtocol, got {other:?}"),
        }
    }
}
