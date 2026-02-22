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

use std::net::SocketAddr;

use proxy_protocol_rs::*;

#[test]
fn v2_local_roundtrip() {
    let bytes = HeaderBuilder::v2_local().build();
    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(info.version, Version::V2);
    assert_eq!(info.command, Command::Local);
    assert!(info.transport.is_none());
    assert!(info.source.is_none());
    assert!(info.destination.is_none());
}

#[test]
fn v2_unix_stream_roundtrip() {
    let src = b"/var/run/client.sock";
    let dst = b"/var/run/server.sock";
    let bytes = HeaderBuilder::v2_unix(src.to_vec(), dst.to_vec(), TransportProtocol::Stream)
        .with_authority("unix.test")
        .build();
    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(info.version, Version::V2);
    assert_eq!(info.command, Command::Proxy);
    assert_eq!(
        info.transport,
        Some(Transport {
            family: AddressFamily::Unix,
            protocol: TransportProtocol::Stream,
        })
    );
    assert_eq!(info.source.unwrap().as_unix().unwrap(), src);
    assert_eq!(info.destination.unwrap().as_unix().unwrap(), dst);
    assert_eq!(info.tlvs.authority.as_deref(), Some("unix.test"));
}

#[test]
fn v2_unix_datagram_roundtrip() {
    let src = b"/tmp/dgram-src.sock";
    let dst = b"/tmp/dgram-dst.sock";
    let bytes =
        HeaderBuilder::v2_unix(src.to_vec(), dst.to_vec(), TransportProtocol::Datagram).build();
    let (info, _) = parse(&bytes).unwrap();
    assert_eq!(
        info.transport,
        Some(Transport {
            family: AddressFamily::Unix,
            protocol: TransportProtocol::Datagram,
        })
    );
}

#[test]
fn v1_ipv6_roundtrip() {
    let src: SocketAddr = "[2001:db8::1]:4321".parse().unwrap();
    let dst: SocketAddr = "[2001:db8::2]:8080".parse().unwrap();
    let bytes = HeaderBuilder::v1_proxy(src, dst).build();
    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(info.version, Version::V1);
    assert_eq!(info.source_inet().unwrap(), src);
    assert_eq!(info.destination_inet().unwrap(), dst);
    assert_eq!(
        info.transport,
        Some(Transport {
            family: AddressFamily::Inet6,
            protocol: TransportProtocol::Stream,
        })
    );
}

#[test]
fn v2_ipv6_roundtrip() {
    let src: SocketAddr = "[2001:db8::1]:4321".parse().unwrap();
    let dst: SocketAddr = "[2001:db8::2]:8080".parse().unwrap();
    let bytes = HeaderBuilder::v2_proxy(src, dst).build();
    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(info.version, Version::V2);
    assert_eq!(info.source_inet().unwrap(), src);
    assert_eq!(info.destination_inet().unwrap(), dst);
    assert_eq!(
        info.transport,
        Some(Transport {
            family: AddressFamily::Inet6,
            protocol: TransportProtocol::Stream,
        })
    );
}

#[test]
fn v2_ipv4_boundary_ports() {
    let src: SocketAddr = "10.0.0.1:0".parse().unwrap();
    let dst: SocketAddr = "10.0.0.2:65535".parse().unwrap();
    let bytes = HeaderBuilder::v2_proxy(src, dst).build();
    let (info, _) = parse(&bytes).unwrap();
    assert_eq!(info.source_inet().unwrap().port(), 0);
    assert_eq!(info.destination_inet().unwrap().port(), 65535);
}

#[test]
fn v2_no_tlvs() {
    let src: SocketAddr = "1.2.3.4:100".parse().unwrap();
    let dst: SocketAddr = "5.6.7.8:200".parse().unwrap();
    let bytes = HeaderBuilder::v2_proxy(src, dst).build();
    let (info, _) = parse(&bytes).unwrap();
    assert!(info.tlvs.alpn.is_none());
    assert!(info.tlvs.authority.is_none());
    assert!(info.tlvs.crc32c.is_none());
    assert!(info.tlvs.unique_id.is_none());
    assert!(info.tlvs.ssl.is_none());
    assert!(info.tlvs.netns.is_none());
    assert!(info.tlvs.raw.is_empty());
}

#[test]
fn v2_empty_authority() {
    let src: SocketAddr = "1.2.3.4:100".parse().unwrap();
    let dst: SocketAddr = "5.6.7.8:200".parse().unwrap();
    let bytes = HeaderBuilder::v2_proxy(src, dst).with_authority("").build();
    let (info, _) = parse(&bytes).unwrap();
    assert_eq!(info.tlvs.authority.as_deref(), Some(""));
}

#[test]
fn v2_ssl_with_crc_roundtrip() {
    let src: SocketAddr = "172.16.0.1:45678".parse().unwrap();
    let dst: SocketAddr = "172.16.0.2:8443".parse().unwrap();

    let ssl = SslInfo {
        client_flags: SslClientFlags::SSL | SslClientFlags::CERT_CONN,
        verified: true,
        version: Some("TLSv1.3".to_string()),
        cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
        sig_alg: Some("RSA-PSS".to_string()),
        key_alg: Some("RSA2048".to_string()),
        cn: Some("client.example.com".to_string()),
        ..Default::default()
    };

    let bytes = HeaderBuilder::v2_proxy(src, dst)
        .with_ssl(ssl)
        .with_crc32c()
        .build();

    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    let ssl = info.tlvs.ssl.as_ref().unwrap();
    assert!(ssl.verified);
    assert_eq!(ssl.version.as_deref(), Some("TLSv1.3"));
    assert_eq!(ssl.cn.as_deref(), Some("client.example.com"));
    assert!(info.tlvs.crc32c.is_some());
}

#[test]
fn v2_ssl_not_verified() {
    let src: SocketAddr = "10.0.0.1:1111".parse().unwrap();
    let dst: SocketAddr = "10.0.0.2:2222".parse().unwrap();

    let ssl = SslInfo {
        client_flags: SslClientFlags::SSL,
        verified: false,
        ..Default::default()
    };

    let bytes = HeaderBuilder::v2_proxy(src, dst).with_ssl(ssl).build();
    let (info, _) = parse(&bytes).unwrap();
    let ssl = info.tlvs.ssl.as_ref().unwrap();
    assert!(!ssl.verified);
    assert!(ssl.client_flags.contains(SslClientFlags::SSL));
    assert!(ssl.version.is_none());
    assert!(ssl.cipher.is_none());
    assert!(ssl.cn.is_none());
}

#[test]
fn v2_all_tlvs_roundtrip() {
    let src: SocketAddr = "192.168.0.50:60000".parse().unwrap();
    let dst: SocketAddr = "192.168.0.1:443".parse().unwrap();

    let bytes = HeaderBuilder::v2_proxy(src, dst)
        .with_authority("test.example.com")
        .with_alpn(b"h2".to_vec())
        .with_unique_id(b"conn-xyz-789".to_vec())
        .with_netns("test-namespace")
        .with_crc32c()
        .build();

    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(info.tlvs.authority.as_deref(), Some("test.example.com"));
    assert_eq!(info.tlvs.alpn.as_deref(), Some(b"h2".as_slice()));
    assert_eq!(
        info.tlvs.unique_id.as_deref(),
        Some(b"conn-xyz-789".as_slice())
    );
    assert_eq!(info.tlvs.netns.as_deref(), Some("test-namespace"));
    assert!(info.tlvs.crc32c.is_some());
}

#[test]
fn v2_raw_vendor_tlv_roundtrip() {
    let src: SocketAddr = "10.0.0.1:1000".parse().unwrap();
    let dst: SocketAddr = "10.0.0.2:2000".parse().unwrap();

    let bytes = HeaderBuilder::v2_proxy(src, dst)
        .with_raw_tlv(0xFE, vec![0xAA, 0xBB, 0xCC])
        .build();

    let (info, _) = parse(&bytes).unwrap();
    let found = info.tlvs.raw.iter().find(|(t, _)| *t == 0xFE);
    assert!(found.is_some());
    assert_eq!(found.unwrap().1, vec![0xAA, 0xBB, 0xCC]);
}

#[tokio::test]
async fn write_to_matches_build() {
    let src: SocketAddr = "10.10.10.1:6000".parse().unwrap();
    let dst: SocketAddr = "10.10.10.2:7000".parse().unwrap();

    let builder = HeaderBuilder::v2_proxy(src, dst)
        .with_authority("write-to-test.example.com")
        .with_crc32c();

    let built = builder.build();

    let mut buf = Vec::new();
    let written = builder.write_to(&mut buf).await.unwrap();

    assert_eq!(written, built.len());
    assert_eq!(buf, built);
}

#[test]
fn v2_crc_with_multiple_tlvs() {
    let src: SocketAddr = "10.0.0.1:1000".parse().unwrap();
    let dst: SocketAddr = "10.0.0.2:2000".parse().unwrap();

    let bytes = HeaderBuilder::v2_proxy(src, dst)
        .with_authority("crc-test")
        .with_alpn(b"h2".to_vec())
        .with_raw_tlv(0xFE, vec![1, 2, 3])
        .with_crc32c()
        .build();

    // Parsing validates CRC — if it's wrong, this returns CrcMismatch
    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert!(info.tlvs.crc32c.is_some());
}

#[test]
fn v2_local_with_crc() {
    let bytes = HeaderBuilder::v2_local().with_crc32c().build();
    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(info.command, Command::Local);
    assert!(info.tlvs.crc32c.is_some());
}

#[test]
fn v1_unknown_roundtrip() {
    let bytes = HeaderBuilder::v1_unknown().build();
    assert_eq!(&bytes, b"PROXY UNKNOWN\r\n");
    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(info.version, Version::V1);
    assert_eq!(info.command, Command::Proxy);
    assert!(info.transport.is_none());
    assert!(info.source.is_none());
    assert!(info.destination.is_none());
}

#[test]
fn v2_datagram_roundtrip() {
    let src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let dst: SocketAddr = "10.0.0.2:5001".parse().unwrap();
    let bytes = HeaderBuilder::v2_proxy(src, dst)
        .with_transport_protocol(TransportProtocol::Datagram)
        .build();
    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(
        info.transport,
        Some(Transport {
            family: AddressFamily::Inet,
            protocol: TransportProtocol::Datagram,
        })
    );
    assert_eq!(info.source_inet().unwrap(), src);
    assert_eq!(info.destination_inet().unwrap(), dst);
}

#[test]
#[should_panic(expected = "same address family")]
fn v2_proxy_rejects_mismatched_families() {
    let v4: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let v6: SocketAddr = "[::1]:80".parse().unwrap();
    let _ = HeaderBuilder::v2_proxy(v4, v6);
}

#[test]
#[should_panic(expected = "same address family")]
fn v1_proxy_rejects_mismatched_families() {
    let v4: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let v6: SocketAddr = "[::1]:80".parse().unwrap();
    let _ = HeaderBuilder::v1_proxy(v4, v6);
}

#[test]
#[should_panic(expected = "128-byte spec maximum")]
fn unique_id_too_long_panics() {
    let src: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let dst: SocketAddr = "5.6.7.8:443".parse().unwrap();
    let _ = HeaderBuilder::v2_proxy(src, dst).with_unique_id(vec![0xAA; 129]);
}

#[test]
fn unique_id_exactly_128_bytes() {
    let src: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let dst: SocketAddr = "5.6.7.8:443".parse().unwrap();
    let header = HeaderBuilder::v2_proxy(src, dst)
        .with_unique_id(vec![0xBB; 128])
        .build();
    let (info, _) = parse(&header).unwrap();
    assert_eq!(info.tlvs.unique_id.as_deref(), Some([0xBB; 128].as_slice()));
}

#[test]
fn display_impls() {
    let addr = ProxyAddress::from("10.0.0.1:80".parse::<SocketAddr>().unwrap());
    assert_eq!(addr.to_string(), "10.0.0.1:80");

    let unix = ProxyAddress::Unix(b"/tmp/test.sock".to_vec());
    assert_eq!(unix.to_string(), "/tmp/test.sock");

    // Non-UTF8 Unix path falls back to byte-length display
    let non_utf8 = ProxyAddress::Unix(vec![0xFF, 0xFE, 0x00]);
    assert_eq!(non_utf8.to_string(), "<unix:3 bytes>");

    assert_eq!(Version::V1.to_string(), "v1");
    assert_eq!(Version::V2.to_string(), "v2");
    assert_eq!(Command::Local.to_string(), "LOCAL");
    assert_eq!(Command::Proxy.to_string(), "PROXY");
    assert_eq!(AddressFamily::Inet.to_string(), "IPv4");
    assert_eq!(AddressFamily::Inet6.to_string(), "IPv6");
    assert_eq!(AddressFamily::Unix.to_string(), "Unix");
    assert_eq!(TransportProtocol::Stream.to_string(), "stream");
    assert_eq!(TransportProtocol::Datagram.to_string(), "datagram");
}

#[test]
fn destination_ip() {
    let src: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let dst: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let bytes = HeaderBuilder::v2_proxy(src, dst).build();
    let (info, _) = parse(&bytes).unwrap();
    assert_eq!(info.destination_ip(), Some(dst.ip()));
    assert_eq!(info.source_ip(), Some(src.ip()));
}

#[test]
fn proxy_address_from_socket_addr() {
    let addr: SocketAddr = "[::1]:8080".parse().unwrap();
    let pa = ProxyAddress::from(addr);
    assert_eq!(pa.as_inet(), Some(addr));
    assert_eq!(pa.ip(), Some(addr.ip()));
    assert!(pa.as_unix().is_none());
}

#[test]
fn v2_local_with_authority() {
    let bytes = HeaderBuilder::v2_local()
        .with_authority("health-check.internal")
        .build();
    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(info.command, Command::Local);
    assert!(info.source.is_none());
    assert_eq!(
        info.tlvs.authority.as_deref(),
        Some("health-check.internal")
    );
}

#[test]
fn v2_unix_long_path_truncated() {
    // Paths longer than 108 bytes are silently truncated by the v2 spec's
    // fixed 108-byte field.
    let long_path = vec![b'a'; 200];
    let bytes = HeaderBuilder::v2_unix(
        long_path.clone(),
        b"/dst".to_vec(),
        TransportProtocol::Stream,
    )
    .build();
    let (info, _) = parse(&bytes).unwrap();
    let src = info.source.unwrap().as_unix().unwrap().to_vec();
    assert_eq!(src.len(), 108);
    assert!(src.iter().all(|&b| b == b'a'));
}

#[test]
fn v2_padding_roundtrip() {
    let src: SocketAddr = "10.0.0.1:1000".parse().unwrap();
    let dst: SocketAddr = "10.0.0.2:2000".parse().unwrap();

    let bytes = HeaderBuilder::v2_proxy(src, dst).with_padding(64).build();

    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(info.source_inet().unwrap(), src);
    // NOOP should be in raw
    assert!(
        info.tlvs
            .raw
            .iter()
            .any(|(t, v)| *t == 0x04 && v.len() == 64)
    );
}

#[test]
fn v2_padding_zero_length() {
    let src: SocketAddr = "10.0.0.1:1000".parse().unwrap();
    let dst: SocketAddr = "10.0.0.2:2000".parse().unwrap();

    let bytes = HeaderBuilder::v2_proxy(src, dst).with_padding(0).build();

    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert!(
        info.tlvs
            .raw
            .iter()
            .any(|(t, v)| *t == 0x04 && v.is_empty())
    );
}

#[test]
fn v2_padding_with_crc_roundtrip() {
    let src: SocketAddr = "10.0.0.1:1000".parse().unwrap();
    let dst: SocketAddr = "10.0.0.2:2000".parse().unwrap();

    let bytes = HeaderBuilder::v2_proxy(src, dst)
        .with_authority("padded.example.com")
        .with_padding(128)
        .with_crc32c()
        .build();

    // CRC validation happens during parse
    let (info, consumed) = parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert!(info.tlvs.crc32c.is_some());
    assert_eq!(info.tlvs.authority.as_deref(), Some("padded.example.com"));
    assert!(
        info.tlvs
            .raw
            .iter()
            .any(|(t, v)| *t == 0x04 && v.len() == 128)
    );
}
