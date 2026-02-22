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
use proxy_protocol_rs::{HeaderBuilder, SslClientFlags, SslInfo};

use std::net::SocketAddr;

fn build_v2_with_tlvs(tlv_bytes: &[u8]) -> Vec<u8> {
    let sig: &[u8] = &[13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10];
    let addr_payload: &[u8] = &[
        // source IP
        127, 0, 0, 1, // destination IP
        10, 11, 12, 13, // source port = 1234
        0x04, 0xD2, // destination port = 23456
        0x5B, 0xA0,
    ];
    let payload_len = (addr_payload.len() + tlv_bytes.len()) as u16;
    let mut buf = Vec::new();
    buf.extend_from_slice(sig);
    // ver = 2, cmd = proxy
    buf.push(0x21);
    // family = inet, proto = stream
    buf.push(0x11);
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.extend_from_slice(addr_payload);
    buf.extend_from_slice(tlv_bytes);
    buf
}

#[test]
fn alpn() {
    // type = ALPN
    let mut tlv = vec![0x01];
    // length = 2
    tlv.extend_from_slice(&2u16.to_be_bytes());
    tlv.extend_from_slice(b"h2");

    let data = build_v2_with_tlvs(&tlv);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(info.tlvs.alpn.as_deref(), Some(b"h2".as_slice()));
}

#[test]
fn authority() {
    let authority = b"internal.example.org";
    let mut tlv = vec![0x02];
    tlv.extend_from_slice(&(authority.len() as u16).to_be_bytes());
    tlv.extend_from_slice(authority);

    let data = build_v2_with_tlvs(&tlv);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(info.tlvs.authority.as_deref(), Some("internal.example.org"));
}

#[test]
fn unique_id() {
    let id = b"conn-12345";
    let mut tlv = vec![0x05];
    tlv.extend_from_slice(&(id.len() as u16).to_be_bytes());
    tlv.extend_from_slice(id);

    let data = build_v2_with_tlvs(&tlv);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(info.tlvs.unique_id.as_deref(), Some(id.as_slice()));
}

#[test]
fn unique_id_too_long() {
    // > 128 bytes
    let id = vec![0xAA; 129];
    let mut tlv = vec![0x05];
    tlv.extend_from_slice(&(id.len() as u16).to_be_bytes());
    tlv.extend_from_slice(&id);

    let data = build_v2_with_tlvs(&tlv);
    assert!(parse(&data).is_err());
}

#[test]
fn netns() {
    let ns = b"/var/run/netns/example";
    let mut tlv = vec![0x30];
    tlv.extend_from_slice(&(ns.len() as u16).to_be_bytes());
    tlv.extend_from_slice(ns);

    let data = build_v2_with_tlvs(&tlv);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(info.tlvs.netns.as_deref(), Some("/var/run/netns/example"));
}

#[test]
fn noop_silently_skipped() {
    // NOOP
    let mut tlv = vec![0x04];
    tlv.extend_from_slice(&10u16.to_be_bytes());
    tlv.extend_from_slice(&[0u8; 10]);

    let data = build_v2_with_tlvs(&tlv);
    let (info, _) = parse(&data).unwrap();
    // NOOP should be in raw but not cause any typed field to be set
    assert!(info.tlvs.alpn.is_none());
    assert!(info.tlvs.authority.is_none());
    assert!(info.tlvs.unique_id.is_none());
    // But it IS in raw
    assert!(info.tlvs.raw.iter().any(|(t, _)| *t == 0x04));
}

#[test]
fn ssl_full() {
    let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let dst: SocketAddr = "10.11.12.13:23456".parse().unwrap();

    let header = HeaderBuilder::v2_proxy(src, dst)
        .with_ssl(SslInfo {
            client_flags: SslClientFlags::SSL
                | SslClientFlags::CERT_CONN
                | SslClientFlags::CERT_SESS,
            verified: true,
            version: Some("TLSv1.3".to_string()),
            cipher: Some("ECDHE-RSA-AES128-GCM-SHA256".to_string()),
            sig_alg: Some("SHA256".to_string()),
            key_alg: Some("RSA2048".to_string()),
            cn: Some("example.com".to_string()),
            ..Default::default()
        })
        .build();

    let (info, _) = parse(&header).unwrap();
    let ssl = info.tlvs.ssl.as_ref().unwrap();
    assert!(ssl.client_flags.contains(SslClientFlags::SSL));
    assert!(ssl.client_flags.contains(SslClientFlags::CERT_CONN));
    assert!(ssl.client_flags.contains(SslClientFlags::CERT_SESS));
    assert!(ssl.verified);
    assert_eq!(ssl.version.as_deref(), Some("TLSv1.3"));
    assert_eq!(ssl.cipher.as_deref(), Some("ECDHE-RSA-AES128-GCM-SHA256"));
    assert_eq!(ssl.sig_alg.as_deref(), Some("SHA256"));
    assert_eq!(ssl.key_alg.as_deref(), Some("RSA2048"));
    assert_eq!(ssl.cn.as_deref(), Some("example.com"));
    assert!(ssl.group.is_none());
    assert!(ssl.sig_scheme.is_none());
    assert!(ssl.client_cert.is_none());
}

#[test]
fn ssl_group_roundtrip() {
    let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let dst: SocketAddr = "10.11.12.13:23456".parse().unwrap();

    let header = HeaderBuilder::v2_proxy(src, dst)
        .with_ssl(SslInfo {
            client_flags: SslClientFlags::SSL,
            verified: true,
            group: Some("x25519".to_string()),
            ..Default::default()
        })
        .build();

    let (info, _) = parse(&header).unwrap();
    let ssl = info.tlvs.ssl.as_ref().unwrap();
    assert_eq!(ssl.group.as_deref(), Some("x25519"));
}

#[test]
fn ssl_sig_scheme_roundtrip() {
    let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let dst: SocketAddr = "10.11.12.13:23456".parse().unwrap();

    let header = HeaderBuilder::v2_proxy(src, dst)
        .with_ssl(SslInfo {
            client_flags: SslClientFlags::SSL,
            verified: true,
            sig_scheme: Some("ecdsa_secp256r1_sha256".to_string()),
            ..Default::default()
        })
        .build();

    let (info, _) = parse(&header).unwrap();
    let ssl = info.tlvs.ssl.as_ref().unwrap();
    assert_eq!(ssl.sig_scheme.as_deref(), Some("ecdsa_secp256r1_sha256"));
}

#[test]
fn ssl_client_cert_roundtrip() {
    let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let dst: SocketAddr = "10.11.12.13:23456".parse().unwrap();

    // Fake DER-encoded certificate bytes
    let cert_der = vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09];

    let header = HeaderBuilder::v2_proxy(src, dst)
        .with_ssl(SslInfo {
            client_flags: SslClientFlags::SSL | SslClientFlags::CERT_CONN,
            verified: true,
            client_cert: Some(cert_der.clone()),
            ..Default::default()
        })
        .build();

    let (info, _) = parse(&header).unwrap();
    let ssl = info.tlvs.ssl.as_ref().unwrap();
    assert_eq!(ssl.client_cert.as_deref(), Some(cert_der.as_slice()));
}

#[test]
fn ssl_all_sub_tlvs_roundtrip() {
    let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let dst: SocketAddr = "10.11.12.13:23456".parse().unwrap();

    let cert_der = vec![0x30, 0x82, 0x03, 0xFF];

    let header = HeaderBuilder::v2_proxy(src, dst)
        .with_ssl(SslInfo {
            client_flags: SslClientFlags::SSL
                | SslClientFlags::CERT_CONN
                | SslClientFlags::CERT_SESS,
            verified: true,
            version: Some("TLSv1.3".to_string()),
            cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
            sig_alg: Some("SHA256".to_string()),
            key_alg: Some("RSA2048".to_string()),
            cn: Some("client.example.com".to_string()),
            group: Some("x25519".to_string()),
            sig_scheme: Some("rsa_pss_rsae_sha256".to_string()),
            client_cert: Some(cert_der.clone()),
        })
        .build();

    let (info, _) = parse(&header).unwrap();
    let ssl = info.tlvs.ssl.as_ref().unwrap();
    assert!(ssl.verified);
    assert_eq!(ssl.version.as_deref(), Some("TLSv1.3"));
    assert_eq!(ssl.cipher.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
    assert_eq!(ssl.sig_alg.as_deref(), Some("SHA256"));
    assert_eq!(ssl.key_alg.as_deref(), Some("RSA2048"));
    assert_eq!(ssl.cn.as_deref(), Some("client.example.com"));
    assert_eq!(ssl.group.as_deref(), Some("x25519"));
    assert_eq!(ssl.sig_scheme.as_deref(), Some("rsa_pss_rsae_sha256"));
    assert_eq!(ssl.client_cert.as_deref(), Some(cert_der.as_slice()));
}

#[test]
fn ssl_client_cert_empty() {
    let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let dst: SocketAddr = "10.11.12.13:23456".parse().unwrap();

    let header = HeaderBuilder::v2_proxy(src, dst)
        .with_ssl(SslInfo {
            client_flags: SslClientFlags::SSL,
            verified: true,
            client_cert: Some(vec![]),
            ..Default::default()
        })
        .build();

    let (info, _) = parse(&header).unwrap();
    let ssl = info.tlvs.ssl.as_ref().unwrap();
    assert_eq!(ssl.client_cert.as_deref(), Some([].as_slice()));
}

#[test]
fn unknown_tlv_preserved_in_raw() {
    // unknown type
    let mut tlv = vec![0xFF];
    let value = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
    tlv.extend_from_slice(&(value.len() as u16).to_be_bytes());
    tlv.extend_from_slice(&value);

    let data = build_v2_with_tlvs(&tlv);
    let (info, _) = parse(&data).unwrap();
    assert!(info.tlvs.raw.iter().any(|(t, v)| *t == 0xFF && *v == value));
}

#[test]
fn multiple_tlvs() {
    let mut tlvs = Vec::new();

    // ALPN
    tlvs.push(0x01);
    tlvs.extend_from_slice(&2u16.to_be_bytes());
    tlvs.extend_from_slice(b"h2");

    // Authority
    let auth = b"example.com";
    tlvs.push(0x02);
    tlvs.extend_from_slice(&(auth.len() as u16).to_be_bytes());
    tlvs.extend_from_slice(auth);

    // NETNS
    let ns = b"/var/run/netns/test";
    tlvs.push(0x30);
    tlvs.extend_from_slice(&(ns.len() as u16).to_be_bytes());
    tlvs.extend_from_slice(ns);

    let data = build_v2_with_tlvs(&tlvs);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(info.tlvs.alpn.as_deref(), Some(b"h2".as_slice()));
    assert_eq!(info.tlvs.authority.as_deref(), Some("example.com"));
    assert_eq!(info.tlvs.netns.as_deref(), Some("/var/run/netns/test"));
    assert_eq!(info.tlvs.raw.len(), 3);
}

#[cfg(feature = "aws")]
mod aws_vendor {
    use super::*;

    /// Build an AWS TLV (0xEA) with flat format: [subtype(1), data(N)]
    fn build_aws_tlv(subtype: u8, data: &[u8]) -> Vec<u8> {
        // subtype + data
        let value_len = 1 + data.len();
        let mut tlv = vec![0xEA];
        tlv.extend_from_slice(&(value_len as u16).to_be_bytes());
        tlv.push(subtype);
        tlv.extend_from_slice(data);
        tlv
    }

    #[test]
    fn vpce_id_from_real_nlb_data() {
        // Real NLB capture from go-proxyproto test suite:
        // TLV bytes: [0xEA, 0x00, 0x17, 0x01, "vpce-08d2bf15fac5001c9"]
        // 0x17 = 23 = 1 (subtype) + 22 (string)
        let tlv = build_aws_tlv(0x01, b"vpce-08d2bf15fac5001c9");
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let aws = info.tlvs.aws().unwrap().unwrap();
        assert_eq!(
            aws.vpc_endpoint_id.as_deref(),
            Some("vpce-08d2bf15fac5001c9")
        );
    }

    #[test]
    fn vpce_id_second_real_capture() {
        // Second real NLB capture from go-proxyproto: vpce-00eafc458ec97b833
        let tlv = build_aws_tlv(0x01, b"vpce-00eafc458ec97b833");
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let aws = info.tlvs.aws().unwrap().unwrap();
        assert_eq!(
            aws.vpc_endpoint_id.as_deref(),
            Some("vpce-00eafc458ec97b833")
        );
    }

    #[test]
    fn vpce_id_empty_string() {
        // Empty VPCE string is valid per go-proxyproto (matches ^[A-Za-z0-9-]*$)
        let tlv = build_aws_tlv(0x01, b"");
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let aws = info.tlvs.aws().unwrap().unwrap();
        assert_eq!(aws.vpc_endpoint_id.as_deref(), Some(""));
    }

    #[test]
    fn vpce_id_bad_chars_rejected() {
        // go-proxyproto rejects "vcpe-!?***&&&&&&&" — special characters
        let tlv = build_aws_tlv(0x01, b"vpce-!?***&&&");
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let result = info.tlvs.aws().unwrap();
        assert!(result.is_err(), "bad chars in VPCE ID should be rejected");
    }

    #[test]
    fn vpce_id_alphanumeric_with_dashes() {
        // Simple alphanumeric + dashes should pass
        let tlv = build_aws_tlv(0x01, b"vpce-abc1234");
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let aws = info.tlvs.aws().unwrap().unwrap();
        assert_eq!(aws.vpc_endpoint_id.as_deref(), Some("vpce-abc1234"));
    }

    #[test]
    fn unknown_subtype_stored_in_raw() {
        // go-proxyproto: changing subtype from 0x01 to 0x02 means it's not a VPCE ID
        let tlv = build_aws_tlv(0x02, b"some-data");
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let aws = info.tlvs.aws().unwrap().unwrap();
        assert!(aws.vpc_endpoint_id.is_none());
        assert_eq!(aws.raw.len(), 1);
        assert_eq!(aws.raw[0].0, 0x02);
        assert_eq!(aws.raw[0].1, b"some-data");
    }

    #[test]
    fn no_aws_tlv_returns_none() {
        // No 0xEA TLV at all
        let data = build_v2_with_tlvs(&[]);
        let (info, _) = parse(&data).unwrap();
        assert!(info.tlvs.aws().is_none());
    }

    #[test]
    fn invalid_utf8_rejected() {
        let tlv = build_aws_tlv(0x01, &[0xFF, 0xFE, 0xFD]);
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let result = info.tlvs.aws().unwrap();
        assert!(result.is_err(), "invalid UTF-8 should be rejected");
    }

    #[test]
    fn raw_preserves_data() {
        let tlv = build_aws_tlv(0x01, b"vpce-test123");
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let aws = info.tlvs.aws().unwrap().unwrap();
        assert_eq!(aws.raw.len(), 1);
        assert_eq!(aws.raw[0].0, 0x01);
        assert_eq!(aws.raw[0].1, b"vpce-test123");
    }
}

#[cfg(feature = "azure")]
mod azure_vendor {
    use super::*;

    /// Build an Azure TLV (0xEE) with flat format: [subtype(1), data(N)]
    fn build_azure_tlv(subtype: u8, data: &[u8]) -> Vec<u8> {
        let value_len = 1 + data.len();
        let mut tlv = vec![0xEE];
        tlv.extend_from_slice(&(value_len as u16).to_be_bytes());
        tlv.push(subtype);
        tlv.extend_from_slice(data);
        tlv
    }

    #[test]
    fn link_id_from_real_azure_data() {
        // Real Azure test data from go-proxyproto:
        // Value: [0x01, 0xc1, 0x45, 0x00, 0x21]
        // Expected LinkID: 0x210045c1 (little-endian)
        let tlv = build_azure_tlv(0x01, &[0xc1, 0x45, 0x00, 0x21]);
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let azure = info.tlvs.azure().unwrap().unwrap();
        assert_eq!(azure.private_endpoint_link_id, Some(0x210045c1));
    }

    #[test]
    fn link_id_zero() {
        let tlv = build_azure_tlv(0x01, &[0x00, 0x00, 0x00, 0x00]);
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let azure = info.tlvs.azure().unwrap().unwrap();
        assert_eq!(azure.private_endpoint_link_id, Some(0));
    }

    #[test]
    fn link_id_max_u32() {
        let tlv = build_azure_tlv(0x01, &[0xFF, 0xFF, 0xFF, 0xFF]);
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let azure = info.tlvs.azure().unwrap().unwrap();
        assert_eq!(azure.private_endpoint_link_id, Some(u32::MAX));
    }

    #[test]
    fn wrong_subtype_not_parsed_as_link_id() {
        // go-proxyproto: subtype 0x02 is not recognized
        let tlv = build_azure_tlv(0x02, &[0x01, 0x01, 0x01, 0x01]);
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let azure = info.tlvs.azure().unwrap().unwrap();
        assert!(azure.private_endpoint_link_id.is_none());
        assert_eq!(azure.raw[0].0, 0x02);
    }

    #[test]
    fn wrong_length_rejected() {
        // go-proxyproto: value length 3 (not 5 total = subtype + 4 bytes)
        let tlv = build_azure_tlv(0x01, &[0x01, 0x01]);
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let result = info.tlvs.azure().unwrap();
        assert!(result.is_err(), "wrong length should be rejected");
    }

    #[test]
    fn no_azure_tlv_returns_none() {
        let data = build_v2_with_tlvs(&[]);
        let (info, _) = parse(&data).unwrap();
        assert!(info.tlvs.azure().is_none());
    }

    #[test]
    fn empty_value_rejected() {
        // Empty TLV value (no subtype byte)
        let mut tlv = vec![0xEE];
        tlv.extend_from_slice(&0u16.to_be_bytes());
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let result = info.tlvs.azure().unwrap();
        assert!(result.is_err(), "empty value should be rejected");
    }

    #[test]
    fn little_endian_byte_order() {
        // Verify byte order: [0x01, 0x00, 0x00, 0x00] should be 1, not 0x01000000
        let tlv = build_azure_tlv(0x01, &[0x01, 0x00, 0x00, 0x00]);
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let azure = info.tlvs.azure().unwrap().unwrap();
        assert_eq!(azure.private_endpoint_link_id, Some(1));
    }

    #[test]
    fn raw_preserves_data() {
        let tlv = build_azure_tlv(0x01, &[0xc1, 0x45, 0x00, 0x21]);
        let data = build_v2_with_tlvs(&tlv);
        let (info, _) = parse(&data).unwrap();

        let azure = info.tlvs.azure().unwrap().unwrap();
        assert_eq!(azure.raw.len(), 1);
        assert_eq!(azure.raw[0].0, 0x01);
        assert_eq!(azure.raw[0].1, &[0xc1, 0x45, 0x00, 0x21]);
    }
}

#[cfg(feature = "gcp")]
#[test]
fn gcp_psc_connection_id() {
    // GCP TLV 0xE0: 8-byte big-endian PSC connection ID
    let conn_id: u64 = 0x0123_4567_89AB_CDEF;
    let mut tlv = vec![0xE0];
    tlv.extend_from_slice(&8u16.to_be_bytes());
    tlv.extend_from_slice(&conn_id.to_be_bytes());

    let data = build_v2_with_tlvs(&tlv);
    let (info, _) = parse(&data).unwrap();

    let gcp = info.tlvs.gcp().unwrap().unwrap();
    assert_eq!(gcp.psc_connection_id, conn_id);
}

#[cfg(feature = "gcp")]
#[test]
fn gcp_wrong_length_rejected() {
    // GCP TLV with 4 bytes instead of 8
    let mut tlv = vec![0xE0];
    tlv.extend_from_slice(&4u16.to_be_bytes());
    tlv.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

    let data = build_v2_with_tlvs(&tlv);
    let (info, _) = parse(&data).unwrap();

    assert!(info.tlvs.gcp().unwrap().is_err());
}

#[test]
fn ssl_unknown_sub_tlv_skipped() {
    // Build an SSL TLV with a known sub-TLV followed by an unknown one.
    // The parser should skip the unknown sub-TLV without error.
    let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let dst: SocketAddr = "10.11.12.13:23456".parse().unwrap();

    let mut ssl_value = Vec::new();
    // client flags byte
    ssl_value.push(SslClientFlags::SSL.bits());
    // verify: 0 = verified
    ssl_value.extend_from_slice(&0u32.to_be_bytes());
    // sub-TLV 0x21 (version) = "TLSv1.3"
    ssl_value.push(0x21);
    ssl_value.extend_from_slice(&7u16.to_be_bytes());
    ssl_value.extend_from_slice(b"TLSv1.3");
    // sub-TLV 0xFE (unknown) = arbitrary data
    ssl_value.push(0xFE);
    ssl_value.extend_from_slice(&3u16.to_be_bytes());
    ssl_value.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

    let header = HeaderBuilder::v2_proxy(src, dst)
        .with_raw_tlv(0x20, ssl_value)
        .build();

    let (info, _) = parse(&header).unwrap();
    let ssl = info.tlvs.ssl.as_ref().unwrap();
    assert!(ssl.verified);
    assert_eq!(ssl.version.as_deref(), Some("TLSv1.3"));
}

#[test]
fn malformed_tlv_truncated_length() {
    // TLV with length field claiming more data than available
    // authority
    let mut tlv = vec![0x02];
    // claims 100 bytes
    tlv.extend_from_slice(&100u16.to_be_bytes());
    // only 5 bytes
    tlv.extend_from_slice(b"short");

    let data = build_v2_with_tlvs(&tlv);
    assert!(parse(&data).is_err());
}

#[test]
fn malformed_tlv_incomplete_header() {
    // Only 2 bytes of a TLV (need at least 3 for type + length)
    let data = build_v2_with_tlvs(&[0x01, 0x00]);
    assert!(parse(&data).is_err());
}

#[test]
fn empty_tlv_value() {
    // TLV with zero-length value
    // ALPN with empty value
    let mut tlv = vec![0x01];
    tlv.extend_from_slice(&0u16.to_be_bytes());

    let data = build_v2_with_tlvs(&tlv);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(info.tlvs.alpn.as_deref(), Some(b"".as_slice()));
}

#[test]
fn truncated_tlv_type_only() {
    // Only a TLV type byte, no length bytes at all
    let data = build_v2_with_tlvs(&[0x01]);
    assert!(parse(&data).is_err());
}

#[test]
fn truncated_tlv_partial_value() {
    // Type + length claiming 5 bytes, but only 2 provided
    // ALPN type
    let mut tlv = vec![0x01];
    // claims 5 bytes
    tlv.extend_from_slice(&5u16.to_be_bytes());
    tlv.push(0xAA);
    // only 2 bytes
    tlv.push(0xBB);
    let data = build_v2_with_tlvs(&tlv);
    assert!(parse(&data).is_err());
}

#[test]
fn zero_length_noop() {
    // NOOP (0x04) with zero-length value — valid per spec
    let mut tlv = vec![0x04];
    tlv.extend_from_slice(&0u16.to_be_bytes());
    let data = build_v2_with_tlvs(&tlv);
    let (info, _) = parse(&data).unwrap();
    assert!(
        info.tlvs
            .raw
            .iter()
            .any(|(t, v)| *t == 0x04 && v.is_empty())
    );
}

#[test]
fn authority_non_utf8_handled_gracefully() {
    // Authority with invalid UTF-8 is stored as lossy-converted string
    let mut tlv = vec![0x02];
    let bad_utf8 = [0xFF, 0xFE, 0x80, 0x81];
    tlv.extend_from_slice(&(bad_utf8.len() as u16).to_be_bytes());
    tlv.extend_from_slice(&bad_utf8);
    let data = build_v2_with_tlvs(&tlv);
    let (info, _) = parse(&data).unwrap();
    // Stored as lossy string with replacement characters
    assert!(info.tlvs.authority.is_some());
    assert!(info.tlvs.authority.unwrap().contains('\u{FFFD}'));
}

#[test]
fn consecutive_tlvs_with_different_types() {
    // Three TLVs of different types parsed correctly
    let mut tlvs = Vec::new();

    // ALPN = "h2"
    tlvs.push(0x01);
    tlvs.extend_from_slice(&2u16.to_be_bytes());
    tlvs.extend_from_slice(b"h2");

    // Unique ID = 16 bytes
    let uid = vec![0x42; 16];
    tlvs.push(0x05);
    tlvs.extend_from_slice(&(uid.len() as u16).to_be_bytes());
    tlvs.extend_from_slice(&uid);

    // Unknown 0xFE = some data
    tlvs.push(0xFE);
    tlvs.extend_from_slice(&4u16.to_be_bytes());
    tlvs.extend_from_slice(&[1, 2, 3, 4]);

    let data = build_v2_with_tlvs(&tlvs);
    let (info, _) = parse(&data).unwrap();
    assert_eq!(info.tlvs.alpn.as_deref(), Some(b"h2".as_slice()));
    assert_eq!(info.tlvs.unique_id.as_deref(), Some(uid.as_slice()));
    assert_eq!(info.tlvs.raw.len(), 3);
}

#[test]
fn crc_wrong_length_rejected() {
    // CRC TLV (0x03) with wrong length (not 4) — must be rejected per spec
    let mut tlv = vec![0x03];
    // length = 3, not 4
    tlv.extend_from_slice(&3u16.to_be_bytes());
    tlv.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

    let data = build_v2_with_tlvs(&tlv);
    assert!(parse(&data).is_err());
}

#[test]
fn crc_wrong_length_5_bytes_rejected() {
    // CRC TLV (0x03) with 5 bytes — also invalid
    let mut tlv = vec![0x03];
    tlv.extend_from_slice(&5u16.to_be_bytes());
    tlv.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);

    let data = build_v2_with_tlvs(&tlv);
    assert!(parse(&data).is_err());
}

#[test]
fn crc_zero_length_rejected() {
    // CRC TLV (0x03) with 0 bytes — invalid
    let mut tlv = vec![0x03];
    tlv.extend_from_slice(&0u16.to_be_bytes());

    let data = build_v2_with_tlvs(&tlv);
    assert!(parse(&data).is_err());
}
