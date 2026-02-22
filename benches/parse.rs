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

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use proxy_protocol_rs::{HeaderBuilder, SslClientFlags, SslInfo, parse};

fn bench_parse_v2_ipv4_minimal(c: &mut Criterion) {
    let header = HeaderBuilder::v2_proxy(
        "10.0.0.1:1234".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
    )
    .build();

    c.bench_function("parse_v2_ipv4_no_tlvs", |b| {
        b.iter(|| parse(black_box(&header)))
    });
}

fn bench_parse_v2_ipv4_with_crc(c: &mut Criterion) {
    let header = HeaderBuilder::v2_proxy(
        "10.0.0.1:1234".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
    )
    .with_crc32c()
    .build();

    c.bench_function("parse_v2_ipv4_crc32c", |b| {
        b.iter(|| parse(black_box(&header)))
    });
}

fn bench_parse_v2_ipv4_full_tlvs(c: &mut Criterion) {
    let header = HeaderBuilder::v2_proxy(
        "10.0.0.1:1234".parse().unwrap(),
        "10.0.0.2:443".parse().unwrap(),
    )
    .with_authority("app.example.com")
    .with_alpn(b"h2".to_vec())
    .with_ssl(SslInfo {
        client_flags: SslClientFlags::SSL | SslClientFlags::CERT_CONN,
        verified: true,
        version: Some("TLSv1.3".into()),
        cipher: Some("TLS_AES_256_GCM_SHA384".into()),
        cn: Some("client.example.com".into()),
        ..Default::default()
    })
    .with_crc32c()
    .build();

    c.bench_function("parse_v2_ipv4_full_tlvs", |b| {
        b.iter(|| parse(black_box(&header)))
    });
}

fn bench_parse_v2_ipv6_minimal(c: &mut Criterion) {
    let header = HeaderBuilder::v2_proxy(
        "[2001:db8::1]:1234".parse().unwrap(),
        "[2001:db8::2]:80".parse().unwrap(),
    )
    .build();

    c.bench_function("parse_v2_ipv6_no_tlvs", |b| {
        b.iter(|| parse(black_box(&header)))
    });
}

fn bench_parse_v1_tcp4(c: &mut Criterion) {
    let header = b"PROXY TCP4 192.168.0.1 10.0.0.1 56324 443\r\n";

    c.bench_function("parse_v1_tcp4", |b| {
        b.iter(|| parse(black_box(header.as_slice())))
    });
}

fn bench_parse_v1_tcp6(c: &mut Criterion) {
    let header =
        b"PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:0000:0042:0000:8a2e:0370:7335 4124 443\r\n";

    c.bench_function("parse_v1_tcp6", |b| {
        b.iter(|| parse(black_box(header.as_slice())))
    });
}

fn bench_parse_v2_aws_packet(c: &mut Criterion) {
    // Real AWS NLB packet with CRC32c + VPC endpoint ID + NOOP
    let data: Vec<u8> = vec![
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33, 17, 0, 84, 172, 31, 7, 113, 172, 31, 10,
        31, 200, 242, 0, 80, 3, 0, 4, 232, 214, 137, 45, 234, 0, 23, 1, 118, 112, 99, 101, 45, 48,
        56, 100, 50, 98, 102, 49, 53, 102, 97, 99, 53, 48, 48, 49, 99, 57, 4, 0, 36, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
    ];

    c.bench_function("parse_v2_aws_nlb_packet", |b| {
        b.iter(|| parse(black_box(&data)))
    });
}

fn bench_build_v2_ipv4(c: &mut Criterion) {
    let src = "10.0.0.1:1234".parse().unwrap();
    let dst = "10.0.0.2:80".parse().unwrap();

    c.bench_function("build_v2_ipv4_no_tlvs", |b| {
        b.iter(|| HeaderBuilder::v2_proxy(black_box(src), black_box(dst)).build())
    });
}

fn bench_build_v2_with_crc(c: &mut Criterion) {
    let src = "10.0.0.1:1234".parse().unwrap();
    let dst = "10.0.0.2:80".parse().unwrap();

    c.bench_function("build_v2_ipv4_crc32c", |b| {
        b.iter(|| {
            HeaderBuilder::v2_proxy(black_box(src), black_box(dst))
                .with_crc32c()
                .build()
        })
    });
}

fn bench_not_proxy_protocol(c: &mut Criterion) {
    let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    c.bench_function("parse_not_pp_http", |b| {
        b.iter(|| parse(black_box(http.as_slice())))
    });
}

criterion_group!(
    benches,
    bench_parse_v2_ipv4_minimal,
    bench_parse_v2_ipv4_with_crc,
    bench_parse_v2_ipv4_full_tlvs,
    bench_parse_v2_ipv6_minimal,
    bench_parse_v1_tcp4,
    bench_parse_v1_tcp6,
    bench_parse_v2_aws_packet,
    bench_build_v2_ipv4,
    bench_build_v2_with_crc,
    bench_not_proxy_protocol,
);
criterion_main!(benches);
