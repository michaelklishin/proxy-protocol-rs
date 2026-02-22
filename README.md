# A Tokio-native Proxy Protocol (v1 and v2) Implementation in Rust

This crate implements the [Proxy Protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) (versions 1 and 2)
on top of Tokio.

It provides a drop-in `TcpListener` wrapper that reads and strips Proxy Protocol headers,
exposing the real client address to the application. Beyond the listener, the crate includes
a standalone parser, a header builder, and TLV support with vendor-specific extensions for AWS, Azure, and GCP.

This library was heavily inspired by [Ranch](https://github.com/ninenines/ranch) (Erlang, Elixir) and
[go-proxyproto](https://github.com/pires/go-proxyproto) (Go).


## Key Features

* Proxy Protocol v1 (text) and v2 (binary) parsing and building
* `ProxyProtocolListener`: a TCP listener wrapper with configurable policies
* `axum::serve` integration behind the `axum` feature via `axum::serve::Listener`
* TLV extensions: ALPN, authority, TLS metadata, CRC32c, unique ID, NETNS
* Connection policies: trusted proxies (exact IPs and CIDRs), mixed mode, custom closures
* Header validation: reject connections based on parsed header content
* Bounded concurrency: configurable semaphore for in-flight PP handshakes
* Vendor-specific TLV support: AWS VPC endpoint ID, Azure Private Link ID, GCP PSC connection ID


## Project Maturity

This library is young but the API is stabilizing.

Before `1.0`, breaking API changes can happen.


## Requirements

* Rust 1.88+ (edition 2024)
* Tokio runtime


## Dependency

```toml
proxy-protocol-rs = "0.7"
```

### With Axum Integration

```toml
proxy-protocol-rs = { version = "0.7", features = ["axum"] }
```

### With Vendor TLV Support

With [AWS NLB](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/edit-target-group-attributes.html):

```toml
# AWS VPC endpoint ID (PP2_TYPE_AWS, 0xEA)
proxy-protocol-rs = { version = "0.7", features = ["aws"] }
```

With [GCP Private Service Connect](https://cloud.google.com/vpc/docs/configure-private-service-connect-producer#proxy-protocol):

```toml
# GCP Private Service Connect connection ID (PP2_TYPE_GCE, 0xE0)
proxy-protocol-rs = { version = "0.7", features = ["gcp"] }
```

With [Azure Private Link](https://learn.microsoft.com/en-us/azure/private-link/private-link-service-overview):

```toml
# Azure Private Endpoint LinkID (PP2_TYPE_AZURE, 0xEE)
proxy-protocol-rs = { version = "0.7", features = ["azure"] }
```


## Usage

### With `axum::serve`

`ProxyProtocolListener` implements `axum::serve::Listener`, so it plugs directly
into `axum::serve`:

```rust
use axum::{Router, extract::ConnectInfo, routing::get};
use tokio::net::TcpListener;
use proxy_protocol_rs::{ProxyProtocolListener, ProxyConnectInfo};

let tcp = TcpListener::bind("0.0.0.0:8080").await?;
let pp = ProxyProtocolListener::new(tcp, Default::default());

let app = Router::new().route("/", get(handler));
axum::serve(pp, app.into_make_service_with_connect_info::<ProxyConnectInfo>())
    .with_graceful_shutdown(shutdown_signal())
    .await?;

async fn handler(ConnectInfo(info): ConnectInfo<ProxyConnectInfo>) -> String {
    // info.client_addr  — real client (from PP header, or TCP peer if absent)
    // info.peer_addr    — the load balancer's address
    // info.proxy_info   — full parsed ProxyInfo, if a PP header was present
    // info.is_proxied() — whether a PP header was present
    format!("client: {} (proxied: {})", info.client_addr, info.is_proxied())
}
```

Connection errors are logged via `tracing` and retried internally;
your handlers only see successfully accepted connections.

### Accept Connections Directly

```rust
use tokio::net::TcpListener;
use proxy_protocol_rs::ProxyProtocolListener;

let listener = TcpListener::bind("0.0.0.0:8080").await?;
let pp = ProxyProtocolListener::new(listener, Default::default());

loop {
    let stream = pp.accept().await?;

    tokio::spawn(async move {
        println!("client: {}", stream.client_addr());
        println!("peer (LB): {}", stream.peer_addr());

        if let Some(info) = stream.proxy_info() {
            println!("{} {} via {:?}", info.version, info.command, info.transport);
        }

        // ProxiedStream implements AsyncRead + AsyncWrite;
        // leftover bytes after the PP header are buffered transparently
    });
}
```

### Configuration

```rust
use std::time::Duration;
use proxy_protocol_rs::{ProxyProtocolConfig, VersionPreference};

let config = ProxyProtocolConfig {
    // default: 5s
    header_timeout: Duration::from_secs(10),
    // default: 4096
    max_header_size: 8192,
    // default: 1024
    max_pending_handshakes: 512,
    // default: Both
    version: VersionPreference::V2Only,
    ..Default::default()
};
```

### TLS Termination

The PP header is always cleartext *before* any TLS handshake.
`ProxiedStream` implements `AsyncRead + AsyncWrite`, so a TLS acceptor wraps it directly:

```rust
let stream = pp.accept().await?;
// capture metadata before TLS consumes the stream
let info = stream.connect_info();
let tls_stream = tls_acceptor.accept(stream).await?;
```

### Parse a Header from a Byte Buffer

```rust
use proxy_protocol_rs::parse;

let (info, consumed) = parse(buf)?;
let leftover = &buf[consumed..];

println!("{} {}", info.version, info.command);
if let Some(src) = info.source_inet() {
    println!("client: {src}");
}
if let Some(dst) = info.destination_inet() {
    println!("destination: {dst}");
}
```

### Trusted Proxies

Only accept PP headers from known load balancers; reject everyone else:

```rust
use proxy_protocol_rs::{ProxyProtocolConfig, ProxyProtocolListener, TrustedProxies};

let policy = TrustedProxies::with_cidrs(
    std::iter::empty(),
    ["10.0.0.0/8".parse()?, "172.16.0.0/12".parse()?],
);
let config = ProxyProtocolConfig {
    policy: Arc::new(policy),
    ..Default::default()
};
let pp = ProxyProtocolListener::new(listener, config);
```

### Mixed Mode (Proxied and Direct Connections)

Accept PP from trusted proxies, pass direct connections through as-is:

```rust
use proxy_protocol_rs::{MixedMode, TrustedProxies, ProxyProtocolConfig, ProxyProtocolListener};

let trusted = TrustedProxies::new(["10.0.0.1".parse()?]);
let config = ProxyProtocolConfig {
    policy: Arc::new(MixedMode::new(trusted)),
    ..Default::default()
};
let pp = ProxyProtocolListener::new(listener, config);
```

### Header Validation

Reject connections after parsing, e.g. to block spoofed source addresses:

```rust
use proxy_protocol_rs::{ProxyProtocolConfig, ProxyInfo};

let config = ProxyProtocolConfig {
    validator: Some(Arc::new(|info: &ProxyInfo, _peer: std::net::SocketAddr| {
        if info.source_ip().is_some_and(|ip| ip.is_loopback()) {
            return Err("loopback source rejected".into());
        }
        Ok(())
    })),
    ..Default::default()
};
```

### Build and Send a Header

```rust
use proxy_protocol_rs::HeaderBuilder;

let header = HeaderBuilder::v2_proxy(
    "203.0.113.42:54321".parse()?,
    "10.0.0.1:8080".parse()?,
)
.with_authority("example.com")
.with_unique_id(b"conn-abc-123")
.with_crc32c()
.build();

stream.write_all(&header).await?;

// or write directly without using an intermediate Vec:
// builder.write_to(&mut stream).await?;
```

```rust
// v2 LOCAL (health-check / proxy-to-self, no addresses)
let header = HeaderBuilder::v2_local().build();
```

```rust
// v1 text header
let header = HeaderBuilder::v1_proxy(
    "203.0.113.42:54321".parse()?,
    "10.0.0.1:8080".parse()?,
).build();
// => b"PROXY TCP4 203.0.113.42 10.0.0.1 54321 8080\r\n"
```

`build` panics if any single TLV value or the total v2 payload exceeds
65,535 bytes (the hard limit of the v2 format).

### TLV Extensions

V2 headers carry TLV (Type-Length-Value) extensions, parsed into typed fields
with the raw bytes always preserved in `tlvs.raw`:

```rust
let (info, _) = parse(buf)?;

if let Some(alpn) = &info.tlvs.alpn { /* e.g. b"h2" */ }
if let Some(authority) = &info.tlvs.authority { /* SNI hostname */ }
if let Some(id) = &info.tlvs.unique_id { /* up to 128 bytes */ }
if let Some(ns) = &info.tlvs.netns { /* network namespace path */ }
if let Some(crc) = info.tlvs.crc32c { /* already validated during parse */ }

if let Some(ssl) = &info.tlvs.ssl {
    println!("TLS: {:?}, verified: {}", ssl.version, ssl.verified);
    println!("cipher: {:?}, CN: {:?}", ssl.cipher, ssl.cn);
}

// all TLVs are also available as raw (type, value) pairs
for (tlv_type, value) in &info.tlvs.raw {
    println!("TLV 0x{tlv_type:02x}: {} bytes", value.len());
}
```

### Public Cloud Vendor TLVs

Each requires its feature flag:

```rust
// feature = "aws"
if let Some(Ok(aws)) = info.tlvs.aws() {
    println!("VPC endpoint: {:?}", aws.vpc_endpoint_id);
}

// feature = "azure"
if let Some(Ok(azure)) = info.tlvs.azure() {
    println!("link ID: {:?}", azure.private_endpoint_link_id);
}

// feature = "gcp"
if let Some(Ok(gcp)) = info.tlvs.gcp() {
    println!("PSC connection: {}", gcp.psc_connection_id);
}
```


## Copyright

(c) 2025-2026 Michael S. Klishin and Contributors.


## License

This crate, `proxy-protocol-rs`, is dual-licensed under
the Apache Software License 2.0 and the MIT license.

SPDX-License-Identifier: Apache-2.0 OR MIT
