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

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use proxy_protocol_rs::{
    AcceptError, HeaderBuilder, ProxyInfo, ProxyProtocolConfig, ProxyProtocolListener,
    TrustedProxies, VersionPreference,
};

#[tokio::test]
async fn accept_extracts_real_client_ip_v2() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(listener, Default::default());

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let header = HeaderBuilder::v2_proxy(
            "203.0.113.42:54321".parse().unwrap(),
            "10.0.0.1:8080".parse().unwrap(),
        )
        .build();
        client.write_all(&header).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
    });

    let stream = pp.accept().await.unwrap();
    assert_eq!(stream.client_addr(), "203.0.113.42:54321".parse().unwrap(),);
}

#[tokio::test]
async fn accept_extracts_real_client_ip_v1() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(listener, Default::default());

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"PROXY TCP4 203.0.113.42 10.0.0.1 54321 8080\r\n")
            .await
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
    });

    let stream = pp.accept().await.unwrap();
    assert_eq!(stream.client_addr(), "203.0.113.42:54321".parse().unwrap(),);
}

#[tokio::test]
async fn leftover_bytes_readable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(listener, Default::default());

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let header = HeaderBuilder::v2_proxy(
            "203.0.113.42:54321".parse().unwrap(),
            "10.0.0.1:8080".parse().unwrap(),
        )
        .build();
        // Send header + HTTP in one write (likely one TCP segment)
        let mut combined = header;
        combined.extend_from_slice(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n");
        client.write_all(&combined).await.unwrap();
    });

    let mut stream = pp.accept().await.unwrap();
    let mut buf = [0u8; 3];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"GET");
}

#[tokio::test]
async fn header_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            header_timeout: Duration::from_millis(100),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        // Send just the start of a v2 signature, then wait
        client
            .write_all(&[13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let result = pp.accept().await;
    assert!(matches!(result, Err(AcceptError::HeaderTimeout(_))));
}

#[tokio::test]
async fn validator_rejects_localhost_spoofing() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            validator: Some(Arc::new(|info: &ProxyInfo, _peer: std::net::SocketAddr| {
                if let Some(ip) = info.source_ip()
                    && ip.is_loopback()
                {
                    return Err("localhost spoofing rejected".into());
                }
                Ok(())
            })),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let header = HeaderBuilder::v2_proxy(
            "127.0.0.1:12345".parse().unwrap(),
            "10.0.0.1:8080".parse().unwrap(),
        )
        .build();
        client.write_all(&header).await.unwrap();
    });

    let result = pp.accept().await;
    assert!(matches!(result, Err(AcceptError::ValidationFailed(_, _))));
}

#[tokio::test]
async fn reject_untrusted_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let policy = TrustedProxies::new(["10.0.1.100".parse().unwrap()]);
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            policy: Arc::new(policy),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let _ = TcpStream::connect(addr).await;
    });

    let result = pp.accept().await;
    assert!(matches!(result, Err(AcceptError::Rejected(_))));
}

#[tokio::test]
async fn cidr_policy_accepts_subnet() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let policy = TrustedProxies::with_cidrs(std::iter::empty(), ["127.0.0.0/8".parse().unwrap()]);
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            policy: Arc::new(policy),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let header = HeaderBuilder::v2_proxy(
            "203.0.113.42:54321".parse().unwrap(),
            "10.0.0.1:8080".parse().unwrap(),
        )
        .build();
        client.write_all(&header).await.unwrap();
    });

    let stream = pp.accept().await.unwrap();
    assert_eq!(stream.client_addr().ip().to_string(), "203.0.113.42");
}

#[tokio::test]
async fn use_policy_passes_non_pp() {
    use proxy_protocol_rs::PolicyDecision;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            policy: Arc::new(|_: std::net::SocketAddr| PolicyDecision::Use),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        // Send plain HTTP, no PP header
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
    });

    let mut stream = pp.accept().await.unwrap();
    assert!(stream.proxy_info().is_none());
    // With no PP header, client_addr() falls back to the TCP peer
    assert!(stream.client_addr().ip().is_loopback());
    assert_eq!(stream.client_addr(), stream.peer_addr());
    // The HTTP bytes should be readable as leftover
    let mut buf = [0u8; 3];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"GET");
}

#[tokio::test]
async fn empty_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(listener, Default::default());

    tokio::spawn(async move {
        let client = TcpStream::connect(addr).await.unwrap();
        // close immediately
        drop(client);
    });

    let result = pp.accept().await;
    assert!(matches!(result, Err(AcceptError::EmptyConnection(_))));
}

#[tokio::test]
async fn version_preference_v2_only_rejects_v1() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            version: VersionPreference::V2Only,
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\n")
            .await
            .unwrap();
    });

    let result = pp.accept().await;
    assert!(matches!(result, Err(AcceptError::VersionMismatch(_))));
}

#[tokio::test]
async fn version_preference_v1_only_rejects_v2() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            version: VersionPreference::V1Only,
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let header = HeaderBuilder::v2_proxy(
            "203.0.113.42:54321".parse().unwrap(),
            "10.0.0.1:8080".parse().unwrap(),
        )
        .build();
        client.write_all(&header).await.unwrap();
    });

    let result = pp.accept().await;
    assert!(matches!(result, Err(AcceptError::VersionMismatch(_))));
}

#[tokio::test]
async fn version_preference_v2_only_accepts_v2() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            version: VersionPreference::V2Only,
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let header = HeaderBuilder::v2_proxy(
            "203.0.113.42:54321".parse().unwrap(),
            "10.0.0.1:8080".parse().unwrap(),
        )
        .build();
        client.write_all(&header).await.unwrap();
    });

    let stream = pp.accept().await.unwrap();
    assert_eq!(stream.client_addr(), "203.0.113.42:54321".parse().unwrap());
}

#[tokio::test]
async fn proxied_stream_write_and_read() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(listener, Default::default());

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let header = HeaderBuilder::v2_proxy(
            "203.0.113.42:54321".parse().unwrap(),
            "10.0.0.1:8080".parse().unwrap(),
        )
        .build();
        client.write_all(&header).await.unwrap();
        // Read the server's response
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HELLO");
    });

    let mut stream = pp.accept().await.unwrap();
    // Write through ProxiedStream
    stream.write_all(b"HELLO").await.unwrap();
    stream.flush().await.unwrap();
}

#[tokio::test]
async fn header_timeout_partial_v1() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            header_timeout: Duration::from_millis(100),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        // Send partial v1 header (no \r\n terminator), then stall
        client
            .write_all(b"PROXY TCP4 1.2.3.4 5.6.7.8")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let result = pp.accept().await;
    assert!(matches!(result, Err(AcceptError::HeaderTimeout(_))));
}

#[tokio::test]
async fn header_timeout_zero_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            header_timeout: Duration::from_millis(100),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let _client = TcpStream::connect(addr).await.unwrap();
        // Hold connection open but send nothing
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let result = pp.accept().await;
    assert!(matches!(result, Err(AcceptError::HeaderTimeout(_))));
}

#[tokio::test]
async fn header_timeout_byte_at_a_time() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            header_timeout: Duration::from_millis(200),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        // Drip-feed the v2 signature one byte at a time, slower than the timeout
        let sig = [13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10];
        for &b in &sig {
            client.write_all(&[b]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let result = pp.accept().await;
    assert!(matches!(result, Err(AcceptError::HeaderTimeout(_))));
}

#[tokio::test]
async fn slow_loris_v1_one_char_per_segment() {
    // Simulate a slow loris attack: send a valid v1 header one character
    // at a time across separate TCP segments with delays between them.
    // The listener must eventually time out rather than waiting forever.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            header_timeout: Duration::from_millis(300),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        // Drip-feed a v1 header char by char, slow enough to stall but
        // each byte arrives before the per-read timeout
        for &b in b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\n" {
            if client.write_all(&[b]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    // Total drip time: ~38 chars * 20ms = ~760ms > 300ms timeout
    let result = pp.accept().await;
    assert!(matches!(result, Err(AcceptError::HeaderTimeout(_))));
}

#[tokio::test]
async fn slow_loris_v2_partial_then_stall() {
    // Send enough of the v2 header to be recognized, then stall forever.
    // The listener must time out.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            header_timeout: Duration::from_millis(150),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        // Send full v2 signature + ver_cmd + fam_proto but NOT the length field
        let partial = [13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 0x21, 0x11];
        client.write_all(&partial).await.unwrap();
        // Stall indefinitely
        tokio::time::sleep(Duration::from_secs(10)).await;
    });

    let result = pp.accept().await;
    assert!(matches!(result, Err(AcceptError::HeaderTimeout(_))));
}

#[tokio::test]
async fn slow_loris_completes_before_timeout() {
    // Drip-feed a valid v1 header, but fast enough to complete before timeout.
    // Verifies slow-but-legitimate clients still succeed.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(
        listener,
        ProxyProtocolConfig {
            header_timeout: Duration::from_secs(2),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let header = b"PROXY TCP4 192.168.1.1 10.0.0.1 12345 80\r\n";
        // Send in 4-byte chunks with small delays
        for chunk in header.chunks(4) {
            client.write_all(chunk).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let stream = pp.accept().await.unwrap();
    assert_eq!(stream.client_addr(), "192.168.1.1:12345".parse().unwrap(),);
}

#[tokio::test]
async fn client_disconnect_mid_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(listener, Default::default());

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        // Send partial v2 header then disconnect
        client
            .write_all(&[13, 10, 13, 10, 0, 13, 10, 81])
            .await
            .unwrap();
        drop(client);
    });

    let result = pp.accept().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn garbage_data_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(listener, Default::default());

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"NOT A PROXY PROTOCOL HEADER\r\n")
            .await
            .unwrap();
    });

    let result = pp.accept().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn multiple_sequential_accepts() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(listener, Default::default());

    tokio::spawn(async move {
        for port in [54321u16, 54322, 54323] {
            let mut client = TcpStream::connect(addr).await.unwrap();
            let header = HeaderBuilder::v2_proxy(
                format!("203.0.113.42:{port}").parse().unwrap(),
                "10.0.0.1:8080".parse().unwrap(),
            )
            .build();
            client.write_all(&header).await.unwrap();
            client.write_all(b"data").await.unwrap();
        }
    });

    for port in [54321u16, 54322, 54323] {
        let stream = pp.accept().await.unwrap();
        let expected: std::net::SocketAddr = format!("203.0.113.42:{port}").parse().unwrap();
        assert_eq!(stream.client_addr(), expected);
    }
}

#[tokio::test]
async fn v2_local_accepted_and_readable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pp = ProxyProtocolListener::new(listener, Default::default());

    tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let header = HeaderBuilder::v2_local().build();
        let mut combined = header;
        combined.extend_from_slice(b"HEALTH");
        client.write_all(&combined).await.unwrap();
    });

    let mut stream = pp.accept().await.unwrap();
    let info = stream.proxy_info().unwrap();
    assert_eq!(info.command, proxy_protocol_rs::Command::Local);
    // client_addr falls back to peer for LOCAL
    assert!(stream.client_addr().ip().is_loopback());
    let mut buf = [0u8; 6];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"HEALTH");
}

// --- ProxyConnectInfo tests ---

mod connect_info {
    use std::net::{IpAddr, SocketAddr};

    use proxy_protocol_rs::{Command, ProxyConnectInfo, ProxyInfo, Tlvs, Version};

    fn dummy_proxy_info() -> ProxyInfo {
        ProxyInfo {
            version: Version::V2,
            command: Command::Local,
            transport: None,
            source: None,
            destination: None,
            tlvs: Tlvs::default(),
        }
    }

    #[test]
    fn client_ip_strips_port() {
        let info = ProxyConnectInfo {
            client_addr: "203.0.113.42:54321".parse().unwrap(),
            peer_addr: "10.0.0.1:9999".parse().unwrap(),
            proxy_info: None,
        };
        assert_eq!(info.client_ip(), "203.0.113.42".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn is_proxied_with_proxy_info() {
        let info = ProxyConnectInfo::from((
            dummy_proxy_info(),
            "10.0.0.1:9999".parse::<SocketAddr>().unwrap(),
        ));
        assert!(info.is_proxied());
    }

    #[test]
    fn is_proxied_without_proxy_info() {
        let info = ProxyConnectInfo::from("127.0.0.1:8080".parse::<SocketAddr>().unwrap());
        assert!(!info.is_proxied());
    }

    #[test]
    fn display_proxied() {
        let info = ProxyConnectInfo {
            client_addr: "203.0.113.42:54321".parse().unwrap(),
            peer_addr: "10.0.0.1:9999".parse().unwrap(),
            proxy_info: Some(dummy_proxy_info()),
        };
        assert_eq!(info.to_string(), "203.0.113.42:54321 via 10.0.0.1:9999");
    }

    #[test]
    fn display_direct() {
        let info = ProxyConnectInfo::from("192.168.1.1:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(info.to_string(), "192.168.1.1:8080 (direct)");
    }

    #[test]
    fn from_socket_addr() {
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let info = ProxyConnectInfo::from(addr);
        assert_eq!(info.client_addr, addr);
        assert_eq!(info.peer_addr, addr);
        assert!(!info.is_proxied());
    }
}

// --- axum::serve::Listener integration tests ---

#[cfg(feature = "axum")]
mod axum_listener {
    use super::*;
    use axum::serve::Listener;

    #[tokio::test]
    async fn accept_returns_proxy_connect_info() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let mut pp = ProxyProtocolListener::new(tcp, Default::default());

        tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            let header = HeaderBuilder::v2_proxy(
                "203.0.113.42:54321".parse().unwrap(),
                "10.0.0.1:8080".parse().unwrap(),
            )
            .build();
            client.write_all(&header).await.unwrap();
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                .await
                .unwrap();
        });

        let (_io, info) = Listener::accept(&mut pp).await;
        assert_eq!(info.client_addr, "203.0.113.42:54321".parse().unwrap(),);
        assert!(info.peer_addr.ip().is_loopback());
        assert!(info.proxy_info.is_some());
    }

    #[tokio::test]
    async fn retries_on_rejected_connection() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        // Policy rejects 127.0.0.1 — all local connections will be rejected
        let policy = TrustedProxies::new(["10.0.1.100".parse().unwrap()]);
        let mut pp = ProxyProtocolListener::new(
            tcp,
            ProxyProtocolConfig {
                policy: Arc::new(policy),
                ..Default::default()
            },
        );

        // Spawn a client that connects (will be rejected), then a second
        // connection after a short delay won't help either.
        tokio::spawn(async move {
            let _ = TcpStream::connect(addr).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = TcpStream::connect(addr).await;
        });

        // The Listener::accept() should loop internally on rejections.
        // Since no valid connection arrives, it should just keep looping.
        // We verify it doesn't panic or return an error by racing with a timeout.
        let result =
            tokio::time::timeout(Duration::from_millis(200), Listener::accept(&mut pp)).await;
        assert!(
            result.is_err(),
            "should have timed out (no valid connections)"
        );
    }

    #[tokio::test]
    async fn local_addr_returns_bound_address() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let expected = tcp.local_addr().unwrap();
        let pp = ProxyProtocolListener::new(tcp, Default::default());

        let info = Listener::local_addr(&pp).unwrap();
        assert_eq!(info.client_addr, expected);
        assert_eq!(info.peer_addr, expected);
        assert!(info.proxy_info.is_none());
    }
}
