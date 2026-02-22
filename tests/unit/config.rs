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
use std::time::Duration;

use proxy_protocol_rs::{
    ConfigError, PolicyDecision, ProxyInfo, ProxyProtocolConfig, TrustedProxies, VersionPreference,
};

#[test]
fn builder_defaults_match_struct_defaults() {
    let from_struct = ProxyProtocolConfig::default();
    let from_builder = ProxyProtocolConfig::builder().build().unwrap();

    assert_eq!(from_struct.header_timeout, from_builder.header_timeout);
    assert_eq!(from_struct.max_header_size, from_builder.max_header_size);
    assert_eq!(
        from_struct.max_pending_handshakes,
        from_builder.max_pending_handshakes
    );
    assert_eq!(from_struct.version, from_builder.version);
    assert!(from_builder.validator.is_none());
}

#[test]
fn builder_sets_all_fields() {
    let trusted = TrustedProxies::new(["10.0.0.1".parse().unwrap()]);
    let cfg = ProxyProtocolConfig::builder()
        .header_timeout(Duration::from_secs(10))
        .max_header_size(8192)
        .max_pending_handshakes(512)
        .policy(trusted)
        .version(VersionPreference::V2Only)
        .build()
        .unwrap();

    assert_eq!(cfg.header_timeout, Duration::from_secs(10));
    assert_eq!(cfg.max_header_size, 8192);
    assert_eq!(cfg.max_pending_handshakes, 512);
    assert_eq!(cfg.version, VersionPreference::V2Only);
}

#[test]
fn builder_rejects_zero_timeout() {
    let err = ProxyProtocolConfig::builder()
        .header_timeout(Duration::ZERO)
        .build();
    assert!(err.is_err());
}

#[test]
fn builder_rejects_zero_header_size() {
    let err = ProxyProtocolConfig::builder().max_header_size(0).build();
    assert!(err.is_err());
}

#[test]
fn builder_rejects_zero_pending_handshakes() {
    let err = ProxyProtocolConfig::builder()
        .max_pending_handshakes(0)
        .build();
    assert!(err.is_err());
}

#[test]
fn builder_accepts_validator_closure() {
    let cfg = ProxyProtocolConfig::builder()
        .validator(|_header: &ProxyInfo, _peer: SocketAddr| Ok(()))
        .build()
        .unwrap();
    assert!(cfg.validator.is_some());
}

#[test]
fn builder_accepts_policy_closure() {
    let cfg = ProxyProtocolConfig::builder()
        .policy(|_addr: SocketAddr| PolicyDecision::Require)
        .build()
        .unwrap();

    assert_eq!(cfg.header_timeout, Duration::from_secs(5));
}

#[test]
fn config_error_displays_message() {
    match ProxyProtocolConfig::builder()
        .header_timeout(Duration::ZERO)
        .build()
    {
        Err(err) => assert_eq!(err.to_string(), "header_timeout must be greater than zero"),
        Ok(_) => panic!("expected ConfigError"),
    }
}

#[test]
fn config_error_eq() {
    match ProxyProtocolConfig::builder()
        .header_timeout(Duration::ZERO)
        .build()
    {
        Err(err) => assert_eq!(err, ConfigError("header_timeout must be greater than zero")),
        Ok(_) => panic!("expected ConfigError"),
    }
}
