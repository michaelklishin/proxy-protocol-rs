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

use std::net::{IpAddr, SocketAddr};

use proxy_protocol_rs::{
    AcceptAll, ConnPolicy, IpNet, MixedMode, OptionalProxy, PolicyDecision, TrustedProxies,
};

#[test]
fn accept_all_returns_require() {
    let policy = AcceptAll;
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    assert_eq!(policy.evaluate(addr), PolicyDecision::Require);
}

#[test]
fn accept_all_any_address() {
    let policy = AcceptAll;
    let addrs: Vec<SocketAddr> = vec![
        "127.0.0.1:80".parse().unwrap(),
        "10.0.0.1:443".parse().unwrap(),
        "[::1]:8080".parse().unwrap(),
    ];
    for addr in addrs {
        assert_eq!(policy.evaluate(addr), PolicyDecision::Require);
    }
}

#[test]
fn trusted_proxies_exact_match() {
    let policy = TrustedProxies::new(["10.0.1.100".parse().unwrap()]);
    assert_eq!(
        policy.evaluate("10.0.1.100:1234".parse().unwrap()),
        PolicyDecision::Require
    );
}

#[test]
fn trusted_proxies_rejection() {
    let policy = TrustedProxies::new(["10.0.1.100".parse().unwrap()]);
    assert_eq!(
        policy.evaluate("10.0.1.101:1234".parse().unwrap()),
        PolicyDecision::Reject
    );
}

#[test]
fn trusted_proxies_cidr_match() {
    let policy = TrustedProxies::with_cidrs(std::iter::empty(), ["10.0.0.0/8".parse().unwrap()]);
    assert_eq!(
        policy.evaluate("10.255.255.255:1234".parse().unwrap()),
        PolicyDecision::Require
    );
    assert_eq!(
        policy.evaluate("192.168.1.1:1234".parse().unwrap()),
        PolicyDecision::Reject
    );
}

#[test]
fn mixed_mode_trusted_require() {
    let trusted = TrustedProxies::new(["10.0.1.100".parse().unwrap()]);
    let policy = MixedMode::new(trusted);
    assert_eq!(
        policy.evaluate("10.0.1.100:1234".parse().unwrap()),
        PolicyDecision::Require
    );
}

#[test]
fn mixed_mode_untrusted_ignore() {
    let trusted = TrustedProxies::new(["10.0.1.100".parse().unwrap()]);
    let policy = MixedMode::new(trusted);
    assert_eq!(
        policy.evaluate("192.168.1.1:1234".parse().unwrap()),
        PolicyDecision::Ignore
    );
}

#[test]
fn optional_proxy_returns_use() {
    let policy = OptionalProxy;
    let addrs: Vec<SocketAddr> = vec![
        "127.0.0.1:80".parse().unwrap(),
        "10.0.1.100:443".parse().unwrap(),
        "[::1]:8080".parse().unwrap(),
    ];
    for addr in addrs {
        assert_eq!(policy.evaluate(addr), PolicyDecision::Use);
    }
}

#[test]
fn closure_based_policy() {
    let policy = |addr: SocketAddr| -> PolicyDecision {
        if addr.port() == 443 {
            PolicyDecision::Require
        } else {
            PolicyDecision::Reject
        }
    };
    assert_eq!(
        policy.evaluate("1.2.3.4:443".parse().unwrap()),
        PolicyDecision::Require
    );
    assert_eq!(
        policy.evaluate("1.2.3.4:80".parse().unwrap()),
        PolicyDecision::Reject
    );
}

#[test]
fn from_ipnets_splits_host_prefix_to_exact() {
    let nets: Vec<IpNet> = vec![
        "10.0.0.1/32".parse().unwrap(),
        "192.168.1.0/24".parse().unwrap(),
    ];
    let tp = TrustedProxies::from_ipnets(nets);

    assert!(tp.contains("10.0.0.1".parse().unwrap()));
    assert!(tp.contains("192.168.1.42".parse().unwrap()));
    assert!(!tp.contains("10.0.0.2".parse().unwrap()));
    assert!(!tp.contains("192.168.2.1".parse().unwrap()));
}

#[test]
fn from_ipnets_ipv6_host_prefix() {
    let nets: Vec<IpNet> = vec!["::1/128".parse().unwrap(), "fd00::/64".parse().unwrap()];
    let tp = TrustedProxies::from_ipnets(nets);

    assert!(tp.contains("::1".parse().unwrap()));
    assert!(tp.contains("fd00::abcd".parse().unwrap()));
    assert!(!tp.contains("::2".parse().unwrap()));
    assert!(!tp.contains("fd01::1".parse().unwrap()));
}

#[test]
fn from_ipnets_empty() {
    let tp = TrustedProxies::from_ipnets(std::iter::empty());
    assert!(!tp.contains("127.0.0.1".parse().unwrap()));
}

#[test]
fn from_ipnets_all_exact() {
    let nets: Vec<IpNet> = vec![
        "10.0.0.1/32".parse().unwrap(),
        "10.0.0.2/32".parse().unwrap(),
    ];
    let tp = TrustedProxies::from_ipnets(nets);

    assert!(tp.contains("10.0.0.1".parse().unwrap()));
    assert!(tp.contains("10.0.0.2".parse().unwrap()));
    assert!(!tp.contains("10.0.0.3".parse().unwrap()));
}

#[test]
fn from_ipnets_mixed_v4_and_v6() {
    let nets: Vec<IpNet> = vec![
        "10.0.0.1/32".parse().unwrap(),
        "fd00::/64".parse().unwrap(),
        "192.168.0.0/16".parse().unwrap(),
        "::1/128".parse().unwrap(),
    ];
    let tp = TrustedProxies::from_ipnets(nets);

    assert!(tp.contains("10.0.0.1".parse().unwrap()));
    assert!(tp.contains("::1".parse().unwrap()));
    assert!(tp.contains("192.168.1.1".parse().unwrap()));
    assert!(tp.contains("fd00::99".parse().unwrap()));
    assert!(!tp.contains("10.0.0.2".parse().unwrap()));
    assert!(!tp.contains("fe80::1".parse().unwrap()));
}

#[test]
fn from_ipnets_all_cidrs() {
    let nets: Vec<IpNet> = vec![
        "10.0.0.0/8".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
    ];
    let tp = TrustedProxies::from_ipnets(nets);

    assert!(tp.contains("10.255.0.1".parse().unwrap()));
    assert!(tp.contains("172.31.255.255".parse().unwrap()));
    assert!(!tp.contains("192.168.1.1".parse().unwrap()));
}

#[test]
fn from_ipnets_works_with_evaluate() {
    let nets: Vec<IpNet> = vec![
        "10.0.0.1/32".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
    ];
    let policy = TrustedProxies::from_ipnets(nets);

    assert_eq!(
        policy.evaluate("10.0.0.1:8080".parse().unwrap()),
        PolicyDecision::Require
    );
    assert_eq!(
        policy.evaluate("172.20.1.1:443".parse().unwrap()),
        PolicyDecision::Require
    );
    assert_eq!(
        policy.evaluate("192.168.1.1:80".parse().unwrap()),
        PolicyDecision::Reject
    );
}

#[test]
fn from_ipnets_mixed_mode() {
    let nets: Vec<IpNet> = vec![
        "10.0.0.1/32".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
    ];
    let policy = MixedMode::new(TrustedProxies::from_ipnets(nets));

    assert_eq!(
        policy.evaluate("10.0.0.1:80".parse().unwrap()),
        PolicyDecision::Require
    );
    assert_eq!(
        policy.evaluate("172.20.1.1:443".parse().unwrap()),
        PolicyDecision::Require
    );
    assert_eq!(
        policy.evaluate("192.168.1.1:80".parse().unwrap()),
        PolicyDecision::Ignore
    );
}

#[test]
fn contains_exact_match() {
    let tp = TrustedProxies::new(["10.0.0.1".parse().unwrap()]);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(tp.contains(ip));
}

#[test]
fn contains_cidr_match() {
    let tp = TrustedProxies::with_cidrs(std::iter::empty(), ["10.0.0.0/8".parse().unwrap()]);
    let ip: IpAddr = "10.1.2.3".parse().unwrap();
    assert!(tp.contains(ip));
}

#[test]
fn contains_no_match() {
    let tp = TrustedProxies::new(["10.0.0.1".parse().unwrap()]);
    let ip: IpAddr = "10.0.0.2".parse().unwrap();
    assert!(!tp.contains(ip));
}
