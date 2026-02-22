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

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnet::{Ipv4Net, Ipv6Net};
use proptest::prelude::*;
use proxy_protocol_rs::{ConnPolicy, IpNet, TrustedProxies};

fn arb_ipv4_net() -> impl Strategy<Value = IpNet> {
    (any::<Ipv4Addr>(), 0u8..=32)
        .prop_map(|(addr, prefix)| IpNet::V4(Ipv4Net::new(addr, prefix).unwrap().trunc()))
}

fn arb_ipv6_net() -> impl Strategy<Value = IpNet> {
    (any::<Ipv6Addr>(), 0u8..=128)
        .prop_map(|(addr, prefix)| IpNet::V6(Ipv6Net::new(addr, prefix).unwrap().trunc()))
}

proptest! {
    /// Every host-length prefix (x.x.x.x/32) must be reachable via `contains`.
    #[test]
    fn prop_from_ipnets_host_prefix_is_contained(addr in any::<Ipv4Addr>()) {
        let net: IpNet = format!("{addr}/32").parse().unwrap();
        let tp = TrustedProxies::from_ipnets([net]);
        prop_assert!(tp.contains(addr.into()));
    }

    /// Every IPv6 /128 host prefix must be reachable via `contains`.
    #[test]
    fn prop_from_ipnets_ipv6_host_prefix_is_contained(addr in any::<Ipv6Addr>()) {
        let net: IpNet = format!("{addr}/128").parse().unwrap();
        let tp = TrustedProxies::from_ipnets([net]);
        prop_assert!(tp.contains(addr.into()));
    }

    /// `from_ipnets` must produce the same membership as `with_cidrs` for any mix of prefixes.
    #[test]
    fn prop_from_ipnets_agrees_with_with_cidrs(
        nets in prop::collection::vec(arb_ipv4_net(), 1..8),
        probe in any::<Ipv4Addr>(),
    ) {
        let from_ipnets = TrustedProxies::from_ipnets(nets.clone());
        let from_with_cidrs = TrustedProxies::with_cidrs(std::iter::empty(), nets);
        prop_assert_eq!(
            from_ipnets.contains(probe.into()),
            from_with_cidrs.contains(probe.into())
        );
    }

    /// `from_ipnets` produces the same `evaluate` result as `with_cidrs` for any peer.
    #[test]
    fn prop_from_ipnets_evaluate_matches(
        nets in prop::collection::vec(arb_ipv6_net(), 1..5),
        probe in any::<Ipv6Addr>(),
        port in any::<u16>(),
    ) {
        let from_ipnets = TrustedProxies::from_ipnets(nets.clone());
        let from_with_cidrs = TrustedProxies::with_cidrs(std::iter::empty(), nets);

        let addr = SocketAddr::new(probe.into(), port);
        prop_assert_eq!(
            from_ipnets.evaluate(addr),
            from_with_cidrs.evaluate(addr)
        );
    }
}
