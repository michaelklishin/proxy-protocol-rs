# proxy-protocol-rs Change Log

## 0.8.0 (Feb 22, 2026)

### Enhancements

 * `ProxyProtocolConfig::builder` provides a fluent builder with construction-time validation
   (to enforce non-zero timeouts, header size and pending handshakes limits)
 * `VersionPreference::V2Only` documentation updates
 * `TrustedProxies::contains` is now a public method (it used to be crate-scoped), useful for logging and access control checks
 * `TrustedProxies::from_ipnets` now can build a `TrustedProxies` from a mixed set of `IpNet`s
    

## 0.7.0 (Feb 22, 2026)

Initial public release.
