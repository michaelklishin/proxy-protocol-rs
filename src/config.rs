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

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::policy::{AcceptAll, ConnPolicy};
use crate::validator::HeaderValidator;

/// Configuration for the Proxy Protocol listener
pub struct ProxyProtocolConfig {
    /// Maximum time to wait for the complete PP header after accept;
    /// default: 5 seconds
    pub header_timeout: Duration,

    /// Maximum buffer size for reading the PP header;
    /// default: 4096 bytes
    pub max_header_size: usize,

    /// Maximum number of connections simultaneously reading PP headers;
    /// default: 1024
    pub max_pending_handshakes: usize,

    /// Pre-read connection policy;
    /// default: `AcceptAll`
    pub policy: Arc<dyn ConnPolicy>,

    /// Post-parse header validator;
    /// default: `None`
    pub validator: Option<Arc<dyn HeaderValidator>>,

    /// Which protocol versions to accept;
    /// default: `Both`
    pub version: VersionPreference,
}

impl Default for ProxyProtocolConfig {
    fn default() -> Self {
        Self {
            header_timeout: Duration::from_secs(5),
            max_header_size: 4096,
            max_pending_handshakes: 1024,
            policy: Arc::new(AcceptAll),
            validator: None,
            version: VersionPreference::Both,
        }
    }
}

impl ProxyProtocolConfig {
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

pub struct ConfigBuilder {
    header_timeout: Duration,
    max_header_size: usize,
    max_pending_handshakes: usize,
    policy: Arc<dyn ConnPolicy>,
    validator: Option<Arc<dyn HeaderValidator>>,
    version: VersionPreference,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self {
            header_timeout: Duration::from_secs(5),
            max_header_size: 4096,
            max_pending_handshakes: 1024,
            policy: Arc::new(AcceptAll),
            validator: None,
            version: VersionPreference::Both,
        }
    }
}

impl ConfigBuilder {
    pub fn header_timeout(mut self, timeout: Duration) -> Self {
        self.header_timeout = timeout;
        self
    }

    pub fn max_header_size(mut self, size: usize) -> Self {
        self.max_header_size = size;
        self
    }

    pub fn max_pending_handshakes(mut self, limit: usize) -> Self {
        self.max_pending_handshakes = limit;
        self
    }

    pub fn policy(mut self, policy: impl ConnPolicy) -> Self {
        self.policy = Arc::new(policy);
        self
    }

    pub fn validator(mut self, validator: impl HeaderValidator) -> Self {
        self.validator = Some(Arc::new(validator));
        self
    }

    pub fn version(mut self, version: VersionPreference) -> Self {
        self.version = version;
        self
    }

    pub fn build(self) -> Result<ProxyProtocolConfig, ConfigError> {
        if self.header_timeout.is_zero() {
            return Err(ConfigError("header_timeout must be greater than zero"));
        }
        if self.max_header_size == 0 {
            return Err(ConfigError("max_header_size must be greater than zero"));
        }
        if self.max_pending_handshakes == 0 {
            return Err(ConfigError(
                "max_pending_handshakes must be greater than zero",
            ));
        }
        Ok(ProxyProtocolConfig {
            header_timeout: self.header_timeout,
            max_header_size: self.max_header_size,
            max_pending_handshakes: self.max_pending_handshakes,
            policy: self.policy,
            validator: self.validator,
            version: self.version,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub &'static str);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VersionPreference {
    Both,
    V1Only,
    /// Accept only v2 headers. V2 supports CRC32c integrity checks and
    /// binary TLVs, making this the stricter option for hardened deployments.
    V2Only,
}
