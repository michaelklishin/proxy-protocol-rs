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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VersionPreference {
    Both,
    V1Only,
    V2Only,
}
