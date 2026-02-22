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

//! Tokio-native Proxy Protocol (v1 and v2) implementation.

pub mod error;
pub mod types;

pub mod parse;

pub mod vendor;

pub mod builder;

pub mod config;
pub mod policy;
pub mod validator;

pub mod listener;
pub mod stream;

#[cfg(feature = "axum")]
pub mod axum;

pub use error::{AcceptError, InvalidReason, ParseError, TlvParseError};
pub use parse::{V2_SIGNATURE, parse};
pub use types::{
    AddressFamily, Command, ProxyAddress, ProxyInfo, SslClientFlags, SslInfo, Tlvs, Transport,
    TransportProtocol, Version,
};

pub use builder::HeaderBuilder;
pub use config::{ProxyProtocolConfig, VersionPreference};
pub use listener::ProxyProtocolListener;
pub use policy::{AcceptAll, ConnPolicy, MixedMode, OptionalProxy, PolicyDecision, TrustedProxies};
pub use stream::{ProxiedStream, ProxyConnectInfo};
pub use validator::HeaderValidator;

#[cfg(feature = "aws")]
pub use vendor::AwsTlvs;
#[cfg(feature = "azure")]
pub use vendor::AzureTlvs;
#[cfg(feature = "gcp")]
pub use vendor::GcpTlvs;
