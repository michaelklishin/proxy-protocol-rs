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

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    #[error("data does not begin with a Proxy Protocol signature")]
    NotProxyProtocol,

    #[error("incomplete header, need more data")]
    Incomplete,

    #[error("malformed Proxy Protocol header: {0}")]
    Invalid(InvalidReason),

    #[error("CRC32c mismatch: expected {expected:#010x}, got {actual:#010x}")]
    CrcMismatch { expected: u32, actual: u32 },
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidReason {
    #[error("unsupported protocol version: {0:#x}")]
    UnsupportedVersion(u8),

    #[error("unknown command nibble: {0:#x}")]
    UnknownCommand(u8),

    #[error("unknown address family: {0:#x}")]
    UnknownFamily(u8),

    #[error("unknown transport protocol: {0:#x}")]
    UnknownProtocol(u8),

    #[error("v1 header exceeds 107-byte limit")]
    V1TooLong,

    #[error("v1 header not valid UTF-8")]
    V1NotUtf8,

    #[error("v1 invalid format: expected 6 space-separated fields")]
    V1InvalidFormat,

    #[error("v1 unknown transport: {0}")]
    V1UnknownTransport(String),

    #[error("invalid IP address: {0}")]
    InvalidIp(String),

    #[error("invalid port: {0}")]
    InvalidPort(String),

    #[error("PROXY command requires a concrete address family and protocol")]
    UnspecWithProxy,

    #[error("payload length {len} exceeds buffer ({buf_len} available)")]
    PayloadOverflow { len: usize, buf_len: usize },

    #[error("malformed TLV at offset {offset}")]
    MalformedTlv { offset: usize },
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AcceptError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("connection from {0} rejected by policy")]
    Rejected(SocketAddr),

    #[error("Proxy Protocol header timeout from {0}")]
    HeaderTimeout(SocketAddr),

    #[error("empty connection from {0}")]
    EmptyConnection(SocketAddr),

    #[error("Proxy Protocol parse error from {1}: {0}")]
    Parse(ParseError, SocketAddr),

    #[error("header validation failed from {1}: {0}")]
    ValidationFailed(Box<dyn std::error::Error + Send + Sync>, SocketAddr),

    #[error("unwanted Proxy Protocol version from {0}")]
    VersionMismatch(SocketAddr),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlvParseError {
    #[error("malformed sub-TLV at offset {offset}")]
    MalformedSubTlv { offset: usize },

    #[error("invalid sub-TLV value: {reason}")]
    InvalidValue { reason: String },
}
