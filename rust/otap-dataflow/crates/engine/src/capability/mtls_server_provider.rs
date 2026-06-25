// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//! `MtlsServerProvider` capability -- supplies a [`rustls::ServerConfig`] for
//! inbound mutual-TLS connections.
//!
//! Consumed by OTLP **receivers** (HTTP + gRPC). The provider owns TLS
//! authentication (server certificate resolution + client-certificate
//! verification); the receiver keeps owning the rest of its server
//! construction. The receiver plugs the returned config into its tonic /
//! HTTP server TLS path (or a `tokio-rustls` acceptor).
//!
//! Some mTLS backends are symmetric: a single provider mints both a client
//! and a server config from the same underlying credentials, so an extension
//! can expose both [`super::mtls_client_provider::MtlsClientProvider`] and
//! this capability.
//!
//! The `#[capability]` proc macro expands the trait below into `local::` /
//! `shared::` trait variants, a `SharedAsLocal` adapter, a zero-sized
//! registration handle, factory bridges, and a `KNOWN_CAPABILITIES` entry.
//! The generated `local`/`shared` modules begin with `use super::*;`, so the
//! request/error types referenced here are in scope for the generated traits.

use otap_df_engine_macros::capability;

pub use super::mtls_client_provider::MtlsError;

/// Generic, transport-neutral context handed to
/// [`MtlsServerProvider::server_tls_config`].
///
/// Carries only knobs already known to receivers (no implementation-specific
/// fields).
#[derive(Debug, Clone, Default)]
pub struct ServerTlsRequest {
    /// The local address the receiver is binding (e.g. `0.0.0.0:4317`).
    /// Provided for diagnostics; implementations may ignore it.
    pub bind_address: String,
}

impl ServerTlsRequest {
    /// Creates a request for the given bind address.
    #[must_use]
    pub fn new(bind_address: impl Into<String>) -> Self {
        Self {
            bind_address: bind_address.into(),
        }
    }
}

/// Supplies a [`rustls::ServerConfig`] for inbound mutual TLS.
///
/// Implementations construct a fresh config per call so each consuming node
/// gets an independent server configuration.
#[capability(
    name = "mtls_server_provider",
    description = "Supplies a rustls ServerConfig for inbound mTLS"
)]
pub trait MtlsServerProvider {
    /// Builds a [`rustls::ServerConfig`] applying this provider's mTLS
    /// authentication (server certificate + client-certificate verification).
    fn server_tls_config(
        &self,
        request: ServerTlsRequest,
    ) -> Result<rustls::ServerConfig, MtlsError>;
}
