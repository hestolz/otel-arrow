// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//! `MtlsClientProvider` capability -- supplies a [`rustls::ClientConfig`] for
//! outbound mutual-TLS connections.
//!
//! Consumed by OTLP **exporters** (HTTP + gRPC). The provider owns TLS
//! authentication (certificate resolution + peer verification); the exporter
//! keeps owning the rest of transport construction (timeouts, keepalive,
//! concurrency, proxy, headers). The exporter applies the returned config via
//! `reqwest::ClientBuilder::use_preconfigured_tls(..)` (HTTP) or a
//! `tokio-rustls` connector fed to `tonic::transport::Endpoint` (gRPC), so its
//! non-TLS defaults are preserved.
//!
//! The `#[capability]` proc macro expands the trait below into `local::` /
//! `shared::` trait variants, a `SharedAsLocal` adapter, a zero-sized
//! registration handle, factory bridges, and a `KNOWN_CAPABILITIES` entry.
//! The generated `local`/`shared` modules begin with `use super::*;`, so the
//! request/error types defined here are in scope for the generated traits.

use otap_df_engine_macros::capability;

/// Generic, transport-neutral context handed to
/// [`MtlsClientProvider::client_tls_config`].
///
/// Carries only knobs already known to exporters (no implementation-specific
/// fields), so the capability contract stays decoupled from any particular
/// mTLS backend.
#[derive(Debug, Clone, Default)]
pub struct ClientTlsRequest {
    /// The destination endpoint URL the exporter is about to connect to
    /// (e.g. `https://backend:4317`). Provided for diagnostics and for
    /// providers that key behavior on the target; implementations may ignore
    /// it.
    pub endpoint: String,
}

impl ClientTlsRequest {
    /// Creates a request for the given destination endpoint.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

/// Error returned when an mTLS provider fails to produce a TLS config.
#[derive(Debug, thiserror::Error)]
pub enum MtlsError {
    /// The provider could not build the requested TLS configuration.
    #[error("mTLS provider error: {0}")]
    Provider(String),

    /// The provider is bound but the current platform does not support it
    /// (e.g. a platform-specific key store unavailable on this OS). Surfaced
    /// as a fail-fast error.
    #[error("mTLS provider unsupported on this platform: {0}")]
    Unsupported(String),
}

/// Supplies a [`rustls::ClientConfig`] for outbound mutual TLS.
///
/// Implementations construct a fresh config per call so each consuming node
/// gets an independent client configuration.
#[capability(
    name = "mtls_client_provider",
    description = "Supplies a rustls ClientConfig for outbound mTLS"
)]
pub trait MtlsClientProvider {
    /// Builds a [`rustls::ClientConfig`] applying this provider's mTLS
    /// authentication (client certificate + server/peer verification).
    fn client_tls_config(
        &self,
        request: ClientTlsRequest,
    ) -> Result<rustls::ClientConfig, MtlsError>;
}
