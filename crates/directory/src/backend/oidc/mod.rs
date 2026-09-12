/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc, time::Instant};
use tokio::sync::{Mutex, RwLock};
use utils::Client;

pub mod config;
pub mod lookup;

pub struct OidcConfig {
    pub issue_url: String,
    pub require_aud: Option<String>,
    pub require_scopes: Vec<String>,
    pub claim_email: String,
    pub claim_name: Option<String>,
    pub claim_groups: Option<String>,
    pub default_domain: Option<String>,
}

#[derive(Clone)]
pub struct OidcDiscovery {
    pub url: String,
    pub document: DiscoveryDocument,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: String,
    pub token_endpoint: String,
    pub authorization_endpoint: String,
    /// Optional private extension used by deployments that deliberately expose the
    /// same primary password to legacy mail protocols. The endpoint returns no profile
    /// or hash; it only verifies a Basic username/password over HTTPS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_verification_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

struct CachedKey {
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

struct JwksCache {
    keys: AHashMap<String, Arc<CachedKey>>,
    last_updated: Instant,
}

/// Result of the last failed discovery attempt, kept so that a provider that is
/// down does not get hammered by every login: retries are spaced out.
struct DiscoveryFailure {
    at: Instant,
    reason: String,
}

pub struct OpenIdDirectory {
    config: OidcConfig,
    /// Discovery document and the JWKS it points to are fetched lazily. The
    /// provider may not be reachable yet when the server starts (it is often
    /// another service of the same deployment); a directory that failed once at
    /// boot must not stay dead until a restart. `None` until the first successful
    /// fetch; every caller goes through `OpenIdDirectory::discovery`.
    discovery: RwLock<Option<Arc<OidcDiscovery>>>,
    discovery_lock: Mutex<Option<DiscoveryFailure>>,
    http: Client,
    cache: RwLock<JwksCache>,
    basic_auth_token: Option<String>,
}

#[derive(Debug)]
pub enum OidcError {
    TokenValidation(String),
    AuthorizationFailed(String),
    Network(String),
    Provider(String),
    Config(String),
}

impl OidcError {
    pub fn is_transient(&self) -> bool {
        matches!(self, OidcError::Network(_) | OidcError::Provider(_))
    }
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OidcError::TokenValidation(msg) => write!(f, "Token validation error: {msg}"),
            OidcError::AuthorizationFailed(msg) => write!(f, "Authorization failed: {msg}"),
            OidcError::Network(msg) => write!(f, "Network error: {msg}"),
            OidcError::Provider(msg) => write!(f, "Provider error: {msg}"),
            OidcError::Config(msg) => write!(f, "Configuration error: {msg}"),
        }
    }
}

impl std::error::Error for OidcError {}
