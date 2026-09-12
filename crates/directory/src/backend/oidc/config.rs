/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Directory;
use crate::backend::oidc::lookup::fetch_jwks_keys;
use crate::backend::oidc::{
    DiscoveryFailure, DiscoveryDocument, JwksCache, OidcConfig, OidcDiscovery, OidcError,
    OpenIdDirectory,
};
use ahash::AHashMap;
use registry::schema::structs;
use reqwest::redirect::Policy;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use trc::AuthEvent;

impl OpenIdDirectory {
    pub async fn open(config: structs::OidcDirectory) -> Result<Directory, String> {
        Self::new(OidcConfig {
            issue_url: config.issuer_url,
            require_aud: config.require_audience,
            require_scopes: config.require_scopes.into_inner(),
            claim_email: config.claim_username,
            claim_name: config.claim_name,
            claim_groups: config.claim_groups,
            default_domain: config.username_domain,
        })
        .await
        .map(Directory::OpenId)
        .map_err(|err| err.to_string())
    }

    pub async fn new(config: OidcConfig) -> Result<Self, OidcError> {
        let http = utils::http::http_client_builder(false)
            .user_agent("Stalwart/1.0")
            .timeout(Duration::from_secs(10))
            // Credentials must never be redirected or inherited by a proxy from the
            // process environment. The endpoint is a fixed, same-host HTTPS target.
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .map_err(|e| OidcError::Network(format!("HTTP client build failed: {e}")))?;

        let directory = Self {
            config,
            discovery: RwLock::new(None),
            discovery_lock: Mutex::new(None),
            http,
            cache: RwLock::new(JwksCache {
                keys: AHashMap::default(),
                // Older than the refresh window, so the first key lookup refreshes.
                last_updated: Instant::now() - Duration::from_secs(600),
            }),
            // Deployment-specific service identity. It is intentionally not part of
            // the public registry object or discovery document and is never logged.
            basic_auth_token: std::env::var("STALWART_OIDC_BASIC_AUTH_TOKEN")
                .ok()
                .filter(|token| !token.is_empty()),
        };

        // Try eagerly so that a misconfiguration shows up in the boot log, but do
        // not fail the directory: the provider may simply not be up yet. The first
        // authentication (or metadata request) retries.
        if let Err(err) = directory.discovery().await {
            trc::event!(
                Auth(AuthEvent::Warning),
                Url = directory.config.issue_url.to_string(),
                Reason = format!(
                    "OIDC discovery failed at startup, will retry on first use: {err}"
                )
            );
        }

        Ok(directory)
    }

    /// Return the discovery document, fetching and validating it on first use.
    /// Concurrent callers wait for one fetch; after a failure the next attempt is
    /// delayed by `RETRY_AFTER` so a provider outage does not turn every login
    /// into a fresh discovery round-trip.
    pub async fn discovery(&self) -> Result<Arc<OidcDiscovery>, OidcError> {
        const RETRY_AFTER: Duration = Duration::from_secs(2);

        if let Some(discovery) = self.discovery.read().await.as_ref() {
            return Ok(discovery.clone());
        }

        let mut last_failure = self.discovery_lock.lock().await;
        if let Some(discovery) = self.discovery.read().await.as_ref() {
            return Ok(discovery.clone());
        }
        if let Some(failure) = last_failure.as_ref()
            && failure.at.elapsed() < RETRY_AFTER
        {
            return Err(OidcError::Network(format!(
                "OIDC discovery unavailable (last attempt: {})",
                failure.reason
            )));
        }

        match self.fetch_discovery().await {
            Ok(discovery) => {
                let discovery = Arc::new(OidcDiscovery {
                    url: self.config.issue_url.clone(),
                    document: discovery,
                });
                *self.discovery.write().await = Some(discovery.clone());
                *last_failure = None;
                Ok(discovery)
            }
            Err(err) => {
                *last_failure = Some(DiscoveryFailure {
                    at: Instant::now(),
                    reason: err.to_string(),
                });
                Err(err)
            }
        }
    }

    /// Fetch and validate the discovery document and prime the JWKS cache.
    async fn fetch_discovery(&self) -> Result<DiscoveryDocument, OidcError> {
        let config = &self.config;
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issue_url.trim_end_matches('/')
        );
        let discovery_bytes = self
            .http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| OidcError::Network(format!("Discovery fetch failed: {e}")))?
            .error_for_status()
            .map_err(|e| OidcError::Provider(format!("Discovery HTTP error: {e}")))?
            .bytes()
            .await
            .map_err(|e| OidcError::Provider(format!("Discovery HTTP error: {e}")))?;
        let discovery: DiscoveryDocument = serde_json::from_slice(&discovery_bytes)
            .map_err(|e| OidcError::Provider(format!("Discovery JSON parse error: {e}")))?;

        let normalised_issue = config.issue_url.trim_end_matches('/');
        let normalised_issuer = discovery.issuer.trim_end_matches('/');
        if normalised_issuer != normalised_issue {
            return Err(OidcError::Provider(format!(
                "Issuer mismatch: discovery document says '{}' but configured issue_url is '{}'",
                discovery.issuer, config.issue_url,
            )));
        }

        if let Some(endpoint) = &discovery.password_verification_endpoint {
            let endpoint_url = reqwest::Url::parse(endpoint).map_err(|err| {
                OidcError::Provider(format!("Invalid password_verification_endpoint URL: {err}"))
            })?;
            let issuer_url = reqwest::Url::parse(&discovery.issuer)
                .map_err(|err| OidcError::Provider(format!("Invalid issuer URL: {err}")))?;
            if endpoint_url.scheme() != "https"
                || endpoint_url.host_str() != issuer_url.host_str()
                || endpoint_url.username() != ""
                || endpoint_url.password().is_some()
            {
                return Err(OidcError::Provider(
                    "password_verification_endpoint must be HTTPS, contain no userinfo, \
                     and use the same hostname as the issuer"
                        .to_string(),
                ));
            }
        }

        if let Some(supported) = &discovery.scopes_supported {
            for scope in &config.require_scopes {
                if !supported.contains(scope) {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = config.issue_url.to_string(),
                        Reason = format!(
                            "Required scope '{}' is not in scopes_supported from the IdP",
                            scope
                        )
                    );
                }
            }
        }

        if let Some(supported) = &discovery.claims_supported {
            let check = |name: &str, label: &str| {
                if !supported.iter().any(|c| c == name) {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = config.issue_url.to_string(),
                        Reason = format!(
                            "Configured {} claim '{}' is not in claims_supported from the IdP",
                            label, name
                        )
                    );
                }
            };
            check(&config.claim_email, "claim_email");
            if let Some(n) = &config.claim_name {
                check(n, "claim_name");
            }
            if let Some(g) = &config.claim_groups {
                check(g, "claim_groups");
            }
        }

        let keys = fetch_jwks_keys(&self.http, &discovery.jwks_uri).await?;
        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.last_updated = Instant::now();

        Ok(discovery)
    }

    /// Test hook: replace the userinfo endpoint of an already fetched document.
    #[cfg(feature = "test_mode")]
    pub async fn set_userinfo_endpoint(&self, endpoint: &str) {
        let mut guard = self.discovery.write().await;
        if let Some(discovery) = guard.take() {
            let mut discovery = Arc::unwrap_or_clone(discovery);
            discovery.document.userinfo_endpoint = endpoint.to_string();
            *guard = Some(Arc::new(discovery));
        }
    }
}
