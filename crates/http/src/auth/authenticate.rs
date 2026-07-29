/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::auth::AccessToken;
use common::{HttpAuthCache, Server, auth::AuthRequest, network::limiter::InFlight};
use directory::Credentials;
use http_proto::{HttpRequest, HttpSessionData};
use hyper::header;
use base64::Engine;
use mail_parser::decoders::base64::base64_decode;
use std::future::Future;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub trait Authenticator: Sync + Send {
    fn authenticate_headers(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<(Option<InFlight>, AccessToken)>> + Send;
}

impl Authenticator for Server {
    async fn authenticate_headers(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
    ) -> trc::Result<(Option<InFlight>, AccessToken)> {
        if let Some((mechanism, token)) = req.authorization() {
            // Check if the credentials are cached
            if let Some(http_cache) = self.inner.cache.http_auth.get(token) {
                // Make sure the revision is still valid
                if http_cache.expires > Instant::now() {
                    let access_token = AccessToken::renew(
                        self.access_token(http_cache.account_id).await?,
                        http_cache.credential_id,
                        session.remote_ip,
                    )?;

                    if access_token.revision() == http_cache.revision {
                        // Enforce authenticated rate limit
                        return self
                            .is_http_authenticated_request_allowed(&access_token, session.remote_ip)
                            .await
                            .map(|in_flight| (in_flight, access_token));
                    }
                }

                // If the revision is not valid, remove the cached credentials
                self.inner.cache.http_auth.remove(token);
            }

            let credentials = if mechanism.eq_ignore_ascii_case("basic") {
                // Decode the base64 encoded credentials
                decode_plain_auth(token).ok_or_else(|| {
                    trc::AuthEvent::Error
                        .into_err()
                        .details("Failed to decode Basic auth request.")
                        .id(token.to_string())
                        .caused_by(trc::location!())
                })?
            } else if mechanism.eq_ignore_ascii_case("bearer") {
                // Enforce anonymous rate limit
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;

                Credentials::Bearer {
                    username: None,
                    token: token.to_string(),
                }
            } else {
                // Enforce anonymous rate limit
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;

                return Err(trc::AuthEvent::Error
                    .into_err()
                    .reason("Unsupported authentication mechanism.")
                    .details(token.to_string())
                    .caused_by(trc::location!()));
            };

            // Authenticate
            let access_token = self
                .authenticate(&AuthRequest::from_credentials(
                    credentials,
                    session.session_id,
                    session.remote_ip,
                ))
                .await?;

            // Cache credentials
            let max_cache_ttl = Duration::from_secs(self.core.oauth.oauth_expiry_token);
            self.inner.cache.http_auth.insert(
                token.into(),
                HttpAuthCache {
                    account_id: access_token.account_id(),
                    revision: access_token.revision(),
                    credential_id: access_token.credential_id(),
                    // A verified JWT must never outlive its own exp just because
                    // the HTTP credential cache is configured for longer. The
                    // unverified peek only shortens an already authenticated token.
                    expires: Instant::now()
                        + auth_cache_ttl(mechanism, token, max_cache_ttl),
                },
            );

            // Enforce authenticated rate limit
            self.is_http_authenticated_request_allowed(&access_token, session.remote_ip)
                .await
                .map(|in_flight| (in_flight, access_token))
        } else {
            // Enforce anonymous rate limit
            self.is_http_anonymous_request_allowed(session.remote_ip)
                .await?;

            Err(trc::AuthEvent::Failed
                .into_err()
                .details("Missing Authorization header.")
                .caused_by(trc::location!()))
        }
    }
}

fn auth_cache_ttl(mechanism: &str, token: &str, max_ttl: Duration) -> Duration {
    if !mechanism.eq_ignore_ascii_case("bearer") {
        return max_ttl;
    }

    let Some(payload) = token.split('.').nth(1).and_then(|payload| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()
    }) else {
        // Opaque OAuth tokens and Stalwart API keys keep the configured cache TTL.
        return max_ttl;
    };
    let Some(exp) = serde_json::from_slice::<serde_json::Value>(&payload)
        .ok()
        .and_then(|claims| claims.get("exp").and_then(|exp| exp.as_u64()))
    else {
        return max_ttl;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Duration::from_secs(exp.saturating_sub(now).min(max_ttl.as_secs()))
}

pub trait HttpHeaders {
    fn authorization(&self) -> Option<(&str, &str)>;
    fn authorization_basic(&self) -> Option<&str>;
}

impl HttpHeaders for HttpRequest {
    fn authorization(&self) -> Option<(&str, &str)> {
        self.headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.split_once(' ').map(|(l, t)| (l, t.trim())))
    }

    fn authorization_basic(&self) -> Option<&str> {
        self.authorization().and_then(|(l, t)| {
            if l.eq_ignore_ascii_case("basic") {
                Some(t)
            } else {
                None
            }
        })
    }
}

fn decode_plain_auth(token: &str) -> Option<Credentials> {
    base64_decode(token.as_bytes())
        .and_then(|token| String::from_utf8(token).ok())
        .and_then(|token| {
            token
                .split_once(':')
                .map(|(login, secret)| Credentials::Basic {
                    username: login.trim().to_lowercase(),
                    secret: secret.to_string(),
                    mfa_token: None,
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_cache_never_outlives_jwt_exp() {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"exp":{exp}}}"#));
        let token = format!("header.{payload}.signature");
        let ttl = auth_cache_ttl("Bearer", &token, Duration::from_secs(900));
        assert!(ttl <= Duration::from_secs(60));
        assert!(ttl >= Duration::from_secs(58));
    }

    #[test]
    fn opaque_bearer_and_basic_keep_configured_cache_ttl() {
        let configured = Duration::from_secs(900);
        assert_eq!(auth_cache_ttl("Bearer", "API_opaque", configured), configured);
        assert_eq!(auth_cache_ttl("Basic", "opaque", configured), configured);
    }
}
