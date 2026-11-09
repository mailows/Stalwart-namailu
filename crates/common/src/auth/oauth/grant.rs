/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{scope::OAuthScopes, token::TokenGrant};
use crate::{
    Server,
    auth::{AccessToken, RECOVERY_ADMIN_ID, TokenScope},
    cache::{http_auth::RevocationEpoch, invalidate::CacheInvalidationBuilder},
    ipc::CacheInvalidation,
};
use registry::{
    schema::{
        enums::{OAuthClientKind, Permission},
        prelude::{Object, ObjectInner, ObjectType, Property},
        structs::OAuthGrant,
    },
    types::{datetime::UTCDateTime, id::ObjectId, ipaddr::IpAddr},
};
use std::net::IpAddr as StdIpAddr;
use store::{
    blake3,
    registry::{
        RegistryQuery,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::now,
};
use trc::AddContext;
use types::id::Id;

pub const MAX_OAUTH_GRANTS: usize = 256;
pub const RECOVERY_ADMIN_GRANT_ID: u64 = 1 << 62;
const MAX_WRITE_ATTEMPTS: usize = 3;

/// naMailu fork (K5): rebuilds a session token from the current account
/// state (`inner` from the access token cache) and checks it still allows the
/// session. Kept free of I/O so it can be unit tested.
pub(crate) fn revalidated_session_token(
    inner: std::sync::Arc<crate::auth::AccessTokenInner>,
    previous: &AccessToken,
    token_scope: Option<TokenScope>,
    remote_ip: StdIpAddr,
    permission: Permission,
    required_scopes: OAuthScopes,
) -> trc::Result<AccessToken> {
    AccessToken::renew(inner, previous.credential_id(), token_scope, remote_ip)?
        .assert_allows_oauth_scopes(required_scopes)?
        .assert_has_permissions(&[Permission::Authenticate, permission])
}

pub struct NewOAuthGrant<'x> {
    pub account_id: u32,
    pub client_id: &'x str,
    pub client_name: Option<&'x str>,
    pub client_kind: OAuthClientKind,
    pub scopes: OAuthScopes,
    pub remote_ip: StdIpAddr,
}

pub struct StoredOAuthGrant {
    pub id: u64,
    pub revision: u64,
    pub grant: Box<OAuthGrant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantDeletion {
    Unconditional,
    IfUnchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRotation {
    Issue { next: TokenGrant, rotated_at: u64 },
    Revoked,
    Rejected,
}

impl StoredOAuthGrant {
    pub fn account_id(&self) -> u32 {
        self.grant.account_id.document_id()
    }

    fn object_id(&self) -> ObjectId {
        ObjectId::new(ObjectType::OAuthGrant, Id::new(self.id))
    }

    pub fn is_current(&self, presented: u64) -> bool {
        matches!(
            self.rotation(presented),
            RotationStep::Retry | RotationStep::Rotate { .. }
        )
    }

    fn rotation(&self, presented: u64) -> RotationStep {
        let current = self.grant.generation;
        if presented == current {
            if self.grant.pending {
                RotationStep::Retry
            } else {
                RotationStep::Rotate {
                    stored: current,
                    next: current.saturating_add(1),
                }
            }
        } else if self.grant.pending && presented == current.saturating_add(1) {
            RotationStep::Rotate {
                stored: presented,
                next: presented.saturating_add(1),
            }
        } else if presented < current {
            RotationStep::Replay
        } else {
            RotationStep::Invalid
        }
    }
}

impl TokenScope {
    pub fn from_grant(grant_id: u64, grant: &OAuthGrant) -> Self {
        TokenScope::Grant {
            grant_id,
            scopes: OAuthScopes::from_grant(grant),
        }
    }
}

impl OAuthScopes {
    pub fn from_grant(grant: &OAuthGrant) -> Self {
        let scopes = OAuthScopes::from_registry(grant.scopes.iter());
        if grant.client_kind == OAuthClientKind::FirstParty {
            scopes | OAuthScopes::FULL
        } else {
            scopes
        }
    }
}

fn client_id_hash(client_id: &str) -> String {
    blake3::hash(client_id.as_bytes()).to_hex().to_string()
}

fn prune_selection(last_used: &[i64], now: i64, idle_timeout: i64) -> Vec<bool> {
    let mut prune = last_used
        .iter()
        .map(|last_used| last_used.saturating_add(idle_timeout) <= now)
        .collect::<Vec<_>>();
    let mut live = last_used
        .iter()
        .zip(&prune)
        .enumerate()
        .filter(|(_, (_, expired))| !**expired)
        .map(|(idx, (last_used, _))| (*last_used, idx))
        .collect::<Vec<_>>();
    if live.len() >= MAX_OAUTH_GRANTS {
        live.sort_unstable();
        let excess = live.len() + 1 - MAX_OAUTH_GRANTS;
        for (_, idx) in live.into_iter().take(excess) {
            prune[idx] = true;
        }
    }
    prune
}

enum RotationStep {
    Retry,
    Rotate { stored: u64, next: u64 },
    Replay,
    Invalid,
}

impl Server {
    pub async fn oauth_grant(&self, grant_id: u64) -> trc::Result<Option<StoredOAuthGrant>> {
        self.registry()
            .get(ObjectId::new(ObjectType::OAuthGrant, Id::new(grant_id)))
            .await
            .caused_by(trc::location!())
            .map(|object| {
                object.and_then(|object| match object.inner {
                    ObjectInner::OAuthGrant(grant) => Some(StoredOAuthGrant {
                        id: grant_id,
                        revision: object.revision,
                        grant,
                    }),
                    _ => None,
                })
            })
    }

    pub async fn oauth_grant_scope(
        &self,
        grant_id: u64,
        account_id: u32,
    ) -> trc::Result<TokenScope> {
        match self.oauth_grant(grant_id).await? {
            Some(stored) if stored.account_id() == account_id => {
                Ok(TokenScope::from_grant(grant_id, &stored.grant))
            }
            None if account_id == RECOVERY_ADMIN_ID && grant_id == RECOVERY_ADMIN_GRANT_ID => {
                Ok(TokenScope::Grant {
                    grant_id,
                    scopes: OAuthScopes::ALL,
                })
            }
            _ => Err(trc::AuthEvent::TokenExpired
                .into_err()
                .account_id(account_id)
                .id(grant_id)
                .details("OAuth grant revoked")),
        }
    }

    pub async fn renew_access_token(
        &self,
        access_token: &AccessToken,
        remote_ip: StdIpAddr,
    ) -> trc::Result<AccessToken> {
        let account_id = access_token.account_id();
        let inner = self.access_token(account_id).await?;
        let token_scope = match access_token.token_scope() {
            Some(TokenScope::Grant { grant_id, .. }) => {
                Some(self.oauth_grant_scope(grant_id, account_id).await?)
            }
            token_scope => token_scope,
        };
        AccessToken::renew(inner, access_token.credential_id(), token_scope, remote_ip)
    }

    pub async fn refresh_access_token(
        &self,
        access_token: &AccessToken,
        remote_ip: StdIpAddr,
    ) -> trc::Result<Option<AccessToken>> {
        let inner = self.access_token(access_token.account_id()).await?;
        if access_token.is_built_from(&inner) {
            Ok(None)
        } else {
            AccessToken::renew(
                inner,
                access_token.credential_id(),
                access_token.token_scope(),
                remote_ip,
            )
            .map(Some)
        }
    }

    /// naMailu fork (K5): revalidates the security state of a long-lived
    /// protocol session (IMAP, POP3, ManageSieve) before it runs a command.
    ///
    /// The account part comes from the access token cache, so on the common
    /// path this is a cache hit plus a few bit tests; it never verifies the
    /// password again. The token is rebuilt from the current cache entry, which
    /// re-applies the credential scope (a removed or expired AppPassword fails
    /// here), the allowed IPs and the expiry, then the session must still hold
    /// `Authenticate`, the protocol permission and, for OAuth tokens, the
    /// required scope. An OAuth grant is looked up again only after the grant
    /// revocation epoch moved. Any `Auth`/`Security` error means the session
    /// must be closed; other errors (store unavailable) are transient.
    pub async fn revalidate_session_token(
        &self,
        access_token: &AccessToken,
        revocation_epoch: &mut RevocationEpoch,
        remote_ip: StdIpAddr,
        permission: Permission,
        required_scopes: OAuthScopes,
    ) -> trc::Result<AccessToken> {
        let account_id = access_token.account_id();
        let mut token_scope = access_token.token_scope();
        let mut next_epoch = None;
        if let Some(TokenScope::Grant { grant_id, .. }) = token_scope {
            let epoch = self.inner.cache.grant_revocations.epoch();
            if epoch != *revocation_epoch {
                token_scope = Some(self.oauth_grant_scope(grant_id, account_id).await?);
                next_epoch = Some(epoch);
            }
        }
        let token = revalidated_session_token(
            self.access_token(account_id).await?,
            access_token,
            token_scope,
            remote_ip,
            permission,
            required_scopes,
        )?;
        if let Some(epoch) = next_epoch {
            *revocation_epoch = epoch;
        }
        Ok(token)
    }

    pub async fn create_oauth_grant(&self, new: NewOAuthGrant<'_>) -> trc::Result<u64> {
        let mut invalidator = CacheInvalidationBuilder::default();
        self.prune_oauth_grants(new.account_id, &mut invalidator)
            .await?;

        let now = UTCDateTime::now();
        let grant = OAuthGrant {
            account_id: Id::from(new.account_id),
            client_id: new.client_id.to_string(),
            client_hash: client_id_hash(new.client_id),
            client_name: new
                .client_name
                .filter(|name| !name.is_empty())
                .map(str::to_string),
            client_kind: new.client_kind,
            scopes: new.scopes.to_registry(),
            remote_ip: Some(IpAddr(new.remote_ip)),
            created_at: now,
            last_used_at: now,
            generation: 0,
            pending: false,
        };
        let object = Object::new(grant.into());

        let result = self
            .registry()
            .write(RegistryWrite::insert(&object))
            .await
            .caused_by(trc::location!())?;
        self.invalidate_caches(invalidator).await?;

        match result {
            RegistryWriteResult::Success(id) => Ok(id.id()),
            failure => Err(trc::AuthEvent::Error
                .into_err()
                .account_id(new.account_id)
                .details("Failed to create OAuth grant")
                .reason(failure)
                .caused_by(trc::location!())),
        }
    }

    async fn prune_oauth_grants(
        &self,
        account_id: u32,
        invalidator: &mut CacheInvalidationBuilder,
    ) -> trc::Result<()> {
        let ids = self
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::OAuthGrant).with_account(account_id))
            .await
            .caused_by(trc::location!())?;
        if ids.is_empty() {
            return Ok(());
        }

        let mut grants = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(stored) = self.oauth_grant(id.id()).await? {
                grants.push(stored);
            }
        }

        let last_used = grants
            .iter()
            .map(|stored| stored.grant.last_used_at.timestamp())
            .collect::<Vec<_>>();
        let prune = prune_selection(
            &last_used,
            now() as i64,
            self.core.oauth.oauth_expiry_refresh_token as i64,
        );
        for (stored, prune) in grants.into_iter().zip(prune) {
            if prune {
                self.delete_oauth_grant(stored, GrantDeletion::IfUnchanged, invalidator)
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn has_oauth_grant(
        &self,
        account_id: u32,
        client_id: &str,
        client_kind: OAuthClientKind,
        scopes: OAuthScopes,
    ) -> trc::Result<bool> {
        let idle_since =
            (now() as i64).saturating_sub(self.core.oauth.oauth_expiry_refresh_token as i64);
        for id in self
            .registry()
            .query::<Vec<Id>>(
                RegistryQuery::new(ObjectType::OAuthGrant)
                    .with_account(account_id)
                    .equal(Property::ClientHash, client_id_hash(client_id)),
            )
            .await
            .caused_by(trc::location!())?
        {
            if self.oauth_grant(id.id()).await?.is_some_and(|stored| {
                let grant = &stored.grant;
                grant.client_id == client_id
                    && grant.client_kind == client_kind
                    && grant.last_used_at.timestamp() > idle_since
                    && OAuthScopes::from_registry(grant.scopes.iter()).contains(scopes)
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn revoke_oauth_grants(
        &self,
        account_id: u32,
        invalidator: &mut CacheInvalidationBuilder,
    ) -> trc::Result<()> {
        for id in self
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::OAuthGrant).with_account(account_id))
            .await
            .caused_by(trc::location!())?
        {
            if let Some(stored) = self.oauth_grant(id.id()).await? {
                self.delete_oauth_grant(stored, GrantDeletion::Unconditional, invalidator)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn delete_oauth_grant(
        &self,
        mut stored: StoredOAuthGrant,
        mode: GrantDeletion,
        invalidator: &mut CacheInvalidationBuilder,
    ) -> trc::Result<bool> {
        for _ in 0..MAX_WRITE_ATTEMPTS {
            let account_id = stored.account_id();
            let object_id = stored.object_id();
            let object =
                Object::with_revision(ObjectInner::OAuthGrant(stored.grant), stored.revision);
            match self
                .registry()
                .write(RegistryWrite::delete_object(object_id, &object))
                .await
            {
                Ok(RegistryWriteResult::Success(_)) => {
                    invalidator.invalidate(CacheInvalidation::OAuthGrant {
                        account_id,
                        grant_id: stored.id,
                    });
                    return Ok(true);
                }
                Ok(RegistryWriteResult::NotFound { .. }) => return Ok(false),
                Ok(failure) => {
                    return Err(trc::AuthEvent::Error
                        .into_err()
                        .id(stored.id)
                        .details("Failed to delete OAuth grant")
                        .reason(failure)
                        .caused_by(trc::location!()));
                }
                Err(err) if err.is_assertion_failure() => {
                    if mode == GrantDeletion::IfUnchanged {
                        return Ok(false);
                    }
                    match self.oauth_grant(stored.id).await? {
                        Some(current) => stored = current,
                        None => return Ok(false),
                    }
                }
                Err(err) => return Err(err.caused_by(trc::location!())),
            }
        }

        Err(trc::StoreEvent::AssertValueFailed
            .into_err()
            .id(stored.id)
            .details("OAuth grant changed concurrently")
            .caused_by(trc::location!()))
    }

    pub async fn rotate_oauth_grant(
        &self,
        mut stored: StoredOAuthGrant,
        presented_generation: u64,
    ) -> trc::Result<GrantRotation> {
        for _ in 0..MAX_WRITE_ATTEMPTS {
            let (stored_generation, next_generation) = match stored.rotation(presented_generation) {
                RotationStep::Retry => {
                    return Ok(GrantRotation::Issue {
                        next: TokenGrant {
                            id: stored.id,
                            generation: stored.grant.generation.saturating_add(1),
                        },
                        rotated_at: stored.grant.last_used_at.timestamp() as u64,
                    });
                }
                RotationStep::Rotate { stored, next } => (stored, next),
                RotationStep::Replay => {
                    trc::event!(
                        Auth(trc::AuthEvent::Failed),
                        AccountId = stored.account_id(),
                        Id = stored.id,
                        Reason = "Superseded refresh token reused, revoking OAuth grant",
                    );
                    let mut invalidator = CacheInvalidationBuilder::default();
                    self.delete_oauth_grant(stored, GrantDeletion::Unconditional, &mut invalidator)
                        .await?;
                    self.invalidate_caches(invalidator).await?;
                    return Ok(GrantRotation::Revoked);
                }
                RotationStep::Invalid => return Ok(GrantRotation::Rejected),
            };

            let now = UTCDateTime::now();
            let mut updated = stored.grant.clone();
            updated.generation = stored_generation;
            updated.pending = true;
            updated.last_used_at = now;
            if updated.client_hash.is_empty() {
                updated.client_hash = client_id_hash(&updated.client_id);
            }
            let old_object =
                Object::with_revision(ObjectInner::OAuthGrant(stored.grant), stored.revision);
            let new_object = Object::new(ObjectInner::OAuthGrant(updated));

            match self
                .registry()
                .write(RegistryWrite::update(
                    Id::new(stored.id),
                    &new_object,
                    &old_object,
                ))
                .await
            {
                Ok(RegistryWriteResult::Success(_)) => {
                    return Ok(GrantRotation::Issue {
                        next: TokenGrant {
                            id: stored.id,
                            generation: next_generation,
                        },
                        rotated_at: now.timestamp() as u64,
                    });
                }
                Ok(failure) => {
                    return Err(trc::AuthEvent::Error
                        .into_err()
                        .id(stored.id)
                        .details("Failed to rotate OAuth grant")
                        .reason(failure)
                        .caused_by(trc::location!()));
                }
                Err(err) if err.is_assertion_failure() => {
                    match self.oauth_grant(stored.id).await? {
                        Some(current) => stored = current,
                        None => return Ok(GrantRotation::Rejected),
                    }
                }
                Err(err) => return Err(err.caused_by(trc::location!())),
            }
        }

        Err(trc::StoreEvent::AssertValueFailed
            .into_err()
            .id(stored.id)
            .details("OAuth grant changed concurrently")
            .caused_by(trc::location!()))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/auth/oauth/grant/tests.rs"]
mod tests;

#[cfg(test)]
mod namailu_k5_tests {
    //! naMailu fork (K5): an IMAP/POP3/ManageSieve session revalidates its
    //! token against the current account state before every command.
    use super::revalidated_session_token;
    use crate::auth::{
        AccessScope, AccessToken, AccessTokenInner, Permissions, TokenScope,
        oauth::scope::OAuthScopes,
    };
    use registry::schema::enums::Permission;
    use std::{net::IpAddr, sync::Arc};

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
    const APP_PASSWORD: u32 = 7;

    fn perms(list: &[Permission]) -> Permissions {
        let mut permissions = Permissions::new();
        for permission in list {
            permissions.set(*permission as usize);
        }
        permissions
    }

    fn scope(permissions: Permissions, credential_id: u32, expires_at: u64) -> AccessScope {
        AccessScope {
            permissions,
            credential_id,
            expires_at,
            allowed_ips: Box::new([]),
        }
    }

    fn inner(scopes: Vec<AccessScope>) -> Arc<AccessTokenInner> {
        Arc::new(AccessTokenInner {
            account_id: 42,
            scopes: scopes.into_boxed_slice(),
            ..Default::default()
        })
    }

    fn mail_user() -> Permissions {
        perms(&[
            Permission::Authenticate,
            Permission::ImapAuthenticate,
            Permission::Pop3Authenticate,
            Permission::SieveAuthenticate,
            Permission::ImapFetch,
        ])
    }

    fn active() -> Arc<AccessTokenInner> {
        inner(vec![
            scope(mail_user(), u32::MAX, u64::MAX),
            scope(mail_user(), APP_PASSWORD, u64::MAX),
        ])
    }

    fn login(inner: Arc<AccessTokenInner>, credential_id: Option<u32>) -> AccessToken {
        AccessToken::renew(inner, credential_id, None, IP).unwrap()
    }

    fn closes_session(err: &trc::Error) -> bool {
        matches!(
            err.as_ref(),
            trc::EventType::Auth(_) | trc::EventType::Security(_)
        )
    }

    fn check(
        inner: Arc<AccessTokenInner>,
        previous: &AccessToken,
        permission: Permission,
    ) -> trc::Result<AccessToken> {
        revalidated_session_token(
            inner,
            previous,
            previous.token_scope(),
            IP,
            permission,
            OAuthScopes::MAIL,
        )
    }

    #[test]
    fn unchanged_account_keeps_the_session() {
        let current = active();
        for credential_id in [None, Some(APP_PASSWORD)] {
            let session = login(current.clone(), credential_id);
            for permission in [
                Permission::ImapAuthenticate,
                Permission::Pop3Authenticate,
                Permission::SieveAuthenticate,
            ] {
                let renewed = check(current.clone(), &session, permission).unwrap();
                assert!(renewed.is_built_from(&current));
                assert_eq!(renewed.credential_id(), session.credential_id());
                assert!(renewed.has_permission(Permission::ImapFetch));
            }
        }
    }

    #[test]
    fn blocked_account_closes_the_session() {
        // x:Account/set permissions Replace {enabledPermissions: {}} = no permissions at all.
        let blocked = inner(vec![
            scope(Permissions::new(), u32::MAX, u64::MAX),
            scope(Permissions::new(), APP_PASSWORD, u64::MAX),
        ]);
        for credential_id in [None, Some(APP_PASSWORD)] {
            let session = login(active(), credential_id);
            for permission in [
                Permission::ImapAuthenticate,
                Permission::Pop3Authenticate,
                Permission::SieveAuthenticate,
            ] {
                let err = check(blocked.clone(), &session, permission).unwrap_err();
                assert!(closes_session(&err), "{err:?}");
            }
        }
    }

    #[test]
    fn removed_protocol_permission_closes_only_that_protocol() {
        let no_pop3 = inner(vec![scope(
            perms(&[Permission::Authenticate, Permission::ImapAuthenticate]),
            u32::MAX,
            u64::MAX,
        )]);
        let session = login(active(), None);
        assert!(check(no_pop3.clone(), &session, Permission::ImapAuthenticate).is_ok());
        let err = check(no_pop3, &session, Permission::Pop3Authenticate).unwrap_err();
        assert!(closes_session(&err), "{err:?}");
    }

    #[test]
    fn removed_app_password_closes_the_session() {
        // The AppPassword was deleted: the rebuilt token has no scope for it.
        let without_app_password = inner(vec![scope(mail_user(), u32::MAX, u64::MAX)]);
        let session = login(active(), Some(APP_PASSWORD));
        let err = check(
            without_app_password.clone(),
            &session,
            Permission::ImapAuthenticate,
        )
        .unwrap_err();
        assert!(closes_session(&err), "{err:?}");

        // A session opened with the primary password is unaffected.
        let primary = login(active(), None);
        assert!(check(without_app_password, &primary, Permission::ImapAuthenticate).is_ok());
    }

    #[test]
    fn expired_app_password_closes_the_session() {
        let session = login(active(), Some(APP_PASSWORD));
        let expired = inner(vec![
            scope(mail_user(), u32::MAX, u64::MAX),
            scope(mail_user(), APP_PASSWORD, 1),
        ]);
        let err = check(expired, &session, Permission::ImapAuthenticate).unwrap_err();
        assert!(closes_session(&err), "{err:?}");
    }

    #[test]
    fn oauth_token_without_mail_scope_closes_the_session() {
        let current = active();
        let session = AccessToken::renew(
            current.clone(),
            None,
            Some(TokenScope::External {
                scopes: OAuthScopes::MAIL,
            }),
            IP,
        )
        .unwrap();
        assert!(check(current.clone(), &session, Permission::ImapAuthenticate).is_ok());

        let err = revalidated_session_token(
            current,
            &session,
            Some(TokenScope::External {
                scopes: OAuthScopes::CALENDARS,
            }),
            IP,
            Permission::ImapAuthenticate,
            OAuthScopes::MAIL,
        )
        .unwrap_err();
        assert!(closes_session(&err), "{err:?}");
    }
}
