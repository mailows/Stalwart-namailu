/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::{Session, SessionData, State};
use common::{
    auth::AuthRequest,
    network::{SessionStream, limiter::LimiterResult},
};
use directory::Credentials;
use imap_proto::{
    Command, ResponseCode, StatusResponse,
    protocol::{authenticate::Mechanism, capability::Capability},
    receiver::{self, Request},
};
use mail_parser::decoders::base64::base64_decode;
use registry::schema::enums::Permission;
use std::sync::Arc;

impl<T: SessionStream> Session<T> {
    pub async fn handle_authenticate(&mut self, request: Request<Command>) -> trc::Result<()> {
        let mut args = request.parse_authenticate()?;

        match args.mechanism {
            Mechanism::Plain | Mechanism::OAuthBearer | Mechanism::XOauth2 => {
                if !args.params.is_empty() {
                    let challenge = base64_decode(args.params.pop().unwrap().as_bytes())
                        .ok_or_else(|| {
                            trc::AuthEvent::Error
                                .into_err()
                                .details("Failed to decode challenge.")
                                .id(args.tag.clone())
                                .code(ResponseCode::Parse)
                        })?;

                    let credentials = if args.mechanism == Mechanism::Plain {
                        Credentials::decode_sasl_challenge_plain(&challenge)
                    } else {
                        Credentials::decode_sasl_challenge_oauth(&challenge)
                    }
                    .ok_or_else(|| {
                        trc::AuthEvent::Error
                            .into_err()
                            .details("Invalid SASL challenge.")
                            .id(args.tag.clone())
                    })?;

                    self.authenticate(credentials, args.tag).await
                } else {
                    self.receiver.request = receiver::Request {
                        tag: args.tag,
                        command: Command::Authenticate,
                        tokens: vec![receiver::Token::Argument(args.mechanism.into_bytes())],
                    };
                    self.receiver.state = receiver::State::Argument { last_ch: b' ' };
                    self.write_bytes(b"+ \r\n".to_vec()).await
                }
            }
            _ => Err(trc::AuthEvent::Error
                .into_err()
                .details("Authentication mechanism not supported.")
                .id(args.tag)
                .code(ResponseCode::Cannot)),
        }
    }

    pub async fn authenticate(&mut self, credentials: Credentials, tag: String) -> trc::Result<()> {
        // Authenticate
        let access_token = self
            .server
            .authenticate(&AuthRequest::from_credentials(
                credentials,
                self.session_id,
                self.remote_addr,
            ))
            .await
            .map_err(|err| {
                if err.matches(trc::EventType::Auth(trc::AuthEvent::Failed)) {
                    let auth_failures = self.state.auth_failures();
                    if auth_failures < self.server.core.imap.max_auth_failures {
                        self.state = State::NotAuthenticated {
                            auth_failures: auth_failures + 1,
                        };
                    } else {
                        return trc::AuthEvent::TooManyAttempts
                            .into_err()
                            .caused_by(err)
                            .id(tag.clone());
                    }
                } else if err.matches(trc::EventType::Auth(trc::AuthEvent::Error)) {
                    // naMailu fork: the directory could not decide (e.g. the password
                    // verification endpoint answered 502 during a deploy). Answering
                    // AUTHENTICATIONFAILED here makes clients such as iOS Mail treat the
                    // stored password as wrong and stop using it, so report a temporary
                    // failure instead (RFC 5530 UNAVAILABLE); the client retries later.
                    return temporary_auth_failure(err).id(tag.clone());
                }

                err.id(tag.clone())
            })
            .and_then(|token| token.assert_has_permission(Permission::ImapAuthenticate))?;

        // Enforce concurrency limits
        let in_flight = match access_token.is_imap_request_allowed() {
            LimiterResult::Allowed(in_flight) => Some(in_flight),
            LimiterResult::Forbidden => {
                return Err(trc::LimitEvent::ConcurrentRequest
                    .into_err()
                    .id(tag.clone()));
            }
            LimiterResult::Disabled => None,
        };

        // Create session
        self.state = State::Authenticated {
            data: Arc::new(
                SessionData::new(self, access_token, in_flight)
                    .await
                    .map_err(|err| err.id(tag.clone()))?,
            ),
        };
        self.write_bytes(
            StatusResponse::ok("Authentication successful")
                .with_code(ResponseCode::Capability {
                    capabilities: Capability::all_capabilities(
                        true,
                        !self.is_tls && self.instance.acceptor.is_tls(),
                        true,
                        self.server.core.imap.max_messages_per_command,
                        self.server.core.imap.max_messages_per_save,
                    ),
                })
                .with_tag(tag)
                .into_bytes(),
        )
        .await
    }

    pub async fn handle_unauthenticate(&mut self, request: Request<Command>) -> trc::Result<()> {
        self.state = State::NotAuthenticated { auth_failures: 0 };
        self.is_condstore = false;
        self.is_qresync = false;
        self.is_utf8 = false;
        self.is_objectid = false;
        self.is_uidonly = false;

        self.write_bytes(
            StatusResponse::completed(Command::Unauthenticate)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}

/// naMailu fork: an authentication backend error is a temporary condition, not
/// a rejected credential. The original reason stays in the event for the log.
pub(crate) fn temporary_auth_failure(err: trc::Error) -> trc::Error {
    err.ctx_unique(trc::Key::Code, ResponseCode::Unavailable.as_str())
        .ctx_unique(
            trc::Key::Details,
            "Temporary authentication failure, try again later.",
        )
}

#[cfg(test)]
mod namailu_tests {
    use super::temporary_auth_failure;
    use imap_proto::protocol::SerializeResponse;

    #[test]
    fn backend_error_is_unavailable_not_authenticationfailed() {
        let err = trc::AuthEvent::Error
            .into_err()
            .reason("Provider error: Password verification endpoint returned HTTP 502");
        let line = String::from_utf8(temporary_auth_failure(err).id("a1").serialize()).unwrap();
        assert!(line.starts_with("a1 NO [UNAVAILABLE] "), "{line}");
        assert!(!line.contains("AUTHENTICATIONFAILED"), "{line}");
    }

    #[test]
    fn wrong_password_stays_authenticationfailed() {
        let line = String::from_utf8(trc::AuthEvent::Failed.into_err().id("a1").serialize()).unwrap();
        assert!(line.contains("[AUTHENTICATIONFAILED]"), "{line}");
    }
}
