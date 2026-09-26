/*
 * SPDX-FileCopyrightText: 2026 namailu.cz
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Fork change: mail that a *user* Sieve script sends out (`redirect`, `vacation`,
//! `notify`) asks the RCPT-stage MTA hook first, exactly like a recipient added in an
//! SMTP/JMAP submission would.
//!
//! Upstream queues these messages directly, without an SMTP session, so no MTA hook,
//! milter or rate limit ever sees them. An operator enforcing per-account sending limits
//! in the hook is then bypassed by a one-line Sieve filter (or by the account's own
//! forwarding), and the redirected mail leaves from the operator's IP.
//!
//! The request mimics an RCPT hook call: `context.stage = "rcpt"`, `context.sasl.login`
//! is the account, the envelope is the account → the target. An extra `context.sieve`
//! says whether this is a redirect of the received message (`"redirect"`) or a message
//! the script created (`"message"`: vacation, notify), so the hook can apply different
//! rules to each.
//!
//! Failure is closed: a hook error, a timeout or anything but `"action": "accept"` drops
//! the outgoing copy. Nothing is lost — when no other action kept the message, the
//! fail-safe at the end of `sieve_script_ingest` files it into the inbox.
//!
//! No RCPT hook configured = upstream behaviour (everything allowed).

use common::{Server, config::smtp::session::Stage};
use std::time::Duration;
use trc::SieveEvent;
use utils::HttpLimitResponse;

/// The hook runs inside local delivery; do not hold it for the full SMTP hook timeout.
const MAX_WAIT: Duration = Duration::from_secs(10);

pub(crate) async fn sieve_outbound_allowed(
    server: &Server,
    account: &str,
    recipient: &str,
    is_redirect: bool,
    session_id: u64,
) -> bool {
    let Some(hook) = server
        .core
        .smtp
        .session
        .hooks
        .iter()
        .find(|hook| hook.run_on_stage.contains(&Stage::Rcpt))
    else {
        return true;
    };

    let body = serde_json::json!({
        "context": {
            "stage": "rcpt",
            "sasl": { "login": account },
            "sieve": if is_redirect { "redirect" } else { "message" },
        },
        "envelope": {
            "from": { "address": account },
            "to": [ { "address": recipient } ],
        },
    });

    let verdict = match hook
        .client
        .post(&hook.url)
        .timeout(hook.timeout.min(MAX_WAIT))
        .headers(hook.headers.clone())
        .body(body.to_string())
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            match response.bytes_with_limit(hook.max_response_size).await {
                Ok(Some(bytes)) => serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("action")
                            .and_then(|action| action.as_str())
                            .map(|action| action == "accept")
                    })
                    .ok_or("invalid hook response"),
                Ok(None) => Err("hook response too large"),
                Err(_) => Err("failed to read hook response"),
            }
        }
        Ok(_) => Err("hook returned an error status"),
        Err(_) => Err("hook request failed"),
    };

    match verdict {
        Ok(true) => true,
        Ok(false) => {
            trc::event!(
                Sieve(SieveEvent::QuotaExceeded),
                From = account.to_string(),
                To = recipient.to_string(),
                Details = "Outgoing Sieve message rejected by MTA hook.",
                SpanId = session_id
            );
            false
        }
        Err(reason) => {
            trc::event!(
                Sieve(SieveEvent::UnexpectedError),
                From = account.to_string(),
                To = recipient.to_string(),
                Details = reason,
                SpanId = session_id
            );
            false
        }
    }
}
