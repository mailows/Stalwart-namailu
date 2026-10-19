/*
 * SPDX-FileCopyrightText: 2026 namailu.cz
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Fork: the sending quota of a held (FUTURERELEASE) message is charged when the
//! queue releases it, not when it is submitted.
//!
//! Namailu enforces per-account plan limits in the RCPT-stage MTA hook. A hook that
//! charges at submission lets a client stockpile several days of quota into one
//! release window, and a message held before the account is suspended would still
//! leave afterwards. So a held submission only asks the hook with
//! `context.futureRelease = "hold"` (the hook checks the account but does not charge),
//! every recipient is queued with `RCPT_RELEASE_UNCHECKED`, and the submitting login
//! is stored in `Metadata::ReleaseAccount`.
//!
//! When a recipient becomes due, this gate asks the same hook again with
//! `context.futureRelease = "release"` for that login:
//! - accept: the hook has charged the quota; the flag is cleared and delivery proceeds;
//! - 4xx reject, timeout or outage: nothing was charged; the recipient waits on the
//!   queue retry schedule (its expiry is kept, so a long hold is not cut short) and
//!   is asked again; on expiry the sender gets the usual DSN;
//! - anything else: permanent failure with the hook's message, DSN to the sender.

use crate::queue::{
    Error, ErrorDetails, MessageWrapper, Metadata, RCPT_RELEASE_UNCHECKED, Status,
};
use common::{Server, config::smtp::session::Stage};
use std::time::Duration;
use store::write::now;
use utils::HttpLimitResponse;

/// The gate runs inside a delivery task; do not hold it for the full hook timeout.
const MAX_WAIT: Duration = Duration::from_secs(10);
/// Longest hook message copied into a DSN.
const MAX_REASON: usize = 300;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReleaseCheck {
    /// The hook accepted and charged the quota.
    Allowed,
    /// Definitive refusal; the text goes into the DSN.
    Denied(String),
    /// Temporary refusal (limit window full) or hook unavailable; ask again later.
    Wait(String),
}

impl MessageWrapper {
    /// Asks the RCPT hook for every due recipient that has not been released yet.
    /// Recipients that must wait are rescheduled and refused ones fail, so the
    /// ordinary delivery loop afterwards only sees recipients that may go now.
    pub(super) async fn release_gate(&mut self, server: &Server) {
        if !self
            .message
            .recipients
            .iter()
            .any(|rcpt| rcpt.flags & RCPT_RELEASE_UNCHECKED != 0)
        {
            return;
        }
        let now = now();
        let due: Vec<usize> = self
            .message
            .recipients
            .iter()
            .enumerate()
            .filter(|(_, rcpt)| {
                rcpt.flags & RCPT_RELEASE_UNCHECKED != 0
                    && matches!(&rcpt.status, Status::Scheduled | Status::TemporaryFailure(_))
                    && rcpt.retry.due <= now
                    && rcpt.queue == self.queue_name
            })
            .map(|(idx, _)| idx)
            .collect();
        if due.is_empty() {
            return;
        }

        let login = self.message.metadata.iter().find_map(|metadata| match metadata {
            Metadata::ReleaseAccount { value, .. } => {
                std::str::from_utf8(value).ok().map(str::to_string)
            }
            _ => None,
        });

        // The hook counts messages in its hourly window on the first recipient of a
        // submission, so number the recipients released in this pass.
        let mut released: Vec<String> = Vec::with_capacity(due.len());
        for idx in due {
            let address = self.message.recipients[idx].address().to_string();
            let check = match &login {
                Some(login) if !login.is_empty() => {
                    let mut envelope_to = released.clone();
                    envelope_to.push(address.clone());
                    release_check(server, login, &self.message.return_path, &envelope_to)
                        .await
                }
                // A held message always carries its login; without it nobody can be
                // charged, so it must not leave.
                _ => ReleaseCheck::Denied("Scheduled message has no submitting account.".into()),
            };
            match check {
                ReleaseCheck::Allowed => {
                    trc::event!(
                        Delivery(trc::DeliveryEvent::RcptTo),
                        SpanId = self.span_id,
                        To = address.clone(),
                        Details = "Held message released by the sending policy.",
                    );
                    self.message.recipients[idx].flags &= !RCPT_RELEASE_UNCHECKED;
                    released.push(address);
                }
                ReleaseCheck::Denied(reason) => {
                    trc::event!(
                        Delivery(trc::DeliveryEvent::RcptToRejected),
                        SpanId = self.span_id,
                        To = address,
                        Details = reason.clone(),
                    );
                    self.message.recipients[idx].flags &= !RCPT_RELEASE_UNCHECKED;
                    self.message.recipients[idx].status = Status::PermanentFailure(ErrorDetails {
                        entity: "localhost".into(),
                        details: Error::Io(reason.into_boxed_str()),
                    });
                }
                ReleaseCheck::Wait(reason) => {
                    trc::event!(
                        Queue(trc::QueueEvent::Rescheduled),
                        SpanId = self.span_id,
                        To = address,
                        Details = reason.clone(),
                    );
                    self.release_wait(idx, reason, server).await;
                }
            }
        }
    }

    /// Reschedules on the queue retry intervals but keeps the expiry set at
    /// submission (`future_release + ttl`); `set_rcpt_status` would reset it.
    async fn release_wait(&mut self, idx: usize, reason: String, server: &Server) {
        let envelope = crate::queue::QueueEnvelope::new(&self.message, &self.message.recipients[idx]);
        let queue = server.get_queue_or_default(
            &server
                .eval_if::<String, _>(&server.core.smtp.queue.queue, &envelope, self.span_id)
                .await
                .unwrap_or_else(|| "default".to_string()),
            self.span_id,
        );
        let rcpt = &mut self.message.recipients[idx];
        rcpt.status = Status::TemporaryFailure(ErrorDetails {
            entity: "localhost".into(),
            details: Error::Io(reason.into_boxed_str()),
        });
        let interval = queue
            .retry
            .get(std::cmp::min(rcpt.retry.inner as usize, queue.retry.len().saturating_sub(1)))
            .copied()
            .unwrap_or(300);
        rcpt.retry.due = now() + interval;
        rcpt.retry.inner += 1;
    }
}

async fn release_check(
    server: &Server,
    login: &str,
    return_path: &str,
    envelope_to: &[String],
) -> ReleaseCheck {
    let Some(hook) = server
        .core
        .smtp
        .session
        .hooks
        .iter()
        .find(|hook| hook.run_on_stage.contains(&Stage::Rcpt))
    else {
        return ReleaseCheck::Wait("Sending policy unavailable.".into());
    };

    let body = serde_json::json!({
        "context": {
            "stage": "rcpt",
            "sasl": { "login": login },
            "futureRelease": "release",
        },
        "envelope": {
            "from": { "address": return_path },
            "to": envelope_to
                .iter()
                .map(|address| serde_json::json!({ "address": address }))
                .collect::<Vec<_>>(),
        },
    });

    let request = hook
        .client
        .post(&hook.url)
        .timeout(hook.timeout.min(MAX_WAIT))
        .headers(hook.headers.clone())
        .body(body.to_string())
        .send();
    match tokio::time::timeout(MAX_WAIT, request).await {
        Ok(Ok(response)) if response.status().is_success() => {
            match response.bytes_with_limit(hook.max_response_size).await {
                Ok(Some(bytes)) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                    Ok(value) => release_verdict(&value),
                    Err(_) => ReleaseCheck::Denied("Invalid sending policy response.".into()),
                },
                _ => ReleaseCheck::Wait("Sending policy unavailable.".into()),
            }
        }
        _ => ReleaseCheck::Wait("Sending policy unavailable.".into()),
    }
}

fn release_verdict(value: &serde_json::Value) -> ReleaseCheck {
    let reason = value
        .pointer("/response/message")
        .and_then(|message| message.as_str())
        .map(|message| {
            let message: String = message
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_REASON)
                .collect();
            message
        })
        .filter(|message| !message.is_empty());
    match value.get("action").and_then(|action| action.as_str()) {
        Some("accept") => ReleaseCheck::Allowed,
        Some("reject")
            if value
                .pointer("/response/status")
                .and_then(|status| status.as_u64())
                .is_some_and(|status| (400..500).contains(&status)) =>
        {
            ReleaseCheck::Wait(reason.unwrap_or_else(|| "Sending limit reached.".into()))
        }
        _ => ReleaseCheck::Denied(
            reason.unwrap_or_else(|| "Scheduled message refused by sending policy.".into()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{ReleaseCheck, release_verdict};

    #[test]
    fn release_verdicts() {
        assert_eq!(
            release_verdict(&serde_json::json!({"action": "accept"})),
            ReleaseCheck::Allowed
        );
        assert_eq!(
            release_verdict(&serde_json::json!({"action": "reject",
                "response": {"status": 451, "message": "Hourly limit\r\nreached."}})),
            ReleaseCheck::Wait("Hourly limitreached.".into())
        );
        assert_eq!(
            release_verdict(&serde_json::json!({"action": "reject",
                "response": {"status": 550, "message": "Sending is suspended."}})),
            ReleaseCheck::Denied("Sending is suspended.".into())
        );
        assert_eq!(
            release_verdict(&serde_json::json!({"action": "reject", "response": {"status": 451}})),
            ReleaseCheck::Wait("Sending limit reached.".into())
        );
        assert!(matches!(
            release_verdict(&serde_json::json!({"action": "quarantine"})),
            ReleaseCheck::Denied(_)
        ));
        assert!(matches!(release_verdict(&serde_json::json!({})), ReleaseCheck::Denied(_)));
    }

    #[test]
    fn release_reason_is_bounded() {
        let long = "x".repeat(1000);
        let ReleaseCheck::Denied(reason) = release_verdict(&serde_json::json!({
            "action": "reject", "response": {"status": 550, "message": long}}))
        else {
            panic!("expected a denial");
        };
        assert_eq!(reason.len(), 300);
    }
}
