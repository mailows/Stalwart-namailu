/*
 * SPDX-FileCopyrightText: 2026 namailu.cz
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Fork: durable retry of the final DATA scan for generated Sieve messages.
//!
//! When the scanner is unavailable while a Sieve script generates a message
//! (vacation, redirect), the copy is queued with `FROM_SCAN_PENDING` instead of
//! being dropped. Before any delivery attempt the queue scans it again:
//! accept clears the flag, a definitive rejection fails every recipient (DSN to
//! the account), an outage reschedules with the queue retry policy and expiry.
//! The original RCPT reservation has a durable idempotency ID. If its reply was
//! lost, a retry returns that reservation rather than charging the quota again.
//! Before *every* attempt the policy also checks the original account binding
//! and current STOP/suspension state, without charging an approved recipient.

use crate::queue::{
    Error, ErrorDetails, FROM_SCAN_PENDING, FROM_SIEVE_POLICY, FROM_SIEVE_REDIRECT,
    MessageWrapper, Metadata, RCPT_SIEVE_UNCHECKED, Status,
};
use common::Server;
use email::sieve::outbound_hook::{
    SieveDataScan, SievePhase, SieveRcptCheck, sieve_data_scan, sieve_outbound_check,
};
use store::write::now;

impl MessageWrapper {
    /// Returns `true` when delivery must stop now (message saved for a later scan).
    pub(super) async fn scan_pending_gate(&mut self, server: &Server) -> bool {
        // Old redirect queue entries have FROM_SIEVE_REDIRECT but no immutable
        // binding. Hold them for operator review instead of letting a recycled
        // address authorize them after an upgrade.
        if self.message.flags & (FROM_SCAN_PENDING | FROM_SIEVE_POLICY | FROM_SIEVE_REDIRECT) == 0
            && !self
                .message
                .recipients
                .iter()
                .any(|rcpt| rcpt.flags & RCPT_SIEVE_UNCHECKED != 0)
        {
            return false;
        }
        let now = now();
        let mut due: Vec<usize> = self
            .message
            .recipients
            .iter()
            .enumerate()
            .filter(|(_, rcpt)| {
                matches!(&rcpt.status, Status::Scheduled | Status::TemporaryFailure(_))
                    && rcpt.retry.due <= now
                    && rcpt.queue == self.queue_name
            })
            .map(|(idx, _)| idx)
            .collect();
        if due.is_empty() {
            return false;
        }

        // Always check the *original* Sieve account. An address alone can be
        // recycled; old queued copies without this binding must never acquire
        // the new owner's rights.
        let account = sieve_account(&self.message.metadata);
        let Some((login, account_id, generated_at_us, message_id)) = account else {
            trc::event!(
                Sieve(trc::SieveEvent::UnexpectedError),
                SpanId = self.span_id,
                Details = "Queued Sieve copy has no original account binding; operator review required.",
            );
            self.reschedule_scan(&due, server).await;
            return true;
        };

        // Check every due recipient on every delivery attempt. Only a recipient
        // whose original RCPT answer was lost may need a reservation retry.
        let is_redirect = self.message.flags & FROM_SIEVE_REDIRECT != 0;
        let mut waiting = false;
        for &idx in &due {
            let address = self.message.recipients[idx].address().to_string();
            let phase = if self.message.recipients[idx].flags & RCPT_SIEVE_UNCHECKED != 0 {
                SievePhase::Reserve
            } else {
                SievePhase::Check
            };
            match sieve_outbound_check(
                server,
                &login,
                &address,
                is_redirect,
                self.span_id,
                account_id,
                generated_at_us,
                &message_id,
                phase,
            )
            .await
            {
                SieveRcptCheck::Allowed => {
                    self.message.recipients[idx].flags &= !RCPT_SIEVE_UNCHECKED;
                }
                SieveRcptCheck::Denied => {
                    self.message.recipients[idx].flags &= !RCPT_SIEVE_UNCHECKED;
                    self.message.recipients[idx].status = Status::PermanentFailure(ErrorDetails {
                        entity: "localhost".into(),
                        details: Error::Io("Recipient refused by outgoing policy.".into()),
                    });
                }
                SieveRcptCheck::Unavailable => waiting = true,
            }
        }
        due.retain(|&idx| {
            matches!(
                &self.message.recipients[idx].status,
                Status::Scheduled | Status::TemporaryFailure(_)
            )
        });
        if due.is_empty() {
            return false;
        }
        if waiting {
            self.reschedule_scan(&due, server).await;
            return true;
        }
        if self.message.flags & FROM_SCAN_PENDING == 0 {
            return false;
        }

        let recipients: Vec<String> = due
            .iter()
            .map(|&idx| self.message.recipients[idx].address().to_string())
            .collect();
        let verdict = match server
            .blob_store()
            .get_blob(self.message.blob_hash.as_slice(), 0..usize::MAX)
            .await
        {
            Ok(Some(raw)) => {
                sieve_data_scan(server, &self.message.return_path, &recipients, &raw).await
            }
            _ => SieveDataScan::Unavailable,
        };

        match verdict {
            SieveDataScan::Accept(_) => {
                // Queued bytes are delivered as signed; scanner-owned headers are
                // informational for local recipients only.
                self.message.flags &= !FROM_SCAN_PENDING;
                false
            }
            SieveDataScan::Reject => {
                // Never deliver: fail every recipient that is still open, in any queue.
                for idx in 0..self.message.recipients.len() {
                    if matches!(
                        &self.message.recipients[idx].status,
                        Status::Scheduled | Status::TemporaryFailure(_)
                    ) {
                        self.message.recipients[idx].status =
                            Status::PermanentFailure(ErrorDetails {
                                entity: "localhost".into(),
                                details: Error::Io(
                                    "Generated message rejected by outgoing content policy."
                                        .into(),
                                ),
                            });
                    }
                }
                self.message.flags &= !FROM_SCAN_PENDING;
                false
            }
            SieveDataScan::Unavailable => {
                self.reschedule_scan(&due, server).await;
                true
            }
        }
    }

    async fn reschedule_scan(&mut self, due: &[usize], server: &Server) {
        for &idx in due {
            self.set_rcpt_status(
                Status::TemporaryFailure(ErrorDetails {
                    entity: "localhost".into(),
                    details: Error::Io("Outgoing policy or content scan unavailable.".into()),
                }),
                idx,
                server,
            )
            .await;
        }
    }
}

fn sieve_account(metadata: &[Metadata]) -> Option<(String, u32, u64, String)> {
    metadata.iter().find_map(|item| match item {
        Metadata::SieveAccount { value, id } if *id > 0 && *id <= u64::from(u32::MAX) + 1 => {
            let raw = std::str::from_utf8(value).ok()?;
            let mut parts = raw.split('\0');
            let login = parts.next()?;
            let generated_at_us = parts.next()?.parse::<u64>().ok()?;
            let message_id = parts.next()?;
            (parts.next().is_none()
                && !login.is_empty()
                && generated_at_us > 0
                && message_id.len() == 32
                && message_id.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .then(|| (login.to_string(), (*id - 1) as u32,
                          generated_at_us, message_id.to_string()))
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sieve_queue_binding_requires_original_principal_and_nonce() {
        let bound = Metadata::SieveAccount {
            value: format!("{}\0{}\0{}", "agent@example.test", 1790000000000000_u64,
                           "0123456789abcdef0123456789abcdef")
                .into_bytes().into_boxed_slice(),
            id: 43,
        };
        assert_eq!(sieve_account(&[bound.clone()]), Some((
            "agent@example.test".to_string(), 42, 1790000000000000,
            "0123456789abcdef0123456789abcdef".to_string(),
        )));
        assert_eq!(sieve_account(&[]), None);
        assert_eq!(sieve_account(&[Metadata::SieveAccount {
            value: b"agent@example.test\0missing\0bad".to_vec().into_boxed_slice(),
            id: 43,
        }]), None);
    }
}
