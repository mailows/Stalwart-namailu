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
//! The RCPT quota reserved at generation time is not reserved again; a recipient
//! whose RCPT hook did not answer then (`RCPT_SIEVE_UNCHECKED`) is asked here
//! first, exactly once per successful answer.

use crate::queue::{
    Error, ErrorDetails, FROM_SCAN_PENDING, FROM_SIEVE_REDIRECT, MessageWrapper,
    RCPT_SIEVE_UNCHECKED, Status,
};
use common::Server;
use email::sieve::outbound_hook::{
    SieveDataScan, SieveRcptCheck, sieve_data_scan, sieve_outbound_check,
};
use store::write::now;

impl MessageWrapper {
    /// Returns `true` when delivery must stop now (message saved for a later scan).
    pub(super) async fn scan_pending_gate(&mut self, server: &Server) -> bool {
        if self.message.flags & FROM_SCAN_PENDING == 0
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

        // RCPT permission and quota for recipients nobody has asked about yet.
        let is_redirect = self.message.flags & FROM_SIEVE_REDIRECT != 0;
        let mut waiting = false;
        for &idx in &due {
            if self.message.recipients[idx].flags & RCPT_SIEVE_UNCHECKED == 0 {
                continue;
            }
            let address = self.message.recipients[idx].address().to_string();
            match sieve_outbound_check(
                server,
                &self.message.return_path,
                &address,
                is_redirect,
                self.span_id,
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
