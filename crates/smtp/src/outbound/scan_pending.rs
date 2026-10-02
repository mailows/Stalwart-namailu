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
//! The RCPT quota reserved at generation time is not reserved again.

use crate::queue::{Error, ErrorDetails, FROM_SCAN_PENDING, MessageWrapper, Status};
use common::Server;
use email::sieve::outbound_hook::{SieveDataScan, sieve_data_scan};
use store::write::now;

impl MessageWrapper {
    /// Returns `true` when delivery must stop now (message saved for a later scan).
    pub(super) async fn scan_pending_gate(&mut self, server: &Server) -> bool {
        if self.message.flags & FROM_SCAN_PENDING == 0 {
            return false;
        }
        let now = now();
        let due: Vec<usize> = self
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
                for idx in due {
                    self.set_rcpt_status(
                        Status::TemporaryFailure(ErrorDetails {
                            entity: "localhost".into(),
                            details: Error::Io("Final content scan unavailable.".into()),
                        }),
                        idx,
                        server,
                    )
                    .await;
                }
                true
            }
        }
    }
}
