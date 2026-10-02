/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use common::{config::mailstore::spamfilter::SpamFilterAction, network::SessionStream};
use mail_auth::{ArcOutput, DkimOutput, DmarcResult, dkim2::Dkim2Output, dmarc::Policy};
use mail_parser::Message;
use spam_filter::{
    SpamFilterInput,
    analysis::{
        init::SpamFilterInit,
        outgoing::SpamFilterScoreOutgoing,
        score::{SpamFilterAnalyzeScore, SpamFilterScore},
    },
};

impl<T: SessionStream> Session<T> {
    pub async fn spam_classify<'x>(
        &'x self,
        message: &'x Message<'x>,
        dkim_result: &'x [DkimOutput<'x>],
        dkim2_result: Option<&'x Dkim2Output<'x>>,
        arc_result: Option<&'x ArcOutput<'x>>,
        dmarc_result: Option<&'x DmarcResult>,
        dmarc_policy: Option<&'x Policy>,
    ) -> SpamFilterAction<SpamFilterScore> {
        let server = &self.server;
        let mut ctx = server.spam_filter_init(self.build_spam_input(
            message,
            dkim_result,
            dkim2_result,
            arc_result,
            dmarc_result,
            dmarc_policy,
        ));

        if !self.is_authenticated() {
            // Spam classification
            server.spam_filter_classify(&mut ctx).await
        } else {
            // Do not classify authenticated sessions
            SpamFilterAction::Disabled
        }
    }

    /// Fork: score an authenticated (outgoing) message without acting on it.
    ///
    /// Upstream does not classify authenticated sessions at all (`spam_classify` above
    /// returns `Disabled`), so an account sending spam from its own mailbox is never
    /// scored. The result only goes to the DATA-stage MTA hook (`serverHeaders`
    /// `X-Spam-Score`, `X-Spam-Tags`); no headers are added, nothing is trained and
    /// local recipients' spam flags are untouched — the hook decides.
    ///
    /// The score counts CONTENT tags only. Tags about the sending infrastructure (IP,
    /// rDNS, EHLO, Received, SPF/DKIM/DMARC/ARC, IP blocklists) describe the operator's
    /// own server for authenticated mail and gave an ordinary message 8.1 points in
    /// testing; they are listed in `X-Spam-Tags` but not added up.
    pub async fn spam_score_outgoing<'x>(
        &'x self,
        message: &'x Message<'x>,
        dkim_result: &'x [DkimOutput<'x>],
        dkim2_result: Option<&'x Dkim2Output<'x>>,
        arc_result: Option<&'x ArcOutput<'x>>,
        dmarc_result: Option<&'x DmarcResult>,
        dmarc_policy: Option<&'x Policy>,
    ) -> Option<(f32, String)> {
        self.server.spam_score_outgoing_input(self.build_spam_input(
            message,
            dkim_result,
            dkim2_result,
            arc_result,
            dmarc_result,
            dmarc_policy,
        )).await
    }

    pub fn build_spam_input<'x>(
        &'x self,
        message: &'x Message<'x>,
        dkim_result: &'x [DkimOutput<'x>],
        dkim2_result: Option<&'x Dkim2Output<'x>>,
        arc_result: Option<&'x ArcOutput>,
        dmarc_result: Option<&'x DmarcResult>,
        dmarc_policy: Option<&'x Policy>,
    ) -> SpamFilterInput<'x> {
        SpamFilterInput {
            message,
            span_id: self.data.session_id,
            arc_result,
            spf_ehlo_result: self.data.spf_ehlo.as_ref(),
            spf_mail_from_result: self.data.spf_mail_from.as_ref(),
            dkim_result,
            dkim2_result,
            dmarc_result,
            dmarc_policy,
            iprev_result: self.data.iprev.as_ref(),
            remote_ip: self.data.remote_ip,
            ehlo_domain: self.data.helo_domain.as_str().into(),
            authenticated_as: self.data.authenticated_as.as_ref().map(|a| a.name()),
            asn: self.data.asn_geo_data.asn.as_ref().map(|a| a.id),
            country: self.data.asn_geo_data.country.as_ref().map(|c| c.as_str()),
            is_tls: self.stream.is_tls(),
            env_from: self
                .data
                .mail_from
                .as_ref()
                .map(|m| m.address_lcase.as_str())
                .unwrap_or_default(),
            env_from_flags: self
                .data
                .mail_from
                .as_ref()
                .map(|m| m.flags)
                .unwrap_or_default(),
            env_rcpt_rewritten_to: self
                .data
                .rcpt_to
                .iter()
                .map(|r| r.address_lcase.as_str())
                .collect(),
            env_rcpt_orig_to: self.data.rcpt_to.iter().map(|r| r.orig_address()).collect(),
            is_test: false,
            is_train: false,
        }
    }
}
