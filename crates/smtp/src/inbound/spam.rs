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
        let server = &self.server;
        let mut ctx = server.spam_filter_init(self.build_spam_input(
            message,
            dkim_result,
            dkim2_result,
            arc_result,
            dmarc_result,
            dmarc_policy,
        ));
        if matches!(
            server.spam_filter_classify(&mut ctx).await,
            SpamFilterAction::Disabled
        ) {
            return None;
        }
        let strong = server
            .core
            .spam
            .scores
            .reject_threshold
            .max(server.core.spam.scores.spam_threshold);
        let mut total = 0.0f32;
        let mut listed: Vec<(&str, f32, bool)> = Vec::new();
        for tag in &ctx.result.tags {
            let score = match server.core.spam.lists.scores.get(tag) {
                Some(SpamFilterAction::Allow(score)) => *score,
                Some(SpamFilterAction::Reject) | Some(SpamFilterAction::Discard) => strong,
                None | Some(SpamFilterAction::Disabled) => 0.0,
            };
            if score == 0.0 {
                continue;
            }
            let infra = is_infrastructure_tag(tag);
            if !infra {
                total += score;
            }
            listed.push((tag.as_str(), score, infra));
        }
        listed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let mut tags = String::new();
        for (tag, score, infra) in listed.into_iter().take(40) {
            if !tags.is_empty() {
                tags.push(' ');
            }
            tags.push_str(&format!("{tag}({score:.1}){}", if infra { "*" } else { "" }));
        }
        Some((total, tags))
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

/// Tags describing the sending infrastructure rather than the message. For
/// authenticated mail that infrastructure is the operator's own server.
fn is_infrastructure_tag(tag: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "SPF_", "R_SPF", "DKIM", "R_DKIM", "DMARC_", "ARC_", "RBL_", "RWL_", "DNSWL_",
        "RDNS_", "HELO_", "RCVD_", "IP_", "ASN", "AUTH_", "VIOLATED_DIRECT_SPF",
        "FORGED_RCVD_TRAIL", "PREVIOUSLY_DELIVERED", "MAILSPIKE", "SENDERSCORE",
    ];
    PREFIXES.iter().any(|p| tag.starts_with(p))
}
