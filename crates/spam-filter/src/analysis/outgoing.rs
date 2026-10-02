/*
 * SPDX-FileCopyrightText: 2026 namailu.cz
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Shared content-only scoring for SMTP submission and final Sieve output.
use common::{Server, config::mailstore::spamfilter::SpamFilterAction};
use crate::{SpamFilterInput, analysis::{init::SpamFilterInit, score::SpamFilterAnalyzeScore}};

pub trait SpamFilterScoreOutgoing: Sync + Send {
    fn spam_score_outgoing_input(
        &self,
        input: SpamFilterInput<'_>,
    ) -> impl std::future::Future<Output = Option<(f32, String)>> + Send;
}

impl SpamFilterScoreOutgoing for Server {
    async fn spam_score_outgoing_input(&self, input: SpamFilterInput<'_>) -> Option<(f32, String)> {
        if !self.core.spam.enabled {
            return None;
        }
        let mut ctx = self.spam_filter_init(input);
        if matches!(self.spam_filter_classify(&mut ctx).await, SpamFilterAction::Disabled) {
            return None;
        }
        let strong = self.core.spam.scores.reject_threshold.max(self.core.spam.scores.spam_threshold);
        let mut total = 0.0f32;
        let mut listed: Vec<(&str, f32, bool)> = Vec::new();
        for tag in &ctx.result.tags {
            let score = match self.core.spam.lists.scores.get(tag) {
                Some(SpamFilterAction::Allow(score)) => *score,
                Some(SpamFilterAction::Reject) | Some(SpamFilterAction::Discard) => strong,
                None | Some(SpamFilterAction::Disabled) => 0.0,
            };
            if score == 0.0 { continue; }
            let infra = is_infrastructure_tag(tag);
            if !infra { total += score; }
            listed.push((tag.as_str(), score, infra));
        }
        listed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let mut tags = String::new();
        for (tag, score, infra) in listed.into_iter().take(40) {
            if !tags.is_empty() { tags.push(' '); }
            tags.push_str(&format!("{tag}({score:.1}){}", if infra { "*" } else { "" }));
        }
        Some((total, tags))
    }
}

/// Infrastructure belongs to the operator, not the authenticated message author.
fn is_infrastructure_tag(tag: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "SPF_", "R_SPF", "DKIM", "R_DKIM", "DMARC_", "ARC_", "RBL_", "RWL_", "DNSWL_",
        "RDNS_", "HELO_", "RCVD_", "IP_", "ASN", "AUTH_", "VIOLATED_DIRECT_SPF",
        "FORGED_RCVD_TRAIL", "PREVIOUSLY_DELIVERED", "MAILSPIKE", "SENDERSCORE",
    ];
    PREFIXES.iter().any(|p| tag.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::is_infrastructure_tag;

    #[test]
    fn excludes_infrastructure_but_retains_content_tags() {
        for tag in ["SPF_FAIL", "DKIM_INVALID", "RBL_SPAMHAUS", "RCVD_COUNT_ZERO", "AUTH_NA"] {
            assert!(is_infrastructure_tag(tag), "{tag}");
        }
        for tag in ["GTUBE", "MIME_BAD_ATTACHMENT", "PHISHING", "HTML_SHORT_LINK_IMG", "BAYES_SPAM"] {
            assert!(!is_infrastructure_tag(tag), "{tag}");
        }
    }
}
