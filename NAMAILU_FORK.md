# Namailu fork of Stalwart 1.0.3 (port in progress)

Branch `namailu-1.0` on top of upstream `v1.0.3`. It carries the changes of the
0.16.26 fork (`namailu-unified-password`, `bad1ab44a`) ported by hand: 1.0 is a
rewrite and none of them applies as a patch. Plan and status:
`mail-server/PLAN_STALWART_1.0.md` in the runbook. Every change is marked
`naMailu fork` in the code and has unit tests in a `namailu_*tests` module
(upstream ships no tests with 1.0).

| # | change | status | files |
|---|---|---|---|
| 1 | unified HUMAN password: Basic credentials verified by the IdP (`password_verification_endpoint`) | ported | `crates/directory/src/backend/oidc/{mod,config,lookup}.rs` |
| 2 | HTTP Basic credential cache capped at 60 s | ported (Bearer is bounded by `exp` upstream) | `crates/http/src/auth/authenticate.rs` |
| 3 | lazy OIDC discovery: a provider that is down at boot does not leave the directory unavailable | ported | `crates/directory/src/backend/oidc/*`, `crates/directory/src/core/dispatch.rs` and its four callers |
| 4 | JMAP session URLs follow the requested host (`STALWART_PUBLIC_URL_HOSTS`) | ported | `crates/http/src/request.rs` |
| 5 | authentication backend error = temporary failure (IMAP `[UNAVAILABLE]`, POP3 `[SYS/TEMP]`) | ported | `crates/{imap,pop3}/src/op/authenticate.rs` |
| 6 | default calendar / address book names without the account name | ported | `crates/groupware/src/cache/mod.rs` |
| 7 | outgoing Sieve (redirect/vacation) asks the RCPT hook, bound to the account | todo | |
| 8 | delayed send with a release-time quota gate | todo | |
| 9 | DATA hook on the exact queued bytes, only verdict headers after it | ported | `crates/smtp/src/inbound/data.rs`, `crates/smtp/src/inbound/hooks/{mod,message}.rs` |
| 10 | spam score for the hook also for authenticated mail (`X-Spam-Score`, `X-Spam-Tags`) | ported | `crates/spam-filter/src/analysis/outgoing.rs`, `crates/smtp/src/inbound/{spam,data}.rs`, `crates/smtp/src/inbound/hooks/message.rs` |
| 11 | `verifiedEnvelopeSender`, `dkimVerifiedFrom` in the hook context | ported | `crates/smtp/src/{core/mod,inbound/{mail,session,data}}.rs`, `crates/smtp/src/inbound/hooks/{mod,message}.rs` |
| 12 | scan + strip verdict headers on JMAP import/set and IMAP APPEND | ported | `crates/email/src/message/ingest.rs`, `crates/jmap/src/email/{import,set}.rs`, `crates/imap/src/op/append.rs` |
| 13 | Google FBL: server-owned, DKIM-signed Feedback-ID | ported | `crates/smtp/src/inbound/{data,dkim}.rs`, `crates/common/src/config/smtp/auth.rs` |

## Unified password (1, 3, 5)

The OIDC directory reads the private `password_verification_endpoint` from the
provider metadata. 1.0 fetches `/.well-known/oauth-authorization-server` first and
the OpenID configuration second; the Namailu IdP serves the same document on both.
The endpoint must be HTTPS on the issuer's host without userinfo, otherwise
discovery fails. Stalwart POSTs `{"username","password"}` with the bearer token
from `STALWART_OIDC_BASIC_AUTH_TOKEN` (never logged, not in the registry).
`204` = valid, `401/403/429` = invalid credentials, anything else, a network
error or a missing token = provider error. A provider error is answered as a
temporary failure (IMAP `NO [UNAVAILABLE]`, POP3 `-ERR [SYS/TEMP]`, SMTP `454
4.7.0`) and is not counted by the auth fail2ban, so a client never drops a stored
password because the IdP was briefly down. App passwords are checked by Stalwart
before the directory and never reach the endpoint.

Upstream retries discovery for 30 s at startup and then marks the directory
`Unavailable` until the next configuration reload (and a reload with a failing
directory is rejected as a whole). The fork tries once at startup; a transient
failure only logs a warning and the first use retries, at most one attempt per
2 s while the provider is down. A misconfiguration (issuer mismatch, missing
introspection endpoint) still fails the directory at startup. The HTTP timeout
towards the provider is 10 s instead of 30 s.

## Spam score for the hook (10)

Upstream does not classify authenticated sessions. The fork scores them for the
DATA-stage MTA hook only: `serverHeaders` carry `X-Spam-Score` (all mail that was
scored) and `X-Spam-Tags` (authenticated mail). Nothing is added to the message,
nothing is trained and recipients' spam flags are untouched; the hook decides.
For authenticated mail only content tags are added up; tags about the sending
infrastructure (SPF/DKIM/DMARC/ARC, RBL, rDNS, HELO, Received, IP/ASN, AUTH) are
listed with `*` but not counted, because they describe our own server.

## Client ingest (12)

JMAP `Email/import`, `Email/set` and IMAP `APPEND` store bytes the client supplies
and bypass the SMTP DATA hook that writes `X-Namailu-Scan-*`.
`strip_untrusted_ingest_headers` removes `X-Namailu-*`, `X-Spam-*`,
`Authentication-Results` and `Received-SPF` (with folded continuation lines, bare
CR line ends and space before the colon) on all three paths. Before storing,
`email_ingest_into` sends the bytes to the scanner (`<hook base>/scan-message`,
the single HTTPS `/mta-hook` with its headers and client). The verdict must name
`engine=clamav` and the SHA-256 of exactly these bytes; `malware`, `suspicious`
and `limit` are refused (550), anything else that is not clean, a missing scanner
or a network error is a temporary failure (451). An imported blob that was
stripped is stored as a new blob.

## DATA hook on the exact queued bytes (9)

Upstream runs the DATA hook on the received message, before milter changes and
trusted DATA Sieve, and applies its answer through the generic milter modifier,
which rewrites every header. The fork applies milter changes first, runs Sieve,
normalizes `Feedback-ID` (13) and then runs the hook last on exactly the bytes
that will be queued (`message.rawBase64`; the lossy text `contents` is empty at
DATA) with the final envelope. After the hook only `X-Namailu-Scan-Status`,
`X-Namailu-Scan-Engine` (both required) and the removal of
`X-Namailu-Quarantine-Release` are applied, byte for byte; any other change, or a
missing verdict, is `451 4.3.0`. A milter or Sieve that adds or duplicates a
recipient not authorized at RCPT (where quotas and agent restrictions are
charged) is `451`. If a filter changed the message, `dkimVerifiedFrom` is
dropped and authenticated mail is scored again on the final bytes.

## Google Feedback Loop header (13)

Authenticated submission: every client `Feedback-ID` (with folded lines) is
removed and one server-owned value is added before the DATA hook:
`<org-tag>:<account-tag>:mail:namailu`, each tag the first 12 hex digits of a
keyed BLAKE3 hash of a Stalwart id, keyed from `STALWART_FEEDBACK_ID_KEY` (at least
32 characters; without it no header is added, client values are still removed).
Same KDF context as the 0.16 fork, so tags stay identical as long as account and
domain ids survive the migration. The org tag is the tenant if there is one (not
with the `postgres s3` build), otherwise the domain of the account's primary
address. Authenticated mail is DKIM1-signed by a second set of signers built from
the same keys that always cover `Feedback-ID`, also for older keys whose persisted
header list lacks it; other mail never signs a `Feedback-ID`. (The registry
default header list is generated code and left unchanged.)

## Build

`Dockerfile.namailu` builds the binary with the features the deployment uses
(`postgres s3`) on top of the official `stalwartlabs/stalwart:v1.0.3` image.
