# Namailu fork of Stalwart 0.16.26

Nine changes on top of upstream `v0.16.26`; everything else is untouched.

| area | change |
|---|---|
| `crates/directory/src/backend/oidc/*`, `crates/http/src/auth/authenticate.rs` | unified HUMAN password: Basic credentials are verified against the identity provider (below) |
| `crates/http/src/request.rs` | the JMAP session document builds its URLs from the requested host (below) |
| `crates/directory/src/backend/oidc/*`, `crates/directory/src/core/dispatch.rs` and its two callers | OIDC discovery is fetched lazily and retried; a provider that is down at boot no longer leaves the directory dead (below) |
| `crates/email/src/sieve/outbound_hook.rs`, `crates/email/src/sieve/ingest.rs` | mail sent by a user Sieve script (redirect, vacation, notify) asks the RCPT-stage MTA hook first (below) |
| `crates/smtp/src/core/mod.rs`, `crates/smtp/src/inbound/{data,session}.rs`, `crates/smtp/src/inbound/hooks/message.rs` | the DATA-stage MTA hook receives the spam filter score as `serverHeaders` `X-Spam-Score` (below) |
| `crates/email/src/message/ingest.rs`, `crates/jmap/src/email/{import,set}.rs`, `crates/imap/src/op/append.rs` | client ingest (JMAP `Email/import`, `Email/set`, IMAP `APPEND`) strips server-owned verdict headers (below) |
| `crates/imap/src/op/authenticate.rs`, `crates/pop3/src/op/authenticate.rs` | an authentication backend error is answered as a temporary failure, not as a wrong password (below) |
| `crates/smtp/src/inbound/data.rs`, `crates/smtp/src/inbound/hooks/{message,mod}.rs` | the DATA-stage MTA hook runs last, on the exact bytes that will be queued; afterwards only its verdict headers may change (below) |
| `crates/smtp/src/inbound/{data,dkim}.rs`, `crates/common/src/{cache/principals,config/smtp/auth}.rs`, `crates/registry/src/schema/structs_impl.rs` | authenticated mail gets a server-owned, DKIM-signed Google Feedback-ID (below) |

## Google Feedback Loop header

For authenticated SMTP submission (including JMAP EmailSubmission's local SMTP
session), the fork removes any client-supplied top-level `Feedback-ID`, including
duplicates and folded lines, and adds exactly one server-owned value before the
DATA-stage scanner and DKIM signing. Its format is
`<org-tag>:<account-tag>:mail:namailu`; each tag is the first 12 hex digits of
a keyed BLAKE3 hash of a Stalwart registry ID, keyed from
`STALWART_FEEDBACK_ID_KEY` (at least 32 characters). Recipients therefore never
see internal sequential IDs, while the value stays stable across messages from
one account and is never derived from message content or recipients. The org tag
is the Stalwart tenant when there is one; Namailu does not use tenants, so it falls
back to the domain of the account's primary address (a customer's own domain is one
organisation; accounts on the shared domains share it and differ by account tag).
Without the
key no Feedback-ID is added at all; client-supplied values are still removed.
Unauthenticated inbound mail is not rewritten by this rule.

`Feedback-ID` is included in the default DKIM1 signed header set for new keys.
The authenticated signer also appends it at runtime to the persisted header
set of older keys, so existing domains do not require key rotation or a
registry migration. Non-authenticated messages, including Sieve redirects,
use the same DKIM key without signing a Feedback-ID copied from the original
sender. The DATA hook receives the same normalized header that will be queued
and signed. [Google's Feedback Loop](https://support.google.com/mail/answer/6254652?hl=en)
only publishes aggregate data for sufficiently large `@gmail.com` traffic;
it does not return individual complaints.

## Backend errors are not wrong passwords

When the directory cannot decide (`auth.error`, e.g. the password verification endpoint
answers 502 for a few seconds during a control-plane deploy), upstream IMAP answers
`NO [AUTHENTICATIONFAILED]`, the same as a wrong password. iOS Mail then treats the stored
password as invalid and stops using it until the user re-enters it (seen 10 Oct 2026: one
account stayed offline for three days after a 2-second 502). The fork answers
`NO [UNAVAILABLE]` (RFC 5530) on IMAP and `-ERR [SYS/TEMP]` (RFC 3206, `RESP-CODES` is
advertised) on POP3; SMTP already answered `454 4.7.0`. The original reason stays in the
log event. `auth.error` was never counted by the auth fail2ban, so nothing changes there.

## Client ingest cannot carry server verdicts

JMAP `Email/import`, `Email/set` and IMAP `APPEND` store bytes the client supplies,
bypassing the SMTP DATA hook that writes `X-Namailu-Scan-*`. `strip_untrusted_ingest_headers`
removes `X-Namailu-*`, `X-Spam-*`, `Authentication-Results` and `Received-SPF` (with folded
continuations, bare CR line ends and whitespace before the colon) before parsing and storing,
so an imported file cannot claim to be ClamAV-clean or carry a forged DKIM/SPF verdict.
Before storing, the same bytes go to the content scanner's `/scan-message` (URL derived from
the single HTTPS `/mta-hook` hook, same Bearer auth and TLS). The response must carry
`engine=clamav` and the SHA-256 of the exact bytes; `malware`/`suspicious`/`limit` → 550,
scanner unreachable, misconfigured or more than one matching hook → 451 (fail closed).
This applies to every client write, including webmail drafts and Sent copies.
The control plane additionally rescans attachment bytes on every API/MCP download.

## Outgoing Sieve mail asks the MTA hook

Upstream queues the messages a user Sieve script sends (`redirect`, `vacation`,
`notify`) directly, without an SMTP session, so no MTA hook, milter or rate limit
sees them. A deployment that enforces per-account sending limits in its RCPT hook
is then bypassed by a one-line filter or by the account's forwarding, and the mail
still leaves from the deployment's IP.

The fork sends each recipient of such a message to the first MTA hook that runs on
the RCPT stage, as a request shaped like an RCPT call: `context.stage = "rcpt"`,
`context.sasl.login` = the account, envelope from the account to the recipient, plus
`context.sieve` = `"redirect"` (the received message) or `"message"` (created by the
script). Only `"action": "accept"` lets the copy out. Errors, timeouts (capped at
10 s) and rejections drop it; the received message itself is never lost, because
the existing fail-safe files it into the inbox when no other action kept it.
Without an RCPT hook configured, behaviour is unchanged.

## Delayed send charges the quota at release

A deployment that charges per-account sending quota in its RCPT hook charges a
held message (`HOLDFOR`/`HOLDUNTIL`, JMAP `EmailSubmission` with a send time) when
it is submitted, although it leaves days later. A client can then stockpile several
days of quota into one release window, and a message held before the account is
suspended still goes out.

The fork keeps delayed send but moves the charge to the release:

- A hold needs an authenticated session and an RCPT-stage MTA hook; otherwise
  `MAIL FROM` answers `501 5.5.4` whatever the `futureRelease` expression says.
- RCPT (and DATA) hook calls of a held submission carry
  `context.futureRelease = "hold"`, so the hook can check the account without
  charging. Each recipient is queued with `RCPT_RELEASE_UNCHECKED` and the login is
  stored in `Metadata::ReleaseAccount`.
- When such a recipient is due, `outbound/release_gate.rs` asks the same hook,
  shaped like an RCPT call for that login, with `context.futureRelease = "release"`
  and the envelope from the return path to the recipients released so far.
  `accept` clears the flag and delivery proceeds. A `4xx` reject, a timeout (10 s)
  or an unreachable hook keeps the recipient waiting on the queue retry intervals;
  the expiry set at submission is kept, so the sender gets the usual DSN if the
  window never opens. Any other answer fails the recipient with the hook's message.

`Metadata::ReleaseAccount` is appended with the same shape as `Headers`, so queue
archives written before it still read. A binary without it cannot read a held
message that carries it: roll back only with no held messages in the queue.
Messages held by a binary without the gate carry no flag and are not checked.

## The DATA hook sees the exact queued bytes

Upstream runs the DATA-stage MTA hook before milter changes and the trusted DATA
Sieve script, sends the body as lossy UTF-8 text, and applies the hook's accept
modifications through the generic milter rewriter, which re-serialises every
header. A scanner could therefore approve bytes that a later filter replaced, and
8BITMIME bodies were scanned in a different form than they were delivered.

The fork applies milter changes and the DATA Sieve script first, then sends the
hook the final message (server headers included) once, as `message.rawBase64`,
with `contents` left empty and the final envelope. A DATA filter that adds or
duplicates a recipient that did not pass RCPT — where quotas and gateway
restrictions are charged — is answered `451 4.3.0`. From the hook's accept
answer only `X-Namailu-Scan-Status` / `X-Namailu-Scan-Engine` additions and
deletions of scanner-owned headers are applied, byte-preserving; any other
modification, or a missing verdict, is `451 4.3.0` (fail closed). The deployed
scanner must understand `rawBase64` on the DATA stage before this build runs.

## Spam score for the MTA hook

Upstream sends `serverHeaders` empty, so a DATA-stage hook cannot see the spam
verdict — and it does not classify authenticated sessions at all, so outgoing mail
is never scored. The fork scores authenticated mail in a score-only pass
(`spam_score_outgoing`: no headers added, nothing trained, local recipients' spam
flags untouched). The fork keeps the score of the message being processed in `SessionData`
(reset for every message) and sends it as `["X-Spam-Score", "<score>"]`. A deployment
can then apply its own policy — Namailu rejects authenticated (outgoing) mail from the
spam threshold instead of the global reject score, which otherwise only tags such mail
and lets it out. No score (filter disabled or not run) = no header.

## Lazy OIDC discovery

Upstream fetches the OIDC discovery document and JWKS once, inside
`OpenIdDirectory::open`, and fails the directory when the provider is not
reachable. The server then starts without that directory and every
authentication for its domains fails until a restart — which is exactly what
happens when the mail server boots before the identity provider on the same
host.

The fork keeps the directory alive: the discovery document is fetched on first
use (`OpenIdDirectory::discovery`), the startup fetch is only an eager attempt
that logs a warning on failure, concurrent callers share one fetch, and a
failed attempt is not repeated for two seconds so an outage of the provider
does not turn every login into a discovery round-trip. Validation of the
document (issuer match, HTTPS password-verification endpoint on the issuer
host, scope and claim warnings) is unchanged, only moved. The two upstream
places that read the document synchronously (`get_pacc_for_domain` and the
per-domain OAuth metadata) now await it and fall back to the server's own
metadata when it is unavailable, as they already did for domains without an
OIDC directory.

## Unified HUMAN password

This fork keeps the regular Stalwart OIDC Bearer flow and AppPassword flow intact,
and adds an intentionally narrow Basic-auth bridge for HUMAN accounts.

When the OIDC discovery document advertises
`password_verification_endpoint`, IMAP/SMTP/POP3 Basic credentials are POSTed
over HTTPS to that endpoint. The request uses the service bearer token from
`STALWART_OIDC_BASIC_AUTH_TOKEN`. A `204 No Content` response authenticates the
account; failure responses disclose no account data.

Security properties:

- the endpoint must be HTTPS, contain no userinfo, and use the issuer hostname;
- redirects and environment HTTP proxies are disabled for the OIDC client;
- password hashes, tokens, profiles, and sessions are never returned;
- the existing OIDC Bearer and scoped AppPassword paths are unchanged;
- the deployment additionally restricts the endpoint with an internal TLS
  listener, source ACL, service bearer, rate limits, and bounded Argon2 work;
- a verified HTTP Basic credential is cached for at most 60 seconds (upstream
  caches it for the whole OAuth token lifetime). The password lives in the IdP,
  so changing it does not bump the Stalwart account revision; the short cache
  is what makes an old password stop working over CalDAV/CardDAV/JMAP within a
  minute. IMAP/SMTP/POP3 verify on every login and are unaffected.

## JMAP session follows the requested host

Upstream builds the absolute URLs in the JMAP session document (`apiUrl`,
`uploadUrl`, `downloadUrl`, `eventSourceUrl`, websocket) from one configured
public URL. A deployment that serves several brands on one server therefore
tells a client that discovered the server on one hostname to continue on
another one.

With `STALWART_PUBLIC_URL_HOSTS=example.org,example.net` the session document
follows the host the request came in on. The host header is untrusted input, so
it is used only when it matches that allowlist exactly; anything else — including
a spoofed `Host` — falls back to `STALWART_PUBLIC_URL`, which keeps serving the
OAuth metadata, its issuer and the web admin links. Those must stay on one
stable host, so they are deliberately left alone. Unset or empty keeps the
upstream behaviour.

The provided image enables the PostgreSQL metadata and S3-compatible blob
backends used by Namailu. Build it with:

```sh
docker build -f Dockerfile.namailu \
  -t namailu/stalwart:v0.16.26-unified-password .
```

The fork remains licensed under the upstream AGPL-3.0-only option. The complete
corresponding source of the running modified version is published at
<https://github.com/mailows/Stalwart-namailu>, branch `namailu-unified-password`
(public). The primary development repository is `git.facilitygo.com/filip/Stalwart`
(private since spam); the GitHub copy is pushed after every deployed change.

## Rebase onto v0.16.26 (13 Oct 2026)

- 26 fork commits applied onto `v0.16.26` without conflicts. Upstream changes worth knowing:
  IMAP `LOGIN`/`AUTHENTICATE` with a wrong app password now gets a tagged `NO` (clients
  waited for a timeout before), OIDC builds the account from `email` when `claimUsername`
  is missing, DKIM, DNSBL and RocksDB fixes, patched hickory-dns fork with DNSSEC fixes.

## Rebase onto v0.16.23 (25 Sep 2026)

- `oidc/config.rs`: upstream v0.16.22 added a 30 s discovery retry at boot and marks a
  failed directory as `Directory::Unavailable` for the rest of the process lifetime. The
  fork keeps its lazy discovery instead (the provider may be down for longer than 30 s
  when the whole host boots), so our version of this file replaces upstream's. Upstream's
  `OidcError::Config` / `is_transient` stay in `mod.rs`, unused by the fork.
- `core/dispatch.rs`: both imports kept (upstream `DirectoryType`, fork `Arc`).
- v0.16.23 serialises the DNSSEC resolver to one nameserver at a time (hickory TCP-retry
  race). Checked before adding any fork-side fallback for "DNSSEC validation failed".
