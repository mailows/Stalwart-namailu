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
| 9 | DATA hook on the exact queued bytes, only verdict headers after it | todo | |
| 10 | spam score for the hook also for authenticated mail (`X-Spam-Score`) | todo | |
| 11 | `verifiedEnvelopeSender`, `dkimVerifiedFrom` in the hook context | ported | `crates/smtp/src/{core/mod,inbound/{mail,session,data}}.rs`, `crates/smtp/src/inbound/hooks/{mod,message}.rs` |
| 12 | scan + strip verdict headers on JMAP import/set and IMAP APPEND | todo | |
| 13 | Google FBL: server-owned, DKIM-signed Feedback-ID | todo | |

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

## Build

`Dockerfile.namailu` builds the binary with the features the deployment uses
(`postgres s3`) on top of the official `stalwartlabs/stalwart:v1.0.3` image.
