# Namailu fork of Stalwart 0.16.23

Three changes on top of upstream `v0.16.23`; everything else is untouched.

| area | change |
|---|---|
| `crates/directory/src/backend/oidc/*`, `crates/http/src/auth/authenticate.rs` | unified HUMAN password: Basic credentials are verified against the identity provider (below) |
| `crates/http/src/request.rs` | the JMAP session document builds its URLs from the requested host (below) |
| `crates/directory/src/backend/oidc/*`, `crates/directory/src/core/dispatch.rs` and its two callers | OIDC discovery is fetched lazily and retried; a provider that is down at boot no longer leaves the directory dead (below) |

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
  listener, source ACL, service bearer, rate limits, and bounded Argon2 work.

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
  -t namailu/stalwart:v0.16.23-unified-password .
```

The fork remains licensed under the upstream AGPL-3.0-only option. The complete
corresponding source of the running modified version is published at
<https://git.facilitygo.com/filip/Stalwart>, branch `namailu-unified-password`,
which is publicly readable.

## Rebase onto v0.16.23 (25 Sep 2026)

- `oidc/config.rs`: upstream v0.16.22 added a 30 s discovery retry at boot and marks a
  failed directory as `Directory::Unavailable` for the rest of the process lifetime. The
  fork keeps its lazy discovery instead (the provider may be down for longer than 30 s
  when the whole host boots), so our version of this file replaces upstream's. Upstream's
  `OidcError::Config` / `is_transient` stay in `mod.rs`, unused by the fork.
- `core/dispatch.rs`: both imports kept (upstream `DirectoryType`, fork `Arc`).
- v0.16.23 serialises the DNSSEC resolver to one nameserver at a time (hickory TCP-retry
  race). Checked before adding any fork-side fallback for "DNSSEC validation failed".
