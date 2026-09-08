# Namailu fork of Stalwart 0.16.14

Two changes on top of upstream `v0.16.14`; everything else is untouched.

| area | change |
|---|---|
| `crates/directory/src/backend/oidc/*`, `crates/http/src/auth/authenticate.rs` | unified HUMAN password: Basic credentials are verified against the identity provider (below) |
| `crates/http/src/request.rs` | the JMAP session document builds its URLs from the requested host (below) |

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
  -t namailu/stalwart:v0.16.21-unified-password .
```

The fork remains licensed under the upstream AGPL-3.0-only option. The complete
corresponding source of the running modified version is published at
<https://git.facilitygo.com/filip/Stalwart>, branch `namailu-unified-password`,
which is publicly readable.
