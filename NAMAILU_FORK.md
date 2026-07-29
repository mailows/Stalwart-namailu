# Namailu fork: unified HUMAN password

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

The provided image enables the PostgreSQL metadata and S3-compatible blob
backends used by Namailu. Build it with:

```sh
docker build -f Dockerfile.namailu \
  -t namailu/stalwart:v0.16.14-unified-password .
```

The fork remains licensed under the upstream AGPL-3.0-only option. Source for the
running modified version is published at
<https://git.facilitygo.com/filip/stalwart>.
