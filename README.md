# marmay-auth

A shared authentication service for applications on one trust domain
(`*.example.com`): Office365/AAD OAuth on the service side, short-lived
single-use Ed25519 **identity assertions** towards consuming
applications. The service is a *pure identity provider* — it vouches
for "this browser belongs to `<email>`" and nothing else. Each
consumer remains the sole authority over its own sessions and users.

## Protocol

1. App shell finds no session token → redirects to
   `https://auth.<domain>/auth/login?return=<app url>`.
2. Service validates the return URL (https, subdomain of the allowed
   domain, no userinfo/port/fragment), sets CSRF + return cookies,
   redirects to AAD.
3. `/auth/callback` checks state, exchanges the code, fetches the
   user (Graph `/me`), signs a ~60 s assertion (`iss = "marmay-auth"`,
   `sub` = email, `name`, `aud` = the *origin* of the return URL,
   random `jti`) and delivers it via `302 <return>#itoken=<assertion>`
   — the fragment never reaches any server.
4. The app's bootstrap exchanges the assertion at the app's own login
   endpoint for an app-minted session token. The app validates
   signature/`iss`/`aud`/`exp` (public key only), consumes the `jti`
   (replay protection), looks the user up, and mints its own session.

## Consuming (the app side)

Depend on the library and use:

- `Marmay.Auth.Assertion.validateIdentityAssertion'` — verify an
  assertion against the service's **public** key. The `aud` check is
  byte-exact URI equality: configure your origin without path or
  trailing slash.
- `Marmay.Auth.ReplayProtection` — `mkConsumedLog` at startup,
  `ensureUnconsumed` after successful validation. One STM
  transaction; rejects a second redemption of the same `jti`.
- `Marmay.Auth.Bootstrap.bootstrapCoreScript` — the client half as an
  inline JS function `runAuthBootstrap(hooks)`; supply `onToken`,
  `onNoAccount`, `onFailure` hooks. Your login endpoint must answer
  `{"jwt": ...}` on success and `{"error": "unknown-user" | ...}` on
  failure.
- `Marmay.Auth.ClientConfig` — the config record with everything a
  consumer needs (public key, origin, skew, auth base URL).
- `Marmay.Auth.ConfigFile.forceLoadConfigFile` — permission-checked
  config loading (refuses files readable by group/other).

**Security note for consumers:** the return-URL check is host-only by
design (any subdomain of the trust domain, any path). Consequently,
XSS in user-generated content on ANY consuming application is
auth-critical — an injected script can harvest assertions redeemable
at that same origin. Sanitize accordingly.

## Key generation

```haskell
-- in cabal repl, import Crypto.JOSE, Data.Aeson, Control.Lens
jwk <- genJWK (OKPGenParam Ed25519)
encode jwk                  -- private JWK -> service config (authIssuerJwk)
encode (jwk ^. asPublicKey) -- public JWK  -> each consumer's config
```

## Service configuration

JSON file (must be `0400`/`0600`; the loader refuses laxer modes):

```json
{ "oauth2Config": { "clientId": "...", "clientSecret": "...",
                    "tenantId": "...", "redirectUri": "https://auth.example.com/auth/callback" },
  "authIssuerJwk": { "...": "private Ed25519 JWK" },
  "allowedReturnDomain": "example.com",
  "tokenExpiryDuration": 60,
  "laxReturnUrlCheck": false
}
```

`allowedReturnDomain` must be lowercase. `laxReturnUrlCheck = true`
(dev only) additionally admits `http` and explicit ports; the service
warns loudly at startup.

### Display names (Entra optional claims)

The asserted display name is `given_name family_name` when both claims
arrive, otherwise the token's `name` (the tenant's display name -- often
"Nachname Vorname"), otherwise the upn. Entra sends `given_name` and
`family_name` only as *optional claims*: in the app registration under
**Token configuration**, add both for the **ID token** (browser flow)
*and* the **access token** (Teams SSO, which validates the token from
`getAuthToken`). Consumers that persist the name at first login (e.g.
provisioning) do not pick up the new order for existing accounts on
their own.

## Deployment

The flake exports `nixosModules.marmay-auth`; the package default is
injected automatically:

```nix
services.marmay-auth = {
  enable = true;
  port = 8090;
  secretsFile = config.age.secrets.marmay-auth.path;  # owner marmay-auth, mode 0400
  nginx = { enable = true; domain = "example.com"; }; # serves auth.example.com
};
```

## Development

```bash
nix develop
cabal build all
cabal test all   # protocol tests: replay protection, assertion round-trip
```
