# Changelog

## 0.3.1.0 — 2026-09-26

Display names in "Vorname Nachname" order.

### Added

- `EntraClaims` carries the Entra optional claims `given_name` and
  `family_name`; `entraIdentity` builds the display name as
  `given_name family_name` when both are present and non-blank, falling
  back to `name` (then the upn) as before. Both login flows (browser ID
  token, Teams SSO access token) share the extraction, so the app
  registration must add the optional claims to both token types
  (README, "Display names").

## 0.3.0.0 — 2026-09-01

Two-stage tab selector: application, then view.

### Breaking

- **Application registry shape**: `ApplicationEntry` is now
  `{ name, url, views }` with `views :: [{ name, path }]` — a tab's
  target is `url <> view.path` (query strings allowed, e.g.
  `/app/assignments?embedded`). The former `contentUrl`/`websiteUrl`
  fields are gone. The nixosModule option changed accordingly
  (`applications.*.views`, defaulting to a single whole-app view), so
  nix-generated registries migrate by updating the flake input;
  hand-written registry files must be adapted.

### Changed

- `/teams/config` selects in two stages (application, then view);
  Save derives entityId (`app/view`), the bounce contentUrl, the
  websiteUrl escape hatch, and the display name (the view's name when
  an application has several views, else the application's).

## 0.2.1.0 — 2026-09-01

The "BG Horn" meta-app surface.

### Added

- **Teams tab selector** (`GET /teams/config`): shown by Teams inside
  the add-a-tab dialog; a dropdown over the application registry, and
  saving stores the tab's contentUrl (the sso bounce with the chosen
  application's URL as return), websiteUrl and suggested display name.
- **Public application registry**: loaded from a separate unencrypted
  file via the new `--applications` flag (`loadPublicConfigFile` — the
  secrets loader refuses world-readable files, which nix-store paths
  are). The nixosModule gains a typed
  `services.marmay-auth.applications` option rendered to that file;
  consumers publish matching `teamsApplications` outputs.
- **`teams/`**: the Teams app package — manifest template with a
  stable app GUID (`package.sh` substitutes domain and client id and
  zips), school-branded icons.

## 0.2.0.0 — 2026-09-01

Teams SSO support and the oid-keyed identity model.

### Breaking

- **Identity assertions are keyed by the Entra object id.**
  `IdentityAssertion` is now `{ assertionId, oid, upn, name }`: the JWT
  `sub` carries the immutable directory object id (the identity key),
  the lowercased user principal name travels as a new
  `https://auth.bu-ki.at/#upn` claim (the human-readable provisioning
  matcher). Consumers must switch their login matching to oid-first
  with upn fallback, backfilling the oid on first login.
- **`authServer` takes an `AuthEnv`** (manager, security config, JWKS
  cache) instead of positional arguments.
- `exchangeCodeForToken`/`getUserInfo`/`Office365User` are gone
  (`Marmay.Auth.Microsoft` is now `Marmay.Auth.Microsoft.CodeExchange`
  exposing `exchangeCodeForIdToken`); the unused `getAuthorizationUrl`
  was removed.

### Added

- **Teams SSO login flow.** `GET /teams/sso?return=<url>` — a
  frameable bounce page that acquires an AAD token silently via
  teams-js (`getAuthToken`) and `POST /auth/teams/exchange?return=<url>`
  — swaps that token for an identity assertion whose audience is the
  validated return URL's origin. The assertion travels over the same
  `#itoken=` fragment contract as the browser flow, so consumers
  cannot tell the flows apart. teams-js is CDN-loaded, version-pinned,
  and integrity-pinned (SRI).
- **Frame-aware bootstrap core.** `bootstrapCoreScript`'s redirect
  target now branches on framedness (iframe → the Teams bounce page,
  top-level → `/auth/login`; new `BootstrapConfig.teamsSsoPath`,
  defaulted) — every consumer of the core becomes Teams-capable by
  upgrading this library, with no app changes.
- **AAD token validation** (`Marmay.Auth.Microsoft.AuthTokenValidator`):
  RS256 against the tenant's JWKS with a lazy 24 h key cache that
  serves stale keys during AAD outages and rate-limits forced
  refetches (key rotation) to once a minute. Shared by both flows —
  the browser flow now reads identity from the code exchange's
  id_token instead of calling Graph (`User.Read` dropped from the
  authorize scope).
- **Security-header middleware** (`securityHeaders`): `/auth/*` is
  never framed and never cached, `/teams/*` carries a configurable
  Teams frame-ancestors allowlist (`teamsConfig.frameAncestors`,
  Microsoft defaults), everything else is never framed.
- **`teamsConfig`** section in the security config (optional;
  `applicationIdUri` as an extra accepted token audience, the
  frame-ancestors list). All keys default — existing config files
  keep working unchanged.

### Tests

- Protocol test suite extended from 7 to 40 offline checks: JWKS
  document parsing, the Entra validation table (issuer/audience/
  expiry/algorithm/claim-shape), the return-URL trust table, audience
  derivation, the exchange handler end-to-end, and the header policy.

## 0.1.0.0 — 2026-08

Initial extraction of the shared authentication service from
competences: Office365 OAuth code flow, Ed25519 identity assertions
with replay protection, the client bootstrap script, config loading.
