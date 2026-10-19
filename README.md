# RAgent Auth

Independent OIDC issuer for RAgent and MT. This repository is the source of a separately deployed Node authentication service. It was extracted from `ragent-service` without importing private repository history.

## Deployment configuration

All environment-specific hosts, callback origins, database targets, network ACLs and CloudBase identifiers must come from an operator-owned configuration outside this repository. The deployment generator validates that configuration and renders disabled candidate files and reverse-proxy templates. See [deployment configuration](deploy/identity/README.md). Examples use reserved, non-production identifiers only. Never commit the operator configuration or generated output.

## Repository boundary and dependency

- This repository owns OIDC protocol handling, protocol persistence/migration, issuer configuration, Docker packaging, deployment templates and tests.
- `ragent-service` remains the account authority: password/SMS validation, phone registration, stable subject mapping, tenant membership and business permissions stay behind its authenticated account bridge. No user data or production credentials are copied here.
- RAgent owns the current `/identity-login` presentation and each application owns its callback/session. The issuer reaches that UI through the existing same-origin reverse proxy; this extraction does not introduce a new login design.
- `ragent-service/identity-provider` consumes this repository as a Git submodule pinned to an exact commit. After cloning the backend, run `git submodule update --init identity-provider`; update the pointer only through a reviewed backend change. Runtime integration is HTTPS/OIDC, not an npm import or a Python package dependency.

Run `npm ci --ignore-scripts && npm test` from this repository root. Build with `docker build -t ragent-auth:local .`. The build context is this root, including when checked out as the backend submodule. Deployment tooling is under [`deploy/identity`](deploy/identity/README.md); see [extraction decisions](docs/extraction.md) and [production packaging](PRODUCTION.md).

CI tests the service and offline deployment generator, then builds the image. It does not publish images, change production or require production secrets. The current production image remains a separately deployed server-local image until an operator performs the next release.


Standalone, disabled-by-default OIDC service. The client integration reuses the existing RAgent login UI through a same-origin interaction route. This repository does not deploy a service, register production clients, or migrate MT business users automatically. Without an interaction UI path the minimal protocol-test form remains available for development.

`oidc-provider` **9.12.2** owns protocol endpoints, code/token handling, sessions, discovery and JWKS. `pg` **8.16.3** persists protocol artifacts. The account service owns password/phone validation and permanent subjects. No password is stored in this service.

## Run and configuration

Node >=22.14.0. `npm ci --ignore-scripts`, configure environment using `.env.example`, then `npm start`. The example env is not automatically loaded. Without `IDENTITY_ENABLED=true`, startup exits without opening a listener. Enabled startup rejects missing DB/bridge credentials, non-HTTPS production URLs, missing asymmetric private JWKS, weak/shared cookie-service keys, non-confidential clients and wildcard/fragment redirects. Generate an independent private JWKS with `node scripts/generate-jwks.js /secure/path/identity.private.json`; inject its JSON through secret management, never commit it. Cookie keys and client secrets also require independent random values. Signing-key rotation must retain previous keys through issued-token validity; do not regenerate keys on restart.

Production main always uses Postgres, never the in-memory test adapter. Run the explicit `npm run migrate` once with `IDENTITY_ENABLED=true` and `IDENTITY_DATABASE_URL` to apply `migrations/001-artifacts.sql`; startup only verifies the table exists and never issues DDL. Migration creates the dedicated `identity_oidc.artifacts` schema/table and indexes in the configured database. Use a dedicated database account and encrypted DB connection appropriate to deployment. Stored artifacts contain protocol tokens and identity claims: restrict DB access/backups accordingly. Artifacts have finite TTLs; reads enforce expiry and minute cleanup deletes expired rows. Consumption uses a conditional atomic update to reject concurrent reuse. Reconnect and revocation have real Postgres tests.

Listener defaults to loopback; explicit validated `IDENTITY_BIND_HOST=0.0.0.0` supports a container whose host publish remains loopback. HTTPS must terminate at a trusted local reverse proxy that replaces forwarded headers; production enables provider proxy awareness. Do not expose the loopback service through an untrusted proxy. No production proxy or DNS is installed here. Provider protocol URLs are rooted at the issuer host; issuer paths are rejected.

## Account bridge

Dedicated `Authorization: Bearer IDENTITY_SERVICE_TOKEN`, never exposed to the browser:

- `POST /api/v1/identity/authenticate-password` `{username,password}`.
- `POST /api/v1/identity/authenticate-phone` `{access_token}`.
- `POST /api/v1/identity/register-phone` `{access_token,username,password}` (username required; password at least six characters and at most 72 UTF-8 bytes).
- `GET /api/v1/identity/accounts/{subject}`.

Responses: `{sub,ragent_user_id,cloudbase_uid,cloudbase_env,username,email,phone,tenant_status}` with stable UUID subject and `tenant_status` `pending|assigned`. Backend disabled/deleted users fail lookup. Node checks live account state at code exchange, userinfo and center-session reuse. Invalid credentials/account-service outages fail closed with a generic browser error; no credential logging or upstream response reflection. The bridge enforces credential rate limits. The PoC does not claim immediate distributed app-session revocation or full global logout: those require client integration and lifecycle work.

## Protocol policy

Static confidential first-party clients only, `authorization_code`, exact registered redirect, PKCE S256 required for every client, no implicit/password/refresh grants or dynamic registration. Basic profile scopes are automatically approved only for the operator-configured first-party clients; do not add untrusted third-party apps to this list. No roles, tenant admin privileges, or RAgent business access follow from OIDC identity claims. A pending account can authenticate but still requires separate application authorization.

Interaction submissions validate a session-bound HMAC CSRF value, issuer Origin, content type and body size. Login identity is taken exclusively from the authenticated backend result, never an asserted userId/accountId. Cookies are host-only, HttpOnly, SameSite=Lax and Secure in production. Access and ID tokens last 600 seconds (ten minutes); codes 60 seconds; interactions 300 seconds; central sessions and grants seven days (604800 seconds). Client applications must independently verify issuer, audience, signature, nonce and state and keep their own host-only sessions. The tests verify ID-token signature/issuer/audience/nonce and state, while application callback and mapping verification are separate client tests.

## Tests

`npm test` runs configuration tests and real HTTP authorize→login→code→token→userinfo against an in-memory *test-only* adapter and fake account bridge. For the same full protocol test plus persistence/reconnect/atomic consumption/expiry/revocation against a fresh isolated PostgreSQL database:

```
IDENTITY_TEST_DATABASE_URL=postgresql://test@127.0.0.1:55439/postgres npm test
```

The database must be dedicated to tests; apply the explicit migration before tests. Coverage includes second-client center-session reuse, password and verified-phone identity equality, wrong PKCE, missing/plain PKCE, wrong redirect, cross-client code exchange, code replay, expiration, disabled account code exchange/userinfo, CSRF, Origin and invalid credentials. Tests never send SMS or contact production. Browser rendering, Safari/cross-root-domain cookies, real CloudBase, reverse proxy/TLS, global logout and production deployment remain unverified.

Official references consulted: [pinned package](https://github.com/panva/node-oidc-provider/tree/v9.12.2), [configuration](https://github.com/panva/node-oidc-provider/blob/v9.12.2/docs/README.md), [adapter contract](https://github.com/panva/node-oidc-provider/blob/v9.12.2/example/my_adapter.js), [interaction example](https://github.com/panva/node-oidc-provider/blob/v9.12.2/example/routes/express.js). Installed pinned package defaults were also inspected during implementation.

### Optional real Python bridge integration

`test/live-bridge.test.js` is skipped unless `IDENTITY_LIVE_BRIDGE_URL` is set. Point it only at a disposable FastAPI bridge fixture (not production), and set `IDENTITY_LIVE_USERNAME`, `IDENTITY_LIVE_PASSWORD`, `IDENTITY_LIVE_SERVICE_TOKEN`, plus the migrated `IDENTITY_TEST_DATABASE_URL`. Run `node --test test/live-bridge.test.js`. This verifies real password authentication and repeated live subject lookup through Python, followed by code/token/userinfo and second-client center-session reuse. It never sends SMS; phone validation in the general protocol suite uses a fake verified-token bridge.

## Existing login UI integration

Set `IDENTITY_INTERACTION_UI_PATH=/identity-login` and `CLOUDBASE_ENV_ID` on the issuer service. Its public issuer host must route `/auth`, `/token`, `/me`, `/jwks`, `/.well-known/*`, and `/interaction/*` to this Node service; route `/identity-login` and its Next assets/API dependencies to the RAgent frontend. Inspect discovery for the exact generated endpoint URLs before configuring the proxy. Keep browser requests on the same public origin and preserve interaction cookies. Do not expose the account bridge publicly or rewrite the issuer origin.

`GET /interaction/{uid}` redirects to the existing styled frontend. `GET /interaction/{uid}/context` returns only a session-bound CSRF value and public CloudBase environment. The UI submits URL-encoded credentials or an upstream verified phone token to `POST /interaction/{uid}` with an exact issuer Origin and `Accept: application/json`; registration uses `/interaction/{uid}/register`. The result is a same-issuer protocol resume URL, never an application JWT or OIDC token. Registration creates an unassigned account with the system `普通用户` role resolved by name (no hardcoded role ID); missing/ambiguous role configuration fails closed.

`ragent_user_id` is a trusted legacy account key for reviewed MT linkage. CloudBase UID/environment claims come exclusively from the backend binding table. They are migration identifiers, not authorization roles. The frontend must not submit these claims as assertions. A changed phone does not change the stable `sub`.

App logout in the initial integration clears that application's session. Central SSO uses a seven-day rolling session, so explicit sign-in can reuse it. Access and ID tokens expire after 600 seconds (ten minutes); the central session and grant use 604800-second lifetimes. The provider saves a session with a fresh seven-day expiry during authenticated protocol activity, so this is a rolling inactivity window, not an absolute seven-day login limit. Its session and signature cookies include persistent Expires dates derived from the saved session expiry; browser closure or computer sleep does not by itself invalidate them. Grant expiry is handled by the first-party renewal behavior below. Previously expired central sessions are not restored by deployment: users must sign in once again. Application sessions must also permit the ten-minute bound: deploy the matching MT client cap changes alongside the issuer update. Reauthentication rechecks central active state. Existing tokens retain their original expiration until replaced. Immediate global logout and back-channel revocation are not implemented; do not present a local logout as a global sign-out.

## Production packaging

See [PRODUCTION.md](PRODUCTION.md) for the standalone Docker/Compose candidate, protected `*_FILE` configuration, explicit migration and proxy requirements. Packaging does not activate the service.

### Silent renewal and grant expiry

Access-token expiry alone does not end the central SSO session. When an explicitly configured first-party client's stored grant has expired or disappeared while its central session remains valid, the issuer rechecks the active account and creates a replacement grant for that same account/client, limited to `openid profile email phone`. Unknown clients, inactive accounts and missing central sessions remain rejected. Existing grants continue through the provider's account/client consistency checks. This does not implement immediate grant revocation or global sign-out; those require a separate revocation policy.

A production `consent_required` response may indicate a missing grant or scopes not present in an existing grant. Inspect the Session/Grant expiration and scope metadata before attributing it to token expiry. Deleted historical artifacts cannot establish the original failure time.
