# deploy the self-hosted auth.md service

This is a reference deployment, not a hosted identity provider. It uses your Cloudflare account, D1 database, signing key, and service-auth secret. No deployment credential is committed here.

## Prerequisites and local validation

- Node 20 or later and pnpm.
- A Cloudflare account authenticated to Wrangler.
- A recent Wrangler binary available as `wrangler`. If it is not installed globally, use `pnpm dlx wrangler@4` in each command below.

Run the deterministic checks before provisioning. `validate:deploy` is offline: it checks the Worker template, both Durable Object migrations, migrations, and canonical routes without a Cloudflare credential.

```sh
pnpm --filter @warden/service typecheck
pnpm exec vitest run packages/service/test/service.test.ts
pnpm validate:deploy
```

The CI workflow runs the same offline deployment-template validation before its test job. It is not proof that a Cloudflare account has been provisioned or that a deployment is live.

## Provision D1 and apply migrations

The provisioning helper validates the checked-in template before creating a D1 database. It deliberately does not rewrite `wrangler.jsonc`: copy the returned database ID into `packages/service/wrangler.jsonc` at `database_id`, review the diff, then apply migrations.

```sh
pnpm --filter @warden/service provision -- warden-auth-md
wrangler d1 migrations apply warden-auth-md --remote --config packages/service/wrangler.jsonc
```

The Worker configuration declares two Durable Objects and class migrations: `CLAIM_CEREMONY` (`v1`) owns one namespace per identity registration and removes expired claim state with an alarm; `EVENT_DELIVERY` (`v2`) owns the global retry alarm for queued security-event deliveries. Do not remove or rename either binding or migration after deployment.

D1 stores identities, issued-token and revocation records, replay records, an expiry-bounded hash-only claim-routing index, event delivery records, rate-limit buckets, and privacy-safe identity-attempt audits. It does not need an assertion, token, or key fixture.

## Configure resource and assertion boundaries

Set `ISSUER` to the final HTTPS origin before a custom-domain deployment. Set `PROTECTED_RESOURCES` to a JSON array of every exact HTTPS audience this issuer may mint or validate. For example, the following non-secret Worker variables allow only the service origin and a specific API origin:

```json
{
  "ISSUER": "https://auth.example.com",
  "PROTECTED_RESOURCES": "[\"https://auth.example.com\",\"https://api.example.com\"]"
}
```

Add those values under `vars` in `packages/service/wrangler.jsonc`, or use your deployment system's equivalent Worker variables. An arbitrary HTTPS `resource` is rejected with `invalid_target`; do not treat an HTTPS URL as an implicit allowlist entry.

For a separate identity-assertion issuer, set `TRUSTED_ASSERTION_ISSUER` and provide its public JWKS as `TRUSTED_ASSERTION_JWKS`. The Worker does not fetch arbitrary JWKS URLs at request time. Each assertion registration requires the caller-supplied `client_id` to match the signed `client_id`; JWT-bearer exchange also requires that client ID and the originating `identity_id` and subject to match the stored registration.

## Set secrets without printing them

Generate an ES256 private JWK and pipe it straight to Wrangler. The key is not echoed, saved to a fixture, or added to source control.

```sh
node --input-type=module -e 'const pair=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);const jwk=await crypto.subtle.exportKey("jwk",pair.privateKey);jwk.kid=`service-${crypto.randomUUID()}`;process.stdout.write(JSON.stringify(jwk))' | wrangler secret put SERVICE_SIGNING_JWK --config packages/service/wrangler.jsonc
wrangler secret put SERVICE_AUTH_TOKEN --config packages/service/wrangler.jsonc
```

Optional non-secret variables are `SERVICE_SIGNING_KID`, `SERVICE_AUTH_SUBJECT`, `SERVICE_AUTH_SCOPE`, and `SERVICE_AUTH_RESOURCE`. Give new active private JWKs their own `kid`; the Worker uses that value. `SERVICE_SIGNING_KID` is only a compatibility fallback for a legacy JWK with no `kid`, and must match the JWK if both are set. Store `SERVICE_RETIRED_JWKS` as a JSON JWKS object or JSON array containing public keys only. It can be a Worker variable or secret; it contains no private material.

## Deploy and check discovery

```sh
wrangler deploy --config packages/service/wrangler.jsonc
curl -fsS https://YOUR-WORKER.workers.dev/auth.md
curl -fsS https://YOUR-WORKER.workers.dev/.well-known/oauth-protected-resource
curl -fsS https://YOUR-WORKER.workers.dev/.well-known/oauth-authorization-server
curl -fsS https://YOUR-WORKER.workers.dev/.well-known/jwks.json
```

Re-deploy after any issuer or resource-allowlist change so discovery documents, JWT issuer, token audience, and endpoint metadata agree.

## Resource-side validation, revocation, and claims

At the resource server, validate a received Bearer token against its exact audience with `service.validateAccessToken(token, expectedResource)`. The helper verifies the signed claims and checks the persisted issued-token record, so a revoked token is rejected even though its signature remains valid.

Only claim start needs `identity_id`. For normal poll and completion requests, the Worker hashes the device code, user code, or claim ID into D1's expiry-bounded routing index, then selects the registration-specific `CLAIM_CEREMONY` namespace. An optional supplied `identity_id` must agree with that route. A claim grant selects the same namespace from its signed identity binding. Treat `temporarily_unavailable` as retryable, but never retry a one-use claim grant after a successful token response.

Revocation creates signed security events for subscribed services. Failed deliveries are retried by `EVENT_DELIVERY` alarms without waiting for another revocation. Recipients must validate the JWT and persist event IDs; this service rejects a replayed inbound security event with `invalid_grant`.

## Rotate signing keys

1. Create a new ES256 private JWK with a new `kid` and set it as `SERVICE_SIGNING_JWK`. Do not retain a conflicting `SERVICE_SIGNING_KID`; omit it or set it to that same new `kid`.
2. Put the old public JWK, without `d`, in `SERVICE_RETIRED_JWKS`.
3. Deploy and confirm `/.well-known/jwks.json` contains the active and retired public keys.
4. Retain the prior public key until all tokens and claim grants signed by it can no longer be valid; then remove it and deploy again.

Rotate a configured third-party assertion issuer by updating `TRUSTED_ASSERTION_JWKS` separately. Do not put any private JWK in either retired-key or trusted-key configuration.

## Reset and seed (development only)

The reset helper is destructive. It defaults to a local D1 target and requires explicit acknowledgement; a remote reset requires two acknowledgements.

```sh
pnpm --filter @warden/service reset -- --local --yes
pnpm --filter @warden/service seed -- --local
```

Use `--remote --yes --confirm-remote` only for a disposable database. The seed contains one non-secret demo identity and no token, assertion, or key.

## Operational limits

- Unit tests use an in-memory rate limiter; the Worker uses D1-backed atomic fixed windows. Move rate limits to a separate Durable Object if very high-volume contention or strict global burst control matters.
- Event subscriptions are HTTPS-only and service-authenticated. Production operators should additionally restrict subscriber hostnames to their own allowlist to reduce SSRF exposure.
- The reference includes tested key-retention wiring and a runbook, but it does not claim a live deployment, an external identity-provider integration, or a third-party security review.
