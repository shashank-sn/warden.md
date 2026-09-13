# service

The self-hosted auth.md service reference for Cloudflare Workers.

It serves RFC 9728 protected-resource metadata, RFC 8414 authorization-server metadata, an auth.md document, and an ES256 public JWKS. Unit tests use in-memory state; a deployment uses D1 for durable records, one claim Durable Object per registration, and a singleton event-delivery Durable Object for retry alarms.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/auth.md` | Agent onboarding document |
| `GET` | `/.well-known/oauth-protected-resource` | RFC 9728 metadata |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 metadata plus `agent_auth` |
| `GET` | `/.well-known/jwks.json` | Active and retained public ES256 keys |
| `POST` | `/agent/identity` | `anonymous`, `service_auth`, or `identity_assertion` registration |
| `POST` | `/agent/identity/claim` | Start or poll a claim ceremony |
| `POST` | `/agent/identity/claim/complete` | Verify, approve, or deny a user code |
| `POST` | `/oauth2/token` | JWT-bearer or one-use claim-grant exchange |
| `POST` | `/oauth2/revoke` | RFC 7009 idempotent revocation |
| `POST` | `/agent/event/notify` | Receive a signed token-revoked security event |
| `POST` | `/agent/events/subscribe` | Register an authenticated event subscriber |

## Security and state contract

Only the configured protected-resource audiences can be registered, issued, or validated. `PROTECTED_RESOURCES` is a JSON array of canonical HTTPS URLs; `ISSUER` is always included as the default resource. The local memory demo may use `http://localhost`; production resources must use HTTPS. An unconfigured or malformed resource returns `invalid_target`.

An `identity_assertion` registration must include a `client_id` that exactly matches the signed assertion. A JWT-bearer token exchange must include that same client ID, the original `identity_id`, and the original subject. A valid signature alone is not enough to switch registrations or clients.

The resource owner should call `service.validateAccessToken(token, expectedResource)` before accepting a Bearer token. It verifies the signature, issuer, audience, and persisted issued-token record, including revocation state. Signature-only verification cannot enforce a later revocation.

The Worker routes a claim start with `identity_id` to `CLAIM_CEREMONY` name `registration:<identity_id>`. Normal polls and completion requests need only their device code, user code, or claim ID: D1 resolves their hash-only route index to the same registration object. If an optional `identity_id` disagrees with that route, the request fails. Claim state and code hashes live in the registration's Durable Object; its alarm removes expired state. D1 retains the expiry-bounded hash-only route index, identities, replay records, issued-token records, safe identity-attempt audit records, subscribers, events, and delivery state. `EVENT_DELIVERY` owns the next retry alarm, so retries do not depend on another revocation request arriving.

The service never logs raw assertions, access tokens, device codes, service secrets, or private keys. The audit table records only identity type, optional client ID and subject, outcome, OAuth error code, and timestamp. A replayed inbound security event is rejected with `invalid_grant` rather than being silently accepted.

## Key rotation

`SERVICE_SIGNING_JWK` holds the active ES256 private JWK. Give every key a unique `kid`; the Worker uses that JWK field. `SERVICE_SIGNING_KID` exists only as a fallback for legacy JWKs without one and must match whenever both are configured. During a rotation, deploy the new active key and set `SERVICE_RETIRED_JWKS` to a JSON JWKS object or array containing only the still-valid *public* keys. Discovery publishes active plus retained public keys, and access-token and claim-grant verification accepts them. Retain the old public key until the longest outstanding token or claim-grant lifetime has elapsed, then remove it and deploy again. Rotate a third-party assertion issuer through its independently configured `TRUSTED_ASSERTION_JWKS`.

## Local checks

```sh
pnpm --filter @warden/service typecheck
pnpm exec vitest run packages/service/test/service.test.ts
pnpm validate:deploy
```

For a complete non-secret memory-only HTTP flow, see [`examples/service-demo`](../../examples/service-demo/README.md). For a real Worker deployment, see [`docs/deploy.md`](../../docs/deploy.md).
