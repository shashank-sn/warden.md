# broker

Completion-scoped delegated authority: one exact action, one audience, one DPoP-bound use, then
completion or expiry revokes what remains.

## Package contract

@warden/broker exposes a Worker-compatible reference broker, a typed agent client, and resource
middleware. The implementation keeps the state-machine and policy boundary visible.

The deployed Worker exposes `GET /.well-known/jwks.json` and `POST /consume`. A resource fetches
that public JWKS through `WorkerBrokerClient`, gives its verifier and consumer to
`createWorkersHandler` or `createNodeMiddleware`, and never receives `BROKER_SIGNING_JWK`. The
local verifier is an early signature check; the Worker owns the authoritative DPoP check and atomic
single consume before application code runs.

Agents use `createWorkerCompletionClient` with their DPoP proof function. It calls the public
exchange, approval, and credential-bound completion routes; a configured `APPROVAL` binding derives
the approver from the request headers rather than a caller-supplied approver string.

## Guarantees

- requested scope is the intersection of subject authority and registration scope; upscoping fails
- the trusted authority resolver supplies registration and subject scope; proposal fields cannot
  claim either one
- a subject assertion can mint one consumable credential
- approved-to-consumed is atomic, so concurrent calls have one winner
- the credential carries one audience, one use marker, expiry, and DPoP key thumbprint
- completion is idempotent and records evidence; a TTL alarm is the fallback
- failed revocation fan-out is retried and visible in evidence, without reviving authority
- credentials, raw proofs, and subject assertions are never written to audit events
- agents cannot request a TTL greater than the broker's configured maximum

See [the draft protocol](../../docs/spec/completion-scoped-grants.md),
[policy configuration](../../docs/broker-policy.md), and the
[security review](../../docs/security/threat-model.md).

## Worker runtime setup

`wrangler.jsonc` declares the coordinator and per-grant-expiry Durable Objects plus the optional D1
audit projection. It is a deployment skeleton: replace its D1 database id and wire trusted service
bindings before deploying. The public Worker fails closed until these are present.

| Requirement | Purpose |
| --- | --- |
| `BROKER_SIGNING_JWK` secret | One stable ES256 private JWK. It stays only in the broker Worker / coordinator and must remain stable across Worker isolates. |
| `BROKER_INTERNAL_TOKEN` secret | High-entropy token authorizing only the coordinator-to-expiry internal callbacks. |
| `BROKER_ISSUER` variable | Required for a real deployment: final HTTPS broker origin minted into credentials. The development fallback is deliberately invalid. |
| `BROKER_SIGNING_KID` / `BROKER_MAX_TTL_SECONDS` variables | Optional active-key label and positive integer TTL cap; the default cap is 300 seconds. |
| `AUTHORITY` service binding | Required. `POST /resolve` receives `agentId`, `subjectId`, and `subjectTokenId`; it returns the verified registration scopes, subject scopes, and resource allowlist. |
| `APPROVAL` service binding | Required for approval-policy grants. `POST /authorize` receives the broker-resolved grant view and returns `{ "approver": "..." }` only after authenticating the human approval. |
| `OPERATOR` service binding | Required for `POST /grants/{id}/revoke`. It receives the same resolved grant view and returns `{ "operator": "..." }` only after authenticating an operator. |
| `REVOCATION` service binding | Required only when `BROKER_REVOCATION_TARGETS` is nonempty. It receives `{ grantId, target, eventId }` and must return a nonempty receipt. |

Generate and set the two secrets without saving their values to source control:

```sh
node --input-type=module -e 'const pair=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);process.stdout.write(JSON.stringify(await crypto.subtle.exportKey("jwk",pair.privateKey)))' | wrangler secret put BROKER_SIGNING_JWK --config packages/broker/wrangler.jsonc
node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("base64url"))' | wrangler secret put BROKER_INTERNAL_TOKEN --config packages/broker/wrangler.jsonc
```

Add deployment-specific service bindings rather than accepting authority from public request bodies:

```json
{
  "services": [
    { "binding": "AUTHORITY", "service": "your-authority-worker" },
    { "binding": "APPROVAL", "service": "your-approval-worker" },
    { "binding": "OPERATOR", "service": "your-operator-worker" }
  ]
}
```

`BROKER_POLICY_JSON` is optional but must be a strict version-1 policy document; unknown and empty
match fields fail startup. `BROKER_REVOCATION_TARGETS`, when used, is a JSON array of HTTPS targets.
The broker retries relay handoffs and preserves their current delivery status in evidence, but the
relay owns message authentication, signing, and receiver-side replay storage. Run the migration and
deploy only after these values and bindings are configured:

```sh
wrangler d1 migrations apply warden-broker --remote --config packages/broker/wrangler.jsonc
wrangler deploy --config packages/broker/wrangler.jsonc
```

## Quickstart

1. Install dependencies with `pnpm install`.
2. Run `pnpm --filter @warden/broker typecheck` and `pnpm test`.
3. Create a `WorkerBrokerClient` with the deployed HTTPS broker origin. Fetch `client.verifier()`
   and pass both that verifier and `client` as `consumer` to `createWorkersHandler`; do not embed a
   `Broker` or a private signing JWK in the resource.
4. Create `createWorkerCompletionClient` with the same agent DPoP session and `approvalHeaders` for
   its approval request. Those headers are forwarded only to the approval route. Use
   `CompletionClient.run()` around the protected call. It completes on success, thrown errors, and
   timeout; completion failures remain in an in-memory retry queue and fall back to grant TTL after a
   process loss.

The local tests are a runnable end-to-end reference: proposal, approval, single protected call,
automatic completion, revocation evidence, and retry behavior. No demo writes credentials to disk.

## Failure modes

| Condition | Behavior | Operator action |
| --- | --- | --- |
| Protected call throws | SDK calls completion in finally. | Inspect evidence; retry the business operation only with a new grant. |
| Completion network failure | SDK buffers and retries in memory; TTL remains authoritative. | Retry buffered completions or wait for expiry evidence. |
| Duplicate protected call | Middleware returns `grant_already_consumed` (409). | Do not retry with the same credential. |
| Clock skew / expired grant | Broker rejects with `grant_expired` and writes expiry evidence. | Mint a new short-lived grant after correcting clock drift. |
| Wrong audience or key | Middleware returns `wrong_audience` or `wrong_dpop_key`. | Treat as a routing or key-binding error, not an approval retry. |
| Operator revocation without trusted binding | Worker returns `operator_authorization_required` (403). | Configure a separate authenticated `OPERATOR` binding; never trust a caller-supplied operator identity. |
