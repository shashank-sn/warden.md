# broker and sdk wire protocol v1

License: MIT
Status: planned v1 contract — not implemented by this repository.

This document fixes the planned HTTP/JSON boundary used by a broker, a protected-resource
adapter, and any language SDK. It does not choose an SDK language or runtime. The in-repository
TypeScript broker is a draft-v0 baseline; it is **not** claimed to conform to this v1 contract.
The v0 one-use rules remain valid unless a v1 standing profile explicitly applies.

## 1. non-negotiable invariants

- A grant names one exact HTTPS audience, one exact action, one non-empty granted-scope set, and
  one DPoP JWK thumbprint (JKT). Wildcard audiences, path templates, wildcard scopes, and implicit
  scope expansion are invalid.
- A resource action is allowed only after the broker-owned consume transition succeeds. A capability
  is not evidence that the resource action has run.
- A coordination record is non-authorizing. It may group child intent but cannot mint a credential
  or expand a child action, audience, scope, TTL, or JKT.
- A reusable grant exists only through an explicit standing profile and cannot participate in
  cross-resource coordination. The default and v0 behavior is exactly one successful consume.
- Credentials, subject assertions, DPoP proofs, private keys, and raw authorization headers MUST
  never enter evidence, logs, error bodies, or the conformance fixtures.

## 2. common HTTP and JSON rules

All endpoints use HTTPS, UTF-8 `application/json`, `cache-control: no-store`, and JSON objects.
Requests with duplicate JSON member names, unknown fields, a non-object body, or an invalid field
type fail with `400 invalid_request`. The documented v1 response shapes are closed: an added field
requires explicit negotiation of a later protocol version rather than silent interpretation.

`/v1` is the protocol version in every path. IDs are opaque URL-path-safe strings; clients must not
derive authorization from their shape. Times are RFC 3339 UTC instants with a `Z` suffix and whole
seconds. Durations and use limits are positive integers.

An action has this canonical form:

```json
{
  "method": "POST",
  "path": "/payments/42",
  "query": ""
}
```

`method` is uppercase, `path` starts with `/`, and `query` is the exact percent-encoded query text
without `?`; `""` means no query. The broker and resource adapter reconstruct these values from the
received protected request. A client-supplied action description is only a proposal and cannot
override the received request.

An `audience` is one canonical absolute HTTPS URL without credentials, fragment, wildcard, or
implicit port. Scope is a non-empty array of unique, non-wildcard strings. The canonical value
returned by the broker is the value used for all later comparisons.

## 3. stable routes

| Route | Caller and purpose | Success |
| --- | --- | --- |
| `POST /v1/grants/exchange` | Agent requests one child or normal grant. | `201` allowed, `202` pending approval. |
| `POST /v1/grants/{grant_id}/approve` | Trusted approval integration approves one pending grant. | `200` approved result. |
| `POST /v1/grants/{grant_id}/consume` | Protected-resource adapter asks the broker to consume before work. | `200` one atomic consume. |
| `POST /v1/grants/{grant_id}/complete` | Agent SDK or resource reports completion. | `200` stable final evidence. |
| `POST /v1/grants/{grant_id}/completion-queue` | Durable SDK queue enqueues a broker-only completion receipt. | `202` stable queue item. |
| `GET /v1/grants/{grant_id}/completion-queue/{queue_id}` | Owning SDK actor observes a non-secret broker queue item. | `200` queue state, not authority. |
| `POST /v1/grants/{grant_id}/revoke` | Trusted operator ends authority. | `200` stable final evidence. |
| `POST /v1/grants/{grant_id}/renew` | Broker renews an eligible standing grant after fresh checks. | `201` new bounded grant. |
| `GET /v1/grants/{grant_id}/evidence` | Authorized evidence reader obtains a redacted final record. | `200` evidence. |
| `POST /v1/task-graphs` | Agent records immutable same-audience graph metadata. | `201` graph record, never a graph credential. |
| `POST /v1/task-graphs/{graph_id}/nodes/{node_id}/approve` | Trusted approval integration decides one graph node. | `200` one node result. |
| `POST /v1/task-graphs/{graph_id}/nodes/{node_id}/finalize` | Trusted resource integration records one node outcome. | `200` node evidence. |
| `POST /v1/task-graphs/{graph_id}/cancel` | Trusted cancellation authority ends eligible graph work. | `200` graph cancellation evidence. |
| `POST /v1/coordinations` | Agent records a bounded multi-resource plan. | `201` non-authorizing record. |
| `POST /v1/coordinations/{coordination_id}/approve` | Trusted approval integration approves a frozen full plan. | `200` only ordinal-one child is ready. |
| `POST /v1/coordinations/{coordination_id}/finalize` | Trusted coordinator records a terminal plan event. | `200` stable final evidence. |
| `GET /.well-known/jwks.json` | Shared public verification-key discovery. | `200` public EC signing keys only. |

The planned routes above deliberately differ from any draft-v0 route layout. They are a v1 target,
not a compatibility assertion about the current runtime.

The fixture retains v0 extension-negative descriptors only for `POST /exchange`, the v0 request
surface that admits grant-proposal fields. They specify the behavior a future v1-capable broker must
enforce when it receives a v1 reuse field there; they do not claim that the current draft-v0
TypeScript reference parses or implements that extension.

## 4. request and response shapes

### 4.1 exchange

Every grant response uses this closed grant view. `issued_at` and `evidence_id` are `null` before
their respective transitions; a later endpoint never adds fields to this view.

```json
{
  "id": "grant-id",
  "status": "approved",
  "action": { "method": "POST", "path": "/payments/42", "query": "" },
  "audience": "https://api.example.test",
  "scope": ["payments:write"],
  "dpop_jkt": "base64url-action-jwk-thumbprint",
  "issued_at": "2030-01-01T00:00:00Z",
  "expires_at": "2030-01-01T00:05:00Z",
  "use_limit": 1,
  "evidence_id": null
}
```

The grant view has exactly the fields above. It MUST NOT include a subject assertion, credential,
raw DPoP proof, private key, standing-policy object, or queue receipt.

`POST /v1/grants/exchange` requires `Idempotency-Key` and a broker-authenticated delegation outside
the JSON body. The body contains no subject assertion:

```json
{
  "action": { "method": "POST", "path": "/payments/42", "query": "" },
  "audience": "https://api.example.test",
  "scope": ["payments:write"],
  "dpop_jkt": "base64url-action-jwk-thumbprint",
  "completion_ttl_seconds": 300
}
```

`graph`, `coordination`, `standing_profile_id`, and `completion_queue` are optional exchange
selectors, but at most one MAY appear. `coordination` together with `standing_profile_id` is the
one semantically specific rejection: it returns `403 cross_resource_reuse_forbidden`. Every other
selector composition returns `400 invalid_request`. A selector-composition rejection creates no
grant, approval, queue record, or completion receipt. Each selector is omitted from the base body
above unless its profile is selected:

- A graph-bound body adds exactly `"graph":{"id":"graph-id","node_id":"node-id"}`.
- A coordination child adds exactly
  `"coordination":{"id":"coordination-id","resource_id":"billing"}`.
- A reusable request adds `"standing_profile_id":"standing-profile-id"` and may add
  `"requested_use_limit":positive-integer`.
- A plain one-use durable-queue request adds exactly
  `"completion_queue":{"dpop_jkt":"base64url-completion-jwk-thumbprint"}`.

`graph` has exactly `id` and `node_id`. A graph-bound exchange is allowed only after that
exact immutable node is approved; its action, audience, requested scope, and action JKT MUST match
the node, its grant expiry is capped by the graph deadline, and it always has
`use_limit: 1`. The broker atomically attaches the resulting distinct grant to that node. An
exact idempotent retry returns the attached grant; a second non-idempotent exchange, a substituted
node field, or an unavailable dependency issues nothing. A substituted action returns
`action_not_authorized`, a substituted audience returns `wrong_audience`, a widened scope returns
`scope_not_authorized`, and a substituted JKT or requested use limit above one returns
`invalid_request`. A coordination child is checked against the one named resource entry. A
standing profile is resolved only by the broker's trusted policy store, never by an agent-supplied
profile object.
`requested_use_limit` is optional: without a standing profile it is absent or `1`; a value above
`1` requires an eligible profile and does not override that profile's fixed limit.

`completion_queue` is optional and has exactly one `dpop_jkt` field. It is valid only when the
durable-queue feature was explicitly negotiated, the exchange is one-use, and none of `graph`,
`coordination`, or `standing_profile_id` is present. Its JKT MUST differ from the action
`dpop_jkt`. The broker validates it as a public JKT but never receives the corresponding private
key. This keeps a restart-capable completion key from becoming action authority or a standing
credential.

The normal allowed result is exactly this `201` envelope:

```json
{
  "decision": "allow",
  "grant": { "...": "closed grant view from this section" },
  "capability": "opaque-dpop-bound-capability"
}
```

The actual capability is sensitive and the example is a field description, not a fixture value. A
queue-enabled allowed result is the only additional allowed variant. It has exactly one extra
`completion_queue` object:

```json
{
  "decision": "allow",
  "grant": { "...": "closed grant view from this section" },
  "capability": "opaque-dpop-bound-capability",
  "completion_queue": {
    "receipt": "opaque-dpop-bound-completion-receipt",
    "audience": "https://broker.example.test/v1/grants/grant-id/completion-queue",
    "dpop_jkt": "base64url-completion-jwk-thumbprint",
    "expires_at": "2030-01-01T00:10:00Z"
  }
}
```

`completion_queue` has exactly `receipt`, `audience`, `dpop_jkt`, and `expires_at`. `receipt` is
sensitive and MUST NOT enter evidence, logs, errors, or fixtures. Its audience is the literal
broker enqueue URL, not the resource audience. The response allows the SDK to store a receipt and
its separate protected-key handle before an offline completion event exists.

A pending result is exactly `202` with `decision: "pending"`, a closed grant view in `proposed`
status, and `approval: {"id":"opaque-approval-id"}`. It has neither `capability` nor
`completion_queue`; approval later returns the stored normal or queue-enabled allowed variant.
A policy block returns the normal error object.

### 4.2 approval, consume, finalization, evidence, and renewal

The exact body is `{}` for `POST /v1/grants/{grant_id}/approve`,
`POST /v1/grants/{grant_id}/complete`, `POST /v1/grants/{grant_id}/revoke`,
`POST /v1/grants/{grant_id}/renew`, and
`POST /v1/coordinations/{coordination_id}/approve`. Their trusted caller identity, proof,
and resolved authorization/finalization context are in headers or durable broker state, never
caller-supplied JSON. Any member in one of these bodies returns `400 invalid_request`.

Approval and finalization routes require `Idempotency-Key`. Approval identity is authenticated by a
trusted server-side integration; no JSON `approver` value is authoritative. A successful approval
returns the stored normal or queue-enabled allowed envelope from section 4.1 and cannot mint a
second capability or completion receipt.

The consume route is a resource-adapter boundary, not a general agent retry endpoint. It receives
the protected request's DPoP-bound capability and proof in HTTP headers and this exact body:

```json
{
  "target": { "method": "POST", "url": "https://api.example.test/payments/42" }
}
```

The adapter MUST be deployment-authenticated. For a normal one-use grant, the broker verifies the
observed target, capability, and forwarded proof before one atomic `approved -> consumed`
transition. Its `200` body is exactly `{"grant": <closed grant view>}` with status `consumed`.
It returns that body only to the resource adapter, which performs the protected action after the
response. A second normal one-use consume never retries the business action; it returns
`409 grant_already_consumed`.

A `bounded_multi_use` grant or `standing` segment instead uses the explicit consume ledger in
[bounded reuse and standing grants](./bounded-reuse-standing-grants.md#3-bounded-consume-state).
Each successful consume returns the same closed `{"grant": <closed grant view>}` envelope while
the fixed profile limit remains; it records one consume event and decrements that ledger atomically.
It does not apply the one-use `approved -> consumed` rule. A later call after the fixed finite limit
returns `409 reuse_limit_exhausted`; a duplicate proof remains `401 dpop_proof_invalid`.

Every finalization and evidence response uses this closed evidence view:

```json
{
  "id": "evidence-id",
  "subject": { "type": "grant", "id": "grant-id" },
  "state": "revoked",
  "finalization_source": "agent",
  "recorded_at": "2030-01-01T00:00:01Z"
}
```

`subject` has exactly `type` and `id`; the evidence view has exactly the five fields above. It is
redacted: it never contains a credential, receipt, proof, assertion, private key, raw resource
body, or internal delivery data.

`POST /v1/grants/{grant_id}/complete` and `POST /v1/grants/{grant_id}/revoke` each return exactly
`{"grant": <closed grant view>, "evidence": <closed evidence view>}` with `200`. `GET
/v1/grants/{grant_id}/evidence` returns exactly `{"evidence": <closed evidence view>}` with `200`
to an authorized evidence reader. Completion is idempotent: a retry after a received or lost `200`
returns the same evidence ID and does not revive authority. An expiry alarm uses this same evidence
shape with source `ttl`.

A successful `POST /v1/grants/{grant_id}/renew` returns the normal closed allowed-exchange
envelope from section 4.1 with status `201`. A standing renewal cannot use the durable-queue opt-in;
it names the new finite grant ID and fixed resolved envelope without exposing a standing parent,
prior segment credential, private key, or policy-management object.

### 4.3 queue views

`POST /v1/grants/{grant_id}/completion-queue` requires `Idempotency-Key`, a completion receipt in
`Authorization: DPoP`, and a fresh matching proof. Its exact JSON body is
`{"completion_event_id":"opaque-stable-id"}`. It never accepts the action capability in place of
the receipt.

A public broker queue view has exactly `id`, `grant_id`, `state`, `accepted_at`, `updated_at`,
`attempts`, `evidence_id`, and `last_error`. `evidence_id` and `last_error` are `null` when absent;
`last_error`, if non-null, is a stable code from section 8. The view contains no receipt, proof,
key handle, dedupe key, or raw terminal payload.

The enqueue route returns exactly `{"queue": <closed queue view>}` with `202` and state `accepted`
after its durable broker enqueue transaction. It does not mean final evidence exists. The broker's
separate worker can later advance the view through `processing`, `recorded`, `recorded_late`, or
`dead_lettered`. `GET /v1/grants/{grant_id}/completion-queue/{queue_id}` returns exactly the same
closed envelope with `200` to the broker-authenticated SDK actor that owns the item. It is an
observation route, not a second credential or authority surface. If the actor cannot observe the
specified grant/queue pairing, it returns `404 grant_not_found` without revealing whether either
opaque identifier exists.

### 4.4 task-graph views

A graph node view has exactly `id`, `state`, `depends_on`, `action`, `audience`, `scope`,
`dpop_jkt`, `use_limit`, `expires_at`, `grant_id`, and `evidence_id`. `scope` is the broker-resolved
granted scope. `use_limit` is always `1`; `expires_at` is `null` before node approval and then the
exact resolved hard expiry, never later than the graph deadline. `grant_id` and `evidence_id` are
`null` until their relevant durable records exist. A graph view has exactly `id`, `state`,
`definition_hash`, `nodes`, `expires_at`, and `evidence_id`; its `nodes` are graph node views.
Neither view contains a capability, credential, proof, assertion, private key, or raw resource
receipt.

`POST /v1/task-graphs` returns exactly `{"graph": <closed graph view>}` with `201`. `POST
/v1/task-graphs/{graph_id}/nodes/{node_id}/approve` returns exactly `{"graph": <closed graph
view>, "node": <closed graph node view>}` with `200`. `POST
/v1/task-graphs/{graph_id}/nodes/{node_id}/finalize` returns exactly
`{"graph": <closed graph view>, "node": <closed graph node view>, "evidence": <closed evidence
view>}` with `200`. `POST /v1/task-graphs/{graph_id}/cancel` returns exactly `{"graph": <closed
graph view>, "evidence": <closed evidence view>}` with `200`.

These replies report durable metadata and evidence only. A node action capability is issued only by
the separate exact grant exchange after the node's resolved approval state permits it. That exchange
MUST carry the exact `graph` selector from section 4.1; graph routes never serialize a node
credential.

### 4.5 coordination replies

The three coordination routes use closed, credential-free response envelopes. A coordination view
has exactly `id`, `state`, `plan_digest`, `entries`, `expires_at`, and `evidence_id`. Each entry
has exactly `ordinal`, `resource_id`, `action`, `audience`, `scope`, `dpop_jkt`,
`completion_ttl_seconds`, and `state`. `evidence_id` is `null` until the broker writes the related
redacted record. A coordination response never has `capability`, a child credential, a proof, or a
trusted resource receipt.

`POST /v1/coordinations` returns `201` with every entry in `unreleased` state:

```json
{
  "coordination": {
    "id": "coordination-id",
    "state": "planned",
    "plan_digest": "sha256-canonical-plan-digest",
    "entries": [
      {
        "ordinal": 1,
        "resource_id": "billing",
        "action": { "method": "POST", "path": "/payments/42", "query": "" },
        "audience": "https://api.example.test",
        "scope": ["payments:write"],
        "dpop_jkt": "base64url-jwk-thumbprint",
        "completion_ttl_seconds": 300,
        "state": "unreleased"
      }
    ],
    "expires_at": "2030-01-01T00:00:00Z",
    "evidence_id": null
  }
}
```

`POST /v1/coordinations/{coordination_id}/approve` returns the same envelope with status `200`.
It sets the plan to `approved`, makes only ordinal one `ready`, and leaves every later entry
`unreleased`; it does not return a child grant or capability. A retry returns the exact same
envelope.

`POST /v1/coordinations/{coordination_id}/finalize` returns `200` with exactly a coordination
view and a redacted evidence view:

```json
{
  "coordination": {
    "id": "coordination-id",
    "state": "finalized",
    "plan_digest": "sha256-canonical-plan-digest",
    "entries": [
      {
        "ordinal": 1,
        "resource_id": "billing",
        "action": { "method": "POST", "path": "/payments/42", "query": "" },
        "audience": "https://api.example.test",
        "scope": ["payments:write"],
        "dpop_jkt": "base64url-jwk-thumbprint",
        "completion_ttl_seconds": 300,
        "state": "succeeded"
      }
    ],
    "expires_at": "2030-01-01T00:00:00Z",
    "evidence_id": "evidence-id"
  },
  "evidence": {
    "id": "evidence-id",
    "subject": { "type": "coordination", "id": "coordination-id" },
    "state": "finalized",
    "finalization_source": "resource",
    "recorded_at": "2030-01-01T00:00:01Z"
  }
}
```

The actual `entries` array reports the resulting durable state for every ordinal. A non-terminal
trusted success receipt can return the same closed envelope with the resulting active or approved
state; no caller-supplied outcome changes the derived ledger state.

### 4.6 public verification keys

`GET /.well-known/jwks.json` is a shared discovery route rather than a credential-bearing v1
operation. Its `200` response has exactly one `keys` array. Each key has exactly `kty`, `crv`,
`x`, `y`, `kid`, `use`, and `alg`; it is an EC P-256 verification key with `use: "sig"` and
`alg: "ES256"`. No entry may contain `d`, `p`, `q`, `dp`, `dq`, `qi`, `k`, a capability, a DPoP
proof, or any private key encoding.

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "base64url-x-coordinate",
      "y": "base64url-y-coordinate",
      "kid": "public-signing-key-id",
      "use": "sig",
      "alg": "ES256"
    }
  ]
}
```

## 5. DPoP and key custody

For every credential-bearing consume, direct-completion, or queue-enqueue request,
`Authorization: DPoP <credential>` and an RFC 9449 `DPoP` JWT are required. For consume and
direct completion, the credential is the grant capability; for queue enqueue, it is the distinct
broker-audience completion receipt. The proof MUST use `ES256`, include a public JWK, `htm`, `htu`,
`iat`, `jti`, and `ath`. `htu` is the canonical absolute request URL without query or fragment, as
defined by [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html); exact query comparison is
separately enforced by the reconstructed signed action. `ath` is the SHA-256 binding for the exact
credential. The proof JKT MUST equal the grant or completion receipt's fixed `dpop_jkt`. A proof
for another endpoint, a different key, a stale proof, or a repeated `(jkt, jti)` is rejected.

The broker accepts a proof only when the absolute difference between `iat` and its authoritative
clock is at most 60 seconds; the exact 60-second boundary is accepted. It MUST retain accepted
`(jkt, jti)` pairs for at least 360 seconds after `iat`; an unexpired duplicate is
`dpop_proof_invalid`. A resource adapter forwards the proof it observed; it does not synthesize a
proof or trust an agent's claimed target.

An SDK owns its DPoP private key. It MAY use a platform keystore, but MUST NOT export that key to a
broker, resource, log, telemetry system, evidence record, or fixture. The broker signing key stays
only in broker-controlled secret storage; resource adapters receive at most public verification
material. v1 requires these custody properties, not a particular language, keystore API, or SDK.

## 6. idempotency and clocks

`Idempotency-Key` is required on exchange, grant approval, completion, completion-queue enqueue,
revoke, renewal, graph creation/node approval/node finalization/graph cancellation, and coordination
creation/approval/finalization. It is 1–128 visible ASCII characters. The broker binds `(route,
authenticated actor, Idempotency-Key)`
to `SHA-256(JCS({"route": route, "actor": actor, "body": body}))`, where JCS is the
[JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html), `route` is the exact
versioned method/path, `actor` is the broker's opaque authenticated-identity binding, and `body`
is the parsed request object after validation. The actor binding is internal and MUST NOT appear in
the response or evidence view.

An exact retry has the same digest and returns the original status, grant/evidence/queue ID, and
credential if one was issued; it never reserves authority or mints again. Reusing the key with a
different canonical request or actor returns `409 idempotency_key_reused` without mutation.

Consume has no retry key because capability consumption is the idempotency boundary. SDKs MUST treat
an unknown consume outcome as requiring an evidence/query decision, not as permission to repeat a
protected action.

The broker clock is authoritative. A grant is expired when `broker_now >= expires_at`; there is no
expiry grace period. A client clock is only a scheduling hint: SDKs may warn before `expires_at` but
MUST NOT decide that a grant is usable, extend its TTL, or substitute a local expiry result for the
broker response. Any server `Date` header is advisory only.

## 7. approval presentation and evidence

Before an approver can act, the broker MUST render its resolved action, exact audience, granted
scope, DPoP JKT binding, use limit, expiry, and any coordination resource entry. Agent prose,
labels, or a parent-plan summary cannot replace these fields. The approver sees a grouped plan only
as context; approval still authorizes one exact child grant.

Evidence is append-only and redacted. It records IDs, state transitions, server times, resolved
action/audience/scope, finalization source, policy/profile/coordination references, and replay or
delivery outcomes. It MUST NOT record sensitive authorization material. Evidence finalization is
durable before any best-effort delivery retry; delivery failure cannot restore a grant.

## 8. error contract

Every non-2xx response has exactly `{"error":"code"}` plus an optional safe
`retry_after_seconds` only for `temporarily_unavailable`. It MUST have no credential, proof,
assertion, key, or internal stack detail. These status mappings are frozen for v1.
[`errors.json`](../../conformance/broker-wire/v1/errors.json) is the machine-readable canonical
map. Its three `sdk_queue` entries are stable local SDK outcomes with HTTP-status equivalents; every
other entry is a broker HTTP response. The table below is the human-readable mirror and must stay
in sync with that manifest.

| Error | HTTP | Meaning |
| --- | --- | --- |
| `invalid_request` | 400 | Malformed, unknown, duplicate, wildcard, or internally inconsistent input. |
| `invalid_credential` | 401 | Missing or invalid capability/delegation authentication. |
| `dpop_proof_invalid` | 401 | Invalid, stale, cross-endpoint, or replayed DPoP proof. |
| `wrong_dpop_key` | 401 | Valid proof key does not equal the grant JKT. |
| `grant_expired` | 401 | Broker clock reached the grant's hard expiry. |
| `grant_revoked` | 401 | Completion, revocation, or finalization ended authority. |
| `scope_not_authorized` | 403 | Requested scope is outside trusted authority or profile scope. |
| `policy_blocked` | 403 | Policy blocks the request. |
| `approval_required` | 403 | Approval identity or approved state is absent where required. |
| `operator_authorization_required` | 403 | Operator finalization lacks trusted operator authorization. |
| `grant_not_approved` | 403 | Consume attempted before an approved state. |
| `wrong_audience` | 403 | Target audience is not the exact bound audience. |
| `action_not_authorized` | 403 | Observed method, path, or query differs from the exact action. |
| `coordination_not_authorizing` | 403 | Parent plan was used as authority, a child exceeds its entry, or an ordinal is released out of order. |
| `standing_profile_required` | 403 | Multi-use was requested without an explicit eligible profile. |
| `standing_profile_mismatch` | 403 | Action, audience, scope, JKT, or limit differs from the profile. |
| `renewal_not_allowed` | 403 | Policy/profile does not permit the requested renewal. |
| `cross_resource_reuse_forbidden` | 403 | A reusable grant and coordination were combined. |
| `grant_not_found` | 404 | No grant/evidence exists for the supplied ID. |
| `coordination_not_found` | 404 | No coordination exists for the supplied ID. |
| `grant_already_consumed` | 409 | Another consume already won. |
| `token_already_exchanged` | 409 | One-use trusted delegation already minted authority. |
| `idempotency_key_reused` | 409 | Same key has a different actor or canonical request. |
| `partial_execution` | 409 | A coordination cannot be reported as all-or-nothing after child results diverge. |
| `reuse_limit_exhausted` | 409 | A bounded-multi-use grant or standing segment has no successful consumes left. |
| `coordination_invalid` | 400 | Plan has invalid/duplicate resource entries or an unsafe parent field. |
| `coordination_expired` | 401 | Parent plan expired before a new child exchange. |
| `temporarily_unavailable` | 503 | Durable broker/evidence work could not finish safely. |
| `graph_invalid` | 400 | Graph metadata is malformed or has duplicate node IDs. |
| `graph_cycle` | 400 | Graph dependencies are cyclic. |
| `graph_expired` | 401 | A graph deadline has elapsed. |
| `graph_cancelled` | 409 | A requested operation is disallowed by cancellation. |
| `graph_terminal` | 409 | A requested operation targets a terminal graph. |
| `graph_idempotency_conflict` | 409 | A graph creation key was reused with different immutable metadata. |
| `node_not_found` | 404 | A node does not belong to the named graph. |
| `node_dependency_unsatisfied` | 409 | A predecessor has not succeeded. |
| `node_terminal` | 409 | A node is already terminal. |
| `node_authority_reused` | 409 | An assertion, grant, or credential was attached to another node. |
| `node_evidence_invalid` | 403 | A terminal node event lacks its required trusted binding. |
| `queue_unauthenticated` | 401 | A completion enqueue lacks required authenticated possession. |
| `invalid_completion_receipt` | 401 | A completion receipt signature, issuer, shape, or purpose is invalid. |
| `wrong_completion_audience` | 403 | A receipt audience is not the exact completion endpoint. |
| `wrong_completion_dpop_key` | 401 | A proof does not match a receipt JKT. |
| `completion_receipt_expired` | 401 | A receipt deadline has elapsed. |
| `queue_idempotency_conflict` | 409 | A dedupe key was reused with a different immutable queue payload. |
| `queue_item_not_found` | 404 | A requested local durable queue item does not exist. |
| `queue_not_retryable` | 409 | A requested local queue retry or requeue is not permitted. |
| `completion_key_unavailable` | 409 | The original protected completion DPoP key is unavailable; the local item is dead-lettered without a broker send. |

## 9. conformance boundary and planned negatives

`conformance/broker-wire/v1/cases.json` is a credential-free planned fixture and
`errors.json` is its exhaustive failure map. A harness supplies its own test credentials and keys;
no fixture literal is usable as authentication material. It covers allow/pending/block exchange,
exact retry and collision, approval retry, one consume and replay, audience/action/DPoP failures,
strict expiry boundaries, completion idempotency, graph and queue failures, and every error mapping
above.

A v1 implementation needs additional negative tests for malformed JSON, duplicate fields, wildcard
or prefix audience matching, implicit scope expansion, a child that exceeds a coordination entry,
cross-resource/reuse composition, private-key/log leakage, and an evidence or delivery failure that
accidentally revives authority. Passing the fixture alone is necessary but not sufficient for a
security review.
