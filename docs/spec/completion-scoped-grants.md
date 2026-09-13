# completion-scoped grants

License: MIT
Status: draft v0 — not a standard; implementers must treat unknown fields as unsupported.
Security considerations: see the [threat model](../security/threat-model.md).

## Changelog

- \`v0\` (2026-09-13): first interoperable reference contract for one-use, completion-scoped grants.

## 1. Overview

A completion-scoped grant is delegated authority for one exact action at one resource. A broker MUST
only narrow the subject authority it receives. It MUST bind a grant to one audience and one DPoP
key thumbprint, permit one successful protected call, and revoke the remaining authority when the
agent says \`done\` or when the grant TTL elapses.

This document composes an auth.md registration, an id-jag or RFC 8693-style subject assertion,
RFC 8707 resource targeting, and RFC 9449 DPoP. It does not modify any of those formats.

## 2. Grant record

| Field | Required | Type | Signed in credential | Meaning |
| --- | --- | --- | --- | --- |
| \`id\` | yes | opaque string | yes | Immutable grant identifier. |
| \`agent_id\` | yes | string | yes | Registered requesting agent. |
| \`subject_id\` | yes | string | yes | Subject whose authority was narrowed. |
| \`action\` | yes | action descriptor | yes | Resolved method, path, and query; the resource reconstructs it from the received request. |
| \`audience\` | yes | absolute HTTPS URL | yes | Exactly one protected resource. |
| \`requested_scope\` | yes | string array | no | What the agent asked to do. |
| \`granted_scope\` | yes | string array | yes | Intersection actually authorized. |
| \`issued_at\` | conditional | RFC 3339 instant | yes | Set once approval mints authority. |
| \`expires_at\` | yes | RFC 3339 instant | yes | Hard latest-use time. |
| \`use_limit\` | yes | integer \`1\` | yes | One successful consume only. |
| \`dpop_jkt\` | yes | JWK thumbprint | yes | RFC 9449 confirmation binding. |
| \`policy_decision\` | yes | enum | no | \`allow\`, \`require-approval\`, or \`block\`. |
| \`approver\` | conditional | subject string | no | Human or policy that approved. |
| \`completion_ttl\` | yes | duration | no | Fallback completion deadline. |
| \`evidence_id\` | conditional | opaque string | no | Stable evidence record pointer. |

The credential MUST NOT contain a subject token, approval UI state, or any secret other than its
own signed claims.

## 3. State machine

\`\`\`mermaid
stateDiagram-v2
    [*] --> proposed: exchange accepted
    proposed --> approved: policy allow or human approval
    proposed --> denied: policy block or denial
    proposed --> expired: ttl alarm
    approved --> consumed: one successful atomic consume
    approved --> revoked: explicit completion or revocation
    approved --> expired: ttl alarm
    consumed --> revoked: explicit completion
    consumed --> expired: ttl alarm
    denied --> [*]
    revoked --> [*]
    expired --> [*]
\`\`\`

| From | Trigger / actor | To | Required side effect | Idempotency rule |
| --- | --- | --- | --- | --- |
| none | validated exchange / broker | \`proposed\` | Audit proposed request and resolved audience. | Same idempotency key returns the original grant. |
| \`proposed\` | policy allow or approver / broker | \`approved\` | Reserve subject assertion once and mint a one-use credential. | A repeated approval returns no second credential. |
| \`proposed\` | block or denial / policy or approver | \`denied\` | Audit decision; never mint. | Repeated decision leaves \`denied\`. |
| \`proposed\`, \`approved\`, \`consumed\` | durable-object TTL / broker | \`expired\` | Revoke, emit evidence and schedule fan-out. | Later alarms return the same evidence. |
| \`approved\` | valid credential + DPoP / resource | \`consumed\` | Atomic compare-and-set and consume audit event. | Exactly one caller succeeds; later callers get \`grant_already_consumed\`. |
| \`approved\`, \`consumed\` | \`POST /grants/{id}/complete\` / authenticated actor | \`revoked\` | Complete, revoke, persist evidence, schedule fan-out. | Same evidence id is returned. |
| any active state | authenticated operator / broker | \`revoked\` | Verify the operator through a trusted binding, persist the finalization, and schedule fan-out. | Same evidence id is returned. |

## 4. Authorization and binding rules

1. The broker MUST obtain agent registration and subject authority from a trusted verifier before
   exchange and intersect requested scope with both values. It MUST NOT accept either authority
   value from the proposal. Any requested scope outside that intersection MUST fail with
   \`scope_not_authorized\`; it MUST NOT silently broaden authority.
2. The resource MUST be an exact audience. The credential \`aud\`, request target, and resource-side
   configuration MUST match. A broker MUST reject a different resource with \`wrong_audience\`.
3. A credential MUST contain \`cnf.jkt\` and the resource MUST verify a fresh DPoP proof over the
   received request method and URL. It MUST reconstruct the signed action, including a query string,
   from that request rather than trusting a client-supplied action field. Key substitution returns
   \`wrong_dpop_key\`; invalid or replayed proof returns \`dpop_proof_invalid\`.
4. Reserving the validated subject assertion and the \`approved -> consumed\` transition MUST be
   atomic at their respective ownership boundaries. A reusable assertion can never mint two live
   consumable credentials.
5. The approval view MUST display the resolved action, audience, and granted scope—not agent-supplied
   prose alone. See threat [T4](../security/threat-model.md#t4-confused-deputy-and-approval-injection).
6. A deployed resource MAY preverify the credential against the broker's public JWKS, but it MUST
   send the credential and received DPoP proof to the broker-owned consume boundary before performing
   the protected action. The broker signing private key MUST remain outside the resource deployment.

## 5. Completion and evidence

\`POST /grants/{id}/complete\` is authoritative when authenticated for the grant. The endpoint MUST
derive the DPoP method and URL from the received HTTP request, not from the JSON body. It marks the
grant revoked even if a revocation callback is unavailable. The completion TTL alarm is a mandatory
fallback, uses the same finalization path, and leaves a record with the completion source. A broker
MUST reject a proposed TTL that exceeds its configured maximum; an agent cannot extend authority.

Evidence records preserve an append-only transition timeline and stable id, then expose the current
relay-delivery snapshot alongside the approver, completion source, and retention deadline. The
reference broker hands an at-least-once
\`{grantId,target,eventId}\` record to a configured trusted relay. A deployment relay and receiver MUST
authenticate that handoff and retain the event id for deduplication if it exposes a remote event
endpoint; signing and receiver storage are not provided by this package. The broker MUST NOT place
credentials, DPoP proofs, or raw subject assertions in evidence or logs.

## 6. Error catalogue

| Code | HTTP | Trigger |
| --- | --- | --- |
| \`invalid_request\` | 400 | Missing or malformed proposal, completion, or consume input. |
| \`scope_not_authorized\` | 403 | Requested scope exceeds registration or subject authority. |
| \`policy_blocked\` | 403 | Matching policy blocks the proposed action. |
| \`approval_required\` | 403 | A client tries to use a proposal before approval. |
| \`operator_authorization_required\` | 403 | An operator revocation lacks a trusted operator authorization. |
| \`token_already_exchanged\` | 409 | A subject assertion has already minted authority. |
| \`invalid_credential\` | 401 | Signature, expiry, claim shape, or use marker is invalid. |
| \`wrong_audience\` | 403 | Credential or request target does not match the grant audience. |
| \`action_not_authorized\` | 403 | Credential or request method/path does not match the signed grant action. |
| \`wrong_dpop_key\` | 401 | Valid DPoP proof is bound to a different JWK thumbprint. |
| \`dpop_proof_invalid\` | 401 | Proof is invalid, stale, replayed, or bound to another request. |
| \`temporarily_unavailable\` | 503 | A broker or evidence operation could not finish without leaking internal failure details. |
| \`grant_not_approved\` | 403 | Grant has not reached \`approved\`. |
| \`grant_not_found\` | 404 | The referenced grant does not exist. |
| \`grant_already_consumed\` | 409 | A second protected call presents the same grant. |
| \`grant_expired\` | 401 | The grant TTL has elapsed. |
| \`grant_revoked\` | 401 | Completion or revocation already ended authority. |

## 7. Worked flow

1. An agent with registered \`payments:write\` subject authority proposes \`POST /invoices/42/pay\` at
   \`https://api.example.test\`; the policy requires approval.
2. The broker records \`proposed\` with \`granted_scope: ["payments:write"]\`, displays that exact
   action and audience, and returns an approval reference.
3. A human approves. The broker atomically reserves the subject assertion and mints a short-lived
   ES256 credential containing the grant id, one-use marker, audience, scope, and DPoP thumbprint.
4. The resource validates the credential and matching DPoP proof, atomically changes the grant to
   \`consumed\`, and performs the payment once.
5. The SDK calls \`complete\` in a \`finally\` block. The broker records \`revoked\`, creates evidence,
   and retries any revocation event delivery. If that call never arrives, the TTL alarm does it.

## 8. Prior art and v1 questions

This profile reuses schemen-gate's policy-gateway shape, executor's custody boundary, and
ghostget's proxy ergonomics. It extends them with a normative completion state machine, evidence
record, and mandatory one-use DPoP-bound credential.

The intentionally deferred v1 questions are tracked as [multi-step task graphs](https://github.com/shashank-sn/warden.md/issues/22),
[cross-resource grants](https://github.com/shashank-sn/warden.md/issues/23),
[durable completion queues](https://github.com/shashank-sn/warden.md/issues/24),
[non-TypeScript SDK interoperability](https://github.com/shashank-sn/warden.md/issues/25), and
[bounded multi-use and standing grants](https://github.com/shashank-sn/warden.md/issues/26). They
are not valid reasons to weaken the v0 rules above.
