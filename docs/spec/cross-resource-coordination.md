# cross-resource coordination

License: MIT
Status: planned v1 contract — not implemented by this repository.

This is a coordination profile for the planned v1 wire contract. It does not make the current
draft-v0 TypeScript broker v1-conformant. Its purpose is to let an agent describe bounded work at
several resources without creating a broad parent credential. The wire, error, DPoP, clock, and
key-custody rules are in [broker and sdk wire protocol v1](./broker-sdk-wire-v1.md).

## 1. model and invariant

A **coordination** is a non-authorizing record of named resource entries. It has no credential,
subject assertion, use allowance, wildcard audience, inherited scope, or bearer authority. It
cannot be presented to a protected resource and cannot itself move a resource action forward.

Each **child grant** is an ordinary exact grant associated with exactly one coordination entry. It
retains the normal v1 and v0-safe shape: one action, one audience, fixed scope, one JKT, one
successful consume, expiry, and final evidence. A parent plan never converts several child grants
into one multi-resource credential.

## 2. coordination record

`POST /v1/coordinations` is idempotent and accepts a complete bounded plan. The broker records at
least the following, resolving all policy values server-side:

| Field | Rule |
| --- | --- |
| `id` | Opaque coordination identifier; not authorization material. |
| `entries` | Non-empty array of entries with unique `resource_id` values and immutable contiguous `ordinal` values `1..n`. |
| `entries[].action` | One exact uppercase method, path, and exact query; no route template or wildcard. |
| `entries[].audience` | One exact canonical HTTPS audience; no wildcard, prefix, inherited base, or list. |
| `entries[].scope` | Non-empty unique set fixed for that entry; no `*` or parent-to-child inheritance. |
| `entries[].dpop_jkt` | One public JKT fixed for that entry's eventual normal child grant. |
| `entries[].child_use_limit` | Always `1`. |
| `entries[].completion_ttl_seconds` | Positive fixed child completion-TTL cap; an exchange cannot request a longer value. |
| `expires_at` | Absolute parent deadline. Every child expiry is less than or equal to it. |
| `state` | `planned`, `approved`, `active`, `finalizing`, `finalized`, or `expired`; no state authorizes a resource. |
| `evidence_id` | Set only on finalization and points to a redacted append-only record. |

The broker rejects an empty plan, non-contiguous/duplicate ordinal, duplicate resource ID, duplicate
canonical entry, wildcard or relative audience, empty/wildcard scope, a child use limit other than
`1`, or a request that attempts to carry a capability or standing profile. It returns
`400 coordination_invalid` with no partial record. Once a plan reaches `approved`, its ordered
entries and deadline are immutable; an edit requires a new plan and a new approval.

The `POST /v1/coordinations` JSON body contains exactly `entries` and `expires_at`; an entry
contains `ordinal`, `resource_id`, `action`, `audience`, `scope`, `dpop_jkt`, and
`completion_ttl_seconds`. `child_use_limit`, state, evidence, approval identity, and every
credential are broker-resolved or server-side values, not request fields. The route requires
`Idempotency-Key` outside the body. Its exact credential-free create, approval, and finalization
envelopes are defined in [the v1 wire response contract](./broker-sdk-wire-v1.md#43-coordination-replies).

## 3. child exchange and per-resource limits

An agent creates a child through `POST /v1/grants/exchange`, naming exactly one
`coordination.id` and `coordination.resource_id`. The child action, audience, scope, and JKT MUST
byte-for-byte match the canonical entry after the broker's canonicalization. The broker refuses a
child if trusted delegation or current policy is narrower than that frozen entry; it MUST NOT add a
scope, audience, query parameter, method, path segment, TTL, or JKT choice beyond the entry.

The broker independently verifies trusted delegation, registration, policy, and the child JKT. A
successful child has `use_limit: 1`, its own ID, own expiry, own approval decision, and own
evidence. A child may not outlive the coordination deadline. A parent plan can therefore provide
context and a broker-controlled release sequence, never a resource credential.

`standing_profile_id` and `coordination` are mutually exclusive. A request containing both fails
with `403 cross_resource_reuse_forbidden`; no profile or child state is changed.

## 4. frozen-plan approval and linear release

`POST /v1/coordinations/{coordination_id}/approve` is available only to the trusted approval
integration. It approves the frozen plan revision, not a generic "batch" or a bearer parent. The
approval surface MUST render **every** ordinal entry before the human can decide: ordinal,
method/path/query, exact audience, granted scope, fixed JKT, one-use limit, child expiry bound, and
the plan deadline. Agent prose and summary labels are contextual only. The approved view includes a
stable plan hash/revision so an edited plan cannot reuse an earlier decision.

The broker records that full-plan decision durably, rechecks policy and trusted delegation for the
first entry, and mints or marks ready only ordinal `1` as a normal exact one-use child grant. It
does not pre-mint, pre-authorize, or expose a capability for ordinals `2..n`.

After child `i` is atomically consumed and the resource action succeeds, only a trusted,
deployment-authenticated resource success receipt for child `i` may unlock ordinal `i + 1`. The
broker persists that receipt and the final child evidence first, rechecks the frozen entry/policy,
then mints or marks ready the next normal one-use child. A parent ID, agent claim, ordinary
completion retry, or a success receipt for another ordinal cannot release a later child.

Retrying the same plan approval or trusted receipt is idempotent. It returns the existing plan or
child state and cannot mint another child, broaden a sibling, reorder entries, or skip an ordinal.

## 5. consume, completion, and partial failure

For each released child, the broker-owned consume transition happens before the protected resource
begins the child action. It atomically changes `approved -> consumed`; exactly one call wins. The
resource then performs the action and supplies a trusted success receipt. The broker persists child
evidence before using that receipt to release the next ordinal. Completion/delivery retries are
idempotent but do not count as a success receipt or release another child.

The coordination becomes `finalizing` once no new child exchange is allowed, then reaches
`finalized` only after each existing child is final or has a durable terminal outcome. It does not
mean that all actions succeeded. Its evidence MUST preserve each child's ID, entry ID, consume
state, terminal outcome (`succeeded`, `failed`, `unknown`, `not_started`, or `expired`), and child
evidence ID when present.

If a child fails, is cancelled, expires, or is revoked, the broker finalizes the coordination,
disables every later unminted entry, and finalizes any already-created but unconsumed child. It does
not retry a consumed action, forge an all-success result, or silently compensate at another
resource. A compensating action requires a fresh exact grant and its own approval/policy decision.
A caller that tries to finalize a diverged plan as all-or-nothing receives `409 partial_execution`.

`POST /v1/coordinations/{coordination_id}/finalize` is available only to a trusted coordinator (the
broker, trusted resource adapter, cancellation service, expiry alarm, or operator). It records one
terminal event: trusted resource success, failure, cancel, expiry, or revoke. The broker derives
the plan outcome from child ledger/evidence state instead of trusting a caller's claimed overall
outcome. A terminal non-success event disables all remaining entries before final evidence is
returned. A retry returns the same coordination evidence ID.

Its exact JSON body has an `event` value of `success`, `failure`, `cancel`, `expiry`, or `revoke`;
`entry_ordinal` is optional and, when present, a positive integer:

```json
{ "event": "success", "entry_ordinal": 1 }
```

The trusted coordinator identity, resource receipt, and any DPoP material are outside that body.
`event` is an input to durable ledger processing, not a caller-authoritative overall outcome claim;
an absent or mismatched child ledger still yields the derived `partial_execution` result.

## 6. expiry, evidence, and replay

At `broker_now >= coordination.expires_at`, the broker rejects new child exchanges with
`401 coordination_expired`, disables every unreleased ordinal, and finalizes proposed or approved
children without allowing a consume. A consumed child has no remaining authority, but its business
outcome can still be `unknown`; the parent evidence records that uncertainty rather than inventing
completion. A later completion returns stable child evidence and cannot revive a grant, parent, or
later ordinal.

Every child keeps its own DPoP replay boundary, `(jkt, jti)`, and own atomic consume state. Reusing
one child's capability, proof, or evidence ID for another entry fails. Parent evidence is redacted:
it contains no capability, proof, subject assertion, private key, or raw authorization header.
Delivery retry state is evidence, not a reason to reopen authority.

## 7. errors and security matrix

The status mappings below are frozen by the [v1 wire error contract](./broker-sdk-wire-v1.md#8-error-contract).

| Threat or invalid condition | Required broker behavior | Error / HTTP | Planned negative test |
| --- | --- | --- | --- |
| Parent plan presented as a credential | Reject; issue no child or capability. | `coordination_not_authorizing` / 403 | Parent ID at protected resource. |
| Wildcard/prefix audience, template action, duplicate/non-contiguous ordinal | Reject the entire plan before state creation. | `coordination_invalid` / 400 | `https://*.example.test`, `/payments/*`, ordinal gap. |
| Child changes action/audience/JKT or widens scope/TTL | Reject rather than inherit or widen. | `coordination_not_authorizing` or `scope_not_authorized` / 403 | Child asks for sibling scope or path. |
| Later child requested before trusted prior success receipt | Keep it unreleased; no skipped ordinal or pre-mint. | `coordination_not_authorizing` / 403 | Ask for ordinal `2` before ordinal `1` success. |
| Coordination ID is absent or unknown | Do not infer a plan from client fields. | `coordination_not_found` / 404 | Unknown parent ID. |
| Expired parent | Block new children and create terminal redacted evidence. | `coordination_expired` / 401 | Exchange exactly at parent expiry. |
| Approval screen relies on agent text or omits an entry | Render the entire frozen plan; fail closed if unavailable. | `approval_required` / 403 | Misleading label plus hidden ordinal. |
| Concurrent/replayed child consume | Let one exact child consume; reject duplicates and cross-entry proof reuse. | `grant_already_consumed` / 409 or `dpop_proof_invalid` / 401 | Two consumes; same DPoP `jti` on sibling. |
| Child failure/cancel/expiry/revoke after prior success | Persist partial result and disable all later entries. | `partial_execution` / 409 for false all-success | Finalize plan as all-success after one failure. |
| Reusable profile combined with plan | Reject before any profile or coordination mutation. | `cross_resource_reuse_forbidden` / 403 | Exchange has both references. |
| Evidence/delivery failure | Keep final authority state; retry delivery separately. | `temporarily_unavailable` / 503 when durability is unavailable | Failing evidence writer does not restore child. |

## 8. planned conformance coverage

The credential-free v1 fixture covers the wire-level parent creation, full-plan approval with only
ordinal one ready, out-of-order child rejection, child mismatch, parent expiry, and failure,
cancellation, expiry, and revocation finalization that preserves partial evidence while disabling
later legs, plus reuse-composition cases. An implementation additionally needs tests that race
sibling consumes, lose a response after consume, lose a trusted success receipt, expire between
plan review and a later release, and prove that every evidence projection stays redacted. No v1
implementation or SDK is selected by this document.
