# durable completion queues

License: MIT
Status: planned v1 design — not implemented and not a v0 extension.

This document defines an opt-in v1 durable SDK queue for reporting completion
after offline operation or process restart. It amends
[completion-scoped grants](./completion-scoped-grants.md). It does not turn
completion into authority, alter v0 grant expiry, or replace v0 revocation
delivery.

The current CompletionClient buffer is an in-memory map with bounded retries. A
process loss intentionally falls back to the grant TTL. That buffer is not durable
storage, is not a v1 queue implementation, and is not evidence of restart-safe
delivery.

## 1. boundary

A durable-queue exchange is an explicit v1 opt-in. Its request has the
`completion_queue` object defined by [the wire contract](./broker-sdk-wire-v1.md#41-exchange):
it supplies a public completion DPoP JKT that is **different** from the action
credential JKT. The broker issues an opaque broker-audience completion receipt only
in the queue-enabled allowed exchange or approval envelope. A pending exchange has
no receipt.

A completion receipt authorizes only one logical report to the broker's exact
completion-queue endpoint. It has no action, scope, resource, or minting power. It
MUST NOT contain, reuse, or be accepted as:

- the action credential used at the protected resource;
- a resource-audience credential;
- a subject assertion or approval decision; or
- a revocation event or revocation-delivery receipt.

The completion DPoP key is a separate restart-surviving, non-exportable local key.
Its public JKT is deliberately known before issuance; the broker never learns or
receives the private key. A queue can make a completion report durable; it can never
make a grant valid, renew it, or invoke the protected action.

## 2. receipt, local record, and broker queue record

The completion receipt has at least these signed claims. `completion_event_id` is
not pre-issued: the SDK chooses it when reporting the completed action, and the
broker atomically binds the receipt to that event on the first accepted enqueue.

| Completion receipt field | Required | Meaning |
| --- | --- | --- |
| `receipt_id` | yes | Opaque stable identifier. |
| `grant_id` | yes | The one grant whose finalization can be reported. |
| `iss` | yes | Issuing broker. |
| `aud` | yes | Exact `POST /v1/grants/{grant_id}/completion-queue` URL, never the protected resource. |
| `purpose` | yes | The literal `completion_queue`. |
| `cnf.jkt` | yes | The separately supplied completion DPoP thumbprint. |
| `issued_at` | yes | Broker timestamp. |
| `expires_at` | yes | Receipt deadline, bounded by completion-evidence retention and allowed to outlive grant expiry. |
| `max_reports` | yes | Always `1`; an exact idempotent enqueue does not consume another report. |

| Local SDK item field | Required | Meaning |
| --- | --- | --- |
| `queue_id` | yes | Opaque local durable identifier. |
| `dedupe_key` | yes | Caller key or canonical hash of broker, grant, receipt, and event IDs. |
| `receipt` | yes | Encrypted receipt at rest; never copied to logs or metrics. |
| `completion_key_reference` | yes | Secure-storage handle for the non-exportable DPoP key, not private-key material. |
| `created_at`, `updated_at` | yes | Queue timestamps from a monotonic local source where available. |
| `state` | yes | `queued`, `delivering`, `retry_wait`, `broker_accepted`, `dead_letter`, `expired`, or `cancelled`. |
| `attempts`, `next_attempt_at` | yes | Retry accounting and schedule. |
| `last_code` | conditional | Stable broker or transport outcome only. |
| `broker_queue_id` | conditional | Opaque ID from the accepted broker queue view. |
| `retention_until` | yes | Latest permitted local metadata retention time. |

The SDK MUST encrypt receipt material and key references at rest using the
platform's protected storage. A restart-capable delivery requires the original
completion DPoP key to remain usable through that protected handle. If it does
not, the scheduler MUST NOT substitute a new key; it moves the item to
`dead_letter` with `completion_key_unavailable`.

The broker has a separate durable queue record. Its closed public view is defined
in [the wire contract](./broker-sdk-wire-v1.md#43-queue-views); its states are
`accepted`, `processing`, `recorded`, `recorded_late`, and `dead_lettered`. An
accepted enqueue is not proof that broker finalization has already run.

## 3. authenticated enqueue and deduplication

Local enqueue and broker enqueue are separate operations. Local enqueue is the
first atomic operation: after the protected action, the SDK MUST durably persist
the encrypted receipt, non-exportable key handle, canonical terminal envelope,
dedupe key, and `queued` state in one local transaction **before** it returns a
queue ID to the caller. It requires no network and MUST succeed or fail locally as
one operation, so an offline SDK can restart and resume delivery later.

The SDK verifies broker signature, issuer, receipt shape, exact broker audience,
literal purpose, receipt expiry, grant ID, and its own completion JKT when it
first receives a receipt online. It then persists the verified receipt with its
issuance metadata. Local enqueue MUST refuse an unverified receipt; it does not
need to create a DPoP proof or contact the broker. For the same dedupe key and
canonical immutable payload, local enqueue returns the original queue ID and
state. Reusing a key with a different receipt, broker, grant, or event ID MUST
fail with `queue_idempotency_conflict`.

The local scheduler later sends
`POST /v1/grants/{grant_id}/completion-queue`. It presents the persisted completion
receipt as a DPoP-bound broker credential and a fresh proof for that exact endpoint;
it does not present the action credential. A valid broker enqueue transaction
durably binds the receipt and completion event, creates or returns one broker queue
record, and returns `202` with the closed `accepted` queue view. An exact retry
returns the same `202` and broker queue ID. The broker's own durable worker later
records final evidence and advances the broker queue view; clients observe that
result through the status route or evidence route, never by reinterpreting the
initial `202` as a finalization response.

The enqueue wire body is exactly `{"completion_event_id":"opaque-stable-id"}`.
`Idempotency-Key`, `Authorization: DPoP <completion-receipt>`, and `DPoP` are HTTP
headers; a completion receipt, proof, key handle, dedupe key, and local queue state
MUST NOT be copied into the JSON body. `GET
/v1/grants/{grant_id}/completion-queue/{queue_id}` returns a non-secret broker queue
view to the broker-authenticated SDK actor that owns the queue item. It is not
authorized by replaying the completion receipt.

Two portable SDK-local operations are intentionally distinct from HTTP routes:

- `queue/scheduler-tick` with `{"queue_id":"opaque-local-id"}` selects a due
  `queued` or `retry_wait` item, makes at most one fresh-proof network attempt, and
  applies retry-cap/deadline state transitions.
- `queue/requeue` with the same body is an operator-authorized transition only from
  `dead_letter` to `queued`, before receipt expiry and with the original key and
  immutable payload still available. It returns `queue_not_retryable` for
  `broker_accepted`, `expired`, or `cancelled` local items.

Their stable local failures use the `sdk_queue` entries in
[the v1 error map](../../conformance/broker-wire/v1/errors.json), expressed as
`{"error":"code","status":status-equivalent}`. They are not broker wire routes.

## 4. delivery and broker transition rules

For each local scheduler attempt, the SDK MUST generate a fresh DPoP proof over
POST and the receipt's exact broker completion endpoint. It sends only the receipt,
event ID, and fresh proof. It MUST NOT send the action credential, a resource DPoP
proof, or a revocation-delivery payload.

Before creating the broker queue record, the broker MUST atomically validate receipt
signature, issuer, audience, purpose, expiry, event ID, DPoP proof, and
receipt-to-grant binding. It then durably records exactly one accepted queue item
before returning `202`. A separate broker worker processes it under the following
grant rules:

| Grant state when broker worker processes the item | Required broker outcome |
| --- | --- |
| approved or consumed | Finalize and revoke remaining grant authority, append completion evidence, queue state `recorded`. |
| revoked | Preserve revoked state, deduplicate by completion event, append late evidence if new, queue state `recorded_late`. |
| expired | Preserve expired state, append late evidence if new, queue state `recorded_late`. |
| denied or unknown | Do not change authority; retain a safe terminal rejection or dead-letter state. |

`recorded_late` proves only that late completion evidence was retained. In
particular, an expired or revoked grant MUST stay expired or revoked; no receipt,
retry, requeue, broker worker, or late delivery may recreate, approve, consume, or
extend it.

| Local SDK state | Trigger | Next state | Required rule |
| --- | --- | --- |
| none | Locally durable enqueue of a verified receipt | queued | Persist exactly once before local acknowledgement; no network is required. |
| queued or retry_wait | `queue/scheduler-tick` selects due item | delivering | Respect `next_attempt_at`, retry cap, and receipt deadline. |
| delivering | Broker returns `202 accepted` | broker_accepted | Persist broker queue ID; erase receipt/key material when recovery no longer needs it. |
| delivering | Retryable transport, 429, or `temporarily_unavailable` | retry_wait | Back off with jitter; retain durable item. |
| queued, retry_wait, or delivering | Scheduler sees receipt deadline | expired | Stop delivery and retain safe metadata only. |
| queued or retry_wait | Authorized local cancellation | cancelled | Stop delivery; local cancellation does not alter broker authority. |
| scheduler at cap | No network attempt | dead_letter | Persist `retry_cap_exhausted`, safe metadata, and no broker delivery. |
| delivering | Stable authentication, binding, or schema rejection | dead_letter | Do not retry automatically. |
| dead_letter | Authorized `queue/requeue` before receipt expiry | queued | Preserve queue ID, event ID, and audit trail; never mint a new receipt. |

The broker's `accepted -> processing -> recorded|recorded_late|dead_lettered`
transition is independent of the local SDK state. A `broker_accepted` local item is
not an authority state and may be retained only as safe observability metadata.

## 5. retry, retention, observability, and dead letters

Local retries use bounded exponential backoff with jitter, a configured attempt
cap, and no retry past receipt expiry. A fresh DPoP proof is mandatory for every
attempt; a captured proof is never retried. The SDK retries only transport failures
and explicit retryable broker responses. It MUST dead-letter stable 4xx binding,
audience, purpose, signature, and key errors.

Retention has two layers:

- Receipt material is retained only until the broker accepts it, the receipt expires,
  or a bounded dead-letter recovery window ends. It is then deleted or
  cryptographically erased.
- Safe queue metadata, state transitions, attempt counts, stable codes, broker queue
  IDs, and broker evidence IDs are retained until `retention_until` for operational
  review.

Observability MUST expose queue depth by state, age, attempts, retry outcome,
dead-letter reason code, broker queue ID, and broker evidence ID when available. It
MUST NOT expose a receipt, action credential, DPoP proof, private-key material, raw
assertion, approval secret, or arbitrary terminal payload.

A dead letter is a durable operator-facing record, not a fallback authorization
path. Requeue is allowed only while the original receipt is valid, the original
completion DPoP key is available, and the immutable payload matches. Otherwise the
item remains terminal and the grant's ordinary expiry or revocation state is
authoritative.

## 6. stable errors and results

Existing v0 grant errors remain applicable. A v1 queue implementation adds these
stable codes and results.

| Code or result | HTTP / queue outcome | Meaning |
| --- | --- | --- |
| queue_unauthenticated | 401 | Enqueue lacks required local identity or DPoP possession. |
| invalid_completion_receipt | 401 | Receipt signature, issuer, shape, or purpose is invalid. |
| wrong_completion_audience | 403 | Receipt audience is not the exact broker completion endpoint. |
| wrong_completion_dpop_key | 401 | Proof does not match receipt `cnf.jkt`. |
| completion_receipt_expired | 401 | Receipt deadline has elapsed. |
| queue_idempotency_conflict | 409 | Dedupe key was reused with different immutable payload. |
| queue_item_not_found | local 404 | Local queue item does not exist. The broker status route uses `grant_not_found` for an unobservable grant/queue pairing. |
| queue_not_retryable | 409 | Requested local requeue is not permitted. |
| completion_key_unavailable | local 409 + `dead_letter` | Original protected DPoP key cannot make a valid proof; scheduler sends nothing. |
| accepted | HTTP 202 | Broker durably owns one queue record; finalization has not yet been claimed. |
| recorded | broker queue state | Broker finalized active authority and stored evidence. |
| recorded_late | broker queue state | Broker stored evidence while preserving expired or revoked authority. |
| temporarily_unavailable | local `retry_wait` | Broker permits a later local scheduler attempt. |

## 7. security cases

- A queue MUST reject an action credential, resource-audience credential, or
  revocation event in place of a completion receipt.
- A receipt for broker A, grant A, or one completion DPoP key MUST fail at broker B,
  grant B, or a different key before any queue or evidence mutation.
- A receipt replay with the same completion event is idempotent; a different event
  ID cannot overwrite or revive an already terminal grant.
- An attacker who modifies local queue metadata, dedupe keys, retry timing, or a
  terminal disposition cannot change broker authority without a valid receipt and
  fresh matching DPoP proof.
- Local-clock rollback, offline operation, process restart, or an expired completion
  key can delay or dead-letter delivery, but cannot extend receipt or grant validity.
- Queue and broker logs MUST treat receipt material as secret and redact it before
  telemetry, support export, or dead-letter inspection.

## 8. v1 amendment and negative-test matrix

This document is a v1 design contract only. It requires an explicit negotiated
queue capability, durable protected storage, and a broker completion-receipt
endpoint. The v0 direct completion path and its current in-memory SDK retry buffer
remain supported but are not durable-queue conformance.

| ID | Negative case | Expected result |
| --- | --- | --- |
| CQ-NEG-01 | Enqueue an action credential or revocation-delivery receipt. | Reject with `invalid_completion_receipt`; persist nothing. |
| CQ-NEG-02 | Enqueue a receipt for a resource audience or another broker endpoint. | Reject with `wrong_completion_audience`. |
| CQ-NEG-03 | Restart with no original protected completion DPoP key. | Move local item to `dead_letter` with `completion_key_unavailable`; never substitute a key. |
| CQ-NEG-04 | Reuse a dedupe key with different grant, receipt, or event ID. | Reject with `queue_idempotency_conflict`; preserve original item. |
| CQ-NEG-05 | Replay a stale DPoP proof or a proof bound to another URL. | Reject before queue/evidence mutation with `wrong_completion_dpop_key` or `dpop_proof_invalid`. |
| CQ-NEG-06 | Receive a retryable outage, then restart before the next attempt. | Retain `retry_wait` durably and let only `queue/scheduler-tick` resume with a fresh proof. |
| CQ-NEG-07 | Broker worker processes an accepted item after grant expiry or revocation. | Report `recorded_late`; preserve terminal grant state and never revive authority. |
| CQ-NEG-08 | Retry a `broker_accepted`, recorded, or recorded-late item. | Do not transmit again; observe broker queue/evidence state only. |
| CQ-NEG-09 | Scheduler reaches receipt expiry or retry cap. | Stop automatically and retain safe `expired` or `dead_letter` metadata. |
| CQ-NEG-10 | Inspect logs, metrics, backups, or dead-letter exports. | Verify no receipt, action credential, DPoP proof, raw assertion, or private key is present. |
| CQ-NEG-11 | Ask for a queue receipt with the action DPoP JKT, a graph, a standing profile, or a coordination child. | Reject before issuance; queue receipts are opt-in, one-use, and bound to a distinct completion JKT. |
