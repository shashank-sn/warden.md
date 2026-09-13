# v1 grant-contract plan

Status: specified design contract. Runtime implementation and a v1 reference runner are planned,
not delivered by this change.

## Outcome

The five v1 follow-on issues have bounded, linked specifications and a portable fixture corpus. The
design extends v0 without turning one-use credentials into broad standing authority, a workflow
engine, or an SDK compatibility claim.

| Issue | Contract | Observable boundary |
| --- | --- | --- |
| [#22](https://github.com/shashank-sn/warden.md/issues/22) | [Task graphs](../spec/task-graphs.md) | Immutable node metadata; every executable node gets its own exact one-use grant. |
| [#23](https://github.com/shashank-sn/warden.md/issues/23) | [Cross-resource coordination](../spec/cross-resource-coordination.md) | A non-authorizing parent coordinates independently bound child grants. |
| [#24](https://github.com/shashank-sn/warden.md/issues/24) | [Durable completion queues](../spec/durable-completion-queues.md) | A separate receipt queues completion; late delivery cannot revive authority. |
| [#25](https://github.com/shashank-sn/warden.md/issues/25) | [Broker SDK wire v1](../spec/broker-sdk-wire-v1.md) | A language-neutral HTTP, DPoP, error, clock, and key-storage contract with fixtures. |
| [#26](https://github.com/shashank-sn/warden.md/issues/26) | [Bounded reuse and standing grants](../spec/bounded-reuse-standing-grants.md) | Explicit versioned reusable profiles that cannot change v0 defaults. |

## Non-negotiable boundaries

1. v0 stays one action, one audience, one DPoP JKT, and one successful consume. A v1-capable
   broker rejects an extension field on its v0 surface rather than silently ignoring it.
2. A graph, coordination parent, queue record, or standing envelope is not a bearer credential.
   Only an exact, signed, DPoP-bound child credential may authorize a protected action.
3. The coordinator is authoritative for eligibility, idempotency, fencing, counters, expiry,
   finalization, deduplication, and replay. D1 may project state but may not decide it.
4. Business actions never auto-retry or compensate. A resource outcome can advance an ordered plan
   only when a configured trusted verifier accepts it.
5. Evidence and fixtures hold safe identifiers, digests, counters, codes, and timestamps only—never
   credentials, DPoP proofs, private JWK material, assertions, or raw result payloads.

## Delivery shape

This change supplies contract documents, a portable wire fixture corpus, and a test-plan ledger.
It deliberately does not add a graph engine, durable outbox, cross-resource runtime, reusable token
runtime, a non-TypeScript SDK, a schema migration, or a deployment claim. The present TypeScript
broker is a draft-v0 reference and is not a selected v1 conformance implementation.

Before a v1 implementation can move a planned case to `PASS`, it must add behavior tests for that
case, run the unchanged wire fixtures through an independently implemented runner, and complete the
[v1 review gate](../security/review-checklist.md#v1-implementation-gate).

## Verification

- Parse the v1 wire corpus and v1 test-plan JSON.
- Verify every linked v1 specification exists and every planned case ID is unique and mapped to an
  issue requirement.
- Run the repository gate. This validates the documentation/fixture contract only; it is not proof
  of a deployed v1 coordinator, Cloudflare integration, SDK durability, or a selected alternate SDK.
