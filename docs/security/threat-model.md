# broker threat model and reference review

Status: reviewed against the reference implementation on 2026-09-13. This is a design review, not
an outside security audit. Credentials, proofs, and subject identifiers are deliberately absent from
this document and its log examples.

## Assets and trust boundaries

| Asset | Owner | Boundary |
| --- | --- | --- |
| One-use credential and DPoP private key | Agent session | Never written to disk by the SDK; resource sees only proof and bearer credential. |
| Subject identity and assertion | Service / broker | Validated before exchange; raw assertion is not logged or retained in evidence. |
| Approval decision | Human approval callback | View receives the broker-resolved action, audience, and scope. |
| Grant state and evidence | Broker coordinator Durable Object / D1 projection | State transitions and the audit-event stream are authoritative in the Durable Object. D1 is a best-effort nonsecret projection; evidence exposes a mutable current delivery snapshot. |
| Revocation event | Broker / trusted relay / resource subscriber | At-least-once event-id handoff with a relay receipt. Relay authentication, signing, and receiver replay storage are integration-owned. |

Adversaries may control agent-provided action text, race protected calls, replay captured requests,
substitute keys, retry webhook delivery, delay clocks, or attempt to splice a valid delegation into a
different resource. They do not receive the broker signing key or a trusted approval identity.

## v1 planning boundary

T9–T20 below are design controls and planned negative cases for the v1 amendments. They are not a
claim that the current v0 broker implements task graphs, cross-resource coordination, durable
completion queues, portable SDK wire v1, or reusable authority. The v0 controls above remain the
only implemented reference boundary until those planned cases have implementation evidence.

## Risk register

| ID | Threat | Impact | Likelihood | Mitigation | Owner | Status | Test / accepted risk |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T1 | Replay or double spend | High | Medium | Per-grant atomic \`approved -> consumed\` compare-and-set. | broker | mitigated | \`broker.test.ts\` concurrent consume case |
| T2 | Completion or revocation replay | High | Medium | Broker completion is idempotent and each relay handoff has a delivery event id. The deployed relay/receiver must authenticate and persist those ids before treating delivery as replay-safe. | broker + integration owner | bounded | \`broker.test.ts\` completion idempotency case; receiver contract is deployment-owned |
| T3 | Delegation-chain splicing | High | Low | Obtain registration and subject scope from a trusted authority resolver; reserve subject token once; credential carries grant and subject. | broker | mitigated | \`broker.test.ts\` scope, authority, subject-token, and idempotency cases |
| T4 | Confused deputy and approval injection | High | Medium | Broker resolves and displays action, audience, scope; policy matches structured fields; request handlers derive action and completion targets from received HTTP requests. | integration owner | mitigated | \`policy.test.ts\`, \`middleware.test.ts\`, and \`worker.test.ts\` endpoint-binding cases |
| T5 | Scope, TTL, or DPoP downgrade | High | Medium | Reject upscope and TTLs above the configured maximum; ES256 allowlist; mandatory JKT and fresh proof. | broker | mitigated | \`broker.test.ts\` audience/key/expiry/TTL cases |
| T6 | Credential leakage in observability | High | Medium | Stable code-only errors, safe audit detail schema, redaction review. | all maintainers | mitigated | \`security.test.ts\` audit/log-safety case |
| T7 | Revocation delivery loss | Medium | Medium | Completion remains authoritative; pending/failed receipt plus exponential retry. | broker | mitigated | \`broker.test.ts\` failed-delivery retry case |
| T8 | Approval after expiry | Medium | Low | Expiry checked inside transition lock and TTL finalization records evidence. | broker | mitigated | \`broker.test.ts\` expired approval case |
| T9 | Dependency cycle, missing prerequisite, unknown node, early exchange, substituted graph-node binding, or graph selector composition | High | Medium | Immutable graph definition, coordinator eligibility checks, and node-specific grants. | future v1 coordinator | specified | Planned \`V1-GRAPH-01\` through \`V1-GRAPH-03\`, \`V1-GRAPH-11\` through \`V1-GRAPH-13\` |
| T10 | Graph-level authority, mixed-resource sequencing, or node action/audience/scope/JKT substitution | High | Medium | No graph credential; every node independently resolves and binds a one-use grant; cross-resource ordering uses its own profile. | future v1 coordinator | specified | Planned \`V1-GRAPH-04\`, \`V1-GRAPH-05\`, and \`V1-GRAPH-10\` |
| T11 | Batch approval or missing resolved node detail | High | Medium | Node-specific approval displays exact binding, dependency state, expiry, and evidence policy. | integration owner | specified | Planned \`V1-GRAPH-06\` |
| T12 | Cancellation race allows a new consume or downstream step | High | Medium | Monotonic cancellation fence and coordinator-owned transition ordering. | future v1 coordinator | specified | Planned \`V1-GRAPH-07\` |
| T13 | Partial failure or expiry retries/advances business work | High | Medium | Terminal blocks are irreversible; retry requires a new graph, node, and grant. | future v1 coordinator | specified | Planned \`V1-GRAPH-08\` |
| T14 | Forged, replayed, or secret-bearing terminal evidence | High | Medium | Trusted evidence policy, deduped outcome identifiers, safe evidence schema. | broker + integration owner | specified | Planned \`V1-GRAPH-09\` |
| T15 | Forged, wrong-key, replayed, action-key-substituted, unavailable-key, or selector-composed completion receipt | High | Medium | Separate broker-audience receipt, a distinct completion DPoP JKT, and durable replay state. | future v1 coordinator | specified | Planned \`V1-QUEUE-01\` through \`V1-QUEUE-03\`, \`V1-QUEUE-11\` through \`V1-QUEUE-14\` |
| T16 | Queue dedupe collision, retry loss, expired receipt, or late delivery revives authority | High | Medium | Immutable payload digest, bounded retry/DLQ, late-delivery observation only. | future v1 coordinator | specified | Planned \`V1-QUEUE-04\` through \`V1-QUEUE-10\` |
| T17 | Cross-resource parent misuse, wildcard, unknown parent, scope expansion, out-of-order consume, or forged successor receipt | High | Medium | Non-authorizing parent, exact child grants, plan digest, trusted ordered outcome. | future v1 coordinator | specified | Planned \`V1-COORD-01\` through \`V1-COORD-10\` |
| T18 | v0 request is silently upgraded to reusable authority, a standing grant is mutated during downgrade, or reuse combines with coordination | High | Medium | Versioned explicit profile; v0 rejects extension fields, downgrade creates a fresh restricted one-use grant, and reuse never composes with coordination. | future v1 coordinator | specified | Planned \`V1-REUSE-01\`, \`V1-REUSE-02\`, \`V1-REUSE-08\`, and \`V1-REUSE-09\` |
| T19 | Multi-use counter/renewal race, mutable bounds, or proof/token substitution | High | Medium | Coordinator-owned atomic counters, fixed envelope digest, one active standing segment. | future v1 coordinator | specified | Planned \`V1-REUSE-03\` through \`V1-REUSE-06\` |
| T20 | Revoked or expired standing grant mints/uses a segment | High | Medium | Parent terminal state disables all segments and future renewal. | future v1 coordinator | specified | Planned \`V1-REUSE-07\` |

## Reference review checklist

- [x] ES256 is the only accepted credential and DPoP algorithm in the reference signer; \`none\` is
  rejected by shape and algorithm checks.
- [x] The deployed Worker publishes only `/.well-known/jwks.json`; resources use that public key for
  preverification and the broker-owned `/consume` boundary for the atomic transition. The signing JWK
  stays in the broker environment. `remote-contract.test.ts` exercises this split.
- [ ] The broker runtime deliberately accepts one configured ES256 signing key. It emits a `kid` but
  does not implement overlapping public-key verification or zero-downtime broker key rotation. Drain
  the bounded active-grant TTL before changing `BROKER_SIGNING_JWK`, or provide that key-ring boundary
  in the deployment integration.
- [x] One-use consume executes under a per-grant atomic lock; concurrent requests have one winner.
- [x] Audit details are scalar safe metadata only; no credential, proof, assertion, or subject token
  is accepted as an audit detail.
- [x] Complete and revoke return the same evidence record on retries.
- [x] HTTP errors expose stable codes, not underlying cryptographic or storage exceptions.
- [x] Revocation relay retries are visible in evidence without making completion non-authoritative.
- [ ] A deployment that requires signed revocation messages and receiver replay protection must provide
  them at its relay boundary; this reference supplies event ids and receipts, not that protocol.

## Negative-test matrix

| High-severity threat | Automated evidence | Result |
| --- | --- | --- |
| T1 double spend | \`packages/broker/test/broker.test.ts\` parallel consume | required in CI |
| T2 completion replay | \`packages/broker/test/broker.test.ts\` repeated complete | required in CI |
| T3 spliced / reused delegation | \`packages/broker/test/broker.test.ts\` scope + subject token | required in CI |
| T4 confused audience | \`packages/broker/test/policy.test.ts\` structured policy match | required in CI |
| T5 key/audience/expiry downgrade | \`packages/broker/test/broker.test.ts\` negative credential paths | required in CI |
| T6 secret logging | \`packages/broker/test/security.test.ts\` safe audit inspection | required in CI |
| T4 request/action substitution | \`packages/broker/test/worker.test.ts\` completion endpoint binding | required in CI |

## v1 planned negative-test matrix

The v1 cases are specified in [the v1 test plan](../plans/v1-grant-contracts-test-plan.json). Their
\`PLANNED\` status is intentional: this documentation change adds contract and fixture validation,
not an unimplemented runtime pass.

| Threats | Planned contract cases | Required result when implemented |
| --- | --- | --- |
| T9–T14 task graph lifecycle/evidence | \`V1-GRAPH-01\` through \`V1-GRAPH-13\` | Reject unsafe graph behavior without minting or advancing authority. |
| T15–T16 durable queue | \`V1-QUEUE-01\` through \`V1-QUEUE-14\` | Authenticate/dedupe/retry safely; require a separate completion key; never revive a terminal grant. |
| T17 coordination | \`V1-COORD-01\` through \`V1-COORD-10\` | Preserve exact per-resource grants and ordered trusted outcomes. |
| T18–T20 reuse/standing | \`V1-REUSE-01\` through \`V1-REUSE-09\` | Preserve v0 one-use and reject counter/renewal/revocation/downgrade bypasses. |
| Portable wire contract | \`V1-WIRE-01\` through \`V1-WIRE-08\` | Run the unchanged fixture corpus in an independent implementation. |

The broker-side state machine has no accepted high-severity implementation exception. The reference
does not provide a signed revocation-relay protocol, receiver replay store, or zero-downtime broker
signing-key rotation; deployments requiring those properties must supply them and obtain an
outside-core review before production use. This PR cannot supply that human approval.
