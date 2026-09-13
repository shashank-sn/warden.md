# release security checklist

Run this checklist against the exact commit proposed for deployment.

1. Confirm credentials and DPoP proofs are ES256 only; reject \`alg: none\`. The reference verifies
   against its one configured broker signing key and does not select keys by an untrusted \`kid\`.
2. Before changing \`BROKER_SIGNING_JWK\`, drain the bounded active-grant TTL. If zero-downtime
   rotation is required, verify the deployment's separate active-and-previous-key ring and that no
   private JWK is returned.
3. Run the concurrent consume test and inspect the compare-and-set ownership boundary.
4. Run completion/revoke idempotency tests and inspect evidence ids and delivery receipts.
5. Search logs, fixtures, and error bodies for tokens, proofs, assertions, and subject-token values.
6. Exercise wrong audience, wrong DPoP key, replayed proof, excess scope, late approval, and expired
   credential paths.
7. Confirm approval UI uses broker-resolved structured action, audience, and scope fields.
8. Confirm failed revocation relay handoff remains visible and retryable without reviving authority.
   Verify the deployment relay authenticates messages and the receiver persists delivery event ids
   when those properties are required.

## v1 implementation gate

These controls are specified design requirements. They are not represented as passing behavior in
the current v0 reference until the exact implementation and negative cases exist.

9. Reject a graph with a cycle, missing dependency, mutable node definition, graph-wide credential,
   or batch approval. Confirm each eligible node has its own resolved action, audience, scope, DPoP
   binding, assertion reservation, approval view, and one-use grant.
10. Exercise cancellation, approval, consume, terminal-report, and expiry races under the
    coordinator fence. Confirm a consumed action is evidenced but no unfinished node can proceed
    after cancellation, failure, or expiry.
11. For a cross-resource plan, reject wildcard or alias audiences, scope inheritance, dynamic legs,
    skipped order, and agent-reported successor success. Confirm a trusted resource outcome is the
    only way to unlock the next exact one-use child grant.
12. For a durable completion queue, authenticate the queue receipt and DPoP proof, test same-key
    replay versus changed-payload conflict, bounded retries, dead-letter visibility, and restart
    recovery. Late delivery must preserve an existing expired or revoked grant exactly as-is.
13. Validate the portable wire corpus with an independently implemented runner. Verify canonical
    idempotency conflicts, stable error/status/retry mapping, RFC 9449 DPoP fields, clock boundaries,
    and that no JWKS or fixture exposes private key material.
14. Reject reusable or standing fields on v0 endpoints. For an explicit v1 profile, test atomic use
    counters, fixed action/audience/scope/JKT/absolute expiry, renewal ceilings, old-segment denial,
    and immediate revoke/expiry of every active segment.
15. Inspect v1 evidence, queue projections, and logs for credentials, DPoP proofs, subject
    assertions, raw result payloads, and private JWK material. None may persist.

Record reviewer identity, commit SHA, date, checks run, findings, and any accepted risks in the PR.
