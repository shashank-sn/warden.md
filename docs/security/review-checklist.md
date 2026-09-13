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

Record reviewer identity, commit SHA, date, checks run, findings, and any accepted risks in the PR.
