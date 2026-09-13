# local verification record

This record names the deterministic checks exercised for the reference implementation. The
revision-bound release receipt is generated separately after the final commit; this document does
not substitute for a live npm publication, deployed Cloudflare Worker, GitHub branch-protection
rule, or outside security review.

## Passed locally

- `CI=true pnpm check`: Biome, all package type checks, deployment-template validation, the full
  Vitest suite, and all package builds.
- `CI=true pnpm demo:service`: anonymous claim, protected-resource validation, and post-revocation
  rejection flow.
- `CI=true pnpm demo:broker`: one-use completion flow through the resource middleware.
- Action manifest and workflow YAML parsing, action unit tests, and local HTTPS valid/broken action
  fixtures.
- A built CLI `npm pack` plus isolated install smoke test is required before a release decision.

## Deliberately not asserted

- GitHub branch-protection enforcement against a real pull request.
- npm publication or provenance, generated release/tag creation, or external action-consumer
  installation.
- Cloudflare account deployment and live D1/Durable Object behavior.
- An outside-core security reviewer signature.

Those checks require external authority or credentials and remain explicit PR follow-ups rather
than local passes.
