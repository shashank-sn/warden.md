# complete roadmap implementation plan

Status: implementation-ready
Scope: close the contract of issues #1 through #20 in one cohesive reference implementation.

## Requirement map

| Unit | Issues | Goal | Primary ownership | Evidence |
| --- | --- | --- | --- | --- |
| Foundation | #1–#3 | Reproducible TypeScript workspace, CI, and release machinery | root | install, lint, typecheck, test, build; workflow validation |
| Conformance toolkit | #4–#8 | A read-only `authmd check` CLI and reusable GitHub Action | `packages/cli`, `action.yml` | unit, golden-report, built-binary, action-summary tests |
| Self-hosted service | #9–#15 | Worker-compatible auth.md discovery, registration, ceremony, token, and revocation flow | `packages/service` | endpoint and state-machine tests; local example flow |
| Completion broker | #16–#20 | Narrow, one-use, DPoP-bound grants with policy, completion, evidence, SDK, and review material | `packages/broker`, `docs/spec`, `docs/security`, `examples` | policy, atomic-consume, completion, middleware, and negative security tests |

## Implementation units

### U1 — workspace and delivery foundation (#1–#3)

- Add a pnpm workspace with strict, NodeNext TypeScript configuration and package-local builds.
- Use Biome as the single formatter/linter and Vitest as the shared test runner.
- Add CI for `lint`, `typecheck`, `test`, and `build`; add Changesets version-PR automation and a release runbook that keeps npm publication separate.
- Keep generated output, local Worker state, and secrets out of version control.

### U2 — conformance CLI and action (#4–#8)

- Model findings once, then render deterministic human and JSON reports from that model.
- Inject HTTP transport; no unit test may make a network request.
- Validate `auth.md`, protected-resource metadata, authorization-server/OIDC metadata, and their cross-document invariants.
- Make the optional probe explicit and read-only. Package the same binary behind a pinned-version composite action.

### U3 — service reference implementation (#9–#15)

- Keep transport handlers thin over typed in-memory/D1-compatible repositories and state-machine objects.
- Implement stable OAuth-style errors, explicit expiry, rate limits, replay protection, ES256 JWKS/assertion primitives, token narrowing, revocation/event delivery, and Worker bindings.
- Provide D1 migrations and Wrangler configuration without requiring live Cloudflare credentials for test execution.

### U4 — completion broker and integrations (#16–#20)

- Put the protocol contract first: normative state transitions, field/error tables, and explicit security annotations.
- Enforce intersection-only downscoping, audience + DPoP binding, single mint per subject, atomic single consume, declarative policy, idempotent completion, and expiry fallback.
- Expose a typed client that completes on success, failure, or timeout; pair it with resource middleware and a runnable local example.
- Link all high-severity threats to negative tests or an explicitly documented exception; no exception is expected for the reference implementation.

## Verification contract

| Requirement family | Hard checks | Review/spot check |
| --- | --- | --- |
| #1–#3 | `pnpm install --frozen-lockfile`, lint, typecheck, test, build | CI and release workflow syntax; no credentials in config |
| #4–#8 | CLI unit/golden/binary/action tests | Help text, stable report shape, action docs and summary |
| #9–#15 | Service endpoint/state-machine/JWT/revocation tests | Worker config and deploy guide with placeholders only |
| #16–#20 | Broker policy/consume/completion/middleware/security tests | Spec transition table, threat model, quickstart and failure modes |

## Scope boundaries

- This is a testable reference implementation and local demo, not a hosted service or a production deployment.
- Live npm publication, a Cloudflare deployment, GitHub branch-protection changes, and an outside-core reviewer signature require separate authority and are not claimed by this PR.
- The PR may reference and close issues only where the implementation and checks substantively meet their stated code/documentation contracts.

## Definition of done

Every issue has a traceable implementation or documentation section, relevant deterministic tests, no secret-bearing fixtures, a passing final repository check suite, independent diff review, and a PR description that links requirements to evidence and names any unavailable external verification.
