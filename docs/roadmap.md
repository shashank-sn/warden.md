# roadmap

three tracks, one loop, and a foundation under all of it. everything here is open work, tracked as issues.

## foundation

- monorepo scaffold and developer tooling
- ci pipeline: lint, typecheck, test, build
- release pipeline: versioning and npm publishing

## track 1: check (conformance toolkit)

goal: any service owner can verify agent readiness in one command.

- cli foundation: check command scaffolding and output design
- auth.md parser and section validation
- metadata validation: protected resource metadata + authorization server metadata
- end-to-end discovery probe and conformance report
- github action: run conformance checks on deploy

## track 2: service (self-hostable auth.md on workers)

goal: a stranger deploys their own agent registration server in one sitting.

- discovery endpoints and data model
- identity endpoint: anonymous, service_auth, and identity_assertion registration
- claim ceremony: state machine, user codes, and polling
- jose layer: jwks, signed identity assertions, and id-jag verification
- token endpoint: jwt-bearer exchange and claim grant
- revocation: rfc 7009 endpoint and set event delivery
- one-click deploy template and end-to-end demo app

## track 3: broker (completion-scoped credentials)

goal: authority that dies when the task does.

- spec: completion-scoped grants (draft v0)
- broker core: downscoping exchange and one-use credential minting
- completion signal, auto-revocation, and policy configuration
- client sdk and resource-side middleware
- threat model and security review

## shipping order

foundation first. then check and service in parallel. broker last, because it builds on both the spec and the patterns the service proves out. dependencies between individual issues are listed in each issue.
