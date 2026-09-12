# roadmap

three tracks, one loop, and a foundation under all of it. every bullet below links to its issue.

## foundation

- [monorepo scaffold and developer tooling](https://github.com/shashank-sn/warden.md/issues/1)
- [ci pipeline: lint, typecheck, test, build](https://github.com/shashank-sn/warden.md/issues/2)
- [release pipeline: versioning and npm publishing](https://github.com/shashank-sn/warden.md/issues/3)

## track 1: check (conformance toolkit)

goal: any service owner can verify agent readiness in one command.

- [cli foundation: check command scaffolding and output design](https://github.com/shashank-sn/warden.md/issues/4)
- [auth.md parser and section validation](https://github.com/shashank-sn/warden.md/issues/5)
- [metadata validation: protected resource metadata + authorization server metadata](https://github.com/shashank-sn/warden.md/issues/6)
- [end-to-end discovery probe and conformance report](https://github.com/shashank-sn/warden.md/issues/7)
- [github action: run conformance checks on deploy](https://github.com/shashank-sn/warden.md/issues/8)

## track 2: service (self-hostable auth.md on workers)

goal: a stranger deploys their own agent registration server in one sitting.

- [discovery endpoints and data model](https://github.com/shashank-sn/warden.md/issues/9)
- [identity endpoint: anonymous, service_auth, and identity_assertion registration](https://github.com/shashank-sn/warden.md/issues/10)
- [claim ceremony: state machine, user codes, and polling](https://github.com/shashank-sn/warden.md/issues/11)
- [jose layer: jwks, signed identity assertions, and id-jag verification](https://github.com/shashank-sn/warden.md/issues/12)
- [token endpoint: jwt-bearer exchange and claim grant](https://github.com/shashank-sn/warden.md/issues/13)
- [revocation: rfc 7009 endpoint and set event delivery](https://github.com/shashank-sn/warden.md/issues/14)
- [one-click deploy template and end-to-end demo app](https://github.com/shashank-sn/warden.md/issues/15)

## track 3: broker (completion-scoped credentials)

goal: authority that dies when the task does.

- [spec: completion-scoped grants (draft v0)](https://github.com/shashank-sn/warden.md/issues/16)
- [broker core: downscoping exchange and one-use credential minting](https://github.com/shashank-sn/warden.md/issues/17)
- [completion signal, auto-revocation, and policy configuration](https://github.com/shashank-sn/warden.md/issues/18)
- [client sdk and resource-side middleware](https://github.com/shashank-sn/warden.md/issues/19)
- [threat model and security review](https://github.com/shashank-sn/warden.md/issues/20)

## shipping order

foundation first. then check and service in parallel. broker last, because it builds on both the spec and the patterns the service proves out. dependencies between individual issues are listed in each issue.
