# warden.md

Agent auth that ends when the work does.

Warden is a TypeScript monorepo with three independently usable pieces:

- `@warden/cli`: read-only auth.md conformance checks and a GitHub Action
- `@warden/service`: self-hosted Cloudflare Worker reference implementation
- `@warden/broker`: completion-scoped, single-use delegated credentials

Start with the [architecture](docs/architecture.md), then run:

```sh
pnpm install
pnpm check
pnpm demo:broker
```

The service package includes its own local flow and deployment guide. The broker and service are
reference implementations: no hosted identity provider, telemetry, or real credentials are needed
for the deterministic test suite.

## Documentation

- [vision](docs/vision.md)
- [conformance CLI and Action](docs/check.md)
- [service deployment](docs/deploy.md)
- [completion-scoped grants draft](docs/spec/completion-scoped-grants.md)
- [broker threat model](docs/security/threat-model.md)
- [release process](docs/releasing.md)

## Development

Node 20+ and pnpm 11.19+ are required. See [contributing](.github/CONTRIBUTING.md) for package
boundaries, required checks, and changeset guidance.
