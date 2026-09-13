# versioning the CLI

The CLI uses Changesets to prepare version pull requests. Publishing is deliberately separate from
that workflow.

1. Add a changeset for every user-visible CLI change: `pnpm changeset`.
2. Merge the change to `initial`. The release workflow opens or updates a version PR.
3. Review the version PR. Its version step synchronizes the composite action's exact CLI default,
   package version, and changelog. Merging it does not publish a package, create a tag, or create a
   GitHub release.
4. Treat any public npm release, provenance attestation, action tag, and GitHub release as a
   separately authorized maintainer operation. This workflow does not automate those operations.

## Current version-PR behavior

The checked-in CLI starts at `0.0.0`; the initial minor changeset produces the first planned
`0.1.0` version PR. Before merging that version PR, run
`pnpm changeset status`, inspect the planned changelog and package version, and run a local
`npm pack` plus isolated install. This repository has not made a live npm publish from this PR.

The workflow intentionally has no npm registry configuration, OIDC token permission, publishing
command, tag step, or GitHub-release step. Its only write effects are the Changesets branch and
version PR. GitHub repository settings must allow Actions to create pull requests for that final
step to run.

No version PR, npm package, provenance attestation, release tag, or external consumer installation
is proof of the others. Verify each separately before announcing a future public release.
