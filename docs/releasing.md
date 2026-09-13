# releasing the CLI

The CLI uses Changesets. Publishing is deliberately separated from normal pull requests.

1. Add a changeset for every user-visible CLI change: `pnpm changeset`.
2. Merge the change to `initial`. The release workflow opens or updates a version PR.
3. Review and merge that version PR. Its version step synchronizes the composite action's exact
   CLI default before the workflow builds, runs `changeset publish` with npm provenance enabled
   through GitHub's OIDC trusted-publishing configuration, and creates the matching immutable
   composite-action release tag (`v<version>`) with generated GitHub notes. No npm token belongs
   in this repository.
4. Verify the `v<version>` tag and generated notes, npm provenance attestation, and an isolated
   `npm install @warden/cli@<version>` before announcing it.

## Dry run

The checked-in CLI starts at `0.0.0`; the initial minor changeset produces the first public
`0.1.0` version PR and matching `v0.1.0` action tag. Before merging that version PR, run
`pnpm changeset status`, inspect the planned changelog and package version, and run a local
`npm pack` plus isolated install. This repository has not made a live npm publish from this PR.

The release workflow is idempotent for the composite-action tag: a rerun leaves an existing
`v<version>` GitHub release in place. It intentionally fails rather than creating a tag if the
publish result does not contain exactly one `@warden/cli` package and a full release commit SHA.

## Trusted publishing prerequisite

An npm maintainer must configure the package's trusted publisher to this repository, the `release`
workflow, and the `initial` branch. The workflow requests `id-token: write`; it does not read an npm
token from GitHub Secrets.
