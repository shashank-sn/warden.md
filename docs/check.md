# conformance checks

`authmd check` verifies the public discovery documents that make a service ready for an
agent. It reads `auth.md`, protected-resource metadata, and authorization-server metadata;
it does not request credentials or write to the target.

## local use

Build and run the workspace CLI against a deployed service:

```sh
pnpm --filter @warden/cli build
pnpm --filter @warden/cli exec authmd check https://api.example.com \
  --json \
  --output .warden/conformance.json \
  --fail-on error
```

`--fail-on` accepts `error`, `warning`, or `never`. `error` is the normal CI setting.
Use `--probe` only when you deliberately want the optional read-only discovery probe:

```sh
pnpm --filter @warden/cli exec authmd check https://api.example.com --probe
```

## GitHub Actions

The root composite action downloads an exact, published `@warden/cli` version with `npx`. It
does not require a package-manager install in the consumer repository, request secrets, or
require write permissions. The runner needs Node.js 20 or newer with npm. The version-release
step synchronizes the action's default with the planned CLI package version in its Version Packages
PR. A caller may supply another exact published version. The check is read-only: it passes
`--probe` only when the caller explicitly sets the opt-in input to `true`. Internally it runs
`npx --yes --package @warden/cli@<cli-version> -- authmd check …`.

`v0.1.0` becomes usable only after a separately authorized npm publish creates
`@warden/cli@0.1.0` and a matching action tag. The version-PR workflow does neither. This source
branch has no published package or action tag yet, so it must not be used as evidence of a live
consumer installation.

```yaml
name: Check deployed auth.md

on:
  deployment_status:

jobs:
  conformance:
    if: github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: shashank-sn/warden.md@v0.1.0
        with:
          url: ${{ github.event.deployment_status.environment_url }}
          fail-on: error
```

Set `cli-version` to the exact released version you want to run. The action writes a
job summary with error and warning counts plus every error and warning finding. It also emits
matching GitHub annotations. The JSON file is available at `report-path`; upload it as an
artifact in the calling workflow if it must outlive the job.

| Input | Default | Meaning |
| --- | --- | --- |
| `url` | — | Required service URL. |
| `fail-on` | `error` | Failure threshold: `error`, `warning`, or `never`. |
| `probe` | `false` | Opt in to the read-only discovery probe. |
| `json-output-path` | `.warden/conformance.json` | Report location, relative to `working-directory` unless absolute. It is overwritten. |
| `cli-version` | matching action release | Exact published `@warden/cli` version; tags and ranges are rejected so action runs are reproducible. The version-release step keeps it aligned with the action tag. |
| `working-directory` | `.` | Directory used to run the CLI and resolve a relative report path. |

| Output | Meaning |
| --- | --- |
| `result` | `success` or `failure` after the selected `fail-on` threshold. A missing or invalid report is always `failure`. |
| `error-count` | Error findings in the JSON report. |
| `warning-count` | Warning findings in the JSON report. |
| `report-path` | Absolute path where the action expected the JSON report. |

For a ready-to-copy deployment workflow, see
[`examples/conformance-action.yml`](../examples/conformance-action.yml).
