# authmd check

authmd check is a read-only conformance toolkit for an agent-ready service. It reads
auth.md, Protected Resource Metadata (RFC 9728), and Authorization Server Metadata
(RFC 8414), then returns one deterministic report for people and CI.

## Local use

    pnpm --filter @warden/cli build
    pnpm --filter @warden/cli exec authmd check https://api.example.com
    pnpm --filter @warden/cli exec authmd check https://api.example.com --json --output report.json

An auth.md file path is also useful for parser-only local checks:

    pnpm --filter @warden/cli exec authmd check ./auth.md

The command uses HTTPS for remote documents, follows at most three redirects, applies
a 10-second per-request timeout, and caps each response at 1 MB. Configure those
defaults with --config path/to/authmd.json:

    {
      "timeoutMs": 5000,
      "maxBytes": 500000,
      "maxRedirects": 2,
      "failOn": "warning",
      "probe": false
    }

## Flags and exits

| Flag | Meaning |
| --- | --- |
| --json | Write the versioned JSON report to stdout. |
| --verbose | Add remediation and specification references to human output. |
| --quiet | Suppress human output. |
| --timeout <ms> | Set the remote request timeout. |
| --config <path> | Read JSON check settings. |
| --fail-on error, warning, or never | Choose the CI failure threshold; default is error. |
| --probe | Print a read-only trace of discovery hops, timing, redirects, and content types. |
| --output <path> | Write the JSON report to a file in addition to normal output. |
| --help, --version | Print command help or the package version. |

--probe does not change the protocol flow: it only exposes the GET requests already
used to read public discovery documents. The CLI never registers an identity, requests
a token, sends a claim, or writes to a remote service.

| Exit | Meaning |
| --- | --- |
| 0 | No finding reaches the selected failure threshold. |
| 1 | At least one finding reaches the selected failure threshold. |
| 2 | Invalid flags, target URL, local input, or configuration. |
| 3 | Unexpected internal failure. |

Severities are error (not conformant), warning (likely interoperability risk), and
info (non-blocking context). --fail-on never returns zero for findings but never hides
a usage failure.

## Report contract

`runConformanceCheck` returns the full report object: `schemaVersion`, `subject`,
`startedAt`, `durationMs`, `findings`, `summary`, and, when requested, probe hops with
their timings. `authmd check --json` and `--output` write a separate
`CanonicalConformanceReport`: a byte-stable CI artifact with stable key order that deliberately
omits wall-clock and transport-duration observations. Use the library result when actual timing
telemetry matters; use the canonical artifact for diffs, golden files, and the GitHub Action.
The human report still includes the opt-in probe timing trace. The canonical artifact uses schema
version 1:

    {
      "schemaVersion": 1,
      "subject": "https://api.example.com/",
      "findings": [
        {
          "ruleId": "PRM_RESOURCE_MISMATCH",
          "severity": "error",
          "message": "resource does not match the URL under test.",
          "location": { "jsonPath": "$.resource" },
          "specReference": "RFC 8707 §2.1"
        }
      ],
      "summary": {
        "errorCount": 1,
        "warningCount": 0,
        "infoCount": 0
      }
    }

Duplicate findings are merged while preserving every contributing rule in sourceRuleIds.
The committed schema and passing, failing, and probe golden fixtures are under
test/fixtures/reports.

## Rule reference

### auth.md and fetch

| Rule ID | Meaning |
| --- | --- |
| AUTHMD_REQUIRED_SECTION | A required level-two walkthrough section is missing. |
| AUTHMD_DUPLICATE_SECTION | A required walkthrough section appears more than once. |
| AUTHMD_EMPTY_SECTION | A required walkthrough section has no content. |
| AUTHMD_UNKNOWN_SECTION | A level-two section is not part of the supported auth.md walkthrough. |
| AUTHMD_METADATA_URL | A linked metadata URL is not absolute HTTPS or has a fragment. |
| FETCH_HTTPS_REQUIRED | A remote input or redirect target is not HTTPS. |
| FETCH_DNS_ERROR, FETCH_TLS_ERROR, FETCH_TIMEOUT, FETCH_NETWORK_ERROR | The document could not be fetched for the named transport reason. |
| FETCH_HTTP_STATUS | A document returned a non-success HTTP status. |
| FETCH_RESPONSE_TOO_LARGE | A document exceeds the configured response limit. |
| FETCH_CONTENT_TYPE | A document has the wrong content type. |
| FETCH_REDIRECT_LOCATION, FETCH_REDIRECT_URL, FETCH_REDIRECT_LIMIT | Redirect discovery is malformed, unsafe, or exceeds its bounded limit. |
| METADATA_JSON_PARSE, METADATA_JSON_OBJECT | A discovered metadata document is not a JSON object. |

Required auth.md sections are Discover, Pick a method, Register, Claim ceremony,
Exchange the assertion, Use the access_token, Errors, and Revocation.

### Protected Resource Metadata

Every metadata finding includes the cited clause in its JSON specReference.

| Rule ID | Meaning | Citation |
| --- | --- | --- |
| PRM_OBJECT | The PRM response is not a JSON object. | RFC 9728 §2 |
| PRM_RESOURCE_REQUIRED, PRM_RESOURCE_URL | resource is missing, mistyped, non-HTTPS, or has a fragment. | RFC 9728 §2 |
| PRM_RESOURCE_MISMATCH | resource does not identify the checked resource. | RFC 8707 §2.1 |
| PRM_AUTHORIZATION_SERVERS_REQUIRED, PRM_AUTHORIZATION_SERVER_URL | authorization_servers is absent, malformed, or contains an invalid URL. | RFC 9728 §2 |
| PRM_SCOPES_TYPE, PRM_BEARER_METHODS_TYPE | Optional list fields have an invalid type. | RFC 9728 §2 |
| PRM_ISSUER_MISMATCH | The server named by PRM differs from Authorization Server Metadata. | RFC 9728 §2 |

### Authorization Server Metadata and agent_auth

| Rule ID | Meaning | Citation |
| --- | --- | --- |
| AS_OBJECT | The Authorization Server response is not a JSON object. | RFC 8414 §2 |
| AS_ISSUER_REQUIRED, AS_ISSUER_URL | issuer is absent, mistyped, non-HTTPS, or has a fragment. | RFC 8414 §2 |
| AS_TOKEN_ENDPOINT_REQUIRED, AS_TOKEN_ENDPOINT_URL | token_endpoint is absent or invalid. | RFC 8414 §2 |
| AS_REVOCATION_ENDPOINT_REQUIRED, AS_REVOCATION_ENDPOINT_URL | revocation_endpoint is absent or invalid. | RFC 7009 §2 |
| AS_GRANT_TYPES, AS_GRANT_TYPE_MISMATCH | Grants are missing, malformed, or incompatible with flows described by auth.md. | RFC 8414 §2; RFC 7523 §2.1 |
| AS_TOKEN_AUTH_METHODS, AS_TOKEN_AUTH_PUBLIC_CLIENT | Token client-auth methods are missing or do not support the published agent flow. | RFC 8414 §2 |
| AGENT_AUTH_REQUIRED, AGENT_AUTH_MISSING_KEY | The agent_auth block or a required key is missing. | auth.md agent_auth profile |
| AGENT_AUTH_ENDPOINT_URL, AGENT_AUTH_ENDPOINT_ISSUER | An agent_auth endpoint is malformed or does not resolve to the issuer. | auth.md agent_auth profile |
| AGENT_AUTH_SKILL_MISMATCH | agent_auth.skill differs from the fetched auth.md URL. | auth.md agent_auth profile |
| AGENT_AUTH_IDENTITY_TYPES, AGENT_AUTH_UNKNOWN_REGISTRATION_MODE | Registration modes are malformed or unknown. | auth.md agent_auth profile |
| AGENT_AUTH_ASSERTION_OBJECT, AGENT_AUTH_ASSERTION_TYPES | The assertion extension is malformed. | auth.md agent_auth profile |
| AGENT_AUTH_EVENTS | The event list is malformed. | auth.md agent_auth profile |
| AUTHMD_REGISTRATION_MODE_MISMATCH | auth.md promises a mode that metadata does not offer. | auth.md agent_auth profile |
| AUTHMD_ISSUER_MISMATCH | The issuer declared in auth.md differs from metadata. | RFC 8414 §2 |

## Extending the CLI

Add a flag in src/cli.ts, parse and validate it there, then pass its typed value to
runConformanceCheck. Keep transport behind Transport; tests must use StubTransport,
never a real network call. To add a reporter, implement the Reporter interface in
src/reporter.ts, preserve the ConformanceReport model, and add a behavior-level test
and a golden update if output changes.
