# planned broker wire v1 fixtures

Status: planned contract fixtures, not a claim that the current draft-v0 TypeScript runtime is v1
conformant.

`cases.json` is the stable, language-neutral input to a future v1 conformance harness.
`errors.json` is the exhaustive frozen code-to-status map. Together they cover the wire contract
in [broker-sdk-wire-v1.md](../../../docs/spec/broker-sdk-wire-v1.md), including graph, durable
queue, coordination, and standing-profile extensions. They select no SDK language or
implementation.

## shape

The top-level object is exactly:

```json
{
  "schema_version": "1.1.0",
  "status": "PLANNED",
  "wire_spec": "docs/spec/broker-sdk-wire-v1.md",
  "fixture_contract": {},
  "requirement_ids": ["V1-22", "V1-23", "V1-24", "V1-25", "V1-26"],
  "cases": []
}
```

Each case has a sequential `WIRE-##` ID, `area`, `scenario`, `method`, `path`, `request`,
`expected`, and a non-empty `covers` array. HTTP cases use an uppercase HTTP `method` and a `/v1/`
`path`, except shared public-JWK discovery at `GET /.well-known/jwks.json` and the one retained-v0
`POST /exchange` negative descriptor. That v0 descriptor specifies a future v1-capable broker's
rejection of a v1 reuse field at the v0 boundary; it is not a claim about the current draft-v0
runtime. The `sdk_queue` cases use `LOCAL` and a portable SDK operation path. `expected.status` is required;
`expected.error` is present only for an error response and must match `errors.json` exactly.
`covers` names only exact planned case IDs from
[`v1-grant-contracts-test-plan.json`](../../../docs/plans/v1-grant-contracts-test-plan.json), such
as `V1-COORD-05`; it never uses a broad requirement ID such as `V1-23`.

The field boundary is deliberate and machine-checked:

| Field | Meaning |
| --- | --- |
| `request` | The exact public JSON request body. It contains no harness controls, credentials, DPoP proof, or secret. |
| `headers` | Safe literal protocol headers, currently `Idempotency-Key` where needed. A harness injects authentication and DPoP material without serializing it here. |
| `harness_preconditions` | Non-wire setup: trusted identities, prior durable state, a deterministic clock, and ephemeral credential/key bindings. These fields must not be copied into a request body. |
| `expected` | The HTTP status and exact stable error envelope when there is an error. |
| `assertions` | A non-empty typed array for every success case; each entry selects a response or durable-state value and applies one operator. Error cases may use state-only assertions to prove preservation or no mutation, never response assertions. |
| `covers` | Non-empty exact planned-case IDs covered by this descriptor. |

## assertion schema

Every assertion has exactly three top-level fields: `target`, `path`, and one operator.
`target` is either `response` (the parsed documented response) or `state` (a harness-normalized
observable state or prior result, not an undocumented HTTP reply). The new state witnesses use the
`graph`,
`race`, `evidence`, `queue`, `original_queue`, `original_response`, `grant`, `grant_count`,
`profile`, `standing`, and `coordination` namespaces. `path` is a JSONPath-like selector rooted at `$`, for example
`$.grant.status` or `$.coordination.entries[1].state`.

The one operator is exactly one of:

- `equals`: the selected value must equal the supplied JSON value.
- `present: true`: the selected value must exist.
- `absent: true`: the selected value must not exist.
- `same_as`: the selected value must equal another selected value, represented as
  `{ "target": "response" | "state", "path": "$.…" }`.
- `not_same_as`: the selected value must differ from another selected value, represented as
  `{ "target": "response" | "state", "path": "$.…" }`. It is used for a fresh downgrade
  result, never to compare sensitive material.
- `keys_exactly`: the selected response object must have exactly the supplied unique member names.
  It pins a closed public-JWK object without serializing a key value.

For example, an allowed exchange checks a documented response field without placing the
capability value in the fixture:

```json
[
  { "target": "response", "path": "$.grant.status", "equals": "approved" },
  { "target": "response", "path": "$.capability", "present": true }
]
```

A pending exchange uses `{ "target": "response", "path": "$.capability", "absent": true }`;
the fixture never serializes a capability to prove either condition.

A queue delivery `202` proves only that the broker atomically accepted a durable queue item. A
later state assertion or documented queue-status response proves the asynchronous recorded,
late-recorded, or dead-letter result; a harness must not treat the `202` itself as completion.

The object names above are fixed by `fixture_contract`. A harness must reject an unknown field in
`request` under the v1 closed-body rule; it must never treat a harness precondition as a wire field.
`errors.json` declares whether an error is a `broker_http` response or a portable `sdk_queue`
outcome with an HTTP-status equivalent.

## sensitive-material rule

The fixture contains no credential, authorization header, DPoP JWT, private key, subject assertion,
or secret. A harness that needs an authenticated case generates ephemeral test material locally and
must neither write it back to this fixture nor report it in failure output. Public `dpop_jkt` labels
are non-secret test identifiers, not keys.

## required coverage

The fixture contains planned cases for:

- allow, pending-approval, and blocked exchange;
- exact idempotency retry versus an idempotency collision;
- initial approval and exact approval retry;
- one consume, duplicate consume, wrong audience/action, invalid/replayed DPoP binding, and wrong
  DPoP key;
- one-second-before and exact-expiry clock boundaries;
- initial completion and idempotent completion retry;
- every frozen v1 error/status mapping, including graph, queue, coordination, partial failure,
  standing reuse, renewal, revocation, and unavailable-durability paths;
- frozen full-plan approval, ordinal-one-only release, out-of-order rejection, and
  failure/cancel/expiry/revoke finalization that disables later entries.
- finite bounded-multi-use consumption without renewal and one permitted standing segment rotation,
  preserving every fixed profile envelope field.

A harness must also preserve the protocol's security properties: no wildcard audience or implicit
scope expansion, one atomic winner per consume, parent coordination never authorizes a child, and
standing reuse never combines with coordination. Passing these planned descriptors alone is not a
production-security certification.
