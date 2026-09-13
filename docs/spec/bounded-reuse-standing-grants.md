# bounded reuse and standing grants

License: MIT
Status: planned v1 contract — not implemented by this repository.

This profile describes the only planned exception to the v0 one-successful-consume rule. The
in-repository TypeScript runtime remains a draft-v0 baseline and is not claimed to implement this
profile or v1. Normal grants remain exact, DPoP-bound, short-lived, and one-use.

## 1. default and opt-in boundary

Without a broker-resolved **standing profile**, `use_limit` is exactly `1`. A client cannot request
multi-use by sending a larger number, a longer TTL, a repeated capability, or an SDK option. Such a
request fails with `403 standing_profile_required` before authority is minted.

A server-owned, versioned opt-in profile selects exactly one reuse mode. An agent receives only an
opaque `standing_profile_id`; it cannot supply or alter the profile body.

| Mode | Meaning | Renewal |
| --- | --- | --- |
| `bounded_multi_use` | One finite grant with a fixed successful-consume limit. It terminates on exhaustion, expiry, or revocation. | Always disabled. |
| `standing` | A non-authorizing policy parent for a bounded, sequential series of finite child segments. The resource sees only a current segment, never a standing parent credential. | Explicitly bounded and never automatic. |

Both modes allow reuse only within the exact profile envelope below:

| Profile field | Fixed rule |
| --- | --- |
| `id`, `version` | Immutable opaque identity and policy revision. |
| `action` | One exact method/path/query; no template, wildcard, or operation family. |
| `audience` | One exact canonical HTTPS audience; no wildcard, prefix, or resource set. |
| `scope` | One non-empty unique scope set; no implicit expansion or wildcard. |
| `dpop_jkt` | One exact JWK thumbprint; key rotation creates a new profile/grant, never substitution. |
| `segment_max_successful_consumes` | Positive bounded integer for each finite grant/segment; no unbounded or `infinite` value. |
| `segment_ttl_seconds` | Positive cap for an individual segment; it cannot reach beyond the outer expiry. |
| `absolute_expires_at` | Hard UTC deadline for every use, segment rotation, and replay record. |
| `renewal` | `disabled` for `bounded_multi_use`; for `standing`, a fixed maximum segment-rotation count plus fresh trusted checks. |
| `revocation` | Profile and grant revocation handles plus evidence retention rule. |

The broker may deny profile use for a particular actor or trusted delegation, but it may never
relax one of these fixed fields. A normal one-use grant can be issued instead; that is a downgrade,
not a silent conversion of a standing grant.

## 2. finite grants and standing segments

An exchange that names `standing_profile_id` is valid only when the profile is active, the broker
has independently verified the caller's delegated authority, and every proposed action, audience,
scope, and JKT equals the fixed profile field. The broker records the profile ID/version, fixed
envelope, `remaining_uses`, absolute expiry, and an independent grant ID in redacted evidence.

### finite bounded multi-use

For `bounded_multi_use`, the broker issues exactly one finite grant. Its `use_limit` equals the
profile's `segment_max_successful_consumes`; its expiry is no later than both `segment_ttl_seconds`
and `absolute_expires_at`; and `renew` is unavailable. Exhaustion, expiry, or revocation is
terminal. It is not silently converted into a standing profile or a new grant.

### standing parent and rotating segments

For `standing`, the profile is a non-authorizing policy parent, not a credential. It can have at
most one active finite **segment** at a time. A segment has its own grant ID, finite use limit,
segment expiry, DPoP binding, and evidence ID, but inherits the parent profile's exact
action/audience/scope/JKT and absolute expiry. The parent evidence links ordered segment IDs and
the remaining allowed rotations; it contains no capability or key material.

No segment overlaps a successor. A later segment can exist only after the previous segment has a
durable terminal record and the broker has run the profile's fresh trusted checks. Thus a standing
profile is still a bounded sequence of ordinary finite authorities, never a long-lived reusable
parent credential.

The broker must reject a wider scope, other audience/action/JKT, larger use limit, or later expiry
with `403 standing_profile_mismatch`. It must reject an exhausted profile grant with
`409 reuse_limit_exhausted`. It does not infer an audience from a URL prefix or infer scope from a
previous successful call.

The wire field is the optional `standing_profile_id` in the planned
[v1 exchange](./broker-sdk-wire-v1.md#41-exchange). The profile's sensitive policy-management
interface is deliberately outside the agent wire surface. The public grant/evidence view contains
only non-secret identifiers and resolved constraints.

## 3. bounded consume state

A `bounded_multi_use` grant and each `standing` segment have a separate, explicit consume ledger;
neither reinterprets the v0 `approved -> consumed` state machine. At each protected call the broker
atomically checks:

1. `broker_now < absolute_expires_at` and the grant/profile are not revoked;
2. method/path/query, audience, scope, and JKT exactly match the fixed envelope;
3. `remaining_uses > 0`; and
4. the DPoP `(jkt, jti)` has not been accepted before.

It then writes one consume event and decrements `remaining_uses` in the same transaction. The
resource acts only after that response. A parallel caller cannot overspend the limit: once the
last use wins, later callers receive `reuse_limit_exhausted`; a duplicate proof receives
`dpop_proof_invalid`. Each use event has its own stable evidence sequence number, time, resolved
action, and final outcome pointer, never a capability or proof value.

The profile cannot be used to retry an unknown business outcome. A lost response is reconciled
through evidence/consume state; a new protected action needs a remaining use or a new exact grant.

## 4. absolute TTL, renewal, and revocation

`absolute_expires_at` is a hard, non-sliding deadline. At equality with the broker clock, a consume
or renewal fails with `401 grant_expired`; client clocks do not grant a grace period. Per-grant
expiry may be earlier, never later. A refreshed credential, activity, retry, or evidence delivery
cannot extend the absolute deadline.

For `bounded_multi_use`, `POST /v1/grants/{grant_id}/renew` always returns
`403 renewal_not_allowed`. The grant remains finite even if an SDK retries, a resource remains
active, or its profile remains configured.

For `standing`, renewal means an explicit bounded **segment rotation**, never extension of the
current segment. It is allowed only while rotations remain, the outer absolute expiry has not been
reached, the prior segment has a durable terminal record, and the broker re-runs trusted delegation
and policy checks. It creates a new segment/grant ID and evidence link with the same fixed
action/audience/scope/JKT, a fresh finite use counter, and an expiry no later than the profile's
absolute deadline. The old segment is never revived; two active segments are forbidden. It MUST NOT
silently rotate, mutate a current counter or TTL, or issue a new profile version. The planned route
is `POST /v1/grants/{grant_id}/renew`; absent/over-limit/automatic renewal returns
`403 renewal_not_allowed`.

Revoking either the profile or an issued standing grant immediately prevents new consumes. The
broker finalizes each affected grant with a stable evidence ID and reason, then performs any
delivery retry independently. Revocation/delivery failure cannot leave an active use path.

## 5. downgrade and composition boundaries

A restrictive change is a **downgrade** only when it is explicit and evidence-visible. The broker
may issue a fresh one-use grant with a subset of trusted scope, a shorter TTL, or a lower use limit;
it must give that grant a new ID. It cannot edit an active standing grant in place, change its JKT,
or claim that a broader replacement is a downgrade. Replacing a standing profile requires a new
profile version and explicitly revoking or retiring the prior one according to policy.

Standing reuse and cross-resource coordination never compose. A standing grant has one audience
and may not name a coordination; a coordination child has `use_limit: 1` and may not name a
standing profile. Both attempt directions return `403 cross_resource_reuse_forbidden` before an
exchange, use decrement, or evidence mutation.

## 6. error and security matrix

Status mappings are frozen by the [v1 wire error contract](./broker-sdk-wire-v1.md#8-error-contract).

| Threat or invalid condition | Required behavior | Error / HTTP | Planned negative test |
| --- | --- | --- | --- |
| No profile requests multi-use | Preserve ordinary one-use semantics. | `standing_profile_required` / 403 | `use_limit: 2` without profile. |
| Finite bounded grant requests renewal | Keep its one finite segment terminal. | `renewal_not_allowed` / 403 | Renew after a remaining or exhausted use. |
| Profile input changes action/audience/scope/JKT | Reject without issuing or decrementing. | `standing_profile_mismatch` / 403 | Extra scope, alternate URL, key swap. |
| Concurrent consumes exceed limit | Commit one ledger row per winning use only. | `reuse_limit_exhausted` / 409 | Two callers race for the final use. |
| Same proof is replayed | Keep replay record; do not decrement twice. | `dpop_proof_invalid` / 401 | Same `(jkt, jti)` after accepted consume. |
| Exact expiry boundary or later | Block consume/renewal and finalize safely. | `grant_expired` / 401 | `broker_now == absolute_expires_at`. |
| Standing rotation is absent, exhausted, overlaps, or changes envelope | Require fresh checks, a terminal prior segment, and fixed constraints. | `renewal_not_allowed` / 403 | Auto-renew, overlapping segment, or wider renewal request. |
| Profile/grant is revoked | Reject every later use; retain redacted evidence. | `grant_revoked` / 401 | Consume after profile revoke. |
| Profile paired with coordination | Reject before either feature has an effect. | `cross_resource_reuse_forbidden` / 403 | Exchange names both IDs. |
| Key, credential, or proof reaches evidence | Fail the security review; redact evidence. | `invalid_request` / 400 when supplied as body fields | Inspect fixture/evidence serialization. |

## 7. planned conformance coverage

The planned credential-free wire fixtures exercise finite bounded-multi-use, profile-required,
profile-mismatch, limit-exhausted, renewal-denied, standing segment rotation, expiry, replay,
revoke, downgrade-to-a-fresh-grant, and coordination-composition responses. In particular,
`V1-REUSE-09` requires a new restricted one-use ID rather than an in-place standing-grant
mutation. A real implementation also needs
atomic-store crash tests, key-rotation tests, and evidence redaction tests. This document selects
neither an implementation nor a non-TypeScript SDK.
