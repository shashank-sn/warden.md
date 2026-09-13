# task graphs

License: MIT
Status: draft v1 design — not implemented and not a v0 extension.

This document defines an opt-in v1 coordination profile for several independently
authorized actions. It amends
[completion-scoped grants](./completion-scoped-grants.md); it does not change the
v0 grant, consume, completion, or revocation contract. A v1-capable broker MUST
reject graph inputs on its v0 surface rather than treating a graph as broader
authority. The current v0 reference does not implement graph inputs and MUST
not be used as though it did.

## 1. Boundary

A task graph is immutable coordination metadata. It can describe order and
evidence, but it is not an authorization object, credential, approval, assertion,
or DPoP proof. It MUST NOT mint graph-wide authority or let one node inherit the
authority of another node.

This profile covers multi-step work at one canonical audience. A graph whose
nodes need ordered outcomes across two or more audiences is a
[cross-resource coordination](./cross-resource-coordination.md) and MUST use that
separate profile. A task graph never turns a predecessor outcome into authority
at another resource.

Every action node MUST independently:

1. resolve a distinct trusted node assertion at its own authorization boundary;
2. mint a distinct, one-use grant through its own graph-bound exchange for its exact action and exact audience;
3. bind that grant to the node's declared DPoP thumbprint; and
4. satisfy all v0 grant checks before the resource performs the action.

A node MAY use the same public DPoP key as another node, but its signed grant,
trusted assertion, audience, action, approval decision, evidence, and consume
transition remain distinct. Raw assertions, credentials, and DPoP proofs MUST NOT
appear in graph metadata or evidence.

## 2. Immutable records

The broker MUST canonicalize and hash the graph definition at creation. Nodes,
dependencies, action descriptors, audiences, requested scopes, DPoP thumbprints,
and graph deadline are immutable after that point. A corrected plan is a new graph.

| Graph field | Required | Meaning |
| --- | --- | --- |
| graph_id | yes | Opaque stable identifier. |
| version | yes | The literal v1. |
| created_at | yes | Broker timestamp. |
| expires_at | yes | Coordination deadline; it can only shorten a node's usable lifetime. |
| definition_hash | yes | Hash of canonical immutable metadata. |
| nodes | yes | Nonempty, unique node set. |
| cancellation_authority | yes | Trusted binding allowed to request cancellation; never caller-provided text alone. |
| terminal_evidence_id | conditional | Stable graph evidence after the graph is terminal. |

| Node field | Required | Meaning |
| --- | --- | --- |
| node_id | yes | Unique immutable identifier within graph_id. |
| depends_on | yes | Unique predecessor node_ids; v1 requires a directed acyclic graph. |
| action | yes | Broker-resolved exact method, path, and query. |
| audience | yes | One absolute HTTPS resource audience. |
| requested_scope | yes | Requested scope only; granted scope is resolved separately. |
| dpop_jkt | yes | JWK thumbprint bound into this node's grant. |
| authority_reference | yes | Opaque reference to the separately resolved trusted assertion; never the assertion. |
| resolved_grant_expiry | conditional | Exact broker-resolved hard expiry after approval; never later than the graph deadline. |
| grant_id | conditional | The distinct grant minted only by a graph-bound exchange after this node is authorized. |
| approval_reference | conditional | Opaque node-specific approval reference. |
| terminal_evidence_id | conditional | Stable record once the node is terminal. |

The graph deadline MUST NOT extend a grant's expiry. A node grant expires at the
earlier of its independently configured maximum and the graph deadline.

### 2.1 planned wire input

`POST /v1/task-graphs` requires `Idempotency-Key` and accepts only the proposed
immutable public definition:

```json
{
  "nodes": [
    {
      "node_id": "node-a",
      "depends_on": [],
      "action": { "method": "POST", "path": "/payments/42", "query": "" },
      "audience": "https://api.example.test",
      "scope": ["payments:write"],
      "dpop_jkt": "base64url-jwk-thumbprint"
    }
  ],
  "expires_at": "2030-01-01T00:00:00Z"
}
```

The body cannot name `authority_reference`, `cancellation_authority`, a credential,
approval, or an already-issued grant. The broker resolves those values from its
trusted policy and identity integrations before it stores the canonical definition.
The proposal's `scope` becomes the record's `requested_scope`; it is never the
granted scope unless the trusted resolver independently returns the same set.
Node approval and graph cancellation have an empty JSON body; their trusted caller
identity is outside the body. A node finalization body is exactly
`{"event":"success"|"failure","event_id":"opaque-stable-id"}` and is accepted
only from a trusted resource integration. Every other graph route and response uses
the common rules in [the v1 wire contract](./broker-sdk-wire-v1.md).

### 2.2 graph-bound grant exchange

An approved node does not itself serialize a credential. To mint its one action grant, the caller
uses `POST /v1/grants/exchange` with the exact public graph selector
`"graph":{"id":"graph-id","node_id":"node-id"}`, as defined by the wire contract. The
broker resolves that immutable node and requires the request's action, audience, requested scope,
and action DPoP JKT to equal the node definition. It independently resolves the trusted assertion
and granted scope; it rejects a mismatch, a non-ready/non-approved node, an elapsed graph deadline,
or a second non-idempotent grant for the node before issuing anything.

`graph` is mutually exclusive with `coordination`, `standing_profile_id`, and
`completion_queue`. It always mints a one-use grant and caps its expiry at the graph deadline.
The graph reference is never a credential, does not authorize a resource directly, and cannot be
used to inherit a predecessor's grant, scope, audience, or proof.

## 3. States and transitions

Graph states are active, cancelling, succeeded, failed, partial_failure,
cancelled, and expired. A graph is succeeded only when every node succeeded. It is
partial_failure when at least one node succeeded and at least one node is failed,
blocked, cancelled, or expired. It is failed when no node succeeded and one or
more nodes failed or were blocked. Terminal graph states are immutable.

Node states are pending, ready, awaiting_approval, approved, consumed, succeeded,
failed, blocked, cancelled, and expired. Succeeded, failed, blocked, cancelled,
and expired are terminal.

| From | Trigger | To | Required rule |
| --- | --- | --- | --- |
| none | Valid graph creation | active / pending or ready nodes | Reject duplicate IDs, unknown dependencies, cycles, or an elapsed deadline. Roots are ready; other nodes are pending. |
| pending | Every predecessor succeeded | ready | Re-evaluate atomically with predecessor evidence. |
| pending | Any predecessor terminal without success | blocked | Persist the failed predecessor and reason; never authorize the node. |
| ready | Trusted assertion resolution and policy allow | approved | Persist node-specific authorization; direct policy allow skips display but not checks. |
| ready | Approval-required policy | awaiting_approval | Persist a node-specific approval reference; do not mint a credential. |
| awaiting_approval | Valid node approval before expiry | approved | Resolve and persist distinct node authorization; do not mint a credential. |
| approved | Valid graph-bound exchange | approved | Atomically attach one distinct one-use node grant; an exact retry returns that same grant. |
| approved | Valid grant and DPoP consume | consumed | The resource's atomic v0 consume is the only transition that permits the action. |
| consumed | Trusted terminal result | succeeded or failed | Append terminal evidence; an agent report alone is not proof of success. |
| pending, ready, awaiting_approval, approved, consumed | Deadline | expired | Revoke any unconsumed grant, preserve prior consume evidence, and block successors. |
| active | Authorized cancellation | cancelling | Start one durable cancellation operation. |
| pending, ready, awaiting_approval | Cancellation | cancelled | Never resolve or mint authority. |
| approved | Cancellation | cancelled | Revoke the node grant before recording cancellation. |
| consumed | Cancellation | consumed | Record cancellation intent and revoke remaining authority; do not rewrite a consumed action. It later reaches succeeded, failed, or expired from trusted evidence. |
| cancelling | All affected nodes terminal | cancelled or partial_failure | Use partial_failure if a node had already succeeded or later produces terminal result. |

Transitions MUST be serialized per graph and per node. A later event cannot move a
terminal node or graph back to a nonterminal state.

## 4. Authorization and approval

The broker MUST obtain each node's trusted assertion, registration scope, subject
scope, resource allowlist, and granted scope from a trusted resolver. A graph
proposal cannot supply or reuse those values. Reusing one assertion, grant_id, or
credential for another node MUST fail with node_authority_reused.

An approval surface MUST render, for the exact node being approved:

- graph_id and node_id;
- the broker-resolved action, audience, and granted scope;
- the dependency IDs and their terminal evidence status;
- the one-use limit, exact expiration time, and DPoP thumbprint;
- the approver identity and policy decision; and
- any cancellation or expiry that occurred before the decision.

The closed node view returned by the approval route carries those resolved action, audience,
granted scope, JKT, one-use limit, and exact-expiry values. An approval UI MUST render that view
and the dependency/evidence state rather than reconstructing the binding from agent text.

Agent-provided graph names, descriptions, or progress text are non-authoritative
and MUST NOT replace the resolved values. Approving one node MUST NOT approve a
sibling, a successor, or the graph as a whole.

## 5. Cancellation, expiry, partial failure, and evidence

Cancellation is a graph-control operation, not an action credential. The broker
MUST authenticate it through cancellation_authority, record one cancellation event,
revoke eligible node grants, and return the same cancellation evidence on retry.
It cannot undo an already consumed protected action.

On graph or node expiry, the broker MUST finalize unresolved nodes, revoke any
remaining node authority, and write expiry evidence. It MUST NOT authorize a
successor after an expired predecessor or recreate an expired grant.

Each terminal node evidence record MUST include graph_id, node_id, final state,
timestamp, trusted event source, stable event ID, grant_id if one existed, and a
pointer to the v0 grant evidence. It MUST be append-only and exclude credentials,
proofs, raw assertions, and arbitrary resource response bodies. The graph terminal
record aggregates node evidence IDs and its final state; it does not replace the
node records.

## 6. Idempotency

| Operation | Idempotency scope | Repeat behavior |
| --- | --- | --- |
| Create graph | Caller key plus canonical definition_hash | Same key and hash returns the original graph; different hash returns graph_idempotency_conflict. |
| Resolve or approve node | graph_id, node_id, authorization attempt | Returns the original approval state; never serializes a node credential. |
| Graph-bound exchange | graph_id, node_id, caller key, canonical request | Returns the attached grant only for an exact retry; never mints a second node grant. |
| Consume node | The v0 grant's one-use atomic transition | Exactly one protected call succeeds. |
| Record terminal result | graph_id, node_id, trusted event ID | Returns existing terminal evidence without changing final state. |
| Cancel graph | graph_id plus cancellation event ID | Returns the original cancellation evidence and does not rerun revocation. |

## 7. Stable errors

Existing v0 grant errors remain applicable. A v1 graph implementation adds only
the following stable code-only errors.

| Code | HTTP | Meaning |
| --- | --- | --- |
| graph_invalid | 400 | Required graph metadata is malformed or has duplicate node IDs. |
| graph_cycle | 400 | Dependencies are cyclic. |
| graph_expired | 401 | The graph deadline has elapsed. |
| graph_cancelled | 409 | A requested operation is disallowed by cancellation. |
| graph_terminal | 409 | A requested operation targets a terminal graph. |
| graph_idempotency_conflict | 409 | A creation key was reused with different immutable metadata. |
| node_not_found | 404 | The node does not belong to graph_id. |
| node_dependency_unsatisfied | 409 | A predecessor has not succeeded. |
| node_terminal | 409 | The node is already terminal. |
| node_authority_reused | 409 | An assertion, grant, or credential was attached to another node. |
| node_evidence_invalid | 403 | A terminal event lacks its required trusted binding. |

## 8. Security cases

- A valid grant for node A presented for node B, or for a different audience,
  MUST fail before resource work; graph membership never broadens its audience.
- A graph that mixes canonical audiences or uses a node outcome to unlock work at
  another audience MUST be rejected as a cross-resource coordination request.
- A forged dependency-success event, a stale approval, or a predecessor result
  from another graph MUST fail node_evidence_invalid.
- Metadata mutation after approval, including a changed action, scope, dependency,
  DPoP thumbprint, or deadline, MUST fail definition-hash verification.
- Concurrent predecessor success, cancellation, and expiry events MUST yield one
  durable terminal state per node and never authorize a blocked successor.
- A cancellation replay is idempotent; an unauthorized cancellation fails before
  it can revoke or alter a grant.
- Observability MUST expose IDs, states, counts, and stable codes only; it MUST
  redact credentials, DPoP proofs, raw assertions, and approval secrets.

## 9. V1 amendment and negative-test matrix

This is a design contract, not a workflow-engine implementation. v1
implementations MUST negotiate this profile explicitly and preserve all v0
single-grant behavior when it is absent. A graph coordinator is permitted to
schedule metadata and evidence only; it is never a bearer of action authority.

| ID | Negative case | Expected result |
| --- | --- | --- |
| TG-NEG-01 | Create a graph with a cycle or unknown dependency. | Reject with graph_cycle or graph_invalid; mint no grants. |
| TG-NEG-02 | Reuse one trusted assertion, grant, or credential for two nodes. | Reject with node_authority_reused; second node remains unauthorized. |
| TG-NEG-03 | Attempt to consume node B with node A's valid credential. | Reject with wrong_audience or action_not_authorized; no B state change. |
| TG-NEG-04 | Approve a node using agent-supplied prose that differs from resolved action or audience. | Display and authorize only resolved fields; mismatch fails before minting. |
| TG-NEG-05 | Authorize a successor while a predecessor is pending, failed, cancelled, or expired. | Reject with node_dependency_unsatisfied or mark successor blocked. |
| TG-NEG-06 | Race approval, cancellation, and expiry for one node. | One terminal result and evidence; no live grant after cancellation or expiry. |
| TG-NEG-07 | Replay graph creation or node approval with the same key but changed metadata. | Reject with graph_idempotency_conflict; preserve original definition. |
| TG-NEG-08 | Submit an unauthenticated or cross-graph terminal event. | Reject with node_evidence_invalid; do not mark success. |
| TG-NEG-09 | Cancel a graph after a node consumed its action grant. | Preserve consumed evidence, revoke remaining authority, and never claim rollback. |
| TG-NEG-10 | Try to extend a node grant through a graph deadline or graph retry. | Reject; node expiry is never later than its independent v0 cap. |
| TG-NEG-11 | Mix canonical audiences in one graph or use one node to unlock another resource. | Reject; use the cross-resource coordination profile. |
| TG-NEG-12 | Exchange with a graph ID/node ID but substitute its action, audience, scope, JKT, or one-use bound. | Reject before a grant is attached; preserve the approved node. |
| TG-NEG-13 | Combine a graph selector with a coordination, standing-profile, or queue selector. | Reject with `invalid_request`; issue no graph grant, queue record, or receipt. |
