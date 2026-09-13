import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

type JsonRecord = Record<string, unknown>;

const repositoryRoot = new URL("../../../", import.meta.url);

const expectedSpecs = {
  "V1-22": "docs/spec/task-graphs.md",
  "V1-23": "docs/spec/cross-resource-coordination.md",
  "V1-24": "docs/spec/durable-completion-queues.md",
  "V1-25": "docs/spec/broker-sdk-wire-v1.md",
  "V1-26": "docs/spec/bounded-reuse-standing-grants.md",
} as const;

const requirementForArea = {
  graph: "V1-22",
  coordination: "V1-23",
  queue: "V1-24",
  standing: "V1-26",
  composition: "V1-26",
} as const;

const fixtureCaseKeys = new Set([
  "id",
  "requirement_id",
  "area",
  "scenario",
  "surface",
  "method",
  "path",
  "headers",
  "request",
  "harness_preconditions",
  "expected",
  "assertions",
  "covers",
]);

const sensitiveKeyNames = new Set([
  "authorization",
  "accesstoken",
  "capability",
  "clientsecret",
  "credential",
  "privatekey",
  "proof",
  "refreshtoken",
  "secret",
  "subjectassertion",
  "token",
  "subjecttoken",
  "bearertoken",
  "dpopjwt",
  "jwt",
  "jws",
  "d",
  "p",
  "q",
  "dp",
  "dq",
  "qi",
  "k",
]);

const sensitiveValuePatterns = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/i,
  /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
  /\b(?:Bearer|DPoP)\s+(?:eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|[A-Za-z0-9_-]{24,})/,
];

const forbiddenNestedCredentialResponsePaths = new Set([
  "$.graph.nodes[0].capability",
  "$.graph.nodes[0].credential",
  "$.node.capability",
  "$.node.credential",
  "$.coordination.entries[0].capability",
  "$.coordination.entries[0].credential",
  "$.coordination.entries[1].capability",
  "$.coordination.entries[1].credential",
]);

const stateAssertionNamespaces = new Set([
  "coordination",
  "evidence",
  "grant",
  "grant_count",
  "graph",
  "original_queue",
  "original_response",
  "profile",
  "queue",
  "race",
  "standing",
]);

function asRecord(value: unknown, label: string): JsonRecord {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new TypeError(`${label} must be an object`);
  }

  return value as JsonRecord;
}

function asArray(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`${label} must be an array`);
  }

  return value;
}

function asString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be a string`);
  }

  return value;
}

function asInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new TypeError(`${label} must be an integer`);
  }

  return value;
}

function expectOnlyKeys(record: JsonRecord, allowed: Set<string>, label: string): void {
  for (const key of Object.keys(record)) {
    expect(allowed.has(key), `${label} has unexpected key ${key}`).toBe(true);
  }
}

function expectExactKeys(record: JsonRecord, keys: readonly string[], label: string): void {
  expect(Object.keys(record).sort(), `${label} must have an exact field set`).toEqual(
    [...keys].sort(),
  );
}

function expectNonEmptyString(value: unknown, label: string): string {
  const string = asString(value, label);
  expect(string.trim(), `${label} must not be empty`).not.toBe("");
  return string;
}

function assertStateAssertionPath(path: string, label: string): void {
  const namespace = path.match(/^\$\.([A-Za-z_][A-Za-z0-9_]*)/)?.[1];
  expect(namespace, `${label} must name a documented state namespace`).toBeDefined();
  expect(
    stateAssertionNamespaces.has(namespace ?? ""),
    `${label} has an unknown state namespace`,
  ).toBe(true);
}

function assertStringArray(value: unknown, label: string): string[] {
  const values = asArray(value, label).map((entry, index) =>
    expectNonEmptyString(entry, `${label}[${index}]`),
  );
  expect(values.length, `${label} must not be empty`).toBeGreaterThan(0);
  expect(new Set(values).size, `${label} values must be unique`).toBe(values.length);
  return values;
}

function assertAction(value: unknown, label: string): void {
  const action = asRecord(value, label);
  expectExactKeys(action, ["method", "path", "query"], label);
  expect(asString(action.method, `${label}.method`)).toMatch(/^[A-Z]+$/);
  expect(asString(action.path, `${label}.path`)).toMatch(/^\//);
  expect(typeof action.query, `${label}.query must be a string`).toBe("string");
}

function assertExchangeRequest(request: JsonRecord, label: string, expectedError?: string): void {
  expectOnlyKeys(
    request,
    new Set([
      "action",
      "audience",
      "scope",
      "dpop_jkt",
      "completion_ttl_seconds",
      "requested_use_limit",
      "graph",
      "coordination",
      "standing_profile_id",
      "completion_queue",
    ]),
    label,
  );
  assertAction(request.action, `${label}.action`);
  expect(asString(request.audience, `${label}.audience`)).toMatch(/^https:\/\//);
  assertStringArray(request.scope, `${label}.scope`);
  expectNonEmptyString(request.dpop_jkt, `${label}.dpop_jkt`);
  expect(
    asInteger(request.completion_ttl_seconds, `${label}.completion_ttl_seconds`),
  ).toBeGreaterThan(0);
  if (request.requested_use_limit !== undefined) {
    expect(asInteger(request.requested_use_limit, `${label}.requested_use_limit`)).toBeGreaterThan(
      0,
    );
  }
  if (request.graph !== undefined) {
    const graph = asRecord(request.graph, `${label}.graph`);
    expectExactKeys(graph, ["id", "node_id"], `${label}.graph`);
    expectNonEmptyString(graph.id, `${label}.graph.id`);
    expectNonEmptyString(graph.node_id, `${label}.graph.node_id`);
  }
  if (request.coordination !== undefined) {
    const coordination = asRecord(request.coordination, `${label}.coordination`);
    expectExactKeys(coordination, ["id", "resource_id"], `${label}.coordination`);
    expectNonEmptyString(coordination.id, `${label}.coordination.id`);
    expectNonEmptyString(coordination.resource_id, `${label}.coordination.resource_id`);
  }
  if (request.standing_profile_id !== undefined) {
    expectNonEmptyString(request.standing_profile_id, `${label}.standing_profile_id`);
  }
  const authoritySelectors = [
    request.graph,
    request.coordination,
    request.standing_profile_id,
    request.completion_queue,
  ].filter((selector) => selector !== undefined);
  if (authoritySelectors.length > 1) {
    const isReusableCoordinationComposition =
      authoritySelectors.length === 2 &&
      request.coordination !== undefined &&
      request.standing_profile_id !== undefined;
    expect(expectedError, `${label} combined selectors must be rejected before mutation`).toBe(
      isReusableCoordinationComposition ? "cross_resource_reuse_forbidden" : "invalid_request",
    );
  }
  if (
    (request.graph !== undefined || request.coordination !== undefined) &&
    request.requested_use_limit !== undefined
  ) {
    const requestedUseLimit = asInteger(
      request.requested_use_limit,
      `${label}.requested_use_limit`,
    );
    if (requestedUseLimit > 1) {
      expect(
        expectedError,
        `${label} multi-use graph or coordination input must fail before mutation`,
      ).toBe("invalid_request");
    } else {
      expect(
        requestedUseLimit,
        `${label} graph and coordination children must be one-use`,
      ).toBeLessThanOrEqual(1);
    }
  }
  if (request.completion_queue !== undefined) {
    const completionQueue = asRecord(request.completion_queue, `${label}.completion_queue`);
    expectExactKeys(completionQueue, ["dpop_jkt"], `${label}.completion_queue`);
    const completionJkt = expectNonEmptyString(
      completionQueue.dpop_jkt,
      `${label}.completion_queue.dpop_jkt`,
    );
    expect(completionJkt, `${label}.completion_queue must use a distinct key`).not.toBe(
      request.dpop_jkt,
    );
    if (request.requested_use_limit !== undefined) {
      const requestedUseLimit = asInteger(
        request.requested_use_limit,
        `${label}.requested_use_limit`,
      );
      if (requestedUseLimit > 1) {
        expect(
          expectedError,
          `${label}.completion_queue multi-use input must fail before mutation`,
        ).toBe("invalid_request");
      } else {
        expect(requestedUseLimit, `${label}.completion_queue must be one-use`).toBeLessThanOrEqual(
          1,
        );
      }
    }
  }
}

function assertConsumeRequest(request: JsonRecord, label: string): void {
  expectExactKeys(request, ["target"], label);
  const target = asRecord(request.target, `${label}.target`);
  expectExactKeys(target, ["method", "url"], `${label}.target`);
  expect(asString(target.method, `${label}.target.method`)).toMatch(/^[A-Z]+$/);
  expect(asString(target.url, `${label}.target.url`)).toMatch(/^https:\/\//);
}

function assertV0ExchangeExtensionRequest(request: JsonRecord, label: string): void {
  expectOnlyKeys(
    request,
    new Set([
      "agentId",
      "subjectId",
      "subjectTokenId",
      "resource",
      "action",
      "requestedScope",
      "dpopThumbprint",
      "expiresInSeconds",
      "idempotencyKey",
      "standing_profile_id",
      "requested_use_limit",
    ]),
    label,
  );
  for (const field of [
    "agentId",
    "subjectId",
    "subjectTokenId",
    "resource",
    "action",
    "requestedScope",
    "dpopThumbprint",
  ]) {
    expect(request[field], `${label}.${field} is required`).toBeDefined();
  }
  expectNonEmptyString(request.agentId, `${label}.agentId`);
  expectNonEmptyString(request.subjectId, `${label}.subjectId`);
  expectNonEmptyString(request.subjectTokenId, `${label}.subjectTokenId`);
  expect(asString(request.resource, `${label}.resource`)).toMatch(/^https:\/\//);
  expect(asString(request.action, `${label}.action`)).toMatch(/^[A-Z]+ \/[^\s]*$/);
  assertStringArray(request.requestedScope, `${label}.requestedScope`);
  expectNonEmptyString(request.dpopThumbprint, `${label}.dpopThumbprint`);
  if (request.expiresInSeconds !== undefined) {
    expect(asInteger(request.expiresInSeconds, `${label}.expiresInSeconds`)).toBeGreaterThan(0);
  }
  if (request.idempotencyKey !== undefined) {
    expectNonEmptyString(request.idempotencyKey, `${label}.idempotencyKey`);
  }
  expect(
    request.standing_profile_id !== undefined || request.requested_use_limit !== undefined,
    `${label} must include the v1 reuse extension under test`,
  ).toBe(true);
  if (request.standing_profile_id !== undefined) {
    expectNonEmptyString(request.standing_profile_id, `${label}.standing_profile_id`);
  }
  if (request.requested_use_limit !== undefined) {
    expect(asInteger(request.requested_use_limit, `${label}.requested_use_limit`)).toBeGreaterThan(
      1,
    );
  }
}

function assertGraphRequest(request: JsonRecord, label: string, expectedError?: string): void {
  expectExactKeys(request, ["nodes", "expires_at"], label);
  expectNonEmptyString(request.expires_at, `${label}.expires_at`);
  const nodes = asArray(request.nodes, `${label}.nodes`);
  if (nodes.length === 0) {
    expect(expectedError, `${label} empty graph must fail before record creation`).toBe(
      "graph_invalid",
    );
    return;
  }
  const nodeIds = new Set<string>();
  for (const [index, value] of nodes.entries()) {
    const node = asRecord(value, `${label}.nodes[${index}]`);
    expectExactKeys(
      node,
      ["node_id", "depends_on", "action", "audience", "scope", "dpop_jkt"],
      `${label}.nodes[${index}]`,
    );
    const nodeId = expectNonEmptyString(node.node_id, `${label}.nodes[${index}].node_id`);
    expect(nodeIds.has(nodeId), `${label} node IDs must be unique`).toBe(false);
    nodeIds.add(nodeId);
    const dependencies = asArray(node.depends_on, `${label}.nodes[${index}].depends_on`).map(
      (dependency, dependencyIndex) =>
        expectNonEmptyString(dependency, `${label}.nodes[${index}].depends_on[${dependencyIndex}]`),
    );
    expect(new Set(dependencies).size, `${label}.nodes[${index}] dependencies must be unique`).toBe(
      dependencies.length,
    );
    assertAction(node.action, `${label}.nodes[${index}].action`);
    expect(asString(node.audience, `${label}.nodes[${index}].audience`)).toMatch(/^https:\/\//);
    assertStringArray(node.scope, `${label}.nodes[${index}].scope`);
    expectNonEmptyString(node.dpop_jkt, `${label}.nodes[${index}].dpop_jkt`);
  }
}

function assertCoordinationRequest(
  request: JsonRecord,
  label: string,
  expectedError?: string,
): void {
  expectExactKeys(request, ["entries", "expires_at"], label);
  expectNonEmptyString(request.expires_at, `${label}.expires_at`);
  const entries = asArray(request.entries, `${label}.entries`);
  expect(entries.length, `${label}.entries must not be empty`).toBeGreaterThan(0);
  const ordinals = new Set<number>();
  const resourceIds = new Set<string>();
  for (const [index, value] of entries.entries()) {
    const entry = asRecord(value, `${label}.entries[${index}]`);
    expectExactKeys(
      entry,
      [
        "ordinal",
        "resource_id",
        "action",
        "audience",
        "scope",
        "dpop_jkt",
        "completion_ttl_seconds",
      ],
      `${label}.entries[${index}]`,
    );
    const ordinal = asInteger(entry.ordinal, `${label}.entries[${index}].ordinal`);
    expect(ordinal).toBeGreaterThan(0);
    const resourceId = expectNonEmptyString(
      entry.resource_id,
      `${label}.entries[${index}].resource_id`,
    );
    if (ordinals.has(ordinal) || resourceIds.has(resourceId)) {
      expect(
        expectedError,
        `${label} duplicate ordinal or resource must fail before record creation`,
      ).toBe("coordination_invalid");
    }
    ordinals.add(ordinal);
    resourceIds.add(resourceId);
    assertAction(entry.action, `${label}.entries[${index}].action`);
    expect(asString(entry.audience, `${label}.entries[${index}].audience`)).toMatch(/^https:\/\//);
    assertStringArray(entry.scope, `${label}.entries[${index}].scope`);
    expectNonEmptyString(entry.dpop_jkt, `${label}.entries[${index}].dpop_jkt`);
    expect(
      asInteger(entry.completion_ttl_seconds, `${label}.entries[${index}].completion_ttl_seconds`),
    ).toBeGreaterThan(0);
  }
}

function assertClosedRequestSchema(
  surface: string,
  method: string,
  path: string,
  request: JsonRecord,
  label: string,
  expectedError?: string,
): void {
  if (surface === "sdk_queue") {
    expect(method).toBe("LOCAL");
    expect(["queue/requeue", "queue/scheduler-tick"]).toContain(path);
    expectExactKeys(request, ["queue_id"], label);
    expectNonEmptyString(request.queue_id, `${label}.queue_id`);
    return;
  }

  if (path === "/exchange") {
    assertV0ExchangeExtensionRequest(request, label);
    return;
  }

  if (path === "/v1/grants/exchange") {
    assertExchangeRequest(request, label, expectedError);
    return;
  }
  if (path.endsWith("/consume")) {
    assertConsumeRequest(request, label);
    return;
  }
  if (path.endsWith("/completion-queue")) {
    expectOnlyKeys(
      request,
      new Set(
        expectedError === "invalid_request"
          ? ["completion_event_id", "terminal_envelope"]
          : ["completion_event_id"],
      ),
      label,
    );
    expectNonEmptyString(request.completion_event_id, `${label}.completion_event_id`);
    if (request.terminal_envelope !== undefined) {
      expect(expectedError, `${label} malformed envelope must be rejected`).toBe("invalid_request");
      asRecord(request.terminal_envelope, `${label}.terminal_envelope`);
    }
    return;
  }
  if (path === "/v1/task-graphs") {
    assertGraphRequest(request, label, expectedError);
    return;
  }
  if (path.includes("/task-graphs/") && path.endsWith("/finalize")) {
    expectExactKeys(request, ["event", "event_id"], label);
    expect(["success", "failure"]).toContain(asString(request.event, `${label}.event`));
    expectNonEmptyString(request.event_id, `${label}.event_id`);
    return;
  }
  if (path === "/v1/coordinations") {
    assertCoordinationRequest(request, label, expectedError);
    return;
  }
  if (path.includes("/coordinations/") && path.endsWith("/finalize")) {
    expectOnlyKeys(request, new Set(["event", "entry_ordinal"]), label);
    expect(["success", "failure", "cancel", "expiry", "revoke"]).toContain(
      asString(request.event, `${label}.event`),
    );
    if (request.entry_ordinal !== undefined) {
      expect(asInteger(request.entry_ordinal, `${label}.entry_ordinal`)).toBeGreaterThan(0);
    }
    return;
  }
  expectExactKeys(request, [], label);
}

function responseAssertionPaths(method: string, path: string, status: number): ReadonlySet<string> {
  const grantPaths = [
    "$.grant.id",
    "$.grant.status",
    "$.grant.action",
    "$.grant.audience",
    "$.grant.scope",
    "$.grant.dpop_jkt",
    "$.grant.issued_at",
    "$.grant.expires_at",
    "$.grant.use_limit",
    "$.grant.evidence_id",
  ];
  const evidencePaths = [
    "$.evidence.id",
    "$.evidence.subject.type",
    "$.evidence.subject.id",
    "$.evidence.state",
    "$.evidence.finalization_source",
    "$.evidence.recorded_at",
  ];
  const queuePaths = [
    "$.queue.id",
    "$.queue.grant_id",
    "$.queue.state",
    "$.queue.accepted_at",
    "$.queue.updated_at",
    "$.queue.attempts",
    "$.queue.evidence_id",
    "$.queue.last_error",
  ];
  const graphPaths = [
    "$.capability",
    "$.graph",
    "$.graph.id",
    "$.graph.state",
    "$.graph.definition_hash",
    "$.graph.nodes[0]",
    "$.graph.nodes[0].id",
    "$.graph.nodes[0].state",
    "$.graph.nodes[0].depends_on",
    "$.graph.nodes[0].action",
    "$.graph.nodes[0].audience",
    "$.graph.nodes[0].scope",
    "$.graph.nodes[0].dpop_jkt",
    "$.graph.nodes[0].use_limit",
    "$.graph.nodes[0].expires_at",
    "$.graph.nodes[0].grant_id",
    "$.graph.nodes[0].evidence_id",
    "$.graph.nodes[0].capability",
    "$.graph.nodes[0].credential",
    "$.graph.expires_at",
    "$.graph.evidence_id",
  ];
  const nodePaths = [
    "$.node",
    "$.node.id",
    "$.node.state",
    "$.node.depends_on",
    "$.node.action",
    "$.node.audience",
    "$.node.scope",
    "$.node.dpop_jkt",
    "$.node.use_limit",
    "$.node.expires_at",
    "$.node.grant_id",
    "$.node.evidence_id",
    "$.node.capability",
    "$.node.credential",
  ];
  const coordinationPaths = [
    "$.coordination",
    "$.coordination.id",
    "$.coordination.state",
    "$.coordination.plan_digest",
    "$.coordination.entries[0]",
    "$.coordination.entries[0].ordinal",
    "$.coordination.entries[0].resource_id",
    "$.coordination.entries[0].action",
    "$.coordination.entries[0].audience",
    "$.coordination.entries[0].scope",
    "$.coordination.entries[0].dpop_jkt",
    "$.coordination.entries[0].completion_ttl_seconds",
    "$.coordination.entries[0].state",
    "$.coordination.entries[0].grant_id",
    "$.coordination.entries[0].capability",
    "$.coordination.entries[0].credential",
    "$.coordination.entries[1].ordinal",
    "$.coordination.entries[1]",
    "$.coordination.entries[1].resource_id",
    "$.coordination.entries[1].action",
    "$.coordination.entries[1].audience",
    "$.coordination.entries[1].scope",
    "$.coordination.entries[1].dpop_jkt",
    "$.coordination.entries[1].completion_ttl_seconds",
    "$.coordination.entries[1].state",
    "$.coordination.entries[1].grant_id",
    "$.coordination.entries[1].capability",
    "$.coordination.entries[1].credential",
    "$.coordination.expires_at",
    "$.coordination.evidence_id",
  ];

  if (method === "GET" && path === "/.well-known/jwks.json" && status === 200) {
    return new Set([
      "$.keys[0]",
      "$.keys[0].kty",
      "$.keys[0].crv",
      "$.keys[0].x",
      "$.keys[0].y",
      "$.keys[0].kid",
      "$.keys[0].use",
      "$.keys[0].alg",
      "$.keys[0].d",
      "$.keys[0].p",
      "$.keys[0].q",
      "$.keys[0].dp",
      "$.keys[0].dq",
      "$.keys[0].qi",
      "$.keys[0].k",
    ]);
  }
  if (method === "GET" && /^\/v1\/grants\/[^/]+\/evidence$/.test(path) && status === 200) {
    return new Set(evidencePaths);
  }
  if (
    method === "GET" &&
    /^\/v1\/grants\/[^/]+\/completion-queue\/[^/]+$/.test(path) &&
    status === 200
  ) {
    return new Set(queuePaths);
  }
  if (method !== "POST") {
    return new Set();
  }
  if (path === "/v1/grants/exchange" && status === 201) {
    return new Set([
      "$.decision",
      ...grantPaths,
      "$.capability",
      "$.completion_queue.receipt",
      "$.completion_queue.audience",
      "$.completion_queue.dpop_jkt",
      "$.completion_queue.expires_at",
    ]);
  }
  if (path === "/v1/grants/exchange" && status === 202) {
    return new Set([
      "$.decision",
      ...grantPaths,
      "$.approval.id",
      "$.capability",
      "$.completion_queue",
    ]);
  }
  if (/^\/v1\/grants\/[^/]+\/approve$/.test(path) && status === 200) {
    return new Set([
      "$.decision",
      ...grantPaths,
      "$.capability",
      "$.completion_queue.receipt",
      "$.completion_queue.audience",
      "$.completion_queue.dpop_jkt",
      "$.completion_queue.expires_at",
    ]);
  }
  if (/^\/v1\/grants\/[^/]+\/consume$/.test(path) && status === 200) {
    return new Set(grantPaths);
  }
  if (/^\/v1\/grants\/[^/]+\/(?:complete|revoke)$/.test(path) && status === 200) {
    return new Set([...grantPaths, ...evidencePaths]);
  }
  if (/^\/v1\/grants\/[^/]+\/completion-queue$/.test(path) && status === 202) {
    return new Set(queuePaths);
  }
  if (/^\/v1\/grants\/[^/]+\/renew$/.test(path) && status === 201) {
    return new Set(["$.decision", ...grantPaths, "$.capability"]);
  }
  if (path === "/v1/task-graphs" && status === 201) {
    return new Set(graphPaths);
  }
  if (/^\/v1\/task-graphs\/[^/]+\/nodes\/[^/]+\/approve$/.test(path) && status === 200) {
    return new Set([...graphPaths, ...nodePaths]);
  }
  if (/^\/v1\/task-graphs\/[^/]+\/nodes\/[^/]+\/finalize$/.test(path) && status === 200) {
    return new Set([...graphPaths, ...nodePaths, ...evidencePaths]);
  }
  if (/^\/v1\/task-graphs\/[^/]+\/cancel$/.test(path) && status === 200) {
    return new Set([...graphPaths, ...evidencePaths]);
  }
  if (path === "/v1/coordinations" && status === 201) {
    return new Set([...coordinationPaths, "$.capability"]);
  }
  if (/^\/v1\/coordinations\/[^/]+\/approve$/.test(path) && status === 200) {
    return new Set([...coordinationPaths, "$.capability"]);
  }
  if (/^\/v1\/coordinations\/[^/]+\/finalize$/.test(path) && status === 200) {
    return new Set([...coordinationPaths, ...evidencePaths, "$.capability"]);
  }
  return new Set();
}

function assertTypedAssertions(
  value: unknown,
  label: string,
  allowedResponsePaths: ReadonlySet<string>,
): void {
  const assertions = asArray(value, label);
  expect(assertions.length, `${label} must not be empty`).toBeGreaterThan(0);
  for (const [index, value] of assertions.entries()) {
    const assertion = asRecord(value, `${label}[${index}]`);
    expectOnlyKeys(
      assertion,
      new Set([
        "target",
        "path",
        "equals",
        "present",
        "absent",
        "same_as",
        "not_same_as",
        "keys_exactly",
      ]),
      `${label}[${index}]`,
    );
    const target = asString(assertion.target, `${label}[${index}].target`);
    expect(["response", "state"]).toContain(target);
    const path = asString(assertion.path, `${label}[${index}].path`);
    expect(path).toMatch(/^\$(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\])*$/);
    if (target === "response") {
      expect(
        allowedResponsePaths.has(path),
        `${label}[${index}] response path must be documented for this route and status`,
      ).toBe(true);
    }
    if (target === "state") {
      assertStateAssertionPath(path, `${label}[${index}].path`);
    }
    const operators = [
      "equals",
      "present",
      "absent",
      "same_as",
      "not_same_as",
      "keys_exactly",
    ].filter((operator) => operator in assertion);
    expect(operators, `${label}[${index}] must have exactly one operator`).toHaveLength(1);
    if (target === "response" && forbiddenNestedCredentialResponsePaths.has(path)) {
      expect(
        operators,
        `${label}[${index}] nested credential selectors may only assert absence`,
      ).toEqual(["absent"]);
      expect(assertion.absent, `${label}[${index}] nested credential selector must be absent`).toBe(
        true,
      );
    }
    if ("present" in assertion || "absent" in assertion) {
      const operator = "present" in assertion ? "present" : "absent";
      expect(assertion[operator], `${label}[${index}].${operator}`).toBe(true);
    }
    if ("same_as" in assertion || "not_same_as" in assertion) {
      const operator = "same_as" in assertion ? "same_as" : "not_same_as";
      const reference = asRecord(assertion[operator], `${label}[${index}].${operator}`);
      expectExactKeys(reference, ["target", "path"], `${label}[${index}].${operator}`);
      const referenceTarget = asString(reference.target, `${label}[${index}].${operator}.target`);
      expect(["response", "state"]).toContain(referenceTarget);
      const referencePath = asString(reference.path, `${label}[${index}].${operator}.path`);
      expect(referencePath).toMatch(/^\$(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\])*$/);
      if (referenceTarget === "response") {
        expect(
          allowedResponsePaths.has(referencePath),
          `${label}[${index}] ${operator} response path must be documented for this route and status`,
        ).toBe(true);
      }
      if (referenceTarget === "state") {
        assertStateAssertionPath(referencePath, `${label}[${index}].${operator}.path`);
      }
    }
    if ("keys_exactly" in assertion) {
      expect(target, `${label}[${index}].keys_exactly is response-only`).toBe("response");
      const keys = assertStringArray(assertion.keys_exactly, `${label}[${index}].keys_exactly`);
      for (const key of keys) {
        expect(key, `${label}[${index}].keys_exactly key must be a JSON member`).toMatch(
          /^[A-Za-z_][A-Za-z0-9_]*$/,
        );
      }
    }
  }
}

function assertCredentialFree(value: unknown, label: string): void {
  if (typeof value === "string") {
    for (const pattern of sensitiveValuePatterns) {
      expect(pattern.test(value), `${label} must not contain secret material`).toBe(false);
    }
    return;
  }

  if (Array.isArray(value)) {
    for (const [index, entry] of value.entries()) {
      assertCredentialFree(entry, `${label}[${index}]`);
    }
    return;
  }

  if (value === null || typeof value !== "object") {
    return;
  }

  for (const [key, entry] of Object.entries(value)) {
    const normalizedKey = key.replace(/[_-]/g, "").toLowerCase();
    expect(sensitiveKeyNames.has(normalizedKey), `${label}.${key} must not be serialized`).toBe(
      false,
    );
    assertCredentialFree(entry, `${label}.${key}`);
  }
}

function requiresIdempotencyKey(method: string, path: string): boolean {
  if (method !== "POST" || !path.startsWith("/v1/")) {
    return false;
  }
  if (/^\/v1\/grants\/[^/]+\/consume$/.test(path)) {
    return false;
  }
  return (
    path === "/v1/grants/exchange" ||
    /^\/v1\/grants\/[^/]+\/(?:approve|complete|completion-queue|revoke|renew)$/.test(path) ||
    path === "/v1/task-graphs" ||
    /^\/v1\/task-graphs\/[^/]+\/(?:cancel|nodes\/[^/]+\/(?:approve|finalize))$/.test(path) ||
    path === "/v1/coordinations" ||
    /^\/v1\/coordinations\/[^/]+\/(?:approve|finalize)$/.test(path)
  );
}

async function readRepositoryJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(new URL(path, repositoryRoot), "utf8")) as unknown;
}

async function readRepositoryText(path: string): Promise<string> {
  return readFile(new URL(path, repositoryRoot), "utf8");
}

describe("v1 documentation and fixture contracts", () => {
  it("keeps the v1 plan mapped to the five specification documents", async () => {
    const plan = asRecord(
      await readRepositoryJson("docs/plans/v1-grant-contracts-test-plan.json"),
      "v1 test plan",
    );
    expect(plan.schema_version).toBe("1.0.0");
    expect(plan.status).toBe("PLANNED");
    const requirements = asArray(plan.requirements, "v1 test plan requirements").map(
      (requirement, index) => asRecord(requirement, `requirement ${index}`),
    );
    const requirementEntries = requirements.map((requirement, index) => ({
      id: asString(requirement.id, `requirement ${index} id`),
      requirement,
    }));
    const requirementIds = requirementEntries.map(({ id }) => id);
    expect(new Set(requirementIds).size).toBe(requirementIds.length);
    for (const { id, requirement } of requirementEntries) {
      expect(asString(requirement.status, `${id} status`)).toBe("SPECIFIED_NOT_IMPLEMENTED");
    }
    const requirementsById = new Map(
      requirementEntries.map(({ id, requirement }) => [id, requirement]),
    );

    expect([...requirementsById.keys()].sort()).toEqual(Object.keys(expectedSpecs).sort());

    for (const [requirementId, specPath] of Object.entries(expectedSpecs)) {
      const requirement = requirementsById.get(requirementId);
      expect(requirement, `${requirementId} is required`).toBeDefined();
      expect(asString(requirement?.spec, `${requirementId} spec`)).toBe(specPath);
      expect((await readRepositoryText(specPath)).trim()).not.toBe("");
    }

    const planCases = asArray(plan.cases, "v1 test plan cases").map((testCase, index) =>
      asRecord(testCase, `plan case ${index}`),
    );
    const planCaseIds = planCases.map((testCase, index) =>
      asString(testCase.id, `plan case ${index} id`),
    );
    const expectedFamilies = new Set(["GRAPH", "COORD", "QUEUE", "WIRE", "REUSE"]);
    const actualFamilies = new Set<string>();

    expect(new Set(planCaseIds).size).toBe(planCaseIds.length);
    for (const [index, testCase] of planCases.entries()) {
      const id = asString(testCase.id, `plan case ${index} id`);
      const family = id.match(/^V1-(GRAPH|COORD|QUEUE|WIRE|REUSE)-\d+$/)?.[1];
      expect(family, `${id} must use a known v1 case family`).toBeDefined();
      actualFamilies.add(family ?? "");
      expect(asString(testCase.status, `${id} status`)).toBe("PLANNED");
      expect(requirementsById.has(asString(testCase.requirement_id, `${id} requirement id`))).toBe(
        true,
      );
    }

    expect(actualFamilies).toEqual(expectedFamilies);
  });

  it("keeps the planned wire fixture credential-free, mapped, and coverage-complete", async () => {
    const [fixtureValue, errorManifestValue, wireSpec, planValue] = await Promise.all([
      readRepositoryJson("conformance/broker-wire/v1/cases.json"),
      readRepositoryJson("conformance/broker-wire/v1/errors.json"),
      readRepositoryText("docs/spec/broker-sdk-wire-v1.md"),
      readRepositoryJson("docs/plans/v1-grant-contracts-test-plan.json"),
    ]);
    const fixture = asRecord(fixtureValue, "v1 wire fixture");
    const errorManifest = asRecord(errorManifestValue, "v1 error manifest");
    const plan = asRecord(planValue, "v1 test plan");
    const fixtureCases = asArray(fixture.cases, "v1 wire fixture cases").map((testCase, index) =>
      asRecord(testCase, `wire case ${index}`),
    );
    const requirementIds = asArray(fixture.requirement_ids, "v1 fixture requirement ids").map(
      (id, index) => asString(id, `v1 fixture requirement id ${index}`),
    );
    const fixtureContract = asRecord(fixture.fixture_contract, "v1 fixture contract");
    const fixtureContractKeys = [
      "assertions",
      "expected",
      "harness_preconditions",
      "headers",
      "request",
      "covers",
    ];
    const errors = asArray(errorManifest.errors, "v1 error manifest errors").map((error, index) =>
      asRecord(error, `v1 error ${index}`),
    );
    const errorMap = new Map<string, { status: number; surface: string }>();
    const plannedCases = asArray(plan.cases, "v1 test plan cases").map((testCase, index) =>
      asRecord(testCase, `plan case ${index}`),
    );
    const plannedCaseRequirementIds = new Map(
      plannedCases.map((testCase, index) => [
        asString(testCase.id, `plan case ${index} id`),
        asString(testCase.requirement_id, `plan case ${index} requirement id`),
      ]),
    );

    expectOnlyKeys(
      fixture,
      new Set([
        "schema_version",
        "status",
        "wire_spec",
        "fixture_contract",
        "requirement_ids",
        "cases",
      ]),
      "v1 wire fixture",
    );
    expectOnlyKeys(
      errorManifest,
      new Set(["schema_version", "status", "wire_spec", "errors"]),
      "v1 error manifest",
    );
    expect(fixture.schema_version).toBe("1.1.0");
    expect(fixture.status).toBe("PLANNED");
    expect(fixture.wire_spec).toBe("docs/spec/broker-sdk-wire-v1.md");
    expect([...requirementIds].sort()).toEqual(Object.keys(expectedSpecs).sort());
    assertCredentialFree(fixture, "v1 wire fixture");
    assertCredentialFree(errorManifest, "v1 error manifest");
    expect(Object.keys(fixtureContract).sort()).toEqual(fixtureContractKeys.slice().sort());
    for (const key of fixtureContractKeys) {
      expect(asString(fixtureContract[key], `v1 fixture contract ${key}`).trim()).not.toBe("");
    }

    expect(errorManifest.schema_version).toBe("1.0.0");
    expect(errorManifest.status).toBe("PLANNED");
    expect(errorManifest.wire_spec).toBe("docs/spec/broker-sdk-wire-v1.md");
    for (const [index, error] of errors.entries()) {
      expectOnlyKeys(error, new Set(["code", "http_status", "surface"]), `v1 error ${index}`);
      const code = asString(error.code, `v1 error ${index} code`);
      const status = asInteger(error.http_status, `v1 error ${index} HTTP status`);
      const surface = asString(error.surface, `v1 error ${index} surface`);
      expect(code).toMatch(/^[a-z]+(?:_[a-z0-9]+)*$/);
      expect(status).toBeGreaterThanOrEqual(400);
      expect(status).toBeLessThanOrEqual(599);
      expect(["broker_http", "sdk_queue"]).toContain(surface);
      expect(errorMap.has(code), `duplicate frozen error ${code}`).toBe(false);
      expect(wireSpec).toContain(`| \`${code}\` | ${status} |`);
      errorMap.set(code, { status, surface });
    }

    const caseIds: string[] = [];
    const caseRequirementIds = new Set<string>();
    const areas = new Set<string>();
    const coveredErrors = new Set<string>();
    const coveredPlanCaseIds = new Set<string>();

    for (const [index, testCase] of fixtureCases.entries()) {
      expectOnlyKeys(testCase, fixtureCaseKeys, `wire case ${index}`);
      const id = asString(testCase.id, `wire case ${index} id`);
      const area = asString(testCase.area, `${id} area`);
      const requirementId = asString(testCase.requirement_id, `${id} requirement id`);
      const scenario = asString(testCase.scenario, `${id} scenario`);
      const surface = asString(testCase.surface ?? "broker_http", `${id} surface`);
      const method = asString(testCase.method, `${id} method`);
      const path = asString(testCase.path, `${id} path`);
      const request = asRecord(testCase.request, `${id} request`);
      const expected = asRecord(testCase.expected, `${id} expected`);
      const covers = asArray(testCase.covers, `${id} covers`).map((coveredCase, coveredIndex) =>
        asString(coveredCase, `${id} covers[${coveredIndex}]`),
      );
      const headers =
        testCase.headers === undefined ? undefined : asRecord(testCase.headers, `${id} headers`);
      const assertions = testCase.assertions;
      const status = asInteger(expected.status, `${id} expected status`);
      const expectedError =
        "error" in expected ? asString(expected.error, `${id} expected error`) : undefined;

      caseIds.push(id);
      areas.add(area);
      caseRequirementIds.add(requirementId);
      expect(id).toMatch(/^WIRE-\d+$/);
      expect(scenario.trim(), `${id} scenario must not be empty`).not.toBe("");
      expect(requirementIds).toContain(requirementId);
      expect(requirementForArea[area as keyof typeof requirementForArea] ?? "V1-25").toBe(
        requirementId,
      );
      expect(["broker_http", "sdk_queue"]).toContain(surface);
      expect(status).toBeGreaterThanOrEqual(100);
      expect(status).toBeLessThanOrEqual(599);
      expect(covers.length, `${id} must cover at least one planned case`).toBeGreaterThan(0);
      expect(new Set(covers).size, `${id} covered plan cases must be unique`).toBe(covers.length);
      for (const coveredCase of covers) {
        expect(plannedCaseRequirementIds.has(coveredCase), `${id} covers known plan case`).toBe(
          true,
        );
        expect(plannedCaseRequirementIds.get(coveredCase)).toBe(requirementId);
        coveredPlanCaseIds.add(coveredCase);
      }

      if (surface === "broker_http") {
        expect(method).toMatch(/^[A-Z]+$/);
        expect(method).not.toBe("LOCAL");
        expect(
          path === "/exchange" || path === "/.well-known/jwks.json" || /^\/v1\//.test(path),
        ).toBe(true);
      } else {
        expect(method).toBe("LOCAL");
        expect(["queue/requeue", "queue/scheduler-tick"]).toContain(path);
      }

      assertClosedRequestSchema(surface, method, path, request, `${id} request`, expectedError);

      if (requiresIdempotencyKey(method, path)) {
        expect(headers, `${id} requires Idempotency-Key`).toBeDefined();
      }
      if (headers !== undefined) {
        expect(Object.keys(headers)).toEqual(["Idempotency-Key"]);
        expect(asString(headers["Idempotency-Key"], `${id} Idempotency-Key`)).toMatch(
          /^[\x21-\x7e]{1,128}$/,
        );
      }

      if (expectedError !== undefined) {
        expectOnlyKeys(expected, new Set(["status", "error"]), `${id} error expectation`);
        if (assertions !== undefined) {
          assertTypedAssertions(assertions, `${id} error-state assertions`, new Set());
        }
        const declaredError = errorMap.get(expectedError);
        expect(declaredError, `${id} error must be frozen`).toBeDefined();
        expect(status).toBe(declaredError?.status);
        expect(surface).toBe(declaredError?.surface);
        coveredErrors.add(expectedError);
      } else {
        expectOnlyKeys(expected, new Set(["status"]), `${id} success expectation`);
        expect(assertions, `${id} success must have assertions`).toBeDefined();
        assertTypedAssertions(
          assertions,
          `${id} assertions`,
          responseAssertionPaths(method, path, status),
        );
      }
    }

    const wireCaseNumbers = caseIds.map((id) => Number(id.slice("WIRE-".length)));
    expect(new Set(caseIds).size).toBe(caseIds.length);
    expect(wireCaseNumbers).toEqual(
      Array.from({ length: caseIds.length }, (_, index) => index + 1),
    );
    expect([...caseRequirementIds].sort()).toEqual(requirementIds.slice().sort());
    for (const area of [
      "exchange",
      "idempotency",
      "dpop",
      "time",
      "completion",
      "graph",
      "queue",
      "coordination",
      "standing",
    ]) {
      expect(areas.has(area), `fixture must cover ${area}`).toBe(true);
    }
    expect([...coveredErrors].sort()).toEqual([...errorMap.keys()].sort());
    expect([...coveredPlanCaseIds].sort()).toEqual([...plannedCaseRequirementIds.keys()].sort());

    const findCovering = (
      plannedCase: string,
      predicate: (candidate: JsonRecord) => boolean = () => true,
    ): JsonRecord => {
      const witness = fixtureCases
        .filter((candidate) =>
          assertStringArray(candidate.covers, "candidate covers").includes(plannedCase),
        )
        .find(predicate);
      expect(witness, `a semantic witness for ${plannedCase} is required`).toBeDefined();
      return witness as JsonRecord;
    };
    const witnessAssertions = (witness: JsonRecord, label: string): unknown[] =>
      asArray(witness.assertions, `${label} assertions`);
    const stateEquals = (path: string, equals: unknown) => ({
      target: "state",
      path,
      equals,
    });
    const responsePresent = (path: string) => ({ target: "response", path, present: true });
    const responseAbsent = (path: string) => ({ target: "response", path, absent: true });
    const stateSameAs = (path: string, target: string, referencePath: string) => ({
      target: "state",
      path,
      same_as: { target, path: referencePath },
    });
    const responseSameAs = (path: string, target: string, referencePath: string) => ({
      target: "response",
      path,
      same_as: { target, path: referencePath },
    });
    const responseNotSameAs = (path: string, target: string, referencePath: string) => ({
      target: "response",
      path,
      not_same_as: { target, path: referencePath },
    });
    const responseKeysExactly = (path: string, keys: readonly string[]) => ({
      target: "response",
      path,
      keys_exactly: keys,
    });
    const graphViewKeys = ["definition_hash", "evidence_id", "expires_at", "id", "nodes", "state"];
    const graphNodeViewKeys = [
      "action",
      "audience",
      "depends_on",
      "dpop_jkt",
      "evidence_id",
      "expires_at",
      "grant_id",
      "id",
      "scope",
      "state",
      "use_limit",
    ];
    const coordinationViewKeys = [
      "entries",
      "evidence_id",
      "expires_at",
      "id",
      "plan_digest",
      "state",
    ];
    const coordinationEntryViewKeys = [
      "action",
      "audience",
      "completion_ttl_seconds",
      "dpop_jkt",
      "ordinal",
      "resource_id",
      "scope",
      "state",
    ];

    const allowedExchange = findCovering(
      "V1-WIRE-01",
      (candidate) =>
        asRecord(candidate.expected, "allowed exchange expected").status === 201 &&
        witnessAssertions(candidate, "allowed exchange").some(
          (assertion) =>
            asRecord(assertion, "allowed exchange assertion").path === "$.capability" &&
            asRecord(assertion, "allowed exchange assertion").present === true,
        ),
    );
    const pendingExchange = findCovering(
      "V1-WIRE-01",
      (candidate) =>
        asRecord(candidate.expected, "pending exchange expected").status === 202 &&
        witnessAssertions(candidate, "pending exchange").some(
          (assertion) =>
            asRecord(assertion, "pending exchange assertion").path === "$.capability" &&
            asRecord(assertion, "pending exchange assertion").absent === true,
        ),
    );
    expect(allowedExchange.path).toBe("/v1/grants/exchange");
    expect(pendingExchange.path).toBe("/v1/grants/exchange");

    const athMismatch = findCovering(
      "V1-WIRE-05",
      (candidate) =>
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "ath mismatch preconditions").binding_state ===
          "ath_mismatch",
    );
    expect(asRecord(athMismatch.expected, "ath mismatch expected").error).toBe(
      "dpop_proof_invalid",
    );
    expect(witnessAssertions(athMismatch, "ath mismatch")).toContainEqual(
      stateEquals("$.grant.consume_count", 0),
    );

    const timeBoundaryWitnesses = fixtureCases.filter((candidate) =>
      assertStringArray(candidate.covers, "time boundary covers").includes("V1-WIRE-06"),
    );
    const timePrecondition = (candidate: JsonRecord, name: string): unknown => {
      const preconditions = candidate.harness_preconditions;
      return preconditions === undefined
        ? undefined
        : asRecord(preconditions, "time boundary preconditions")[name];
    };
    expect(
      [
        ...new Set(
          timeBoundaryWitnesses.map((candidate) =>
            timePrecondition(candidate, "broker_time_relation"),
          ),
        ).values(),
      ]
        .filter((value): value is string => typeof value === "string")
        .sort(),
    ).toEqual(["at_expiry", "one_second_before_expiry"]);
    expect(
      [
        ...new Set(
          timeBoundaryWitnesses.map((candidate) =>
            timePrecondition(candidate, "dpop_iat_relation"),
          ),
        ).values(),
      ]
        .filter((value): value is string => typeof value === "string")
        .sort(),
    ).toEqual(["at_60_seconds", "outside_60_seconds"]);
    const preExpiryConsume = findCovering(
      "V1-WIRE-06",
      (candidate) =>
        timePrecondition(candidate, "broker_time_relation") === "one_second_before_expiry",
    );
    const expiryConsume = findCovering(
      "V1-WIRE-06",
      (candidate) => timePrecondition(candidate, "broker_time_relation") === "at_expiry",
    );
    const clockBoundaryConsume = findCovering(
      "V1-WIRE-06",
      (candidate) => timePrecondition(candidate, "dpop_iat_relation") === "at_60_seconds",
    );
    const staleProofConsume = findCovering(
      "V1-WIRE-06",
      (candidate) => timePrecondition(candidate, "dpop_iat_relation") === "outside_60_seconds",
    );
    expect(asRecord(preExpiryConsume.expected, "pre-expiry consume expected").status).toBe(200);
    expect(asRecord(expiryConsume.expected, "expiry consume expected").status).toBe(401);
    expect(asRecord(clockBoundaryConsume.expected, "clock-boundary consume expected").status).toBe(
      200,
    );
    expect(asRecord(staleProofConsume.expected, "stale proof consume expected").status).toBe(401);
    expect(timePrecondition(staleProofConsume, "binding_state")).toBe("valid");
    expect(witnessAssertions(staleProofConsume, "stale proof consume")).toContainEqual(
      stateEquals("$.grant.consume_count", 0),
    );
    const replayedProof = findCovering(
      "V1-WIRE-05",
      (candidate) => timePrecondition(candidate, "binding_state") === "replayed",
    );
    expect(timePrecondition(replayedProof, "dpop_iat_relation")).toBeUndefined();
    expect(witnessAssertions(replayedProof, "replayed proof")).toContainEqual(
      stateEquals("$.grant.consume_mutation_count", 0),
    );
    const replayedStandingProof = findCovering(
      "V1-REUSE-05",
      (candidate) => timePrecondition(candidate, "binding_state") === "replayed_after_restart",
    );
    expect(witnessAssertions(replayedStandingProof, "replayed standing proof")).toContainEqual(
      stateEquals("$.standing.consume_mutation_count", 0),
    );

    const approvalRetry = findCovering(
      "V1-WIRE-03",
      (candidate) =>
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "approval retry preconditions").retry === "exact",
    );
    expect(witnessAssertions(approvalRetry, "approval retry")).toContainEqual(
      responseSameAs("$.grant.id", "state", "$.original_response.grant.id"),
    );
    expect(witnessAssertions(approvalRetry, "approval retry")).toContainEqual(
      responseSameAs("$.capability", "state", "$.original_response.capability"),
    );
    expect(witnessAssertions(approvalRetry, "approval retry")).toContainEqual(
      stateEquals("$.grant.mint_count", 0),
    );

    const completionRetry = findCovering(
      "V1-WIRE-07",
      (candidate) =>
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "completion retry preconditions").retry ===
          "exact",
    );
    expect(witnessAssertions(completionRetry, "completion retry")).toContainEqual(
      responseSameAs("$.grant.id", "state", "$.original_response.grant.id"),
    );
    expect(witnessAssertions(completionRetry, "completion retry")).toContainEqual(
      responseSameAs("$.evidence.id", "state", "$.original_response.evidence.id"),
    );
    expect(witnessAssertions(completionRetry, "completion retry")).toContainEqual(
      stateEquals("$.evidence.mutation_count", 0),
    );

    const queueOptIn = findCovering(
      "V1-QUEUE-12",
      (candidate) =>
        candidate.path === "/v1/grants/exchange" &&
        asRecord(candidate.request, "queue opt-in request").completion_queue !== undefined,
    );
    const queueOptInRequest = asRecord(queueOptIn.request, "queue opt-in request");
    const completionQueue = asRecord(
      queueOptInRequest.completion_queue,
      "queue opt-in completion queue",
    );
    expect(completionQueue.dpop_jkt).not.toBe(queueOptInRequest.dpop_jkt);
    expect(witnessAssertions(queueOptIn, "queue opt-in")).toContainEqual(
      responsePresent("$.completion_queue.receipt"),
    );

    const malformedQueue = findCovering(
      "V1-QUEUE-02",
      (candidate) =>
        candidate.path.endsWith("/completion-queue") &&
        asRecord(candidate.expected, "malformed queue expected").error === "invalid_request",
    );
    expect(
      asRecord(malformedQueue.request, "malformed queue request").terminal_envelope,
    ).toBeDefined();

    const restartQueue = findCovering(
      "V1-QUEUE-05",
      (candidate) => candidate.surface === "sdk_queue" && candidate.path === "queue/scheduler-tick",
    );
    expect(witnessAssertions(restartQueue, "restart queue")).toContainEqual(
      stateEquals("$.queue.fresh_dpop_required", true),
    );

    const terminalQueues = fixtureCases.filter(
      (candidate) =>
        assertStringArray(candidate.covers, "terminal queue covers").includes("V1-QUEUE-10") &&
        asRecord(candidate.expected, "terminal queue expected").error === "queue_not_retryable",
    );
    expect(
      terminalQueues.map(
        (candidate) =>
          asRecord(candidate.harness_preconditions, "terminal queue preconditions").queue_state,
      ),
    ).toEqual(["broker_accepted", "expired", "cancelled"]);
    for (const terminalQueue of terminalQueues) {
      expect(witnessAssertions(terminalQueue, "terminal queue")).toContainEqual(
        stateEquals("$.queue.broker_delivery_count", 0),
      );
    }

    const liveDeadLetterRequeue = findCovering(
      "V1-QUEUE-10",
      (candidate) =>
        candidate.path === "queue/requeue" &&
        asRecord(candidate.expected, "live dead-letter requeue expected").status === 200,
    );
    const liveDeadLetterPreconditions = asRecord(
      liveDeadLetterRequeue.harness_preconditions,
      "live dead-letter requeue preconditions",
    );
    expect(liveDeadLetterPreconditions.queue_state).toBe("dead_letter");
    expect(liveDeadLetterPreconditions.operator_authorization).toBe("valid");
    expect(liveDeadLetterPreconditions.receipt_time_relation).toBe("before_expiry");
    expect(liveDeadLetterPreconditions.original_completion_key_state).toBe("available");
    expect(liveDeadLetterPreconditions.original_payload_state).toBe("immutable_available");
    expect(witnessAssertions(liveDeadLetterRequeue, "live dead-letter requeue")).toContainEqual(
      stateEquals("$.queue.state", "queued"),
    );
    for (const path of ["$.queue.id", "$.queue.completion_event_id", "$.queue.payload_digest"]) {
      const originalPath = path.replace("$.queue.", "$.original_queue.");
      expect(witnessAssertions(liveDeadLetterRequeue, "live dead-letter requeue")).toContainEqual(
        stateSameAs(path, "state", originalPath),
      );
    }
    expect(witnessAssertions(liveDeadLetterRequeue, "live dead-letter requeue")).toContainEqual(
      stateEquals("$.queue.receipt_mint_count", 0),
    );
    expect(witnessAssertions(liveDeadLetterRequeue, "live dead-letter requeue")).toContainEqual(
      stateEquals("$.queue.audit_trail_preserves_original", true),
    );
    expect(witnessAssertions(liveDeadLetterRequeue, "live dead-letter requeue")).toContainEqual(
      stateEquals("$.queue.requeue_transition_recorded", true),
    );
    expect(witnessAssertions(liveDeadLetterRequeue, "live dead-letter requeue")).toContainEqual(
      stateEquals("$.queue.broker_delivery_count", 0),
    );

    const unavailableKeyQueue = findCovering(
      "V1-QUEUE-13",
      (candidate) =>
        candidate.path === "queue/scheduler-tick" &&
        asRecord(candidate.expected, "missing key expected").error === "completion_key_unavailable",
    );
    expect(witnessAssertions(unavailableKeyQueue, "missing key queue")).toContainEqual(
      stateEquals("$.queue.state", "dead_letter"),
    );
    expect(witnessAssertions(unavailableKeyQueue, "missing key queue")).toContainEqual(
      stateEquals("$.queue.broker_delivery_count", 0),
    );

    const lateQueue = findCovering(
      "V1-QUEUE-07",
      (candidate) =>
        candidate.method === "GET" &&
        witnessAssertions(candidate, "late queue").some(
          (assertion) =>
            asRecord(assertion, "late queue assertion").path === "$.queue.state" &&
            asRecord(assertion, "late queue assertion").equals === "recorded_late",
        ),
    );
    expect(witnessAssertions(lateQueue, "late queue")).toContainEqual(
      stateEquals("$.grant.authority_revived", false),
    );

    const expiredReceiptQueue = findCovering(
      "V1-QUEUE-08",
      (candidate) =>
        asRecord(candidate.expected, "expired receipt queue expected").error ===
        "completion_receipt_expired",
    );
    expect(
      asRecord(expiredReceiptQueue.harness_preconditions, "expired receipt queue preconditions")
        .receipt_time_relation,
    ).toBe("at_expiry");
    expect(witnessAssertions(expiredReceiptQueue, "expired receipt queue")).toContainEqual(
      stateEquals("$.queue.item_count", 0),
    );
    expect(witnessAssertions(expiredReceiptQueue, "expired receipt queue")).toContainEqual(
      stateEquals("$.queue.evidence_mutation_count", 0),
    );
    expect(witnessAssertions(expiredReceiptQueue, "expired receipt queue")).toContainEqual(
      stateEquals("$.grant.authority_revived", false),
    );

    const queueObservability = findCovering("V1-QUEUE-03");
    expect(witnessAssertions(queueObservability, "queue observability")).toContainEqual(
      stateEquals("$.queue.telemetry_contains_sensitive_material", false),
    );

    const queueExactRetry = findCovering(
      "V1-QUEUE-04",
      (candidate) =>
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "queue retry preconditions").retry === "exact",
    );
    expect(asRecord(queueExactRetry.expected, "queue retry expected").status).toBe(202);
    expect(witnessAssertions(queueExactRetry, "queue retry")).toContainEqual(
      responseSameAs("$.queue.id", "state", "$.original_response.queue.id"),
    );
    expect(witnessAssertions(queueExactRetry, "queue retry")).toContainEqual(
      stateEquals("$.queue.item_count", 1),
    );
    expect(witnessAssertions(queueExactRetry, "queue retry")).toContainEqual(
      stateEquals("$.queue.enqueue_mutation_count", 0),
    );
    expect(witnessAssertions(queueExactRetry, "queue retry")).toContainEqual(
      stateEquals("$.queue.evidence_mutation_count", 0),
    );

    const graphMixedAudience = findCovering(
      "V1-GRAPH-10",
      (candidate) => asRecord(candidate.expected, "mixed graph expected").error === "graph_invalid",
    );
    const mixedNodes = asArray(
      asRecord(graphMixedAudience.request, "mixed graph request").nodes,
      "mixed graph nodes",
    );
    expect(asRecord(mixedNodes[0], "mixed graph first node").audience).not.toBe(
      asRecord(mixedNodes[1], "mixed graph second node").audience,
    );

    const graphCreate = findCovering(
      "V1-GRAPH-01",
      (candidate) =>
        candidate.path === "/v1/task-graphs" &&
        asRecord(candidate.expected, "graph create expected").status === 201,
    );
    expect(witnessAssertions(graphCreate, "graph create")).toContainEqual({
      target: "response",
      path: "$.capability",
      absent: true,
    });
    expect(witnessAssertions(graphCreate, "graph create")).toContainEqual({
      target: "response",
      path: "$.graph.state",
      equals: "active",
    });
    expect(witnessAssertions(graphCreate, "graph create")).toContainEqual({
      target: "response",
      path: "$.graph.nodes[0].grant_id",
      equals: null,
    });

    const emptyGraph = findCovering(
      "V1-GRAPH-01",
      (candidate) =>
        asArray(asRecord(candidate.request, "empty graph request").nodes, "empty graph nodes")
          .length === 0,
    );
    expect(asRecord(emptyGraph.expected, "empty graph expected").error).toBe("graph_invalid");
    expect(
      asRecord(emptyGraph.harness_preconditions, "empty graph preconditions").invalid_graph_reason,
    ).toBe("empty_nodes");
    expect(witnessAssertions(emptyGraph, "empty graph")).toContainEqual(
      stateEquals("$.graph.record_count", 0),
    );
    expect(witnessAssertions(emptyGraph, "empty graph")).toContainEqual(
      stateEquals("$.graph.grant_count", 0),
    );

    const graphSuccessReplies = fixtureCases
      .filter(
        (candidate) =>
          candidate.path.startsWith("/v1/task-graphs/") ||
          (candidate.path === "/v1/task-graphs" &&
            asRecord(candidate.expected, "graph create expected").status === 201),
      )
      .filter((candidate) => {
        const status = asRecord(candidate.expected, "graph reply expected").status;
        return typeof status === "number" && status >= 200 && status < 300;
      });
    expect(graphSuccessReplies.length).toBeGreaterThan(0);
    for (const graphReply of graphSuccessReplies) {
      expect(witnessAssertions(graphReply, "graph reply")).toContainEqual(
        responseAbsent("$.capability"),
      );
      for (const path of ["$.graph.nodes[0].capability", "$.graph.nodes[0].credential"]) {
        expect(witnessAssertions(graphReply, "graph reply")).toContainEqual(responseAbsent(path));
      }
      if (/\/nodes\/[^/]+\/(?:approve|finalize)$/.test(graphReply.path as string)) {
        for (const path of ["$.node.capability", "$.node.credential"]) {
          expect(witnessAssertions(graphReply, "graph node reply")).toContainEqual(
            responseAbsent(path),
          );
        }
      }
    }
    expect(witnessAssertions(graphCreate, "graph create")).toContainEqual(
      responseKeysExactly("$.graph", graphViewKeys),
    );
    expect(witnessAssertions(graphCreate, "graph create")).toContainEqual(
      responseKeysExactly("$.graph.nodes[0]", graphNodeViewKeys),
    );

    const graphApproval = findCovering("V1-GRAPH-06", (candidate) =>
      /\/approve$/.test(asString(candidate.path, "graph approval path")),
    );
    for (const path of ["$.node.grant_id", "$.graph.nodes[0].grant_id"]) {
      expect(witnessAssertions(graphApproval, "graph approval")).toContainEqual({
        target: "response",
        path,
        equals: null,
      });
    }
    for (const [path, equals] of [
      ["$.node.action", { method: "POST", path: "/payments/42", query: "" }],
      ["$.node.audience", "https://api.example.test"],
      ["$.node.scope", ["payments:write"]],
      ["$.node.dpop_jkt", "jkt-graph-a"],
      ["$.node.use_limit", 1],
    ] as const) {
      expect(witnessAssertions(graphApproval, "graph approval")).toContainEqual({
        target: "response",
        path,
        equals,
      });
    }
    const graphApprovalPreconditions = asRecord(
      graphApproval.harness_preconditions,
      "graph approval preconditions",
    );
    const graphDeadline = asString(
      graphApprovalPreconditions.graph_deadline,
      "graph approval deadline",
    );
    const graphV0ExpiryCap = asString(
      graphApprovalPreconditions.v0_grant_expiry_cap,
      "graph approval v0 expiry cap",
    );
    expect(Date.parse(graphDeadline)).toBeLessThanOrEqual(Date.parse(graphV0ExpiryCap));
    expect(witnessAssertions(graphApproval, "graph approval")).toContainEqual({
      target: "response",
      path: "$.node.expires_at",
      equals: graphDeadline,
    });
    expect(witnessAssertions(graphApproval, "graph approval")).toContainEqual({
      target: "response",
      path: "$.graph.expires_at",
      equals: graphDeadline,
    });
    expect(witnessAssertions(graphApproval, "graph approval")).toContainEqual({
      target: "response",
      path: "$.graph.nodes[0].action",
      same_as: { target: "response", path: "$.node.action" },
    });
    for (const path of ["$.graph", "$.graph.nodes[0]", "$.node"]) {
      expect(witnessAssertions(graphApproval, "graph approval")).toContainEqual(
        responseKeysExactly(path, path === "$.graph" ? graphViewKeys : graphNodeViewKeys),
      );
    }

    const graphBoundExchange = findCovering(
      "V1-GRAPH-12",
      (candidate) =>
        candidate.path === "/v1/grants/exchange" &&
        asRecord(candidate.expected, "graph exchange expected").status === 201,
    );
    expect(
      asRecord(graphBoundExchange.harness_preconditions, "graph exchange preconditions")
        .graph_node_state,
    ).toBe("approved");
    expect(witnessAssertions(graphBoundExchange, "graph exchange")).toContainEqual(
      stateSameAs("$.graph.nodes[0].grant_id", "response", "$.grant.id"),
    );
    expect(witnessAssertions(graphBoundExchange, "graph exchange")).toContainEqual(
      stateEquals("$.graph.nodes[0].grant_count", 1),
    );
    expect(witnessAssertions(graphBoundExchange, "graph exchange")).toContainEqual(
      stateSameAs("$.graph.nodes[0].expires_at", "response", "$.grant.expires_at"),
    );
    const graphBoundPreconditions = asRecord(
      graphBoundExchange.harness_preconditions,
      "graph exchange preconditions",
    );
    const graphBoundDeadline = asString(
      graphBoundPreconditions.graph_deadline,
      "graph exchange deadline",
    );
    const graphBoundV0ExpiryCap = asString(
      graphBoundPreconditions.v0_grant_expiry_cap,
      "graph exchange v0 expiry cap",
    );
    expect(Date.parse(graphBoundV0ExpiryCap)).toBeLessThanOrEqual(Date.parse(graphBoundDeadline));
    expect(witnessAssertions(graphBoundExchange, "graph exchange")).toContainEqual({
      target: "response",
      path: "$.grant.expires_at",
      equals: graphBoundV0ExpiryCap,
    });

    const graphExchangeExpiryBranches = fixtureCases
      .filter(
        (candidate) =>
          candidate.path === "/v1/grants/exchange" &&
          assertStringArray(candidate.covers, "graph exchange expiry covers").includes(
            "V1-GRAPH-12",
          ) &&
          asRecord(candidate.expected, "graph exchange expiry expected").status === 201,
      )
      .map((candidate) => {
        const preconditions = asRecord(
          candidate.harness_preconditions,
          "graph exchange expiry preconditions",
        );
        const deadline = asString(preconditions.graph_deadline, "graph exchange deadline");
        const v0Cap = asString(preconditions.v0_grant_expiry_cap, "graph exchange v0 expiry cap");
        const expectedExpiry = Date.parse(deadline) <= Date.parse(v0Cap) ? deadline : v0Cap;
        const expiryAssertion = witnessAssertions(candidate, "graph exchange expiry").find(
          (assertion) =>
            asRecord(assertion, "graph exchange expiry assertion").path === "$.grant.expires_at",
        );
        expect(expiryAssertion, "graph exchange expiry assertion is required").toBeDefined();
        expect(asRecord(expiryAssertion, "graph exchange expiry assertion").equals).toBe(
          expectedExpiry,
        );
        return expectedExpiry === deadline ? "graph" : "v0";
      })
      .sort();
    expect(graphExchangeExpiryBranches).toEqual(["graph", "v0"]);

    const exactEmptyRequestRoutes = [
      /^\/v1\/grants\/[^/]+\/(?:approve|complete|revoke|renew)$/,
      /^\/v1\/coordinations\/[^/]+\/approve$/,
    ];
    for (const route of exactEmptyRequestRoutes) {
      const routeCases = fixtureCases.filter((candidate) => route.test(candidate.path));
      expect(routeCases.length, `fixture must cover ${route.source}`).toBeGreaterThan(0);
      for (const routeCase of routeCases) {
        expect(Object.keys(asRecord(routeCase.request, "exact empty request")).sort()).toEqual([]);
      }
    }

    const graphBoundMismatches = fixtureCases.filter((candidate) => {
      if (!assertStringArray(candidate.covers, "graph mismatch covers").includes("V1-GRAPH-12")) {
        return false;
      }
      const preconditions = candidate.harness_preconditions;
      return (
        preconditions !== undefined &&
        asRecord(preconditions, "graph mismatch preconditions").graph_substitution_field !==
          undefined
      );
    });
    const graphSubstitutionFields = graphBoundMismatches
      .map((candidate) =>
        asString(
          asRecord(candidate.harness_preconditions, "graph mismatch preconditions")
            .graph_substitution_field,
          "graph substitution field",
        ),
      )
      .sort();
    expect(graphSubstitutionFields).toEqual([
      "action",
      "audience",
      "dpop_jkt",
      "requested_use_limit",
      "scope",
    ]);
    for (const graphBoundMismatch of graphBoundMismatches) {
      expect(witnessAssertions(graphBoundMismatch, "graph mismatch")).toContainEqual(
        stateEquals("$.graph.nodes[0].grant_count", 0),
      );
    }

    const graphSelectorCompositions = fixtureCases.filter((candidate) =>
      assertStringArray(candidate.covers, "graph selector composition covers").includes(
        "V1-GRAPH-13",
      ),
    );
    const graphSelectorPairs = graphSelectorCompositions
      .map((candidate) => {
        const request = asRecord(candidate.request, "graph selector composition request");
        return ["graph", "coordination", "standing_profile_id", "completion_queue"]
          .filter((selector) => request[selector] !== undefined)
          .sort()
          .join("+");
      })
      .sort();
    expect(graphSelectorPairs).toEqual([
      "completion_queue+graph",
      "coordination+graph",
      "graph+standing_profile_id",
    ]);
    for (const composition of graphSelectorCompositions) {
      expect(asRecord(composition.expected, "graph selector composition expected").error).toBe(
        "invalid_request",
      );
      expect(witnessAssertions(composition, "graph selector composition")).toContainEqual(
        stateEquals("$.grant_count", 0),
      );
    }

    const queueSelectorCompositions = fixtureCases.filter((candidate) =>
      assertStringArray(candidate.covers, "queue selector composition covers").includes(
        "V1-QUEUE-14",
      ),
    );
    const queueSelectorPairs = queueSelectorCompositions
      .map((candidate) => {
        const request = asRecord(candidate.request, "queue selector composition request");
        return ["graph", "coordination", "standing_profile_id", "completion_queue"]
          .filter((selector) => request[selector] !== undefined)
          .sort()
          .join("+");
      })
      .sort();
    expect(queueSelectorPairs).toEqual([
      "completion_queue+coordination",
      "completion_queue+standing_profile_id",
    ]);
    for (const composition of queueSelectorCompositions) {
      expect(asRecord(composition.expected, "queue selector composition expected").error).toBe(
        "invalid_request",
      );
      expect(witnessAssertions(composition, "queue selector composition")).toContainEqual(
        stateEquals("$.grant_count", 0),
      );
    }

    const failedGraphPredecessor = findCovering(
      "V1-GRAPH-08",
      (candidate) =>
        asRecord(candidate.expected, "failed graph predecessor expected").error ===
        "node_dependency_unsatisfied",
    );
    expect(witnessAssertions(failedGraphPredecessor, "failed graph predecessor")).toContainEqual(
      stateEquals("$.graph.nodes[1].state", "blocked"),
    );

    const coordinationCreate = findCovering(
      "V1-COORD-08",
      (candidate) => candidate.path === "/v1/coordinations",
    );
    expect(witnessAssertions(coordinationCreate, "coordination create")).toContainEqual(
      responseAbsent("$.capability"),
    );
    expect(witnessAssertions(coordinationCreate, "coordination create")).toContainEqual({
      target: "response",
      path: "$.coordination.entries[0].state",
      equals: "unreleased",
    });
    expect(witnessAssertions(coordinationCreate, "coordination create")).toContainEqual({
      target: "response",
      path: "$.coordination.entries[1].state",
      equals: "unreleased",
    });
    expect(witnessAssertions(coordinationCreate, "coordination create")).toContainEqual({
      target: "response",
      path: "$.coordination.entries[0].grant_id",
      absent: true,
    });
    expect(witnessAssertions(coordinationCreate, "coordination create")).toContainEqual({
      target: "response",
      path: "$.coordination.entries[1].grant_id",
      absent: true,
    });
    expect(witnessAssertions(coordinationCreate, "coordination create")).toContainEqual(
      responseKeysExactly("$.coordination", coordinationViewKeys),
    );
    for (const path of ["$.coordination.entries[0]", "$.coordination.entries[1]"]) {
      expect(witnessAssertions(coordinationCreate, "coordination create")).toContainEqual(
        responseKeysExactly(path, coordinationEntryViewKeys),
      );
    }

    const duplicateOrdinalCoordination = findCovering(
      "V1-COORD-01",
      (candidate) =>
        candidate.path === "/v1/coordinations" &&
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "duplicate ordinal preconditions")
          .duplicate_ordinal === true,
    );
    const duplicateOrdinalEntries = asArray(
      asRecord(duplicateOrdinalCoordination.request, "duplicate ordinal request").entries,
      "duplicate ordinal entries",
    ).map((entry, index) => asRecord(entry, `duplicate ordinal entry ${index}`));
    expect(duplicateOrdinalEntries).toHaveLength(2);
    expect(duplicateOrdinalEntries[0]?.ordinal).toBe(duplicateOrdinalEntries[1]?.ordinal);
    expect(duplicateOrdinalEntries[0]?.resource_id).not.toBe(
      duplicateOrdinalEntries[1]?.resource_id,
    );
    expect(witnessAssertions(duplicateOrdinalCoordination, "duplicate ordinal")).toContainEqual(
      stateEquals("$.coordination.record_count", 0),
    );
    expect(witnessAssertions(duplicateOrdinalCoordination, "duplicate ordinal")).toContainEqual(
      stateEquals("$.coordination.child_grant_count", 0),
    );

    const duplicateResourceCoordination = findCovering(
      "V1-COORD-01",
      (candidate) =>
        candidate.path === "/v1/coordinations" &&
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "duplicate resource preconditions")
          .duplicate_resource_id === true,
    );
    expect(
      asRecord(duplicateResourceCoordination.expected, "duplicate resource expected").error,
    ).toBe("coordination_invalid");
    const duplicateResourceEntries = asArray(
      asRecord(duplicateResourceCoordination.request, "duplicate resource request").entries,
      "duplicate resource entries",
    ).map((entry, index) => asRecord(entry, `duplicate resource entry ${index}`));
    expect(duplicateResourceEntries).toHaveLength(2);
    expect(duplicateResourceEntries[0]?.ordinal).not.toBe(duplicateResourceEntries[1]?.ordinal);
    expect(duplicateResourceEntries[0]?.resource_id).toBe(duplicateResourceEntries[1]?.resource_id);
    expect(witnessAssertions(duplicateResourceCoordination, "duplicate resource")).toContainEqual(
      stateEquals("$.coordination.record_count", 0),
    );
    expect(witnessAssertions(duplicateResourceCoordination, "duplicate resource")).toContainEqual(
      stateEquals("$.coordination.child_grant_count", 0),
    );

    const coordinationApproval = findCovering("V1-COORD-03", (candidate) =>
      /\/approve$/.test(asString(candidate.path, "coordination approval path")),
    );
    expect(witnessAssertions(coordinationApproval, "coordination approval")).toContainEqual(
      stateSameAs("$.coordination.approved_plan_digest", "response", "$.coordination.plan_digest"),
    );
    expect(witnessAssertions(coordinationApproval, "coordination approval")).toContainEqual(
      responseAbsent("$.capability"),
    );
    expect(witnessAssertions(coordinationApproval, "coordination approval")).toContainEqual({
      target: "response",
      path: "$.coordination.entries[0].state",
      equals: "ready",
    });
    expect(witnessAssertions(coordinationApproval, "coordination approval")).toContainEqual({
      target: "response",
      path: "$.coordination.entries[0].grant_id",
      absent: true,
    });

    const widenedCoordinationScope = findCovering(
      "V1-COORD-02",
      (candidate) =>
        asRecord(candidate.expected, "widened coordination scope expected").error ===
        "scope_not_authorized",
    );
    const widenedCoordinationRequest = asRecord(
      widenedCoordinationScope.request,
      "widened coordination scope request",
    );
    expect(asRecord(widenedCoordinationRequest.action, "widened coordination action")).toEqual({
      method: "POST",
      path: "/payments/42",
      query: "",
    });
    expect(widenedCoordinationRequest.scope).toEqual(["payments:write", "payments:admin"]);
    expect(widenedCoordinationRequest.dpop_jkt).toBe("jkt-coordination-a");
    expect(
      witnessAssertions(widenedCoordinationScope, "widened coordination scope"),
    ).toContainEqual(stateEquals("$.coordination.entries[0].grant_count", 0));
    expect(
      witnessAssertions(widenedCoordinationScope, "widened coordination scope"),
    ).toContainEqual(stateEquals("$.coordination.child_grant_count", 0));

    const readyCoordinationChild = findCovering(
      "V1-COORD-10",
      (candidate) =>
        asRecord(candidate.expected, "ready coordination child expected").status === 201,
    );
    const readyCoordinationChildPreconditions = asRecord(
      readyCoordinationChild.harness_preconditions,
      "ready coordination child preconditions",
    );
    expect(readyCoordinationChildPreconditions.parent_state).toBe("approved");
    expect(readyCoordinationChildPreconditions.entry_ordinal).toBe(1);
    expect(readyCoordinationChildPreconditions.entry_state).toBe("ready");
    expect(readyCoordinationChildPreconditions.trusted_child_authority_state).toBe("resolved");
    const parentDeadline = asString(
      readyCoordinationChildPreconditions.parent_deadline,
      "ready coordination child parent deadline",
    );
    const childV0ExpiryCap = asString(
      readyCoordinationChildPreconditions.v0_grant_expiry_cap,
      "ready coordination child v0 expiry cap",
    );
    expect(Date.parse(childV0ExpiryCap)).toBeLessThanOrEqual(Date.parse(parentDeadline));
    const readyCoordinationChildRequest = asRecord(
      readyCoordinationChild.request,
      "ready coordination child request",
    );
    expect(
      asRecord(readyCoordinationChildRequest.coordination, "ready coordination selector"),
    ).toEqual({ id: "coordination-a", resource_id: "billing" });
    for (const [path, equals] of [
      ["$.grant.action", { method: "POST", path: "/payments/42", query: "" }],
      ["$.grant.audience", "https://api.example.test"],
      ["$.grant.scope", ["payments:write"]],
      ["$.grant.dpop_jkt", "jkt-coordination-a"],
      ["$.grant.use_limit", 1],
      ["$.grant.expires_at", childV0ExpiryCap],
    ] as const) {
      expect(witnessAssertions(readyCoordinationChild, "ready coordination child")).toContainEqual({
        target: "response",
        path,
        equals,
      });
    }
    expect(witnessAssertions(readyCoordinationChild, "ready coordination child")).toContainEqual(
      responsePresent("$.capability"),
    );
    expect(witnessAssertions(readyCoordinationChild, "ready coordination child")).toContainEqual(
      stateSameAs("$.coordination.entries[0].grant_id", "response", "$.grant.id"),
    );
    expect(witnessAssertions(readyCoordinationChild, "ready coordination child")).toContainEqual(
      stateEquals("$.coordination.entries[0].grant_count", 1),
    );
    expect(witnessAssertions(readyCoordinationChild, "ready coordination child")).toContainEqual(
      stateSameAs("$.coordination.entries[0].expires_at", "response", "$.grant.expires_at"),
    );
    expect(witnessAssertions(readyCoordinationChild, "ready coordination child")).toContainEqual({
      target: "state",
      path: "$.coordination.entries[1].grant_id",
      absent: true,
    });
    expect(witnessAssertions(readyCoordinationChild, "ready coordination child")).toContainEqual({
      target: "state",
      path: "$.coordination.parent_capability",
      absent: true,
    });

    const coordinationChildExpiryBranches = fixtureCases
      .filter(
        (candidate) =>
          assertStringArray(candidate.covers, "coordination child expiry covers").includes(
            "V1-COORD-10",
          ) && asRecord(candidate.expected, "coordination child expiry expected").status === 201,
      )
      .map((candidate) => {
        const preconditions = asRecord(
          candidate.harness_preconditions,
          "coordination child expiry preconditions",
        );
        const deadline = asString(
          preconditions.parent_deadline,
          "coordination child parent deadline",
        );
        const v0Cap = asString(
          preconditions.v0_grant_expiry_cap,
          "coordination child v0 expiry cap",
        );
        const expectedExpiry = Date.parse(deadline) <= Date.parse(v0Cap) ? deadline : v0Cap;
        const expiryAssertion = witnessAssertions(candidate, "coordination child expiry").find(
          (assertion) =>
            asRecord(assertion, "coordination child expiry assertion").path ===
            "$.grant.expires_at",
        );
        expect(expiryAssertion, "coordination child expiry assertion is required").toBeDefined();
        expect(asRecord(expiryAssertion, "coordination child expiry assertion").equals).toBe(
          expectedExpiry,
        );
        return expectedExpiry === deadline ? "parent" : "v0";
      })
      .sort();
    expect(coordinationChildExpiryBranches).toEqual(["parent", "v0"]);

    const coordinationSuccessReplies = fixtureCases.filter((candidate) => {
      if (!candidate.path.startsWith("/v1/coordinations")) {
        return false;
      }
      const status = asRecord(candidate.expected, "coordination reply expected").status;
      return typeof status === "number" && status >= 200 && status < 300;
    });
    expect(coordinationSuccessReplies.length).toBeGreaterThan(0);
    for (const coordinationReply of coordinationSuccessReplies) {
      expect(witnessAssertions(coordinationReply, "coordination reply")).toContainEqual(
        responseAbsent("$.capability"),
      );
      for (const ordinal of [0, 1]) {
        for (const field of ["capability", "credential"]) {
          expect(witnessAssertions(coordinationReply, "coordination reply")).toContainEqual(
            responseAbsent(`$.coordination.entries[${ordinal}].${field}`),
          );
        }
      }
    }
    expect(witnessAssertions(coordinationApproval, "coordination approval")).toContainEqual({
      target: "response",
      path: "$.coordination.entries[1].state",
      equals: "unreleased",
    });
    expect(witnessAssertions(coordinationApproval, "coordination approval")).toContainEqual({
      target: "response",
      path: "$.coordination.entries[1].grant_id",
      absent: true,
    });
    expect(witnessAssertions(coordinationApproval, "coordination approval")).toContainEqual(
      stateEquals("$.coordination.entries[1].state", "unreleased"),
    );
    expect(witnessAssertions(coordinationApproval, "coordination approval")).toContainEqual({
      target: "state",
      path: "$.coordination.entries[1].grant_id",
      absent: true,
    });
    expect(witnessAssertions(coordinationApproval, "coordination approval")).toContainEqual(
      responseKeysExactly("$.coordination", coordinationViewKeys),
    );
    for (const path of ["$.coordination.entries[0]", "$.coordination.entries[1]"]) {
      expect(witnessAssertions(coordinationApproval, "coordination approval")).toContainEqual(
        responseKeysExactly(path, coordinationEntryViewKeys),
      );
    }

    const failedCoordinationFinalization = findCovering(
      "V1-COORD-07",
      (candidate) =>
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "failed coordination preconditions")
          .terminal_cause === "failure",
    );
    expect(
      witnessAssertions(failedCoordinationFinalization, "failed coordination finalization"),
    ).toContainEqual(responseKeysExactly("$.coordination", coordinationViewKeys));
    for (const path of ["$.coordination.entries[0]", "$.coordination.entries[1]"]) {
      expect(
        witnessAssertions(failedCoordinationFinalization, "failed coordination finalization"),
      ).toContainEqual(responseKeysExactly(path, coordinationEntryViewKeys));
    }

    const successorBeforeEvidence = findCovering(
      "V1-COORD-04",
      (candidate) =>
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "successor preconditions").predecessor_state ===
          "pending",
    );
    const successorRequest = asRecord(successorBeforeEvidence.request, "successor request");
    expect(asRecord(successorRequest.coordination, "successor coordination").resource_id).toBe(
      "ledger",
    );
    expect(asRecord(successorRequest.action, "successor action").path).toBe("/entries/42");
    expect(successorRequest.audience).toBe("https://ledger.example.test");
    expect(successorRequest.scope).toEqual(["ledger:write"]);
    expect(successorRequest.dpop_jkt).toBe("jkt-coordination-b");

    const forgedOutcome = findCovering(
      "V1-COORD-06",
      (candidate) =>
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "forged outcome preconditions")
          .resource_outcome_receipt_state === "forged",
    );
    expect(witnessAssertions(forgedOutcome, "forged outcome")).toContainEqual(
      stateEquals("$.coordination.evidence_mutation_count", 0),
    );

    const parallelOutcome = findCovering(
      "V1-COORD-05",
      (candidate) =>
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "parallel outcome preconditions")
          .parallel_outcome_attempts === 2,
    );
    expect(witnessAssertions(parallelOutcome, "parallel outcome")).toContainEqual(
      stateEquals("$.coordination.outcome_winner_count", 1),
    );
    expect(witnessAssertions(parallelOutcome, "parallel outcome")).toContainEqual(
      stateEquals("$.coordination.successor_release_count", 1),
    );

    const replayedOutcome = findCovering(
      "V1-COORD-06",
      (candidate) =>
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "replayed outcome preconditions")
          .resource_outcome_receipt_state === "replayed_identical",
    );
    expect(witnessAssertions(replayedOutcome, "replayed outcome")).toContainEqual(
      stateEquals("$.coordination.successor_release_count", 0),
    );
    expect(witnessAssertions(replayedOutcome, "replayed outcome")).toContainEqual(
      stateEquals("$.coordination.evidence_mutation_count", 0),
    );

    const terminalCoordinationWitnesses = fixtureCases.filter((candidate) => {
      if (
        !assertStringArray(candidate.covers, "terminal coordination covers").includes("V1-COORD-07")
      ) {
        return false;
      }
      const preconditions = candidate.harness_preconditions;
      return (
        candidate.path.endsWith("/finalize") &&
        preconditions !== undefined &&
        asRecord(preconditions, "terminal coordination preconditions").terminal_cause !== undefined
      );
    });
    const terminalCoordinationCauses = terminalCoordinationWitnesses
      .map((candidate) =>
        asString(
          asRecord(candidate.harness_preconditions, "terminal coordination preconditions")
            .terminal_cause,
          "terminal coordination cause",
        ),
      )
      .sort();
    expect(terminalCoordinationCauses).toEqual(["cancel", "expiry", "failure", "revoke"]);
    for (const terminalCoordination of terminalCoordinationWitnesses) {
      expect(asRecord(terminalCoordination.expected, "terminal coordination expected").status).toBe(
        200,
      );
      expect(witnessAssertions(terminalCoordination, "terminal coordination")).toContainEqual(
        stateEquals("$.coordination.partial_evidence_preserved", true),
      );
      expect(witnessAssertions(terminalCoordination, "terminal coordination")).toContainEqual(
        stateEquals("$.coordination.remaining_entries_disabled", true),
      );
      expect(witnessAssertions(terminalCoordination, "terminal coordination")).toContainEqual(
        stateEquals("$.coordination.unconsumed_child_grant_count", 0),
      );
    }

    const v0ReuseDescriptors = fixtureCases.filter(
      (candidate) =>
        candidate.path === "/exchange" &&
        assertStringArray(candidate.covers, "v0 reuse descriptor covers").includes("V1-REUSE-01"),
    );
    expect(v0ReuseDescriptors).toHaveLength(2);
    expect(
      v0ReuseDescriptors.some(
        (candidate) =>
          asRecord(candidate.request, "v0 standing request").standing_profile_id !== undefined,
      ),
    ).toBe(true);
    expect(
      v0ReuseDescriptors.some(
        (candidate) => asRecord(candidate.request, "v0 limit request").requested_use_limit === 2,
      ),
    ).toBe(true);

    const downgrade = findCovering("V1-REUSE-09");
    expect(witnessAssertions(downgrade, "downgrade")).toContainEqual(
      responseNotSameAs("$.grant.id", "state", "$.standing.previous_grant.id"),
    );
    expect(witnessAssertions(downgrade, "downgrade")).toContainEqual(
      stateEquals("$.standing.in_place_mutation", false),
    );

    const renewal = findCovering(
      "V1-REUSE-06",
      (candidate) =>
        candidate.path.endsWith("/renew") &&
        asRecord(candidate.expected, "renewal expected").status === 201,
    );
    expect(witnessAssertions(renewal, "renewal")).toContainEqual(
      responseNotSameAs("$.grant.id", "state", "$.standing.prior_segment.grant.id"),
    );
    for (const [path, referencePath] of [
      ["$.grant.action", "$.profile.action"],
      ["$.grant.audience", "$.profile.audience"],
      ["$.grant.scope", "$.profile.scope"],
      ["$.grant.dpop_jkt", "$.profile.dpop_jkt"],
      ["$.grant.use_limit", "$.profile.segment_max_successful_consumes"],
      ["$.grant.expires_at", "$.profile.next_segment_expires_at"],
    ]) {
      expect(witnessAssertions(renewal, "renewal")).toContainEqual(
        responseSameAs(path, "state", referencePath),
      );
    }
    expect(witnessAssertions(renewal, "renewal")).toContainEqual(
      stateEquals("$.standing.active_segment_count", 1),
    );
    expect(witnessAssertions(renewal, "renewal")).toContainEqual(
      stateEquals("$.standing.remaining_rotations", 1),
    );
    expect(witnessAssertions(renewal, "renewal")).toContainEqual(
      stateEquals("$.grant.expires_at_lte_absolute", true),
    );

    const finalUseRace = findCovering(
      "V1-REUSE-03",
      (candidate) =>
        candidate.harness_preconditions !== undefined &&
        asRecord(candidate.harness_preconditions, "final-use race preconditions")
          .parallel_consume_attempts === 2,
    );
    expect(
      asRecord(finalUseRace.harness_preconditions, "final-use race preconditions")
        .remaining_uses_before,
    ).toBe(1);
    expect(asRecord(finalUseRace.expected, "final-use race expected").status).toBe(200);
    expect(witnessAssertions(finalUseRace, "final-use race")).toContainEqual(
      stateEquals("$.standing.winner_count", 1),
    );
    expect(witnessAssertions(finalUseRace, "final-use race")).toContainEqual(
      stateEquals("$.standing.remaining_successful_consumes", 0),
    );
    expect(witnessAssertions(finalUseRace, "final-use race")).toContainEqual(
      stateEquals("$.standing.loser_error", "reuse_limit_exhausted"),
    );
    expect(witnessAssertions(finalUseRace, "final-use race")).toContainEqual(
      stateEquals("$.standing.consume_mutation_count", 1),
    );

    const standingProfileMismatchFields = fixtureCases
      .filter(
        (candidate) =>
          assertStringArray(candidate.covers, "standing mismatch covers").includes("V1-REUSE-04") &&
          candidate.harness_preconditions !== undefined,
      )
      .flatMap((candidate) => {
        const preconditions = asRecord(
          candidate.harness_preconditions,
          "standing mismatch preconditions",
        );
        if (preconditions.profile_mismatch_field !== undefined) {
          return [asString(preconditions.profile_mismatch_field, "standing mismatch field")];
        }
        if (preconditions.binding_state === "ath_mismatch") {
          return ["proof_token"];
        }
        return [];
      });
    expect(new Set(standingProfileMismatchFields)).toEqual(
      new Set([
        "action",
        "audience",
        "scope",
        "dpop_jkt",
        "completion_ttl_seconds",
        "requested_use_limit",
        "proof_token",
      ]),
    );

    const standingExpiry = findCovering(
      "V1-REUSE-07",
      (candidate) =>
        asRecord(candidate.expected, "standing expiry expected").error === "grant_expired",
    );
    expect(witnessAssertions(standingExpiry, "standing expiry")).toContainEqual({
      target: "state",
      path: "$.evidence.credential",
      absent: true,
    });

    const publicKeys = findCovering(
      "V1-WIRE-08",
      (candidate) => candidate.path === "/.well-known/jwks.json",
    );
    expect(witnessAssertions(publicKeys, "public keys")).toContainEqual({
      target: "response",
      path: "$.keys[0]",
      keys_exactly: ["alg", "crv", "kid", "kty", "use", "x", "y"],
    });
    for (const [path, expected] of [
      ["$.keys[0].kty", "EC"],
      ["$.keys[0].crv", "P-256"],
      ["$.keys[0].use", "sig"],
      ["$.keys[0].alg", "ES256"],
    ] as const) {
      expect(witnessAssertions(publicKeys, "public keys")).toContainEqual({
        target: "response",
        path,
        equals: expected,
      });
    }
    for (const path of ["$.keys[0].x", "$.keys[0].y", "$.keys[0].kid"]) {
      expect(witnessAssertions(publicKeys, "public keys")).toContainEqual(responsePresent(path));
    }
    for (const path of [
      "$.keys[0].d",
      "$.keys[0].p",
      "$.keys[0].q",
      "$.keys[0].dp",
      "$.keys[0].dq",
      "$.keys[0].qi",
      "$.keys[0].k",
    ]) {
      expect(witnessAssertions(publicKeys, "public keys")).toContainEqual(responseAbsent(path));
    }
  });
});
