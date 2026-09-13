import { Broker, type DpopReplayEntry, type RevocationTransport } from "./broker.js";
import { Es256CapabilitySigner } from "./crypto.js";
import {
  BROKER_COORDINATOR_NAME,
  type DurableObjectNamespace,
  type DurableObjectState,
  type GrantExpiryEnvironment,
  INTERNAL_EXPIRY_PATH,
  INTERNAL_EXPIRY_SCHEDULE_PATH,
  INTERNAL_TOKEN_HEADER,
} from "./durable-object.js";
import { type BrokerStoreSnapshot, InMemoryBrokerStore } from "./store.js";
import type {
  AuditEvent,
  AuthorityResolver,
  Grant,
  PolicyDecision,
  PolicyDocument,
  PolicyRule,
  VerifiedAuthority,
} from "./types.js";
import { type ApprovalAuthorizer, createBrokerWorker } from "./worker.js";

const runtimeStateKey = "broker-runtime-state-v1";

export interface ServiceBinding {
  fetch(request: Request): Promise<Response>;
}

export interface BrokerD1PreparedStatement {
  bind(...values: readonly unknown[]): BrokerD1PreparedStatement;
  run(): Promise<unknown>;
}

export interface BrokerD1Database {
  prepare(query: string): BrokerD1PreparedStatement;
}

export interface BrokerRuntimeEnvironment extends GrantExpiryEnvironment {
  BROKER_COORDINATOR: DurableObjectNamespace;
  GRANT_EXPIRY: DurableObjectNamespace;
  BROKER_DB?: BrokerD1Database;
  BROKER_SIGNING_JWK?: string;
  BROKER_SIGNING_KID?: string;
  BROKER_ISSUER?: string;
  BROKER_MAX_TTL_SECONDS?: string;
  BROKER_POLICY_JSON?: string;
  BROKER_REVOCATION_TARGETS?: string;
  AUTHORITY?: ServiceBinding;
  APPROVAL?: ServiceBinding;
  OPERATOR?: ServiceBinding;
  REVOCATION?: ServiceBinding;
}

interface BrokerRuntimeState {
  version: 1;
  store: BrokerStoreSnapshot;
  dpopReplayEntries: readonly DpopReplayEntry[];
}

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { "cache-control": "no-store" },
  });
}

function isInternalPath(path: string): boolean {
  return path === "/__warden/internal" || path.startsWith("/__warden/internal/");
}

function isStringArray(value: unknown): value is readonly string[] {
  return (
    Array.isArray(value) && value.every((entry) => typeof entry === "string" && entry.length > 0)
  );
}

function hasOnlyKeys(value: JsonObject, allowed: readonly string[]): boolean {
  const allowedKeys = new Set(allowed);
  return Object.keys(value).every((key) => allowedKeys.has(key));
}

function parseAuthority(
  value: unknown,
  input: Parameters<AuthorityResolver["resolve"]>[0],
): VerifiedAuthority | undefined {
  if (
    !isObject(value) ||
    value.agentId !== input.agentId ||
    value.subjectId !== input.subjectId ||
    value.subjectTokenId !== input.subjectTokenId ||
    !isStringArray(value.registrationScopes) ||
    !isStringArray(value.subjectScopes) ||
    !isStringArray(value.resources)
  ) {
    return undefined;
  }
  return {
    agentId: value.agentId,
    subjectId: value.subjectId,
    subjectTokenId: value.subjectTokenId,
    registrationScopes: value.registrationScopes,
    subjectScopes: value.subjectScopes,
    resources: value.resources,
  };
}

/** Resolves authority only through an explicitly configured service binding. */
class BoundAuthorityResolver implements AuthorityResolver {
  public constructor(private readonly authority: ServiceBinding | undefined) {}

  public async resolve(
    input: Parameters<AuthorityResolver["resolve"]>[0],
  ): Promise<VerifiedAuthority | undefined> {
    if (!this.authority) {
      return undefined;
    }
    try {
      const response = await this.authority.fetch(
        new Request("https://warden-authority.internal/resolve", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            agentId: input.agentId,
            subjectId: input.subjectId,
            subjectTokenId: input.subjectTokenId,
          }),
        }),
      );
      if (!response.ok) {
        return undefined;
      }
      return parseAuthority(await response.json(), input);
    } catch {
      return undefined;
    }
  }
}

class BoundApprovalAuthorizer implements ApprovalAuthorizer {
  public constructor(
    private readonly broker: Broker,
    private readonly approval: ServiceBinding | undefined,
  ) {}

  public async authorize(input: {
    request: Request;
    grantId: string;
  }): Promise<string | undefined> {
    const grant = this.broker.store.getGrant(input.grantId);
    if (!grant || !this.approval) {
      return undefined;
    }
    const headers = new Headers({ "content-type": "application/json" });
    const authorization = input.request.headers.get("authorization");
    if (authorization) {
      headers.set("authorization", authorization);
    }
    try {
      const response = await this.approval.fetch(
        new Request("https://warden-approval.internal/authorize", {
          method: "POST",
          headers,
          body: JSON.stringify({ grant: approvalView(grant) }),
        }),
      );
      if (!response.ok) {
        return undefined;
      }
      const body: unknown = await response.json();
      return isObject(body) && typeof body.approver === "string" && body.approver.length > 0
        ? body.approver
        : undefined;
    } catch {
      return undefined;
    }
  }
}

/** Authorizes an operator revocation through a separately configured trusted binding. */
class BoundOperatorAuthorizer implements ApprovalAuthorizer {
  public constructor(
    private readonly broker: Broker,
    private readonly operator: ServiceBinding | undefined,
  ) {}

  public async authorize(input: {
    request: Request;
    grantId: string;
  }): Promise<string | undefined> {
    const grant = this.broker.store.getGrant(input.grantId);
    if (!grant || !this.operator) {
      return undefined;
    }
    const headers = new Headers({ "content-type": "application/json" });
    const authorization = input.request.headers.get("authorization");
    if (authorization) {
      headers.set("authorization", authorization);
    }
    try {
      const response = await this.operator.fetch(
        new Request("https://warden-operator.internal/authorize", {
          method: "POST",
          headers,
          body: JSON.stringify({ grant: approvalView(grant) }),
        }),
      );
      if (!response.ok) {
        return undefined;
      }
      const body: unknown = await response.json();
      return isObject(body) && typeof body.operator === "string" && body.operator.length > 0
        ? body.operator
        : undefined;
    } catch {
      return undefined;
    }
  }
}

function approvalView(grant: Grant): JsonObject {
  return {
    id: grant.id,
    agentId: grant.agentId,
    subjectId: grant.subjectId,
    action: grant.action,
    audience: grant.audience,
    requestedScope: grant.requestedScope,
    grantedScope: grant.grantedScope,
    policyDecision: grant.policyDecision,
    approvalReference: grant.approvalReference,
    expiresAt: grant.expiresAt,
  };
}

/** Delivers only to the explicitly configured trusted service binding. */
class BoundRevocationTransport implements RevocationTransport {
  public constructor(private readonly revocation: ServiceBinding | undefined) {}

  public async deliver(input: {
    grantId: string;
    target: string;
    eventId: string;
  }): Promise<{ receipt: string }> {
    if (!this.revocation) {
      throw new Error("REVOCATION binding is required for configured revocation targets");
    }
    const response = await this.revocation.fetch(
      new Request("https://warden-revocation.internal/deliver", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      }),
    );
    if (!response.ok) {
      throw new Error(`revocation delivery failed with ${response.status}`);
    }
    const body: unknown = await response.json();
    if (!isObject(body) || typeof body.receipt !== "string" || !body.receipt) {
      throw new Error("revocation delivery did not return a receipt");
    }
    return { receipt: body.receipt };
  }
}

function isPolicyDecision(value: unknown): value is PolicyDecision {
  return value === "allow" || value === "require-approval" || value === "block";
}

function parsePolicyRule(value: unknown): PolicyRule {
  if (
    !isObject(value) ||
    !hasOnlyKeys(value, ["id", "decision", "match"]) ||
    typeof value.id !== "string" ||
    !value.id ||
    !isPolicyDecision(value.decision)
  ) {
    throw new Error("BROKER_POLICY_JSON contains an invalid rule");
  }
  if (value.match === undefined) {
    return { id: value.id, decision: value.decision };
  }
  if (
    !isObject(value.match) ||
    !hasOnlyKeys(value.match, ["agentId", "resource", "action", "scope", "timeWindow"]) ||
    Object.keys(value.match).length === 0
  ) {
    throw new Error("BROKER_POLICY_JSON contains an invalid rule match");
  }
  const match: NonNullable<PolicyRule["match"]> = {};
  for (const key of ["agentId", "resource", "action"] as const) {
    const candidate = value.match[key];
    if (candidate !== undefined) {
      if (typeof candidate !== "string" || !candidate) {
        throw new Error("BROKER_POLICY_JSON contains an invalid rule match");
      }
      match[key] = candidate;
    }
  }
  if (value.match.scope !== undefined) {
    if (!isStringArray(value.match.scope)) {
      throw new Error("BROKER_POLICY_JSON contains an invalid rule scope");
    }
    match.scope = value.match.scope;
  }
  if (value.match.timeWindow !== undefined) {
    const window = value.match.timeWindow;
    if (
      !isObject(window) ||
      !hasOnlyKeys(window, ["startHourInclusive", "endHourExclusive"]) ||
      typeof window.startHourInclusive !== "number" ||
      typeof window.endHourExclusive !== "number" ||
      !Number.isSafeInteger(window.startHourInclusive) ||
      !Number.isSafeInteger(window.endHourExclusive) ||
      window.startHourInclusive < 0 ||
      window.startHourInclusive > 23 ||
      window.endHourExclusive < 0 ||
      window.endHourExclusive > 23
    ) {
      throw new Error("BROKER_POLICY_JSON contains an invalid time window");
    }
    match.timeWindow = {
      startHourInclusive: window.startHourInclusive,
      endHourExclusive: window.endHourExclusive,
    };
  }
  return { id: value.id, decision: value.decision, match };
}

function parsePolicy(value: string | undefined): PolicyDocument | undefined {
  if (value === undefined) {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("BROKER_POLICY_JSON must be valid JSON");
  }
  if (
    !isObject(parsed) ||
    !hasOnlyKeys(parsed, ["version", "default", "rules"]) ||
    parsed.version !== 1 ||
    !isPolicyDecision(parsed.default) ||
    !Array.isArray(parsed.rules)
  ) {
    throw new Error("BROKER_POLICY_JSON must be a policy document");
  }
  return {
    version: 1,
    default: parsed.default,
    rules: parsed.rules.map(parsePolicyRule),
  };
}

function parseRevocationTargets(value: string | undefined): readonly string[] {
  if (value === undefined) {
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("BROKER_REVOCATION_TARGETS must be valid JSON");
  }
  if (!isStringArray(parsed)) {
    throw new Error("BROKER_REVOCATION_TARGETS must be a string array");
  }
  const targets = new Set<string>();
  for (const target of parsed) {
    let url: URL;
    try {
      url = new URL(target);
    } catch {
      throw new Error("BROKER_REVOCATION_TARGETS must contain https URLs");
    }
    if (url.protocol !== "https:" || url.username || url.password) {
      throw new Error("BROKER_REVOCATION_TARGETS must contain https URLs");
    }
    targets.add(target);
  }
  return [...targets];
}

function parseMaxTtl(value: string | undefined): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error("BROKER_MAX_TTL_SECONDS must be a positive integer");
  }
  return parsed;
}

function configuredIssuer(value: string | undefined): string {
  const issuer = value ?? "https://warden-broker.invalid";
  const parsed = new URL(issuer);
  if (parsed.protocol !== "https:" || parsed.search || parsed.hash) {
    throw new Error("BROKER_ISSUER must be an https origin");
  }
  return issuer.replace(/\/+$/u, "");
}

function requireInternalToken(environment: BrokerRuntimeEnvironment): void {
  if (!environment.BROKER_INTERNAL_TOKEN) {
    throw new Error("BROKER_INTERNAL_TOKEN is required");
  }
}

async function signerFromEnvironment(
  environment: BrokerRuntimeEnvironment,
): Promise<Es256CapabilitySigner> {
  if (!environment.BROKER_SIGNING_JWK) {
    throw new Error("BROKER_SIGNING_JWK is required");
  }
  let privateJwk: JsonWebKey;
  try {
    privateJwk = JSON.parse(environment.BROKER_SIGNING_JWK) as JsonWebKey;
  } catch {
    throw new Error("BROKER_SIGNING_JWK must be valid JSON");
  }
  return Es256CapabilitySigner.fromPrivateJwk(
    environment.BROKER_SIGNING_KID ?? "broker-es256-1",
    privateJwk,
  );
}

function isStoreSnapshot(value: unknown): value is BrokerStoreSnapshot {
  return (
    isObject(value) &&
    value.version === 1 &&
    Array.isArray(value.grants) &&
    Array.isArray(value.audits) &&
    Array.isArray(value.evidence) &&
    Array.isArray(value.idempotency) &&
    Array.isArray(value.subjectTokenGrants) &&
    Array.isArray(value.deliveries)
  );
}

function parseReplayEntries(value: unknown): readonly DpopReplayEntry[] {
  if (!Array.isArray(value)) {
    throw new Error("invalid broker replay state");
  }
  const entries: DpopReplayEntry[] = [];
  for (const entry of value) {
    if (
      !isObject(entry) ||
      typeof entry.jti !== "string" ||
      !entry.jti ||
      typeof entry.expiresAt !== "number" ||
      !Number.isFinite(entry.expiresAt)
    ) {
      throw new Error("invalid broker replay state");
    }
    entries.push({ jti: entry.jti, expiresAt: entry.expiresAt });
  }
  return entries;
}

function parseRuntimeState(value: unknown): BrokerRuntimeState | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isObject(value) || value.version !== 1 || !isStoreSnapshot(value.store)) {
    throw new Error("invalid broker durable state");
  }
  return {
    version: 1,
    store: value.store,
    dpopReplayEntries: parseReplayEntries(value.dpopReplayEntries),
  };
}

const grantUpsert = `
  INSERT INTO grants (
    id, agent_id, subject_id, audience, action_descriptor, requested_scope,
    granted_scope, dpop_thumbprint, state, issued_at, expires_at, completed_at, evidence_id
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(id) DO UPDATE SET
    agent_id = excluded.agent_id,
    subject_id = excluded.subject_id,
    audience = excluded.audience,
    action_descriptor = excluded.action_descriptor,
    requested_scope = excluded.requested_scope,
    granted_scope = excluded.granted_scope,
    dpop_thumbprint = excluded.dpop_thumbprint,
    state = excluded.state,
    issued_at = excluded.issued_at,
    expires_at = excluded.expires_at,
    completed_at = excluded.completed_at,
    evidence_id = excluded.evidence_id
`;

const auditInsert = `
  INSERT OR IGNORE INTO broker_audit_events (
    id, grant_id, event_type, created_at, safe_detail
  ) VALUES (?, ?, ?, ?, ?)
`;

const permittedAuditDetailKeys = new Set(["policy", "source", "approver", "delivered", "attempts"]);

function safeAuditDetail(event: AuditEvent): string | null {
  if (!event.detail) {
    return null;
  }
  const safe: Record<string, string | number | boolean> = {};
  for (const [key, value] of Object.entries(event.detail)) {
    if (permittedAuditDetailKeys.has(key)) {
      safe[key] = value;
    }
  }
  return Object.keys(safe).length > 0 ? JSON.stringify(safe) : null;
}

/**
 * D1 is an audit projection, not part of the coordinator's atomic transition.
 * DO storage remains authoritative if this best-effort mirror is unavailable.
 */
export async function projectBrokerLedger(
  database: BrokerD1Database | undefined,
  broker: Broker,
): Promise<void> {
  if (!database) {
    return;
  }
  for (const grant of broker.store.listGrants()) {
    await database
      .prepare(grantUpsert)
      .bind(
        grant.id,
        grant.agentId,
        grant.subjectId,
        grant.audience,
        grant.action,
        JSON.stringify(grant.requestedScope),
        JSON.stringify(grant.grantedScope),
        grant.dpopThumbprint,
        grant.status,
        grant.issuedAt ?? null,
        grant.expiresAt,
        grant.completedAt ?? null,
        grant.evidenceId ?? null,
      )
      .run();
    for (const event of broker.store.auditFor(grant.id)) {
      await database
        .prepare(auditInsert)
        .bind(event.id, event.grantId, event.type, event.at, safeAuditDetail(event))
        .run();
    }
  }
}

/** The singleton Durable Object owns all mutable broker state. */
export class BrokerCoordinatorDurableObject {
  private brokerPromise: Promise<Broker> | undefined;
  private router: ReturnType<typeof createBrokerWorker> | undefined;

  public constructor(
    private readonly state: DurableObjectState,
    private readonly environment: BrokerRuntimeEnvironment,
  ) {}

  public async fetch(request: Request): Promise<Response> {
    try {
      const broker = await this.broker();
      const path = new URL(request.url).pathname;
      const response = isInternalPath(path)
        ? await this.internal(request, broker)
        : await this.publicRouter(broker).fetch(request);
      await this.persist(broker);
      await this.project(broker);
      await this.scheduleRetry(broker);
      return response;
    } catch {
      this.resetBroker();
      return json({ error: "temporarily_unavailable" }, 503);
    }
  }

  private async broker(): Promise<Broker> {
    this.brokerPromise ??= this.createBroker();
    return this.brokerPromise;
  }

  private async createBroker(): Promise<Broker> {
    requireInternalToken(this.environment);
    const stored = parseRuntimeState(await this.state.storage.get<unknown>(runtimeStateKey));
    return Broker.create({
      signer: await signerFromEnvironment(this.environment),
      store: InMemoryBrokerStore.fromSnapshot(stored?.store),
      authorityResolver: new BoundAuthorityResolver(this.environment.AUTHORITY),
      issuer: configuredIssuer(this.environment.BROKER_ISSUER),
      maxTtlSeconds: parseMaxTtl(this.environment.BROKER_MAX_TTL_SECONDS),
      policy: parsePolicy(this.environment.BROKER_POLICY_JSON),
      revocationTargets: parseRevocationTargets(this.environment.BROKER_REVOCATION_TARGETS),
      revocationTransport: new BoundRevocationTransport(this.environment.REVOCATION),
      dpopReplayEntries: stored?.dpopReplayEntries,
    });
  }

  private resetBroker(): void {
    this.brokerPromise = undefined;
    this.router = undefined;
  }

  private publicRouter(broker: Broker): ReturnType<typeof createBrokerWorker> {
    this.router ??= createBrokerWorker(broker, {
      approvalAuthorizer: new BoundApprovalAuthorizer(broker, this.environment.APPROVAL),
      operatorAuthorizer: new BoundOperatorAuthorizer(broker, this.environment.OPERATOR),
      onActiveGrant: (grant) => this.scheduleExpiry(grant),
    });
    return this.router;
  }

  private async internal(request: Request, broker: Broker): Promise<Response> {
    if (
      request.method !== "POST" ||
      new URL(request.url).pathname !== INTERNAL_EXPIRY_PATH ||
      !this.environment.BROKER_INTERNAL_TOKEN ||
      request.headers.get(INTERNAL_TOKEN_HEADER) !== this.environment.BROKER_INTERNAL_TOKEN
    ) {
      return json({ error: "not_found" }, 404);
    }
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid_request" }, 400);
    }
    if (!isObject(body) || typeof body.grantId !== "string" || !body.grantId) {
      return json({ error: "invalid_request" }, 400);
    }
    return json(await broker.expire(body.grantId));
  }

  private async scheduleExpiry(grant: Grant): Promise<void> {
    if (!this.environment.BROKER_INTERNAL_TOKEN) {
      throw new Error("BROKER_INTERNAL_TOKEN is required for expiry scheduling");
    }
    const expiry = this.environment.GRANT_EXPIRY.get(
      this.environment.GRANT_EXPIRY.idFromName(grant.id),
    );
    const response = await expiry.fetch(
      new Request(`https://grant-expiry.internal${INTERNAL_EXPIRY_SCHEDULE_PATH}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          [INTERNAL_TOKEN_HEADER]: this.environment.BROKER_INTERNAL_TOKEN,
        },
        body: JSON.stringify({ grantId: grant.id, expiresAt: grant.expiresAt }),
      }),
    );
    if (!response.ok) {
      throw new Error(`expiry schedule failed with ${response.status}`);
    }
  }

  private async persist(broker: Broker): Promise<void> {
    await this.state.storage.put<BrokerRuntimeState>(runtimeStateKey, {
      version: 1,
      store: broker.store.snapshot(),
      dpopReplayEntries: broker.dpopReplayEntries(),
    });
  }

  private async project(broker: Broker): Promise<void> {
    try {
      await projectBrokerLedger(this.environment.BROKER_DB, broker);
    } catch {
      // The Durable Object state above is authoritative; retry on a later mutation.
    }
  }

  public async alarm(): Promise<void> {
    try {
      const broker = await this.broker();
      await broker.retryRevocations();
      await this.persist(broker);
      await this.project(broker);
      await this.scheduleRetry(broker);
    } catch (error) {
      this.resetBroker();
      throw error;
    }
  }

  private async scheduleRetry(broker: Broker): Promise<void> {
    let earliest: number | undefined;
    for (const grant of broker.store.listGrants()) {
      for (const delivery of broker.store.deliveriesFor(grant.id)) {
        if (delivery.status === "delivered") {
          continue;
        }
        const dueAt = delivery.nextAttemptAt ?? Date.now();
        if (earliest === undefined || dueAt < earliest) {
          earliest = dueAt;
        }
      }
    }
    if (earliest !== undefined) {
      await this.state.storage.setAlarm(earliest);
    }
  }
}

export function createBrokerRuntimeWorker(): {
  fetch(request: Request, environment: BrokerRuntimeEnvironment): Promise<Response>;
} {
  return {
    async fetch(request, environment): Promise<Response> {
      const path = new URL(request.url).pathname;
      if (isInternalPath(path)) {
        return json({ error: "not_found" }, 404);
      }
      try {
        const coordinator = environment.BROKER_COORDINATOR.get(
          environment.BROKER_COORDINATOR.idFromName(BROKER_COORDINATOR_NAME),
        );
        return await coordinator.fetch(request);
      } catch {
        return json({ error: "temporarily_unavailable" }, 503);
      }
    },
  };
}

const runtimeWorker = createBrokerRuntimeWorker();

export default runtimeWorker;
