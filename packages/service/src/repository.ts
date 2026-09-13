import type {
  ClaimRecord,
  ClaimRepository,
  D1Database,
  DurableObjectState,
  EventDelivery,
  EventSubscriber,
  IdentityAttempt,
  IssuedToken,
  ReplayRecord,
  RevocationEvent,
  ServiceIdentity,
  ServiceStore,
} from "./types.js";

function copy<T>(value: T): T {
  return structuredClone(value);
}

export class InMemoryServiceStore implements ServiceStore {
  private readonly identities = new Map<string, ServiceIdentity>();
  private readonly identityAttempts = new Map<string, IdentityAttempt>();
  private readonly claims = new Map<string, ClaimRecord>();
  private readonly tokens = new Map<string, IssuedToken>();
  private readonly replays = new Map<string, number>();
  private readonly subscribers = new Map<string, EventSubscriber>();
  private readonly eventsById = new Map<string, RevocationEvent>();
  private readonly eventIdByToken = new Map<string, string>();
  private readonly deliveries = new Map<string, EventDelivery>();

  public async createIdentity(identity: ServiceIdentity): Promise<void> {
    this.identities.set(identity.id, copy(identity));
  }

  public async findIdentityById(id: string): Promise<ServiceIdentity | undefined> {
    const identity = this.identities.get(id);
    return identity ? copy(identity) : undefined;
  }

  public async findIdentityBySubject(subject: string): Promise<ServiceIdentity | undefined> {
    const identity = [...this.identities.values()].find(
      (candidate) => candidate.subject === subject,
    );
    return identity ? copy(identity) : undefined;
  }

  public async saveIdentity(identity: ServiceIdentity): Promise<void> {
    this.identities.set(identity.id, copy(identity));
  }

  public async createIdentityAttempt(attempt: IdentityAttempt): Promise<void> {
    this.identityAttempts.set(attempt.id, copy(attempt));
  }

  public async listIdentityAttempts(): Promise<readonly IdentityAttempt[]> {
    return [...this.identityAttempts.values()]
      .sort((left, right) => left.occurredAt - right.occurredAt)
      .map(copy);
  }

  public async createClaim(claim: ClaimRecord): Promise<void> {
    this.claims.set(claim.id, copy(claim));
  }

  public async findClaimById(id: string): Promise<ClaimRecord | undefined> {
    const claim = this.claims.get(id);
    return claim ? copy(claim) : undefined;
  }

  public async findByUserCodeHash(hash: string): Promise<ClaimRecord | undefined> {
    const claim = [...this.claims.values()].find((candidate) => candidate.userCodeHash === hash);
    return claim ? copy(claim) : undefined;
  }

  public async findByDeviceCodeHash(hash: string): Promise<ClaimRecord | undefined> {
    const claim = [...this.claims.values()].find((candidate) => candidate.deviceCodeHash === hash);
    return claim ? copy(claim) : undefined;
  }

  public async compareAndSet(previous: ClaimRecord, next: ClaimRecord): Promise<boolean> {
    const stored = this.claims.get(previous.id);
    if (!stored || stored.version !== previous.version || next.version !== previous.version + 1) {
      return false;
    }
    this.claims.set(next.id, copy(next));
    return true;
  }

  public async createToken(token: IssuedToken): Promise<void> {
    this.tokens.set(token.id, copy(token));
  }

  public async findTokenById(id: string): Promise<IssuedToken | undefined> {
    const token = this.tokens.get(id);
    return token ? copy(token) : undefined;
  }

  public async revokeToken(id: string, at: number): Promise<boolean> {
    const token = this.tokens.get(id);
    if (!token || token.revokedAt !== undefined) {
      return false;
    }
    this.tokens.set(id, { ...token, revokedAt: at });
    return true;
  }

  public async markIfUnused(record: ReplayRecord, now: number): Promise<boolean> {
    const existingExpiry = this.replays.get(record.id);
    if (existingExpiry !== undefined && existingExpiry > now) {
      return false;
    }
    this.replays.set(record.id, record.expiresAt);
    return true;
  }

  public async createSubscriber(subscriber: EventSubscriber): Promise<void> {
    this.subscribers.set(subscriber.id, copy(subscriber));
  }

  public async listSubscribers(): Promise<readonly EventSubscriber[]> {
    return [...this.subscribers.values()]
      .filter((subscriber) => subscriber.disabledAt === undefined)
      .map(copy);
  }

  public async createEvent(event: RevocationEvent): Promise<boolean> {
    if (this.eventIdByToken.has(event.tokenId)) {
      return false;
    }
    this.eventsById.set(event.id, copy(event));
    this.eventIdByToken.set(event.tokenId, event.id);
    return true;
  }

  public async findEventById(id: string): Promise<RevocationEvent | undefined> {
    const event = this.eventsById.get(id);
    return event ? copy(event) : undefined;
  }

  public async findEventByTokenId(tokenId: string): Promise<RevocationEvent | undefined> {
    const eventId = this.eventIdByToken.get(tokenId);
    const event = eventId ? this.eventsById.get(eventId) : undefined;
    return event ? copy(event) : undefined;
  }

  public async createDelivery(delivery: EventDelivery): Promise<void> {
    this.deliveries.set(delivery.id, copy(delivery));
  }

  public async listDueDeliveries(now: number, limit: number): Promise<readonly EventDelivery[]> {
    return [...this.deliveries.values()]
      .filter((delivery) => delivery.status === "pending" && delivery.nextAttemptAt <= now)
      .sort((left, right) => left.nextAttemptAt - right.nextAttemptAt)
      .slice(0, limit)
      .map(copy);
  }

  public async nextPendingDeliveryAt(): Promise<number | undefined> {
    return [...this.deliveries.values()]
      .filter((delivery) => delivery.status === "pending")
      .map((delivery) => delivery.nextAttemptAt)
      .sort((left, right) => left - right)[0];
  }

  public async findSubscriber(id: string): Promise<EventSubscriber | undefined> {
    const subscriber = this.subscribers.get(id);
    return subscriber ? copy(subscriber) : undefined;
  }

  public async saveDelivery(delivery: EventDelivery): Promise<void> {
    this.deliveries.set(delivery.id, copy(delivery));
  }
}

function claimKey(id: string): string {
  return `claim:${id}`;
}

function userCodeIndexKey(hash: string): string {
  return `claim:user-code:${hash}`;
}

function deviceCodeIndexKey(hash: string): string {
  return `claim:device-code:${hash}`;
}

const activeClaimIdsKey = "claim:active-ids";
const nextClaimExpiryKey = "claim:next-expiry";

/**
 * Claim state is owned by one Durable Object, so a read-check-write transition
 * is serialized by the runtime instead of relying on cross-request memory.
 */
export class DurableObjectClaimState implements ClaimRepository {
  public constructor(private readonly state: DurableObjectState) {}

  public async createClaim(claim: ClaimRecord): Promise<void> {
    const [existing, userCodeClaim, deviceCodeClaim, activeClaimIds, nextExpiry] =
      await Promise.all([
        this.state.storage.get<ClaimRecord>(claimKey(claim.id)),
        this.state.storage.get<string>(userCodeIndexKey(claim.userCodeHash)),
        this.state.storage.get<string>(deviceCodeIndexKey(claim.deviceCodeHash)),
        this.state.storage.get<readonly string[]>(activeClaimIdsKey),
        this.state.storage.get<number>(nextClaimExpiryKey),
      ]);
    if (existing || userCodeClaim || deviceCodeClaim) {
      throw new Error(`claim ${claim.id} conflicts with existing state`);
    }
    await this.state.storage.put({
      [claimKey(claim.id)]: copy(claim),
      [userCodeIndexKey(claim.userCodeHash)]: claim.id,
      [deviceCodeIndexKey(claim.deviceCodeHash)]: claim.id,
      [activeClaimIdsKey]: [...(activeClaimIds ?? []), claim.id],
      [nextClaimExpiryKey]: Math.min(nextExpiry ?? claim.expiresAt, claim.expiresAt),
    });
    if (nextExpiry === undefined || claim.expiresAt < nextExpiry) {
      await this.state.storage.setAlarm(claim.expiresAt);
    }
  }

  public async findClaimById(id: string): Promise<ClaimRecord | undefined> {
    const claim = await this.state.storage.get<ClaimRecord>(claimKey(id));
    return claim ? copy(claim) : undefined;
  }

  public async findByUserCodeHash(hash: string): Promise<ClaimRecord | undefined> {
    const id = await this.state.storage.get<string>(userCodeIndexKey(hash));
    return id ? this.findClaimById(id) : undefined;
  }

  public async findByDeviceCodeHash(hash: string): Promise<ClaimRecord | undefined> {
    const id = await this.state.storage.get<string>(deviceCodeIndexKey(hash));
    return id ? this.findClaimById(id) : undefined;
  }

  public async compareAndSet(previous: ClaimRecord, next: ClaimRecord): Promise<boolean> {
    const stored = await this.state.storage.get<ClaimRecord>(claimKey(previous.id));
    if (
      !stored ||
      stored.version !== previous.version ||
      stored.userCodeHash !== previous.userCodeHash ||
      stored.deviceCodeHash !== previous.deviceCodeHash ||
      next.id !== previous.id ||
      next.userCodeHash !== previous.userCodeHash ||
      next.deviceCodeHash !== previous.deviceCodeHash ||
      next.version !== previous.version + 1
    ) {
      return false;
    }
    await this.state.storage.put(claimKey(next.id), copy(next));
    return true;
  }

  /** Removes expired claim hashes and state from this registration-owned object. */
  public async removeExpiredClaims(now: number): Promise<number> {
    const claimIds = await this.state.storage.get<readonly string[]>(activeClaimIdsKey);
    if (!claimIds || claimIds.length === 0) {
      await this.state.storage.deleteAlarm();
      return 0;
    }
    const claims = await Promise.all(claimIds.map((id) => this.findClaimById(id)));
    const expired = claims.filter(
      (claim): claim is ClaimRecord => claim !== undefined && claim.expiresAt <= now,
    );
    const remaining = claims.filter(
      (claim): claim is ClaimRecord => claim !== undefined && claim.expiresAt > now,
    );
    await Promise.all(
      expired.map((claim) =>
        this.state.storage.delete([
          claimKey(claim.id),
          userCodeIndexKey(claim.userCodeHash),
          deviceCodeIndexKey(claim.deviceCodeHash),
        ]),
      ),
    );
    if (remaining.length === 0) {
      await this.state.storage.delete(activeClaimIdsKey);
      await this.state.storage.delete(nextClaimExpiryKey);
      await this.state.storage.deleteAlarm();
      return expired.length;
    }
    const nextExpiry = Math.min(...remaining.map((claim) => claim.expiresAt));
    await this.state.storage.put({
      [activeClaimIdsKey]: remaining.map((claim) => claim.id),
      [nextClaimExpiryKey]: nextExpiry,
    });
    await this.state.storage.setAlarm(nextExpiry);
    return expired.length;
  }
}

/**
 * A D1 hash-only index lets the Worker find the registration-owned Durable
 * Object for normal device-code polling and completion requests. Claim state
 * remains authoritative in that Durable Object.
 */
export interface ClaimRouteRepository {
  createClaimRoute(claim: ClaimRecord): Promise<void>;
  findRegistrationByClaimId(claimId: string, now: number): Promise<string | undefined>;
  findRegistrationByUserCodeHash(hash: string, now: number): Promise<string | undefined>;
  findRegistrationByDeviceCodeHash(hash: string, now: number): Promise<string | undefined>;
}

interface ClaimRouteRow {
  identity_id: string;
}

export class D1ClaimRouteRepository implements ClaimRouteRepository {
  public constructor(private readonly database: D1Database) {}

  public async createClaimRoute(claim: ClaimRecord): Promise<void> {
    await this.database
      .prepare(
        `INSERT INTO claim_routes
          (claim_id, identity_id, user_code_hash, device_code_hash, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(claim.id, claim.identityId, claim.userCodeHash, claim.deviceCodeHash, claim.expiresAt)
      .run();
  }

  public findRegistrationByClaimId(claimId: string, now: number): Promise<string | undefined> {
    return this.findRegistration("claim_id", claimId, now);
  }

  public findRegistrationByUserCodeHash(hash: string, now: number): Promise<string | undefined> {
    return this.findRegistration("user_code_hash", hash, now);
  }

  public findRegistrationByDeviceCodeHash(hash: string, now: number): Promise<string | undefined> {
    return this.findRegistration("device_code_hash", hash, now);
  }

  public async removeExpiredRoutes(now: number): Promise<void> {
    await this.database.prepare("DELETE FROM claim_routes WHERE expires_at <= ?").bind(now).run();
  }

  private async findRegistration(
    column: "claim_id" | "user_code_hash" | "device_code_hash",
    value: string,
    now: number,
  ): Promise<string | undefined> {
    const row = await this.database
      .prepare(`SELECT identity_id FROM claim_routes WHERE ${column} = ? AND expires_at > ?`)
      .bind(value, now)
      .first<ClaimRouteRow>();
    return row?.identity_id;
  }
}

/** Uses Durable Object claim state while retaining D1 for the rest of the service. */
export class ClaimStateServiceStore implements ServiceStore {
  public constructor(
    private readonly base: ServiceStore,
    private readonly claims: ClaimRepository,
    private readonly claimRoutes?: ClaimRouteRepository,
  ) {}

  public createIdentity(identity: ServiceIdentity): Promise<void> {
    return this.base.createIdentity(identity);
  }

  public findIdentityById(id: string): Promise<ServiceIdentity | undefined> {
    return this.base.findIdentityById(id);
  }

  public findIdentityBySubject(subject: string): Promise<ServiceIdentity | undefined> {
    return this.base.findIdentityBySubject(subject);
  }

  public saveIdentity(identity: ServiceIdentity): Promise<void> {
    return this.base.saveIdentity(identity);
  }

  public createIdentityAttempt(attempt: IdentityAttempt): Promise<void> {
    return this.base.createIdentityAttempt(attempt);
  }

  public listIdentityAttempts(): Promise<readonly IdentityAttempt[]> {
    return this.base.listIdentityAttempts();
  }

  public async createClaim(claim: ClaimRecord): Promise<void> {
    await this.claimRoutes?.createClaimRoute(claim);
    await this.claims.createClaim(claim);
  }

  public findClaimById(id: string): Promise<ClaimRecord | undefined> {
    return this.claims.findClaimById(id);
  }

  public findByUserCodeHash(hash: string): Promise<ClaimRecord | undefined> {
    return this.claims.findByUserCodeHash(hash);
  }

  public findByDeviceCodeHash(hash: string): Promise<ClaimRecord | undefined> {
    return this.claims.findByDeviceCodeHash(hash);
  }

  public compareAndSet(previous: ClaimRecord, next: ClaimRecord): Promise<boolean> {
    return this.claims.compareAndSet(previous, next);
  }

  public createToken(token: IssuedToken): Promise<void> {
    return this.base.createToken(token);
  }

  public findTokenById(id: string): Promise<IssuedToken | undefined> {
    return this.base.findTokenById(id);
  }

  public revokeToken(id: string, at: number): Promise<boolean> {
    return this.base.revokeToken(id, at);
  }

  public markIfUnused(record: ReplayRecord, now: number): Promise<boolean> {
    return this.base.markIfUnused(record, now);
  }

  public createSubscriber(subscriber: EventSubscriber): Promise<void> {
    return this.base.createSubscriber(subscriber);
  }

  public listSubscribers(): Promise<readonly EventSubscriber[]> {
    return this.base.listSubscribers();
  }

  public createEvent(event: RevocationEvent): Promise<boolean> {
    return this.base.createEvent(event);
  }

  public findEventById(id: string): Promise<RevocationEvent | undefined> {
    return this.base.findEventById(id);
  }

  public findEventByTokenId(tokenId: string): Promise<RevocationEvent | undefined> {
    return this.base.findEventByTokenId(tokenId);
  }

  public createDelivery(delivery: EventDelivery): Promise<void> {
    return this.base.createDelivery(delivery);
  }

  public listDueDeliveries(now: number, limit: number): Promise<readonly EventDelivery[]> {
    return this.base.listDueDeliveries(now, limit);
  }

  public nextPendingDeliveryAt(): Promise<number | undefined> {
    return this.base.nextPendingDeliveryAt();
  }

  public findSubscriber(id: string): Promise<EventSubscriber | undefined> {
    return this.base.findSubscriber(id);
  }

  public saveDelivery(delivery: EventDelivery): Promise<void> {
    return this.base.saveDelivery(delivery);
  }
}

interface IdentityRow {
  id: string;
  identity_type: ServiceIdentity["type"];
  scopes_json: string;
  resource: string | null;
  client_id: string | null;
  subject: string | null;
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
}

interface IdentityAttemptRow {
  id: string;
  identity_type: IdentityAttempt["identityType"];
  client_id: string | null;
  subject: string | null;
  outcome: IdentityAttempt["outcome"];
  error_code: string | null;
  occurred_at: number;
}

interface ClaimRow {
  id: string;
  identity_id: string;
  user_code_hash: string;
  device_code_hash: string;
  status: ClaimRecord["status"];
  scopes_json: string;
  resource: string | null;
  created_at: number;
  expires_at: number;
  interval_seconds: number;
  last_poll_at: number | null;
  verification_attempts: number;
  user_code_used_at: number | null;
  grant_used_at: number | null;
  version: number;
}

interface TokenRow {
  id: string;
  identity_id: string;
  subject: string;
  scopes_json: string;
  resource: string;
  issued_at: number;
  expires_at: number;
  revoked_at: number | null;
}

interface SubscriberRow {
  id: string;
  url: string;
  created_at: number;
  disabled_at: number | null;
}

interface DeliveryRow {
  id: string;
  event_id: string;
  subscriber_id: string;
  status: EventDelivery["status"];
  attempts: number;
  next_attempt_at: number;
  last_attempt_at: number | null;
  receipt: string | null;
}

interface EventRow {
  id: string;
  token_id: string;
  subject: string;
  occurred_at: number;
}

function optionalString(value: string | null): string | undefined {
  return value ?? undefined;
}

function optionalNumber(value: number | null): number | undefined {
  return value ?? undefined;
}

function mapIdentity(row: IdentityRow): ServiceIdentity {
  return {
    id: row.id,
    type: row.identity_type,
    scopes: JSON.parse(row.scopes_json) as string[],
    resource: optionalString(row.resource),
    clientId: optionalString(row.client_id),
    subject: optionalString(row.subject),
    createdAt: row.created_at,
    expiresAt: optionalNumber(row.expires_at),
    revokedAt: optionalNumber(row.revoked_at),
  };
}

function mapIdentityAttempt(row: IdentityAttemptRow): IdentityAttempt {
  return {
    id: row.id,
    identityType: row.identity_type,
    clientId: optionalString(row.client_id),
    subject: optionalString(row.subject),
    outcome: row.outcome,
    errorCode: optionalString(row.error_code),
    occurredAt: row.occurred_at,
  };
}

function mapClaim(row: ClaimRow): ClaimRecord {
  return {
    id: row.id,
    identityId: row.identity_id,
    userCodeHash: row.user_code_hash,
    deviceCodeHash: row.device_code_hash,
    status: row.status,
    scopes: JSON.parse(row.scopes_json) as string[],
    resource: optionalString(row.resource),
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    intervalSeconds: row.interval_seconds,
    lastPollAt: optionalNumber(row.last_poll_at),
    verificationAttempts: row.verification_attempts,
    userCodeUsedAt: optionalNumber(row.user_code_used_at),
    grantUsedAt: optionalNumber(row.grant_used_at),
    version: row.version,
  };
}

function mapToken(row: TokenRow): IssuedToken {
  return {
    id: row.id,
    identityId: row.identity_id,
    subject: row.subject,
    scopes: JSON.parse(row.scopes_json) as string[],
    resource: row.resource,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    revokedAt: optionalNumber(row.revoked_at),
  };
}

function mapSubscriber(row: SubscriberRow): EventSubscriber {
  return {
    id: row.id,
    url: row.url,
    createdAt: row.created_at,
    disabledAt: optionalNumber(row.disabled_at),
  };
}

function mapDelivery(row: DeliveryRow): EventDelivery {
  return {
    id: row.id,
    eventId: row.event_id,
    subscriberId: row.subscriber_id,
    status: row.status,
    attempts: row.attempts,
    nextAttemptAt: row.next_attempt_at,
    lastAttemptAt: optionalNumber(row.last_attempt_at),
    receipt: optionalString(row.receipt),
  };
}

function changed(result: { meta?: { changes?: number } }): boolean {
  return (result.meta?.changes ?? 0) > 0;
}

/** A typed adapter for the SQL in migrations/0001_initial.sql. */
export class D1ServiceStore implements ServiceStore {
  public constructor(private readonly database: D1Database) {}

  public async createIdentity(identity: ServiceIdentity): Promise<void> {
    await this.database
      .prepare(
        `INSERT INTO agent_identities
          (id, identity_type, scopes_json, resource, client_id, subject, created_at, expires_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        identity.id,
        identity.type,
        JSON.stringify(identity.scopes),
        identity.resource ?? null,
        identity.clientId ?? null,
        identity.subject ?? null,
        identity.createdAt,
        identity.expiresAt ?? null,
        identity.revokedAt ?? null,
      )
      .run();
  }

  public async findIdentityById(id: string): Promise<ServiceIdentity | undefined> {
    const row = await this.database
      .prepare("SELECT * FROM agent_identities WHERE id = ?")
      .bind(id)
      .first<IdentityRow>();
    return row ? mapIdentity(row) : undefined;
  }

  public async findIdentityBySubject(subject: string): Promise<ServiceIdentity | undefined> {
    const row = await this.database
      .prepare("SELECT * FROM agent_identities WHERE subject = ? ORDER BY created_at DESC LIMIT 1")
      .bind(subject)
      .first<IdentityRow>();
    return row ? mapIdentity(row) : undefined;
  }

  public async saveIdentity(identity: ServiceIdentity): Promise<void> {
    await this.database
      .prepare(
        `UPDATE agent_identities
         SET scopes_json = ?, resource = ?, client_id = ?, subject = ?, expires_at = ?, revoked_at = ?
         WHERE id = ?`,
      )
      .bind(
        JSON.stringify(identity.scopes),
        identity.resource ?? null,
        identity.clientId ?? null,
        identity.subject ?? null,
        identity.expiresAt ?? null,
        identity.revokedAt ?? null,
        identity.id,
      )
      .run();
  }

  public async createIdentityAttempt(attempt: IdentityAttempt): Promise<void> {
    await this.database
      .prepare(
        `INSERT INTO identity_attempt_audit
          (id, identity_type, client_id, subject, outcome, error_code, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        attempt.id,
        attempt.identityType,
        attempt.clientId ?? null,
        attempt.subject ?? null,
        attempt.outcome,
        attempt.errorCode ?? null,
        attempt.occurredAt,
      )
      .run();
  }

  public async listIdentityAttempts(): Promise<readonly IdentityAttempt[]> {
    const rows = await this.database
      .prepare("SELECT * FROM identity_attempt_audit ORDER BY occurred_at ASC")
      .all<IdentityAttemptRow>();
    return rows.results.map(mapIdentityAttempt);
  }

  public async createClaim(claim: ClaimRecord): Promise<void> {
    await this.database
      .prepare(
        `INSERT INTO agent_claims
          (id, identity_id, user_code_hash, device_code_hash, status, scopes_json, resource, created_at,
           expires_at, interval_seconds, last_poll_at, verification_attempts, user_code_used_at, grant_used_at,
           version)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        claim.id,
        claim.identityId,
        claim.userCodeHash,
        claim.deviceCodeHash,
        claim.status,
        JSON.stringify(claim.scopes),
        claim.resource ?? null,
        claim.createdAt,
        claim.expiresAt,
        claim.intervalSeconds,
        claim.lastPollAt ?? null,
        claim.verificationAttempts,
        claim.userCodeUsedAt ?? null,
        claim.grantUsedAt ?? null,
        claim.version,
      )
      .run();
  }

  public async findClaimById(id: string): Promise<ClaimRecord | undefined> {
    const row = await this.database
      .prepare("SELECT * FROM agent_claims WHERE id = ?")
      .bind(id)
      .first<ClaimRow>();
    return row ? mapClaim(row) : undefined;
  }

  public async findByUserCodeHash(hash: string): Promise<ClaimRecord | undefined> {
    const row = await this.database
      .prepare("SELECT * FROM agent_claims WHERE user_code_hash = ?")
      .bind(hash)
      .first<ClaimRow>();
    return row ? mapClaim(row) : undefined;
  }

  public async findByDeviceCodeHash(hash: string): Promise<ClaimRecord | undefined> {
    const row = await this.database
      .prepare("SELECT * FROM agent_claims WHERE device_code_hash = ?")
      .bind(hash)
      .first<ClaimRow>();
    return row ? mapClaim(row) : undefined;
  }

  public async compareAndSet(previous: ClaimRecord, next: ClaimRecord): Promise<boolean> {
    const result = await this.database
      .prepare(
        `UPDATE agent_claims
         SET status = ?, scopes_json = ?, resource = ?, expires_at = ?, interval_seconds = ?, last_poll_at = ?,
             verification_attempts = ?, user_code_used_at = ?, grant_used_at = ?, version = ?
         WHERE id = ? AND version = ?`,
      )
      .bind(
        next.status,
        JSON.stringify(next.scopes),
        next.resource ?? null,
        next.expiresAt,
        next.intervalSeconds,
        next.lastPollAt ?? null,
        next.verificationAttempts,
        next.userCodeUsedAt ?? null,
        next.grantUsedAt ?? null,
        next.version,
        previous.id,
        previous.version,
      )
      .run();
    return changed(result);
  }

  public async createToken(token: IssuedToken): Promise<void> {
    await this.database
      .prepare(
        `INSERT INTO issued_tokens
          (id, identity_id, subject, scopes_json, resource, issued_at, expires_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        token.id,
        token.identityId,
        token.subject,
        JSON.stringify(token.scopes),
        token.resource,
        token.issuedAt,
        token.expiresAt,
        token.revokedAt ?? null,
      )
      .run();
  }

  public async findTokenById(id: string): Promise<IssuedToken | undefined> {
    const row = await this.database
      .prepare("SELECT * FROM issued_tokens WHERE id = ?")
      .bind(id)
      .first<TokenRow>();
    return row ? mapToken(row) : undefined;
  }

  public async revokeToken(id: string, at: number): Promise<boolean> {
    const result = await this.database
      .prepare("UPDATE issued_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
      .bind(at, id)
      .run();
    return changed(result);
  }

  public async markIfUnused(record: ReplayRecord, now: number): Promise<boolean> {
    await this.database
      .prepare("DELETE FROM assertion_replays WHERE expires_at <= ?")
      .bind(now)
      .run();
    const result = await this.database
      .prepare("INSERT OR IGNORE INTO assertion_replays (id, expires_at) VALUES (?, ?)")
      .bind(record.id, record.expiresAt)
      .run();
    return changed(result);
  }

  public async createSubscriber(subscriber: EventSubscriber): Promise<void> {
    await this.database
      .prepare(
        "INSERT INTO event_subscribers (id, url, created_at, disabled_at) VALUES (?, ?, ?, ?)",
      )
      .bind(subscriber.id, subscriber.url, subscriber.createdAt, subscriber.disabledAt ?? null)
      .run();
  }

  public async listSubscribers(): Promise<readonly EventSubscriber[]> {
    const rows = await this.database
      .prepare("SELECT * FROM event_subscribers WHERE disabled_at IS NULL ORDER BY created_at ASC")
      .all<SubscriberRow>();
    return rows.results.map(mapSubscriber);
  }

  public async createEvent(event: RevocationEvent): Promise<boolean> {
    const result = await this.database
      .prepare(
        "INSERT OR IGNORE INTO revocation_events (id, token_id, subject, occurred_at) VALUES (?, ?, ?, ?)",
      )
      .bind(event.id, event.tokenId, event.subject, event.occurredAt)
      .run();
    return changed(result);
  }

  public async findEventById(id: string): Promise<RevocationEvent | undefined> {
    const row = await this.database
      .prepare("SELECT * FROM revocation_events WHERE id = ?")
      .bind(id)
      .first<EventRow>();
    return row
      ? { id: row.id, tokenId: row.token_id, subject: row.subject, occurredAt: row.occurred_at }
      : undefined;
  }

  public async findEventByTokenId(tokenId: string): Promise<RevocationEvent | undefined> {
    const row = await this.database
      .prepare("SELECT * FROM revocation_events WHERE token_id = ?")
      .bind(tokenId)
      .first<EventRow>();
    return row
      ? { id: row.id, tokenId: row.token_id, subject: row.subject, occurredAt: row.occurred_at }
      : undefined;
  }

  public async createDelivery(delivery: EventDelivery): Promise<void> {
    await this.database
      .prepare(
        `INSERT INTO event_deliveries
          (id, event_id, subscriber_id, status, attempts, next_attempt_at, last_attempt_at, receipt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        delivery.id,
        delivery.eventId,
        delivery.subscriberId,
        delivery.status,
        delivery.attempts,
        delivery.nextAttemptAt,
        delivery.lastAttemptAt ?? null,
        delivery.receipt ?? null,
      )
      .run();
  }

  public async listDueDeliveries(now: number, limit: number): Promise<readonly EventDelivery[]> {
    const rows = await this.database
      .prepare(
        "SELECT * FROM event_deliveries WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at ASC LIMIT ?",
      )
      .bind(now, limit)
      .all<DeliveryRow>();
    return rows.results.map(mapDelivery);
  }

  public async nextPendingDeliveryAt(): Promise<number | undefined> {
    const row = await this.database
      .prepare(
        "SELECT next_attempt_at FROM event_deliveries WHERE status = 'pending' ORDER BY next_attempt_at ASC LIMIT 1",
      )
      .first<{ next_attempt_at: number }>();
    return row?.next_attempt_at;
  }

  public async findSubscriber(id: string): Promise<EventSubscriber | undefined> {
    const row = await this.database
      .prepare("SELECT * FROM event_subscribers WHERE id = ?")
      .bind(id)
      .first<SubscriberRow>();
    return row ? mapSubscriber(row) : undefined;
  }

  public async saveDelivery(delivery: EventDelivery): Promise<void> {
    await this.database
      .prepare(
        `UPDATE event_deliveries
         SET status = ?, attempts = ?, next_attempt_at = ?, last_attempt_at = ?, receipt = ?
         WHERE id = ?`,
      )
      .bind(
        delivery.status,
        delivery.attempts,
        delivery.nextAttemptAt,
        delivery.lastAttemptAt ?? null,
        delivery.receipt ?? null,
        delivery.id,
      )
      .run();
  }
}
