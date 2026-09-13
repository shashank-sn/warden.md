import { randomId } from "./encoding.js";
import type { AuditEvent, EvidenceRecord, Grant, RevocationDelivery } from "./types.js";

type GrantMutation<T> = (grant: Grant) => Promise<T> | T;

export interface ExchangeCreation {
  grant: Grant;
  created: boolean;
  subjectTokenReserved: boolean;
}

/**
 * Plain data retained by the Durable Object coordinator between isolates.
 * Locks deliberately stay in memory: a Durable Object serializes requests and
 * recreates this store from a completed transition only.
 */
export interface BrokerStoreSnapshot {
  version: 1;
  grants: readonly Grant[];
  audits: readonly (readonly [string, readonly AuditEvent[]])[];
  evidence: readonly EvidenceRecord[];
  idempotency: readonly (readonly [string, string])[];
  subjectTokenGrants: readonly (readonly [string, string])[];
  deliveries: readonly (readonly [string, readonly RevocationDelivery[]])[];
}

function copyGrant(grant: Grant): Grant {
  return {
    ...grant,
    requestedScope: [...grant.requestedScope],
    grantedScope: [...grant.grantedScope],
  };
}

function copyEvidence(evidence: EvidenceRecord): EvidenceRecord {
  return {
    ...evidence,
    timeline: evidence.timeline.map((event) => ({
      ...event,
      detail: event.detail ? { ...event.detail } : undefined,
    })),
    revocationDeliveries: evidence.revocationDeliveries.map((delivery) => ({ ...delivery })),
  };
}

function copyAudit(event: AuditEvent): AuditEvent {
  return { ...event, detail: event.detail ? { ...event.detail } : undefined };
}

export class InMemoryBrokerStore {
  private readonly grants = new Map<string, Grant>();
  private readonly audits = new Map<string, AuditEvent[]>();
  private readonly evidence = new Map<string, EvidenceRecord>();
  private readonly idempotency = new Map<string, string>();
  private readonly subjectTokenGrant = new Map<string, string>();
  private readonly deliveries = new Map<string, RevocationDelivery[]>();
  private readonly locks = new Map<string, Promise<void>>();

  public static fromSnapshot(snapshot: BrokerStoreSnapshot | undefined): InMemoryBrokerStore {
    const store = new InMemoryBrokerStore();
    if (snapshot) {
      store.restore(snapshot);
    }
    return store;
  }

  public snapshot(): BrokerStoreSnapshot {
    return {
      version: 1,
      grants: this.listGrants(),
      audits: [...this.audits.entries()].map(([grantId, events]) => [
        grantId,
        events.map(copyAudit),
      ]),
      evidence: [...this.evidence.values()].map(copyEvidence),
      idempotency: [...this.idempotency.entries()],
      subjectTokenGrants: [...this.subjectTokenGrant.entries()],
      deliveries: [...this.deliveries.entries()].map(([grantId, records]) => [
        grantId,
        records.map((record) => ({ ...record })),
      ]),
    };
  }

  public restore(snapshot: BrokerStoreSnapshot): void {
    if (snapshot.version !== 1) {
      throw new Error("unsupported broker store snapshot");
    }
    this.grants.clear();
    this.audits.clear();
    this.evidence.clear();
    this.idempotency.clear();
    this.subjectTokenGrant.clear();
    this.deliveries.clear();

    for (const grant of snapshot.grants) {
      this.grants.set(grant.id, copyGrant(grant));
    }
    for (const [grantId, events] of snapshot.audits) {
      this.audits.set(grantId, events.map(copyAudit));
    }
    for (const evidence of snapshot.evidence) {
      this.evidence.set(evidence.grantId, copyEvidence(evidence));
    }
    for (const [key, grantId] of snapshot.idempotency) {
      this.idempotency.set(key, grantId);
    }
    for (const [subjectTokenId, grantId] of snapshot.subjectTokenGrants) {
      this.subjectTokenGrant.set(subjectTokenId, grantId);
    }
    for (const [grantId, records] of snapshot.deliveries) {
      this.deliveries.set(
        grantId,
        records.map((record) => ({ ...record })),
      );
    }
  }

  public async createExchangeGrant(
    grant: Grant,
    idempotencyKey: string | undefined,
    reserveSubjectToken: boolean,
  ): Promise<ExchangeCreation> {
    return this.withLock("exchange", () => {
      if (idempotencyKey) {
        const existingId = this.idempotency.get(idempotencyKey);
        const existing = existingId ? this.grants.get(existingId) : undefined;
        if (existing) {
          return { grant: copyGrant(existing), created: false, subjectTokenReserved: true };
        }
      }
      if (reserveSubjectToken) {
        const existing = this.subjectTokenGrant.get(grant.subjectTokenId);
        if (existing && existing !== grant.id) {
          return { grant: copyGrant(grant), created: false, subjectTokenReserved: false };
        }
        this.subjectTokenGrant.set(grant.subjectTokenId, grant.id);
      }
      this.grants.set(grant.id, copyGrant(grant));
      if (idempotencyKey) {
        this.idempotency.set(idempotencyKey, grant.id);
      }
      return { grant: copyGrant(grant), created: true, subjectTokenReserved: true };
    });
  }

  public getGrant(id: string): Grant | undefined {
    const grant = this.grants.get(id);
    return grant ? copyGrant(grant) : undefined;
  }

  public findByIdempotencyKey(key: string): Grant | undefined {
    const grantId = this.idempotency.get(key);
    return grantId ? this.getGrant(grantId) : undefined;
  }

  public listGrants(): Grant[] {
    return [...this.grants.values()].map(copyGrant);
  }

  public async mutateGrant<T>(grantId: string, mutation: GrantMutation<T>): Promise<T | undefined> {
    return this.withLock(`grant:${grantId}`, async () => {
      const grant = this.grants.get(grantId);
      if (!grant) {
        return undefined;
      }
      const result = await mutation(grant);
      this.grants.set(grantId, grant);
      return result;
    });
  }

  public async reserveSubjectToken(subjectTokenId: string, grantId: string): Promise<boolean> {
    return this.withLock(`subject:${subjectTokenId}`, () => {
      const existing = this.subjectTokenGrant.get(subjectTokenId);
      if (existing && existing !== grantId) {
        return false;
      }
      this.subjectTokenGrant.set(subjectTokenId, grantId);
      return true;
    });
  }

  public appendAudit(event: AuditEvent): void {
    const events = this.audits.get(event.grantId) ?? [];
    events.push(copyAudit(event));
    this.audits.set(event.grantId, events);
  }

  public auditFor(grantId: string): AuditEvent[] {
    return (this.audits.get(grantId) ?? []).map(copyAudit);
  }

  public setEvidence(record: EvidenceRecord): void {
    this.evidence.set(record.grantId, copyEvidence(record));
  }

  public evidenceFor(grantId: string): EvidenceRecord | undefined {
    const record = this.evidence.get(grantId);
    return record ? copyEvidence(record) : undefined;
  }

  public addDeliveries(grantId: string, targets: readonly string[]): RevocationDelivery[] {
    const records = targets.map((target) => ({
      id: randomId("delivery"),
      grantId,
      target,
      status: "pending" as const,
      attempts: 0,
    }));
    this.deliveries.set(grantId, records);
    return records.map((record) => ({ ...record }));
  }

  public deliveriesFor(grantId: string): RevocationDelivery[] {
    return (this.deliveries.get(grantId) ?? []).map((record) => ({ ...record }));
  }

  public updateDelivery(
    grantId: string,
    deliveryId: string,
    patch: Partial<RevocationDelivery>,
  ): void {
    const records = this.deliveries.get(grantId) ?? [];
    const record = records.find((candidate) => candidate.id === deliveryId);
    if (record) {
      Object.assign(record, patch);
    }
    this.refreshEvidenceDeliveries(grantId);
  }

  public refreshEvidenceDeliveries(grantId: string): void {
    const record = this.evidence.get(grantId);
    if (record) {
      record.revocationDeliveries = this.deliveriesFor(grantId);
      this.evidence.set(grantId, record);
    }
  }

  private async withLock<T>(key: string, operation: () => Promise<T> | T): Promise<T> {
    const previous = this.locks.get(key) ?? Promise.resolve();
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const lock = previous.then(() => gate);
    this.locks.set(key, lock);
    await previous;
    try {
      return await operation();
    } finally {
      release?.();
      if (this.locks.get(key) === lock) {
        this.locks.delete(key);
      }
    }
  }
}
