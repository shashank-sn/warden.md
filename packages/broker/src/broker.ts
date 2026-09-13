import { RejectingAuthorityResolver } from "./authority.js";
import {
  type CapabilitySigner,
  Es256CapabilitySigner,
  type JsonWebKeySet,
  verifyDpopProof,
} from "./crypto.js";
import { randomId } from "./encoding.js";
import { BrokerError } from "./errors.js";
import { PolicyEngine } from "./policy.js";
import { InMemoryBrokerStore } from "./store.js";
import type {
  AuditEvent,
  AuthorityResolver,
  CapabilityClaims,
  Clock,
  CompletionSource,
  ConsumeResult,
  DpopProof,
  EvidenceRecord,
  ExchangeResult,
  Grant,
  GrantProposal,
  PolicyDocument,
  RevocationDelivery,
} from "./types.js";
import { systemClock } from "./types.js";

export interface ConsumeInput {
  credential: string;
  proof: DpopProof;
  audience: string;
}

export interface RevocationTransport {
  deliver(input: {
    grantId: string;
    target: string;
    eventId: string;
  }): Promise<{ receipt: string }>;
}

/** Replay entries are durable coordinator state, not client-controlled input. */
export interface DpopReplayEntry {
  jti: string;
  expiresAt: number;
}

export interface BrokerOptions {
  clock?: Clock;
  signer?: CapabilitySigner;
  store?: InMemoryBrokerStore;
  policy?: PolicyDocument;
  authorityResolver?: AuthorityResolver;
  issuer?: string;
  revocationTargets?: readonly string[];
  revocationTransport?: RevocationTransport;
  retentionMs?: number;
  maxTtlSeconds?: number;
  dpopReplayEntries?: readonly DpopReplayEntry[];
}

const defaultPolicy: PolicyDocument = {
  version: 1,
  default: "require-approval",
  rules: [],
};

const defaultTtlSeconds = 300;
const defaultRetentionMs = 30 * 24 * 60 * 60 * 1000;

export class Broker {
  public readonly store: InMemoryBrokerStore;
  private readonly clock: Clock;
  private readonly signer: CapabilitySigner;
  private readonly policy: PolicyEngine;
  private readonly authorityResolver: AuthorityResolver;
  private readonly issuer: string;
  private readonly revocationTargets: readonly string[];
  private readonly revocationTransport?: RevocationTransport;
  private readonly retentionMs: number;
  private readonly maxTtlSeconds: number;
  private readonly usedDpopJtis: Map<string, number>;

  private constructor(
    options: Required<Omit<BrokerOptions, "revocationTransport">> &
      Pick<BrokerOptions, "revocationTransport">,
  ) {
    this.clock = options.clock;
    this.signer = options.signer;
    this.store = options.store;
    this.policy = new PolicyEngine(options.policy, options.clock);
    this.authorityResolver = options.authorityResolver;
    this.issuer = options.issuer;
    this.revocationTargets = options.revocationTargets;
    this.revocationTransport = options.revocationTransport;
    this.retentionMs = options.retentionMs;
    this.maxTtlSeconds = options.maxTtlSeconds;
    this.usedDpopJtis = new Map(
      options.dpopReplayEntries
        .filter(
          (entry) =>
            entry.jti && Number.isFinite(entry.expiresAt) && entry.expiresAt > this.clock.now(),
        )
        .map((entry): [string, number] => [entry.jti, entry.expiresAt]),
    );
  }

  public static async create(options: BrokerOptions = {}): Promise<Broker> {
    const maxTtlSeconds = options.maxTtlSeconds ?? defaultTtlSeconds;
    if (!Number.isSafeInteger(maxTtlSeconds) || maxTtlSeconds <= 0) {
      throw new BrokerError("invalid_request");
    }
    return new Broker({
      clock: options.clock ?? systemClock,
      signer: options.signer ?? (await Es256CapabilitySigner.create()),
      store: options.store ?? new InMemoryBrokerStore(),
      policy: options.policy ?? defaultPolicy,
      authorityResolver: options.authorityResolver ?? new RejectingAuthorityResolver(),
      issuer: options.issuer ?? "https://warden.local",
      revocationTargets: options.revocationTargets ?? [],
      revocationTransport: options.revocationTransport,
      retentionMs: options.retentionMs ?? defaultRetentionMs,
      maxTtlSeconds,
      dpopReplayEntries: options.dpopReplayEntries ?? [],
    });
  }

  public async exchange(proposal: GrantProposal): Promise<ExchangeResult> {
    this.assertProposal(proposal);
    const idempotencyKey = proposal.idempotencyKey
      ? `${proposal.agentId}:${proposal.idempotencyKey}`
      : undefined;

    const authority = await this.authorityResolver.resolve({
      agentId: proposal.agentId,
      subjectId: proposal.subjectId,
      subjectTokenId: proposal.subjectTokenId,
    });
    if (!authority) {
      throw new BrokerError("invalid_credential");
    }
    if (!authority.resources.includes(proposal.resource)) {
      throw new BrokerError("wrong_audience");
    }
    const allowedScope = proposal.requestedScope.filter(
      (scope) =>
        authority.registrationScopes.includes(scope) && authority.subjectScopes.includes(scope),
    );
    if (allowedScope.length !== proposal.requestedScope.length) {
      throw new BrokerError("scope_not_authorized");
    }

    const decision = this.policy.decide(proposal).decision;
    const now = this.clock.now();
    const grant: Grant & { idempotencyKey?: string } = {
      id: randomId("grant"),
      status: decision === "block" ? "denied" : decision === "allow" ? "approved" : "proposed",
      agentId: proposal.agentId,
      subjectId: proposal.subjectId,
      subjectTokenId: proposal.subjectTokenId,
      action: proposal.action,
      audience: proposal.resource,
      requestedScope: [...proposal.requestedScope],
      grantedScope: allowedScope,
      dpopThumbprint: proposal.dpopThumbprint,
      policyDecision: decision,
      approvalReference: decision === "require-approval" ? randomId("approval") : undefined,
      approver: decision === "allow" ? "policy" : undefined,
      issuedAt: decision === "allow" ? now : undefined,
      expiresAt: now + this.requestedTtlSeconds(proposal) * 1000,
      idempotencyKey,
    };
    const created = await this.store.createExchangeGrant(
      grant,
      idempotencyKey,
      decision === "allow",
    );
    if (!created.subjectTokenReserved) {
      throw new BrokerError("token_already_exchanged");
    }
    if (!created.created) {
      return this.asExchangeResult(created.grant);
    }
    this.audit(grant.id, "grant_proposed", { policy: decision });

    if (decision === "block") {
      this.audit(grant.id, "grant_denied", { policy: decision });
      return { grant };
    }
    if (decision === "allow") {
      this.audit(grant.id, "grant_approved", { policy: decision });
      return { grant, credential: await this.mint(grant) };
    }
    return { grant, approvalReference: grant.approvalReference };
  }

  public async approve(grantId: string, approver: string): Promise<ExchangeResult> {
    const result = await this.store.mutateGrant(grantId, async (grant) => {
      this.assertNotExpired(grant);
      if (grant.status === "denied") {
        throw new BrokerError("policy_blocked");
      }
      if (grant.status !== "proposed") {
        throw new BrokerError("grant_not_approved");
      }
      const reserved = await this.store.reserveSubjectToken(grant.subjectTokenId, grant.id);
      if (!reserved) {
        throw new BrokerError("token_already_exchanged");
      }
      grant.status = "approved";
      grant.approver = approver;
      grant.issuedAt = this.clock.now();
      this.audit(grant.id, "grant_approved", { approver: "approved" });
      return { grant: { ...grant }, credential: await this.mint(grant) };
    });
    if (!result) {
      throw new BrokerError("grant_not_found");
    }
    return result;
  }

  public async consume(input: ConsumeInput): Promise<ConsumeResult> {
    const claims = await this.signer.verify(input.credential, this.clock.now(), {
      allowExpired: true,
    });
    const result = await this.store.mutateGrant(claims.grantId, async (grant) => {
      this.assertNotExpired(grant);
      if (input.audience !== grant.audience || claims.aud !== grant.audience) {
        throw new BrokerError(
          input.audience !== grant.audience ? "wrong_audience" : "action_not_authorized",
        );
      }
      let action: string;
      try {
        const target = new URL(input.proof.url);
        if (target.origin !== new URL(grant.audience).origin) {
          throw new BrokerError("wrong_audience");
        }
        action = `${input.proof.method.toUpperCase()} ${target.pathname}${target.search}`;
      } catch (error) {
        if (error instanceof BrokerError) {
          throw error;
        }
        throw new BrokerError("dpop_proof_invalid");
      }
      if (action !== grant.action || claims.action !== grant.action) {
        throw new BrokerError("action_not_authorized");
      }
      if (grant.status === "consumed") {
        throw new BrokerError("grant_already_consumed");
      }
      if (grant.status === "revoked") {
        throw new BrokerError("grant_revoked");
      }
      if (grant.status !== "approved") {
        throw new BrokerError("grant_not_approved");
      }
      await verifyDpopProof(input.proof, grant.dpopThumbprint, this.clock.now(), this.usedDpopJtis);
      grant.status = "consumed";
      grant.consumedAt = this.clock.now();
      this.audit(grant.id, "grant_consumed");
      return { grant: { ...grant } };
    });
    if (!result) {
      throw new BrokerError("grant_not_found");
    }
    return result;
  }

  public async complete(
    grantId: string,
    source: CompletionSource = "agent",
  ): Promise<EvidenceRecord> {
    return this.finalize(grantId, source, "revoked");
  }

  public async completeAuthenticated(
    grantId: string,
    input: Pick<ConsumeInput, "credential" | "proof">,
  ): Promise<EvidenceRecord> {
    const claims = await this.signer.verify(input.credential, this.clock.now());
    if (claims.grantId !== grantId) {
      throw new BrokerError("invalid_credential");
    }
    const grant = this.store.getGrant(grantId);
    if (!grant) {
      throw new BrokerError("grant_not_found");
    }
    if (claims.aud !== grant.audience) {
      throw new BrokerError("wrong_audience");
    }
    if (
      claims.sub !== grant.subjectId ||
      claims.action !== grant.action ||
      claims.cnf.jkt !== grant.dpopThumbprint ||
      !sameScope(claims.scope, grant.grantedScope)
    ) {
      throw new BrokerError("invalid_credential");
    }
    if (input.proof.method.toUpperCase() !== "POST") {
      throw new BrokerError("dpop_proof_invalid");
    }
    await verifyDpopProof(input.proof, grant.dpopThumbprint, this.clock.now(), this.usedDpopJtis);
    return this.complete(grantId, "agent");
  }

  public async revoke(
    grantId: string,
    source: CompletionSource = "operator",
  ): Promise<EvidenceRecord> {
    return this.finalize(grantId, source, "revoked");
  }

  public async expireDue(): Promise<EvidenceRecord[]> {
    const expired: EvidenceRecord[] = [];
    for (const grant of this.store.listGrants()) {
      if (
        ["proposed", "approved", "consumed"].includes(grant.status) &&
        grant.expiresAt <= this.clock.now()
      ) {
        expired.push(await this.expire(grant.id));
      }
    }
    return expired;
  }

  public async expire(grantId: string): Promise<EvidenceRecord> {
    return this.finalize(grantId, "ttl", "expired");
  }

  public async retryRevocations(): Promise<void> {
    for (const grant of this.store.listGrants()) {
      const deliveries = this.store
        .deliveriesFor(grant.id)
        .filter(
          (delivery) =>
            delivery.status !== "delivered" &&
            (delivery.nextAttemptAt === undefined || delivery.nextAttemptAt <= this.clock.now()),
        );
      for (const delivery of deliveries) {
        await this.deliver(grant.id, delivery);
      }
    }
  }

  public async getEvidence(grantId: string): Promise<EvidenceRecord | undefined> {
    return this.store.evidenceFor(grantId);
  }

  /** Public verification material only; the deployment signing key remains broker-local. */
  public async jwks(): Promise<JsonWebKeySet> {
    return { keys: [await this.signer.publicJwk()] };
  }

  public dpopReplayEntries(): readonly DpopReplayEntry[] {
    const now = this.clock.now();
    const active: DpopReplayEntry[] = [];
    for (const [jti, expiresAt] of this.usedDpopJtis) {
      if (expiresAt <= now) {
        this.usedDpopJtis.delete(jti);
      } else {
        active.push({ jti, expiresAt });
      }
    }
    return active;
  }

  private async finalize(
    grantId: string,
    source: CompletionSource,
    finalStatus: "revoked" | "expired",
  ): Promise<EvidenceRecord> {
    const prepared = await this.store.mutateGrant(grantId, (grant) => {
      const existing = this.store.evidenceFor(grant.id);
      if (existing) {
        return existing;
      }
      if (grant.status === "denied") {
        throw new BrokerError("grant_not_approved");
      }
      grant.status = finalStatus;
      grant.completedAt = this.clock.now();
      grant.completionSource = source;
      const eventType =
        finalStatus === "expired"
          ? "grant_expired"
          : source === "agent"
            ? "grant_completed"
            : "grant_revoked";
      this.audit(grant.id, eventType, { source });
      const deliveries = this.store.addDeliveries(grant.id, this.revocationTargets);
      const evidence: EvidenceRecord = {
        id: randomId("evidence"),
        grantId: grant.id,
        createdAt: this.clock.now(),
        timeline: this.store.auditFor(grant.id),
        approver: grant.approver,
        completionSource: source,
        revocationDeliveries: deliveries,
        retentionUntil: this.clock.now() + this.retentionMs,
      };
      grant.evidenceId = evidence.id;
      this.store.setEvidence(evidence);
      return evidence;
    });
    if (!prepared) {
      throw new BrokerError("grant_not_found");
    }
    for (const delivery of this.store.deliveriesFor(grantId)) {
      if (delivery.status !== "delivered") {
        await this.deliver(grantId, delivery);
      }
    }
    return this.store.evidenceFor(grantId) ?? prepared;
  }

  private async deliver(grantId: string, delivery: RevocationDelivery): Promise<void> {
    const now = this.clock.now();
    const attempts = delivery.attempts + 1;
    if (!this.revocationTransport) {
      this.store.updateDelivery(grantId, delivery.id, {
        status: "failed",
        attempts,
        lastAttemptAt: now,
        nextAttemptAt: now + Math.min(2 ** attempts * 1000, 60_000),
      });
      this.audit(grantId, "revocation_delivery", { delivered: false, attempts });
      return;
    }
    try {
      const response = await this.revocationTransport.deliver({
        grantId,
        target: delivery.target,
        eventId: delivery.id,
      });
      this.store.updateDelivery(grantId, delivery.id, {
        status: "delivered",
        attempts,
        lastAttemptAt: now,
        receipt: response.receipt,
      });
      this.audit(grantId, "revocation_delivery", { delivered: true, attempts });
    } catch {
      this.store.updateDelivery(grantId, delivery.id, {
        status: "failed",
        attempts,
        lastAttemptAt: now,
        nextAttemptAt: now + Math.min(2 ** attempts * 1000, 60_000),
      });
      this.audit(grantId, "revocation_delivery", { delivered: false, attempts });
    }
  }

  private async mint(grant: Grant): Promise<string> {
    const issuedAt = Math.floor((grant.issuedAt ?? this.clock.now()) / 1000);
    const claims: CapabilityClaims = {
      iss: this.issuer,
      jti: randomId("credential"),
      grantId: grant.id,
      sub: grant.subjectId,
      aud: grant.audience,
      action: grant.action,
      scope: grant.grantedScope,
      cnf: { jkt: grant.dpopThumbprint },
      use: 1,
      iat: issuedAt,
      exp: Math.floor(grant.expiresAt / 1000),
    };
    return this.signer.sign(claims);
  }

  private asExchangeResult(grant: Grant): ExchangeResult {
    return {
      grant,
      approvalReference: grant.approvalReference,
    };
  }

  private assertProposal(proposal: GrantProposal): void {
    if (
      !proposal?.agentId ||
      !proposal.subjectId ||
      !proposal.subjectTokenId ||
      !proposal.resource ||
      !proposal.action ||
      !proposal.dpopThumbprint ||
      !Array.isArray(proposal.requestedScope) ||
      proposal.requestedScope.length === 0 ||
      proposal.requestedScope.some((scope) => !scope || typeof scope !== "string")
    ) {
      throw new BrokerError("invalid_request");
    }
    if (!/^([A-Z]+) \/[^\s]*$/u.test(proposal.action)) {
      throw new BrokerError("invalid_request");
    }
    try {
      const resource = new URL(proposal.resource);
      if (
        resource.protocol !== "https:" ||
        resource.pathname !== "/" ||
        resource.search ||
        resource.hash
      ) {
        throw new BrokerError("invalid_request");
      }
    } catch (error) {
      if (error instanceof BrokerError) {
        throw error;
      }
      throw new BrokerError("invalid_request");
    }
  }

  private requestedTtlSeconds(proposal: GrantProposal): number {
    const ttl = proposal.expiresInSeconds ?? this.maxTtlSeconds;
    if (!Number.isSafeInteger(ttl) || ttl <= 0 || ttl > this.maxTtlSeconds) {
      throw new BrokerError("invalid_request");
    }
    return ttl;
  }

  private assertNotExpired(grant: Grant): void {
    if (grant.status === "expired" || grant.expiresAt <= this.clock.now()) {
      throw new BrokerError("grant_expired");
    }
  }

  private audit(grantId: string, type: AuditEvent["type"], detail?: AuditEvent["detail"]): void {
    this.store.appendAudit({
      id: randomId("audit"),
      grantId,
      type,
      at: this.clock.now(),
      detail,
    });
  }
}

function sameScope(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  const expected = new Set(right);
  return left.every((scope) => expected.has(scope));
}
