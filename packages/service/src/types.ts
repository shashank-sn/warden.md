export type IdentityType = "anonymous" | "service_auth" | "identity_assertion";

export type ClaimStatus = "pending" | "user_verified" | "approved" | "denied" | "expired";

export interface Clock {
  now(): number;
}

export const systemClock: Clock = {
  now: () => Date.now(),
};

export interface IdentifierGenerator {
  next(prefix: string): string;
}

export const randomIdentifierGenerator: IdentifierGenerator = {
  next: (prefix) => `${prefix}_${crypto.randomUUID()}`,
};

export interface ServiceIdentity {
  id: string;
  type: IdentityType;
  scopes: readonly string[];
  resource?: string;
  clientId?: string;
  subject?: string;
  createdAt: number;
  expiresAt?: number;
  revokedAt?: number;
}

export interface ClaimRecord {
  id: string;
  identityId: string;
  userCodeHash: string;
  deviceCodeHash: string;
  status: ClaimStatus;
  scopes: readonly string[];
  resource?: string;
  createdAt: number;
  expiresAt: number;
  intervalSeconds: number;
  lastPollAt?: number;
  verificationAttempts: number;
  userCodeUsedAt?: number;
  grantUsedAt?: number;
  version: number;
}

export interface IssuedToken {
  id: string;
  identityId: string;
  subject: string;
  scopes: readonly string[];
  resource: string;
  issuedAt: number;
  expiresAt: number;
  revokedAt?: number;
}

/** A privacy-safe record of a registration decision, never the assertion itself. */
export interface IdentityAttempt {
  id: string;
  identityType: IdentityType;
  clientId?: string;
  subject?: string;
  outcome: "accepted" | "rejected";
  errorCode?: string;
  occurredAt: number;
}

export interface RevocationEvent {
  id: string;
  tokenId: string;
  subject: string;
  occurredAt: number;
}

export interface EventSubscriber {
  id: string;
  url: string;
  createdAt: number;
  disabledAt?: number;
}

export interface EventDelivery {
  id: string;
  eventId: string;
  subscriberId: string;
  status: "pending" | "delivered" | "failed";
  attempts: number;
  nextAttemptAt: number;
  lastAttemptAt?: number;
  receipt?: string;
}

export interface ReplayRecord {
  id: string;
  expiresAt: number;
}

export interface IdentityRepository {
  createIdentity(identity: ServiceIdentity): Promise<void>;
  findIdentityById(id: string): Promise<ServiceIdentity | undefined>;
  findIdentityBySubject(subject: string): Promise<ServiceIdentity | undefined>;
  saveIdentity(identity: ServiceIdentity): Promise<void>;
}

export interface IdentityAttemptRepository {
  createIdentityAttempt(attempt: IdentityAttempt): Promise<void>;
  listIdentityAttempts(): Promise<readonly IdentityAttempt[]>;
}

export interface ClaimRepository {
  createClaim(claim: ClaimRecord): Promise<void>;
  findClaimById(id: string): Promise<ClaimRecord | undefined>;
  findByUserCodeHash(hash: string): Promise<ClaimRecord | undefined>;
  findByDeviceCodeHash(hash: string): Promise<ClaimRecord | undefined>;
  compareAndSet(previous: ClaimRecord, next: ClaimRecord): Promise<boolean>;
}

export interface TokenRepository {
  createToken(token: IssuedToken): Promise<void>;
  findTokenById(id: string): Promise<IssuedToken | undefined>;
  revokeToken(id: string, at: number): Promise<boolean>;
}

export interface ReplayRepository {
  markIfUnused(record: ReplayRecord, now: number): Promise<boolean>;
}

export interface EventRepository {
  createSubscriber(subscriber: EventSubscriber): Promise<void>;
  listSubscribers(): Promise<readonly EventSubscriber[]>;
  createEvent(event: RevocationEvent): Promise<boolean>;
  findEventById(id: string): Promise<RevocationEvent | undefined>;
  findEventByTokenId(tokenId: string): Promise<RevocationEvent | undefined>;
  createDelivery(delivery: EventDelivery): Promise<void>;
  listDueDeliveries(now: number, limit: number): Promise<readonly EventDelivery[]>;
  nextPendingDeliveryAt(): Promise<number | undefined>;
  findSubscriber(id: string): Promise<EventSubscriber | undefined>;
  saveDelivery(delivery: EventDelivery): Promise<void>;
}

export interface ServiceStore
  extends IdentityRepository,
    IdentityAttemptRepository,
    ClaimRepository,
    TokenRepository,
    ReplayRepository,
    EventRepository {}

export interface ServiceAuthResult {
  subject: string;
  clientId?: string;
  scopes?: readonly string[];
  resource?: string;
}

export interface ServiceAuthenticator {
  authenticate(token: string): Promise<ServiceAuthResult | undefined>;
}

export interface RateLimiter {
  take(key: string, limit: number, windowSeconds: number, now: number): Promise<boolean>;
}

export interface SigningKey {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: PublicJwk;
}

export interface PublicJwk extends JsonWebKey {
  kid?: string;
  use?: string;
  alg?: string;
}

export interface VerificationKeyResolver {
  resolve(issuer: string, kid: string): Promise<CryptoKey | undefined>;
}

export interface ClaimOptions {
  expiresInSeconds: number;
  initialIntervalSeconds: number;
  maxVerificationAttempts: number;
  verificationWindowSeconds: number;
  maxStartsPerWindow: number;
  startWindowSeconds: number;
}

export interface TokenOptions {
  expiresInSeconds: number;
}

export interface AnonymousOptions {
  expiresInSeconds: number;
  maxRegistrationsPerWindow: number;
  registrationWindowSeconds: number;
}

export interface ServiceOptions {
  issuer: string;
  supportedScopes: readonly string[];
  defaultResource: string;
  /** Every protected-resource audience this service may issue or accept. */
  protectedResources?: readonly string[];
  signingKey: SigningKey;
  /** Public verification keys retained while tokens from a previous active key can exist. */
  retiredSigningKeys?: readonly PublicJwk[];
  verificationKeys: VerificationKeyResolver;
  trustedAssertionIssuer: string;
  claim?: Partial<ClaimOptions>;
  token?: Partial<TokenOptions>;
  anonymous?: Partial<AnonymousOptions>;
}

export interface RegistrationRequest {
  identityType: IdentityType;
  scope?: string;
  resource?: string;
  clientId?: string;
  serviceToken?: string;
  assertion?: string;
  rateLimitKey: string;
}

export interface RegistrationResult {
  identity: ServiceIdentity;
}

export interface StartClaimRequest {
  identityId: string;
  scope?: string;
  resource?: string;
  rateLimitKey: string;
}

export interface StartedClaim {
  claim: ClaimRecord;
  deviceCode: string;
  userCode: string;
}

export interface PollResult {
  status: "pending" | "approved";
  claim?: ClaimRecord;
}

export interface TokenExchangeRequest {
  grantType: string;
  assertion?: string;
  claimGrant?: string;
  clientId?: string;
  scope?: string;
  resource?: string;
}

export interface TokenExchangeResult {
  accessToken: string;
  tokenType: "Bearer";
  expiresIn: number;
  scope: string;
  resource: string;
}

export interface SecurityEventClaims {
  iss: string;
  aud: string;
  sub: string;
  jti: string;
  iat: number;
  exp: number;
  events: Readonly<Record<string, Readonly<Record<string, never>>>>;
  sid?: string;
  [claim: string]: unknown;
}

export type DeliveryFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface D1Result {
  success: boolean;
  meta?: {
    changes?: number;
  };
}

export interface D1PreparedStatement {
  bind(...values: readonly unknown[]): D1PreparedStatement;
  first<T>(): Promise<T | null>;
  all<T>(): Promise<{ results: readonly T[] }>;
  run(): Promise<D1Result>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
}

/** The storage surface used by the claim ceremony Durable Object. */
export interface DurableObjectStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  put(entries: Readonly<Record<string, unknown>>): Promise<void>;
  delete(key: string | readonly string[]): Promise<unknown>;
  setAlarm(scheduledTime: number | Date): Promise<void>;
  deleteAlarm(): Promise<void>;
}

/** A structural subset of Cloudflare's DurableObjectState for local tests. */
export interface DurableObjectState {
  storage: DurableObjectStorage;
  blockConcurrencyWhile?<T>(callback: () => Promise<T>): Promise<T>;
}

export interface DurableObjectId {
  readonly name?: string;
}

export interface DurableObjectStub {
  fetch(request: Request): Promise<Response>;
}

export interface DurableObjectNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): DurableObjectStub;
}
