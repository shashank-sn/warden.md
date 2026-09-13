export type GrantStatus = "proposed" | "approved" | "consumed" | "revoked" | "expired" | "denied";

export type PolicyDecision = "allow" | "require-approval" | "block";

export interface GrantProposal {
  agentId: string;
  subjectId: string;
  subjectTokenId: string;
  resource: string;
  action: string;
  requestedScope: readonly string[];
  dpopThumbprint: string;
  expiresInSeconds?: number;
  idempotencyKey?: string;
}

export interface VerifiedAuthority {
  agentId: string;
  subjectId: string;
  subjectTokenId: string;
  registrationScopes: readonly string[];
  subjectScopes: readonly string[];
  resources: readonly string[];
}

export interface AuthorityResolver {
  resolve(
    input: Pick<GrantProposal, "agentId" | "subjectId" | "subjectTokenId">,
  ): Promise<VerifiedAuthority | undefined>;
}

export interface Grant {
  id: string;
  status: GrantStatus;
  agentId: string;
  subjectId: string;
  subjectTokenId: string;
  action: string;
  audience: string;
  requestedScope: readonly string[];
  grantedScope: readonly string[];
  dpopThumbprint: string;
  policyDecision: PolicyDecision;
  approver?: string;
  approvalReference?: string;
  issuedAt?: number;
  expiresAt: number;
  consumedAt?: number;
  completedAt?: number;
  completionSource?: CompletionSource;
  evidenceId?: string;
}

export type CompletionSource = "agent" | "resource" | "ttl" | "operator";

export interface CapabilityClaims {
  iss: string;
  jti: string;
  grantId: string;
  sub: string;
  aud: string;
  action: string;
  scope: readonly string[];
  cnf: {
    jkt: string;
  };
  use: 1;
  iat: number;
  exp: number;
}

export interface AuditEvent {
  id: string;
  grantId: string;
  type:
    | "grant_proposed"
    | "grant_approved"
    | "grant_denied"
    | "grant_consumed"
    | "grant_completed"
    | "grant_expired"
    | "grant_revoked"
    | "revocation_delivery";
  at: number;
  actor?: string;
  detail?: Readonly<Record<string, string | number | boolean>>;
}

export interface EvidenceRecord {
  id: string;
  grantId: string;
  createdAt: number;
  timeline: readonly AuditEvent[];
  approver?: string;
  completionSource: CompletionSource;
  revocationDeliveries: readonly RevocationDelivery[];
  retentionUntil: number;
}

export interface RevocationDelivery {
  id: string;
  grantId: string;
  target: string;
  status: "pending" | "delivered" | "failed";
  attempts: number;
  lastAttemptAt?: number;
  nextAttemptAt?: number;
  receipt?: string;
}

export interface PolicyRule {
  id: string;
  decision: PolicyDecision;
  match?: {
    agentId?: string;
    resource?: string;
    action?: string;
    scope?: readonly string[];
    timeWindow?: {
      startHourInclusive: number;
      endHourExclusive: number;
    };
  };
}

export interface PolicyDocument {
  version: 1;
  default: PolicyDecision;
  rules: readonly PolicyRule[];
}

export interface DpopProof {
  token: string;
  method: string;
  url: string;
}

export interface ExchangeResult {
  grant: Grant;
  approvalReference?: string;
  credential?: string;
}

export interface ConsumeResult {
  grant: Grant;
  evidence?: EvidenceRecord;
}

export interface Clock {
  now(): number;
}

export const systemClock: Clock = {
  now: () => Date.now(),
};
