export type BrokerErrorCode =
  | "action_not_authorized"
  | "approval_required"
  | "grant_already_consumed"
  | "grant_expired"
  | "grant_not_found"
  | "grant_not_approved"
  | "grant_revoked"
  | "invalid_credential"
  | "invalid_request"
  | "operator_authorization_required"
  | "policy_blocked"
  | "scope_not_authorized"
  | "token_already_exchanged"
  | "wrong_audience"
  | "wrong_dpop_key"
  | "dpop_proof_invalid";

const statusByCode: Record<BrokerErrorCode, number> = {
  action_not_authorized: 403,
  approval_required: 403,
  grant_already_consumed: 409,
  grant_expired: 401,
  grant_not_found: 404,
  grant_not_approved: 403,
  grant_revoked: 401,
  invalid_credential: 401,
  invalid_request: 400,
  operator_authorization_required: 403,
  policy_blocked: 403,
  scope_not_authorized: 403,
  token_already_exchanged: 409,
  wrong_audience: 403,
  wrong_dpop_key: 401,
  dpop_proof_invalid: 401,
};

export class BrokerError extends Error {
  public readonly status: number;

  public constructor(
    public readonly code: BrokerErrorCode,
    message = code,
  ) {
    super(message);
    this.name = "BrokerError";
    this.status = statusByCode[code];
  }
}

export function isBrokerError(value: unknown): value is BrokerError {
  return value instanceof BrokerError;
}
