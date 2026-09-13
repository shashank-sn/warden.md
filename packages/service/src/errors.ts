export type OAuthErrorCode =
  | "access_denied"
  | "authorization_pending"
  | "expired_token"
  | "invalid_client"
  | "invalid_grant"
  | "invalid_request"
  | "invalid_scope"
  | "invalid_target"
  | "invalid_token"
  | "slow_down"
  | "temporarily_unavailable"
  | "unsupported_grant_type";

const statusByCode: Record<OAuthErrorCode, number> = {
  access_denied: 400,
  authorization_pending: 400,
  expired_token: 400,
  invalid_client: 401,
  invalid_grant: 400,
  invalid_request: 400,
  invalid_scope: 400,
  invalid_target: 400,
  invalid_token: 401,
  slow_down: 400,
  temporarily_unavailable: 503,
  unsupported_grant_type: 400,
};

export class OAuthError extends Error {
  public readonly status: number;

  public constructor(public readonly code: OAuthErrorCode) {
    super(code);
    this.name = "OAuthError";
    this.status = statusByCode[code];
  }
}

export function isOAuthError(value: unknown): value is OAuthError {
  return value instanceof OAuthError;
}

export function errorResponse(error: OAuthError): Response {
  return new Response(JSON.stringify({ error: error.code }), {
    status: error.status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      ...(error.code === "invalid_client" ? { "www-authenticate": "Bearer" } : {}),
    },
  });
}
