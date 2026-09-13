import type { Broker } from "./broker.js";
import type { CapabilityConsumer } from "./client.js";
import type { CapabilityVerifier } from "./crypto.js";
import { isBrokerError } from "./errors.js";
import type { ConsumeResult } from "./types.js";

export interface MiddlewareOptions {
  /** Local embedding only. Deployed resources should use `consumer` instead. */
  broker?: Broker;
  /** A broker-owned atomic consume boundary, such as `WorkerBrokerClient`. */
  consumer?: CapabilityConsumer;
  /** Optional local public-key preverification fetched from the broker JWKS endpoint. */
  verifier?: CapabilityVerifier;
  audience: string;
  now?(): number;
  onEvidence?(result: ConsumeResult): Promise<void> | void;
}

export function createWorkersHandler<T extends Response>(
  options: MiddlewareOptions,
  protectedHandler: (request: Request, consume: ConsumeResult) => Promise<T>,
): (request: Request) => Promise<T | Response> {
  const consumer = configuredConsumer(options);
  return async (request) => {
    const authorization = request.headers.get("authorization");
    const dpop = request.headers.get("dpop");
    if (!authorization?.startsWith("Bearer ") || !dpop) {
      return errorResponse("invalid_credential", 401);
    }
    const target = new URL(request.url);
    if (target.origin !== new URL(options.audience).origin) {
      return errorResponse("wrong_audience", 403);
    }
    const credential = authorization.slice("Bearer ".length);
    try {
      await options.verifier?.verify(credential, now(options));
    } catch (error) {
      return responseForCredentialError(error);
    }

    let consumed: ConsumeResult;
    try {
      consumed = await consumer.consume({
        credential,
        proof: { token: dpop, method: request.method, url: request.url },
        audience: options.audience,
      });
    } catch (error) {
      return responseForOperationError(error);
    }

    try {
      await options.onEvidence?.(consumed);
    } catch {
      return errorResponse("temporarily_unavailable", 503);
    }
    return protectedHandler(request, consumed);
  };
}

export interface NodeLikeRequest {
  method?: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
}

export interface NodeLikeResponse {
  status(status: number): NodeLikeResponse;
  json(body: unknown): void;
}

export function createNodeMiddleware(options: MiddlewareOptions) {
  const consumer = configuredConsumer(options);
  return async (
    request: NodeLikeRequest,
    response: NodeLikeResponse,
    next: (error?: unknown) => void,
  ): Promise<void> => {
    const authorization = asHeader(request.headers.authorization);
    const dpop = asHeader(request.headers.dpop);
    if (!authorization?.startsWith("Bearer ") || !dpop) {
      response.status(401).json({ error: "invalid_credential" });
      return;
    }
    const url = nodeRequestUrl(request, options.audience);
    const credential = authorization.slice("Bearer ".length);
    try {
      await options.verifier?.verify(credential, now(options));
    } catch (error) {
      sendNodeError(response, credentialError(error));
      return;
    }

    let consumed: ConsumeResult;
    try {
      consumed = await consumer.consume({
        credential,
        proof: {
          token: dpop,
          method: request.method ?? "GET",
          url,
        },
        audience: options.audience,
      });
    } catch (error) {
      sendNodeError(response, operationError(error));
      return;
    }

    try {
      await options.onEvidence?.(consumed);
    } catch {
      response.status(503).json({ error: "temporarily_unavailable" });
      return;
    }
    next();
  };
}

function configuredConsumer(options: MiddlewareOptions): CapabilityConsumer {
  if (options.broker && options.consumer) {
    throw new Error("configure either broker or consumer, not both");
  }
  const consumer = options.consumer ?? options.broker;
  if (!consumer) {
    throw new Error("a broker consumer is required");
  }
  return consumer;
}

function now(options: MiddlewareOptions): number {
  return options.now?.() ?? Date.now();
}

function asHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function nodeRequestUrl(request: NodeLikeRequest, audience: string): string {
  return new URL(request.originalUrl ?? "/", audience).toString();
}

function errorResponse(code: string, status: number): Response {
  return Response.json({ error: code }, { status, headers: { "cache-control": "no-store" } });
}

function credentialError(error: unknown): { code: string; status: number } {
  if (isBrokerError(error)) {
    return { code: error.code, status: error.status };
  }
  return { code: "invalid_credential", status: 401 };
}

function responseForCredentialError(error: unknown): Response {
  const result = credentialError(error);
  return errorResponse(result.code, result.status);
}

function operationError(error: unknown): { code: string; status: number } {
  if (isBrokerError(error)) {
    return { code: error.code, status: error.status };
  }
  return { code: "temporarily_unavailable", status: 503 };
}

function responseForOperationError(error: unknown): Response {
  const result = operationError(error);
  return errorResponse(result.code, result.status);
}

function sendNodeError(response: NodeLikeResponse, result: { code: string; status: number }): void {
  response.status(result.status).json({ error: result.code });
}
