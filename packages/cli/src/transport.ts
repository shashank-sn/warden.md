import { performance } from "node:perf_hooks";

export type TransportErrorKind = "dns" | "tls" | "timeout" | "body-too-large" | "network";

export class TransportError extends Error {
  public constructor(
    public readonly kind: TransportErrorKind,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "TransportError";
  }
}

export type TransportRequest = {
  url: string;
  timeoutMs: number;
  maxBytes: number;
  headers?: Record<string, string>;
};

export type TransportResponse = {
  url: string;
  status: number;
  headers: Record<string, string | undefined>;
  body: string;
  durationMs: number;
};

export interface Transport {
  get(request: TransportRequest): Promise<TransportResponse>;
}

export function createFetchTransport(): Transport {
  return {
    async get(request) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), request.timeoutMs);
      const startedAt = performance.now();

      try {
        const response = await fetch(request.url, {
          method: "GET",
          headers: request.headers,
          redirect: "manual",
          signal: controller.signal,
        });
        const body = await readResponseBody(response, request.maxBytes);
        const headers = Object.fromEntries(response.headers.entries());

        return {
          url: response.url || request.url,
          status: response.status,
          headers,
          body,
          durationMs: Math.round(performance.now() - startedAt),
        };
      } catch (error) {
        throw classifyTransportError(error);
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}

async function readResponseBody(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) {
    return "";
  }

  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  while (true) {
    const next = await reader.read();
    if (next.done) {
      break;
    }

    totalBytes += next.value.byteLength;
    if (totalBytes > maxBytes) {
      await reader.cancel();
      throw new TransportError(
        "body-too-large",
        "Response body exceeds the configured size limit.",
      );
    }
    chunks.push(next.value);
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return new TextDecoder().decode(bytes);
}

function classifyTransportError(error: unknown): TransportError {
  if (error instanceof TransportError) {
    return error;
  }

  if (isAbortError(error)) {
    return new TransportError("timeout", "The request timed out.", { cause: error });
  }

  const code = errorCode(error);
  if (code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "ENODATA") {
    return new TransportError("dns", "DNS resolution failed.", { cause: error });
  }

  if (
    code?.startsWith("ERR_TLS") === true ||
    code?.startsWith("CERT_") === true ||
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
  ) {
    return new TransportError("tls", "TLS negotiation failed.", { cause: error });
  }

  return new TransportError("network", "The network request failed.", { cause: error });
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException
    ? error.name === "AbortError"
    : typeof error === "object" && error !== null && "name" in error
      ? (error as { name?: unknown }).name === "AbortError"
      : false;
}

function errorCode(error: unknown): string | undefined {
  let current: unknown = error;

  for (let depth = 0; depth < 3; depth += 1) {
    if (typeof current !== "object" || current === null) {
      return undefined;
    }

    const details = current as { code?: unknown; cause?: unknown };
    if (typeof details.code === "string") {
      return details.code;
    }
    current = details.cause;
  }

  return undefined;
}
