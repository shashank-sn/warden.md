import type { Broker, ConsumeInput } from "./broker.js";
import { type CapabilityVerifier, Es256CapabilityVerifier, type JsonWebKeySet } from "./crypto.js";
import { BrokerError, type BrokerErrorCode } from "./errors.js";
import type {
  CompletionSource,
  ConsumeResult,
  DpopProof,
  ExchangeResult,
  Grant,
  GrantProposal,
} from "./types.js";

export interface CompletionApi {
  exchange(proposal: GrantProposal): Promise<ExchangeResult>;
  approve(grantId: string, approver: string): Promise<ExchangeResult>;
  complete(grantId: string, source?: CompletionSource): Promise<unknown>;
}

/** The resource-facing boundary needed for a broker-owned atomic consume. */
export interface CapabilityConsumer {
  consume(input: ConsumeInput): Promise<ConsumeResult>;
}

interface CredentialBoundCompletionApi {
  readonly approvalIdentityFromTransport?: true;
  completeCredentialBound(input: { grant: Grant; credential: string }): Promise<unknown>;
}

export interface CompletionRunInput<T> {
  proposal: GrantProposal;
  approver?: string;
  timeoutMs?: number;
  call(input: { grant: Grant; credential: string }): Promise<T>;
}

export class CompletionClient {
  private readonly bufferedCompletions = new Map<string, { grant: Grant; credential: string }>();

  public constructor(
    private readonly api: CompletionApi,
    private readonly completionAttempts = 2,
  ) {}

  public async run<T>(input: CompletionRunInput<T>): Promise<T> {
    let exchange = await this.api.exchange(input.proposal);
    if (!exchange.credential) {
      if (!input.approver && !credentialBoundApi(this.api)?.approvalIdentityFromTransport) {
        throw new BrokerError("approval_required");
      }
      exchange = await this.api.approve(exchange.grant.id, input.approver ?? "");
    }
    const credential = exchange.credential;
    if (!credential) {
      throw new BrokerError("grant_not_approved");
    }

    try {
      return await this.withTimeout(
        input.call({ grant: exchange.grant, credential }),
        input.timeoutMs,
      );
    } finally {
      await this.completeOrBuffer(exchange.grant, credential);
    }
  }

  public async retryBufferedCompletions(): Promise<void> {
    for (const completion of [...this.bufferedCompletions.values()]) {
      await this.completeOrBuffer(completion.grant, completion.credential);
    }
  }

  public bufferedCompletionCount(): number {
    return this.bufferedCompletions.size;
  }

  private async completeOrBuffer(grant: Grant, credential: string): Promise<void> {
    for (let attempt = 0; attempt < this.completionAttempts; attempt += 1) {
      try {
        const credentialBound = credentialBoundApi(this.api);
        if (credentialBound) {
          await credentialBound.completeCredentialBound({ grant, credential });
        } else {
          await this.api.complete(grant.id, "agent");
        }
        this.bufferedCompletions.delete(grant.id);
        return;
      } catch {
        // The queue is memory-only. A process loss falls back to the grant TTL by design.
      }
    }
    this.bufferedCompletions.set(grant.id, { grant, credential });
  }

  private async withTimeout<T>(promise: Promise<T>, timeoutMs?: number): Promise<T> {
    if (!timeoutMs) {
      return promise;
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("protected_call_timed_out")), timeoutMs);
    });
    try {
      return await Promise.race([promise, timeout]);
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
    }
  }
}

export function createLocalCompletionClient(broker: Broker): CompletionClient {
  return new CompletionClient(broker);
}

export interface WorkerBrokerClientOptions {
  brokerUrl: string;
  fetch?: typeof fetch;
  /** Forwarded only to the approval route so approval identity does not reach other broker endpoints. */
  approvalHeaders?: HeadersInit;
}

export interface WorkerCompletionClientOptions extends WorkerBrokerClientOptions {
  dpopProof(input: { method: string; url: string }): Promise<DpopProof>;
}

/** A broker Worker transport failure is retryable, never an invalid credential. */
export class WorkerBrokerTransportError extends Error {
  public constructor() {
    super("broker worker unavailable");
    this.name = "WorkerBrokerTransportError";
  }
}

export function isWorkerBrokerTransportError(value: unknown): value is WorkerBrokerTransportError {
  return value instanceof WorkerBrokerTransportError;
}

/**
 * HTTP client for the deployed broker Worker. It needs only the broker URL and any caller-owned
 * approval credentials; it never accepts or stores BROKER_SIGNING_JWK.
 */
export class WorkerBrokerClient implements CapabilityConsumer {
  private readonly baseUrl: string;
  private readonly fetcher: typeof fetch;

  public constructor(private readonly options: WorkerBrokerClientOptions) {
    let parsed: URL;
    try {
      parsed = new URL(options.brokerUrl);
    } catch {
      throw new Error("brokerUrl must be an https origin");
    }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
      throw new Error("brokerUrl must be an https origin");
    }
    this.baseUrl = parsed.origin;
    this.fetcher = options.fetch ?? globalThis.fetch;
    if (typeof this.fetcher !== "function") {
      throw new Error("a fetch implementation is required");
    }
  }

  public async exchange(proposal: GrantProposal): Promise<ExchangeResult> {
    return this.request("/exchange", { method: "POST", body: proposal });
  }

  /** The broker approval binding derives the approver from the configured approval headers. */
  public async approve(grantId: string, _approver: string): Promise<ExchangeResult> {
    return this.request(`/grants/${encodeURIComponent(grantId)}/approve`, {
      method: "POST",
      headers: this.options.approvalHeaders,
    });
  }

  public async consume(input: ConsumeInput): Promise<ConsumeResult> {
    return this.request("/consume", { method: "POST", body: input });
  }

  public async jwks(): Promise<JsonWebKeySet> {
    return this.request("/.well-known/jwks.json", { method: "GET" });
  }

  public async verifier(): Promise<CapabilityVerifier> {
    return Es256CapabilityVerifier.fromJwks(await this.jwks());
  }

  public async completeCredentialBound(input: {
    grant: Grant;
    credential: string;
    dpopProof: WorkerCompletionClientOptions["dpopProof"];
  }): Promise<unknown> {
    const url = this.endpoint(`/grants/${encodeURIComponent(input.grant.id)}/complete`);
    const proof = await input.dpopProof({ method: "POST", url });
    if (proof.method.toUpperCase() !== "POST" || proof.url !== url) {
      throw new Error("completion proof must bind the broker completion endpoint");
    }
    return this.request(`/grants/${encodeURIComponent(input.grant.id)}/complete`, {
      method: "POST",
      body: { credential: input.credential, proof: { token: proof.token } },
    });
  }

  private endpoint(path: string): string {
    return new URL(path, `${this.baseUrl}/`).toString();
  }

  private async request<T>(
    path: string,
    input: { method: "GET" | "POST"; body?: unknown; headers?: HeadersInit },
  ): Promise<T> {
    const headers = new Headers(input.headers);
    if (input.body !== undefined) {
      headers.set("content-type", "application/json");
    }
    let response: Response;
    try {
      response = await this.fetcher(
        new Request(this.endpoint(path), {
          method: input.method,
          headers,
          body: input.body === undefined ? undefined : JSON.stringify(input.body),
        }),
      );
    } catch {
      throw new WorkerBrokerTransportError();
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      body = undefined;
    }
    if (!response.ok) {
      throw responseError(body);
    }
    return body as T;
  }
}

export function createWorkerCompletionClient(
  options: WorkerCompletionClientOptions,
): CompletionClient {
  const client = new WorkerBrokerClient(options);
  const api: CompletionApi & CredentialBoundCompletionApi = {
    approvalIdentityFromTransport: true,
    exchange: (proposal) => client.exchange(proposal),
    approve: (grantId, approver) => client.approve(grantId, approver),
    async complete(): Promise<never> {
      throw new Error("worker completion requires a credential-bound DPoP proof");
    },
    completeCredentialBound: ({ grant, credential }) =>
      client.completeCredentialBound({ grant, credential, dpopProof: options.dpopProof }),
  };
  return new CompletionClient(api);
}

function credentialBoundApi(api: CompletionApi): CredentialBoundCompletionApi | undefined {
  const candidate = api as CompletionApi & Partial<CredentialBoundCompletionApi>;
  return typeof candidate.completeCredentialBound === "function"
    ? (candidate as CompletionApi & CredentialBoundCompletionApi)
    : undefined;
}

const brokerErrorCodes: ReadonlySet<BrokerErrorCode> = new Set([
  "action_not_authorized",
  "approval_required",
  "dpop_proof_invalid",
  "grant_already_consumed",
  "grant_expired",
  "grant_not_approved",
  "grant_not_found",
  "grant_revoked",
  "invalid_credential",
  "invalid_request",
  "operator_authorization_required",
  "policy_blocked",
  "scope_not_authorized",
  "token_already_exchanged",
  "wrong_audience",
  "wrong_dpop_key",
]);

function responseError(body: unknown): Error {
  if (
    typeof body === "object" &&
    body !== null &&
    "error" in body &&
    typeof body.error === "string" &&
    brokerErrorCodes.has(body.error as BrokerErrorCode)
  ) {
    return new BrokerError(body.error as BrokerErrorCode);
  }
  return new WorkerBrokerTransportError();
}
