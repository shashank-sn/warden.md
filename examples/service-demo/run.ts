import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import {
  createEs256SigningKey,
  createRouter,
  createService,
  createStaticVerificationKeys,
  InMemoryServiceStore,
} from "../../packages/service/src/index.js";

interface IdentityResponse {
  identity_id: string;
}

interface ClaimStartResponse {
  device_code: string;
  user_code: string;
}

interface ClaimVerificationResponse {
  claim_id: string;
}

interface ClaimPollResponse {
  claim_grant: string;
}

interface TokenResponse {
  access_token: string;
}

type LocalService = Awaited<ReturnType<typeof createService>>;

function requestedPort(serve: boolean): number {
  const value = process.env.PORT ?? (serve ? "8788" : "0");
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("PORT must be an integer between 0 and 65535.");
  }
  return port;
}

async function listen(server: Server, port: number): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, "localhost");
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Local demo server did not provide a TCP port.");
  }
  return address.port;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function requestBody(incoming: IncomingMessage): Promise<Buffer | undefined> {
  const method = incoming.method ?? "GET";
  if (method === "GET" || method === "HEAD") {
    return undefined;
  }
  const chunks: Uint8Array[] = [];
  for await (const chunk of incoming) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return chunks.length > 0 ? Buffer.concat(chunks) : undefined;
}

async function toRequest(incoming: IncomingMessage, issuer: string): Promise<Request> {
  const method = incoming.method ?? "GET";
  const body = await requestBody(incoming);
  return new Request(new URL(incoming.url ?? "/", issuer), {
    method,
    headers: incoming.headers as HeadersInit,
    ...(body ? { body } : {}),
  });
}

async function sendResponse(outgoing: ServerResponse, response: Response): Promise<void> {
  outgoing.writeHead(response.status, Object.fromEntries(response.headers.entries()));
  outgoing.end(Buffer.from(await response.arrayBuffer()));
}

function sendJson(outgoing: ServerResponse, status: number, body: object): void {
  outgoing.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
  });
  outgoing.end(JSON.stringify(body));
}

function bearerToken(value: string | undefined): string | undefined {
  const match = value?.match(/^Bearer +(.+)$/iu);
  return match?.[1];
}

async function protectedResource(
  incoming: IncomingMessage,
  outgoing: ServerResponse,
  service: LocalService,
  issuer: string,
): Promise<void> {
  if (incoming.method !== "GET") {
    sendJson(outgoing, 405, { error: "method_not_allowed" });
    return;
  }
  const token = bearerToken(incoming.headers.authorization);
  if (!token) {
    sendJson(outgoing, 401, { error: "invalid_token" });
    return;
  }
  try {
    await service.validateAccessToken(token, issuer);
    sendJson(outgoing, 200, { authorized: true });
  } catch {
    sendJson(outgoing, 401, { error: "invalid_token" });
  }
}

async function postJson<T>(url: string, body: object): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`Local ${new URL(url).pathname} request returned ${response.status}.`);
  }
  return (await response.json()) as T;
}

async function postForm(url: string, body: Record<string, string>): Promise<Response> {
  return fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body),
  });
}

function requireStatus(response: Response, status: number, label: string): void {
  if (response.status !== status) {
    throw new Error(`${label} returned ${response.status}, expected ${status}.`);
  }
}

async function runFlow(issuer: string): Promise<void> {
  const registered = await postJson<IdentityResponse>(`${issuer}/agent/identity`, {
    identity_type: "anonymous",
    scope: "agent:read",
    resource: issuer,
  });
  const claim = await postJson<ClaimStartResponse>(`${issuer}/agent/identity/claim`, {
    identity_id: registered.identity_id,
    scope: "agent:read",
    resource: issuer,
  });
  const verified = await postJson<ClaimVerificationResponse>(
    `${issuer}/agent/identity/claim/complete`,
    {
      action: "verify",
      user_code: claim.user_code,
    },
  );
  await postJson(`${issuer}/agent/identity/claim/complete`, {
    action: "approve",
    claim_id: verified.claim_id,
  });
  const approved = await postJson<ClaimPollResponse>(`${issuer}/agent/identity/claim`, {
    action: "poll",
    device_code: claim.device_code,
  });
  const token = await postJson<TokenResponse>(`${issuer}/oauth2/token`, {
    grant_type: "urn:workos:agent-auth:grant-type:claim",
    claim_grant: approved.claim_grant,
    scope: "agent:read",
    resource: issuer,
  });
  const beforeRevocation = await fetch(`${issuer}/protected`, {
    headers: { authorization: `Bearer ${token.access_token}` },
  });
  requireStatus(beforeRevocation, 200, "Protected-resource validation before revocation");

  const revoked = await postForm(`${issuer}/oauth2/revoke`, { token: token.access_token });
  requireStatus(revoked, 200, "Revocation");

  const afterRevocation = await fetch(`${issuer}/protected`, {
    headers: { authorization: `Bearer ${token.access_token}` },
  });
  requireStatus(afterRevocation, 401, "Protected-resource validation after revocation");
}

async function main(): Promise<void> {
  const argumentsList = process.argv.slice(2);
  if (argumentsList.some((argument) => argument !== "--serve")) {
    throw new Error("Usage: pnpm demo:service [--serve]");
  }
  const serve = argumentsList.includes("--serve");
  let issuer = "";
  let service: LocalService | undefined;
  let router: ReturnType<typeof createRouter> | undefined;

  const server = createServer((incoming, outgoing) => {
    void (async () => {
      try {
        if (!service || !router) {
          sendJson(outgoing, 503, { error: "temporarily_unavailable" });
          return;
        }
        const url = new URL(incoming.url ?? "/", issuer);
        if (url.pathname === "/protected") {
          await protectedResource(incoming, outgoing, service, issuer);
          return;
        }
        await sendResponse(outgoing, await router.fetch(await toRequest(incoming, issuer)));
      } catch {
        sendJson(outgoing, 500, { error: "temporarily_unavailable" });
      }
    })();
  });

  let serverStarted = false;
  let keepServerOpen = false;
  try {
    const port = await listen(server, requestedPort(serve));
    serverStarted = true;
    issuer = `http://localhost:${port}`;
    const signingKey = await createEs256SigningKey("demo-es256-1");
    service = await createService(
      {
        issuer,
        defaultResource: issuer,
        supportedScopes: ["agent:read", "agent:write"],
        signingKey,
        verificationKeys: await createStaticVerificationKeys(issuer, signingKey),
        trustedAssertionIssuer: issuer,
      },
      { store: new InMemoryServiceStore() },
    );
    router = createRouter(service);

    await runFlow(issuer);
    console.log(
      `Completed the anonymous claim, protected-resource validation, and revocation flow at ${issuer}.`,
    );
    console.log("No codes, grants, access tokens, assertions, or private keys were printed.");
    if (serve) {
      keepServerOpen = true;
      console.log("Discovery routes and /protected remain available; stop with Ctrl-C.");
    }
  } finally {
    if (serverStarted && !keepServerOpen) {
      await close(server);
    }
  }
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? `Demo failed: ${error.message}` : "Demo failed.");
  process.exitCode = 1;
});
