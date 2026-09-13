import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { type AuthMdDocument, parseAuthMd, validateAuthMdDocument } from "./authmd.js";
import { type FetchOptions, fetchDocument } from "./fetcher.js";
import {
  authorizationServerMetadataUrls,
  type JsonObject,
  protectedResourceMetadataUrls,
  validateAuthorizationServerMetadata,
  validateProtectedResourceMetadata,
} from "./metadata.js";
import {
  type ConformanceReport,
  deduplicateFindings,
  type Finding,
  type ProbeHop,
  REPORT_SCHEMA_VERSION,
  summarizeFindings,
} from "./model.js";
import type { Transport } from "./transport.js";

export const DEFAULT_CHECK_OPTIONS = {
  timeoutMs: 10_000,
  maxBytes: 1_000_000,
  maxRedirects: 3,
  probe: false,
} as const;

type ConfigurableCheckOptions = {
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  probe?: boolean;
};

export class CheckInputError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "CheckInputError";
  }
}

export type CheckOptions = ConfigurableCheckOptions & {
  transport: Transport;
  now?: () => number;
};

type ResolvedSubject =
  | {
      kind: "remote";
      subject: string;
      authMdUrl: string;
    }
  | {
      kind: "local";
      subject: string;
      path: string;
    };

type JsonDiscovery = {
  value?: JsonObject;
  url?: string;
  findings: Finding[];
  trace: ProbeHop[];
};

export async function runConformanceCheck(
  input: string,
  options: CheckOptions,
): Promise<ConformanceReport> {
  const configured = {
    ...DEFAULT_CHECK_OPTIONS,
    ...options,
  };
  const now = options.now ?? Date.now;
  const startedAt = now();
  const resolved = resolveSubject(input);
  const findings: Finding[] = [];
  const trace: ProbeHop[] = [];

  let document: AuthMdDocument;
  if (resolved.kind === "local") {
    document = await readLocalDocument(resolved);
  } else {
    const fetched = await fetchDocument(
      options.transport,
      resolved.authMdUrl,
      "markdown",
      configured,
    );
    trace.push(...(fetched.ok ? fetched.value.trace : fetched.error.trace));

    if (!fetched.ok) {
      findings.push(fetched.error.finding);
      return report(
        resolved.subject,
        startedAt,
        now(),
        findings,
        configured.probe ? trace : undefined,
      );
    }

    document = parseAuthMd(fetched.value.url, fetched.value.body);
  }

  findings.push(...validateAuthMdDocument(document));

  if (resolved.kind === "remote") {
    const protectedResource = await discoverJson(
      protectedResourceCandidates(document, resolved.subject),
      options.transport,
      configured,
    );
    trace.push(...protectedResource.trace);
    findings.push(...protectedResource.findings);

    if (protectedResource.value !== undefined) {
      findings.push(
        ...validateProtectedResourceMetadata(protectedResource.value, resolved.subject),
      );
      const authorizationServer = firstValidAuthorizationServer(protectedResource.value);

      if (authorizationServer !== undefined) {
        const authorizationMetadata = await discoverJson(
          authorizationServerMetadataUrls(authorizationServer),
          options.transport,
          configured,
        );
        trace.push(...authorizationMetadata.trace);
        findings.push(...authorizationMetadata.findings);

        if (authorizationMetadata.value !== undefined) {
          findings.push(
            ...validateAuthorizationServerMetadata(authorizationMetadata.value, {
              authDocument: document,
              protectedResourceMetadata: protectedResource.value,
            }),
          );
        }
      }
    }
  }

  return report(resolved.subject, startedAt, now(), findings, configured.probe ? trace : undefined);
}

function resolveSubject(input: string): ResolvedSubject {
  if (input.length === 0) {
    throw new CheckInputError("A URL or auth.md path is required.");
  }

  if (input.startsWith("http:") || input.startsWith("https:") || input.includes("://")) {
    let url: URL;
    try {
      url = new URL(input);
    } catch {
      throw new CheckInputError("Expected a valid HTTPS URL.");
    }

    if (url.protocol !== "https:") {
      throw new CheckInputError("Only HTTPS URLs are supported.");
    }

    url.hash = "";
    const isAuthMd = url.pathname === "/auth.md";
    const subject = isAuthMd ? new URL("/", url).toString() : url.toString();
    const authMdUrl = isAuthMd ? url.toString() : new URL("/auth.md", url).toString();
    return { kind: "remote", subject, authMdUrl };
  }

  if (!input.endsWith(".md") && !input.includes("/") && !input.includes("\\")) {
    throw new CheckInputError("Expected a valid HTTPS URL or an auth.md file path.");
  }

  const path = resolve(input);
  return { kind: "local", subject: path, path };
}

async function readLocalDocument(
  subject: Extract<ResolvedSubject, { kind: "local" }>,
): Promise<AuthMdDocument> {
  let text: string;
  try {
    text = await readFile(subject.path, "utf8");
  } catch {
    throw new CheckInputError(`Could not read auth.md file: ${subject.path}`);
  }

  return parseAuthMd(subject.path, text);
}

function protectedResourceCandidates(document: AuthMdDocument, subject: string): string[] {
  const explicitReferences = document.metadataReferences
    .filter((reference) => reference.kind === "protected-resource")
    .map((reference) => reference.url)
    .filter(isAbsoluteHttpsUrlWithoutFragment);

  return unique([...explicitReferences, ...protectedResourceMetadataUrls(subject)]);
}

async function discoverJson(
  candidates: readonly string[],
  transport: Transport,
  options: FetchOptions,
): Promise<JsonDiscovery> {
  const trace: ProbeHop[] = [];
  const failures: Finding[] = [];

  for (const candidate of candidates) {
    const fetched = await fetchDocument(transport, candidate, "json", options);
    trace.push(...(fetched.ok ? fetched.value.trace : fetched.error.trace));

    if (!fetched.ok) {
      failures.push(fetched.error.finding);
      continue;
    }

    try {
      const parsed: unknown = JSON.parse(fetched.value.body);
      if (!isJsonObject(parsed)) {
        failures.push({
          ruleId: "METADATA_JSON_OBJECT",
          severity: "error",
          message: "Metadata document must be a JSON object.",
          location: { document: fetched.value.url },
          help: "Return a JSON object from the discovery endpoint.",
        });
        continue;
      }
      return { value: parsed, url: fetched.value.url, findings: [], trace };
    } catch {
      failures.push({
        ruleId: "METADATA_JSON_PARSE",
        severity: "error",
        message: "Metadata document is not valid JSON.",
        location: { document: fetched.value.url },
        help: "Return syntactically valid JSON from the discovery endpoint.",
      });
    }
  }

  return {
    findings: failures.length > 0 ? [failures[failures.length - 1] as Finding] : [],
    trace,
  };
}

function firstValidAuthorizationServer(metadata: JsonObject): string | undefined {
  const authorizationServers = metadata.authorization_servers;
  if (!Array.isArray(authorizationServers)) {
    return undefined;
  }

  return authorizationServers.find(
    (value): value is string =>
      typeof value === "string" && isAbsoluteHttpsUrlWithoutFragment(value),
  );
}

function report(
  subject: string,
  startedAt: number,
  finishedAt: number,
  inputFindings: readonly Finding[],
  probe: ProbeHop[] | undefined,
): ConformanceReport {
  const findings = deduplicateFindings(inputFindings);
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    subject,
    startedAt: new Date(startedAt).toISOString(),
    durationMs: Math.max(0, finishedAt - startedAt),
    findings,
    summary: summarizeFindings(findings),
    ...(probe === undefined ? {} : { probe }),
  };
}

function isAbsoluteHttpsUrlWithoutFragment(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.origin !== "null" && url.hash.length === 0;
  } catch {
    return false;
  }
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
