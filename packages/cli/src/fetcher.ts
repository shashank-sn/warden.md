import type { Finding, ProbeHop } from "./model.js";
import { type Transport, TransportError, type TransportResponse } from "./transport.js";

export type DocumentKind = "markdown" | "json";

export type FetchOptions = {
  timeoutMs: number;
  maxBytes: number;
  maxRedirects: number;
};

export type FetchedDocument = {
  url: string;
  body: string;
  contentType?: string;
  trace: ProbeHop[];
};

export type FetchFailure = {
  finding: Finding;
  trace: ProbeHop[];
};

export type FetchResult =
  | {
      ok: true;
      value: FetchedDocument;
    }
  | {
      ok: false;
      error: FetchFailure;
    };

export async function fetchDocument(
  transport: Transport,
  initialUrl: string,
  kind: DocumentKind,
  options: FetchOptions,
): Promise<FetchResult> {
  const trace: ProbeHop[] = [];
  let currentUrl = initialUrl;

  for (let redirectCount = 0; redirectCount <= options.maxRedirects; redirectCount += 1) {
    let response: TransportResponse;
    try {
      response = await transport.get({
        url: currentUrl,
        timeoutMs: options.timeoutMs,
        maxBytes: options.maxBytes,
        headers: {
          accept: kind === "markdown" ? "text/markdown, text/plain;q=0.9" : "application/json",
        },
      });
    } catch (error) {
      return {
        ok: false,
        error: {
          finding: transportFailureFinding(error, currentUrl),
          trace,
        },
      };
    }

    const location = headerValue(response, "location");
    const contentType = headerValue(response, "content-type");
    trace.push({
      url: currentUrl,
      status: response.status,
      durationMs: response.durationMs,
      ...(contentType === undefined ? {} : { contentType }),
      ...(location === undefined ? {} : { redirectTo: location }),
    });

    if (isRedirect(response.status)) {
      if (location === undefined) {
        return {
          ok: false,
          error: {
            finding: fetchFinding(
              "FETCH_REDIRECT_LOCATION",
              "error",
              "Redirect response is missing a Location header.",
              currentUrl,
            ),
            trace,
          },
        };
      }

      if (redirectCount === options.maxRedirects) {
        return {
          ok: false,
          error: {
            finding: fetchFinding(
              "FETCH_REDIRECT_LIMIT",
              "error",
              `Document exceeded the redirect limit of ${options.maxRedirects}.`,
              currentUrl,
            ),
            trace,
          },
        };
      }

      try {
        const nextUrl = new URL(location, currentUrl);
        if (nextUrl.protocol !== "https:") {
          return {
            ok: false,
            error: {
              finding: fetchFinding(
                "FETCH_HTTPS_REQUIRED",
                "error",
                "Redirect target must use HTTPS.",
                currentUrl,
              ),
              trace,
            },
          };
        }
        currentUrl = nextUrl.toString();
        continue;
      } catch {
        return {
          ok: false,
          error: {
            finding: fetchFinding(
              "FETCH_REDIRECT_URL",
              "error",
              "Redirect target is not a valid URL.",
              currentUrl,
            ),
            trace,
          },
        };
      }
    }

    if (response.status < 200 || response.status >= 300) {
      return {
        ok: false,
        error: {
          finding: fetchFinding(
            "FETCH_HTTP_STATUS",
            "error",
            `Document returned HTTP ${response.status}.`,
            currentUrl,
          ),
          trace,
        },
      };
    }

    if (response.body.length > options.maxBytes) {
      return {
        ok: false,
        error: {
          finding: fetchFinding(
            "FETCH_RESPONSE_TOO_LARGE",
            "error",
            "Document exceeds the configured response-size limit.",
            currentUrl,
          ),
          trace,
        },
      };
    }

    if (!isExpectedContentType(contentType, kind)) {
      return {
        ok: false,
        error: {
          finding: fetchFinding(
            "FETCH_CONTENT_TYPE",
            "error",
            "Expected " +
              expectedContentType(kind) +
              " content but received " +
              (contentType ?? "none") +
              ".",
            currentUrl,
          ),
          trace,
        },
      };
    }

    return {
      ok: true,
      value: {
        url: currentUrl,
        body: response.body,
        ...(contentType === undefined ? {} : { contentType }),
        trace,
      },
    };
  }

  return {
    ok: false,
    error: {
      finding: fetchFinding(
        "FETCH_REDIRECT_LIMIT",
        "error",
        "Document exceeded the redirect limit.",
        currentUrl,
      ),
      trace,
    },
  };
}

function transportFailureFinding(error: unknown, url: string): Finding {
  if (error instanceof TransportError) {
    const ruleIdByKind = {
      dns: "FETCH_DNS_ERROR",
      tls: "FETCH_TLS_ERROR",
      timeout: "FETCH_TIMEOUT",
      "body-too-large": "FETCH_RESPONSE_TOO_LARGE",
      network: "FETCH_NETWORK_ERROR",
    } as const;

    return fetchFinding(ruleIdByKind[error.kind], "error", error.message, url);
  }

  return fetchFinding("FETCH_NETWORK_ERROR", "error", "The network request failed.", url);
}

function fetchFinding(
  ruleId: string,
  severity: Finding["severity"],
  message: string,
  url: string,
): Finding {
  return {
    ruleId,
    severity,
    message,
    location: { document: url },
    help: "Serve a public HTTPS document with the expected status and content type.",
  };
}

function headerValue(response: TransportResponse, name: string): string | undefined {
  const direct = response.headers[name];
  if (direct !== undefined) {
    return direct;
  }

  const match = Object.entries(response.headers).find(([key]) => key.toLowerCase() === name);
  return match?.[1];
}

function isRedirect(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function isExpectedContentType(contentType: string | undefined, kind: DocumentKind): boolean {
  if (contentType === undefined) {
    return false;
  }

  const value = contentType.split(";", 1)[0]?.trim().toLowerCase();
  if (kind === "markdown") {
    return value === "text/markdown" || value === "text/plain" || value === "text/x-markdown";
  }

  return value === "application/json" || value?.endsWith("+json") === true;
}

function expectedContentType(kind: DocumentKind): string {
  return kind === "markdown" ? "Markdown" : "JSON";
}
