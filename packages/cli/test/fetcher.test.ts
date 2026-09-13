import { describe, expect, it } from "vitest";

import { fetchDocument } from "../src/fetcher.js";
import { TransportError } from "../src/transport.js";
import { response, StubTransport } from "./helpers.js";

const options = { timeoutMs: 100, maxBytes: 8, maxRedirects: 1 };

describe("document fetcher", () => {
  it.each([
    ["dns", "FETCH_DNS_ERROR"],
    ["tls", "FETCH_TLS_ERROR"],
    ["timeout", "FETCH_TIMEOUT"],
    ["body-too-large", "FETCH_RESPONSE_TOO_LARGE"],
  ] as const)("maps %s failures to %s without network access", async (kind, ruleId) => {
    const transport = new StubTransport({
      "https://service.test/auth.md": new TransportError(kind, `${kind} failure`),
    });

    const result = await fetchDocument(
      transport,
      "https://service.test/auth.md",
      "markdown",
      options,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.finding.ruleId).toBe(ruleId);
    }
    expect(transport.requests).toHaveLength(1);
  });

  it.each([
    [
      "HTTP failures",
      response("https://service.test/auth.md", 404, "missing", { "content-type": "text/plain" }),
      "FETCH_HTTP_STATUS",
    ],
    [
      "server failures",
      response("https://service.test/auth.md", 500, "failed", { "content-type": "text/plain" }),
      "FETCH_HTTP_STATUS",
    ],
    [
      "wrong content types",
      response("https://service.test/auth.md", 200, "{}", { "content-type": "application/json" }),
      "FETCH_CONTENT_TYPE",
    ],
    [
      "oversized bodies",
      response("https://service.test/auth.md", 200, "123456789", {
        "content-type": "text/markdown",
      }),
      "FETCH_RESPONSE_TOO_LARGE",
    ],
  ])("maps %s to a stable finding", async (_name, fixture, ruleId) => {
    const result = await fetchDocument(
      new StubTransport({ "https://service.test/auth.md": fixture }),
      "https://service.test/auth.md",
      "markdown",
      options,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.finding.ruleId).toBe(ruleId);
    }
  });

  it("follows a bounded HTTPS redirect and preserves a hop trace", async () => {
    const transport = new StubTransport({
      "https://service.test/auth.md": response("https://service.test/auth.md", 302, "", {
        location: "/docs/auth.md",
      }),
      "https://service.test/docs/auth.md": response(
        "https://service.test/docs/auth.md",
        200,
        "hello",
        { "content-type": "text/markdown" },
      ),
    });

    const result = await fetchDocument(
      transport,
      "https://service.test/auth.md",
      "markdown",
      options,
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.url).toBe("https://service.test/docs/auth.md");
      expect(result.value.trace).toHaveLength(2);
    }
  });
});
