import { describe, expect, it } from "vitest";
import { jwkThumbprint, verifyDpopProof } from "../src/crypto.js";
import {
  Broker,
  createDpopSession,
  Es256CapabilitySigner,
  type GrantProposal,
} from "../src/index.js";
import { createAuthorityResolver } from "./support.js";

const encode = (value: unknown): string =>
  btoa(JSON.stringify(value)).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");

describe("broker security boundaries", () => {
  it("does not retain credentials, DPoP proofs, or subject token values in audit events", async () => {
    const broker = await Broker.create({
      policy: { version: 1, default: "require-approval", rules: [] },
      authorityResolver: createAuthorityResolver([
        { subjectTokenId: "subject-token-must-not-appear" },
      ]),
    });
    const session = await createDpopSession();
    const proposal: GrantProposal = {
      agentId: "agent-a",
      subjectId: "person-a",
      subjectTokenId: "subject-token-must-not-appear",
      resource: "https://resource.example.test",
      action: "POST /records/42",
      requestedScope: ["records:write"],
      dpopThumbprint: session.thumbprint,
    };
    const exchanged = await broker.exchange(proposal);
    const approved = await broker.approve(exchanged.grant.id, "person-a");
    const proof = await session.proof("POST", "https://resource.example.test/records/42", {
      now: () => Date.now(),
    });
    await broker.consume({
      credential: approved.credential ?? "",
      proof,
      audience: "https://resource.example.test",
    });

    const audit = JSON.stringify(broker.store.auditFor(exchanged.grant.id));
    expect(audit).not.toContain("subject-token-must-not-appear");
    expect(audit).not.toContain(approved.credential ?? "credential-not-issued");
    expect(audit).not.toContain(proof.token);
  });

  it("rejects an alg none credential before authorization", async () => {
    const signer = await Es256CapabilitySigner.create();
    const forged = [
      btoa(JSON.stringify({ alg: "none", typ: "JWT" })).replaceAll("=", ""),
      btoa(JSON.stringify({ exp: 4_102_444_800, use: 1, cnf: { jkt: "x" } })).replaceAll("=", ""),
      "ignored",
    ].join(".");

    await expect(signer.verify(forged, Date.now())).rejects.toMatchObject({
      code: "invalid_credential",
    });
  });

  it("rejects an otherwise valid credential after its signed expiry", async () => {
    const signer = await Es256CapabilitySigner.create();
    const expired = await signer.sign({
      iss: "https://broker.example.test",
      jti: "credential-expired",
      grantId: "grant-expired",
      sub: "person-a",
      aud: "https://resource.example.test",
      action: "POST /records/42",
      scope: ["records:write"],
      cnf: { jkt: "thumbprint" },
      use: 1,
      iat: 1,
      exp: 2,
    });

    await expect(signer.verify(expired, Date.now())).rejects.toMatchObject({
      code: "invalid_credential",
    });
  });

  it("normalizes malformed compact-JWT signatures to a credential error", async () => {
    const signer = await Es256CapabilitySigner.create();
    const malformed = [
      encode({ alg: "ES256", typ: "JWT" }),
      encode({ exp: 4_102_444_800, use: 1, cnf: { jkt: "thumbprint" } }),
      "%",
    ].join(".");

    await expect(signer.verify(malformed, Date.now())).rejects.toMatchObject({
      code: "invalid_credential",
    });
  });

  it("normalizes malformed but thumbprint-shaped DPoP JWKs to a broker error", async () => {
    const now = Date.now();
    const malformedJwk: JsonWebKey = { kty: "EC", crv: "P-256", x: "!", y: "!" };
    const proof = {
      method: "POST",
      url: "https://resource.example.test/records/42",
      token: [
        encode({ alg: "ES256", typ: "JWT", jwk: malformedJwk }),
        encode({
          htm: "POST",
          htu: "https://resource.example.test/records/42",
          iat: Math.floor(now / 1000),
          jti: "bad-jwk",
        }),
        "AQ",
      ].join("."),
    };

    await expect(
      verifyDpopProof(proof, await jwkThumbprint(malformedJwk), now, new Map()),
    ).rejects.toMatchObject({ code: "dpop_proof_invalid" });
  });

  it("rejects non-finite DPoP times and missing or non-string replay IDs", async () => {
    const now = Date.now();
    const jwk: JsonWebKey = { kty: "EC", crv: "P-256", x: "!", y: "!" };
    const invalidPayloads = [
      { iat: "not-a-timestamp", jti: "replay-id" },
      { iat: Math.floor(now / 1000), jti: "" },
      { iat: Math.floor(now / 1000), jti: 42 },
    ];

    for (const payload of invalidPayloads) {
      await expect(
        verifyDpopProof(
          {
            method: "POST",
            url: "https://resource.example.test/records/42",
            token: [
              encode({ alg: "ES256", typ: "JWT", jwk }),
              encode({ htm: "POST", htu: "https://resource.example.test/records/42", ...payload }),
              "AQ",
            ].join("."),
          },
          "unused-thumbprint",
          now,
          new Map(),
        ),
      ).rejects.toMatchObject({ code: "dpop_proof_invalid" });
    }
  });
});
