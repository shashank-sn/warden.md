import {
  asBufferSource,
  decodeBase64Url,
  decodeJson,
  encodeBase64Url,
  encodeJson,
  randomId,
  sha256,
  utf8,
} from "./encoding.js";
import { BrokerError } from "./errors.js";
import type { CapabilityClaims, Clock, DpopProof } from "./types.js";

type JwtHeader = {
  alg: "ES256";
  kid?: string;
  typ: "JWT";
  jwk?: JsonWebKey;
};

export type PublicJwk = JsonWebKey & { kid?: string };

export interface JsonWebKeySet {
  keys: readonly PublicJwk[];
}

type DpopPayload = {
  htm: string;
  htu: string;
  iat: number;
  jti: string;
};

export interface DpopSession {
  thumbprint: string;
  proof(method: string, url: string, clock: Clock): Promise<DpopProof>;
}

export interface CapabilityVerifier {
  verify(
    token: string,
    now: number,
    options?: { allowExpired?: boolean },
  ): Promise<CapabilityClaims>;
}

export interface CapabilitySigner extends CapabilityVerifier {
  publicJwk(): Promise<PublicJwk>;
  sign(claims: CapabilityClaims): Promise<string>;
}

type ParsedCapabilityToken = {
  header: JwtHeader;
  claims: CapabilityClaims;
  signature: Uint8Array;
  unsigned: string;
};

export class Es256CapabilitySigner implements CapabilitySigner {
  private constructor(
    private readonly keyPair: CryptoKeyPair,
    private readonly keyId: string,
  ) {}

  public static async create(keyId = randomId("kid")): Promise<Es256CapabilitySigner> {
    const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    return new Es256CapabilitySigner(keyPair, keyId);
  }

  /** Imports the deployment-owned ES256 key instead of generating per-isolate authority. */
  public static async fromPrivateJwk(
    keyId: string,
    privateJwk: JsonWebKey,
  ): Promise<Es256CapabilitySigner> {
    if (
      !keyId ||
      privateJwk.kty !== "EC" ||
      privateJwk.crv !== "P-256" ||
      !privateJwk.d ||
      !privateJwk.x ||
      !privateJwk.y
    ) {
      throw new Error("expected an ES256 private JWK");
    }
    try {
      const [privateKey, publicKey] = await Promise.all([
        crypto.subtle.importKey("jwk", privateJwk, { name: "ECDSA", namedCurve: "P-256" }, false, [
          "sign",
        ]),
        crypto.subtle.importKey(
          "jwk",
          {
            kty: "EC",
            crv: "P-256",
            x: privateJwk.x,
            y: privateJwk.y,
          },
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["verify"],
        ),
      ]);
      return new Es256CapabilitySigner({ privateKey, publicKey }, keyId);
    } catch {
      throw new Error("expected an ES256 private JWK");
    }
  }

  public async publicJwk(): Promise<PublicJwk> {
    return { ...(await crypto.subtle.exportKey("jwk", this.keyPair.publicKey)), kid: this.keyId };
  }

  public async sign(claims: CapabilityClaims): Promise<string> {
    const header: JwtHeader = { alg: "ES256", kid: this.keyId, typ: "JWT" };
    const unsigned = `${encodeJson(header)}.${encodeJson(claims)}`;
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      this.keyPair.privateKey,
      asBufferSource(utf8(unsigned)),
    );
    return `${unsigned}.${encodeBase64Url(new Uint8Array(signature))}`;
  }

  public async verify(
    token: string,
    now: number,
    options: { allowExpired?: boolean } = {},
  ): Promise<CapabilityClaims> {
    const parsed = parseCapabilityToken(token);
    if (parsed.header.kid !== this.keyId) {
      throw new BrokerError("invalid_credential");
    }
    await verifyCapabilitySignature(this.keyPair.publicKey, parsed);
    return validateCapabilityClaims(parsed.claims, now, options);
  }
}

/** Verifies broker credentials from a public JWKS without access to the broker signing key. */
export class Es256CapabilityVerifier implements CapabilityVerifier {
  private constructor(private readonly keys: ReadonlyMap<string, CryptoKey>) {}

  public static async fromJwks(jwks: JsonWebKeySet): Promise<Es256CapabilityVerifier> {
    if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) {
      throw new Error("expected a non-empty ES256 JWKS");
    }
    const keys = new Map<string, CryptoKey>();
    for (const jwk of jwks.keys) {
      if (
        !jwk.kid ||
        jwk.kty !== "EC" ||
        jwk.crv !== "P-256" ||
        !jwk.x ||
        !jwk.y ||
        jwk.d !== undefined ||
        keys.has(jwk.kid)
      ) {
        throw new Error("expected a non-empty ES256 JWKS");
      }
      try {
        keys.set(
          jwk.kid,
          await crypto.subtle.importKey(
            "jwk",
            { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
            { name: "ECDSA", namedCurve: "P-256" },
            false,
            ["verify"],
          ),
        );
      } catch {
        throw new Error("expected a non-empty ES256 JWKS");
      }
    }
    return new Es256CapabilityVerifier(keys);
  }

  public async verify(
    token: string,
    now: number,
    options: { allowExpired?: boolean } = {},
  ): Promise<CapabilityClaims> {
    const parsed = parseCapabilityToken(token);
    const key = parsed.header.kid ? this.keys.get(parsed.header.kid) : undefined;
    if (!key) {
      throw new BrokerError("invalid_credential");
    }
    await verifyCapabilitySignature(key, parsed);
    return validateCapabilityClaims(parsed.claims, now, options);
  }
}

function parseCapabilityToken(token: string): ParsedCapabilityToken {
  const [headerEncoded, payloadEncoded, signatureEncoded, ...rest] = token.split(".");
  if (!headerEncoded || !payloadEncoded || !signatureEncoded || rest.length > 0) {
    throw new BrokerError("invalid_credential");
  }
  let header: JwtHeader;
  let claims: CapabilityClaims;
  let signature: Uint8Array;
  try {
    header = decodeJson<JwtHeader>(headerEncoded);
    claims = decodeJson<CapabilityClaims>(payloadEncoded);
    signature = decodeBase64Url(signatureEncoded);
  } catch {
    throw new BrokerError("invalid_credential");
  }
  if (header.alg !== "ES256" || header.typ !== "JWT") {
    throw new BrokerError("invalid_credential");
  }
  return { header, claims, signature, unsigned: `${headerEncoded}.${payloadEncoded}` };
}

async function verifyCapabilitySignature(
  key: CryptoKey,
  parsed: ParsedCapabilityToken,
): Promise<void> {
  let valid: boolean;
  try {
    valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      asBufferSource(parsed.signature),
      asBufferSource(utf8(parsed.unsigned)),
    );
  } catch {
    throw new BrokerError("invalid_credential");
  }
  if (!valid) {
    throw new BrokerError("invalid_credential");
  }
}

function validateCapabilityClaims(
  claims: CapabilityClaims,
  now: number,
  options: { allowExpired?: boolean },
): CapabilityClaims {
  if (
    !Number.isFinite(claims.exp) ||
    claims.exp <= 0 ||
    (!options.allowExpired && claims.exp * 1000 <= now) ||
    claims.use !== 1 ||
    !claims.cnf?.jkt
  ) {
    throw new BrokerError("invalid_credential");
  }
  return claims;
}

export async function createDpopSession(): Promise<DpopSession> {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const thumbprint = await jwkThumbprint(publicJwk);

  return {
    thumbprint,
    async proof(method, url, clock) {
      const header: JwtHeader = { alg: "ES256", typ: "JWT", jwk: publicJwk };
      const payload: DpopPayload = {
        htm: method.toUpperCase(),
        htu: url,
        iat: Math.floor(clock.now() / 1000),
        jti: randomId("dpop"),
      };
      const unsigned = `${encodeJson(header)}.${encodeJson(payload)}`;
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.privateKey,
        asBufferSource(utf8(unsigned)),
      );
      return { token: `${unsigned}.${encodeBase64Url(new Uint8Array(signature))}`, method, url };
    },
  };
}

export async function verifyDpopProof(
  proof: DpopProof,
  expectedThumbprint: string,
  now: number,
  seen: Map<string, number>,
): Promise<void> {
  const [headerEncoded, payloadEncoded, signatureEncoded, ...rest] = proof.token.split(".");
  if (!headerEncoded || !payloadEncoded || !signatureEncoded || rest.length > 0) {
    throw new BrokerError("dpop_proof_invalid");
  }

  let header: JwtHeader;
  let payload: DpopPayload;
  try {
    header = decodeJson<JwtHeader>(headerEncoded);
    payload = decodeJson<DpopPayload>(payloadEncoded);
  } catch {
    throw new BrokerError("dpop_proof_invalid");
  }

  if (
    header.alg !== "ES256" ||
    header.typ !== "JWT" ||
    !header.jwk ||
    typeof payload.iat !== "number" ||
    !Number.isFinite(payload.iat) ||
    typeof payload.jti !== "string" ||
    !payload.jti ||
    payload.htm !== proof.method.toUpperCase() ||
    payload.htu !== proof.url ||
    Math.abs(now - payload.iat * 1000) > 300_000
  ) {
    throw new BrokerError("dpop_proof_invalid");
  }

  let thumbprint: string;
  try {
    thumbprint = await jwkThumbprint(header.jwk);
  } catch {
    throw new BrokerError("dpop_proof_invalid");
  }
  if (thumbprint !== expectedThumbprint) {
    throw new BrokerError("wrong_dpop_key");
  }

  let valid: boolean;
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      header.jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      asBufferSource(decodeBase64Url(signatureEncoded)),
      asBufferSource(utf8(`${headerEncoded}.${payloadEncoded}`)),
    );
  } catch {
    throw new BrokerError("dpop_proof_invalid");
  }
  if (!valid) {
    throw new BrokerError("dpop_proof_invalid");
  }

  for (const [jti, expiresAt] of seen) {
    if (expiresAt <= now) {
      seen.delete(jti);
    }
  }
  if (seen.has(payload.jti)) {
    throw new BrokerError("dpop_proof_invalid");
  }
  seen.set(payload.jti, now + 300_000);
}

export async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  if (!jwk.kty || !jwk.crv || !jwk.x || !jwk.y) {
    throw new BrokerError("dpop_proof_invalid");
  }
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return encodeBase64Url(await sha256(utf8(canonical)));
}
