import { decodeJson, encodeJson, toArrayBuffer, utf8 } from "./encoding.js";
import { OAuthError } from "./errors.js";
import type {
  Clock,
  PublicJwk,
  ReplayRepository,
  SigningKey,
  VerificationKeyResolver,
} from "./types.js";

export interface JwtHeader {
  alg: "ES256";
  kid: string;
  typ?: "JWT";
}

export interface JwtClaims {
  iss: string;
  sub: string;
  aud: string | readonly string[];
  exp: number;
  iat: number;
  jti: string;
  nbf?: number;
  [claim: string]: unknown;
}

export interface VerifiedJwt {
  header: JwtHeader;
  claims: JwtClaims;
}

export interface VerifyJwtOptions {
  keyResolver: VerificationKeyResolver;
  expectedIssuer: string;
  expectedAudience: string;
  clock: Clock;
  replayRepository?: ReplayRepository;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFiniteInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && Number.isInteger(value);
}

function isAudience(value: unknown): value is string | readonly string[] {
  return (
    typeof value === "string" ||
    (Array.isArray(value) && value.length > 0 && value.every((entry) => typeof entry === "string"))
  );
}

function audienceContains(audience: string | readonly string[], expectedAudience: string): boolean {
  return typeof audience === "string"
    ? audience === expectedAudience
    : audience.includes(expectedAudience);
}

function parseHeader(value: unknown): JwtHeader {
  if (!isRecord(value) || value.alg !== "ES256" || typeof value.kid !== "string" || !value.kid) {
    throw new OAuthError("invalid_grant");
  }
  if (value.typ !== undefined && value.typ !== "JWT") {
    throw new OAuthError("invalid_grant");
  }
  return { alg: "ES256", kid: value.kid, ...(value.typ === "JWT" ? { typ: "JWT" } : {}) };
}

function parseClaims(value: unknown): JwtClaims {
  if (
    !isRecord(value) ||
    typeof value.iss !== "string" ||
    !value.iss ||
    typeof value.sub !== "string" ||
    !value.sub ||
    !isAudience(value.aud) ||
    !isFiniteInteger(value.exp) ||
    !isFiniteInteger(value.iat) ||
    typeof value.jti !== "string" ||
    !value.jti ||
    (value.nbf !== undefined && !isFiniteInteger(value.nbf))
  ) {
    throw new OAuthError("invalid_grant");
  }
  return value as JwtClaims;
}

export async function createEs256SigningKey(kid: string): Promise<SigningKey> {
  const keyPair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return {
    kid,
    privateKey: keyPair.privateKey,
    publicJwk: { ...publicJwk, kid, use: "sig", alg: "ES256" },
  };
}

export async function importEs256SigningKey(
  kid: string,
  privateJwk: JsonWebKey,
): Promise<SigningKey> {
  if (
    privateJwk.kty !== "EC" ||
    privateJwk.crv !== "P-256" ||
    !privateJwk.d ||
    !privateJwk.x ||
    !privateJwk.y
  ) {
    throw new Error("SERVICE_SIGNING_JWK must be an ES256 private JWK");
  }
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  return {
    kid,
    privateKey,
    publicJwk: {
      kty: "EC",
      crv: "P-256",
      x: privateJwk.x,
      y: privateJwk.y,
      kid,
      use: "sig",
      alg: "ES256",
    },
  };
}

export async function importEs256VerificationKey(jwk: JsonWebKey): Promise<CryptoKey> {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
    throw new Error("expected an ES256 public JWK");
  }
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, [
    "verify",
  ]);
}

export class StaticVerificationKeys implements VerificationKeyResolver {
  private readonly keys = new Map<string, CryptoKey>();

  public constructor(
    private readonly issuer: string,
    keys: Readonly<Record<string, CryptoKey>>,
  ) {
    for (const [kid, key] of Object.entries(keys)) {
      this.keys.set(kid, key);
    }
  }

  public async resolve(issuer: string, kid: string): Promise<CryptoKey | undefined> {
    return issuer === this.issuer ? this.keys.get(kid) : undefined;
  }
}

export async function createStaticVerificationKeys(
  issuer: string,
  signingKey: SigningKey,
  retiredKeys: readonly PublicJwk[] = [],
): Promise<StaticVerificationKeys> {
  return createVerificationKeysFromJwks(issuer, {
    keys: [signingKey.publicJwk, ...retiredKeys],
  });
}

export async function createVerificationKeysFromJwks(
  issuer: string,
  value: { keys: readonly PublicJwk[] },
): Promise<StaticVerificationKeys> {
  const keys: Record<string, CryptoKey> = {};
  for (const jwk of value.keys) {
    if (typeof jwk.kid !== "string" || !jwk.kid) {
      throw new Error("every trusted JWK needs a kid");
    }
    if (keys[jwk.kid]) {
      throw new Error(`duplicate trusted JWK kid: ${jwk.kid}`);
    }
    keys[jwk.kid] = await importEs256VerificationKey(jwk);
  }
  return new StaticVerificationKeys(issuer, keys);
}

export async function signJwt(claims: JwtClaims, signingKey: SigningKey): Promise<string> {
  const header: JwtHeader = { alg: "ES256", kid: signingKey.kid, typ: "JWT" };
  const encodedHeader = encodeJson(header);
  const encodedClaims = encodeJson(claims);
  const message = `${encodedHeader}.${encodedClaims}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signingKey.privateKey,
    toArrayBuffer(utf8(message)),
  );
  const binary = new Uint8Array(signature);
  let signatureString = "";
  for (const byte of binary) {
    signatureString += String.fromCodePoint(byte);
  }
  return `${message}.${btoa(signatureString).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "")}`;
}

function decodeSignature(encoded: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    throw new OAuthError("invalid_grant");
  }
  const normalized = encoded.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(`${normalized}${"=".repeat((4 - (normalized.length % 4)) % 4)}`);
  return Uint8Array.from(binary, (character) => character.codePointAt(0) ?? 0);
}

export async function verifyJwt(token: string, options: VerifyJwtOptions): Promise<VerifiedJwt> {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw new OAuthError("invalid_grant");
  }
  const [encodedHeader, encodedClaims, encodedSignature] = parts as [string, string, string];
  let header: JwtHeader;
  let claims: JwtClaims;
  try {
    header = parseHeader(decodeJson<unknown>(encodedHeader));
    claims = parseClaims(decodeJson<unknown>(encodedClaims));
  } catch (error) {
    if (error instanceof OAuthError) {
      throw error;
    }
    throw new OAuthError("invalid_grant");
  }

  if (
    claims.iss !== options.expectedIssuer ||
    !audienceContains(claims.aud, options.expectedAudience)
  ) {
    throw new OAuthError("invalid_grant");
  }
  const nowSeconds = Math.floor(options.clock.now() / 1000);
  if (claims.exp <= nowSeconds || claims.iat > nowSeconds + 60 || (claims.nbf ?? 0) > nowSeconds) {
    throw new OAuthError("invalid_grant");
  }
  const key = await options.keyResolver.resolve(claims.iss, header.kid);
  if (!key) {
    throw new OAuthError("invalid_grant");
  }
  let signature: Uint8Array;
  try {
    signature = decodeSignature(encodedSignature);
  } catch (error) {
    if (error instanceof OAuthError) {
      throw error;
    }
    throw new OAuthError("invalid_grant");
  }
  const verified = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    toArrayBuffer(signature),
    toArrayBuffer(utf8(`${encodedHeader}.${encodedClaims}`)),
  );
  if (!verified) {
    throw new OAuthError("invalid_grant");
  }
  if (options.replayRepository) {
    const unused = await options.replayRepository.markIfUnused(
      { id: `${claims.iss}:${claims.jti}`, expiresAt: claims.exp * 1000 },
      options.clock.now(),
    );
    if (!unused) {
      throw new OAuthError("invalid_grant");
    }
  }
  return { header, claims };
}

function publicJwk(jwk: PublicJwk): PublicJwk {
  const { d: _privatePart, ...value } = jwk;
  return value;
}

export function jwks(
  signingKey: SigningKey,
  retiredKeys: readonly PublicJwk[] = [],
): { keys: readonly PublicJwk[] } {
  return {
    keys: [
      { ...publicJwk(signingKey.publicJwk), kid: signingKey.kid, use: "sig", alg: "ES256" },
      ...retiredKeys.map(publicJwk),
    ],
  };
}
