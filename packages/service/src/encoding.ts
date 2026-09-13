const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function toBase64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) {
    binary += String.fromCodePoint(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/u.test(value)) {
    throw new Error("invalid base64url");
  }
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(`${normalized}${padding}`);
  return Uint8Array.from(binary, (character) => character.codePointAt(0) ?? 0);
}

export function encodeJson(value: unknown): string {
  return toBase64Url(encoder.encode(JSON.stringify(value)));
}

export function decodeJson<T>(value: string): T {
  return JSON.parse(decoder.decode(fromBase64Url(value))) as T;
}

export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

export function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}

export async function sha256(value: string | Uint8Array): Promise<string> {
  const bytes = typeof value === "string" ? utf8(value) : value;
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes))));
}

export function splitScope(scope: string | undefined): readonly string[] {
  if (!scope) {
    return [];
  }
  return [...new Set(scope.split(/\s+/u).filter(Boolean))];
}

export function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = utf8(left);
  const rightBytes = utf8(right);
  const longest = Math.max(leftBytes.length, rightBytes.length);
  let difference = leftBytes.length ^ rightBytes.length;
  for (let index = 0; index < longest; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return difference === 0;
}
