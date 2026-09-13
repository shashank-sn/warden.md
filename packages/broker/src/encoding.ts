const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function encodeBase64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) {
    binary += String.fromCodePoint(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(`${normalized}${padding}`);
  return Uint8Array.from(binary, (character) => character.codePointAt(0) ?? 0);
}

export function encodeJson(value: unknown): string {
  return encodeBase64Url(encoder.encode(JSON.stringify(value)));
}

export function decodeJson<T>(value: string): T {
  return JSON.parse(decoder.decode(decodeBase64Url(value))) as T;
}

export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

export function asBufferSource(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

export async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", asBufferSource(value)));
}

export function randomId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID()}`;
}
