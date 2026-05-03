import type { PrivateIdentityKey } from "./cryptoService";
import { base64UrlToBytes, bytesToBase64Url } from "./cryptoService";

/** Standard Base64 (RFC 4648) for opaque blobs in JSON when interoping outside base64url. */
export function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function base64ToUint8Array(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/** Same as `bytesToBase64Url` / `base64UrlToBytes` — explicit aliases for storage helpers. */
export function binaryToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64Url(bytes);
}

export function base64UrlToBinary(value: string): Uint8Array {
  return base64UrlToBytes(value);
}

/**
 * Build a `PrivateIdentityKey` from raw key material (e.g. after reading `ArrayBuffer` from a file API).
 * Stored form matches the rest of the stack: base64url strings.
 */
export function identityKeyPairFromArrayBuffers(
  publicKey: ArrayBuffer | Uint8Array,
  privateKey: ArrayBuffer | Uint8Array,
): PrivateIdentityKey {
  const pub = publicKey instanceof Uint8Array ? publicKey : new Uint8Array(publicKey);
  const priv = privateKey instanceof Uint8Array ? privateKey : new Uint8Array(privateKey);
  return {
    algorithm: "Ed25519",
    publicKey: bytesToBase64Url(pub),
    privateKey: bytesToBase64Url(priv),
  };
}

export function identityKeyPairToArrayBuffers(ik: PrivateIdentityKey): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  return {
    publicKey: base64UrlToBytes(ik.publicKey),
    privateKey: base64UrlToBytes(ik.privateKey),
  };
}
