"use client";

/**
 * Symmetric message encryption for Signal-derived sessions.
 *
 * `masterSecret` (base64url) is the X3DH output stored at `session_${peerId}`.
 * We feed it through SHA-256 + HKDF (with a fixed app-specific info string) so the
 * AES-GCM key isn't the raw shared secret on the wire. Each ciphertext carries a
 * fresh 12-byte IV, and the wire format is base64url(iv || ciphertext).
 *
 * Ratchet-derived per-message keys use the same wire format via
 * `encryptWithMessageKey` / `decryptWithMessageKey` (32-byte raw AES-256 keys).
 */

import { base64UrlToBytes, bytesToBase64Url } from "./cryptoService";

const HKDF_INFO = new TextEncoder().encode(
  "secure-messenger.signal.message-key.v1.AES-256-GCM",
);
const IV_BYTES = 12;
const AES_KEY_BITS = 256;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

async function deriveAesGcmKey(masterSecretBase64Url: string): Promise<CryptoKey> {
  const ikm = base64UrlToBytes(masterSecretBase64Url);
  const baseKey = await crypto.subtle.importKey("raw", ikm.buffer as ArrayBuffer, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(),
      info: HKDF_INFO,
    },
    baseKey,
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypt UTF-8 `plaintext` with the session masterSecret.
 * Returns base64url(iv || ciphertext) so the backend keeps treating it as opaque text.
 */
export async function encryptMessage(
  masterSecretBase64Url: string,
  plaintext: string,
): Promise<string> {
  if (!masterSecretBase64Url) throw new Error("encryptMessage: missing masterSecret");
  const key = await deriveAesGcmKey(masterSecretBase64Url);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintextBytes = textEncoder.encode(plaintext);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    key,
    plaintextBytes.buffer as ArrayBuffer,
  );
  const cipherBytes = new Uint8Array(cipherBuffer);
  const wire = new Uint8Array(IV_BYTES + cipherBytes.length);
  wire.set(iv, 0);
  wire.set(cipherBytes, IV_BYTES);
  return bytesToBase64Url(wire);
}

/**
 * Decrypt a wire string produced by `encryptMessage`. Throws on tag/key mismatch
 * (callers should map that to the safe placeholder UI).
 */
export async function decryptMessage(
  masterSecretBase64Url: string,
  wireBase64Url: string,
): Promise<string> {
  if (!masterSecretBase64Url) throw new Error("decryptMessage: missing masterSecret");
  if (!wireBase64Url) throw new Error("decryptMessage: missing ciphertext");
  const wire = base64UrlToBytes(wireBase64Url);
  if (wire.length <= IV_BYTES) {
    throw new Error("decryptMessage: wire payload too short for IV+ciphertext");
  }
  const iv = wire.slice(0, IV_BYTES);
  const cipherBytes = wire.slice(IV_BYTES);
  const key = await deriveAesGcmKey(masterSecretBase64Url);
  const plainBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    key,
    cipherBytes.buffer as ArrayBuffer,
  );
  return textDecoder.decode(plainBuffer);
}

async function importRawAesGcmKey(messageKey: Uint8Array): Promise<CryptoKey> {
  if (messageKey.length !== 32) {
    throw new Error("importRawAesGcmKey: expected 32-byte AES-256 key.");
  }
  return crypto.subtle.importKey(
    "raw",
    messageKey.buffer.slice(messageKey.byteOffset, messageKey.byteOffset + messageKey.byteLength) as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

/** AES-GCM with a chain-derived 32-byte key; wire = base64url(iv || ciphertext). */
export async function encryptWithMessageKey(messageKey: Uint8Array, plaintext: string): Promise<string> {
  const key = await importRawAesGcmKey(messageKey);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintextBytes = textEncoder.encode(plaintext);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    key,
    plaintextBytes.buffer.slice(
      plaintextBytes.byteOffset,
      plaintextBytes.byteOffset + plaintextBytes.byteLength,
    ) as ArrayBuffer,
  );
  const cipherBytes = new Uint8Array(cipherBuffer);
  const wire = new Uint8Array(IV_BYTES + cipherBytes.length);
  wire.set(iv, 0);
  wire.set(cipherBytes, IV_BYTES);
  return bytesToBase64Url(wire);
}

export async function decryptWithMessageKey(messageKey: Uint8Array, wireBase64Url: string): Promise<string> {
  const wire = base64UrlToBytes(wireBase64Url);
  if (wire.length <= IV_BYTES) {
    throw new Error("decryptWithMessageKey: wire payload too short.");
  }
  const iv = wire.slice(0, IV_BYTES);
  const cipherBytes = wire.slice(IV_BYTES);
  const key = await importRawAesGcmKey(messageKey);
  const plainBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    key,
    cipherBytes.buffer.slice(
      cipherBytes.byteOffset,
      cipherBytes.byteOffset + cipherBytes.byteLength,
    ) as ArrayBuffer,
  );
  return textDecoder.decode(plainBuffer);
}

export const ENCRYPTED_PLACEHOLDER =
  "🔒 Encrypted message (click to establish session)";

/** Decrypt or return the placeholder so the UI never shows raw ciphertext on failure. */
export async function decryptOrPlaceholder(
  masterSecretBase64Url: string | null,
  wireBase64Url: string,
): Promise<string> {
  if (!masterSecretBase64Url) return ENCRYPTED_PLACEHOLDER;
  try {
    return await decryptMessage(masterSecretBase64Url, wireBase64Url);
  } catch (error) {
    console.warn("[Encryption] decryptMessage failed, showing placeholder:", error);
    return ENCRYPTED_PLACEHOLDER;
  }
}
