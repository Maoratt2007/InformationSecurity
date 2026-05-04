"use client";

/**
 * Client-side encryption for Signal peer-session JSON stored in Supabase `ratchet_key_id`.
 *
 * **Primary key (v2):** AES-256-GCM key derived from the Supabase `user_id` (UUID string).
 * Same user always gets the same key after logout/login, so session blobs stay decryptable
 * even when the Ed25519 identity key file in localStorage is recreated elsewhere.
 *
 * **Legacy key (v1):** HKDF from the persistent identity *private* key — still attempted on
 * decrypt for older rows written before v2.
 *
 * Wire formats for `ratchet_key_id` (text):
 *   - **v2 (preferred):** `base64(IV) : base64(ciphertext)` — IV and ciphertext are separate,
 *     so the IV used at encrypt time is always explicit.
 *   - **v1 (legacy):** single standard-Base64 of `12-byte IV || ciphertext` (packed).
 */

const IV_BYTES = 12;

const SESSION_WRAP_V2_PREFIX = new TextEncoder().encode("secure-messenger.session-wrap.v2|");

/** Legacy HKDF info when the wrap key was derived from the Ed25519 identity private key. */
const SESSION_KEY_HKDF_INFO = new TextEncoder().encode(
  "secure-messenger.session-storage-key.v1",
);

// ---------- internal Base64 helpers (standard RFC 4648) ----------

function stdBase64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function stdBase64Decode(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function toAlignedBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

function base64UrlToBytes(value: string): Uint8Array {
  const b64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  return stdBase64Decode(b64);
}

function previewBytes(b: Uint8Array, count = 4): string {
  return Array.from(b.slice(0, count))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

// ---------- Stable wrap key from Supabase user id ----------

/**
 * Derive a stable AES-256-GCM key from `userId` (Supabase auth UUID). Deterministic for the
 * same string so logout/login does not lose the ability to unwrap `ratchet_key_id`.
 */
export async function deriveSessionWrapKeyFromUserId(userId: string): Promise<CryptoKey> {
  const normalized = userId.trim();
  const material = new Uint8Array(SESSION_WRAP_V2_PREFIX.length + normalized.length);
  material.set(SESSION_WRAP_V2_PREFIX, 0);
  material.set(new TextEncoder().encode(normalized), SESSION_WRAP_V2_PREFIX.length);
  const hashBuf = await crypto.subtle.digest("SHA-256", toAlignedBuffer(material));
  return crypto.subtle.importKey(
    "raw",
    hashBuf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * @deprecated Legacy: derive AES-GCM from identity private key (base64url). Used only to
 * decrypt session rows written before user-id–based wrap keys.
 */
export async function deriveSessionStorageKey(
  identityPrivateKeyBase64Url: string,
): Promise<CryptoKey> {
  const keyBytes = base64UrlToBytes(identityPrivateKeyBase64Url);
  const rawKey = await crypto.subtle.importKey(
    "raw",
    toAlignedBuffer(keyBytes),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: SESSION_KEY_HKDF_INFO,
    },
    rawKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * AES-256-GCM encrypt. Wire: `base64(IV):base64(ciphertext)` (v2).
 */
export async function encryptSessionBlob(key: CryptoKey, plaintext: string): Promise<string> {
  if (!plaintext || plaintext.length === 0) {
    throw new Error("encryptSessionBlob: plaintext is empty.");
  }
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const encoded = new TextEncoder().encode(plaintext);
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toAlignedBuffer(iv) },
    key,
    toAlignedBuffer(encoded),
  );
  const cipherBytes = new Uint8Array(cipherBuf);
  const wire = `${stdBase64Encode(iv)}:${stdBase64Encode(cipherBytes)}`;
  console.log(
    `[SessionEncryption] encrypt v2: ivBytes=${iv.length} (preview ${previewBytes(iv)}…) cipherBytes=${cipherBytes.length}`,
  );
  return wire;
}

/**
 * Decrypt a blob from `encryptSessionBlob` (v2 `iv:cipher`) or legacy v1 packed Base64.
 */
export async function decryptSessionBlob(
  key: CryptoKey,
  ciphertextBase64: string,
): Promise<string | null> {
  if (!ciphertextBase64?.trim()) {
    console.warn("[SessionEncryption] decrypt: empty ciphertext.");
    return null;
  }

  const trimmed = ciphertextBase64.trim();
  let iv: Uint8Array;
  let cipher: Uint8Array;

  const colonIdx = trimmed.indexOf(":");
  if (colonIdx > 0 && colonIdx < trimmed.length - 1) {
    try {
      const ivB64 = trimmed.slice(0, colonIdx);
      const cipherB64 = trimmed.slice(colonIdx + 1);
      iv = stdBase64Decode(ivB64);
      cipher = stdBase64Decode(cipherB64);
    } catch (error) {
      console.warn("[SessionEncryption] decrypt v2: Base64 decode failed.", error);
      return null;
    }
    if (iv.length !== IV_BYTES) {
      console.warn(`[SessionEncryption] decrypt v2: expected IV length ${IV_BYTES}, got ${iv.length}.`);
      return null;
    }
    console.log(
      `[SessionEncryption] decrypt v2: ivBytes=${iv.length} (preview ${previewBytes(iv)}…) cipherBytes=${cipher.length}`,
    );
  } else {
    let wire: Uint8Array;
    try {
      wire = stdBase64Decode(trimmed);
    } catch (error) {
      console.warn("[SessionEncryption] decrypt v1: Base64 decode failed.", error);
      return null;
    }
    if (wire.length <= IV_BYTES) {
      console.warn(
        `[SessionEncryption] decrypt v1: wire too short (${wire.length} bytes) — IV missing.`,
      );
      return null;
    }
    iv = wire.slice(0, IV_BYTES);
    cipher = wire.slice(IV_BYTES);
    console.log(
      `[SessionEncryption] decrypt v1 (packed): ivBytes=${iv.length} (preview ${previewBytes(iv)}…) cipherBytes=${cipher.length}`,
    );
  }

  try {
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toAlignedBuffer(iv) },
      key,
      toAlignedBuffer(cipher),
    );
    return new TextDecoder().decode(plainBuf);
  } catch (error) {
    console.warn(
      "[SessionEncryption] AES-GCM decrypt failed (wrong key, corrupt blob, or truncated ciphertext):",
      error,
    );
    return null;
  }
}
