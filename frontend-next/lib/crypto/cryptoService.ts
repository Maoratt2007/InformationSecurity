import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { openDB, type DBSchema, type IDBPDatabase } from "idb";

export type Base64UrlString = string;

export interface PublicIdentityKey {
  algorithm: "Ed25519";
  publicKey: Base64UrlString;
}

export interface PrivateIdentityKey extends PublicIdentityKey {
  privateKey: Base64UrlString;
}

export interface PublicSignedPreKey {
  algorithm: "X25519";
  keyId: number;
  publicKey: Base64UrlString;
  signature: Base64UrlString;
  signatureAlgorithm: "Ed25519";
}

export interface PrivateSignedPreKey {
  algorithm: "X25519";
  keyId: number;
  publicKey: Base64UrlString;
  signature: Base64UrlString;
  signatureAlgorithm: "Ed25519";
  privateKey: Base64UrlString;
}

export interface PublicOneTimePreKey {
  algorithm: "X25519";
  keyId: number;
  publicKey: Base64UrlString;
}

export interface PrivateOneTimePreKey extends PublicOneTimePreKey {
  privateKey: Base64UrlString;
}

export interface PublicRegistrationBundle {
  deviceId: string;
  identityKey: PublicIdentityKey;
  signedPreKey: PublicSignedPreKey;
  oneTimePreKeys: PublicOneTimePreKey[];
  createdAt: string;
}

export interface PrivateRegistrationBundle {
  deviceId: string;
  identityKey: PrivateIdentityKey;
  signedPreKey: PrivateSignedPreKey;
  oneTimePreKeys: PrivateOneTimePreKey[];
  createdAt: string;
}

export interface SignalRegistrationResult {
  publicBundle: PublicRegistrationBundle;
  privateBundle: PrivateRegistrationBundle;
  payload: SignalRegistrationPayload;
}

export interface GenerateRegistrationKeysOptions {
  deviceId?: string;
  signedPreKeyId?: number;
  oneTimePreKeyCount?: number;
  oneTimePreKeyStartId?: number;
}

export interface SignalRegistrationPayload {
  device_id: string;
  identity_key_public: Base64UrlString;
  signed_pre_key_id: number;
  signed_pre_key_public: Base64UrlString;
  signed_pre_key_signature: Base64UrlString;
  one_time_pre_keys: Array<{
    key_id: string;
    public_key: Base64UrlString;
  }>;
}

export type RegistrationKeyBundle = SignalRegistrationResult;
export type BackendKeyBundlePayload = SignalRegistrationPayload;

export interface StorePrivateBundleOptions {
  userId: string;
  deviceId?: string;
  privateBundle: PrivateRegistrationBundle;
}

export interface StoredPrivateBundleRecord {
  storageKey: string;
  userId: string;
  deviceId: string;
  privateBundle: PrivateRegistrationBundle;
  savedAt: string;
}

interface PrivateKeyDatabase extends DBSchema {
  privateBundles: {
    key: string;
    value: StoredPrivateBundleRecord;
    indexes: {
      "by-user-id": string;
    };
  };
}

const DEFAULT_DEVICE_ID = "primary";
const DEFAULT_SIGNED_PRE_KEY_ID = 1;
const DEFAULT_ONE_TIME_PRE_KEY_COUNT = 50;
const DEFAULT_ONE_TIME_PRE_KEY_START_ID = 1;
const MAX_ONE_TIME_PRE_KEY_COUNT = 500;
const PRIVATE_KEY_DB_NAME = "secure-messenger-private-keys";
const PRIVATE_KEY_DB_VERSION = 1;
const SIGNED_PRE_KEY_SIGNATURE_CONTEXT = "secure-messenger.registration.signed-pre-key.v1";

const textEncoder = new TextEncoder();

export function generateIdentityKeyPair(): PrivateIdentityKey {
  // The identity key is the long-term Ed25519 signing key used to authenticate pre-keys.
  const { secretKey, publicKey } = ed25519.keygen();

  return {
    algorithm: "Ed25519",
    publicKey: bytesToBase64Url(publicKey),
    privateKey: bytesToBase64Url(secretKey),
  };
}

export function generateSignedPreKey(identityKey: PrivateIdentityKey, keyId = DEFAULT_SIGNED_PRE_KEY_ID) {
  assertPositiveInteger(keyId, "Signed pre-key ID");

  // The signed pre-key is an X25519 Diffie-Hellman key authenticated by the identity key.
  const { secretKey, publicKey } = x25519.keygen();
  const signatureMessage = buildSignedPreKeySignatureMessage(keyId, publicKey);
  const signature = ed25519.sign(signatureMessage, base64UrlToBytes(identityKey.privateKey));

  return {
    publicSignedPreKey: {
      algorithm: "X25519",
      keyId,
      publicKey: bytesToBase64Url(publicKey),
      signature: bytesToBase64Url(signature),
      signatureAlgorithm: "Ed25519",
    } satisfies PublicSignedPreKey,
    privateSignedPreKey: {
      algorithm: "X25519",
      keyId,
      publicKey: bytesToBase64Url(publicKey),
      signature: bytesToBase64Url(signature),
      signatureAlgorithm: "Ed25519",
      privateKey: bytesToBase64Url(secretKey),
    } satisfies PrivateSignedPreKey,
  };
}

export function generateOneTimePreKeys(
  count = DEFAULT_ONE_TIME_PRE_KEY_COUNT,
  startId = DEFAULT_ONE_TIME_PRE_KEY_START_ID,
) {
  assertPositiveInteger(count, "One-time pre-key count");
  assertPositiveInteger(startId, "One-time pre-key start ID");

  if (count > MAX_ONE_TIME_PRE_KEY_COUNT) {
    throw new Error(`One-time pre-key count must not exceed ${MAX_ONE_TIME_PRE_KEY_COUNT}.`);
  }

  const publicOneTimePreKeys: PublicOneTimePreKey[] = [];
  const privateOneTimePreKeys: PrivateOneTimePreKey[] = [];

  // One-time pre-keys provide asynchronous session setup for the first message from a sender.
  for (let index = 0; index < count; index += 1) {
    const keyId = startId + index;
    const { secretKey, publicKey } = x25519.keygen();
    const encodedPublicKey = bytesToBase64Url(publicKey);

    publicOneTimePreKeys.push({
      algorithm: "X25519",
      keyId,
      publicKey: encodedPublicKey,
    });

    privateOneTimePreKeys.push({
      algorithm: "X25519",
      keyId,
      publicKey: encodedPublicKey,
      privateKey: bytesToBase64Url(secretKey),
    });
  }

  return {
    publicOneTimePreKeys,
    privateOneTimePreKeys,
  };
}

export function generateSignalRegistrationKeys(
  options: GenerateRegistrationKeysOptions = {},
): SignalRegistrationResult {
  const deviceId = options.deviceId ?? DEFAULT_DEVICE_ID;
  const createdAt = new Date().toISOString();
  const identityKey = generateIdentityKeyPair();
  const { publicSignedPreKey, privateSignedPreKey } = generateSignedPreKey(
    identityKey,
    options.signedPreKeyId ?? DEFAULT_SIGNED_PRE_KEY_ID,
  );
  const { publicOneTimePreKeys, privateOneTimePreKeys } = generateOneTimePreKeys(
    options.oneTimePreKeyCount ?? DEFAULT_ONE_TIME_PRE_KEY_COUNT,
    options.oneTimePreKeyStartId ?? DEFAULT_ONE_TIME_PRE_KEY_START_ID,
  );

  const publicBundle: PublicRegistrationBundle = {
    deviceId,
    identityKey: {
      algorithm: identityKey.algorithm,
      publicKey: identityKey.publicKey,
    },
    signedPreKey: publicSignedPreKey,
    oneTimePreKeys: publicOneTimePreKeys,
    createdAt,
  };

  const privateBundle: PrivateRegistrationBundle = {
    deviceId,
    identityKey,
    signedPreKey: privateSignedPreKey,
    oneTimePreKeys: privateOneTimePreKeys,
    createdAt,
  };

  const payload = toBackendKeyBundlePayload(publicBundle);
  const result: SignalRegistrationResult = {
    publicBundle,
    privateBundle,
    payload,
  };

  logSignalRegistrationResult(result);

  return result;
}

export const generateRegistrationKeys = generateSignalRegistrationKeys;
export const generateRegistrationBundle = generateSignalRegistrationKeys;

export function toBackendKeyBundlePayload(
  publicBundle: PublicRegistrationBundle,
): SignalRegistrationPayload {
  return {
    device_id: publicBundle.deviceId,
    identity_key_public: publicBundle.identityKey.publicKey,
    signed_pre_key_id: publicBundle.signedPreKey.keyId,
    signed_pre_key_public: publicBundle.signedPreKey.publicKey,
    signed_pre_key_signature: publicBundle.signedPreKey.signature,
    one_time_pre_keys: publicBundle.oneTimePreKeys.map((key) => ({
      key_id: String(key.keyId),
      public_key: key.publicKey,
    })),
  };
}

export function verifySignedPreKey(publicBundle: PublicRegistrationBundle): boolean {
  return ed25519.verify(
    base64UrlToBytes(publicBundle.signedPreKey.signature),
    buildSignedPreKeySignatureMessage(
      publicBundle.signedPreKey.keyId,
      base64UrlToBytes(publicBundle.signedPreKey.publicKey),
    ),
    base64UrlToBytes(publicBundle.identityKey.publicKey),
    { zip215: false },
  );
}

function logSignalRegistrationResult(result: SignalRegistrationResult): void {
  const { privateBundle, publicBundle, payload } = result;

  console.log("[Signal Registration] ========================================");
  console.log("[Signal Registration] Generated client registration keys");
  console.log("[Signal Registration] deviceId:", privateBundle.deviceId);
  console.log("[Signal Registration] createdAt:", privateBundle.createdAt);

  logEncodedValue("Identity Key (IK) public", privateBundle.identityKey.publicKey);
  logEncodedValue("Identity Key (IK) private", privateBundle.identityKey.privateKey);

  console.log("[Signal Registration] Signed Pre Key (SPK) keyId:", privateBundle.signedPreKey.keyId);
  logEncodedValue("Signed Pre Key (SPK) public", privateBundle.signedPreKey.publicKey);
  logEncodedValue("Signed Pre Key (SPK) private", privateBundle.signedPreKey.privateKey);
  logEncodedValue("Signed Pre Key (SPK) signature", privateBundle.signedPreKey.signature);

  console.log("[Signal Registration] One-Time Pre Keys (OPKs) count:", privateBundle.oneTimePreKeys.length);

  for (const oneTimePreKey of privateBundle.oneTimePreKeys) {
    console.log(`[Signal Registration] OPK #${oneTimePreKey.keyId}`);
    logEncodedValue(`OPK #${oneTimePreKey.keyId} public`, oneTimePreKey.publicKey);
    logEncodedValue(`OPK #${oneTimePreKey.keyId} private`, oneTimePreKey.privateKey);
  }

  console.log("[Signal Registration] Public bundle:", publicBundle);
  console.log("[Signal Registration] Backend payload (public keys only):", payload);
  console.log("[Signal Registration] Payload excludes private keys:", payloadHasNoPrivateKeys(payload, publicBundle));
  console.log("[Signal Registration] ========================================");
}

function logEncodedValue(label: string, base64UrlValue: Base64UrlString): void {
  console.log(`[Signal Registration] ${label} (Base64URL):`, base64UrlValue);
  console.log(`[Signal Registration] ${label} (Hex):`, bytesToHex(base64UrlToBytes(base64UrlValue)));
}

function payloadHasNoPrivateKeys(
  payload: SignalRegistrationPayload,
  publicBundle: PublicRegistrationBundle,
): boolean {
  return (
    payload.identity_key_public === publicBundle.identityKey.publicKey &&
    payload.signed_pre_key_public === publicBundle.signedPreKey.publicKey &&
    payload.signed_pre_key_signature === publicBundle.signedPreKey.signature &&
    payload.one_time_pre_keys.length === publicBundle.oneTimePreKeys.length &&
    payload.one_time_pre_keys.every((payloadKey, index) => {
      const publicKey = publicBundle.oneTimePreKeys[index];
      return payloadKey.key_id === String(publicKey.keyId) && payloadKey.public_key === publicKey.publicKey;
    })
  );
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function storePrivateBundleInIndexedDb({
  userId,
  deviceId,
  privateBundle,
}: StorePrivateBundleOptions): Promise<StoredPrivateBundleRecord> {
  // IndexedDB keeps private key material out of localStorage and supports structured records.
  const resolvedDeviceId = deviceId ?? privateBundle.deviceId;
  const record: StoredPrivateBundleRecord = {
    storageKey: buildStorageKey(userId, resolvedDeviceId),
    userId,
    deviceId: resolvedDeviceId,
    privateBundle,
    savedAt: new Date().toISOString(),
  };

  const db = await openPrivateKeyDatabase();
  await db.put("privateBundles", record);
  return record;
}

export async function loadPrivateBundleFromIndexedDb(
  userId: string,
  deviceId = DEFAULT_DEVICE_ID,
): Promise<StoredPrivateBundleRecord | undefined> {
  const db = await openPrivateKeyDatabase();
  return db.get("privateBundles", buildStorageKey(userId, deviceId));
}

export async function deletePrivateBundleFromIndexedDb(
  userId: string,
  deviceId = DEFAULT_DEVICE_ID,
): Promise<void> {
  const db = await openPrivateKeyDatabase();
  await db.delete("privateBundles", buildStorageKey(userId, deviceId));
}

function buildSignedPreKeySignatureMessage(keyId: number, publicKey: Uint8Array): Uint8Array {
  const context = textEncoder.encode(SIGNED_PRE_KEY_SIGNATURE_CONTEXT);
  const keyIdBytes = new Uint8Array(4);

  new DataView(keyIdBytes.buffer).setUint32(0, keyId, false);

  const message = new Uint8Array(context.length + keyIdBytes.length + publicKey.length);
  message.set(context, 0);
  message.set(keyIdBytes, context.length);
  message.set(publicKey, context.length + keyIdBytes.length);

  return message;
}

function bytesToBase64Url(bytes: Uint8Array): Base64UrlString {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlToBytes(value: Base64UrlString): Uint8Array {
  const paddedBase64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  const binary = atob(paddedBase64);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

async function openPrivateKeyDatabase(): Promise<IDBPDatabase<PrivateKeyDatabase>> {
  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB is not available. Private keys must be stored in a browser context.");
  }

  return openDB<PrivateKeyDatabase>(PRIVATE_KEY_DB_NAME, PRIVATE_KEY_DB_VERSION, {
    upgrade(db) {
      if (!db.objectStoreNames.contains("privateBundles")) {
        const store = db.createObjectStore("privateBundles", { keyPath: "storageKey" });
        store.createIndex("by-user-id", "userId");
      }
    },
  });
}

function buildStorageKey(userId: string, deviceId: string): string {
  if (!userId.trim()) {
    throw new Error("User ID is required before private keys can be stored.");
  }

  if (!deviceId.trim()) {
    throw new Error("Device ID is required before private keys can be stored.");
  }

  return `${userId}:${deviceId}`;
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer.`);
  }
}
