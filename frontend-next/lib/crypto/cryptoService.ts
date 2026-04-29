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

export interface RegistrationKeyBundle {
  publicBundle: PublicRegistrationBundle;
  privateBundle: PrivateRegistrationBundle;
}

export interface GenerateRegistrationKeysOptions {
  deviceId?: string;
  signedPreKeyId?: number;
  oneTimePreKeyCount?: number;
  oneTimePreKeyStartId?: number;
}

export interface BackendKeyBundlePayload {
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

export function generateRegistrationKeys(options: GenerateRegistrationKeysOptions = {}): RegistrationKeyBundle {
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

  return {
    publicBundle: {
      deviceId,
      identityKey: {
        algorithm: identityKey.algorithm,
        publicKey: identityKey.publicKey,
      },
      signedPreKey: publicSignedPreKey,
      oneTimePreKeys: publicOneTimePreKeys,
      createdAt,
    },
    privateBundle: {
      deviceId,
      identityKey,
      signedPreKey: privateSignedPreKey,
      oneTimePreKeys: privateOneTimePreKeys,
      createdAt,
    },
  };
}

export const generateRegistrationBundle = generateRegistrationKeys;

export function toBackendKeyBundlePayload(publicBundle: PublicRegistrationBundle): BackendKeyBundlePayload {
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
