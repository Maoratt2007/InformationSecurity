"use client";

import type {
  Base64UrlString,
  PrivateIdentityKey,
  PrivateOneTimePreKey,
  PrivateRegistrationBundle,
  PrivateSignedPreKey,
  StorePrivateBundleOptions,
  StoredPrivateBundleRecord,
} from "./cryptoService";

const STORAGE_PREFIX = "secure-messenger.signal.private-bundle.v1";
const STORAGE_VERSION = 1;
const DEFAULT_DEVICE_ID = "primary";

let privateBundleSessionStorageMigrated = false;

/** Copy private-bundle keys from sessionStorage once (older builds used session-only storage). */
function migratePrivateBundleKeysFromSessionStorageOnce(): void {
  if (privateBundleSessionStorageMigrated || typeof window === "undefined") return;
  if (typeof window.sessionStorage === "undefined") return;
  privateBundleSessionStorageMigrated = true;
  const prefix = `${STORAGE_PREFIX}:`;
  const keys: string[] = [];
  for (let i = 0; i < window.sessionStorage.length; i += 1) {
    const k = window.sessionStorage.key(i);
    if (k?.startsWith(prefix)) keys.push(k);
  }
  for (const k of keys) {
    const v = window.sessionStorage.getItem(k);
    if (!v) continue;
    if (!window.localStorage.getItem(k)) {
      window.localStorage.setItem(k, v);
    }
    window.sessionStorage.removeItem(k);
  }
}

interface StoredPrivateIdentityKey extends Omit<PrivateIdentityKey, "privateKey"> {
  privateKeyBase64: string;
}

interface StoredPrivateSignedPreKey extends Omit<PrivateSignedPreKey, "privateKey"> {
  privateKeyBase64: string;
}

interface StoredPrivateOneTimePreKey extends Omit<PrivateOneTimePreKey, "privateKey"> {
  privateKeyBase64: string;
}

interface LocalStoragePrivateBundleRecord {
  version: number;
  storageKey: string;
  userId: string;
  deviceId: string;
  savedAt: string;
  privateBundle: {
    deviceId: string;
    identityKey: StoredPrivateIdentityKey;
    signedPreKey: StoredPrivateSignedPreKey;
    oneTimePreKeys: StoredPrivateOneTimePreKey[];
    createdAt: string;
  };
}

export class KeyStorageService {
  /** Ensures any legacy sessionStorage private-bundle keys are moved to localStorage (no-op after first run). */
  static ensureLegacyPrivateBundleMigrated(): void {
    migratePrivateBundleKeysFromSessionStorageOnce();
  }

  static save({ userId, deviceId, privateBundle }: StorePrivateBundleOptions): StoredPrivateBundleRecord {
    const storage = this.getStorage();
    const resolvedDeviceId = deviceId ?? privateBundle.deviceId;
    const record: StoredPrivateBundleRecord = {
      storageKey: this.buildStorageKey(userId, resolvedDeviceId),
      userId,
      deviceId: resolvedDeviceId,
      privateBundle,
      savedAt: new Date().toISOString(),
    };

    storage.setItem(record.storageKey, JSON.stringify(serializeRecord(record)));
    console.log("[KeyStorageService] Saved private keys to localStorage", {
      storageKey: record.storageKey,
      userId: record.userId,
      deviceId: record.deviceId,
    });

    return record;
  }

  static load(userId: string, deviceId = DEFAULT_DEVICE_ID): StoredPrivateBundleRecord | undefined {
    migratePrivateBundleKeysFromSessionStorageOnce();
    const storage = this.getStorage();
    const storageKey = this.buildStorageKey(userId, deviceId);
    const serializedRecord = storage.getItem(storageKey);

    if (!serializedRecord) {
      return undefined;
    }

    const record = deserializeRecord(JSON.parse(serializedRecord));
    console.log("[KeyStorageService] Loaded private keys from localStorage", {
      storageKey: record.storageKey,
      userId: record.userId,
      deviceId: record.deviceId,
    });
    return record;
  }

  static restoreSessionFromLocalStorage(): StoredPrivateBundleRecord | undefined {
    migratePrivateBundleKeysFromSessionStorageOnce();
    const storage = this.getStorage();

    for (let index = 0; index < storage.length; index += 1) {
      const storageKey = storage.key(index);

      if (!storageKey?.startsWith(`${STORAGE_PREFIX}:`)) {
        continue;
      }

      const serializedRecord = storage.getItem(storageKey);
      if (!serializedRecord) {
        continue;
      }

      const record = deserializeRecord(JSON.parse(serializedRecord));
      console.log("Session restored from local storage", {
        userId: record.userId,
        deviceId: record.deviceId,
        createdAt: record.privateBundle.createdAt,
        oneTimePreKeyCount: record.privateBundle.oneTimePreKeys.length,
      });
      return record;
    }

    return undefined;
  }

  private static buildStorageKey(userId: string, deviceId: string): string {
    if (!userId.trim()) {
      throw new Error("User ID is required before private keys can be saved.");
    }

    if (!deviceId.trim()) {
      throw new Error("Device ID is required before private keys can be saved.");
    }

    return `${STORAGE_PREFIX}:${userId}:${deviceId}`;
  }

  private static getStorage(): Storage {
    if (typeof window === "undefined" || typeof window.localStorage === "undefined") {
      throw new Error("localStorage is not available. KeyStorageService must run in the browser.");
    }

    return window.localStorage;
  }
}

function serializeRecord(record: StoredPrivateBundleRecord): LocalStoragePrivateBundleRecord {
  return {
    version: STORAGE_VERSION,
    storageKey: record.storageKey,
    userId: record.userId,
    deviceId: record.deviceId,
    savedAt: record.savedAt,
    privateBundle: {
      deviceId: record.privateBundle.deviceId,
      identityKey: {
        ...record.privateBundle.identityKey,
        privateKeyBase64: encodePrivateKeyForStorage(record.privateBundle.identityKey.privateKey),
      },
      signedPreKey: {
        ...record.privateBundle.signedPreKey,
        privateKeyBase64: encodePrivateKeyForStorage(record.privateBundle.signedPreKey.privateKey),
      },
      oneTimePreKeys: record.privateBundle.oneTimePreKeys.map((key) => ({
        ...key,
        privateKeyBase64: encodePrivateKeyForStorage(key.privateKey),
      })),
      createdAt: record.privateBundle.createdAt,
    },
  };
}

function deserializeRecord(value: unknown): StoredPrivateBundleRecord {
  const record = value as LocalStoragePrivateBundleRecord;

  return {
    storageKey: record.storageKey,
    userId: record.userId,
    deviceId: record.deviceId,
    savedAt: record.savedAt,
    privateBundle: {
      deviceId: record.privateBundle.deviceId,
      identityKey: {
        algorithm: record.privateBundle.identityKey.algorithm,
        publicKey: record.privateBundle.identityKey.publicKey,
        privateKey: decodePrivateKeyFromStorage(record.privateBundle.identityKey.privateKeyBase64),
      },
      signedPreKey: {
        algorithm: record.privateBundle.signedPreKey.algorithm,
        keyId: record.privateBundle.signedPreKey.keyId,
        publicKey: record.privateBundle.signedPreKey.publicKey,
        signature: record.privateBundle.signedPreKey.signature,
        signatureAlgorithm: record.privateBundle.signedPreKey.signatureAlgorithm,
        privateKey: decodePrivateKeyFromStorage(record.privateBundle.signedPreKey.privateKeyBase64),
      },
      oneTimePreKeys: record.privateBundle.oneTimePreKeys.map((key) => ({
        algorithm: key.algorithm,
        keyId: key.keyId,
        publicKey: key.publicKey,
        privateKey: decodePrivateKeyFromStorage(key.privateKeyBase64),
      })),
      createdAt: record.privateBundle.createdAt,
    },
  };
}

function encodePrivateKeyForStorage(value: Base64UrlString): string {
  return value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
}

function decodePrivateKeyFromStorage(value: string): Base64UrlString {
  return value.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
