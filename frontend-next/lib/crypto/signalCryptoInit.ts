"use client";

import { generateRegistrationBundle, type PrivateIdentityKey } from "./cryptoService";
import { KeyStorageService } from "./keyStorageService";
import { ensurePersistentIdentityKeyPair } from "./signalIdentityPersistence";

const inflight = new Map<string, Promise<void>>();

function bundleIdentityMatches(userId: string, identityKey: PrivateIdentityKey): boolean {
  try {
    const record = KeyStorageService.load(userId);
    if (!record) return false;
    const ik = record.privateBundle.identityKey;
    return ik.publicKey === identityKey.publicKey && ik.privateKey === identityKey.privateKey;
  } catch {
    return false;
  }
}

/**
 * Ensures localStorage holds a stable Ed25519 identity for `userId` and that the full
 * `KeyStorageService` private bundle uses that same identity (regenerating signed pre-key + OTPKs if needed).
 * Idempotent; safe to call before chat / X3DH. Does not upload to the server.
 */
export function ensureSignalCryptoInitialized(userId: string): Promise<void> {
  const existing = inflight.get(userId);
  if (existing) return existing;

  const work = (async () => {
    if (typeof window === "undefined") {
      throw new Error("Signal crypto initialization requires a browser environment.");
    }

    const identityKey = ensurePersistentIdentityKeyPair(userId);

    if (bundleIdentityMatches(userId, identityKey)) {
      return;
    }

    const { privateBundle } = generateRegistrationBundle({
      deviceId: "primary",
      oneTimePreKeyCount: 50,
      identityKey,
    });

    KeyStorageService.save({
      userId,
      deviceId: privateBundle.deviceId,
      privateBundle,
    });
  })();

  inflight.set(userId, work);
  return work.finally(() => {
    if (inflight.get(userId) === work) {
      inflight.delete(userId);
    }
  });
}
