"use client";

import { KeyStorageService } from "./keyStorageService";
import { ensureRegistrationKeyBundleUploaded } from "./registration";
import { SIGNAL_PERSISTENT_IDENTITY_STORAGE_PREFIX } from "./signalIdentityPersistence";

const PRIVATE_BUNDLE_PREFIX = "secure-messenger.signal.private-bundle.v1";

const LOCAL_FASTAPI_URL = "http://127.0.0.1:8000";

function getFastApiBaseUrl(): string {
  const configuredUrl = process.env.NEXT_PUBLIC_API_URL?.trim();
  if (!configuredUrl || configuredUrl.includes("supabase.co")) {
    return LOCAL_FASTAPI_URL;
  }
  return configuredUrl.replace(/\/$/, "");
}

/**
 * Removes Signal private-bundle entries and per-peer `session_*` crypto sessions from
 * localStorage and any matching legacy keys in sessionStorage.
 */
export function clearSignalCryptoFromLocalStorage(): void {
  if (typeof window === "undefined") return;
  const collect = (storage: Storage): string[] => {
    const keysToRemove: string[] = [];
    for (let i = 0; i < storage.length; i += 1) {
      const key = storage.key(i);
      if (!key) continue;
      if (
        key.startsWith(PRIVATE_BUNDLE_PREFIX) ||
        key.startsWith("session_") ||
        key.startsWith(SIGNAL_PERSISTENT_IDENTITY_STORAGE_PREFIX)
      ) {
        keysToRemove.push(key);
      }
    }
    return keysToRemove;
  };
  for (const key of collect(window.localStorage)) {
    window.localStorage.removeItem(key);
  }
  if (typeof window.sessionStorage !== "undefined") {
    for (const key of collect(window.sessionStorage)) {
      window.sessionStorage.removeItem(key);
    }
  }
}

/**
 * On app load: compare the identity public key in localStorage with the database.
 * If the DB has no bundle, or the keys do not match, clear local Signal state and run a full re-registration (new keys + upload).
 */
export async function verifyDatabaseIdentityOrResetAndUpload(
  userId: string,
  accessToken: string,
): Promise<void> {
  const base = getFastApiBaseUrl();
  const url = `${base}/api/users/${encodeURIComponent(userId)}/key-bundle?peek_own_bundle=true`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });

  if (response.status === 404) {
    console.warn(
      "[Signal] No key bundle in database for this user. Clearing local Signal state and re-registering keys.",
    );
    clearSignalCryptoFromLocalStorage();
    await ensureRegistrationKeyBundleUploaded({ userId, accessToken });
    return;
  }

  if (!response.ok) {
    console.warn(
      "[Signal] Identity verification skipped: could not read key bundle from server.",
      response.status,
      await response.text().catch(() => ""),
    );
    return;
  }

  const bundle = (await response.json()) as { identity_key_public?: string };
  const dbIdentityPublic = bundle.identity_key_public;
  if (typeof dbIdentityPublic !== "string" || dbIdentityPublic.length === 0) {
    console.warn(
      "[Signal] Database returned no identity key. Clearing local Signal state and re-registering keys.",
    );
    clearSignalCryptoFromLocalStorage();
    await ensureRegistrationKeyBundleUploaded({ userId, accessToken });
    return;
  }

  let localRecord: ReturnType<typeof KeyStorageService.load> | undefined;
  try {
    localRecord = KeyStorageService.load(userId);
  } catch {
    localRecord = undefined;
  }
  const localIdentityPublic = localRecord?.privateBundle?.identityKey?.publicKey;

  if (localIdentityPublic === dbIdentityPublic) {
    return;
  }

  console.warn("Local Identity Key does not match DB. Resetting local session...");
  clearSignalCryptoFromLocalStorage();
  await ensureRegistrationKeyBundleUploaded({ userId, accessToken });
}
