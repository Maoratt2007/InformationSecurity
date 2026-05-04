"use client";

import { KeyStorageService } from "./keyStorageService";
import { ensureRegistrationKeyBundleUploaded } from "./registration";
import { SIGNAL_PERSISTENT_IDENTITY_STORAGE_PREFIX } from "./signalIdentityPersistence";
import { clearSupabaseSessionsAfterIdentityReset } from "../../lib/supabase/sessionStore";

const PRIVATE_BUNDLE_PREFIX = "secure-messenger.signal.private-bundle.v1";

const LOCAL_FASTAPI_URL = "http://127.0.0.1:8000";

function getFastApiBaseUrl(): string {
  const configuredUrl = process.env.NEXT_PUBLIC_API_URL?.trim();
  if (!configuredUrl || configuredUrl.includes("supabase.co")) {
    return LOCAL_FASTAPI_URL;
  }
  return configuredUrl.replace(/\/$/, "");
}

function collectKeysMatchingPrefixes(storage: Storage, prefixes: string[]): string[] {
  const keysToRemove: string[] = [];
  for (let i = 0; i < storage.length; i += 1) {
    const key = storage.key(i);
    if (!key) continue;
    if (prefixes.some((p) => key.startsWith(p))) {
      keysToRemove.push(key);
    }
  }
  return keysToRemove;
}

function removeCollectedFromStorage(storage: Storage, keys: string[]): void {
  for (const key of keys) {
    storage.removeItem(key);
  }
}

/**
 * On **Supabase sign-out** only: remove private bundle + per-peer `session_*` keys so another
 * account on the same browser cannot read them. Does **not** remove the persistent Ed25519
 * identity — that stays tied to this device so the same user_id can unwrap `ratchet_key_id`
 * after login.
 */
export function clearMessengerCryptoOnSignOut(): void {
  if (typeof window === "undefined") return;
  const prefixes = [PRIVATE_BUNDLE_PREFIX, "session_"];
  const localKeys = collectKeysMatchingPrefixes(window.localStorage, prefixes);
  removeCollectedFromStorage(window.localStorage, localKeys);
  if (typeof window.sessionStorage !== "undefined") {
    const sessionKeys = collectKeysMatchingPrefixes(window.sessionStorage, prefixes);
    removeCollectedFromStorage(window.sessionStorage, sessionKeys);
  }
  console.log(
    "[Signal] clearMessengerCryptoOnSignOut: removed",
    localKeys.length,
    "localStorage key(s) (bundle + session_*); persistent identity key kept.",
  );
}

/**
 * Full reset: bundle, `session_*`, **and** persistent identity (used when server identity
 * mismatches or bundle is missing — new keys are generated).
 */
export function clearSignalCryptoFromLocalStorage(): void {
  if (typeof window === "undefined") return;
  const prefixes = [
    PRIVATE_BUNDLE_PREFIX,
    "session_",
    SIGNAL_PERSISTENT_IDENTITY_STORAGE_PREFIX,
  ];
  const localKeys = collectKeysMatchingPrefixes(window.localStorage, prefixes);
  removeCollectedFromStorage(window.localStorage, localKeys);
  if (typeof window.sessionStorage !== "undefined") {
    const sessionKeys = collectKeysMatchingPrefixes(window.sessionStorage, prefixes);
    removeCollectedFromStorage(window.sessionStorage, sessionKeys);
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
    await clearSupabaseSessionsAfterIdentityReset(userId);
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
    await clearSupabaseSessionsAfterIdentityReset(userId);
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
  await clearSupabaseSessionsAfterIdentityReset(userId);
  await ensureRegistrationKeyBundleUploaded({ userId, accessToken });
}
