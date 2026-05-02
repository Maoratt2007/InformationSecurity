"use client";

import { KeyStorageService } from "./keyStorageService";
import { ensureRegistrationKeyBundleUploaded } from "./registration";

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
 * Removes Signal private-bundle entries and per-peer `session_*` crypto sessions from sessionStorage.
 */
export function clearSignalCryptoFromSessionStorage(): void {
  if (typeof window === "undefined") return;
  const keysToRemove: string[] = [];
  for (let i = 0; i < window.sessionStorage.length; i += 1) {
    const key = window.sessionStorage.key(i);
    if (!key) continue;
    if (key.startsWith(PRIVATE_BUNDLE_PREFIX) || key.startsWith("session_")) {
      keysToRemove.push(key);
    }
  }
  for (const key of keysToRemove) {
    window.sessionStorage.removeItem(key);
  }
}

/**
 * On app load: compare the identity public key in sessionStorage with the database.
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
    clearSignalCryptoFromSessionStorage();
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
    clearSignalCryptoFromSessionStorage();
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
  clearSignalCryptoFromSessionStorage();
  await ensureRegistrationKeyBundleUploaded({ userId, accessToken });
}
