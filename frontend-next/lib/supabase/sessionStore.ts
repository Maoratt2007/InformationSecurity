"use client";

/**
 * Encrypted Signal peer-session persistence in Supabase (`ratchet_key_id` only).
 *
 * Wrap key: **Supabase `user_id`** → SHA-256 → AES-256-GCM (see `deriveSessionWrapKeyFromUserId`).
 * Stable across logout/login even though `AuthSyncListener` clears bundle + `session_*` keys;
 * the persistent Ed25519 identity is also kept on sign-out so logs can confirm it matches.
 *
 * Legacy rows encrypted with HKDF(identity private key) are still tried if the user-id key fails.
 *
 * Init order: ensureSignalCrypto → verify DB identity → restore sessions → WebSocket.
 */

import { loadPersistedIdentityKeyPair } from "../crypto/signalIdentityPersistence";
import {
  deriveSessionWrapKeyFromUserId,
  deriveSessionStorageKey,
  encryptSessionBlob,
  decryptSessionBlob,
} from "../crypto/sessionEncryption";
import {
  upsertSessionRow,
  fetchSessionsForUser,
  deleteAllSessionsForUser,
} from "./sessions";

const encKeyCache = new Map<string, CryptoKey>();

export function invalidateSessionEncryptionKey(userId: string): void {
  encKeyCache.delete(userId);
}

async function getSessionWrapKey(userId: string): Promise<CryptoKey> {
  const cached = encKeyCache.get(userId);
  if (cached) return cached;

  const identity = loadPersistedIdentityKeyPair(userId);
  console.log(
    "[SignalSessionWrap] Current Identity Public Key:",
    identity?.publicKey ?? "(none in localStorage yet)",
  );

  const key = await deriveSessionWrapKeyFromUserId(userId);
  encKeyCache.set(userId, key);
  console.log(
    "[SignalSessionWrap] Session wrap AES-GCM key derived from Supabase user_id (stable across logout).",
  );
  return key;
}

function isValidStoredPeerSessionJson(json: string): boolean {
  try {
    const o = JSON.parse(json) as Record<string, unknown>;
    return typeof o.masterSecret === "string" && typeof o.ephemeralPublicKey === "string";
  } catch {
    return false;
  }
}

/**
 * Encrypt full `StoredPeerSession` JSON and upsert to Supabase (`ratchet_key_id` only).
 */
export async function syncSessionToSupabase(
  userId: string,
  peerId: string,
  sessionJson: string,
): Promise<void> {
  try {
    if (!sessionJson || sessionJson.length === 0) {
      console.warn("[SessionStore] sync skipped — empty session JSON for peer", peerId);
      return;
    }
    const key = await getSessionWrapKey(userId);
    const encrypted = await encryptSessionBlob(key, sessionJson);
    console.log(
      `[SessionStore] sync peer=${peerId} plaintextBytes=${sessionJson.length} ratchet_key_id chars=${encrypted.length}`,
    );
    await upsertSessionRow(userId, peerId, encrypted);
  } catch (error) {
    console.warn("[SessionStore] syncSessionToSupabase failed (peer:", peerId, "):", error);
  }
}

/**
 * Fetch rows, decrypt `ratchet_key_id`, validate JSON, write `session_<contact_id>` to localStorage.
 */
export async function loadAndRestoreSessionsFromSupabase(userId: string): Promise<void> {
  if (typeof window === "undefined") return;
  try {
    const primaryKey = await getSessionWrapKey(userId);
    const rows = await fetchSessionsForUser(userId);
    let restored = 0;
    let undecryptable = 0;

    for (const row of rows) {
      const lsKey = `session_${row.contact_id}`;

      if (window.localStorage.getItem(lsKey)) {
        continue;
      }

      const blob = row.ratchet_key_id;
      if (!blob) {
        console.warn("[SessionStore] empty ratchet_key_id for contact", row.contact_id);
        continue;
      }

      let plaintext = await decryptSessionBlob(primaryKey, blob);

      if (!plaintext) {
        const identity = loadPersistedIdentityKeyPair(userId);
        if (identity?.privateKey) {
          const legacyKey = await deriveSessionStorageKey(identity.privateKey);
          plaintext = await decryptSessionBlob(legacyKey, blob);
          if (plaintext) {
            console.log(
              "[SessionStore] Decrypted contact",
              row.contact_id,
              "using legacy identity-derived key — will re-save with user-id key on next ratchet update.",
            );
          }
        }
      }

      if (!plaintext) {
        console.warn(
          "[SessionStore] Could not decrypt session for contact",
          row.contact_id,
          "— stale or wrong key; will re-derive on next message if possible.",
        );
        undecryptable += 1;
        continue;
      }

      if (!isValidStoredPeerSessionJson(plaintext)) {
        console.warn("[SessionStore] decrypted payload is not a valid peer session JSON:", row.contact_id);
        undecryptable += 1;
        continue;
      }

      window.localStorage.setItem(lsKey, plaintext);
      restored += 1;
      console.log(
        `[SessionStore] re-hydrated localStorage key=${lsKey} (${plaintext.length} chars JSON)`,
      );
    }

    if (rows.length > 0) {
      console.log(
        `[SessionStore] processed ${rows.length} row(s); restored=${restored}, undecryptable=${undecryptable}.`,
      );
    }
  } catch (error) {
    console.warn("[SessionStore] loadAndRestoreSessionsFromSupabase failed:", error);
  }
}

export async function clearSupabaseSessionsAfterIdentityReset(userId: string): Promise<void> {
  invalidateSessionEncryptionKey(userId);
  await deleteAllSessionsForUser(userId);
}
