/**
 * Raw Supabase operations for the `sessions` table (schema: `signal_protocol`).
 *
 * Persistence model: a single encrypted blob in `ratchet_key_id` (AES-GCM ciphertext
 * as standard Base64 of `12-byte IV || ciphertext`). Other columns (e.g. chain_key,
 * root_key, last_received_index) are nullable and are not sent — they stay null.
 *
 * Required columns for upsert: id (optional default), user_id, contact_id, ratchet_key_id.
 * Conflict target: (user_id, contact_id).
 */

import { supabase } from "./client";

const SIGNAL_SCHEMA = "signal_protocol";

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface SessionRow {
  user_id: string;
  contact_id: string;
  ratchet_key_id: string | null;
}

function isValidUuid(value: string): boolean {
  return UUID_REGEX.test(value);
}

/**
 * Upsert one session row: only `user_id`, `contact_id`, and encrypted `ratchet_key_id`.
 */
export async function upsertSessionRow(
  userId: string,
  contactId: string,
  encryptedBlob: string,
): Promise<void> {
  if (!isValidUuid(userId) || !isValidUuid(contactId)) {
    console.warn("[Sessions] upsert skipped — invalid UUID(s):", { userId, contactId });
    return;
  }
  if (!encryptedBlob || encryptedBlob.length === 0) {
    console.warn("[Sessions] upsert skipped — empty encrypted blob (peer:", contactId, ")");
    return;
  }

  console.log(
    `[Sessions] upsert user=${userId} contact=${contactId} ratchet_key_id length=${encryptedBlob.length}`,
  );

  const { error } = await supabase
    .schema(SIGNAL_SCHEMA)
    .from("sessions")
    .upsert(
      {
        user_id: userId,
        contact_id: contactId,
        ratchet_key_id: encryptedBlob,
      },
      { onConflict: "user_id,contact_id" },
    );

  if (error) {
    console.warn("[Sessions] upsert failed:", error.message, { userId, contactId });
    return;
  }
  console.log(`[Sessions] upsert OK contact=${contactId}`);
}

/**
 * Fetch all session rows for a given user (only columns needed to restore local state).
 */
export async function fetchSessionsForUser(userId: string): Promise<SessionRow[]> {
  if (!isValidUuid(userId)) {
    console.warn("[Sessions] fetch skipped — invalid UUID:", userId);
    return [];
  }

  const { data, error } = await supabase
    .schema(SIGNAL_SCHEMA)
    .from("sessions")
    .select("user_id, contact_id, ratchet_key_id")
    .eq("user_id", userId);

  if (error) {
    console.warn("[Sessions] fetch failed:", error.message);
    return [];
  }

  const rows = (data ?? []) as SessionRow[];
  console.log(`[Sessions] fetched ${rows.length} row(s) for user=${userId}`);
  return rows;
}

/** Delete every session row owned by `userId` (e.g. after local identity reset). */
export async function deleteAllSessionsForUser(userId: string): Promise<void> {
  if (!isValidUuid(userId)) return;

  const { error } = await supabase
    .schema(SIGNAL_SCHEMA)
    .from("sessions")
    .delete()
    .eq("user_id", userId);

  if (error) {
    console.warn("[Sessions] delete-all failed:", error.message);
    return;
  }
  console.log(`[Sessions] deleted all rows for user=${userId}`);
}
