import { supabase } from "./client";

export interface SignalProfile {
  id: string;
  username: string;
  email: string;
  created_at?: string;
}

interface UpsertSignalProfileInput {
  id: string;
  email: string;
  fullName?: string | null;
}

export async function upsertSignalProfile({ id, email, fullName }: UpsertSignalProfileInput) {
  const normalizedEmail = email.trim().toLowerCase();
  const username = fullName?.trim() || normalizedEmail.split("@")[0] || "User";

  const { data, error } = await supabase
    .schema("signal_protocol")
    .from("users")
    .upsert(
      {
        id,
        username,
        email: normalizedEmail,
      },
      { onConflict: "id" },
    )
    .select("id, username, email, created_at")
    .single();

  if (error) {
    throw error;
  }

  return data as SignalProfile;
}

export async function fetchSignalProfiles(currentUserId?: string) {
  let query = supabase
    .schema("signal_protocol")
    .from("users")
    .select("id, username, email, created_at")
    .order("username", { ascending: true });

  if (currentUserId) {
    query = query.neq("id", currentUserId);
  }

  const { data, error } = await query;

  if (error) {
    throw error;
  }

  return (data ?? []) as SignalProfile[];
}
