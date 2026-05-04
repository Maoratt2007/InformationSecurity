"use client";

import { supabase } from "@/lib/supabase/client";

/**
 * Ends the Supabase session for this browser profile. Other tabs receive `SIGNED_OUT` via
 * Supabase’s cross-tab sync; `AuthSyncListener` clears Signal state and leaves `/chat`.
 */
export async function logoutUser(): Promise<void> {
  try {
    await supabase.auth.signOut();
  } catch (error) {
    console.warn("[logoutUser] supabase signOut failed", error);
  }
}
