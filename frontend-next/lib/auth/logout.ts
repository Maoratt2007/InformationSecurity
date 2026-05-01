"use client";

import { supabase } from "@/lib/supabase/client";

export async function logoutUser(): Promise<void> {
  try {
    await supabase.auth.signOut();
  } catch (error) {
    console.warn("[logoutUser] supabase signOut failed", error);
  }
  try {
    window.sessionStorage.clear();
  } catch {
    /* ignore */
  }
  try {
    window.localStorage.clear();
  } catch {
    /* ignore */
  }
  window.location.replace("/");
}
