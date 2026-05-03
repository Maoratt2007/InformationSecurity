"use client";

import { useEffect } from "react";
import { KeyStorageService } from "@/lib/crypto/keyStorageService";

/** Restores private-bundle from localStorage on hard refresh; does not wipe keys or Supabase session. */
export function KeyStorageBootstrap() {
  useEffect(() => {
    try {
      KeyStorageService.restoreSessionFromLocalStorage();
    } catch (error) {
      console.warn("[KeyStorageService] Session restore failed.", error);
    }
  }, []);

  return null;
}
