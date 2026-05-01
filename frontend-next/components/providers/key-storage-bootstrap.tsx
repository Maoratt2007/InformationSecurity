"use client";

import { useEffect } from "react";
import { KeyStorageService } from "@/lib/crypto/keyStorageService";

export function KeyStorageBootstrap() {
  useEffect(() => {
    try {
      for (let index = window.localStorage.length - 1; index >= 0; index -= 1) {
        const key = window.localStorage.key(index);
        if (
          key?.startsWith("secure-messenger.signal.private-bundle.v1") ||
          key?.startsWith("sb-")
        ) {
          window.localStorage.removeItem(key);
        }
      }

      KeyStorageService.restoreSessionFromLocalStorage();
    } catch (error) {
      console.warn("[KeyStorageService] Session restore failed.", error);
    }
  }, []);

  return null;
}
