"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase/client";
import { clearSignalCryptoFromLocalStorage } from "@/lib/crypto/identityVerification";

/**
 * Keeps all tabs in sync with Supabase auth: one sign-out closes protected routes everywhere
 * without a manual refresh, and clears messenger crypto from shared localStorage.
 */
export function AuthSyncListener() {
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((event, session) => {
      if (event === "SIGNED_OUT") {
        clearSignalCryptoFromLocalStorage();
        if (pathname.startsWith("/chat")) {
          router.replace("/");
        }
        return;
      }

      if (event === "INITIAL_SESSION" && !session?.user && pathname.startsWith("/chat")) {
        router.replace("/");
      }
    });

    return () => subscription.unsubscribe();
  }, [router, pathname]);

  return null;
}
