"use client";

import { useEffect, useState } from "react";
import { ChatShell } from "@/components/chat/chat-shell";
import { verifyDatabaseIdentityOrResetAndUpload } from "@/lib/crypto/identityVerification";
import { ensureSignalCryptoInitialized } from "@/lib/crypto/signalCryptoInit";
import { supabase } from "@/lib/supabase/client";
import { fetchSignalProfiles, upsertSignalProfile } from "@/lib/supabase/profiles";
import type { ChatContact } from "@/types/chat";

export default function ChatPage() {
  const [clientId, setClientId] = useState<string | null>(null);
  const [contacts, setContacts] = useState<ChatContact[]>([]);
  const [signalCryptoReady, setSignalCryptoReady] = useState(false);
  const [status, setStatus] = useState("Loading Supabase session...");

  useEffect(() => {
    let isMounted = true;

    async function loadSupabaseState() {
      const { data: sessionData, error: sessionError } = await supabase.auth.getSession();

      if (sessionError || !sessionData.session?.user) {
        window.location.href = "/";
        return;
      }

      const user = sessionData.session.user;
      const accessToken = sessionData.session.access_token;

      await upsertSignalProfile({
        id: user.id,
        email: user.email ?? "",
        fullName: user.user_metadata?.full_name,
      });

      setStatus("Loading persistent Signal identity…");
      await ensureSignalCryptoInitialized(user.id);

      if (accessToken) {
        setStatus("Verifying keys with server…");
        await verifyDatabaseIdentityOrResetAndUpload(user.id, accessToken);
      }

      setSignalCryptoReady(true);

      const profiles = await fetchSignalProfiles(user.id);

      if (!isMounted) {
        return;
      }

      setClientId(user.id);
      setContacts(
        profiles.map((profile) => ({
          id: profile.id,
          name: profile.username,
          status: "offline",
        })),
      );
      setStatus("");
    }

    loadSupabaseState().catch((error: unknown) => {
      setStatus(error instanceof Error ? error.message : "Could not load Supabase profile data.");
    });

    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <main className="min-h-screen bg-slate-100 px-4 py-8">
      <div className="mx-auto max-w-7xl space-y-4">
        <header>
          <h1 className="text-2xl font-semibold text-slate-900">Chat Dashboard</h1>
          <p className="text-sm text-slate-600">Realtime transport ready for end-to-end encrypted payload exchange.</p>
        </header>
        {clientId && signalCryptoReady ? (
          <ChatShell clientId={clientId} contacts={contacts} signalCryptoReady={signalCryptoReady} />
        ) : (
          <section className="rounded-2xl border bg-white p-6 text-sm text-slate-600 shadow-card">{status}</section>
        )}
      </div>
    </main>
  );
}
