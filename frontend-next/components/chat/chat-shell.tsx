"use client";

import { useEffect, useMemo, useState } from "react";
import { LogOut, ShieldCheck } from "lucide-react";
import { logoutUser } from "@/lib/auth/logout";
import {
  readStoredMasterSecret,
  SIGNAL_SESSION_UPDATED_EVENT,
  useChatWebSocket,
} from "@/hooks/use-chat-websocket";
import { useSignalSession } from "@/hooks/use-signal-session";
import { supabase } from "@/lib/supabase/client";
import type { ChatContact } from "@/types/chat";
import { ChatWindow } from "./chat-window";
import { ContactList } from "./contact-list";
import { MessageInput } from "./message-input";

interface ChatShellProps {
  clientId: string;
  contacts: ChatContact[];
  /** When false, realtime and send paths stay disabled until keys are initialized upstream. */
  signalCryptoReady?: boolean;
}

export function ChatShell({
  clientId,
  contacts: initialContacts,
  signalCryptoReady = true,
}: ChatShellProps) {
  const [activeContactId, setActiveContactId] = useState(initialContacts[0]?.id ?? "");
  const [sessionKeyThumbprint, setSessionKeyThumbprint] = useState<string | null>(null);
  /** Usernames for peers seen via WebSocket presence before the parent contact list was refetched. */
  const [presencePeerNames, setPresencePeerNames] = useState<Record<string, string>>({});
  /** Peer IDs that appeared via realtime presence but are not in `initialContacts`; keep listed as offline after they disconnect. */
  const [presenceOnlyPeerIds, setPresenceOnlyPeerIds] = useState<string[]>([]);
  const { isConnected, messages, onlineClients, sendMessage, loadConversation } = useChatWebSocket(clientId, {
    cryptoReady: signalCryptoReady,
  });
  const { establishSession } = useSignalSession();

  useEffect(() => {
    if (!activeContactId || activeContactId === clientId) return;

    let cancelled = false;

    (async () => {
      const {
        data: { session },
      } = await supabase.auth.getSession();
      const token = session?.access_token;
      if (!token || cancelled) return;
      await loadConversation(activeContactId, token);
    })();

    return () => {
      cancelled = true;
    };
  }, [activeContactId, clientId, loadConversation]);

  useEffect(() => {
    const syncThumbprint = () => {
      if (!activeContactId) {
        setSessionKeyThumbprint(null);
        return;
      }
      const ms = readStoredMasterSecret(activeContactId);
      setSessionKeyThumbprint(ms ? ms.slice(0, 6) : null);
    };
    syncThumbprint();
    window.addEventListener(SIGNAL_SESSION_UPDATED_EVENT, syncThumbprint);
    const storageKey = `session_${activeContactId}`;
    const onStorage = (event: StorageEvent) => {
      if (event.key === storageKey) {
        syncThumbprint();
      }
    };
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener(SIGNAL_SESSION_UPDATED_EVENT, syncThumbprint);
      window.removeEventListener("storage", onStorage);
    };
  }, [activeContactId]);

  useEffect(() => {
    const knownIds = new Set(initialContacts.map((c) => c.id));
    const unknownOnline = onlineClients.filter((id) => id !== clientId && !knownIds.has(id));
    if (unknownOnline.length === 0) return;

    let cancelled = false;
    (async () => {
      const { data, error } = await supabase
        .schema("signal_protocol")
        .from("users")
        .select("id, username")
        .in("id", unknownOnline);
      if (cancelled || error || !data?.length) return;
      setPresencePeerNames((prev) => {
        const next = { ...prev };
        for (const row of data) {
          next[row.id] = row.username;
        }
        return next;
      });
    })();

    return () => {
      cancelled = true;
    };
  }, [onlineClients, clientId, initialContacts]);

  useEffect(() => {
    const knownIds = new Set(initialContacts.map((c) => c.id));
    const discovered = onlineClients.filter((id) => id !== clientId && !knownIds.has(id));
    if (discovered.length === 0) return;
    setPresenceOnlyPeerIds((prev) => {
      const next = new Set(prev);
      for (const id of discovered) next.add(id);
      return [...next];
    });
  }, [onlineClients, clientId, initialContacts]);

  const contacts = useMemo<ChatContact[]>(() => {
    const knownIds = new Set(initialContacts.map((c) => c.id));
    const merged: ChatContact[] = initialContacts.map((contact) => ({
      ...contact,
      status: onlineClients.includes(contact.id) ? "online" : "offline",
    }));

    for (const peerId of presenceOnlyPeerIds) {
      if (peerId === clientId || knownIds.has(peerId)) continue;
      const short = peerId.replace(/-/g, "").slice(0, 8);
      merged.push({
        id: peerId,
        name: presencePeerNames[peerId] ?? `Peer ${short}`,
        status: onlineClients.includes(peerId) ? "online" : "offline",
      });
    }

    return merged;
  }, [initialContacts, onlineClients, clientId, presencePeerNames, presenceOnlyPeerIds]);

  useEffect(() => {
    if (contacts.some((c) => c.id === activeContactId)) return;
    setActiveContactId(contacts[0]?.id ?? "");
  }, [contacts, activeContactId]);

  const filteredMessages = messages.filter(
    (message) =>
      (message.senderId === activeContactId && message.recipientId === clientId) ||
      (message.senderId === clientId && message.recipientId === activeContactId),
  );

  return (
    <div className="flex h-[calc(100vh-7rem)] overflow-hidden rounded-2xl border bg-white shadow-card">
      <ContactList contacts={contacts} activeContactId={activeContactId} onSelectContact={setActiveContactId} />
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b bg-white px-4 py-3">
          <div>
            <p className="text-sm font-semibold text-slate-900">Secure Messaging Dashboard</p>
            <p className="text-xs text-slate-500">Session with {activeContactId}</p>
          </div>
          <div className="flex items-center gap-3">
            <p className="flex items-center gap-2 text-xs text-slate-600">
              <ShieldCheck className={`h-4 w-4 ${isConnected ? "text-emerald-600" : "text-slate-400"}`} />
              {isConnected ? "Realtime connected" : "Disconnected"}
            </p>
            <button
              type="button"
              onClick={() => void logoutUser()}
              className="inline-flex items-center gap-2 rounded-lg border border-rose-300 bg-white px-3 py-1.5 text-xs font-medium text-rose-700 hover:bg-rose-50"
            >
              <LogOut className="h-3.5 w-3.5" />
              Log out
            </button>
          </div>
        </header>
        <ChatWindow messages={filteredMessages} currentUserId={clientId} />
        <MessageInput
          disabled={!signalCryptoReady || !isConnected || !activeContactId}
          sessionKeyThumbprint={sessionKeyThumbprint}
          onSend={async (content) => {
            const {
              data: { session },
            } = await supabase.auth.getSession();
            const accessToken = session?.access_token;
            if (accessToken) {
              await establishSession(clientId, activeContactId, accessToken);
            }
            await sendMessage({
              senderId: clientId,
              recipientId: activeContactId,
              content,
              clientMessageId: crypto.randomUUID(),
            });
          }}
        />
      </div>
    </div>
  );
}
