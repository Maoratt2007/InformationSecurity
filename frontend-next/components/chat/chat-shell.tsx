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
}

export function ChatShell({ clientId, contacts: initialContacts }: ChatShellProps) {
  const [activeContactId, setActiveContactId] = useState(initialContacts[0]?.id ?? "");
  const [sessionKeyThumbprint, setSessionKeyThumbprint] = useState<string | null>(null);
  const { isConnected, messages, onlineClients, sendMessage, loadConversation } =
    useChatWebSocket(clientId);
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
    return () => window.removeEventListener(SIGNAL_SESSION_UPDATED_EVENT, syncThumbprint);
  }, [activeContactId]);

  const contacts = useMemo<ChatContact[]>(
    () =>
      initialContacts.map((contact) => ({
        ...contact,
        status: onlineClients.includes(contact.id) ? "online" : "offline",
      })),
    [initialContacts, onlineClients],
  );

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
          disabled={!isConnected || !activeContactId}
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
