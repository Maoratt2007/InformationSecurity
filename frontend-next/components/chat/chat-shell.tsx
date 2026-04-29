"use client";

import { useMemo, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { useChatWebSocket } from "@/hooks/use-chat-websocket";
import type { ChatContact } from "@/types/chat";
import { ChatWindow } from "./chat-window";
import { ContactList } from "./contact-list";
import { MessageInput } from "./message-input";

const CONTACTS: ChatContact[] = [
  { id: "lecturer-001", name: "Dr. Noor", status: "online" },
  { id: "ta-001", name: "Teaching Assistant", status: "online" },
  { id: "student-042", name: "Research Partner", status: "offline" },
];

interface ChatShellProps {
  clientId: string;
}

export function ChatShell({ clientId }: ChatShellProps) {
  const [activeContactId, setActiveContactId] = useState(CONTACTS[0].id);
  const { isConnected, messages, onlineClients, sendMessage } = useChatWebSocket(clientId);

  const contacts = useMemo<ChatContact[]>(
    () =>
      CONTACTS.map((contact) => ({
        ...contact,
        status: onlineClients.includes(contact.id) ? "online" : "offline",
      })),
    [onlineClients],
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
          <p className="flex items-center gap-2 text-xs text-slate-600">
            <ShieldCheck className={`h-4 w-4 ${isConnected ? "text-emerald-600" : "text-slate-400"}`} />
            {isConnected ? "Realtime connected" : "Disconnected"}
          </p>
        </header>
        <ChatWindow messages={filteredMessages} currentUserId={clientId} />
        <MessageInput
          disabled={!isConnected}
          onSend={(content) =>
            sendMessage({
              senderId: clientId,
              recipientId: activeContactId,
              content,
              clientMessageId: crypto.randomUUID(),
            })
          }
        />
      </div>
    </div>
  );
}
