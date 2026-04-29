import { Users } from "lucide-react";
import type { ChatContact } from "@/types/chat";

interface ContactListProps {
  contacts: ChatContact[];
  activeContactId: string;
  onSelectContact: (contactId: string) => void;
}

export function ContactList({ contacts, activeContactId, onSelectContact }: ContactListProps) {
  return (
    <aside className="w-full border-r bg-white lg:w-72">
      <div className="border-b px-4 py-3">
        <p className="flex items-center gap-2 text-sm font-semibold text-slate-700">
          <Users className="h-4 w-4" />
          Active sessions
        </p>
      </div>
      <ul className="space-y-1 p-2">
        {contacts.map((contact) => (
          <li key={contact.id}>
            <button
              type="button"
              onClick={() => onSelectContact(contact.id)}
              className={`flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-sm ${
                activeContactId === contact.id ? "bg-academy-100 text-academy-900" : "hover:bg-slate-100"
              }`}
            >
              <span className="font-medium">{contact.name}</span>
              <span className={`h-2.5 w-2.5 rounded-full ${contact.status === "online" ? "bg-emerald-500" : "bg-slate-400"}`} />
            </button>
          </li>
        ))}
      </ul>
    </aside>
  );
}
