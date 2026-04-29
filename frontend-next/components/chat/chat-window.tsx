import type { ChatMessage } from "@/types/chat";

interface ChatWindowProps {
  messages: ChatMessage[];
  currentUserId: string;
}

export function ChatWindow({ messages, currentUserId }: ChatWindowProps) {
  return (
    <section className="flex-1 overflow-y-auto bg-slate-50 p-4">
      <div className="mx-auto max-w-3xl space-y-3">
        {messages.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-300 bg-white p-6 text-center">
            <p className="text-sm font-medium text-slate-700">No messages in this session yet</p>
            <p className="mt-1 text-xs text-slate-500">Use this channel to exchange encrypted payloads once client-side key handling is added.</p>
          </div>
        ) : null}
        {messages.map((message, index) => {
          const isMine = message.senderId === currentUserId;
          return (
            <article
              key={`${message.clientMessageId ?? "msg"}-${index}`}
              className={`max-w-xl rounded-2xl px-4 py-3 text-sm shadow-sm ${
                isMine ? "ml-auto bg-academy-700 text-white" : "mr-auto bg-white text-slate-900"
              }`}
            >
              <p>{message.content}</p>
              {isMine ? (
                <p className="mt-2 text-[11px] text-academy-100">
                  {message.delivered ? "Delivered" : "Queued for recipient"}
                </p>
              ) : null}
            </article>
          );
        })}
      </div>
    </section>
  );
}
