"use client";

import { FormEvent, useState } from "react";
import { SendHorizonal } from "lucide-react";

interface MessageInputProps {
  onSend: (content: string) => void;
  disabled?: boolean;
}

export function MessageInput({ onSend, disabled = false }: MessageInputProps) {
  const [text, setText] = useState("");

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!text.trim() || disabled) {
      return;
    }
    onSend(text.trim());
    setText("");
  }

  return (
    <form onSubmit={submit} className="border-t bg-white p-3">
      <div className="flex items-center gap-2">
        <input
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder="Write a message"
          className="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none ring-academy-500 focus:ring-2"
        />
        <button
          type="submit"
          disabled={disabled}
          className="inline-flex items-center gap-2 rounded-lg bg-academy-700 px-3 py-2 text-sm font-medium text-white hover:bg-academy-900 disabled:opacity-60"
        >
          <SendHorizonal className="h-4 w-4" />
          Send
        </button>
      </div>
    </form>
  );
}
