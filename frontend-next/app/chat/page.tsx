import { ChatShell } from "@/components/chat/chat-shell";

export default function ChatPage() {
  const demoClientId = "student-001";

  return (
    <main className="min-h-screen bg-slate-100 px-4 py-8">
      <div className="mx-auto max-w-7xl space-y-4">
        <header>
          <h1 className="text-2xl font-semibold text-slate-900">Chat Dashboard</h1>
          <p className="text-sm text-slate-600">Realtime transport ready for end-to-end encrypted payload exchange.</p>
        </header>
        <ChatShell clientId={demoClientId} />
      </div>
    </main>
  );
}
