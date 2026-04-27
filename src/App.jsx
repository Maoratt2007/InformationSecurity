import { useMemo, useState } from "react"
import { Lock, SendHorizontal, Settings, ShieldCheck } from "lucide-react"
import {
  decryptMessage,
  encryptMessage,
  generateKeyPairs,
  performX3DHKeyAgreement,
} from "./lib/cryptoUtils"

const CONTACTS = [
  { id: "1", name: "Ava Nelson", role: "Security Engineering" },
  { id: "2", name: "Daniel Park", role: "Compliance Operations" },
  { id: "3", name: "Rina Cohen", role: "Platform Reliability" },
]

const INITIAL_MESSAGES = [
  { id: "m1", sender: "remote", body: "Confirmed. Key rotation completed for the current session." },
  { id: "m2", sender: "me", body: "Acknowledged. Proceeding with endpoint synchronization." },
]

function AuthScreen({ onAuthenticate }) {
  const [mode, setMode] = useState("login")

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 p-6">
      <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-8 shadow-sm">
        <div className="mb-6">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Secure Communications</p>
          <h1 className="mt-2 text-2xl font-semibold text-slate-900">E2EE Messenger</h1>
          <p className="mt-1 text-sm text-slate-600">Access your protected communication workspace.</p>
        </div>

        <div className="mb-5 flex rounded-lg border border-slate-200 p-1">
          <button
            type="button"
            onClick={() => setMode("login")}
            className={`flex-1 rounded-md px-3 py-2 text-sm font-medium ${
              mode === "login" ? "bg-slate-900 text-white" : "text-slate-600"
            }`}
          >
            Login
          </button>
          <button
            type="button"
            onClick={() => setMode("register")}
            className={`flex-1 rounded-md px-3 py-2 text-sm font-medium ${
              mode === "register" ? "bg-slate-900 text-white" : "text-slate-600"
            }`}
          >
            Register
          </button>
        </div>

        <form
          onSubmit={(event) => {
            event.preventDefault()
            onAuthenticate()
          }}
          className="space-y-3"
        >
          {mode === "register" && (
            <input
              required
              placeholder="Organization Name"
              className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none transition focus:border-slate-500"
            />
          )}
          <input
            required
            placeholder="Work Email"
            type="email"
            className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none transition focus:border-slate-500"
          />
          <input
            required
            placeholder="Password"
            type="password"
            className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none transition focus:border-slate-500"
          />
          <button
            type="submit"
            className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800"
          >
            <Lock className="h-4 w-4" />
            {mode === "login" ? "Sign In Securely" : "Create Secure Account"}
          </button>
        </form>
      </div>
    </div>
  )
}

function SecurityDashboard({ isOpen, onClose, identity }) {
  if (!isOpen) {
    return null
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/45 p-4">
      <div className="w-full max-w-2xl rounded-xl border border-slate-200 bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-start justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Security Dashboard</p>
            <h2 className="mt-2 text-xl font-semibold text-slate-900">Cryptographic Identity</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
          >
            Close
          </button>
        </div>

        <div className="space-y-3">
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
            <p className="mb-1 text-xs font-medium uppercase text-slate-500">Identity Key</p>
            <p className="font-mono text-xs text-slate-800">{identity.identityKey}</p>
          </div>
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
            <p className="mb-1 text-xs font-medium uppercase text-slate-500">Signed Pre-Key</p>
            <p className="font-mono text-xs text-slate-800">{identity.signedPreKey}</p>
          </div>
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
            <p className="mb-1 text-xs font-medium uppercase text-slate-500">One-Time Pre-Keys</p>
            <ul className="space-y-1 font-mono text-xs text-slate-800">
              {identity.oneTimePreKeys.map((key) => (
                <li key={key}>{key}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [activeContactId, setActiveContactId] = useState(CONTACTS[0].id)
  const [showSecurityDashboard, setShowSecurityDashboard] = useState(false)
  const [input, setInput] = useState("")
  const [identity, setIdentity] = useState(generateKeyPairs())
  const [sessionKey, setSessionKey] = useState(performX3DHKeyAgreement("SESSION-KEY-PLACEHOLDER"))
  const [messages, setMessages] = useState(
    INITIAL_MESSAGES.map((message) => ({
      ...message,
      encryptedBody: encryptMessage(message.body, "SESSION-KEY-PLACEHOLDER"),
      body: decryptMessage(encryptMessage(message.body, "SESSION-KEY-PLACEHOLDER"), "SESSION-KEY-PLACEHOLDER"),
    })),
  )

  const activeContact = useMemo(
    () => CONTACTS.find((contact) => contact.id === activeContactId) || CONTACTS[0],
    [activeContactId],
  )

  if (!isAuthenticated) {
    return (
      <AuthScreen
        onAuthenticate={() => {
          setIdentity(generateKeyPairs())
          setSessionKey(performX3DHKeyAgreement("SESSION-KEY-PLACEHOLDER"))
          setIsAuthenticated(true)
        }}
      />
    )
  }

  const sendMessage = () => {
    if (!input.trim()) {
      return
    }

    const plaintext = input.trim()
    const ciphertext = encryptMessage(plaintext, sessionKey)
    const decryptedForDisplay = decryptMessage(ciphertext, sessionKey)

    setMessages((current) => [
      ...current,
      {
        id: crypto.randomUUID(),
        sender: "me",
        encryptedBody: ciphertext,
        body: decryptedForDisplay,
      },
    ])
    setInput("")
  }

  return (
    <div className="flex min-h-screen bg-slate-100 p-4">
      <SecurityDashboard
        isOpen={showSecurityDashboard}
        onClose={() => setShowSecurityDashboard(false)}
        identity={identity}
      />

      <div className="mx-auto flex h-[calc(100vh-2rem)] w-full max-w-7xl overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <aside className="w-80 border-r border-slate-200 bg-slate-950/95 text-slate-100">
          <div className="border-b border-slate-800 p-4">
            <p className="text-xs uppercase tracking-[0.14em] text-slate-400">Messaging</p>
            <h2 className="mt-1 text-lg font-semibold text-white">Secure Channel</h2>
          </div>
          <div className="p-2">
            {CONTACTS.map((contact) => (
              <button
                type="button"
                key={contact.id}
                onClick={() => setActiveContactId(contact.id)}
                className={`mb-1 w-full rounded-lg px-3 py-3 text-left transition ${
                  activeContactId === contact.id ? "bg-slate-800 text-white" : "text-slate-300 hover:bg-slate-900"
                }`}
              >
                <p className="text-sm font-medium">{contact.name}</p>
                <p className="mt-0.5 text-xs text-slate-400">{contact.role}</p>
              </button>
            ))}
          </div>
        </aside>

        <main className="flex flex-1 flex-col bg-slate-50">
          <header className="flex items-center justify-between border-b border-slate-200 bg-white px-5 py-4">
            <div>
              <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Active Conversation</p>
              <h3 className="text-base font-semibold text-slate-900">{activeContact.name}</h3>
            </div>
            <button
              type="button"
              onClick={() => setShowSecurityDashboard(true)}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100"
            >
              <ShieldCheck className="h-4 w-4" />
              Security Dashboard
            </button>
          </header>

          <div className="flex-1 space-y-3 overflow-y-auto p-5">
            {messages.map((message) => (
              <div key={message.id} className={`flex ${message.sender === "me" ? "justify-end" : "justify-start"}`}>
                <div
                  className={`max-w-[72%] rounded-2xl px-4 py-2.5 text-sm shadow-sm ${
                    message.sender === "me"
                      ? "rounded-br-md bg-slate-900 text-white"
                      : "rounded-bl-md border border-slate-200 bg-white text-slate-800"
                  }`}
                >
                  {message.body}
                </div>
              </div>
            ))}
          </div>

          <footer className="border-t border-slate-200 bg-white p-4">
            <form
              className="flex items-center gap-2"
              onSubmit={(event) => {
                event.preventDefault()
                sendMessage()
              }}
            >
              <input
                value={input}
                onChange={(event) => setInput(event.target.value)}
                placeholder="Write a secure message"
                className="flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none transition focus:border-slate-500"
              />
              <button
                type="submit"
                className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800"
              >
                <SendHorizontal className="h-4 w-4" />
                Send
              </button>
              <button
                type="button"
                onClick={() => setShowSecurityDashboard(true)}
                className="inline-flex items-center justify-center rounded-lg border border-slate-300 bg-white p-2.5 text-slate-700 hover:bg-slate-100"
                aria-label="Open security dashboard"
              >
                <Settings className="h-4 w-4" />
              </button>
            </form>
          </footer>
        </main>
      </div>
    </div>
  )
}

export default App
