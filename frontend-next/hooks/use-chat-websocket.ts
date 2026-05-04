"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { base64UrlToBytes, bytesToHex } from "@/lib/crypto/cryptoService";
import {
  decryptOrPlaceholder,
  decryptWithMessageKey,
  ENCRYPTED_PLACEHOLDER,
  encryptWithMessageKey,
} from "@/lib/crypto/encryption";
import { RatchetSession } from "@/lib/crypto/ratchet";
import { deriveIncomingSession } from "@/lib/crypto/x3dh";
import { ensureRegistrationKeyBundleUploaded } from "@/lib/crypto/registration";
import { KeyStorageService } from "@/lib/crypto/keyStorageService";
import { broadcastSameUserTab, subscribeSameUserTab } from "@/lib/messenger/same-user-tab-sync";
import { syncSessionToSupabase } from "@/lib/supabase/sessionStore";
import { supabase } from "@/lib/supabase/client";
import type { ChatMessage } from "@/types/chat";

const WS_BASE_URL = process.env.NEXT_PUBLIC_CHAT_WS_URL ?? "ws://localhost:8000/ws/chat";
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";

const PRIVATE_BUNDLE_PREFIX = "secure-messenger.signal.private-bundle.v1";

let peerSessionSessionStorageMigrated = false;

/** Copy `session_*` peer crypto blobs from sessionStorage once (older builds). */
function migratePeerSessionKeysFromSessionStorageOnce(): void {
  if (peerSessionSessionStorageMigrated || typeof window === "undefined") return;
  if (typeof window.sessionStorage === "undefined") return;
  peerSessionSessionStorageMigrated = true;
  const keys: string[] = [];
  for (let i = 0; i < window.sessionStorage.length; i += 1) {
    const k = window.sessionStorage.key(i);
    if (k?.startsWith("session_")) keys.push(k);
  }
  for (const k of keys) {
    const v = window.sessionStorage.getItem(k);
    if (!v) continue;
    if (!window.localStorage.getItem(k)) {
      window.localStorage.setItem(k, v);
    }
    window.sessionStorage.removeItem(k);
  }
}

/** Fired when `session_${peerId}` is written after X3DH (UI thumbprint, etc.). */
export const SIGNAL_SESSION_UPDATED_EVENT = "secure-messenger.signal-session-updated";

export function dispatchSignalSessionUpdated(detail?: { peerUserId?: string }): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(SIGNAL_SESSION_UPDATED_EVENT, { detail }));
}

function b64PrefixForLog(s: string | undefined, chars: number): string {
  if (!s || typeof s !== "string") return "(none)";
  return `${s.slice(0, chars)}…(${s.length} chars)`;
}

function bundleDebugSnapshot(bundle: unknown): Record<string, unknown> {
  if (!bundle || typeof bundle !== "object") {
    return { value: String(bundle) };
  }
  const b = bundle as Record<string, unknown>;
  const ik = b.identityKey as Record<string, string> | undefined;
  const spk = b.signedPreKey as Record<string, unknown> | undefined;
  const otks = (b.oneTimePreKeys as Record<string, string>[] | undefined) ?? [];
  return {
    deviceId: b.deviceId,
    createdAt: b.createdAt,
    identityKey: ik
      ? {
          algorithm: ik.algorithm,
          publicKey: b64PrefixForLog(ik.publicKey, 12),
          privateKey: b64PrefixForLog(ik.privateKey, 5),
        }
      : null,
    signedPreKey: spk
      ? {
          keyId: spk.keyId,
          publicKey: b64PrefixForLog(spk.publicKey as string, 12),
          privateKey: b64PrefixForLog(spk.privateKey as string, 5),
        }
      : null,
    oneTimePreKeys: otks.map((op) => ({
      keyId: op.keyId,
      publicKey: b64PrefixForLog(op.publicKey, 12),
      privateKey: b64PrefixForLog(op.privateKey, 5),
    })),
    oneTimePreKeyCount: otks.length,
  };
}

declare global {
  interface Window {
    /** DevTools: `window.__signalSession(peerUserId)` returns stored masterSecret for that peer (base64url). */
    __signalSession?: (peerId: string) => string | null;
  }
}

interface PresenceEvent {
  type: "presence";
  online_clients: string[];
}

export interface EncryptionHeader {
  ephemeral_public_key: string;
  used_one_time_pre_key_id: string | null;
  sender_identity_key_public: string;
  counter?: number;
}

interface ChatEvent {
  type: "chat";
  sender_id: string;
  recipient_id: string;
  content: string;
  client_message_id?: string;
  echo?: boolean;
  delivered?: boolean;
  encryption_header?: EncryptionHeader;
  message_id?: string;
  created_at?: string;
}

interface WsErrorEvent {
  type: "error";
  reason?: string;
  client_message_id?: string;
}

interface HistoryRow {
  message_id: string;
  sender_id: string;
  recipient_id: string;
  content: string;
  encryption_header?: EncryptionHeader | Record<string, unknown> | null;
  created_at: string;
}

/**
 * One JSON blob in localStorage per peer: X3DH metadata + serialized ratchet
 * (chains + senderCounter / receiverCounter). Survives reload and new tabs in this browser.
 * Exported so the sessionStore can reference the type when encrypting/decrypting for Supabase.
 */
export interface StoredPeerSession {
  masterSecret: string;
  ephemeralPublicKey: string;
  usedOneTimePreKeyId: string | null;
  role: "initiator" | "responder";
  ratchetJson: string;
}

function sessionKey(peerId: string): string {
  return `session_${peerId}`;
}

function readStoredPeerSession(peerId: string): StoredPeerSession | null {
  if (typeof window === "undefined") return null;
  migratePeerSessionKeysFromSessionStorageOnce();
  const raw = window.localStorage.getItem(sessionKey(peerId));
  if (!raw) return null;
  try {
    const o = JSON.parse(raw) as Record<string, unknown>;
    if (typeof o.masterSecret !== "string" || typeof o.ephemeralPublicKey !== "string") return null;
    return {
      masterSecret: o.masterSecret,
      ephemeralPublicKey: o.ephemeralPublicKey,
      usedOneTimePreKeyId:
        o.usedOneTimePreKeyId === undefined || o.usedOneTimePreKeyId === null
          ? null
          : String(o.usedOneTimePreKeyId),
      role: o.role === "responder" ? "responder" : "initiator",
      ratchetJson: typeof o.ratchetJson === "string" ? o.ratchetJson : "",
    };
  } catch {
    return null;
  }
}

function writeStoredPeerSession(
  peerId: string,
  session: StoredPeerSession,
  userId?: string,
): void {
  if (typeof window === "undefined") return;
  const json = JSON.stringify(session);
  window.localStorage.setItem(sessionKey(peerId), json);
  if (userId) {
    void syncSessionToSupabase(userId, peerId, json);
  }
}

/**
 * Load ratchet for live TX/RX: prefers saved `ratchetJson` so counters/chains
 * match the last message in this tab (deserialize restores senderCounter/receiverCounter).
 */
async function loadLiveRatchet(peerId: string): Promise<RatchetSession | null> {
  const stored = readStoredPeerSession(peerId);
  if (!stored?.masterSecret) return null;
  if (stored.ratchetJson) {
    return RatchetSession.deserialize(stored.ratchetJson);
  }
  const r = await RatchetSession.fromRootKey(base64UrlToBytes(stored.masterSecret), stored.role);
  writeStoredPeerSession(peerId, { ...stored, ratchetJson: r.serialize() });
  return r;
}

async function saveLiveRatchet(
  peerId: string,
  ratchet: RatchetSession,
  userId?: string,
): Promise<void> {
  const stored = readStoredPeerSession(peerId);
  if (!stored) return;
  writeStoredPeerSession(peerId, { ...stored, ratchetJson: ratchet.serialize() }, userId);
}

/**
 * Persist a new peer session after X3DH key agreement.
 * When `userId` is provided the session is also encrypted and synced to Supabase so that
 * the peer can recover the ratchet state when they come back online.
 */
export async function persistPeerSessionWithRatchet(
  peerId: string,
  payload: Omit<StoredPeerSession, "ratchetJson">,
  userId?: string,
): Promise<void> {
  const masterSecretHex = bytesToHex(base64UrlToBytes(payload.masterSecret));
  console.log(
    "%c[X3DH] 🔑 MasterSecret Generated:",
    "color: #ff00ff; font-weight: bold;",
    masterSecretHex,
  );
  const ratchet = await RatchetSession.fromRootKey(base64UrlToBytes(payload.masterSecret), payload.role);
  writeStoredPeerSession(peerId, { ...payload, ratchetJson: ratchet.serialize() }, userId);
}

function readActiveSession(peerId: string): {
  ephemeralPublicKey: string;
  usedOneTimePreKeyId: string | null;
} | null {
  const s = readStoredPeerSession(peerId);
  if (!s) return null;
  return {
    ephemeralPublicKey: s.ephemeralPublicKey,
    usedOneTimePreKeyId: s.usedOneTimePreKeyId,
  };
}

const DEFAULT_SIGNAL_DEVICE_ID = "primary";

export function readMyPrivateBundle(myUserId: string): unknown | null {
  if (typeof window === "undefined") return null;
  KeyStorageService.ensureLegacyPrivateBundleMigrated();
  const primaryKey = `${PRIVATE_BUNDLE_PREFIX}:${myUserId}:${DEFAULT_SIGNAL_DEVICE_ID}`;
  const primaryRaw = window.localStorage.getItem(primaryKey);
  if (primaryRaw) {
    try {
      const parsed = JSON.parse(primaryRaw) as { privateBundle?: unknown };
      if (parsed.privateBundle != null) {
        return parsed.privateBundle;
      }
    } catch {
      /* fall through */
    }
  }
  const wantedPrefix = `${PRIVATE_BUNDLE_PREFIX}:${myUserId}:`;
  for (let index = 0; index < window.localStorage.length; index += 1) {
    const key = window.localStorage.key(index);
    if (key?.startsWith(wantedPrefix)) {
      const raw = window.localStorage.getItem(key);
      if (!raw) return null;
      try {
        const parsed = JSON.parse(raw) as { privateBundle?: unknown };
        return parsed.privateBundle ?? null;
      } catch {
        return null;
      }
    }
  }
  return null;
}

async function ensureIdentitySyncWithServer(myUserId: string): Promise<boolean> {
  const local = readMyPrivateBundle(myUserId) as { identityKey?: { publicKey?: string } } | null;
  const localIk = local?.identityKey?.publicKey;
  if (!localIk) return false;

  const {
    data: { session },
  } = await supabase.auth.getSession();
  const token = session?.access_token;
  if (!token) return false;

  const url = `${API_BASE_URL}/api/users/${encodeURIComponent(myUserId)}/key-bundle?peek_own_bundle=true`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  if (!res.ok) return false;

  const row = (await res.json()) as { identity_key_public?: string };
  const serverIk = row.identity_key_public;
  if (!serverIk || serverIk === localIk) return false;

  console.warn(
    "[Signal] identity_key_public mismatch vs server; re-uploading key bundle for user",
    myUserId,
  );
  await ensureRegistrationKeyBundleUploaded({ userId: myUserId, accessToken: token });
  return true;
}

export function readStoredMasterSecret(peerId: string): string | null {
  const s = readStoredPeerSession(peerId);
  return s?.masterSecret?.length ? s.masterSecret : null;
}

export async function maybeDeriveSession(
  myUserId: string,
  senderId: string,
  header: unknown,
): Promise<void> {
  if (typeof window === "undefined") return;
  if (!header || senderId === myUserId) return;
  if (readStoredMasterSecret(senderId)) return;
  if (!isUsableEncryptionHeader(header)) return;

  await ensureIdentitySyncWithServer(myUserId);

  const myPrivateBundle = readMyPrivateBundle(myUserId);
  if (!myPrivateBundle) {
    console.warn("[ChatWS] deriveIncomingSession skipped: no local privateBundle in localStorage.");
    return;
  }

  const localOpkIds = ((myPrivateBundle as { oneTimePreKeys?: { keyId: unknown }[] }).oneTimePreKeys ?? []).map(
    (k) => String(k.keyId),
  );
  console.log("[Signal][rx] header from", senderId, {
    ephemeral_public_key: header.ephemeral_public_key,
    used_one_time_pre_key_id: header.used_one_time_pre_key_id,
    sender_identity_key_public: header.sender_identity_key_public,
    localOpkIds,
  });

  const myBundleForLog = myPrivateBundle as { identityKey?: { publicKey?: string } };
  console.log(
    "[Signal][rx] Deriving with senderIK:",
    header.sender_identity_key_public,
    "and myIdentityPub:",
    myBundleForLog.identityKey?.publicKey,
  );

  console.log("[Signal][rx] encryption_header (full JSON, pre-derive):", {
    ephemeral_public_key: header.ephemeral_public_key,
    used_one_time_pre_key_id: header.used_one_time_pre_key_id,
    sender_identity_key_public: header.sender_identity_key_public,
  });
  console.log("[Signal][rx] myPrivateBundle from localStorage (sanitized):", bundleDebugSnapshot(myPrivateBundle));

  const persistSession = async (masterSecret: string) => {
    await persistPeerSessionWithRatchet(
      senderId,
      {
        masterSecret,
        ephemeralPublicKey: header.ephemeral_public_key,
        usedOneTimePreKeyId: header.used_one_time_pre_key_id,
        role: "responder",
      },
      myUserId,
    );
    dispatchSignalSessionUpdated({ peerUserId: senderId });
  };

  const attemptDerive = async (bundle: unknown) => {
    const { masterSecret } = await deriveIncomingSession(
      bundle,
      header.sender_identity_key_public,
      header.ephemeral_public_key,
      header.used_one_time_pre_key_id,
    );
    await persistSession(masterSecret);
  };

  try {
    await attemptDerive(myPrivateBundle);
  } catch (error) {
    const enc = header as EncryptionHeader;
    const rxIk = (myPrivateBundle as { identityKey?: { publicKey?: string } })?.identityKey?.publicKey;
    console.error(
      "[Signal][rx] Derivation failed. The wire header advertises sender_identity_key_public; the sender must use the private key that matches that public key for X3DH.",
      {
        wire_sender_identity_key_public: enc.sender_identity_key_public,
        receiver_local_identity_key_public: rxIk,
      },
    );
    console.error("[Signal] deriveIncomingSession failed:", error, {
      senderId,
      headerSummary: {
        ephemeral_public_key: enc.ephemeral_public_key?.slice?.(0, 24),
        used_one_time_pre_key_id: enc.used_one_time_pre_key_id,
        sender_identity_key_public: enc.sender_identity_key_public?.slice?.(0, 24),
      },
      localOpkIds,
    });
    await ensureIdentitySyncWithServer(myUserId);
    const bundleAfterSync = readMyPrivateBundle(myUserId);
    if (!bundleAfterSync) return;
    try {
      await attemptDerive(bundleAfterSync);
    } catch (retryError) {
      const enc2 = header as EncryptionHeader;
      const rxIk2 = (bundleAfterSync as { identityKey?: { publicKey?: string } })?.identityKey?.publicKey;
      console.error(
        "[Signal][rx] Derivation failed after re-sync.",
        { wire_sender_identity_key_public: enc2.sender_identity_key_public, receiver_local_identity_key_public: rxIk2 },
      );
      console.error("[Signal] deriveIncomingSession retry failed:", retryError, { senderId, localOpkIds });
    }
  }
}

function isUsableEncryptionHeader(h: unknown): h is EncryptionHeader {
  if (!h || typeof h !== "object") return false;
  const o = h as Record<string, unknown>;
  return (
    typeof o.ephemeral_public_key === "string" &&
    o.ephemeral_public_key.length > 0 &&
    typeof o.sender_identity_key_public === "string" &&
    o.sender_identity_key_public.length > 0
  );
}

export interface UseChatWebSocketOptions {
  /** When false, the WebSocket stays closed until local Signal keys are initialized. */
  cryptoReady?: boolean;
}

export function useChatWebSocket(clientId: string, options?: UseChatWebSocketOptions) {
  const cryptoReady = options?.cryptoReady ?? true;
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [onlineClients, setOnlineClients] = useState<string[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.__signalSession = (peerId: string) => readStoredMasterSecret(peerId);
  }, []);

  useEffect(() => {
    if (!cryptoReady) return;
    return subscribeSameUserTab((payload) => {
      if (payload.senderId !== clientId) return;
      if (payload.type === "self_outgoing") {
        setMessages((prev) => {
          if (prev.some((m) => m.clientMessageId === payload.clientMessageId)) return prev;
          return [
            ...prev,
            {
              senderId: payload.senderId,
              recipientId: payload.recipientId,
              content: payload.content,
              clientMessageId: payload.clientMessageId,
              echo: true,
              delivered: false,
              receivedAt: payload.receivedAt,
            },
          ];
        });
        return;
      }
      if (payload.type === "self_echo_confirmed") {
        setMessages((prev) => {
          const idx = prev.findIndex((m) => m.clientMessageId === payload.clientMessageId);
          if (idx < 0) return prev;
          const updated = [...prev];
          updated[idx] = {
            ...updated[idx],
            clientMessageId: payload.serverMessageId,
            echo: true,
            delivered: payload.delivered ?? updated[idx].delivered,
            receivedAt: payload.created_at ?? updated[idx].receivedAt,
          };
          return updated;
        });
      }
    });
  }, [clientId, cryptoReady]);

  const loadConversation = useCallback(
    async (peerId: string, accessToken: string) => {
      const url = `${API_BASE_URL}/api/conversations/${encodeURIComponent(peerId)}/messages?limit=50`;
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!res.ok) {
        console.warn("[ChatWS] loadConversation failed:", res.status, await res.text().catch(() => ""));
        return;
      }
      const rows = (await res.json()) as HistoryRow[];
      const rowsChrono = [...rows].sort(
        (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
      );

      for (const row of rowsChrono) {
        await maybeDeriveSession(clientId, row.sender_id, row.encryption_header);
      }

      const stored = readStoredPeerSession(peerId);
      // Replay from chain index 0 so header.counter aligns (does not mutate live ratchet in session_${peerId}).
      const replay =
        stored?.masterSecret &&
        (await RatchetSession.fromRootKey(base64UrlToBytes(stored.masterSecret), stored.role));

      const decryptedRows: { row: HistoryRow; content: string }[] = [];
      for (const row of rowsChrono) {
        const header = row.encryption_header as EncryptionHeader | undefined;
        const sessionPeerId = row.sender_id === clientId ? row.recipient_id : row.sender_id;
        let content: string;

        if (replay && header && typeof header.counter === "number") {
          try {
            if (row.sender_id === clientId) {
              const messageKey = await replay.advanceSenderTo(header.counter);
              content = await decryptWithMessageKey(messageKey, row.content);
            } else {
              const mk = await replay.advanceReceiverTo(header.counter);
              content = await decryptWithMessageKey(mk, row.content);
            }
          } catch {
            content = await decryptOrPlaceholder(readStoredMasterSecret(sessionPeerId), row.content);
          }
        } else if (replay && row.sender_id === clientId) {
          try {
            const { messageKey } = await replay.getNextSenderKey();
            content = await decryptWithMessageKey(messageKey, row.content);
          } catch {
            content = await decryptOrPlaceholder(readStoredMasterSecret(sessionPeerId), row.content);
          }
        } else {
          content = await decryptOrPlaceholder(readStoredMasterSecret(sessionPeerId), row.content);
        }

        decryptedRows.push({ row, content });
      }

      setMessages((prev) => {
        const seen = new Set<string>();
        for (const m of prev) {
          if (m.clientMessageId) seen.add(m.clientMessageId);
        }
        const merged = [...prev];
        for (const { row, content } of decryptedRows) {
          const stableId = row.message_id;
          if (seen.has(stableId)) continue;
          seen.add(stableId);
          merged.push({
            senderId: row.sender_id,
            recipientId: row.recipient_id,
            content,
            clientMessageId: stableId,
            receivedAt: row.created_at,
          });
        }
        return merged;
      });
    },
    [clientId],
  );

  useEffect(() => {
    if (!cryptoReady) {
      setIsConnected(false);
      return;
    }

    let isMounted = true;

    function connect() {
      const socket = new WebSocket(`${WS_BASE_URL}/${encodeURIComponent(clientId)}`);
      socketRef.current = socket;

      socket.onopen = () => setIsConnected(true);
      socket.onerror = () => setIsConnected(false);
      socket.onclose = () => {
        setIsConnected(false);
        if (isMounted) {
          reconnectTimerRef.current = setTimeout(connect, 1500);
        }
      };
      socket.onmessage = (event) => {
        let payload: PresenceEvent | ChatEvent | WsErrorEvent;

        try {
          payload = JSON.parse(event.data) as PresenceEvent | ChatEvent | WsErrorEvent;
        } catch {
          return;
        }

        if (payload.type === "presence") {
          setOnlineClients(payload.online_clients);
          return;
        }

        if (payload.type === "error") {
          console.error(
            "[ChatWS] Server rejected message:",
            payload.reason,
            "client_message_id =",
            payload.client_message_id,
          );
          return;
        }

        const chat = payload as ChatEvent;
        const stableClientId = chat.message_id ?? chat.client_message_id;
        const sessionPeerId = chat.sender_id === clientId ? chat.recipient_id : chat.sender_id;

        const appendMessage = (content: string) => {
          setMessages((prev) => {
            if (stableClientId && prev.some((m) => m.clientMessageId === stableClientId)) {
              return prev;
            }
            return [
              ...prev,
              {
                senderId: chat.sender_id,
                recipientId: chat.recipient_id,
                content,
                clientMessageId: stableClientId,
                echo: chat.echo,
                delivered: chat.delivered,
                receivedAt: chat.created_at ?? new Date().toISOString(),
              },
            ];
          });
        };

        const handleDecryptedAppend = async () => {
          if (chat.echo) {
            setMessages((prev) => {
              const localMatchIdx = prev.findIndex((m) => m.clientMessageId === chat.client_message_id);
              if (localMatchIdx >= 0) {
                const cid = chat.client_message_id;
                const sid = chat.message_id;
                if (cid && chat.sender_id === clientId) {
                  queueMicrotask(() => {
                    broadcastSameUserTab({
                      type: "self_echo_confirmed",
                      senderId: clientId,
                      recipientId: chat.recipient_id,
                      clientMessageId: cid,
                      serverMessageId: typeof sid === "string" && sid.length > 0 ? sid : cid,
                      delivered: chat.delivered,
                      created_at: chat.created_at,
                    });
                  });
                }
                const updated = [...prev];
                updated[localMatchIdx] = {
                  ...updated[localMatchIdx],
                  clientMessageId: chat.message_id ?? updated[localMatchIdx].clientMessageId,
                  echo: true,
                  delivered: chat.delivered,
                  receivedAt: chat.created_at ?? updated[localMatchIdx].receivedAt,
                };
                return updated;
              }
              if (stableClientId && prev.some((m) => m.clientMessageId === stableClientId)) {
                return prev;
              }
              return [
                ...prev,
                {
                  senderId: chat.sender_id,
                  recipientId: chat.recipient_id,
                  content: ENCRYPTED_PLACEHOLDER,
                  clientMessageId: stableClientId,
                  echo: true,
                  delivered: chat.delivered,
                  receivedAt: chat.created_at ?? new Date().toISOString(),
                },
              ];
            });
            return;
          }

          if (chat.sender_id !== clientId && chat.encryption_header) {
            await maybeDeriveSession(clientId, chat.sender_id, chat.encryption_header);
          }

          const header = chat.encryption_header as EncryptionHeader | undefined;
          let decrypted: string;
          if (header && typeof header.counter === "number") {
            try {
              const ratchet = await loadLiveRatchet(sessionPeerId);
              if (!ratchet) {
                decrypted = ENCRYPTED_PLACEHOLDER;
              } else {
                const messageKey = await ratchet.advanceReceiverTo(header.counter);
                await saveLiveRatchet(sessionPeerId, ratchet, clientId);
                decrypted = await decryptWithMessageKey(messageKey, chat.content);
              }
            } catch {
              decrypted = await decryptOrPlaceholder(readStoredMasterSecret(sessionPeerId), chat.content);
            }
          } else {
            decrypted = await decryptOrPlaceholder(readStoredMasterSecret(sessionPeerId), chat.content);
          }
          appendMessage(decrypted);
        };

        void handleDecryptedAppend();
      };
    }

    connect();

    return () => {
      isMounted = false;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [clientId, cryptoReady]);

  const sendMessage = useCallback(
    async (message: Omit<ChatMessage, "delivered" | "echo" | "receivedAt">) => {
      if (!cryptoReady) {
        console.warn("[ChatWS] Refusing to send: Signal crypto is not ready yet.");
        return;
      }
      if (!socketRef.current || socketRef.current.readyState !== WebSocket.OPEN) {
        return;
      }

      const session = readActiveSession(message.recipientId);
      const masterSecret = readStoredMasterSecret(message.recipientId);
      if (!session?.ephemeralPublicKey || !masterSecret) {
        console.warn(
          `[ChatWS] Refusing to send: no Signal session/masterSecret for ${message.recipientId}. Click again to establish session.`,
        );
        return;
      }
      const myBundle = readMyPrivateBundle(clientId) as {
        identityKey?: { publicKey?: string; privateKey?: string };
      } | null;
      const senderIK = myBundle?.identityKey?.publicKey;
      if (!senderIK || !myBundle?.identityKey) {
        console.warn(
          "[ChatWS] Refusing to send: sender identity key not found in localStorage (primary bundle).",
        );
        return;
      }

      let ciphertext: string;
      let counter: number;
      try {
        const ratchet = await loadLiveRatchet(message.recipientId);
        if (!ratchet) throw new Error("no ratchet");
        const next = await ratchet.getNextSenderKey();
        await saveLiveRatchet(message.recipientId, ratchet, clientId);
        ciphertext = await encryptWithMessageKey(next.messageKey, message.content);
        counter = next.counter;
      } catch (error) {
        console.error("[ChatWS] Encryption failed; not sending:", error);
        return;
      }

      const encryptionHeader: EncryptionHeader = {
        ephemeral_public_key: session.ephemeralPublicKey,
        used_one_time_pre_key_id: session.usedOneTimePreKeyId,
        sender_identity_key_public: senderIK,
        counter,
      };

      const receivedAt = new Date().toISOString();
      if (message.clientMessageId) {
        broadcastSameUserTab({
          type: "self_outgoing",
          senderId: clientId,
          recipientId: message.recipientId,
          clientMessageId: message.clientMessageId,
          content: message.content,
          receivedAt,
        });
      }

      setMessages((prev) => {
        if (prev.some((m) => m.clientMessageId === message.clientMessageId)) return prev;
        return [
          ...prev,
          {
            senderId: clientId,
            recipientId: message.recipientId,
            content: message.content,
            clientMessageId: message.clientMessageId,
            echo: true,
            delivered: false,
            receivedAt,
          },
        ];
      });

      socketRef.current.send(
        JSON.stringify({
          recipient_id: message.recipientId,
          content: ciphertext,
          client_message_id: message.clientMessageId,
          encryption_header: encryptionHeader,
        }),
      );
    },
    [clientId, cryptoReady],
  );

  return {
    isConnected,
    messages,
    onlineClients,
    sendMessage,
    loadConversation,
    cryptoReady,
  };
}
