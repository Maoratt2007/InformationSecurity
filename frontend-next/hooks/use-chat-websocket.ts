"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  decryptOrPlaceholder,
  ENCRYPTED_PLACEHOLDER,
  encryptMessage,
} from "@/lib/crypto/encryption";
import { deriveIncomingSession } from "@/lib/crypto/x3dh";
import { ensureRegistrationKeyBundleUploaded } from "@/lib/crypto/registration";
import { supabase } from "@/lib/supabase/client";
import type { ChatMessage } from "@/types/chat";

const WS_BASE_URL = process.env.NEXT_PUBLIC_CHAT_WS_URL ?? "ws://localhost:8000/ws/chat";
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";

const PRIVATE_BUNDLE_PREFIX = "secure-messenger.signal.private-bundle.v1";

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

function readActiveSession(peerId: string): {
  ephemeralPublicKey: string;
  usedOneTimePreKeyId: string | null;
} | null {
  if (typeof window === "undefined") return null;
  const raw = window.sessionStorage.getItem(`session_${peerId}`);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (typeof parsed?.ephemeralPublicKey === "string") {
      return {
        ephemeralPublicKey: parsed.ephemeralPublicKey,
        usedOneTimePreKeyId:
          parsed.usedOneTimePreKeyId === undefined || parsed.usedOneTimePreKeyId === null
            ? null
            : String(parsed.usedOneTimePreKeyId),
      };
    }
  } catch {
    /* ignore */
  }
  return null;
}

/** Must match `KeyStorageService` / `establishSession` — always prefer the `primary` device bundle. */
const DEFAULT_SIGNAL_DEVICE_ID = "primary";

/** Same storage slot as `use-signal-session` / X3DH so header IK and DH1 use one bundle. */
export function readMyPrivateBundle(myUserId: string): unknown | null {
  if (typeof window === "undefined") return null;
  const primaryKey = `${PRIVATE_BUNDLE_PREFIX}:${myUserId}:${DEFAULT_SIGNAL_DEVICE_ID}`;
  const primaryRaw = window.sessionStorage.getItem(primaryKey);
  if (primaryRaw) {
    try {
      const parsed = JSON.parse(primaryRaw) as { privateBundle?: unknown };
      if (parsed.privateBundle != null) {
        return parsed.privateBundle;
      }
    } catch {
      /* fall through to scan */
    }
  }
  const wantedPrefix = `${PRIVATE_BUNDLE_PREFIX}:${myUserId}:`;
  for (let index = 0; index < window.sessionStorage.length; index += 1) {
    const key = window.sessionStorage.key(index);
    if (key?.startsWith(wantedPrefix)) {
      const raw = window.sessionStorage.getItem(key);
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

/**
 * If the server's stored identity key for this user differs from the local bundle's public IK,
 * re-upload the key bundle so senders fetch a consistent identity.
 * Returns true when a re-registration upload was performed.
 */
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

/** Returns a non-empty masterSecret for `session_{peerId}` or null if missing/invalid. */
export function readStoredMasterSecret(peerId: string): string | null {
  if (typeof window === "undefined") return null;
  const raw = window.sessionStorage.getItem(`session_${peerId}`);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as { masterSecret?: unknown };
    return typeof parsed.masterSecret === "string" && parsed.masterSecret.length > 0
      ? parsed.masterSecret
      : null;
  } catch {
    return null;
  }
}

/** Passive receiver: derive masterSecret from first message header only (no key-bundle fetch). */
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
    console.warn("[ChatWS] deriveIncomingSession skipped: no local privateBundle in sessionStorage.");
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
  console.log("[Signal][rx] myPrivateBundle from sessionStorage (sanitized):", bundleDebugSnapshot(myPrivateBundle));

  const persistSession = (masterSecret: string) => {
    window.sessionStorage.setItem(
      `session_${senderId}`,
      JSON.stringify({
        masterSecret,
        ephemeralPublicKey: header.ephemeral_public_key,
        usedOneTimePreKeyId: header.used_one_time_pre_key_id,
      }),
    );
    console.log(
      `[Signal] Incoming session derived from ${senderId} masterSecret=${masterSecret.slice(0, 16)}…`,
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
    persistSession(masterSecret);
  };

  try {
    await attemptDerive(myPrivateBundle);
  } catch (error) {
    const enc = header as EncryptionHeader;
    const rxIk = (myPrivateBundle as { identityKey?: { publicKey?: string } })?.identityKey?.publicKey;
    console.error(
      "[Signal][rx] Derivation failed. The wire header advertises sender_identity_key_public; the sender must use the private key that matches that public key for X3DH. If the header used a key from a different device slot or stale bundle, DH1/DH2 will not match the receiver.",
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
      const enc = header as EncryptionHeader;
      const rxIk = (bundleAfterSync as { identityKey?: { publicKey?: string } })?.identityKey?.publicKey;
      console.error(
        "[Signal][rx] Derivation failed after re-sync. Wire sender identity still inconsistent with X3DH math or local receiver keys.",
        { wire_sender_identity_key_public: enc.sender_identity_key_public, receiver_local_identity_key_public: rxIk },
      );
      console.error("[Signal] deriveIncomingSession retry failed:", retryError, {
        senderId,
        localOpkIds,
      });
    }
  }
}

export function useChatWebSocket(clientId: string) {
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [onlineClients, setOnlineClients] = useState<string[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.__signalSession = (peerId: string) => readStoredMasterSecret(peerId);
  }, []);

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

      for (const row of rows) {
        await maybeDeriveSession(clientId, row.sender_id, row.encryption_header);
      }

      const decryptedRows = await Promise.all(
        rows.map(async (row) => {
          const sessionPeerId = row.sender_id === clientId ? row.recipient_id : row.sender_id;
          const masterSecret = readStoredMasterSecret(sessionPeerId);
          const content = await decryptOrPlaceholder(masterSecret, row.content);
          return { row, content };
        }),
      );

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
          if (!chat.echo && chat.sender_id !== clientId && chat.encryption_header) {
            await maybeDeriveSession(clientId, chat.sender_id, chat.encryption_header);
          }
          const masterSecret = readStoredMasterSecret(sessionPeerId);
          const decrypted = chat.content
            ? await decryptOrPlaceholder(masterSecret, chat.content)
            : ENCRYPTED_PLACEHOLDER;
          appendMessage(decrypted);
        };

        void handleDecryptedAppend();
      };
    }

    connect();

    return () => {
      // NOTE: do not touch sessionStorage here. Signal sessions must persist across reconnects.
      isMounted = false;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [clientId]);

  const sendMessage = useCallback(
    async (message: Omit<ChatMessage, "delivered" | "echo" | "receivedAt">) => {
      if (!socketRef.current || socketRef.current.readyState !== WebSocket.OPEN) {
        return;
      }

      let encryptionHeader: EncryptionHeader | undefined;
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
          "[ChatWS] Refusing to send: sender identity key not found in sessionStorage (primary bundle).",
        );
        return;
      }
      encryptionHeader = {
        ephemeral_public_key: session.ephemeralPublicKey,
        used_one_time_pre_key_id: session.usedOneTimePreKeyId,
        sender_identity_key_public: senderIK,
      };

      let ciphertext: string;
      try {
        ciphertext = await encryptMessage(masterSecret, message.content);
      } catch (error) {
        console.error("[ChatWS] Encryption failed; not sending:", error);
        return;
      }

      socketRef.current.send(
        JSON.stringify({
          recipient_id: message.recipientId,
          content: ciphertext,
          client_message_id: message.clientMessageId,
          encryption_header: encryptionHeader,
        }),
      );
    },
    [clientId],
  );

  return {
    isConnected,
    messages,
    onlineClients,
    sendMessage,
    loadConversation,
  };
}
