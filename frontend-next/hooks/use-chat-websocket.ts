"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { deriveIncomingSession } from "@/lib/crypto/x3dh";
import type { ChatMessage } from "@/types/chat";

const WS_BASE_URL = process.env.NEXT_PUBLIC_CHAT_WS_URL ?? "ws://localhost:8000/ws/chat";

const PRIVATE_BUNDLE_PREFIX = "secure-messenger.signal.private-bundle.v1";

interface PresenceEvent {
  type: "presence";
  online_clients: string[];
}

interface EncryptionHeader {
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

function readMyPrivateBundle(myUserId: string): unknown | null {
  if (typeof window === "undefined") return null;
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

export function useChatWebSocket(clientId: string) {
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [onlineClients, setOnlineClients] = useState<string[]>([]);
  const [isConnected, setIsConnected] = useState(false);

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
        let payload: PresenceEvent | ChatEvent;

        try {
          payload = JSON.parse(event.data) as PresenceEvent | ChatEvent;
        } catch {
          return;
        }

        if (payload.type === "presence") {
          setOnlineClients(payload.online_clients);
          return;
        }

        if (
          !payload.echo &&
          payload.sender_id !== clientId &&
          payload.encryption_header &&
          typeof window !== "undefined" &&
          !window.sessionStorage.getItem(`session_${payload.sender_id}`)
        ) {
          const header = payload.encryption_header;
          const myPrivateBundle = readMyPrivateBundle(clientId);
          if (myPrivateBundle) {
            void (async () => {
              try {
                const { masterSecret } = await deriveIncomingSession(
                  myPrivateBundle,
                  header.sender_identity_key_public,
                  header.ephemeral_public_key,
                  header.used_one_time_pre_key_id,
                );
                window.sessionStorage.setItem(
                  `session_${payload.sender_id}`,
                  JSON.stringify({ masterSecret }),
                );
                console.log(`[Signal] Incoming session derived from ${payload.sender_id}`);
              } catch (error) {
                console.error("[Signal] deriveIncomingSession failed:", error);
              }
            })();
          } else {
            console.warn(
              "[ChatWS] Received encryption_header but no local privateBundle in sessionStorage.",
            );
          }
        }

        setMessages((prev) => [
          ...prev,
          {
            senderId: payload.sender_id,
            recipientId: payload.recipient_id,
            content: payload.content,
            clientMessageId: payload.client_message_id,
            echo: payload.echo,
            delivered: payload.delivered,
            receivedAt: new Date().toISOString(),
          },
        ]);
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
  }, [clientId]);

  const sendMessage = useCallback(
    (message: Omit<ChatMessage, "delivered" | "echo" | "receivedAt">) => {
      if (!socketRef.current || socketRef.current.readyState !== WebSocket.OPEN) {
        return;
      }

      let encryptionHeader: EncryptionHeader | undefined;
      const session = readActiveSession(message.recipientId);
      if (session?.ephemeralPublicKey) {
        const myBundle = readMyPrivateBundle(clientId) as { identityKey?: { publicKey?: string } } | null;
        const senderIK = myBundle?.identityKey?.publicKey;
        if (senderIK) {
          encryptionHeader = {
            ephemeral_public_key: session.ephemeralPublicKey,
            used_one_time_pre_key_id: session.usedOneTimePreKeyId,
            sender_identity_key_public: senderIK,
          };
        } else {
          console.warn(
            "[ChatWS] Skipping encryption_header: sender identity key not found in sessionStorage.",
          );
        }
      }

      socketRef.current.send(
        JSON.stringify({
          recipient_id: message.recipientId,
          content: message.content,
          client_message_id: message.clientMessageId,
          ...(encryptionHeader ? { encryption_header: encryptionHeader } : {}),
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
  };
}
