"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ChatMessage } from "@/types/chat";

const WS_BASE_URL = process.env.NEXT_PUBLIC_CHAT_WS_URL ?? "ws://localhost:8000/ws/chat";

interface PresenceEvent {
  type: "presence";
  online_clients: string[];
}

interface ChatEvent {
  type: "chat";
  sender_id: string;
  recipient_id: string;
  content: string;
  client_message_id?: string;
  echo?: boolean;
  delivered?: boolean;
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

  const sendMessage = useCallback((message: Omit<ChatMessage, "delivered" | "echo" | "receivedAt">) => {
    if (!socketRef.current || socketRef.current.readyState !== WebSocket.OPEN) {
      return;
    }

    socketRef.current.send(
      JSON.stringify({
        recipient_id: message.recipientId,
        content: message.content,
        client_message_id: message.clientMessageId,
      }),
    );
  }, []);

  return {
    isConnected,
    messages,
    onlineClients,
    sendMessage,
  };
}
