"use client";

/**
 * Same Supabase user often opens multiple tabs. They share localStorage Signal state, but the
 * symmetric ratchet only advances in the tab that sends, so sibling tabs cannot decrypt the
 * server echo of their own messages. We mirror plaintext + server ids across tabs on the same
 * origin via BroadcastChannel (no server involvement).
 */

export const SAME_USER_TAB_CHANNEL = "secure-messenger.same-user-tabs.v1";

export type SameUserTabPayload =
  | {
      type: "self_outgoing";
      senderId: string;
      recipientId: string;
      clientMessageId: string;
      content: string;
      receivedAt: string;
    }
  | {
      type: "self_echo_confirmed";
      senderId: string;
      recipientId: string;
      clientMessageId: string;
      serverMessageId: string;
      delivered?: boolean;
      created_at?: string;
    };

let channel: BroadcastChannel | null = null;

function getChannel(): BroadcastChannel | null {
  if (typeof window === "undefined" || typeof BroadcastChannel === "undefined") {
    return null;
  }
  if (!channel) {
    channel = new BroadcastChannel(SAME_USER_TAB_CHANNEL);
  }
  return channel;
}

export function broadcastSameUserTab(payload: SameUserTabPayload): void {
  getChannel()?.postMessage(payload);
}

export function subscribeSameUserTab(handler: (payload: SameUserTabPayload) => void): () => void {
  const ch = getChannel();
  if (!ch) {
    return () => {};
  }
  const listener = (ev: MessageEvent<SameUserTabPayload>) => {
    const data = ev.data;
    if (!data || typeof data !== "object" || typeof (data as SameUserTabPayload).type !== "string") {
      return;
    }
    handler(data);
  };
  ch.addEventListener("message", listener);
  return () => ch.removeEventListener("message", listener);
}
