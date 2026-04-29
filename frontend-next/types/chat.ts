export interface ChatContact {
  id: string;
  name: string;
  status: "online" | "offline";
}

export interface ChatMessage {
  senderId: string;
  recipientId: string;
  content: string;
  clientMessageId?: string;
  echo?: boolean;
  delivered?: boolean;
  receivedAt: string;
}
