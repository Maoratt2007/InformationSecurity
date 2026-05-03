"use client";

import { bytesToHex, hexToBytes } from "./cryptoService";

const LABEL_AB = new TextEncoder().encode("secure-messenger.ratchet.chain.AB.v1");
const LABEL_BA = new TextEncoder().encode("secure-messenger.ratchet.chain.BA.v1");
const KDF_MSG = new Uint8Array([0x01]);
const KDF_CHAIN = new Uint8Array([0x02]);

type RatchetRole = "initiator" | "responder";

/** Wire JSON for localStorage — hex-encoded key material + counters. */
interface RatchetWireV1 {
  v: 1;
  role: RatchetRole;
  rootKey: string;
  senderChain: string;
  receiverChain: string;
  senderCounter: number;
  receiverCounter: number;
}

/**
 * Symmetric ratchet: sender / receiver chains from shared rootKey; one step:
 * messageKey = HMAC-SHA256(chainKey, 0x01), nextChain = HMAC-SHA256(chainKey, 0x02).
 */
export class RatchetSession {
  private readonly rootKey: Uint8Array;
  private readonly role: RatchetRole;
  private senderChain: Uint8Array;
  private receiverChain: Uint8Array;
  private senderCounter: number;
  private receiverCounter: number;

  private constructor(rootKey: Uint8Array, role: RatchetRole) {
    if (rootKey.length === 0) {
      throw new Error("RatchetSession: rootKey must be non-empty.");
    }
    this.rootKey = new Uint8Array(rootKey);
    this.role = role;
    this.senderCounter = 0;
    this.receiverCounter = 0;
    this.senderChain = new Uint8Array(0);
    this.receiverChain = new Uint8Array(0);
  }

  static async fromRootKey(rootKey: Uint8Array, role: RatchetRole): Promise<RatchetSession> {
    const session = new RatchetSession(rootKey, role);
    const ab = await RatchetSession.hmacSha256(session.rootKey, LABEL_AB);
    const ba = await RatchetSession.hmacSha256(session.rootKey, LABEL_BA);
    if (session.role === "initiator") {
      session.senderChain = ab;
      session.receiverChain = ba;
    } else {
      session.senderChain = ba;
      session.receiverChain = ab;
    }
    return session;
  }

  async getNextSenderKey(): Promise<{ messageKey: Uint8Array; counter: number }> {
    if (this.senderChain.length !== 32) {
      throw new Error("RatchetSession.getNextSenderKey: invalid sender chain.");
    }
    const counter = this.senderCounter;
    const hexKey = bytesToHex(this.senderChain);
    console.log("[Ratchet-Debug] Send: senderChainKey (before roll)=", hexKey, "counter=", counter);
    const { messageKey, chainKey } = await RatchetSession.kdfChainStep(this.senderChain);
    console.log("[Ratchet-Debug] Send: derived messageKey=", bytesToHex(messageKey));
    this.senderChain = chainKey;
    this.senderCounter += 1;
    console.log("[Ratchet-Debug] Send: new senderChainKey=", bytesToHex(this.senderChain));
    return { messageKey, counter };
  }

  /**
   * Derives the sender message key for a past outbound message whose `encryption_header.counter`
   * was `counter`, without requiring full history from the first message (unlike sequential
   * `getNextSenderKey` replay). Mirrors {@link advanceReceiverTo} on the sender chain.
   */
  async advanceSenderTo(counter: number): Promise<Uint8Array> {
    if (this.senderChain.length !== 32) {
      throw new Error("RatchetSession.advanceSenderTo: invalid sender chain.");
    }
    if (!Number.isInteger(counter) || counter < 0) {
      throw new Error("RatchetSession.advanceSenderTo: counter must be a non-negative integer.");
    }
    if (counter < this.senderCounter) {
      throw new Error(
        `RatchetSession.advanceSenderTo: stale counter ${counter} (next expected ${this.senderCounter}).`,
      );
    }
    while (this.senderCounter < counter) {
      const { chainKey } = await RatchetSession.kdfChainStep(this.senderChain);
      this.senderChain = chainKey;
      this.senderCounter += 1;
    }
    const { messageKey, chainKey } = await RatchetSession.kdfChainStep(this.senderChain);
    this.senderChain = chainKey;
    this.senderCounter += 1;
    return messageKey;
  }

  async advanceReceiverTo(counter: number): Promise<Uint8Array> {
    if (this.receiverChain.length !== 32) {
      throw new Error("RatchetSession.advanceReceiverTo: invalid receiver chain.");
    }
    if (!Number.isInteger(counter) || counter < 0) {
      throw new Error("RatchetSession.advanceReceiverTo: counter must be a non-negative integer.");
    }
    console.log(
      "[Ratchet-Debug] Receive: counter from header=",
      counter,
      "expected=",
      this.receiverCounter,
    );
    if (counter < this.receiverCounter) {
      throw new Error(
        `RatchetSession.advanceReceiverTo: stale counter ${counter} (next expected ${this.receiverCounter}).`,
      );
    }
    if (this.receiverCounter < counter) {
      console.log(
        `[Ratchet-Debug] Skipping keys from index ${this.receiverCounter} to ${counter - 1}`,
      );
    }
    while (this.receiverCounter < counter) {
      const { chainKey } = await RatchetSession.kdfChainStep(this.receiverChain);
      this.receiverChain = chainKey;
      this.receiverCounter += 1;
    }
    const { messageKey, chainKey } = await RatchetSession.kdfChainStep(this.receiverChain);
    console.log("[Ratchet-Debug] Receive: derived decryptionKey=", bytesToHex(messageKey));
    this.receiverChain = chainKey;
    this.receiverCounter += 1;
    return messageKey;
  }

  serialize(): string {
    const wire: RatchetWireV1 = {
      v: 1,
      role: this.role,
      rootKey: bytesToHex(this.rootKey),
      senderChain: bytesToHex(this.senderChain),
      receiverChain: bytesToHex(this.receiverChain),
      senderCounter: this.senderCounter,
      receiverCounter: this.receiverCounter,
    };
    return JSON.stringify(wire);
  }

  /** Restores chains and sender/receiver counters from localStorage JSON. */
  static async deserialize(json: string): Promise<RatchetSession> {
    const wire = JSON.parse(json) as RatchetWireV1;
    if (wire.v !== 1 || (wire.role !== "initiator" && wire.role !== "responder")) {
      throw new Error("RatchetSession.deserialize: unsupported wire format.");
    }
    const session = new RatchetSession(hexToBytes(wire.rootKey), wire.role);
    session.senderChain = hexToBytes(wire.senderChain);
    session.receiverChain = hexToBytes(wire.receiverChain);
    session.senderCounter = wire.senderCounter;
    session.receiverCounter = wire.receiverCounter;
    if (session.senderChain.length !== 32 || session.receiverChain.length !== 32) {
      throw new Error("RatchetSession.deserialize: chain keys must be 32 bytes.");
    }
    return session;
  }

  private static async hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      RatchetSession.sliceBuffer(key),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", cryptoKey, RatchetSession.sliceBuffer(data));
    return new Uint8Array(sig);
  }

  private static async kdfChainStep(chainKey: Uint8Array): Promise<{
    messageKey: Uint8Array;
    chainKey: Uint8Array;
  }> {
    const messageKey = await RatchetSession.hmacSha256(chainKey, KDF_MSG);
    const nextChain = await RatchetSession.hmacSha256(chainKey, KDF_CHAIN);
    return { messageKey, chainKey: nextChain };
  }

  private static sliceBuffer(u8: Uint8Array): ArrayBuffer {
    return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
  }
}
