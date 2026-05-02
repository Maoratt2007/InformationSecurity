"use client";

import { bytesToHex, hexToBytes } from "./cryptoService";

const LABEL_AB = new TextEncoder().encode("secure-messenger.ratchet.chain.AB.v1");
const LABEL_BA = new TextEncoder().encode("secure-messenger.ratchet.chain.BA.v1");
const KDF_MSG = new Uint8Array([0x01]);
const KDF_CHAIN = new Uint8Array([0x02]);

type RatchetRole = "initiator" | "responder";

const DBG = "[Ratchet-Debug]";

/** Short hex preview for console (never log full raw keys). */
function dbgKeyPreview(bytes: Uint8Array): string {
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 16)}…(${bytes.length} bytes)`;
}

/** Wire JSON shape for `localStorage` — hex-encoded key material only. */
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
 * Minimal symmetric Double Ratchet: two KDF chains (sender / receiver) rooted
 * in a shared `rootKey`, with per-direction counters.
 *
 * Peers agree on chain direction via X3DH role:
 * - Initiator: sender = AB, receiver = BA
 * - Responder: sender = BA, receiver = AB
 *
 * One step: `messageKey = HMAC-SHA256(chainKey, 0x01)`,
 * `nextChainKey = HMAC-SHA256(chainKey, 0x02)` (Web Crypto HMAC-SHA-256).
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

  /** After X3DH: build chain heads from `rootKey` (32-byte shared secret material). */
  static async fromRootKey(rootKey: Uint8Array, role: RatchetRole): Promise<RatchetSession> {
    const session = new RatchetSession(rootKey, role);
    const ab = await RatchetSession.hmacSha256(session.rootKey, LABEL_AB);
    const ba = await RatchetSession.hmacSha256(session.rootKey, LABEL_BA);
    console.log(
      `${DBG} Initialization: rootKey (decoded masterSecret bytes)=${dbgKeyPreview(session.rootKey)} role=${session.role}`,
    );
    console.log(`${DBG} Initialization: chain seed AB=${dbgKeyPreview(ab)} BA=${dbgKeyPreview(ba)}`);
    if (session.role === "initiator") {
      session.senderChain = ab;
      session.receiverChain = ba;
    } else {
      session.senderChain = ba;
      session.receiverChain = ab;
    }
    console.log(
      `${DBG} Initialization: senderChain(head)=${dbgKeyPreview(session.senderChain)} receiverChain(head)=${dbgKeyPreview(session.receiverChain)}`,
    );
    return session;
  }

  /** Next outbound message: one chain step; returns AES-256 message key + wire counter. */
  async getNextSenderKey(): Promise<{ messageKey: Uint8Array; counter: number }> {
    if (this.senderChain.length !== 32) {
      throw new Error("RatchetSession.getNextSenderKey: invalid sender chain.");
    }
    console.log(`${DBG} Send: senderChainKey (before roll)=${dbgKeyPreview(this.senderChain)}`);
    const counter = this.senderCounter;
    const { messageKey, chainKey } = await RatchetSession.kdfChainStep(this.senderChain);
    this.senderChain = chainKey;
    this.senderCounter += 1;
    console.log(`${DBG} Send: messageKey (this message)=${dbgKeyPreview(messageKey)}`);
    console.log(`${DBG} Send: senderChainKey (after roll, next message)=${dbgKeyPreview(this.senderChain)}`);
    console.log(`${DBG} Send: header counter=${counter}`);
    return { messageKey, counter };
  }

  /**
   * If `counter` is ahead of the local receiver counter, KDF forward and discard
   * skipped message keys until it matches, then derive the key for this message.
   */
  async advanceReceiverTo(counter: number): Promise<Uint8Array> {
    if (this.receiverChain.length !== 32) {
      throw new Error("RatchetSession.advanceReceiverTo: invalid receiver chain.");
    }
    if (!Number.isInteger(counter) || counter < 0) {
      throw new Error("RatchetSession.advanceReceiverTo: counter must be a non-negative integer.");
    }
    console.log(`${DBG} Receive: counter (from header)=${counter} nextExpected=${this.receiverCounter}`);
    if (counter < this.receiverCounter) {
      throw new Error(
        `RatchetSession.advanceReceiverTo: stale counter ${counter} (next expected ${this.receiverCounter}).`,
      );
    }
    console.log(`${DBG} Receive: receiverChainKey (initial chain head)=${dbgKeyPreview(this.receiverChain)}`);
    if (this.receiverCounter < counter) {
      const x = this.receiverCounter;
      const y = counter - 1;
      console.log(`${DBG} Skipping keys from index ${x} to ${y}`);
    }
    while (this.receiverCounter < counter) {
      const { chainKey } = await RatchetSession.kdfChainStep(this.receiverChain);
      this.receiverChain = chainKey;
      this.receiverCounter += 1;
    }
    console.log(`${DBG} Receive: receiverChainKey (used for decryption derivation)=${dbgKeyPreview(this.receiverChain)}`);
    const { messageKey, chainKey } = await RatchetSession.kdfChainStep(this.receiverChain);
    this.receiverChain = chainKey;
    this.receiverCounter += 1;
    console.log(`${DBG} Receive: decryptionKey (messageKey)=${dbgKeyPreview(messageKey)}`);
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
    console.log(
      `${DBG} Initialization (restored): rootKey=${dbgKeyPreview(session.rootKey)} role=${session.role} ` +
        `senderCounter=${session.senderCounter} receiverCounter=${session.receiverCounter}`,
    );
    console.log(
      `${DBG} Initialization (restored): senderChain=${dbgKeyPreview(session.senderChain)} receiverChain=${dbgKeyPreview(session.receiverChain)}`,
    );
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
