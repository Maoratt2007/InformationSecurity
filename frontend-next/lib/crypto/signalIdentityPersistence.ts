"use client";

import type { PrivateIdentityKey } from "./cryptoService";
import { generateIdentityKeyPair } from "./cryptoService";

/** Prefix for `localStorage` keys holding the long-term Ed25519 identity per user. */
export const SIGNAL_PERSISTENT_IDENTITY_STORAGE_PREFIX = "secure-messenger.signal.persistent-identity.v1";

const STORAGE_PREFIX = SIGNAL_PERSISTENT_IDENTITY_STORAGE_PREFIX;

function storageKeyForUser(userId: string): string {
  return `${STORAGE_PREFIX}:${userId}`;
}

interface IdentityWireV1 {
  v: 1;
  algorithm: "Ed25519";
  publicKey: string;
  privateKey: string;
}

function isIdentityWireV1(value: unknown): value is IdentityWireV1 {
  if (!value || typeof value !== "object") return false;
  const o = value as Record<string, unknown>;
  return (
    o.v === 1 &&
    o.algorithm === "Ed25519" &&
    typeof o.publicKey === "string" &&
    o.publicKey.length > 0 &&
    typeof o.privateKey === "string" &&
    o.privateKey.length > 0
  );
}

export function loadPersistedIdentityKeyPair(userId: string): PrivateIdentityKey | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(storageKeyForUser(userId));
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isIdentityWireV1(parsed)) return null;
    return {
      algorithm: "Ed25519",
      publicKey: parsed.publicKey,
      privateKey: parsed.privateKey,
    };
  } catch {
    return null;
  }
}

export function savePersistedIdentityKeyPair(userId: string, identity: PrivateIdentityKey): void {
  if (typeof window === "undefined") return;
  const wire: IdentityWireV1 = {
    v: 1,
    algorithm: identity.algorithm,
    publicKey: identity.publicKey,
    privateKey: identity.privateKey,
  };
  window.localStorage.setItem(storageKeyForUser(userId), JSON.stringify(wire));
}

/**
 * Load the long-term Ed25519 identity from localStorage for this user, or create one and persist it.
 * Keys are stored as base64url strings (same wire format as `PrivateIdentityKey` elsewhere).
 */
export function ensurePersistentIdentityKeyPair(userId: string): PrivateIdentityKey {
  if (!userId.trim()) {
    throw new Error("User ID is required before a persistent identity key can be loaded or created.");
  }
  if (typeof window === "undefined") {
    throw new Error("Persistent identity is only available in the browser.");
  }

  const existing = loadPersistedIdentityKeyPair(userId);
  if (existing) {
    return existing;
  }

  const generated = generateIdentityKeyPair();
  savePersistedIdentityKeyPair(userId, generated);
  return generated;
}
