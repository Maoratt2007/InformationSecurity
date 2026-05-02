import { initiateX3DH } from "../lib/crypto/x3dh";
import {
  dispatchSignalSessionUpdated,
  persistPeerSessionWithRatchet,
  readMyPrivateBundle,
  readStoredMasterSecret,
} from "./use-chat-websocket";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";

const sessionLocks = new Set<string>();

export function useSignalSession() {
  const establishSession = async (
    myUserId: string,
    activeContactId: string,
    accessToken: string,
  ) => {
    if (!activeContactId) return;
    if (!myUserId) return;

    // Strict guard: only skip when a usable masterSecret is already saved.
    if (readStoredMasterSecret(activeContactId)) return;

    if (sessionLocks.has(activeContactId)) return;
    sessionLocks.add(activeContactId);

    let errored = false;
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/users/${encodeURIComponent(activeContactId)}/key-bundle`,
        {
          headers: { Authorization: `Bearer ${accessToken}` },
        },
      );

      if (!response.ok) throw new Error("Failed to fetch key bundle");
      const receiverBundle = await response.json();
      console.log("[Signal][tx] GET /key-bundle response JSON (full):", receiverBundle);
      console.log(
        "[Signal][tx] Fetched receiver identity_key_public for",
        activeContactId,
        receiverBundle.identity_key_public,
      );

      const myPrivateBundle = readMyPrivateBundle(myUserId);
      if (!myPrivateBundle) {
        errored = true;
        console.error("[Signal] No private bundle for user", myUserId);
        return;
      }

      const bundle = myPrivateBundle as { identityKey?: { publicKey?: string } };
      console.log("[Signal][tx] Using Identity Public Key:", bundle.identityKey?.publicKey);

      const { masterSecret, ephemeralPublicKey, usedOneTimePreKeyId } = await initiateX3DH(
        myPrivateBundle,
        receiverBundle,
      );

      await persistPeerSessionWithRatchet(activeContactId, {
        masterSecret,
        ephemeralPublicKey,
        usedOneTimePreKeyId,
        role: "initiator",
      });

      console.log(
        `[Signal] Initiator session with ${activeContactId} masterSecret=${masterSecret.slice(0, 16)}…`,
      );
      dispatchSignalSessionUpdated({ peerUserId: activeContactId });
    } catch (error) {
      errored = true;
      console.error("[Signal] Failed to establish secure session:", error);
    } finally {
      if (errored) sessionLocks.delete(activeContactId);
    }
  };

  return { establishSession };
}
