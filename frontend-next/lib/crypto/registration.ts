import {
  generateRegistrationBundle,
  type PrivateRegistrationBundle,
  type PublicRegistrationBundle,
  toBackendKeyBundlePayload,
  verifySignedPreKey,
} from "./cryptoService";
import { KeyStorageService } from "./keyStorageService";
import { ensureSignalCryptoInitialized } from "./signalCryptoInit";

const LOCAL_FASTAPI_URL = "http://127.0.0.1:8000";
const KEY_BUNDLE_UPLOAD_TIMEOUT_MS = 10000;

interface EnsureRegistrationBundleOptions {
  userId: string;
  accessToken: string;
}

export async function ensureRegistrationKeyBundleUploaded({
  userId,
  accessToken,
}: EnsureRegistrationBundleOptions) {
  await ensureSignalCryptoInitialized(userId);
  const storedBundle = tryLoadBundleFromLocalStorage(userId);

  const registrationBundle = storedBundle?.privateBundle
    ? {
        privateBundle: storedBundle.privateBundle,
        publicBundle: publicBundleFromPrivateBundle(storedBundle.privateBundle),
      }
    : generateRegistrationBundle({
        deviceId: "primary",
        oneTimePreKeyCount: 50,
      });

  if (!verifySignedPreKey(registrationBundle.publicBundle)) {
    throw new Error("Generated signed pre-key could not be verified.");
  }

  if (!storedBundle) {
    KeyStorageService.save({
      userId,
      deviceId: registrationBundle.privateBundle.deviceId,
      privateBundle: registrationBundle.privateBundle,
    });
  }

  const abortController = new AbortController();
  const timeoutId = window.setTimeout(() => abortController.abort(), KEY_BUNDLE_UPLOAD_TIMEOUT_MS);
  const keyBundleEndpoint = getFastApiKeyBundleEndpoint(userId);
  const payload = toBackendKeyBundlePayload(registrationBundle.publicBundle);
  const serializedPayload = JSON.stringify(payload);

  console.log("[KeyBundle] POST", keyBundleEndpoint);
  console.log("[KeyBundle] payload JSON ->", serializedPayload);

  try {
    const response = await fetch(keyBundleEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: serializedPayload,
      mode: "cors",
      signal: abortController.signal,
    });

    if (!response.ok) {
      const rawResponseText = await response.text();
      console.error("[KeyBundle] RAW server response ->", rawResponseText);
      console.error("[KeyBundle] status ->", response.status, response.statusText);
      console.error("[KeyBundle] payload that was sent ->", serializedPayload);
      throw new Error(rawResponseText || `HTTP ${response.status}`);
    }
  } catch (error) {
    console.error("[KeyBundle] upload failed.", error);
    console.error("[KeyBundle] endpoint ->", keyBundleEndpoint);
    console.error("[KeyBundle] payload that was sent ->", serializedPayload);
    throw error;
  } finally {
    window.clearTimeout(timeoutId);
  }
}

function getFastApiBaseUrl() {
  const configuredUrl = process.env.NEXT_PUBLIC_API_URL?.trim();

  if (!configuredUrl || configuredUrl.includes("supabase.co")) {
    return LOCAL_FASTAPI_URL;
  }

  return configuredUrl.replace(/\/$/, "");
}

function getFastApiKeyBundleEndpoint(userId: string) {
  const endpoint = `${getFastApiBaseUrl()}/api/users/${encodeURIComponent(userId)}/key-bundle`;

  if (endpoint.includes("supabase.co")) {
    throw new Error("Key-bundle upload must go through FastAPI, not Supabase.");
  }

  return endpoint;
}

function publicBundleFromPrivateBundle(privateBundle: PrivateRegistrationBundle): PublicRegistrationBundle {
  return {
    deviceId: privateBundle.deviceId,
    identityKey: {
      algorithm: privateBundle.identityKey.algorithm,
      publicKey: privateBundle.identityKey.publicKey,
    },
    signedPreKey: {
      algorithm: privateBundle.signedPreKey.algorithm,
      keyId: privateBundle.signedPreKey.keyId,
      publicKey: privateBundle.signedPreKey.publicKey,
      signature: privateBundle.signedPreKey.signature,
      signatureAlgorithm: privateBundle.signedPreKey.signatureAlgorithm,
    },
    oneTimePreKeys: privateBundle.oneTimePreKeys.map((key) => ({
      algorithm: key.algorithm,
      keyId: key.keyId,
      publicKey: key.publicKey,
    })),
    createdAt: privateBundle.createdAt,
  };
}

function tryLoadBundleFromLocalStorage(userId: string) {
  try {
    return KeyStorageService.load(userId);
  } catch (error) {
    console.warn("[KeyStorageService] Could not load private keys from localStorage.", error);
    return undefined;
  }
}

