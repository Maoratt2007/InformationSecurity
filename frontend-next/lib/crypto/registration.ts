import {
  generateRegistrationBundle,
  loadPrivateBundleFromIndexedDb,
  type PrivateRegistrationBundle,
  type PublicRegistrationBundle,
  storePrivateBundleInIndexedDb,
  toBackendKeyBundlePayload,
  verifySignedPreKey,
} from "./cryptoService";

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
  const storedBundle = await loadPrivateBundleFromIndexedDb(userId);
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
    await storePrivateBundleInIndexedDb({
      userId,
      deviceId: registrationBundle.privateBundle.deviceId,
      privateBundle: registrationBundle.privateBundle,
    });
  }

  const abortController = new AbortController();
  const timeoutId = window.setTimeout(() => abortController.abort(), KEY_BUNDLE_UPLOAD_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(`${getFastApiBaseUrl()}/api/users/${userId}/key-bundle`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(toBackendKeyBundlePayload(registrationBundle.publicBundle)),
      signal: abortController.signal,
    });
  } finally {
    window.clearTimeout(timeoutId);
  }

  if (!response.ok) {
    const errorBody = await response.json().catch(() => null);
    throw new Error(errorBody?.detail ?? "Public key bundle could not be uploaded.");
  }
}

function getFastApiBaseUrl() {
  const configuredUrl = process.env.NEXT_PUBLIC_API_URL?.trim();

  if (!configuredUrl || configuredUrl.includes("supabase.co")) {
    return LOCAL_FASTAPI_URL;
  }

  return configuredUrl.replace(/\/$/, "");
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
