import { x25519 } from "@noble/curves/ed25519.js";

// === פונקציות עזר (העתקנו מ-cryptoService כי הן לא מיוצאות שם) ===
function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlToBytes(value: string): Uint8Array {
  const paddedBase64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "="
  );
  const binary = atob(paddedBase64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

// === פונקציית KDF מבוססת SHA-256 (מייצרת את המפתח הסופי) ===
async function deriveMasterSecret(inputMaterial: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', inputMaterial.buffer as ArrayBuffer);
  return bytesToBase64Url(new Uint8Array(hashBuffer));
}

/**
 * פונקציה המייצרת את הסוד המשותף (Master Secret) מול משתמש אחר
 */
export async function initiateX3DH(
  initiatorPrivateBundle: any,
  receiverPublicKeyBundle: any
) {
  // 1. המרת המפתחות של המקבל מ-Base64 למערך בתים (Bytes)
  const receiverIK = base64UrlToBytes(receiverPublicKeyBundle.identity_key_public);
  const receiverSPK = base64UrlToBytes(receiverPublicKeyBundle.signed_pre_key_public);
  const receiverOPK = receiverPublicKeyBundle.one_time_pre_key
    ? base64UrlToBytes(receiverPublicKeyBundle.one_time_pre_key.public_key)
    : null;

  // 2. שליפת מפתח הזהות הפרטי של השולח
  const initiatorIK_priv = base64UrlToBytes(initiatorPrivateBundle.identityKey.privateKey);

  // 3. ייצור מפתח זמני (Ephemeral Key) באמצעות הספרייה שלכם
  const ephemeralKey = x25519.keygen();
  const EK_priv = ephemeralKey.secretKey;
  const EK_pub = ephemeralKey.publicKey;

  // 4. חישובי Diffie-Hellman
  const dh1 = x25519.getSharedSecret(initiatorIK_priv, receiverSPK);
  const dh2 = x25519.getSharedSecret(EK_priv, receiverIK);
  const dh3 = x25519.getSharedSecret(EK_priv, receiverSPK);
  
  let dh4 = new Uint8Array(0);
  if (receiverOPK) {
    dh4 = x25519.getSharedSecret(EK_priv, receiverOPK);
  }

  // 5. שרשור כל התוצאות ביחד
  const combinedSecrets = new Uint8Array(dh1.length + dh2.length + dh3.length + dh4.length);
  combinedSecrets.set(dh1, 0);
  combinedSecrets.set(dh2, dh1.length);
  combinedSecrets.set(dh3, dh1.length + dh2.length);
  if (receiverOPK) {
    combinedSecrets.set(dh4, dh1.length + dh2.length + dh3.length);
  }

  // 6. העברה דרך KDF
  const masterSecret = await deriveMasterSecret(combinedSecrets);

  return {
    masterSecret,
    ephemeralPublicKey: bytesToBase64Url(EK_pub),
    usedOneTimePreKeyId: receiverPublicKeyBundle.one_time_pre_key?.key_id || null
  };
}