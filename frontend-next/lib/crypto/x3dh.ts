import { ed25519, x25519 } from "@noble/curves/ed25519.js";

/**
 * Ed25519 compressed public key (identity on the wire) → X25519 Montgomery u (RFC 7748).
 * Required because `x25519.getSharedSecret` expects Montgomery points, not Ed25519 encodings.
 * (`@noble/curves` v2.2.0 does not export this name; implementation matches u = (1 + y) / (1 − y).)
 */
function edwardsToMontgomeryPub(ed25519PublicKey32: Uint8Array): Uint8Array {
  const point = ed25519.Point.fromBytes(ed25519PublicKey32);
  const { y } = point.toAffine();
  const Fp = ed25519.Point.Fp;
  const u = Fp.mul(Fp.add(Fp.ONE, y), Fp.inv(Fp.sub(Fp.ONE, y)));
  return Fp.toBytes(u);
}

/**
 * Convert an Ed25519 32-byte private seed into the X25519 secret scalar (RFC 8032 §5.1.5).
 * `x25519.getSharedSecret` expects an X25519 seed (which it clamps internally) and does NOT
 * apply the SHA-512 expansion that Ed25519 signing keys use, so we hash + truncate here so
 * DH1/DH2 use the correct Curve25519 scalar derived from the same Ed25519 identity key.
 */
async function getEd25519Scalar(privateKeySeed: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest("SHA-512", privateKeySeed.buffer as ArrayBuffer);
  return new Uint8Array(hashBuffer).slice(0, 32);
}

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

function bytesToHexPreview(bytes: Uint8Array, maxBytes = 32): string {
  const n = Math.min(maxBytes, bytes.length);
  return Array.from(bytes.slice(0, n))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** First `count` hex characters of the full hex encoding (for DH outputs). */
function dhHexPrefix(bytes: Uint8Array, hexChars = 5): string {
  const full = bytesToHexPreview(bytes, bytes.length);
  return full.slice(0, hexChars);
}

function b64Prefix(s: string | undefined, chars: number): string {
  if (!s || typeof s !== "string") return "(none)";
  return s.slice(0, chars);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * פונקציה המייצרת את הסוד המשותף (Master Secret) מול משתמש אחר
 */
export async function initiateX3DH(
  initiatorPrivateBundle: any,
  receiverPublicKeyBundle: any
) {
  // 1. המרת המפתחות של המקבל מ-Base64 למערך בתים (Bytes)
  const receiverIK_Ed25519 = base64UrlToBytes(receiverPublicKeyBundle.identity_key_public);
  const receiverIK = edwardsToMontgomeryPub(receiverIK_Ed25519);
  const receiverSPK = base64UrlToBytes(receiverPublicKeyBundle.signed_pre_key_public);

  const otk = receiverPublicKeyBundle.one_time_pre_key;
  const otkKeyId = otk?.key_id;
  const useReceiverOpk =
    otk != null &&
    otkKeyId != null &&
    String(otkKeyId).trim() !== "" &&
    typeof otk.public_key === "string" &&
    otk.public_key.length > 0;
  const receiverOPK = useReceiverOpk ? base64UrlToBytes(otk.public_key) : null;

  const ikPrivB64 = initiatorPrivateBundle?.identityKey?.privateKey;
  const ikPubB64 = initiatorPrivateBundle?.identityKey?.publicKey;
  if (typeof ikPrivB64 !== "string" || typeof ikPubB64 !== "string" || !ikPrivB64 || !ikPubB64) {
    throw new Error("[X3DH] initiator identityKey.privateKey and identityKey.publicKey are required.");
  }
  const initiatorIK_priv = base64UrlToBytes(ikPrivB64);
  const derivedIdentityPub = ed25519.getPublicKey(initiatorIK_priv);
  const storedIdentityPub = base64UrlToBytes(ikPubB64);
  if (!bytesEqual(derivedIdentityPub, storedIdentityPub)) {
    throw new Error(
      "[X3DH] Identity key pair invalid: publicKey does not match privateKey (Ed25519). Use the same primary bundle for the encryption header and X3DH.",
    );
  }

  // 3. ייצור מפתח זמני (Ephemeral Key) באמצעות הספרייה שלכם
  const ephemeralKey = x25519.keygen();
  const EK_priv = ephemeralKey.secretKey;
  const EK_pub = ephemeralKey.publicKey;

  console.group("[X3DH][initiateX3DH] parameters");
  console.log("Identity (initiator IK_priv first 5 b64 chars):", b64Prefix(initiatorPrivateBundle.identityKey?.privateKey, 5));
  console.log(
    "Identity receiver IK: Ed25519 wire prefix hex:",
    bytesToHexPreview(receiverIK_Ed25519, 5),
    "| Montgomery u (X25519 DH) prefix hex:",
    bytesToHexPreview(receiverIK, 5),
  );
  console.log("Signed pre-key receiverSPK_pub (first 5 bytes hex):", bytesToHexPreview(receiverSPK, 5));
  console.log("Signed pre-key receiverSPK_priv:", "(not available on initiator — receiver-only)");
  console.log("Ephemeral EK_pub (first 5 bytes hex):", bytesToHexPreview(EK_pub, 5));
  console.log("Ephemeral EK_priv (first 5 bytes hex):", bytesToHexPreview(EK_priv, 5));
  console.log("One-time pre-key:", {
    used: useReceiverOpk,
    key_id: useReceiverOpk ? String(otkKeyId) : null,
    opk_pub_first5Hex: receiverOPK ? bytesToHexPreview(receiverOPK, 5) : null,
    opk_pub_b64_prefix5: useReceiverOpk ? b64Prefix(otk?.public_key, 5) : null,
    opk_priv: "(not available on initiator — receiver-only)",
  });
  console.table([
    { role: "initiatorIK_priv", b64prefix5: b64Prefix(initiatorPrivateBundle.identityKey?.privateKey, 5) },
    {
      role: "receiverIK_Montgomery_u",
      hexFirst5bytes: bytesToHexPreview(receiverIK, 5),
    },
    { role: "receiverSPK_pub", hexFirst5bytes: bytesToHexPreview(receiverSPK, 5) },
    { role: "EK_pub", hexFirst5bytes: bytesToHexPreview(EK_pub, 5) },
    { role: "EK_priv", hexFirst5bytes: bytesToHexPreview(EK_priv, 5) },
  ]);
  console.groupEnd();

  // 4. חישובי Diffie-Hellman
  const initiatorIK_scalar = await getEd25519Scalar(initiatorIK_priv);
  const dh1 = x25519.getSharedSecret(initiatorIK_scalar, receiverSPK);
  const dh2 = x25519.getSharedSecret(EK_priv, receiverIK);
  const dh3 = x25519.getSharedSecret(EK_priv, receiverSPK);
  
  let dh4 = new Uint8Array(0);
  if (receiverOPK) {
    dh4 = x25519.getSharedSecret(EK_priv, receiverOPK);
  }

  console.group("[X3DH][initiateX3DH] DH intermediates (first 5 hex chars each)");
  console.log("DH1 (IK_i_priv × SPK_r_pub):", dhHexPrefix(dh1, 5));
  console.log("DH2 (EK_priv × IK_r_pub):", dhHexPrefix(dh2, 5));
  console.log("DH3 (EK_priv × SPK_r_pub):", dhHexPrefix(dh3, 5));
  console.log("DH4 (EK_priv × OPK_r_pub):", receiverOPK ? dhHexPrefix(dh4, 5) : "(skipped — no OPK)");
  console.table([
    { dh: "DH1", first5HexChars: dhHexPrefix(dh1, 5), byteLen: dh1.length },
    { dh: "DH2", first5HexChars: dhHexPrefix(dh2, 5), byteLen: dh2.length },
    { dh: "DH3", first5HexChars: dhHexPrefix(dh3, 5), byteLen: dh3.length },
    { dh: "DH4", first5HexChars: receiverOPK ? dhHexPrefix(dh4, 5) : "-", byteLen: receiverOPK ? dh4.length : 0 },
  ]);
  console.groupEnd();

  // 5. שרשור כל התוצאות ביחד
  const combinedSecrets = new Uint8Array(dh1.length + dh2.length + dh3.length + dh4.length);
  combinedSecrets.set(dh1, 0);
  combinedSecrets.set(dh2, dh1.length);
  combinedSecrets.set(dh3, dh1.length + dh2.length);
  if (receiverOPK) {
    combinedSecrets.set(dh4, dh1.length + dh2.length + dh3.length);
  }

  console.log(
    `[X3DH][initiateX3DH] combinedSecrets length=${combinedSecrets.length} first10Hex=${bytesToHexPreview(combinedSecrets, 5)}`,
  );

  // 6. העברה דרך KDF
  const masterSecret = await deriveMasterSecret(combinedSecrets);

  return {
    masterSecret,
    ephemeralPublicKey: bytesToBase64Url(EK_pub),
    usedOneTimePreKeyId: useReceiverOpk ? String(otkKeyId) : null,
  };
}

/**
 * פונקציה המחשבת את הסוד המשותף בצד המקבל (כאשר מתקבלת הודעה ראשונה)
 */
export async function deriveIncomingSession(
    receiverPrivateBundle: any,
    senderIK_pub_base64: string,
    senderEK_pub_base64: string,
    usedOneTimePreKeyId: string | null
) {
    // 1. המרת מפתחות השולח (עמית) למערך בתים (Ed25519 wire → Montgomery u for X25519)
    const senderIK_Ed25519 = base64UrlToBytes(senderIK_pub_base64);
    const senderIK = edwardsToMontgomeryPub(senderIK_Ed25519);
    const senderEK = base64UrlToBytes(senderEK_pub_base64);
  
    // 2. שליפת המפתחות הפרטיים של המקבל (אורון)
    const receiverIK_priv = base64UrlToBytes(receiverPrivateBundle.identityKey.privateKey);
    const receiverSPK_priv = base64UrlToBytes(receiverPrivateBundle.signedPreKey.privateKey);

    const spkPubB64 = receiverPrivateBundle.signedPreKey?.publicKey;
    if (typeof spkPubB64 !== "string" || !spkPubB64) {
      throw new Error("[X3DH] receiver signedPreKey.publicKey missing from local bundle.");
    }
    const receiverSPK_pub_bytes = base64UrlToBytes(spkPubB64);

    console.group("[X3DH][deriveIncomingSession] wire + local keys (before OPK lookup)");
    console.log("Sender IK_pub / EK_pub (first 5 b64 chars):", b64Prefix(senderIK_pub_base64, 5), b64Prefix(senderEK_pub_base64, 5));
    console.log("Receiver IK_priv / SPK_priv / SPK_pub (previews):", {
      ikPriv_b64_5: b64Prefix(receiverPrivateBundle.identityKey?.privateKey, 5),
      spkPriv_hex5: bytesToHexPreview(receiverSPK_priv, 5),
      spkPub_hex5: bytesToHexPreview(receiverSPK_pub_bytes, 5),
    });
    console.groupEnd();

    const useReceiverOpk =
      usedOneTimePreKeyId !== null &&
      usedOneTimePreKeyId !== undefined &&
      String(usedOneTimePreKeyId).trim() !== "";

    let receiverOPK_priv: Uint8Array | null = null;
    let selectedOpkEntry: { keyId?: unknown; publicKey?: string; privateKey?: string } | null = null;
    if (useReceiverOpk) {
      const expectedId = String(usedOneTimePreKeyId).trim();
      const keys = receiverPrivateBundle.oneTimePreKeys ?? [];
      const localIds = keys.map((k: any) => String(k.keyId));
      const opk = keys.find((k: any) => String(k.keyId) === expectedId);
      if (!opk) {
        throw new Error(
          `[X3DH] receiver OPK ${expectedId} missing from local bundle. ` +
            `Local OPK ids: [${localIds.join(", ")}]. ` +
            `Likely cause: client regenerated bundle after the sender fetched the older public bundle. Re-register or clear localStorage on both sides.`,
        );
      }
      selectedOpkEntry = opk;
      receiverOPK_priv = base64UrlToBytes(opk.privateKey);
    }

    console.group("[X3DH][deriveIncomingSession] parameters");
    console.log("Sender IK_pub (header, first 5 b64 chars):", b64Prefix(senderIK_pub_base64, 5));
    console.log("Sender EK_pub (header, first 5 b64 chars):", b64Prefix(senderEK_pub_base64, 5));
    console.log("Receiver IK_priv (first 5 b64 chars):", b64Prefix(receiverPrivateBundle.identityKey?.privateKey, 5));
    console.log("Receiver SPK_pub (from local bundle, first 5 bytes hex):", bytesToHexPreview(receiverSPK_pub_bytes, 5));
    console.log("Receiver SPK_priv (first 5 bytes hex):", bytesToHexPreview(receiverSPK_priv, 5));
    console.log("One-time pre-key:", {
      usedOneTimePreKeyId,
      opk_key_id_used: useReceiverOpk ? String(usedOneTimePreKeyId).trim() : null,
      opk_pub_b64_prefix5: selectedOpkEntry?.publicKey ? b64Prefix(selectedOpkEntry.publicKey, 5) : null,
      opk_pub_hex5:
        selectedOpkEntry?.publicKey && typeof selectedOpkEntry.publicKey === "string"
          ? bytesToHexPreview(base64UrlToBytes(selectedOpkEntry.publicKey), 5)
          : null,
      opk_priv_first5Hex: receiverOPK_priv ? bytesToHexPreview(receiverOPK_priv, 5) : null,
    });
    console.table([
      {
        role: "senderIK_Montgomery_u",
        b64prefix5: b64Prefix(senderIK_pub_base64, 5),
        hexFirst5bytes: bytesToHexPreview(senderIK, 5),
      },
      { role: "senderEK (from wire)", b64prefix5: b64Prefix(senderEK_pub_base64, 5), hexFirst5bytes: bytesToHexPreview(senderEK, 5) },
      { role: "receiverIK_priv", b64prefix5: b64Prefix(receiverPrivateBundle.identityKey?.privateKey, 5), hexFirst5bytes: bytesToHexPreview(receiverIK_priv, 5) },
      { role: "receiverSPK_pub", hexFirst5bytes: bytesToHexPreview(receiverSPK_pub_bytes, 5) },
      { role: "receiverSPK_priv", hexFirst5bytes: bytesToHexPreview(receiverSPK_priv, 5) },
    ]);
    console.groupEnd();

    // 3. חישובי Diffie-Hellman בצד המקבל (הופכים את הסדר)
    const receiverIK_scalar = await getEd25519Scalar(receiverIK_priv);
    const dh1 = x25519.getSharedSecret(receiverSPK_priv, senderIK);
    const dh2 = x25519.getSharedSecret(receiverIK_scalar, senderEK);
    const dh3 = x25519.getSharedSecret(receiverSPK_priv, senderEK);

    let dh4 = new Uint8Array(0);
    if (receiverOPK_priv) {
      dh4 = x25519.getSharedSecret(receiverOPK_priv, senderEK);
    }

    console.group("[X3DH][deriveIncomingSession] DH intermediates (first 5 hex chars each)");
    console.log("DH1 (SPK_r_priv × IK_s_pub):", dhHexPrefix(dh1, 5));
    console.log("DH2 (IK_r_priv × EK_s_pub):", dhHexPrefix(dh2, 5));
    console.log("DH3 (SPK_r_priv × EK_s_pub):", dhHexPrefix(dh3, 5));
    console.log("DH4 (OPK_r_priv × EK_s_pub):", receiverOPK_priv ? dhHexPrefix(dh4, 5) : "(skipped — no OPK)");
    console.table([
      { dh: "DH1", first5HexChars: dhHexPrefix(dh1, 5), byteLen: dh1.length },
      { dh: "DH2", first5HexChars: dhHexPrefix(dh2, 5), byteLen: dh2.length },
      { dh: "DH3", first5HexChars: dhHexPrefix(dh3, 5), byteLen: dh3.length },
      { dh: "DH4", first5HexChars: receiverOPK_priv ? dhHexPrefix(dh4, 5) : "-", byteLen: receiverOPK_priv ? dh4.length : 0 },
    ]);
    console.groupEnd();

    // 4. שרשור התוצאות באותו סדר בדיוק
    const combinedSecrets = new Uint8Array(dh1.length + dh2.length + dh3.length + dh4.length);
    combinedSecrets.set(dh1, 0);
    combinedSecrets.set(dh2, dh1.length);
    combinedSecrets.set(dh3, dh1.length + dh2.length);
    if (receiverOPK_priv) {
      combinedSecrets.set(dh4, dh1.length + dh2.length + dh3.length);
    }

    console.log(
      `[X3DH][deriveIncomingSession] combinedSecrets length=${combinedSecrets.length} first10Hex=${bytesToHexPreview(combinedSecrets, 5)}`,
    );

    // 5. העברה דרך KDF (נקבל את אותו הסוד בדיוק!)
    const masterSecret = await deriveMasterSecret(combinedSecrets);
  
    return { masterSecret };
}