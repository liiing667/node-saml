import * as crypto from "crypto";
import { pemCertificates, toPem } from "xml-crypto";
import { assertRequired } from "./utility";
import { PemLabel } from "./types";

export const keyInfoToPem = (
  keyInfo: string | Buffer,
  pemLabel: PemLabel,
  optionName = "keyInfo",
): string => {
  assertRequired(keyInfo, `${optionName} is not provided`);
  assertRequired(
    typeof keyInfo === "string" || Buffer.isBuffer(keyInfo) || undefined,
    `${optionName} is not a string or a Buffer`,
  );

  // toPem() reads a Buffer that does not open with a boundary as DER, but a
  // Buffer here has always been the bytes of a PEM or base64 file.
  const keyData = Buffer.isBuffer(keyInfo) ? keyInfo.toString("latin1") : keyInfo;
  assertRequired(keyData.trim(), `${optionName} is not provided`);

  try {
    return toPem(keyData, pemLabel);
  } catch (error) {
    // toPem() gives one message for malformed text and for data its label doesn't fit, so name
    // both ways the value was read rather than guess which one failed.
    const base64Contents: Record<PemLabel, string> = {
      CERTIFICATE: "certificate",
      "PUBLIC KEY": "public key",
      "PRIVATE KEY": "private key",
      "RSA PRIVATE KEY": "private key",
    };
    throw new TypeError(
      `${optionName} is neither valid PEM nor a valid Base64 ${base64Contents[pemLabel]}: ${(error as Error).message}`,
    );
  }
};

// Base64 carries no label, so it may be PKCS #8 or PKCS #1. Some Node versions read PKCS #8 under
// either label, so trying PKCS #8 first keeps each key under its own label on every version.
export const privateKeyToPem = (keyInfo: string | Buffer, optionName: string): string => {
  try {
    return keyInfoToPem(keyInfo, "PRIVATE KEY", optionName);
  } catch {
    return keyInfoToPem(keyInfo, "RSA PRIVATE KEY", optionName);
  }
};

// Node's crypto has always read a PEM decryptionPvk as given, and it passes over text around the
// message that toPem() refuses, so only base64, which Node cannot read, is converted. The base64
// alphabet has no "-", so a value holding a boundary is PEM.
export const decryptionPvkToPem = (decryptionPvk: string | Buffer): string | Buffer => {
  const text = Buffer.isBuffer(decryptionPvk) ? decryptionPvk.toString("latin1") : decryptionPvk;
  if (typeof text === "string" && text.includes("-----BEGIN")) {
    return decryptionPvk;
  }

  return privateKeyToPem(decryptionPvk, "decryptionPvk");
};

/**
 * A stable identity for a decryption private key. It hashes the public half, so the fingerprint
 * can be reported without exposing the private key, and so the same key gets the same identity
 * whether it arrived as PEM, Base64, PKCS #1 or PKCS #8.
 */
export const decryptionPvkFingerprint = (decryptionPvk: string | Buffer): string => {
  const pem = decryptionPvkToPem(decryptionPvk);
  try {
    const publicDer = crypto
      .createPublicKey(crypto.createPrivateKey(pem))
      .export({ type: "spki", format: "der" });
    return `sha256:${crypto.createHash("sha256").update(publicDer).digest("hex")}`;
  } catch {
    const material = Buffer.isBuffer(pem) ? pem : Buffer.from(pem, "latin1");
    return `sha256:${crypto.createHash("sha256").update(material).digest("hex")}`;
  }
};

/**
 * A stable identity for a decryption key set. Order and duplicates do not change the generation,
 * so the same rotation window keeps the same identity.
 */
export const decryptionPvkGeneration = (fingerprints: string[]): string => {
  const identity = JSON.stringify([...new Set(fingerprints)].sort());
  return `sha256:${crypto.createHash("sha256").update(identity).digest("hex")}`;
};

export const keyInfoToBase64Certificate = (
  keyInfo: string | Buffer,
  optionName: string,
): string => {
  const certificates = pemCertificates(keyInfoToPem(keyInfo, "CERTIFICATE", optionName));
  assertRequired(
    certificates.length === 1 || undefined,
    `${optionName} must hold exactly one certificate, but holds ${certificates.length}`,
  );

  return certificates[0];
};

export const generateUniqueId = (): string => {
  return "_" + crypto.randomBytes(20).toString("hex");
};
