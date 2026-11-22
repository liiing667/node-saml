import * as crypto from "crypto";
import { certificateFingerprint } from "./crypto";
import { IdpTrustSnapshot, Profile, SamlTrustReport, SamlValidationStage } from "./types";

/**
 * A resolved view of the IdP certificates used for one signature check. The PEM files are kept
 * for verification; the public snapshot exposes only stable identity.
 */
export interface ResolvedIdpTrust extends IdpTrustSnapshot {
  pemFiles: string[];
}

export const deriveTrustGeneration = (
  issuer: string | null,
  certFingerprints: string[],
): string => {
  const canonical = JSON.stringify([issuer, [...new Set(certFingerprints)].sort()]);
  return `sha256:${crypto.createHash("sha256").update(canonical).digest("hex")}`;
};

export const createTrust = (pemFiles: string[], issuer: string | null): ResolvedIdpTrust => {
  const certFingerprints = [...new Set(pemFiles.map(certificateFingerprint))].sort();
  return {
    generation: deriveTrustGeneration(issuer, certFingerprints),
    issuer,
    certFingerprints,
    pemFiles,
  };
};

export const publicTrust = (trust: ResolvedIdpTrust): IdpTrustSnapshot => ({
  generation: trust.generation,
  metadataGeneration: trust.generation,
  metadataVersion: trust.generation,
  idpCertGeneration: trust.generation,
  issuer: trust.issuer,
  certFingerprints: [...trust.certFingerprints],
});

export const trustReport = (
  trust: ResolvedIdpTrust,
  validationStage: SamlValidationStage,
  verifiedPem?: string,
): SamlTrustReport => {
  const certFingerprint = verifiedPem == null ? null : certificateFingerprint(verifiedPem);
  return {
    ...publicTrust(trust),
    certFingerprint,
    validationStage,
  };
};

/**
 * A rejected validation still has to say which trust anchor was in force. Attach the evidence to
 * the error the caller already handles rather than replacing it.
 */
export const attachTrustReport = (error: unknown, report: SamlTrustReport): void => {
  if (typeof error !== "object" || error === null) {
    return;
  }
  try {
    Object.assign(error, {
      samlTrust: report,
      trustReport: report,
      issuer: report.issuer,
      idpIssuer: report.issuer,
      generation: report.generation,
      idpCertGeneration: report.generation,
      certFingerprint: report.certFingerprint,
      certFingerprints: report.certFingerprints,
      metadataGeneration: report.generation,
      metadataVersion: report.generation,
      validationStage: report.validationStage,
      verificationStage: report.validationStage,
    });
  } catch {
    // A non-extensible error still carries its original message.
  }
};

export const applyTrustReport = (profile: Profile, report: SamlTrustReport): void => {
  Object.assign(profile, {
    idpTrust: report,
    metadataGeneration: report.generation,
    metadataVersion: report.generation,
    idpCertGeneration: report.generation,
    certFingerprint: report.certFingerprint,
    idpCertFingerprint: report.certFingerprint,
    certificateFingerprint: report.certFingerprint,
    certFingerprints: report.certFingerprints,
    idpCertFingerprints: report.certFingerprints,
    certificateFingerprints: report.certFingerprints,
    verificationStage: report.validationStage,
    validationStage: report.validationStage,
  });
};
