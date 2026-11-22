import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { expect } from "chai";
import { IdpCertCallback, InMemoryCacheProvider, SAML, SamlConfig } from "../src";

const readStatic = (name: string): string =>
  fs.readFileSync(path.join(__dirname, "static", name), "utf8");

const certA = readStatic("cert.pem");
const certB = readStatic("acme_tools_com.cert");
const fingerprint = (pem: string): string => new crypto.X509Certificate(pem).fingerprint256;
type CertCallback = Parameters<IdpCertCallback>[0];

const baseConfig = (idpCert: SamlConfig["idpCert"]): SamlConfig => ({
  callbackUrl: "http://localhost/saml/consume",
  issuer: "onesaml_login",
  idpIssuer: "https://evil-corp.com",
  audience: false,
  acceptedClockSkewMs: -1,
  idpCert,
});

const signedAssertionResponse = {
  SAMLResponse: fs.readFileSync(
    path.join(
      __dirname,
      "static",
      "signatures",
      "valid",
      "response.root-unsigned.assertion-signed.xml",
    ),
    "base64",
  ),
});

describe("IdP certificate generation", function () {
  it("replaces cached PEMs when static idpCert changes, atomically", async function () {
    const saml = new SAML(baseConfig(certA));

    const first = await saml.getIdentityProviderTrustAsync();
    expect(first.certFingerprints).to.deep.equal([fingerprint(certA)]);
    expect(saml.pemFiles).to.deep.equal([certA]);

    const cachedPems = saml.pemFiles;
    const cached = await saml.getIdentityProviderTrustAsync();
    expect(cached.generation).to.equal(first.generation);
    expect(saml.pemFiles).to.equal(cachedPems);

    saml.options.idpCert = certB;
    const rotated = await saml.getIdentityProviderTrustAsync();
    expect(rotated.generation).to.not.equal(first.generation);
    expect(rotated.certFingerprints).to.deep.equal([fingerprint(certB)]);
    expect(saml.pemFiles[0]).to.equal(certB);

    // A failed publication cannot remove the last complete set. The old set remains usable and
    // still has its original identity.
    saml.options.idpCert = "this is not a certificate";
    const afterFailure = await saml.getIdentityProviderTrustAsync();
    expect(afterFailure).to.deep.equal(rotated);
    expect(saml.pemFiles[0]).to.equal(certB);
  });

  it("resolves an idpCert callback once per validation and keeps the last complete set", async function () {
    let published: string | string[] = certA;
    let fail = false;
    const saml = new SAML(
      baseConfig((callback: CertCallback) => {
        if (fail) {
          callback(new Error("metadata publication failed"));
        } else {
          callback(null, published);
        }
      }),
    );

    const first = await saml.getIdentityProviderTrustAsync();
    expect(first.certFingerprints).to.deep.equal([fingerprint(certA)]);
    expect(saml.pemFiles).to.have.length(0);

    published = certB;
    const rotated = await saml.getIdentityProviderTrustAsync();
    expect(rotated.generation).to.not.equal(first.generation);
    expect(rotated.certFingerprints).to.deep.equal([fingerprint(certB)]);
    expect(saml.pemFiles).to.have.length(0);

    fail = true;
    const afterFailure = await saml.getIdentityProviderTrustAsync();
    expect(afterFailure).to.deep.equal(rotated);

    // A fresh instance with a working callback sees the published generation, not the failure.
    fail = false;
    const restarted = new SAML(baseConfig((callback: CertCallback) => callback(null, published)));
    expect(await restarted.getIdentityProviderTrustAsync()).to.deep.equal(rotated);
  });

  it("reports the certificate and stage that authenticated the profile", async function () {
    const saml = new SAML({
      ...baseConfig(certA),
      wantAuthnResponseSigned: false,
    });

    const result = await saml.validatePostResponseAsync(signedAssertionResponse);
    const profile = result.profile;
    if (profile == null) {
      assert.fail("expected a profile");
    }

    expect(profile.certFingerprint).to.equal(fingerprint(certA));
    expect(profile.certFingerprints).to.deep.equal([fingerprint(certA)]);
    expect(profile.verificationStage).to.equal("assertion");
    expect(profile.metadataGeneration).to.equal(saml.idpCertGeneration);
    expect(profile.metadataVersion).to.equal(profile.metadataGeneration);
  });

  it("keeps a dual-certificate window, then refuses the retired certificate", async function () {
    const saml = new SAML({
      ...baseConfig([certB, certA]),
      wantAuthnResponseSigned: false,
    });

    const dual = await saml.validatePostResponseAsync(signedAssertionResponse);
    const dualProfile = dual.profile;
    if (dualProfile == null) {
      assert.fail("expected a profile");
    }
    expect(dualProfile.certFingerprints).to.deep.equal(
      [fingerprint(certA), fingerprint(certB)].sort(),
    );
    expect(dualProfile.certFingerprint).to.equal(fingerprint(certA));

    saml.options.idpCert = certB;
    await assert.rejects(saml.validatePostResponseAsync(signedAssertionResponse), {
      message: "Invalid signature",
    });

    saml.options.idpCert = certA;
    const single = await saml.validatePostResponseAsync(signedAssertionResponse);
    const singleProfile = single.profile;
    if (singleProfile == null) {
      assert.fail("expected a profile");
    }
    expect(singleProfile.certFingerprints).to.deep.equal([fingerprint(certA)]);
    expect(singleProfile.metadataGeneration).to.not.equal(dualProfile.metadataGeneration);
  });

  it("gives the same generation to a restarted instance with the same complete set", async function () {
    const first = new SAML(baseConfig([certB, certA]));
    const restarted = new SAML(baseConfig([certA, certB]));

    expect(await restarted.getIdentityProviderTrustAsync()).to.deep.equal(
      await first.getIdentityProviderTrustAsync(),
    );
  });

  it("recovers the last complete generation from a shared cache after restart", async function () {
    const cacheProvider = new InMemoryCacheProvider();
    const first = new SAML({ ...baseConfig(certA), cacheProvider });
    await first.getIdentityProviderTrustAsync();

    const restarted = new SAML({
      ...baseConfig((callback: CertCallback) =>
        callback(new Error("metadata publication failed")),
      ),
      cacheProvider,
    });

    expect(await restarted.getIdentityProviderTrustAsync()).to.deep.equal(
      await first.getIdentityProviderTrustAsync(),
    );
  });

  it("attaches the frozen issuer, certificate set and stage to a rejection", async function () {
    const saml = new SAML({
      ...baseConfig(certB),
      wantAuthnResponseSigned: false,
    });

    const first = await saml.validatePostResponseAsync(signedAssertionResponse).catch((error) => {
      const report = (error as { samlTrust?: Record<string, unknown> }).samlTrust;
      expect(report?.issuer).to.equal("https://evil-corp.com");
      expect(report?.certFingerprints).to.deep.equal([fingerprint(certB)]);
      expect(report?.certFingerprint).to.equal(null);
      expect(report?.validationStage).to.equal("assertion");
      return true;
    });
    expect(first).to.equal(true);
  });
});
