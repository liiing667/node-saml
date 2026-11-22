import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import * as util from "util";
import * as xmlenc from "xml-encryption";
import { expect } from "chai";
import { InMemoryCacheProvider, SAML, SamlConfig } from "../src";
import { decryptionPvkFingerprint, sha256Digest } from "../src/crypto";
import { signXmlResponse } from "../src/utility";

const readStatic = (name: string) => fs.readFileSync(`${__dirname}/static/${name}`, "utf8");
const encryptXml = util.promisify(xmlenc.encrypt);

const callbackUrl = "http://localhost/saml/consume";
const idpCert = readStatic("cert.pem");
const signingKey = readStatic("key.pem");
const firstKey = readStatic("acme_tools_com.key");
const secondKey = readStatic("testshib encryption pvk.pem");

const instant = (offsetMs = 0): string => new Date(Date.now() + offsetMs).toISOString();

const assertionXml = (nameID: string): string =>
  `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_assertion" IssueInstant="${instant()}">` +
  "<saml2:Issuer>idp</saml2:Issuer>" +
  `<saml2:Subject><saml2:NameID>${nameID}</saml2:NameID>` +
  '<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
  `<saml2:SubjectConfirmationData NotOnOrAfter="${instant(300000)}" Recipient="${callbackUrl}"/>` +
  "</saml2:SubjectConfirmation></saml2:Subject>" +
  `<saml2:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">` +
  "<saml2:AudienceRestriction><saml2:Audience>onesaml_login</saml2:Audience></saml2:AudienceRestriction>" +
  "</saml2:Conditions>" +
  `<saml2:AuthnStatement AuthnInstant="${instant()}"/></saml2:Assertion>`;

const responseXml = (assertion: string, encrypted: boolean): string =>
  '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
  'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" ' +
  `IssueInstant="${instant()}">` +
  "<saml2:Issuer>idp</saml2:Issuer>" +
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
  (encrypted ? `<saml2:EncryptedAssertion>${assertion}</saml2:EncryptedAssertion>` : assertion) +
  "</samlp:Response>";

const signedResponse = (assertion: string, encrypted = false): string =>
  signXmlResponse(responseXml(assertion, encrypted), {
    privateKey: signingKey,
    signatureAlgorithm: "sha256",
  });

const containerFor = (signedXml: string) => ({
  SAMLResponse: Buffer.from(signedXml).toString("base64"),
});

class FailingOnceCache extends InMemoryCacheProvider {
  private failures = 1;

  async saveIfAbsentAsync(key: string, value: string, expiresAtMs: number): Promise<boolean> {
    if (this.failures-- > 0) {
      throw new Error("cache write failed");
    }
    return super.saveIfAbsentAsync(key, value, expiresAtMs);
  }
}

function newSaml(overrides: Partial<SamlConfig> = {}): SAML {
  return new SAML({
    callbackUrl,
    idpCert,
    issuer: "onesaml_login",
    audience: false,
    wantAssertionsSigned: false,
    ...overrides,
  });
}

async function encryptWithCurrentKey(assertion: string): Promise<string> {
  return encryptXml(assertion, {
    rsa_pub: readStatic("testshib encryption pub.pem"),
    pem: readStatic("testshib encryption cert.pem"),
    encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
  });
}

// `xml-encryption` writes one EncryptedKey. Decrypt that key only to recover the symmetric key,
// then wrap the same key again for a second RP key with a different OAEP digest. This is the
// rotation shape that used to make the second `decryptionPvk` reuse the first EncryptedKey.
async function encryptWithTwoKeys(assertion: string): Promise<string> {
  const encrypted = await encryptXml(assertion, {
    rsa_pub: readStatic("pub.pem"),
    pem: readStatic("cert.pem"),
    encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
  });
  const wrappedKey = /<e:CipherValue>([^<]+)<\/e:CipherValue>/.exec(encrypted);
  assert.ok(wrappedKey, "expected the first EncryptedKey");
  const symmetricKey = crypto.privateDecrypt(
    {
      key: signingKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha1",
    },
    Buffer.from(wrappedKey[1], "base64"),
  );
  const currentPublicKey = crypto.createPublicKey(readStatic("testshib encryption pub.pem"));
  const currentWrappedKey = crypto
    .publicEncrypt(
      {
        key: currentPublicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      symmetricKey,
    )
    .toString("base64");
  const currentEncryptedKey =
    '<e:EncryptedKey Id="current-key" xmlns:e="http://www.w3.org/2001/04/xmlenc#">' +
    '<e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">' +
    '<DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#" ' +
    'Algorithm="http://www.w3.org/2000/09/xmldsig#sha256"/>' +
    "</e:EncryptionMethod>" +
    `<e:CipherData><e:CipherValue>${currentWrappedKey}</e:CipherValue></e:CipherData>` +
    "</e:EncryptedKey>";
  return encrypted.replace("</e:EncryptedKey>", `</e:EncryptedKey>${currentEncryptedKey}`);
}

describe("encrypted response transaction", function () {
  this.timeout(10000);

  it("uses the EncryptedKey and algorithm that belong to the key that decrypts", async function () {
    const encrypted = await encryptWithTwoKeys(assertionXml("rotation@example.com"));
    const saml = newSaml({ decryptionPvk: [firstKey, secondKey] });

    const { profile } = await saml.validatePostResponseAsync(
      containerFor(signedResponse(encrypted, true)),
    );

    assert.ok(profile);
    expect(profile.nameID).to.equal("rotation@example.com");
    expect(profile.nameIdDigest).to.equal(sha256Digest("rotation@example.com"));
    expect(profile.decryptKey).to.equal(decryptionPvkFingerprint(secondKey));
    expect(profile.encryptedResponse?.encryptedKeyId).to.equal("current-key");
    expect(profile.encryptedResponse?.keyEncryptionDigest).to.equal(
      "http://www.w3.org/2000/09/xmldsig#sha256",
    );
    expect(profile.encryptedResponse?.contentEncryptionAlgorithm).to.equal(
      "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    );
    expect(profile.encryptedResponse?.decryptKey).to.equal(profile.decryptKey);
    expect(profile.encryptedResponse?.signatureVerified).to.equal(true);
    expect(profile.encryptedResponse?.stage).to.equal("complete");
  });

  it(
    "leaves a plain assertion and its NameID unchanged when keys are configured",
    async function () {
      const saml = newSaml({ decryptionPvk: [firstKey, secondKey] });

      const { profile } = await saml.validatePostResponseAsync(
        containerFor(signedResponse(assertionXml("plain@example.com"))),
      );

      assert.ok(profile);
      expect(profile.nameID).to.equal("plain@example.com");
      expect(profile.encryptedResponse).to.equal(undefined);
      expect(profile.decryptKey).to.equal(undefined);
    },
  );

  it("does not let a cache failure turn the same assertion into a new login", async function () {
    const cacheProvider = new FailingOnceCache();
    const encrypted = await encryptWithCurrentKey(assertionXml("cached@example.com"));
    const response = containerFor(signedResponse(encrypted, true));
    const saml = newSaml({
      cacheProvider,
      decryptionPvk: secondKey,
      rejectReplayedAssertions: true,
    });

    let firstError: unknown;
    try {
      await saml.validatePostResponseAsync(response);
    } catch (error) {
      firstError = error;
    }
    assert.ok(firstError instanceof Error);
    const firstErrorAsError = firstError as Error;
    expect(firstErrorAsError.message).to.equal("cache write failed");
    const report = (firstErrorAsError as Error & { encryptedResponse?: Record<string, unknown> })
      .encryptedResponse;
    assert.ok(report);
    const firstReport = report as Record<string, unknown>;
    expect(firstReport.cacheState).to.equal("failed");
    expect(firstReport.failureStage).to.equal("replay-cache");
    expect(firstReport.nameIdDigest).to.equal(sha256Digest("cached@example.com"));

    const replay = "The assertion _assertion has already been received";
    await assert.rejects(saml.validatePostResponseAsync(response), { message: replay });
    await assert.rejects(newSaml({
      cacheProvider,
      decryptionPvk: secondKey,
      rejectReplayedAssertions: true,
    }).validatePostResponseAsync(response), { message: replay });

    expect(
      await cacheProvider.getAsync(JSON.stringify(["assertion", "idp", "_assertion"])),
    ).to.not.equal(null);
  });
});
