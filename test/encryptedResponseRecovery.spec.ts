import * as assert from "assert";
import * as fs from "fs";
import * as util from "util";
import * as xmlenc from "xml-encryption";
import { expect } from "chai";
import { SAML, SamlConfig } from "../src";
import { signXmlResponse } from "../src/utility";

const readStatic = (name: string) => fs.readFileSync(`${__dirname}/static/${name}`, "utf8");
const encryptXml = util.promisify(xmlenc.encrypt);

const callbackUrl = "http://localhost/saml/consume";
const idpCert = readStatic("cert.pem");
const decryptionPvk = fs.readFileSync(`${__dirname}/static/testshib encryption pvk.pem`);
const otherKey = readStatic("acme_tools_com.key");
const nameID = "encrypted-recovery@example.com";

function config(overrides: Partial<SamlConfig> = {}): SamlConfig {
  return {
    callbackUrl,
    idpCert,
    issuer: "onesaml_login",
    audience: false,
    wantAssertionsSigned: false,
    decryptionPvk,
    ...overrides,
  };
}

describe("encrypted response recovery", function () {
  let samlResponse: string;

  before(async function () {
    const assertion =
      '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="assertion0">' +
      `<saml2:Subject><saml2:NameID>${nameID}</saml2:NameID></saml2:Subject>` +
      "</saml2:Assertion>";
    const encryptedAssertion = await encryptXml(assertion, {
      rsa_pub: readStatic("testshib encryption pub.pem"),
      pem: readStatic("testshib encryption cert.pem"),
      encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
      keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    });
    const response =
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response0">' +
      '<saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">' +
      encryptedAssertion +
      "</saml2:EncryptedAssertion>" +
      "</samlp:Response>";
    const signed = signXmlResponse(response, {
      privateKey: readStatic("key.pem"),
      signatureAlgorithm: "sha256",
    });
    samlResponse = Buffer.from(signed).toString("base64");
  });

  it("reports the ciphertext, decryption key and assertion that produced a profile", async function () {
    const saml = new SAML(config());
    const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: samlResponse });

    assert.ok(profile);
    expect(profile.nameID).to.equal(nameID);
    expect(profile.decryptKey).to.match(/^sha256:/);
    expect(profile.encryptedResponse?.cipher).to.contain("EncryptedAssertion");
    expect(profile.encryptedResponse?.assertionId).to.equal("assertion0");
    expect(profile.encryptedResponse?.signatureVerified).to.equal(true);
    expect(profile.encryptedResponse?.stage).to.equal("complete");
    expect(saml.decryptionKeyGeneration).to.equal(profile.decryptionKeyGeneration);
  });

  it("does not publish a profile when the decrypted assertion fails its signature", async function () {
    const saml = new SAML(config({ wantAssertionsSigned: true }));
    let error: unknown;
    try {
      await saml.validatePostResponseAsync({
        SAMLResponse: fs.readFileSync(
          `${__dirname}/static/signatures/invalid/response.root-signed.assertion-invalidly-signed-encrypted.xml`,
          "base64",
        ),
      });
    } catch (err) {
      error = err;
    }

    assert.ok(error instanceof Error);
    expect(error.message).to.equal("Invalid signature from encrypted assertion");
    const report = (
      error as Error & { encryptedResponse?: Record<string, unknown> }
    ).encryptedResponse;
    assert.ok(report);
    expect(report.failureStage).to.equal("verify-signature");
    expect(report.decryptKey).to.match(/^sha256:/);
    expect(report.cipher).to.contain("EncryptedAssertion");
    expect(report.assertion).to.equal(null);
  });

  it("accepts a ciphertext encrypted to one key in a rotation window", async function () {
    const saml = new SAML(config({ decryptionPvk: [otherKey, decryptionPvk] }));
    const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: samlResponse });

    assert.ok(profile);
    expect(profile.nameID).to.equal(nameID);
    expect(profile.encryptedResponse?.decryptionKeys).to.have.length(2);
    expect(profile.decryptKey).to.match(/^sha256:/);
    expect(profile.encryptedResponse?.decryptKey).to.equal(profile.decryptKey);
  });

  it("uses the key frozen when validation started, not one changed during it", async function () {
    class RotatingSAML extends SAML {
      protected async getSignedAssertion(signedXml: string): Promise<string | null> {
        this.options.decryptionPvk = otherKey;
        return super.getSignedAssertion(signedXml);
      }
    }

    const saml = new RotatingSAML(config());
    const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: samlResponse });

    assert.ok(profile);
    expect(profile.nameID).to.equal(nameID);
  });

  it("reports the same key generation after a restart", async function () {
    const first = await new SAML(config()).validatePostResponseAsync({
      SAMLResponse: samlResponse,
    });
    const second = await new SAML(config()).validatePostResponseAsync({
      SAMLResponse: samlResponse,
    });

    const firstProfile = first.profile;
    const secondProfile = second.profile;
    assert.ok(firstProfile);
    assert.ok(secondProfile);
    expect(secondProfile.encryptedResponse?.decryptionKeyGeneration).to.equal(
      firstProfile.encryptedResponse?.decryptionKeyGeneration,
    );
    expect(secondProfile.decryptKey).to.equal(firstProfile.decryptKey);
  });
});
