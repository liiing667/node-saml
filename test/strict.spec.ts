"use strict";
import { SAML } from "../src";
import * as fs from "fs";
import * as sinon from "sinon";
import * as util from "util";
import * as xmlenc from "xml-encryption";
import * as assert from "assert";
import { expect } from "chai";
import { SamlConfig } from "../src/types";
import { signXmlResponse } from "../src/utility";

const idpCert = fs.readFileSync(__dirname + "/static/cert.pem", "ascii");
const signingKey = fs.readFileSync(__dirname + "/static/key.pem");
const encryptXml = util.promisify(xmlenc.encrypt);

const callbackUrl = "http://localhost/saml/consume";

const baseConfig: SamlConfig = {
  callbackUrl,
  idpCert,
  issuer: "onesaml_login",
  audience: false,
  wantAssertionsSigned: false,
};

// A root-signed response whose bearer confirmation is valid until 2030; the response and
// confirmation attributes are the variables under test.
const buildSignedResponse = (responseAttributes: string, confirmDataAttributes: string): string => {
  const xml =
    '<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="2014-05-28T00:16:08Z"' +
    responseAttributes +
    ">" +
    "<saml:Issuer>https://idp.example.com/metadata</saml:Issuer>" +
    '<saml:Assertion Version="2.0" ID="_assertion" IssueInstant="2014-05-28T00:16:08Z">' +
    "<saml:Issuer>https://idp.example.com/metadata</saml:Issuer>" +
    "<saml:Subject>" +
    "<saml:NameID>ben@example.com</saml:NameID>" +
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    '<saml:SubjectConfirmationData NotOnOrAfter="2030-01-01T00:00:00Z"' +
    confirmDataAttributes +
    "/>" +
    "</saml:SubjectConfirmation>" +
    "</saml:Subject>" +
    '<saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2030-01-01T00:00:00Z"/>' +
    '<saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionIndex="_session"/>' +
    "</saml:Assertion>" +
    "</Response>";
  return signXmlResponse(xml, { privateKey: signingKey, signatureAlgorithm: "sha256" });
};

const containerFor = (signedXml: string) => ({
  SAMLResponse: Buffer.from(signedXml).toString("base64"),
});

describe("strict /", function () {
  describe("construction", function () {
    it("rejects a non-boolean `strict`", function () {
      expect(() => new SAML({ ...baseConfig, strict: "false" as unknown as boolean })).to.throw(
        TypeError,
        /strict/,
      );
    });

    it("requires `signatureAlgorithm` when `privateKey` is set", function () {
      expect(() => new SAML({ ...baseConfig, privateKey: signingKey, strict: true })).to.throw(
        TypeError,
        /`signatureAlgorithm` is required/,
      );
    });

    it("requires `digestAlgorithm` when `privateKey` is set", function () {
      expect(
        () =>
          new SAML({
            ...baseConfig,
            privateKey: signingKey,
            signatureAlgorithm: "sha256",
            strict: true,
          }),
      ).to.throw(TypeError, /`digestAlgorithm` is required/);
    });

    it("rejects an unrecognized `signatureAlgorithm` rather than falling back to SHA-1", function () {
      expect(
        () => new SAML({ ...baseConfig, signatureAlgorithm: "SHA256" as never, strict: true }),
      ).to.throw(TypeError, /`signatureAlgorithm` is set to "SHA256", which is not recognized/);
    });

    it("rejects an unrecognized `digestAlgorithm` rather than falling back to SHA-1", function () {
      expect(() => new SAML({ ...baseConfig, digestAlgorithm: "SHA256", strict: true })).to.throw(
        TypeError,
        /`digestAlgorithm` is set to "SHA256", which is not recognized/,
      );
    });

    it("still permits all of these by default", function () {
      expect(
        () =>
          new SAML({
            ...baseConfig,
            privateKey: signingKey,
            digestAlgorithm: "SHA256",
          }),
      ).to.not.throw();
    });
  });

  describe("Destination", function () {
    const recipient = ` Recipient="${callbackUrl}"`;

    it("rejects a signed Response with no Destination", async function () {
      const samlObj = new SAML({ ...baseConfig, strict: true });
      await assert.rejects(
        samlObj.validatePostResponseAsync(containerFor(buildSignedResponse("", recipient))),
        {
          message: `The signed Response has no Destination, where \`callbackUrl\` ("${callbackUrl}") was expected. SAML bindings require a Destination on a signed message.`,
        },
      );
    });

    it("rejects a signed Response whose Destination is not `callbackUrl`", async function () {
      const samlObj = new SAML({ ...baseConfig, strict: true });
      await assert.rejects(
        samlObj.validatePostResponseAsync(
          containerFor(buildSignedResponse(' Destination="http://localhost/elsewhere"', recipient)),
        ),
        {
          message: `The Response has the Destination "http://localhost/elsewhere", where \`callbackUrl\` ("${callbackUrl}") was expected.`,
        },
      );
    });

    it("accepts both by default", async function () {
      const samlObj = new SAML(baseConfig);
      await assert.doesNotReject(
        samlObj.validatePostResponseAsync(containerFor(buildSignedResponse("", recipient))),
      );
      await assert.doesNotReject(
        samlObj.validatePostResponseAsync(
          containerFor(buildSignedResponse(' Destination="http://localhost/elsewhere"', recipient)),
        ),
      );
    });
  });

  describe("SubjectConfirmationData Recipient", function () {
    const destination = ` Destination="${callbackUrl}"`;

    it("rejects an assertion whose bearer Recipient is not `callbackUrl`", async function () {
      const samlObj = new SAML({ ...baseConfig, strict: true });
      await assert.rejects(
        samlObj.validatePostResponseAsync(
          containerFor(buildSignedResponse(destination, ' Recipient="http://localhost/elsewhere"')),
        ),
        {
          message: `No bearer SubjectConfirmationData in the assertion has the Recipient \`callbackUrl\` ("${callbackUrl}"); received: http://localhost/elsewhere.`,
        },
      );
    });

    it("rejects an assertion whose bearer confirmation has no Recipient", async function () {
      const samlObj = new SAML({ ...baseConfig, strict: true });
      await assert.rejects(
        samlObj.validatePostResponseAsync(containerFor(buildSignedResponse(destination, ""))),
        {
          message: `No bearer SubjectConfirmationData in the assertion has the Recipient \`callbackUrl\` ("${callbackUrl}"); received: no Recipient.`,
        },
      );
    });

    it("accepts both by default", async function () {
      const samlObj = new SAML(baseConfig);
      await assert.doesNotReject(
        samlObj.validatePostResponseAsync(
          containerFor(buildSignedResponse(destination, ' Recipient="http://localhost/elsewhere"')),
        ),
      );
      await assert.doesNotReject(
        samlObj.validatePostResponseAsync(containerFor(buildSignedResponse(destination, ""))),
      );
    });
  });

  it("accepts a fully compliant response", async function () {
    const samlObj = new SAML({ ...baseConfig, strict: true });
    const { profile } = await samlObj.validatePostResponseAsync(
      containerFor(
        buildSignedResponse(` Destination="${callbackUrl}"`, ` Recipient="${callbackUrl}"`),
      ),
    );
    assert.ok(profile != null);
    expect(profile.nameID).to.equal("ben@example.com");
  });

  describe("signature references", function () {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers({
        now: Date.parse("2020-09-25T16:59:00Z"),
        toFake: ["Date"],
      });
    });

    afterEach(function () {
      fakeClock.restore();
    });

    const twoReferences = {
      SAMLResponse: fs.readFileSync(
        __dirname +
          "/static/signatures/invalid/response.root-signed-2references.assertion-unsigned.xml",
        "base64",
      ),
    };

    it("rejects a signature with two references", async function () {
      const samlObj = new SAML({ ...baseConfig, strict: true });
      await assert.rejects(samlObj.validatePostResponseAsync(twoReferences), {
        message:
          "The signature on the Response element has 2 references; SAML requires exactly one, to the element signed (SAML core §5.4.2). Configure the identity provider to sign the Response with a single reference.",
      });
    });

    it("treats the element as unsigned by default", async function () {
      const samlObj = new SAML(baseConfig);
      await assert.rejects(samlObj.validatePostResponseAsync(twoReferences), {
        message: "Invalid document signature",
      });
    });
  });

  describe("decryption algorithms", function () {
    const decryptionPvk = fs.readFileSync(
      __dirname + "/static/testshib encryption pvk.pem",
      "ascii",
    );

    // A signed Response whose encrypted assertion is fully compliant, so that only the content
    // encryption algorithm can decide acceptance.
    const buildEncryptedResponse = async (): Promise<string> => {
      const assertion =
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_assertion" IssueInstant="2014-05-28T00:16:08Z">' +
        "<saml:Issuer>https://idp.example.com/metadata</saml:Issuer>" +
        "<saml:Subject>" +
        "<saml:NameID>ben@example.com</saml:NameID>" +
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
        `<saml:SubjectConfirmationData NotOnOrAfter="2030-01-01T00:00:00Z" Recipient="${callbackUrl}"/>` +
        "</saml:SubjectConfirmation>" +
        "</saml:Subject>" +
        '<saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2030-01-01T00:00:00Z"/>' +
        '<saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionIndex="_session"/>' +
        "</saml:Assertion>";
      const encryptedData = await encryptXml(assertion, {
        rsa_pub: fs.readFileSync(__dirname + "/static/testshib encryption pub.pem"),
        pem: fs.readFileSync(__dirname + "/static/testshib encryption cert.pem"),
        encryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
        keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
      });
      const xml =
        `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="${callbackUrl}">` +
        "<saml:Issuer>https://idp.example.com/metadata</saml:Issuer>" +
        `<saml:EncryptedAssertion>${encryptedData}</saml:EncryptedAssertion>` +
        "</Response>";
      return signXmlResponse(xml, { privateKey: signingKey, signatureAlgorithm: "sha256" });
    };

    it("rejects an EncryptedAssertion content-encrypted with aes128-cbc", async function () {
      const samlObj = new SAML({ ...baseConfig, decryptionPvk, strict: true });
      const container = {
        SAMLResponse: Buffer.from(await buildEncryptedResponse()).toString("base64"),
      };
      await assert.rejects(samlObj.validatePostResponseAsync(container), {
        message:
          'The EncryptedAssertion was decrypted with content encryption algorithm "http://www.w3.org/2001/04/xmlenc#aes128-cbc", which `strict` rejects. Configure the identity provider to encrypt with aes128-gcm or aes256-gcm.',
      });
    });

    it("accepts it by default", async function () {
      const samlObj = new SAML({ ...baseConfig, decryptionPvk });
      const container = {
        SAMLResponse: Buffer.from(await buildEncryptedResponse()).toString("base64"),
      };
      await assert.doesNotReject(samlObj.validatePostResponseAsync(container));
    });

    it("rejects an EncryptedID content-encrypted with aes128-cbc", async function () {
      const samlObj = new SAML({
        ...baseConfig,
        decryptionPvk: fs.readFileSync(__dirname + "/static/key.pem", "ascii"),
        strict: true,
      });
      await assert.rejects(
        samlObj.validatePostRequestAsync({
          SAMLRequest: fs.readFileSync(
            __dirname + "/static/logout_request_with_encrypted_name_id.xml",
            "base64",
          ),
        }),
        {
          message:
            'The EncryptedID was decrypted with content encryption algorithm "http://www.w3.org/2001/04/xmlenc#aes128-cbc", which `strict` rejects. Configure the identity provider to encrypt with aes128-gcm or aes256-gcm.',
        },
      );
    });
  });
});
