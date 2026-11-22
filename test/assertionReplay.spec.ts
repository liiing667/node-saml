import * as fs from "fs";
import * as path from "path";
import * as util from "util";
import * as sinon from "sinon";
import * as xmlenc from "xml-encryption";
import { expect } from "chai";
import {
  CacheProvider,
  InMemoryCacheProvider,
  SAML,
  SamlConfig,
  ValidateInResponseTo,
} from "../src";
import { signXml } from "../src/xml";

const encryptXml = util.promisify(xmlenc.encrypt);

const privateKey = fs.readFileSync(path.join(__dirname, "static", "key.pem"), "utf-8");
const idpCert = fs.readFileSync(path.join(__dirname, "static", "cert.pem"), "utf-8");
const callbackUrl = "http://localhost/saml/consume";
const namespaces =
  'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
const success =
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>';
const audienceRestriction =
  "<saml:AudienceRestriction><saml:Audience>onesaml_login</saml:Audience></saml:AudienceRestriction>";

function instant(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function sign(xml: string, element: string): string {
  const xpath = `//*[local-name(.)='${element}']`;
  return signXml(
    xml,
    xpath,
    { reference: xpath, action: "prepend" },
    { privateKey, signatureAlgorithm: "sha256", digestAlgorithm: "sha256" },
  );
}

function inResponseToAttribute(inResponseTo?: string): string {
  return inResponseTo == null ? "" : ` InResponseTo="${inResponseTo}"`;
}

function confirmation(notOnOrAfter: string, inResponseTo?: string): string {
  return (
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    `<saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${callbackUrl}"${inResponseToAttribute(inResponseTo)}/>` +
    "</saml:SubjectConfirmation>"
  );
}

// Unsolicited by default, so nothing but the assertion's ID can tell a second copy from the first.
function response({
  inResponseTo,
  issueInstant = instant(),
  assertionElement = "saml:Assertion",
  assertionAttributes = ` ID="_assertion" Version="2.0" IssueInstant="${issueInstant}"`,
  issuer = "<saml:Issuer>idp</saml:Issuer>",
  conditions = `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">${audienceRestriction}</saml:Conditions>`,
  confirmations = [confirmation(instant(300000), inResponseTo)],
  subject = `<saml:Subject><saml:NameID>user</saml:NameID>${confirmations.join("")}</saml:Subject>`,
  signAssertion = true,
}: {
  inResponseTo?: string;
  issueInstant?: string;
  assertionElement?: string;
  assertionAttributes?: string;
  issuer?: string;
  conditions?: string;
  confirmations?: string[];
  subject?: string;
  signAssertion?: boolean;
} = {}): Record<string, string> {
  const xml =
    `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}"${inResponseToAttribute(inResponseTo)}>` +
    `<saml:Issuer>idp</saml:Issuer>${success}` +
    `<${assertionElement}${assertionAttributes}>${issuer}${subject}` +
    `${conditions}<saml:AuthnStatement AuthnInstant="${instant()}"/></${assertionElement}></samlp:Response>`;
  const signed = sign(signAssertion ? sign(xml, "Assertion") : xml, "Response");
  return { SAMLResponse: Buffer.from(signed).toString("base64") };
}

function newSaml(config: Partial<SamlConfig> = {}): SAML {
  return new SAML({
    callbackUrl,
    idpCert,
    issuer: "onesaml_login",
    validateInResponseTo: ValidateInResponseTo.never,
    rejectReplayedAssertions: true,
    ...config,
  });
}

async function outcome(validation: Promise<unknown>): Promise<string> {
  return validation.then(
    () => "accepted",
    (err: Error) => err.message,
  );
}

class RecordingCacheProvider extends InMemoryCacheProvider {
  expiries: number[] = [];

  async saveIfAbsentAsync(key: string, value: string, expiresAtMs: number): Promise<boolean> {
    this.expiries.push(expiresAtMs);
    return super.saveIfAbsentAsync(key, value, expiresAtMs);
  }
}

describe("rejectReplayedAssertions", function () {
  afterEach(function () {
    sinon.restore();
  });

  it("rejects a second copy of an accepted response", async () => {
    const saml = newSaml();
    const copy = response();

    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal(
      "The assertion _assertion has already been received",
    );
  });

  it("rejects a second copy of a response whose assertion is encrypted", async () => {
    const assertion = sign(
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion" Version="2.0" IssueInstant="${instant()}">` +
        `<saml:Issuer>idp</saml:Issuer>` +
        `<saml:Subject><saml:NameID>user</saml:NameID>${confirmation(instant(300000))}</saml:Subject>` +
        `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">${audienceRestriction}</saml:Conditions>` +
        `<saml:AuthnStatement AuthnInstant="${instant()}"/></saml:Assertion>`,
      "Assertion",
    );
    const encryptedAssertion = await encryptXml(assertion, {
      rsa_pub: fs.readFileSync(path.join(__dirname, "static", "testshib encryption pub.pem")),
      pem: fs.readFileSync(path.join(__dirname, "static", "testshib encryption cert.pem")),
      encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
      keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    });
    const signed = sign(
      `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}">` +
        `<saml:Issuer>idp</saml:Issuer>${success}` +
        `<saml:EncryptedAssertion>${encryptedAssertion}</saml:EncryptedAssertion></samlp:Response>`,
      "Response",
    );
    const copy = { SAMLResponse: Buffer.from(signed).toString("base64") };
    const saml = newSaml({
      decryptionPvk: fs.readFileSync(path.join(__dirname, "static", "testshib encryption pvk.pem")),
    });

    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal(
      "The assertion _assertion has already been received",
    );
  });

  it("accepts a second copy when it is false", async () => {
    const saml = newSaml({ rejectReplayedAssertions: false });
    const copy = response();

    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
  });

  it("accepts only one of two copies validated at the same moment", async () => {
    const saml = newSaml();
    const copy = response();

    const outcomes = await Promise.all([
      outcome(saml.validatePostResponseAsync(copy)),
      outcome(saml.validatePostResponseAsync(copy)),
    ]);

    expect(outcomes.sort()).to.deep.equal([
      "The assertion _assertion has already been received",
      "accepted",
    ]);
  });

  for (const validateInResponseTo of [
    ValidateInResponseTo.always,
    ValidateInResponseTo.ifPresent,
  ]) {
    it(`accepts one of two copies of a solicited response validated at the same moment under "${validateInResponseTo}"`, async () => {
      const cacheProvider = new InMemoryCacheProvider();
      await cacheProvider.saveAsync("_request", new Date().toISOString());
      const saml = newSaml({ cacheProvider, validateInResponseTo });
      const copy = response({ inResponseTo: "_request" });

      const outcomes = await Promise.all([
        outcome(saml.validatePostResponseAsync(copy)),
        outcome(saml.validatePostResponseAsync(copy)),
      ]);

      expect(outcomes.sort()).to.deep.equal([
        "The assertion _assertion has already been received",
        "accepted",
      ]);
    });
  }

  it("rejects a copy presented once valid, after it was rejected as not yet valid", async () => {
    const clock = sinon.useFakeTimers({ now: Date.now(), toFake: ["Date"] });
    const saml = newSaml();
    const early = response({
      conditions: `<saml:Conditions NotBefore="${instant(60000)}" NotOnOrAfter="${instant(300000)}">${audienceRestriction}</saml:Conditions>`,
    });

    expect(await outcome(saml.validatePostResponseAsync(early))).to.equal(
      "SAML assertion not yet valid",
    );
    clock.tick(120000);
    expect(await outcome(saml.validatePostResponseAsync(early))).to.equal(
      "The assertion _assertion has already been received",
    );
  });

  it(
    "keeps the recorded ID after a replay is rejected, so an attacker cannot pre-reject a login",
    async () => {
      const cacheProvider = new InMemoryCacheProvider();
      const saml = newSaml({ cacheProvider });
      const copy = response();
      const assertionKey = JSON.stringify(["assertion", "idp", "_assertion"]);

      expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
      expect(await cacheProvider.getAsync(assertionKey)).to.exist;

      // The replay is rejected, and the record of the accepted assertion has to outlive it: the
      // remembered ID is what stops the replayed bytes establishing a second session.
      expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal(
        "The assertion _assertion has already been received",
      );
      expect(await cacheProvider.getAsync(assertionKey)).to.exist;
    },
  );

  it("keeps an ID until the latest moment the assertion could be accepted", async () => {
    const cacheProvider = new RecordingCacheProvider();
    const saml = newSaml({ cacheProvider, acceptedClockSkewMs: 1000 });
    const conditionsEnd = instant(300000);
    const laterConfirmationEnd = instant(600000);

    await saml.validatePostResponseAsync(
      response({
        conditions: `<saml:Conditions NotOnOrAfter="${conditionsEnd}">${audienceRestriction}</saml:Conditions>`,
        confirmations: [confirmation(instant(120000)), confirmation(laterConfirmationEnd)],
      }),
    );

    // The later confirmation can be chosen next time, but Conditions still ends acceptance.
    expect(cacheProvider.expiries).to.deep.equal([Date.parse(conditionsEnd) + 1000]);
  });

  it("keeps an ID no longer than maxAssertionAgeMs allows the assertion", async () => {
    const cacheProvider = new RecordingCacheProvider();
    const saml = newSaml({ cacheProvider, maxAssertionAgeMs: 60000 });
    const issueInstant = instant();

    await saml.validatePostResponseAsync(response({ issueInstant }));

    expect(cacheProvider.expiries).to.deep.equal([Date.parse(issueInstant) + 60000]);
  });

  describe("when maxAssertionAgeMs ends acceptance at the epoch", function () {
    const issueInstant = new Date(-60000).toISOString();

    it("rejects the assertion through its Conditions", async () => {
      const saml = newSaml({ maxAssertionAgeMs: 60000 });
      const copy = response({ issueInstant, confirmations: [] });

      expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal(
        "SAML assertion expired: assertion too old",
      );
    });

    it("rejects the assertion through its SubjectConfirmation", async () => {
      const saml = newSaml({ maxAssertionAgeMs: 60000 });
      const copy = response({
        issueInstant,
        conditions: `<saml:Conditions>${audienceRestriction}</saml:Conditions>`,
      });

      expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal(
        "No valid subject confirmation found among those available in the SAML assertion",
      );
    });
  });

  it("rejects an assertion whose acceptance nothing ends", async () => {
    const saml = newSaml({ audience: false });

    expect(
      await outcome(
        saml.validatePostResponseAsync(response({ conditions: "", confirmations: [] })),
      ),
    ).to.equal(
      "The assertion has no NotOnOrAfter, so it would be accepted for ever and cannot be checked for replay",
    );
  });

  it("does not record an assertion that has already expired", async () => {
    const cacheProvider = new RecordingCacheProvider();
    const saml = newSaml({ cacheProvider });
    const expired = response({
      conditions: `<saml:Conditions NotOnOrAfter="${instant(-1000)}">${audienceRestriction}</saml:Conditions>`,
    });

    expect(await outcome(saml.validatePostResponseAsync(expired))).to.equal(
      "SAML assertion expired: clocks skewed too much",
    );
    expect(cacheProvider.expiries).to.deep.equal([]);
  });

  it(
    "leaves no ID behind when a content check after recording rejects the assertion",
    async () => {
      const cacheProvider = new InMemoryCacheProvider();
      const saml = newSaml({ cacheProvider });
      const assertionKey = JSON.stringify(["assertion", "idp", "_assertion"]);
      // The signature verifies and the assertion is recorded before its audience is checked, but
      // the audience does not match, so the response is rejected and must not be consumed at all.
      const wrongAudience = response({
        conditions:
          `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">` +
          "<saml:AudienceRestriction><saml:Audience>someone-else</saml:Audience></saml:AudienceRestriction>" +
          "</saml:Conditions>",
      });

      expect(await outcome(saml.validatePostResponseAsync(wrongAudience))).to.equal(
        "SAML assertion audience mismatch. Expected: onesaml_login Received: someone-else",
      );
      expect(await cacheProvider.getAsync(assertionKey)).to.not.exist;

      // With the record rolled back, the same bytes fail for the same reason again, never as a
      // replay: a rejected validation cannot pre-reject a later, corrected response.
      expect(await outcome(saml.validatePostResponseAsync(wrongAudience))).to.equal(
        "SAML assertion audience mismatch. Expected: onesaml_login Received: someone-else",
      );
    },
  );

  it(
    "rolls back only the assertion it recorded, leaving another assertion's record intact",
    async () => {
      const cacheProvider = new InMemoryCacheProvider();
      const saml = newSaml({ cacheProvider });
      const accepted = response({
        assertionAttributes: ` ID="_accepted" Version="2.0" IssueInstant="${instant()}"`,
      });
      const rejected = response({
        assertionAttributes: ` ID="_rejected" Version="2.0" IssueInstant="${instant()}"`,
        conditions:
          `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">` +
          "<saml:AudienceRestriction><saml:Audience>someone-else</saml:Audience></saml:AudienceRestriction>" +
          "</saml:Conditions>",
      });

      expect(await outcome(saml.validatePostResponseAsync(accepted))).to.equal("accepted");
      expect(await outcome(saml.validatePostResponseAsync(rejected))).to.match(
        /SAML assertion audience mismatch/,
      );

      expect(
        await cacheProvider.getAsync(JSON.stringify(["assertion", "idp", "_accepted"])),
      ).to.exist;
      expect(
        await cacheProvider.getAsync(JSON.stringify(["assertion", "idp", "_rejected"])),
      ).to.not.exist;
    },
  );

  it("rejects an assertion with no ID", async () => {
    const saml = newSaml({ wantAssertionsSigned: false });

    expect(
      await outcome(
        saml.validatePostResponseAsync(
          response({
            assertionElement: "Assertion",
            assertionAttributes: "",
            signAssertion: false,
          }),
        ),
      ),
    ).to.equal("The assertion has no ID, so it cannot be checked for replay");
  });

  it("rejects a second copy of an assertion with no Issuer", async () => {
    const saml = newSaml();
    const copy = response({ issuer: "" });

    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal(
      "The assertion _assertion has already been received",
    );
  });

  it("rejects a second copy of an assertion with no Subject", async () => {
    const saml = newSaml();
    const copy = response({ subject: "" });

    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal(
      "The assertion _assertion has already been received",
    );
  });

  it("passes over a confirmation whose data has no NotOnOrAfter", async () => {
    const cacheProvider = new RecordingCacheProvider();
    const saml = newSaml({ cacheProvider });
    const confirmationEnd = instant(120000);
    const bearer = 'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"';

    await saml.validatePostResponseAsync(
      response({
        confirmations: [
          `<saml:SubjectConfirmation ${bearer}/>`,
          `<saml:SubjectConfirmation ${bearer}><saml:SubjectConfirmationData/></saml:SubjectConfirmation>`,
          confirmation(confirmationEnd),
        ],
      }),
    );

    expect(cacheProvider.expiries).to.deep.equal([Date.parse(confirmationEnd)]);
  });

  it("keeps the IDs of different identity providers apart in a shared cache", async () => {
    const cacheProvider = new InMemoryCacheProvider();
    const saml = newSaml({ cacheProvider });

    expect(await outcome(saml.validatePostResponseAsync(response()))).to.equal("accepted");
    expect(
      await outcome(
        saml.validatePostResponseAsync(
          response({ issuer: "<saml:Issuer>other-idp</saml:Issuer>" }),
        ),
      ),
    ).to.equal("accepted");
  });

  it("requires a cache provider with saveIfAbsentAsync", () => {
    const cacheProvider: CacheProvider = {
      saveAsync: async () => null,
      getAsync: async () => null,
      removeAsync: async () => null,
    };

    expect(() => newSaml({ cacheProvider })).to.throw(
      TypeError,
      "rejectReplayedAssertions requires a cacheProvider with saveIfAbsentAsync, which saves a key with an expiry only if it is absent, in one step",
    );
  });

  it("cannot be combined with acceptedClockSkewMs: -1", () => {
    expect(() => newSaml({ acceptedClockSkewMs: -1 })).to.throw(
      TypeError,
      "rejectReplayedAssertions cannot be used with acceptedClockSkewMs: -1, under which an assertion never expires",
    );
  });
});
