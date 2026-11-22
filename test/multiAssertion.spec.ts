import * as fs from "fs";
import * as path from "path";
import * as util from "util";
import * as xmlenc from "xml-encryption";
import { expect } from "chai";
import { InMemoryCacheProvider, SAML, SamlConfig, ValidateInResponseTo } from "../src";
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

function sign(xml: string, id: string): string {
  const xpath = `//*[@ID='${id}']`;
  return signXml(
    xml,
    xpath,
    { reference: xpath, action: "prepend" },
    { privateKey, signatureAlgorithm: "sha256", digestAlgorithm: "sha256" },
  );
}

function assertion(id: string, nameId: string, signAssertion: boolean): string {
  const xml =
    `<saml:Assertion ID="${id}" Version="2.0" IssueInstant="${instant()}">` +
    "<saml:Issuer>idp</saml:Issuer>" +
    `<saml:Subject><saml:NameID>${nameId}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData NotOnOrAfter="${instant(300000)}" Recipient="${callbackUrl}"/>` +
    "</saml:SubjectConfirmation></saml:Subject>" +
    `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">${audienceRestriction}</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${instant()}"/></saml:Assertion>`;
  return signAssertion ? sign(xml, id) : xml;
}

function assertionWithInResponseTo(
  id: string,
  nameId: string,
  signAssertion: boolean,
  inResponseTo: string,
): string {
  const xml =
    `<saml:Assertion ID="${id}" Version="2.0" IssueInstant="${instant()}">` +
    "<saml:Issuer>idp</saml:Issuer>" +
    `<saml:Subject><saml:NameID>${nameId}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData NotOnOrAfter="${instant(300000)}" Recipient="${callbackUrl}" InResponseTo="${inResponseTo}"/>` +
    "</saml:SubjectConfirmation></saml:Subject>" +
    `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">${audienceRestriction}</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${instant()}"/></saml:Assertion>`;
  return signAssertion ? sign(xml, id) : xml;
}

async function encryptedAssertion(id: string): Promise<string> {
  const signed = sign(
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${instant()}">` +
      "<saml:Issuer>idp</saml:Issuer>" +
      `<saml:Subject><saml:NameID>user</saml:NameID>` +
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
      `<saml:SubjectConfirmationData NotOnOrAfter="${instant(300000)}" Recipient="${callbackUrl}"/>` +
      "</saml:SubjectConfirmation></saml:Subject>" +
      `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">${audienceRestriction}</saml:Conditions>` +
      `<saml:AuthnStatement AuthnInstant="${instant()}"/></saml:Assertion>`,
    id,
  );
  return encryptXml(signed, {
    rsa_pub: fs.readFileSync(path.join(__dirname, "static", "testshib encryption pub.pem")),
    pem: fs.readFileSync(path.join(__dirname, "static", "testshib encryption cert.pem")),
    encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
  });
}

// Two top-level assertions in one Response. Each can be signed or left unsigned, so a response
// can be built in which only one of the two carries a verifiable signature.
function response(
  assertions: { id: string; nameId: string; signAssertion: boolean }[],
  signResponse = false,
): Record<string, string> {
  const xml =
    `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}">` +
    `<saml:Issuer>idp</saml:Issuer>${success}` +
    assertions.map((one) => assertion(one.id, one.nameId, one.signAssertion)).join("") +
    "</samlp:Response>";
  const signed = signResponse ? sign(xml, "_response") : xml;
  return { SAMLResponse: Buffer.from(signed).toString("base64") };
}

function newSaml(config: Partial<SamlConfig> = {}): SAML {
  return new SAML({
    callbackUrl,
    idpCert,
    issuer: "onesaml_login",
    audience: false,
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

describe("A Response with multiple assertions", function () {
  const MULTIPLE_ASSERTIONS = "Invalid signature: multiple assertions";

  it("is rejected when one assertion is signed and the other is unsigned", async () => {
    const saml = newSaml({ wantAuthnResponseSigned: false });
    const body = response([
      { id: "_signed", nameId: "victim", signAssertion: true },
      { id: "_unsigned", nameId: "attacker", signAssertion: false },
    ]);

    expect(await outcome(saml.validatePostResponseAsync(body))).to.equal(MULTIPLE_ASSERTIONS);
  });

  it("is rejected when both assertions are signed", async () => {
    const saml = newSaml({ wantAuthnResponseSigned: false });
    const body = response([
      { id: "_first", nameId: "victim", signAssertion: true },
      { id: "_second", nameId: "attacker", signAssertion: true },
    ]);

    expect(await outcome(saml.validatePostResponseAsync(body))).to.equal(MULTIPLE_ASSERTIONS);
  });

  it("is rejected when neither assertion is signed", async () => {
    const saml = newSaml({ wantAuthnResponseSigned: false });
    const body = response([
      { id: "_first", nameId: "victim", signAssertion: false },
      { id: "_second", nameId: "attacker", signAssertion: false },
    ]);

    expect(await outcome(saml.validatePostResponseAsync(body))).to.equal(MULTIPLE_ASSERTIONS);
  });

  it("is rejected when the Response is signed and covers two assertions", async () => {
    const saml = newSaml({ wantAssertionsSigned: false });
    const body = response(
      [
        { id: "_first", nameId: "victim", signAssertion: false },
        { id: "_second", nameId: "attacker", signAssertion: false },
      ],
      true,
    );

    expect(await outcome(saml.validatePostResponseAsync(body))).to.equal(MULTIPLE_ASSERTIONS);
  });

  it(
    "is rejected when a plaintext assertion and an EncryptedAssertion are both present",
    async () => {
      const saml = newSaml({
        wantAuthnResponseSigned: false,
        decryptionPvk: fs.readFileSync(
          path.join(__dirname, "static", "testshib encryption pvk.pem"),
        ),
      });
      const xml =
        `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}">` +
        `<saml:Issuer>idp</saml:Issuer>${success}` +
        assertion("_plain", "victim", true) +
        `<saml:EncryptedAssertion>${await encryptedAssertion(
          "_encrypted",
        )}</saml:EncryptedAssertion>` +
        "</samlp:Response>";
      const body = { SAMLResponse: Buffer.from(xml).toString("base64") };

      expect(await outcome(saml.validatePostResponseAsync(body))).to.equal(MULTIPLE_ASSERTIONS);
    },
  );

  it("is rejected when the Response carries two EncryptedAssertions", async () => {
    const saml = newSaml({
      wantAuthnResponseSigned: false,
      decryptionPvk: fs.readFileSync(
        path.join(__dirname, "static", "testshib encryption pvk.pem"),
      ),
    });
    const xml =
      `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}">` +
      `<saml:Issuer>idp</saml:Issuer>${success}` +
      `<saml:EncryptedAssertion>${await encryptedAssertion("_first")}</saml:EncryptedAssertion>` +
      `<saml:EncryptedAssertion>${await encryptedAssertion("_second")}</saml:EncryptedAssertion>` +
      "</samlp:Response>";
    const body = { SAMLResponse: Buffer.from(xml).toString("base64") };

    expect(await outcome(saml.validatePostResponseAsync(body))).to.equal(MULTIPLE_ASSERTIONS);
  });

  it("records no assertion ID, so neither identity can be consumed", async () => {
    const cacheProvider = new InMemoryCacheProvider();
    const saml = newSaml({ cacheProvider, wantAuthnResponseSigned: false });
    const body = response([
      { id: "_signed", nameId: "victim", signAssertion: true },
      { id: "_unsigned", nameId: "attacker", signAssertion: false },
    ]);

    expect(await outcome(saml.validatePostResponseAsync(body))).to.equal(MULTIPLE_ASSERTIONS);
    expect(
      await cacheProvider.getAsync(JSON.stringify(["assertion", "idp", "_signed"])),
    ).to.not.exist;
    expect(
      await cacheProvider.getAsync(JSON.stringify(["assertion", "idp", "_unsigned"])),
    ).to.not.exist;
  });

  it("leaves the request it names pending, so rejecting it cannot consume a login", async () => {
    const cacheProvider = new InMemoryCacheProvider();
    await cacheProvider.saveAsync("_request", new Date().toISOString());
    const saml = newSaml({
      cacheProvider,
      wantAuthnResponseSigned: false,
      validateInResponseTo: ValidateInResponseTo.ifPresent,
    });
    const xml =
      `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}" InResponseTo="_request">` +
      `<saml:Issuer>idp</saml:Issuer>${success}` +
      assertionWithInResponseTo("_signed", "victim", true, "_request") +
      assertionWithInResponseTo("_unsigned", "attacker", false, "_request") +
      "</samlp:Response>";
    const body = {
      SAMLResponse: Buffer.from(xml).toString("base64"),
    };

    expect(await outcome(saml.validatePostResponseAsync(body))).to.equal(MULTIPLE_ASSERTIONS);
    expect(await cacheProvider.getAsync("_request")).to.exist;
  });
});
