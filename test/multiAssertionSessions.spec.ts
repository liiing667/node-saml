import * as fs from "fs";
import * as path from "path";
import { expect } from "chai";
import { InMemoryCacheProvider, SAML, SamlConfig, ValidateInResponseTo } from "../src";
import { signXml } from "../src/xml";

const privateKey = fs.readFileSync(path.join(__dirname, "static", "key.pem"), "utf-8");
const idpCert = fs.readFileSync(path.join(__dirname, "static", "cert.pem"), "utf-8");
const callbackUrl = "http://localhost/saml/consume";
const namespaces =
  'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
const success =
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>';

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

function assertion({
  id,
  nameId,
  sessionIndex,
  audience = "onesaml_login",
}: {
  id: string;
  nameId: string;
  sessionIndex: string;
  audience?: string;
}): string {
  const xml =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${instant()}">` +
    "<saml:Issuer>idp</saml:Issuer>" +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID>` +
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    `<saml:SubjectConfirmationData NotOnOrAfter="${instant(300000)}" Recipient="${callbackUrl}"/>` +
    "</saml:SubjectConfirmation></saml:Subject>" +
    `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">` +
    `<saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction>` +
    "</saml:Conditions>" +
    `<saml:AuthnStatement AuthnInstant="${instant()}" SessionIndex="${sessionIndex}"/>` +
    "</saml:Assertion>";
  return sign(xml, id);
}

function response(assertions: string[], responseId: string): Record<string, string> {
  const xml =
    `<samlp:Response ${namespaces} ID="${responseId}" Version="2.0" IssueInstant="${instant()}">` +
    `<saml:Issuer>idp</saml:Issuer>${success}` +
    assertions.join("") +
    "</samlp:Response>";
  return { SAMLResponse: Buffer.from(xml).toString("base64") };
}

function newSaml(config: Partial<SamlConfig> = {}): SAML {
  return new SAML({
    callbackUrl,
    entryPoint: "https://idp.example.com/sso",
    idpCert,
    issuer: "onesaml_login",
    audience: "onesaml_login",
    validateInResponseTo: ValidateInResponseTo.never,
    rejectReplayedAssertions: true,
    wantAuthnResponseSigned: false,
    ...config,
  });
}

async function outcome(validation: Promise<unknown>): Promise<string> {
  return validation.then(
    () => "accepted",
    (err: Error) => err.message,
  );
}

describe("A Response with more than one assertion", function () {
  it("keeps every assertion, subject and SessionIndex traceable", async () => {
    const saml = newSaml();
    const first = assertion({ id: "_assertion_1", nameId: "user", sessionIndex: "_session_1" });
    const second = assertion({ id: "_assertion_2", nameId: "user", sessionIndex: "_session_2" });

    const { profile, sessions, assertions, sessionIndexes, subjects } =
      await saml.validatePostResponseAsync(response([first, second], "_response"));

    expect(profile).to.not.equal(null);
    expect(profile?.sessionIndex).to.equal("_session_1");
    expect(profile?.sessionIndexes).to.deep.equal(["_session_1", "_session_2"]);
    expect(profile?.subjects).to.deep.equal(["user"]);
    expect(profile?.sessions).to.have.length(2);
    expect(profile?.assertions).to.equal(profile?.sessions);
    expect(sessions).to.equal(profile?.sessions);
    expect(assertions).to.equal(profile?.sessions);
    expect(sessionIndexes).to.deep.equal(["_session_1", "_session_2"]);
    expect(subjects).to.deep.equal(["user"]);
    expect(Object.isFrozen(profile?.sessions)).to.equal(true);

    expect(profile?.sessions?.[0]?.id).to.equal("_assertion_1");
    expect(profile?.sessions?.[0]?.sessionIndex).to.equal("_session_1");
    expect(profile?.sessions?.[1]?.id).to.equal("_assertion_2");
    expect(profile?.sessions?.[1]?.sessionIndex).to.equal("_session_2");
    expect(profile?.sessions?.[0]?.subject).to.equal("user");
    expect(profile?.sessions?.[1]?.subject).to.equal("user");
    expect(profile?.sessions?.[0]?.profile.sessionIndex).to.equal("_session_1");
    expect(profile?.sessions?.[1]?.profile.sessionIndex).to.equal("_session_2");
    expect(profile?.sessions?.[0]?.getAssertionXml()).to.contain("_assertion_1");
    expect(profile?.sessions?.[1]?.getAssertionXml()).to.contain("_assertion_2");
    expect(profile?.getAssertionsXml?.()).to.have.length(2);
    expect(profile?.getAssertions?.()).to.have.length(2);
    expect(profile?.assertionXmls).to.deep.equal(profile?.getAssertionsXml?.());
    expect(profile?.parsedAssertions).to.have.length(2);

    // The legacy accessors still name the first assertion.
    expect(profile?.getAssertionXml?.()).to.contain("_assertion_1");
    expect(profile?.getAssertionXml?.()).to.not.contain("_assertion_2");
  });

  it("keeps a distinct subject for each assertion", async () => {
    const saml = newSaml();
    const first = assertion({ id: "_assertion_1", nameId: "one", sessionIndex: "_session_1" });
    const second = assertion({ id: "_assertion_2", nameId: "two", sessionIndex: "_session_2" });

    const { profile } = await saml.validatePostResponseAsync(
      response([first, second], "_response"),
    );

    expect(profile?.nameID).to.equal("one");
    expect(profile?.subjects).to.deep.equal(["one", "two"]);
    expect(profile?.sessions?.[0]?.nameID).to.equal("one");
    expect(profile?.sessions?.[1]?.nameID).to.equal("two");
  });

  it("rejects a replay of the second assertion as a new user", async () => {
    const cacheProvider = new InMemoryCacheProvider();
    const saml = newSaml({ cacheProvider });
    const first = assertion({ id: "_assertion_1", nameId: "user", sessionIndex: "_session_1" });
    const second = assertion({ id: "_assertion_2", nameId: "user", sessionIndex: "_session_2" });

    expect(
      await outcome(saml.validatePostResponseAsync(response([first, second], "_response"))),
    ).to.equal("accepted");
    expect(
      await outcome(saml.validatePostResponseAsync(response([second], "_second_response"))),
    ).to.equal("The assertion _assertion_2 has already been received");
  });

  it("accepts only one of two concurrent copies", async () => {
    const saml = newSaml();
    const body = response(
      [
        assertion({ id: "_assertion_1", nameId: "user", sessionIndex: "_session_1" }),
        assertion({ id: "_assertion_2", nameId: "user", sessionIndex: "_session_2" }),
      ],
      "_response",
    );

    const outcomes = await Promise.all([
      outcome(saml.validatePostResponseAsync(body)),
      outcome(saml.validatePostResponseAsync(body)),
    ]);

    expect(outcomes.filter((one) => one === "accepted")).to.have.length(1);
    expect(outcomes.filter((one) => one.includes("has already been received"))).to.have.length(1);
  });

  it("rejects a replay after a new SAML instance uses the same cache", async () => {
    const cacheProvider = new InMemoryCacheProvider();
    const body = response(
      [
        assertion({ id: "_assertion_1", nameId: "user", sessionIndex: "_session_1" }),
        assertion({ id: "_assertion_2", nameId: "user", sessionIndex: "_session_2" }),
      ],
      "_response",
    );

    expect(await outcome(newSaml({ cacheProvider }).validatePostResponseAsync(body))).to.equal(
      "accepted",
    );
    expect(await outcome(newSaml({ cacheProvider }).validatePostResponseAsync(body))).to.equal(
      "The assertion _assertion_1 has already been received",
    );
  });

  it("rolls back every assertion when one of them fails validation", async () => {
    const saml = newSaml();
    const first = assertion({ id: "_assertion_1", nameId: "user", sessionIndex: "_session_1" });
    const second = assertion({
      id: "_assertion_2",
      nameId: "user",
      sessionIndex: "_session_2",
      audience: "someone-else",
    });

    expect(
      await outcome(saml.validatePostResponseAsync(response([first, second], "_response"))),
    ).to.match(/SAML assertion audience mismatch/);
    // The first assertion was not consumed by the rejected response.
    expect(
      await outcome(saml.validatePostResponseAsync(response([first], "_second_response"))),
    ).to.equal("accepted");
  });

  it("rolls back an assertion recorded before a later one is a replay", async () => {
    const saml = newSaml();
    const first = assertion({ id: "_assertion_1", nameId: "user", sessionIndex: "_session_1" });
    const second = assertion({ id: "_assertion_2", nameId: "user", sessionIndex: "_session_2" });

    expect(await outcome(saml.validatePostResponseAsync(response([first], "_first")))).to.equal(
      "accepted",
    );
    expect(
      await outcome(saml.validatePostResponseAsync(response([second, first], "_second"))),
    ).to.equal("The assertion _assertion_1 has already been received");
    // The second assertion was not consumed by the rejected response.
    expect(
      await outcome(saml.validatePostResponseAsync(response([second], "_third"))),
    ).to.equal("accepted");
  });

  it("puts every SessionIndex in a logout request built from the profile", async () => {
    const saml = newSaml();
    const { profile } = await saml.validatePostResponseAsync(
      response(
        [
          assertion({ id: "_assertion_1", nameId: "user", sessionIndex: "_session_1" }),
          assertion({ id: "_assertion_2", nameId: "user", sessionIndex: "_session_2" }),
        ],
        "_response",
      ),
    );
    expect(profile).to.not.equal(null);

    const request = await saml._generateLogoutRequest(profile as NonNullable<typeof profile>);
    const sessionIndexElements =
      request.match(/<saml2p:SessionIndex[^>]*>[^<]+<\/saml2p:SessionIndex>/g) ?? [];

    expect(sessionIndexElements).to.have.length(2);
    expect(request).to.contain("_session_1");
    expect(request).to.contain("_session_2");
  });

  it("keeps the single-assertion profile for existing callers", async () => {
    const saml = newSaml();
    const only = assertion({ id: "_assertion", nameId: "user", sessionIndex: "_session" });

    const { profile } = await saml.validatePostResponseAsync(response([only], "_response"));

    expect(profile?.issuer).to.equal("idp");
    expect(profile?.nameID).to.equal("user");
    expect(profile?.sessionIndex).to.equal("_session");
    expect(profile?.sessionIndexes).to.deep.equal(["_session"]);
    expect(profile?.sessions).to.have.length(1);
    expect(profile?.getAssertionXml?.()).to.contain("_assertion");
    expect(Object.keys(profile ?? {})).to.not.include("sessions");
  });
});
