import * as fs from "fs";
import * as path from "path";
import * as zlib from "zlib";
import { expect } from "chai";
import { InMemoryCacheProvider } from "../src";
import { SAML } from "../src/saml";
import { SamlConfig, ValidateInResponseTo } from "../src/types";
import { signXml } from "../src/xml";

const privateKey = fs.readFileSync(path.join(__dirname, "static", "key.pem"), "utf-8");
const idpCert = fs.readFileSync(path.join(__dirname, "static", "cert.pem"), "utf-8");
const callbackUrl = "http://localhost/saml/consume";
const namespaces =
  'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
  'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';

function instant(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function sign(xml: string, element: string): string {
  const xpath = `//*[local-name(.)='${element}']`;
  return signXml(
    xml,
    xpath,
    { reference: `${xpath}/*[local-name(.)='Issuer']`, action: "after" },
    { privateKey, signatureAlgorithm: "sha256", digestAlgorithm: "sha256" },
  );
}

// One login request ID per tab, in the order getAuthorize* is called.
function idGenerator(): () => string {
  let counter = 0;
  return () => `_request_${++counter}`;
}

function loginResponse(requestId: string): Record<string, string> {
  const method = `Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"`;
  const success =
    '<samlp:Status><samlp:StatusCode ' +
    'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>';
  const xml =
    `<samlp:Response ${namespaces} ID="_response_${requestId}" Version="2.0" ` +
    `IssueInstant="${instant()}" InResponseTo="${requestId}">` +
    `<saml:Issuer>idp</saml:Issuer>${success}` +
    `<saml:Assertion ID="_assertion_${requestId}" Version="2.0" ` +
    `IssueInstant="${instant()}"><saml:Issuer>idp</saml:Issuer>` +
    `<saml:Subject><saml:NameID>user</saml:NameID>` +
    `<saml:SubjectConfirmation ${method}><saml:SubjectConfirmationData NotOnOrAfter="${instant(
      300000,
    )}" Recipient="${callbackUrl}" ` +
    `InResponseTo="${requestId}"/></saml:SubjectConfirmation></saml:SubjectConfirmation>` +
    `</saml:Subject>` +
    `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">` +
    "<saml:AudienceRestriction><saml:Audience>onesaml_login</saml:Audience>" +
    "</saml:AudienceRestriction></saml:Conditions>" +
    `<saml:AuthnStatement AuthnInstant="${instant()}"/></saml:Assertion></samlp:Response>`;
  return { SAMLResponse: Buffer.from(sign(xml, "Assertion")).toString("base64") };
}

function newSaml(config: Partial<SamlConfig> = {}): SAML {
  return new SAML({
    callbackUrl,
    entryPoint: "https://idp.example.com/sso",
    issuer: "onesaml_login",
    idpCert,
    validateInResponseTo: ValidateInResponseTo.always,
    wantAuthnResponseSigned: false,
    generateUniqueId: idGenerator(),
    ...config,
  });
}

function outcome(validation: Promise<unknown>): Promise<string> {
  return validation.then(
    () => "accepted",
    (err: Error) => err.message,
  );
}

describe("Login transaction (request ID, RelayState, callbackUrl)", function () {
  describe("freezing the transaction when a login starts", function () {
    it("stores the request ID, RelayState and callbackUrl for a redirect login", async () => {
      const cacheProvider = new InMemoryCacheProvider();
      const saml = newSaml({ cacheProvider });

      const url = new URL(await saml.getAuthorizeUrlAsync("tab-one", {}));
      const requestId = url.searchParams.get("SAMLRequest");
      expect(requestId).to.be.a("string");

      const stored = JSON.parse((await cacheProvider.getAsync("_request_1")) as string);
      expect(stored).to.deep.equal({
        createdAt: stored.createdAt,
        relayState: "tab-one",
        callbackUrl,
      });
      expect(stored.createdAt).to.be.a("string");
    });

    it("stores the same transaction for a POST login", async () => {
      const cacheProvider = new InMemoryCacheProvider();
      const saml = newSaml({ cacheProvider });

      const message = await saml.getAuthorizeMessageAsync("tab-post", {});
      expect(message.SAMLRequest).to.be.a("string");

      const stored = JSON.parse((await cacheProvider.getAsync("_request_1")) as string);
      expect(stored.relayState).to.equal("tab-post");
      expect(stored.callbackUrl).to.equal(callbackUrl);
    });

    it("records a null RelayState when none is sent", async () => {
      const cacheProvider = new InMemoryCacheProvider();
      const saml = newSaml({ cacheProvider });

      const url = new URL(await saml.getAuthorizeUrlAsync("", {}));
      expect(url.searchParams.get("RelayState")).to.equal(null);

      const stored = JSON.parse((await cacheProvider.getAsync("_request_1")) as string);
      expect(stored.relayState).to.equal(null);
    });

    it("uses a RelayState already on the entry point URL when the caller gives none", async () => {
      const cacheProvider = new InMemoryCacheProvider();
      const saml = newSaml({
        cacheProvider,
        entryPoint: "https://idp.example.com/sso?RelayState=from-entry-point",
      });

      const url = new URL(await saml.getAuthorizeUrlAsync("", {}));
      expect(url.searchParams.get("RelayState")).to.equal("from-entry-point");

      const stored = JSON.parse((await cacheProvider.getAsync("_request_1")) as string);
      expect(stored.relayState).to.equal("from-entry-point");
    });

    it("does not write a transaction when InResponseTo validation is off", async () => {
      const cacheProvider = new InMemoryCacheProvider();
      const saml = newSaml({
        cacheProvider,
        validateInResponseTo: ValidateInResponseTo.never,
      });

      await saml.getAuthorizeUrlAsync("tab-one", {});
      expect(await cacheProvider.getAsync("_request_1")).to.equal(null);
    });
  });

  describe("binding a response to the tab that started it", function () {
    let saml: SAML;
    let cacheProvider: InMemoryCacheProvider;

    beforeEach(async function () {
      cacheProvider = new InMemoryCacheProvider();
      saml = newSaml({ cacheProvider });
      await saml.getAuthorizeUrlAsync("tab-one", {});
      await saml.getAuthorizeUrlAsync("tab-two", {});
    });

    it("accepts the response carrying its own tab's RelayState", async () => {
      const result = await saml.validatePostResponseAsync({
        ...loginResponse("_request_1"),
        RelayState: "tab-one",
      });

      expect(result.profile).to.not.equal(null);
      expect(result.relayState).to.equal("tab-one");
    });

    it("rejects a response whose RelayState names another tab's transaction", async () => {
      expect(
        await outcome(
          saml.validatePostResponseAsync({
            ...loginResponse("_request_1"),
            RelayState: "tab-two",
          }),
        ),
      ).to.equal("RelayState does not match the one the AuthnRequest was issued with");
      // The transaction is consumed, so the swapped response cannot be retried either.
      expect(await cacheProvider.getAsync("_request_1")).to.equal(null);
    });

    it("rejects a response that drops a RelayState the request was issued with", async () => {
      expect(await outcome(saml.validatePostResponseAsync(loginResponse("_request_1")))).to.equal(
        "RelayState does not match the one the AuthnRequest was issued with",
      );
    });

    // The cross-account/cross-business case: the IdP answers tab one's request, but the response
    // is presented at the callback with the other tab's RelayState, which is what would bind the
    // resulting session to the wrong browser context.
    it("rejects a genuine response delivered into the other tab's session", async () => {
      const responseForTabOneWithTabTwosState = {
        ...loginResponse("_request_1"),
        RelayState: "tab-two",
      };

      expect(
        await outcome(saml.validatePostResponseAsync(responseForTabOneWithTabTwosState)),
      ).to.equal("RelayState does not match the one the AuthnRequest was issued with");
      // Tab two's own transaction is untouched, so its genuine response still works.
      const tabTwo = await saml.validatePostResponseAsync({
        ...loginResponse("_request_2"),
        RelayState: "tab-two",
      });
      expect(tabTwo.profile).to.not.equal(null);
    });

    it("accepts each tab's own response independently", async () => {
      const first = await saml.validatePostResponseAsync({
        ...loginResponse("_request_1"),
        RelayState: "tab-one",
      });
      const second = await saml.validatePostResponseAsync({
        ...loginResponse("_request_2"),
        RelayState: "tab-two",
      });

      expect(first.profile).to.not.equal(null);
      expect(second.profile).to.not.equal(null);
      expect(first.relayState).to.equal("tab-one");
      expect(second.relayState).to.equal("tab-two");
    });

    it("accepts a response with no RelayState when its request carried none", async () => {
      const noRelayStateSaml = newSaml({ cacheProvider, generateUniqueId: idGenerator() });
      await noRelayStateSaml.getAuthorizeUrlAsync("", {});

      const result = await noRelayStateSaml.validatePostResponseAsync(loginResponse("_request_1"));

      expect(result.profile).to.not.equal(null);
      expect(result).to.not.have.property("relayState");
    });
  });

  describe("across a restart with a shared persistent cache", function () {
    it("still binds the response to its tab after a new SAML instance is constructed", async () => {
      const cacheProvider = new InMemoryCacheProvider();
      await newSaml({ cacheProvider }).getAuthorizeUrlAsync("tab-one", {});

      // A fresh instance stands in for the process that handles the callback after a restart.
      const restarted = newSaml({ cacheProvider, generateUniqueId: idGenerator() });
      const result = await restarted.validatePostResponseAsync({
        ...loginResponse("_request_1"),
        RelayState: "tab-one",
      });

      expect(result.profile).to.not.equal(null);
      expect(result.relayState).to.equal("tab-one");
    });

    it("rejects a response whose RelayState does not survive the restart intact", async () => {
      const cacheProvider = new InMemoryCacheProvider();
      await newSaml({ cacheProvider }).getAuthorizeUrlAsync("tab-one", {});

      const restarted = newSaml({ cacheProvider, generateUniqueId: idGenerator() });
      expect(
        await outcome(
          restarted.validatePostResponseAsync({
            ...loginResponse("_request_1"),
            RelayState: "some-other-tab",
          }),
        ),
      ).to.equal("RelayState does not match the one the AuthnRequest was issued with");
    });
  });

  describe("both bindings", function () {
    it("freezes and verifies the transaction over the POST binding", async () => {
      const cacheProvider = new InMemoryCacheProvider();
      const saml = newSaml({ cacheProvider });

      const message = await saml.getAuthorizeMessageAsync("post-tab", {});
      expect(message.RelayState).to.equal("post-tab");

      const result = await saml.validatePostResponseAsync({
        ...loginResponse("_request_1"),
        RelayState: "post-tab",
      });
      expect(result.relayState).to.equal("post-tab");
    });

    it("freezes the transaction over the redirect binding, including compression", async () => {
      const cacheProvider = new InMemoryCacheProvider();
      const saml = newSaml({ cacheProvider, skipRequestCompression: false });

      const url = new URL(await saml.getAuthorizeUrlAsync("redirect-tab", {}));
      expect(url.searchParams.get("RelayState")).to.equal("redirect-tab");
      const inflated = zlib.inflateRawSync(
        Buffer.from(url.searchParams.get("SAMLRequest") as string, "base64"),
      ).toString();
      expect(inflated).to.contain('ID="_request_1"');

      const stored = JSON.parse((await cacheProvider.getAsync("_request_1")) as string);
      expect(stored.relayState).to.equal("redirect-tab");
    });
  });
});
