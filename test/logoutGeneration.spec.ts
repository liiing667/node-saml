import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as zlib from "zlib";
import { expect } from "chai";
import {
  InMemoryCacheProvider,
  LogoutReportedError,
  SAML,
  SamlConfig,
  ValidateInResponseTo,
} from "../src";
import { Profile } from "../src/types";
import { signXml } from "../src/xml";

const privateKey = fs.readFileSync(path.join(__dirname, "static", "key.pem"), "utf-8");
const idpCert = fs.readFileSync(path.join(__dirname, "static", "cert.pem"), "utf-8");
const namespaces =
  'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
const success =
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>';
const requesterError =
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>';
const nameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const user: Profile = {
  issuer: "idp",
  nameID: "user",
  nameIDFormat,
  sessionIndex: "_session_1",
};

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

function logoutResponseXml({
  inResponseTo,
  status = success,
}: {
  inResponseTo: string;
  status?: string;
}): string {
  return (
    `<samlp:LogoutResponse ${namespaces} ID="_logout_response" Version="2.0" IssueInstant="${instant()}" InResponseTo="${inResponseTo}">` +
    `<saml:Issuer>idp</saml:Issuer>${status}</samlp:LogoutResponse>`
  );
}

function signedPostLogoutResponse(xml: string): Record<string, string> {
  return { SAMLResponse: Buffer.from(sign(xml, "LogoutResponse")).toString("base64") };
}

function signedRedirectLogoutResponse(xml: string): string {
  const signed = {
    SAMLResponse: zlib.deflateRawSync(xml).toString("base64"),
    SigAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  };
  const signature = crypto
    .createSign("RSA-SHA256")
    .update(new URLSearchParams(signed).toString())
    .sign(privateKey, "base64");
  return new URLSearchParams({ ...signed, Signature: signature }).toString();
}

function loginResponse({
  inResponseTo,
  sessionIndex,
  nameID = "user",
}: {
  inResponseTo?: string;
  sessionIndex?: string;
  nameID?: string;
}): Record<string, string> {
  const inResponseToAttribute = inResponseTo == null ? "" : ` InResponseTo="${inResponseTo}"`;
  const subjectInResponseToAttribute =
    inResponseTo == null ? "" : ` InResponseTo="${inResponseTo}"`;
  const sessionIndexAttribute = sessionIndex == null ? "" : ` SessionIndex="${sessionIndex}"`;
  const xml =
    `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}"${inResponseToAttribute}>` +
    `<saml:Issuer>idp</saml:Issuer>${success}` +
    `<saml:Assertion ID="_assertion" Version="2.0" IssueInstant="${instant()}">` +
    `<saml:Issuer>idp</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="${nameIDFormat}">${nameID}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData NotOnOrAfter="${instant(300000)}" Recipient="http://localhost/saml/consume"${subjectInResponseToAttribute}/>` +
    `</saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">` +
    `<saml:AudienceRestriction><saml:Audience>onesaml_login</saml:Audience></saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${instant()}"${sessionIndexAttribute}/>` +
    `</saml:Assertion></samlp:Response>`;
  return { SAMLResponse: Buffer.from(sign(xml, "Assertion")).toString("base64") };
}

function newSaml(config: Partial<SamlConfig> = {}): SAML {
  return new SAML({
    callbackUrl: "http://localhost/saml/consume",
    entryPoint: "https://idp.example.com/sso",
    logoutUrl: "https://idp.example.com/slo",
    issuer: "onesaml_login",
    idpCert,
    validateInResponseTo: ValidateInResponseTo.always,
    wantAuthnResponseSigned: true,
    generateUniqueId: () => "_logout_request",
    ...config,
  });
}

describe("logout session generation", function () {
  it("freezes the identity, request ID and local termination result", async function () {
    const saml = newSaml();

    const { url, report } = await saml.beginLogoutAsync(user, "", {});

    expect(url).to.contain("SAMLRequest=");
    expect(report.requestId).to.equal("_logout_request");
    expect(report.sessionGeneration).to.equal(1);
    expect(report.sessionIndex).to.equal(user.sessionIndex);
    expect(report.nameID).to.equal(user.nameID);
    expect(report.terminationResult).to.equal("terminated");
    expect(report.stage).to.equal("initiated");
    expect(await saml.getLogoutReportAsync(report.requestId)).to.deep.equal(report);
  });

  it(
    "keeps the request ID and generation across an IdP failure, then commits a retry",
    async function () {
      const saml = newSaml();
      const first = await saml.beginLogoutAsync(user, "", {});
      const failure = signedPostLogoutResponse(
        logoutResponseXml({
          inResponseTo: first.report.requestId,
          status: requesterError,
        }),
      );

      await assert.rejects(saml.validatePostResponseAsync(failure), {
        message: "Bad status code: urn:oasis:names:tc:SAML:2.0:status:Requester",
      });

      const failed = await saml.getLogoutReportAsync(first.report.requestId);
      expect(failed?.responseResult).to.equal("failure");
      expect(failed?.terminationResult).to.equal("terminated");
      expect(failed?.failure?.stage).to.equal("response-status");
      expect(failed?.failure?.location).to.contain("verifyLogoutResponse");

      const retry = await saml.beginLogoutAsync(user, "", {});
      expect(retry.report.requestId).to.equal(first.report.requestId);
      expect(retry.report.sessionGeneration).to.equal(first.report.sessionGeneration);
      expect(retry.report.terminationResult).to.equal("terminated");

      const result = await saml.validatePostResponseAsync(
        signedPostLogoutResponse(logoutResponseXml({ inResponseTo: first.report.requestId })),
      );
      expect(result.logoutReport?.requestId).to.equal(first.report.requestId);
      expect(result.logoutReport?.sessionGeneration).to.equal(first.report.sessionGeneration);
      expect(result.logoutReport?.terminationResult).to.equal("terminated");
      const completed = await saml.getLogoutReportAsync(first.report.requestId);
      expect(completed?.state).to.equal("terminated");
      expect(completed?.responseResult).to.equal("success");
      expect(completed?.terminationResult).to.equal("terminated");
    },
  );

  it("does not revive a terminated session when a completed logout is retried", async function () {
    let nextId = 0;
    const saml = newSaml({ generateUniqueId: () => `_logout_${++nextId}` });
    const first = await saml.beginLogoutAsync(user, "", {});

    await saml.validatePostResponseAsync(
      signedPostLogoutResponse(logoutResponseXml({ inResponseTo: first.report.requestId })),
    );

    const retry = await saml.beginLogoutAsync(user, "", {});
    expect(retry.report.requestId).to.not.equal(first.report.requestId);
    expect(retry.report.sessionGeneration).to.equal(first.report.sessionGeneration + 1);
    expect(retry.report.terminationResult).to.equal("terminated");
    expect((await saml.getLogoutReportAsync(first.report.requestId))?.responseResult).to.equal(
      "success",
    );
  });

  it("reads the same complete state from a new SAML instance sharing the cache", async function () {
    const cacheProvider = new InMemoryCacheProvider();
    const saml = newSaml({ cacheProvider });
    const first = await saml.beginLogoutAsync(user, "", {});
    await assert.rejects(
      saml.validatePostResponseAsync(
        signedPostLogoutResponse(
          logoutResponseXml({
            inResponseTo: first.report.requestId,
            status: requesterError,
          }),
        ),
      ),
      { message: "Bad status code: urn:oasis:names:tc:SAML:2.0:status:Requester" },
    );

    const restarted = newSaml({ cacheProvider });
    const recovered = await restarted.recoverLogoutSessionAsync(user);

    expect(await restarted.getLogoutReportAsync(user)).to.deep.equal(recovered);
    expect(recovered?.requestId).to.equal(first.report.requestId);
    expect(recovered?.sessionGeneration).to.equal(first.report.sessionGeneration);
    expect(recovered?.terminationResult).to.equal("terminated");
    expect(recovered?.responseResult).to.equal("failure");
    expect(recovered?.failure?.stage).to.equal("response-status");
  });

  it(
    "rejects a login assertion issued before the logout and accepts one issued after it",
    async function () {
      let nextId = 0;
      const cacheProvider = new InMemoryCacheProvider();
      const saml = newSaml({
        cacheProvider,
        generateUniqueId: () => `_request_${++nextId}`,
        wantAuthnResponseSigned: false,
      });

      await saml.getAuthorizeUrlAsync("", {});
      const oldLoginRequestId = "_request_1";
      const logout = await saml.beginLogoutAsync(user, "", {});
      await saml.validatePostResponseAsync(
        signedPostLogoutResponse(logoutResponseXml({ inResponseTo: logout.report.requestId })),
      );

      await assert.rejects(
        saml.validatePostResponseAsync(
          loginResponse({ inResponseTo: oldLoginRequestId, sessionIndex: user.sessionIndex }),
        ),
        (err: LogoutReportedError) =>
          err.message.includes("terminated by logout request") &&
          err.logoutReport?.failure?.stage === "login-generation",
      );

      await saml.getAuthorizeUrlAsync("", {});
      const { profile } = await saml.validatePostResponseAsync(
        loginResponse({ inResponseTo: "_request_3", sessionIndex: user.sessionIndex }),
      );
      expect(profile?.nameID).to.equal("user");
    },
  );

  it("keeps a legacy request ID usable and reports it as a legacy transaction", async function () {
    const saml = newSaml();
    await saml.cacheProvider.saveAsync("_legacy_request", new Date().toISOString());

    const report = await saml.getLogoutReportAsync("_legacy_request");
    expect(report?.stage).to.equal("legacy");
    expect(report?.sessionGeneration).to.equal(0);
    expect(report?.terminationResult).to.equal("not-terminated");

    const { loggedOut } = await saml.validatePostResponseAsync(
      signedPostLogoutResponse(logoutResponseXml({ inResponseTo: "_legacy_request" })),
    );
    expect(loggedOut).to.be.true;
  });

  it("records the failure stage for a Redirect-binding logout response", async function () {
    const saml = newSaml();
    const first = await saml.beginLogoutAsync(user, "", {});
    const query = signedRedirectLogoutResponse(
      logoutResponseXml({
        inResponseTo: first.report.requestId,
        status: requesterError,
      }),
    );

    await assert.rejects(saml.validateRedirectAsync(query), {
      message: "Bad status code: urn:oasis:names:tc:SAML:2.0:status:Requester",
    });

    const report = await saml.getLogoutReportAsync(first.report.requestId);
    expect(report?.failure?.stage).to.equal("response-status");
    expect(report?.terminationResult).to.equal("terminated");
  });

  it(
    "does not block an anonymous login when the logout carries no session index",
    async function () {
      const anonymous = { ...user, sessionIndex: undefined };
      const saml = newSaml({
        wantAuthnResponseSigned: false,
        validateInResponseTo: ValidateInResponseTo.never,
        generateUniqueId: (() => {
          let nextId = 0;
          return () => `_anonymous_${++nextId}`;
        })(),
      });
      const logout = await saml.beginLogoutAsync(anonymous, "", {});
      expect(logout.report.sessionIndex).to.equal(null);

      await saml.validatePostResponseAsync(
        signedPostLogoutResponse(logoutResponseXml({ inResponseTo: logout.report.requestId })),
      );

      const { profile } = await saml.validatePostResponseAsync(
        loginResponse({ nameID: anonymous.nameID }),
      );
      expect(profile?.nameID).to.equal(anonymous.nameID);
    },
  );
});
