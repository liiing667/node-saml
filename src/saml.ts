import * as crypto from "crypto";
import { ParsedQs } from "qs";
import * as querystring from "querystring";
import { URL, URLSearchParams } from "url";
import * as util from "util";
import * as zlib from "zlib";
import * as algorithms from "./algorithms";
import { DEFAULT_IDENTIFIER_FORMAT, DEFAULT_WANT_ASSERTIONS_SIGNED } from "./constants";
import { generateUniqueId, keyInfoToPem, privateKeyToPem } from "./crypto";
import { dateStringToTimestamp, generateInstant } from "./date-time";
import { warnIfRequestExtensionsInvalid } from "./extensions";
import { InMemoryCacheProvider } from "./in-memory-cache-provider";
import {
  assertValidAttributeConsumingServices,
  buildServiceProviderMetadata,
  warnIfContactOrOrganizationInvalid,
} from "./metadata";
import { signAuthnRequestPost } from "./saml-post-signing";
import {
  AudienceRestrictionXML,
  AuthOptions,
  AuthorizeRequestXML,
  CacheProvider,
  IdpCertCallback,
  isValidSamlSigningOptions,
  LogoutError,
  LogoutFailure,
  LogoutReport,
  LogoutResponseResult,
  LogoutResult,
  LogoutSessionState,
  LogoutSessionTerminatedError,
  LogoutStage,
  LogoutRequestXML,
  Profile,
  SamlConfig,
  SamlIDPEntryConfig,
  SamlIDPListConfig,
  SamlOptions,
  SamlResponseXmlJs,
  SamlStatusError,
  ValidateInResponseTo,
  XmlJsObject,
  XMLInput,
  XMLObject,
  XMLOutput,
  XMLValue,
} from "./types";
import { assertBooleanIfPresent, assertRequired } from "./utility";
import {
  buildXml2JsObject,
  buildXmlBuilderObject,
  decryptXml,
  getNameIdAsync,
  getVerifiedXml,
  parseDomFromString,
  parseXml2JsFromString,
  warnIfDecryptionWillFailInNextMajor,
  xpath,
} from "./xml";

const debugLog = util.debuglog("node-saml");

// `host` sits before `options`, so removing it outright would slide `options` into its place
// and silently discard a JavaScript caller's `additionalParams`. Accepting both shapes lets
// callers move first. Module-level so it adds nothing to the `SAML` class surface, which
// subclasses inherit. Passing `undefined` for both cannot be told from passing neither, so
// that case is not reported.
function resolveAuthOptions(
  hostOrOptions: string | AuthOptions | undefined,
  legacyOptions: AuthOptions | undefined,
  methodName: string,
): AuthOptions | undefined {
  if (typeof hostOrOptions === "string" || legacyOptions !== undefined) {
    debugLog(
      "%s was called with a `host` argument. It is unused and is removed in the next major version; call %s(RelayState, options) instead.",
      methodName,
      methodName,
    );
    return legacyOptions;
  }

  return hostOrOptions;
}

// Ignored, so no caller can substitute the verifier, and accepted so that a caller who passed it
// still compiles. Module-level: a `protected` helper would join the `SAML` class surface.
function warnIgnoredInjectedDependencies(legacyInjectedDependencies: unknown): void {
  if (legacyInjectedDependencies !== undefined) {
    debugLog(
      "validatePostRequestAsync was called with injected dependencies. They are ignored — signature verification cannot be substituted — and the argument is removed in the next major version; call validatePostRequestAsync(container) instead.",
    );
  }
}

// xml2js keeps attribute prefixes as written, so `xsi` is resolved against the declarations in
// scope rather than trusted by name.
function isXsiNil(value: XMLOutput, ancestors: XMLOutput[]): boolean {
  const own: XMLOutput = value.$ ?? {};
  const inScope: XMLOutput = Object.assign({}, ...ancestors.map((element) => element.$), own);
  return Object.keys(own).some((name) => {
    const [prefix, localName] = name.split(":");
    return (
      localName === "nil" &&
      inScope[`xmlns:${prefix}`] === "http://www.w3.org/2001/XMLSchema-instance" &&
      /^\s*(true|1)\s*$/.test(own[name])
    );
  });
}

// Reading the ID and then removing it lets two concurrent copies of one response both find it,
// so a provider that can take it in one step does.
async function consumeRequestIdAsync(
  cacheProvider: CacheProvider,
  requestId: string,
): Promise<string | null> {
  if (cacheProvider.consumeAsync) {
    return cacheProvider.consumeAsync(requestId);
  }

  const value = await cacheProvider.getAsync(requestId);
  await cacheProvider.removeAsync(requestId);
  return value;
}

async function consumeInResponseToAsync(
  cacheProvider: CacheProvider,
  inResponseTo: string | null,
): Promise<void> {
  if (inResponseTo != null && (await consumeRequestIdAsync(cacheProvider, inResponseTo)) == null) {
    throw new Error("InResponseTo is not valid");
  }
}

function logoutGenerationKey(issuer: string): string {
  return JSON.stringify(["node-saml", "logout-generation", issuer]);
}

function loginGenerationKey(issuer: string, requestId: string): string {
  return JSON.stringify(["node-saml", "login-generation", issuer, requestId]);
}

function logoutReportKey(issuer: string, requestId: string): string {
  return JSON.stringify(["node-saml", "logout-report", issuer, requestId]);
}

interface LogoutIdentity {
  nameID?: string | null;
  nameIDFormat?: string | null;
  nameQualifier?: string | null;
  spNameQualifier?: string | null;
  sessionIndex?: string | null;
}

function logoutSessionKey(issuer: string, user: LogoutIdentity): string {
  return JSON.stringify([
    "node-saml",
    "logout-session",
    issuer,
    user.nameID ?? null,
    user.nameIDFormat ?? null,
    user.nameQualifier ?? null,
    user.spNameQualifier ?? null,
    user.sessionIndex ?? null,
  ]);
}

function parseJsonObject(value: string | null): Record<string, unknown> | null {
  if (value == null) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return parsed != null && typeof parsed === "object"
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function parseGeneration(value: string | null): number {
  if (value == null || !/^\d+$/.test(value)) {
    return 0;
  }
  const generation = Number(value);
  return Number.isSafeInteger(generation) ? generation : 0;
}

function parseLoginGeneration(value: string | null): number | null {
  if (value == null || !/^\d+$/.test(value)) {
    return null;
  }
  const generation = Number(value);
  return Number.isSafeInteger(generation) ? generation : null;
}

function isLogoutStage(value: unknown): value is LogoutStage {
  return (
    typeof value === "string" &&
    [
      "initiated",
      "request-url",
      "response-signature",
      "response-status",
      "response-issuer",
      "response-in-response-to",
      "login-generation",
      "response-validation",
      "committed",
      "recovered",
      "legacy",
    ].includes(value)
  );
}

function parseLogoutFailure(value: unknown): LogoutFailure | undefined {
  if (value == null || typeof value !== "object") {
    return undefined;
  }
  const failure = value as Partial<LogoutFailure>;
  if (
    !isLogoutStage(failure.stage) ||
    typeof failure.message !== "string" ||
    typeof failure.location !== "string"
  ) {
    return undefined;
  }
  return { stage: failure.stage, message: failure.message, location: failure.location };
}

function parseLogoutRecord(value: string | null): LogoutReport | null {
  const record = parseJsonObject(value);
  if (record == null || record.version !== 1) {
    return null;
  }
  if (record.kind !== "logout" && record.kind !== "logout-session") {
    return null;
  }
  const requestId = record.requestId;
  const requestIssueInstant = record.requestIssueInstant;
  const sessionGeneration = record.sessionGeneration;
  const nameID = record.nameID;
  const state = record.state;
  const terminationResult = record.terminationResult;
  const responseResult = record.responseResult;
  const stage = record.stage;
  if (
    typeof requestId !== "string" ||
    typeof requestIssueInstant !== "string" ||
    typeof sessionGeneration !== "number" ||
    typeof nameID !== "string" ||
    (state !== "pending" && state !== "terminated" && state !== "failed") ||
    (terminationResult !== "terminated" && terminationResult !== "not-terminated") ||
    (responseResult !== "none" &&
      responseResult !== "success" &&
      responseResult !== "failure" &&
      responseResult !== "replay") ||
    !isLogoutStage(stage)
  ) {
    return null;
  }
  return {
    version: 1,
    kind: "logout",
    requestId,
    requestIssueInstant,
    sessionGeneration,
    sessionIndex: typeof record.sessionIndex === "string" ? record.sessionIndex : null,
    nameID,
    nameIDFormat: typeof record.nameIDFormat === "string" ? record.nameIDFormat : null,
    nameQualifier: typeof record.nameQualifier === "string" ? record.nameQualifier : null,
    spNameQualifier: typeof record.spNameQualifier === "string" ? record.spNameQualifier : null,
    state,
    terminationResult,
    responseResult,
    stage,
    attempts: typeof record.attempts === "number" ? record.attempts : 1,
    createdAt: typeof record.createdAt === "string" ? record.createdAt : "",
    updatedAt: typeof record.updatedAt === "string" ? record.updatedAt : "",
    failure: parseLogoutFailure(record.failure),
  };
}

function parseLogoutSessionState(value: string | null): LogoutSessionState | null {
  const record = parseJsonObject(value);
  if (record?.kind !== "logout-session") {
    return null;
  }
  const report = parseLogoutRecord(value);
  return report == null ? null : logoutSessionStateFromReport(report);
}

function logoutSessionStateFromReport(report: LogoutReport): LogoutSessionState {
  return {
    version: report.version,
    kind: "logout-session",
    requestId: report.requestId,
    requestIssueInstant: report.requestIssueInstant,
    sessionGeneration: report.sessionGeneration,
    sessionIndex: report.sessionIndex,
    nameID: report.nameID,
    nameIDFormat: report.nameIDFormat,
    nameQualifier: report.nameQualifier,
    spNameQualifier: report.spNameQualifier,
    state: report.state,
    terminationResult: report.terminationResult,
    responseResult: report.responseResult,
    stage: report.stage,
    attempts: report.attempts,
    createdAt: report.createdAt,
    updatedAt: report.updatedAt,
    failure: report.failure,
  };
}

function logoutReportFromSessionState(state: LogoutSessionState): LogoutReport {
  return {
    version: state.version,
    kind: "logout",
    requestId: state.requestId,
    requestIssueInstant: state.requestIssueInstant,
    sessionGeneration: state.sessionGeneration,
    sessionIndex: state.sessionIndex,
    nameID: state.nameID,
    nameIDFormat: state.nameIDFormat,
    nameQualifier: state.nameQualifier,
    spNameQualifier: state.spNameQualifier,
    state: state.state,
    terminationResult: state.terminationResult,
    responseResult: state.responseResult,
    stage: state.stage,
    attempts: state.attempts,
    createdAt: state.createdAt,
    updatedAt: state.updatedAt,
    failure: state.failure,
  };
}

async function putCacheValueAsync(
  cacheProvider: CacheProvider,
  key: string,
  value: string,
): Promise<void> {
  if (cacheProvider.updateAsync) {
    if (await cacheProvider.updateAsync(key, value)) {
      return;
    }
  } else {
    await cacheProvider.removeAsync(key);
  }
  const saved = await cacheProvider.saveAsync(key, value);
  if (saved == null && cacheProvider.updateAsync) {
    // Another writer inserted the key between the update and the insert; publish ours in place.
    await cacheProvider.updateAsync(key, value);
  }
}

async function currentLogoutGenerationAsync(
  cacheProvider: CacheProvider,
  issuer: string,
): Promise<number> {
  return parseGeneration(await cacheProvider.getAsync(logoutGenerationKey(issuer)));
}

async function nextLogoutGenerationAsync(
  cacheProvider: CacheProvider,
  issuer: string,
): Promise<number> {
  const key = logoutGenerationKey(issuer);
  for (let attempt = 0; attempt < 4; attempt++) {
    const currentValue = await cacheProvider.getAsync(key);
    const next = parseGeneration(currentValue) + 1;
    if (cacheProvider.compareAndSwapAsync) {
      if (await cacheProvider.compareAndSwapAsync(key, currentValue, String(next))) {
        return next;
      }
      continue;
    }
    await putCacheValueAsync(cacheProvider, key, String(next));
    return next;
  }
  throw new Error("Could not allocate a logout session generation");
}

function logoutFailureLocation(stage: LogoutStage): string {
  switch (stage) {
    case "response-status":
      return "src/saml.ts:SAML.verifyLogoutResponse (status)";
    case "response-issuer":
      return "src/saml.ts:SAML.verifyIssuer";
    case "response-in-response-to":
      return "src/saml.ts:SAML.validateInResponseTo";
    case "login-generation":
      return "src/saml.ts:SAML.assertLoginSessionGenerationAsync";
    case "response-signature":
      return "src/saml.ts:SAML.validatePostResponseAsync/validateRedirectAsync (signature)";
    case "request-url":
      return "src/saml.ts:SAML.getLogoutUrlAsync";
    case "initiated":
      return "src/saml.ts:SAML._generateLogoutRequest";
    default:
      return "src/saml.ts:SAML.validatePostResponseAsync/validateRedirectAsync";
  }
}

function logoutFailureFrom(err: unknown, fallbackStage: LogoutStage): LogoutFailure {
  const message = err instanceof Error ? err.message : String(err);
  let stage = fallbackStage;
  if (message.startsWith("Bad status code")) {
    stage = "response-status";
  } else if (
    message.startsWith("Unknown SAML issuer") ||
    message.startsWith("Missing SAML issuer") ||
    message.startsWith("Expected one SAML issuer")
  ) {
    stage = "response-issuer";
  } else if (message.includes("InResponseTo")) {
    stage = "response-in-response-to";
  } else if (message.toLowerCase().includes("signature")) {
    stage = "response-signature";
  }
  return { stage, message, location: logoutFailureLocation(stage) };
}

function logoutReportWithFailure(
  report: LogoutReport,
  err: unknown,
  fallbackStage: LogoutStage,
): LogoutReport {
  const failure = logoutFailureFrom(err, fallbackStage);
  return { ...report, stage: failure.stage, updatedAt: generateInstant(), failure };
}

function attachLogoutReport(err: unknown, report: LogoutReport | null): void {
  if (report == null || !(err instanceof Error)) {
    return;
  }
  Object.defineProperty(err, "logoutReport", {
    configurable: true,
    enumerable: false,
    value: report,
    writable: true,
  });
}

function hasLogoutReport(err: unknown): boolean {
  return err instanceof Error && Object.prototype.hasOwnProperty.call(err, "logoutReport");
}

function withLogoutReport<T extends { profile: Profile | null; loggedOut: boolean }>(
  result: T,
  report: LogoutReport | null,
): T & { logoutReport?: LogoutReport } {
  if (report != null) {
    Object.defineProperty(result, "logoutReport", {
      configurable: true,
      enumerable: false,
      value: report,
      writable: true,
    });
  }
  return result;
}

// An unsigned Response's InResponseTo can name any request, the sender's own or someone else's
// pending one, so under "always" it cannot tie an assertion to a request. "ifPresent" accepts the
// response as unsolicited instead.
function assertResponseInResponseToCanAnswer(
  validateInResponseTo: ValidateInResponseTo,
  inResponseToIsVerified: boolean,
): void {
  if (!inResponseToIsVerified && validateInResponseTo === ValidateInResponseTo.always) {
    throw new Error("SubjectInResponseTo is missing and the Response's InResponseTo is not signed");
  }
}

function getRootAttribute(dom: Document, name: string): string | null {
  const nodes = xpath.selectAttributes(dom, `/*/@${name}`);
  return nodes.length ? nodes[0].nodeValue : null;
}

// SAML core §2.3.3 and §3.2.1-2 allow one; with more, the order would pick the issuer.
function assertOneIssuer(issuers: (string | null | undefined)[]): void {
  if (issuers.length > 1) {
    throw new Error(`Expected one SAML issuer, received ${issuers.length}: ${issuers.join(", ")}`);
  }
}

// Compared as parsed URLs, so the case of the scheme and host and an explicit default port don't
// count, while the path does, trailing slash included.
function isSameUrl(received: string, expected: string): boolean {
  try {
    return new URL(received).href === new URL(expected).href;
  } catch {
    return received === expected;
  }
}

// SAML core §3.2.2, and SAML bindings §3.4.5.2 and §3.5.5.2, which require it of a signed message:
// https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
function warnIfDestinationIsNot(
  endpointOption: "callbackUrl" | "logoutCallbackUrl",
  endpoint: string | undefined,
  messageName: string,
  destination: string | null | undefined,
): void {
  if (endpoint == null) {
    return;
  }
  if (destination == null) {
    debugLog(
      'The signed %s has no Destination, where `%s` ("%s") was expected. SAML bindings require one on a signed message, and the next major version rejects it. Configure the identity provider to include the Destination in the messages it signs.',
      messageName,
      endpointOption,
      endpoint,
    );
  } else if (!isSameUrl(destination, endpoint)) {
    debugLog(
      'The %s has the Destination "%s", where `%s` ("%s") was expected. The next major version rejects it. If that Destination is the URL of this endpoint, set `%s` to it; otherwise, configure the identity provider to send it to `%s`.',
      messageName,
      destination,
      endpointOption,
      endpoint,
      endpointOption,
      endpointOption,
    );
  }
}

// SAML profiles §4.1.4.2 and §4.1.4.3: an assertion is delivered through a bearer confirmation whose
// Recipient is the assertion consumer service.
// https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
function warnIfNoBearerConfirmationNames(
  callbackUrl: string,
  confirmationMethods: string[],
  timelyBearerRecipients: (string | undefined)[],
): void {
  if (timelyBearerRecipients.length === 0) {
    debugLog(
      'The assertion has no bearer SubjectConfirmation that is valid now; received: %s. The next major version accepts an assertion only through a bearer SubjectConfirmation whose Recipient is `callbackUrl` ("%s"), and rejects this one. Configure the identity provider to send one that is valid when the assertion arrives.',
      confirmationMethods.length > 0 ? confirmationMethods.join(", ") : "none",
      callbackUrl,
    );
  } else if (
    !timelyBearerRecipients.some(
      (recipient) => recipient != null && isSameUrl(recipient, callbackUrl),
    )
  ) {
    debugLog(
      'No bearer SubjectConfirmationData in the assertion has the Recipient `callbackUrl` ("%s"); received: %s. The next major version rejects the assertion. Configure the identity provider to send `callbackUrl` as the Recipient, or, if a Recipient received is the URL of this endpoint, set `callbackUrl` to it.',
      callbackUrl,
      timelyBearerRecipients.map((recipient) => recipient ?? "no Recipient").join(", "),
    );
  }
}

async function getSubjectInResponseTosAsync(assertionXml: string): Promise<string[]> {
  return xpath
    .selectAttributes(
      await parseDomFromString(assertionXml),
      "/*[local-name()='Assertion']/*[local-name()='Subject']/*[local-name()='SubjectConfirmation']/*[local-name()='SubjectConfirmationData']/@InResponseTo",
    )
    .map((attribute) => attribute.nodeValue)
    .filter((value): value is string => value != null);
}

// The last moment validation would still accept the assertion: each NotOnOrAfter it checks, capped
// by maxAssertionAgeMs, plus the clock skew it allows. A SubjectConfirmation other than the one
// chosen this time can be chosen next time, so the latest of theirs counts. Null if nothing bounds it.
function assertionAcceptedUntilMs(
  assertion: XMLOutput,
  maxAssertionAgeMs: number,
  acceptedClockSkewMs: number,
): number | null {
  const limitMs = (notOnOrAfter: string) => {
    const notOnOrAfterMs = dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter");
    const issueInstantMs = dateStringToTimestamp(assertion.$.IssueInstant, "IssueInstant");
    return maxAssertionAgeMs === 0
      ? notOnOrAfterMs
      : Math.min(notOnOrAfterMs, issueInstantMs + maxAssertionAgeMs);
  };
  const limitsMs: number[] = [];
  const conditionsNotOnOrAfter = assertion.Conditions?.[0].$?.NotOnOrAfter;
  if (conditionsNotOnOrAfter != null) {
    limitsMs.push(limitMs(conditionsNotOnOrAfter));
  }
  const confirmationLimitsMs = ((assertion.Subject?.[0].SubjectConfirmation ?? []) as XMLOutput[])
    .map((confirmation) => confirmation.SubjectConfirmationData?.[0].$?.NotOnOrAfter)
    .filter((notOnOrAfter) => notOnOrAfter != null)
    .map(limitMs);
  if (confirmationLimitsMs.length > 0) {
    limitsMs.push(Math.max(...confirmationLimitsMs));
  }
  return limitsMs.length === 0 ? null : Math.min(...limitsMs) + acceptedClockSkewMs;
}

class ReplayedAssertionError extends Error {}

// SAML profiles §4.1.4.5: the SP remembers the ID of each assertion it accepts for as long as that
// assertion would be valid. It is recorded before the checks that can still reject the assertion, so
// one rejected as not yet valid cannot be presented again once it is.
// https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
async function recordAssertionAsync(assertionXml: string, options: SamlOptions): Promise<void> {
  const doc: XMLOutput = await parseXml2JsFromString(assertionXml);
  const assertion: XMLOutput = doc.Assertion;
  const id = assertion.$?.ID;
  if (id == null) {
    throw new Error("The assertion has no ID, so it cannot be checked for replay");
  }
  const acceptedUntilMs = assertionAcceptedUntilMs(
    assertion,
    options.maxAssertionAgeMs,
    options.acceptedClockSkewMs,
  );
  if (acceptedUntilMs == null) {
    throw new Error(
      "The assertion has no NotOnOrAfter, so it would be accepted for ever and cannot be checked for replay",
    );
  }
  if (acceptedUntilMs <= new Date().getTime()) {
    return; // already expired, which the checks that follow reject
  }

  // Kept apart from request IDs, which are stored as they are, and from other identity providers'.
  const key = JSON.stringify(["assertion", assertion.Issuer?.[0]._ ?? "", id]);
  // The constructor refuses a cacheProvider without saveIfAbsentAsync while this option is on.
  const cacheProvider = options.cacheProvider as Required<Pick<CacheProvider, "saveIfAbsentAsync">>;
  if (!(await cacheProvider.saveIfAbsentAsync(key, generateInstant(), acceptedUntilMs))) {
    throw new ReplayedAssertionError(`The assertion ${id} has already been received`);
  }
}

const inflateRawAsync = util.promisify(zlib.inflateRaw);
const deflateRawAsync = util.promisify(zlib.deflateRaw);

const redirectParameterNames = ["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"];

// For a parameter a caller supplies: null and undefined mean it was not given, and "" or [] that
// it is empty.
const hasValue = <T>(value: T | null | undefined): value is T =>
  value != null && String(value) !== "";

// As `querystring.parse` decodes a name or a value.
const decodeQueryComponent = (component: string): string =>
  querystring.unescape(component.replace(/\+/g, " "));

const queryParameterNames = (originalQuery: string): string[] =>
  originalQuery.split("&").map((token) => decodeQueryComponent(token.split("=", 1)[0]));

interface RedirectParameters {
  samlMessageType: "SAMLRequest" | "SAMLResponse";
  samlMessage: string;
  relayState?: string | undefined;
  signed?: { octets: string; signature: string; sigAlg: string };
}

// SAML bindings 3.4.4.1: the signature covers these parameters as they arrived, still URL-encoded.
// https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
function readRedirectParameters(originalQuery: string): RedirectParameters {
  const parameters = new Map<string, { token: string; value: string }>();
  for (const token of originalQuery.split("&")) {
    const [encodedName] = token.split("=", 1);
    const name = decodeQueryComponent(encodedName);
    if (!redirectParameterNames.includes(name)) continue;
    // The signature covers one parameter of each name, and nothing says which of two that is.
    if (parameters.has(name)) {
      throw new Error(`The query string has more than one ${name} parameter`);
    }
    const value = decodeQueryComponent(token.slice(encodedName.length + 1));
    parameters.set(name, { token, value });
  }

  const request = parameters.get("SAMLRequest");
  const response = parameters.get("SAMLResponse");
  if (request && response) {
    throw new Error("The query string has both a SAMLRequest and a SAMLResponse parameter");
  }
  const message = request ?? response;
  if (!message) {
    throw new Error("The query string has no SAMLRequest or SAMLResponse parameter");
  }
  const relayState = parameters.get("RelayState");
  const signature = parameters.get("Signature");
  const sigAlg = parameters.get("SigAlg");

  let signed: RedirectParameters["signed"];
  if (signature) {
    if (!sigAlg) {
      throw new Error("The query string has a Signature parameter but no SigAlg parameter");
    }
    const covered = relayState ? [message, relayState, sigAlg] : [message, sigAlg];
    signed = {
      octets: covered.map(({ token }) => token).join("&"),
      signature: signature.value,
      sigAlg: sigAlg.value,
    };
  }

  return {
    samlMessageType: request ? "SAMLRequest" : "SAMLResponse",
    samlMessage: message.value,
    relayState: relayState?.value,
    signed,
  };
}

// `container` is typed as a `qs` parse, and `qs` reads `RelayState[]` and `[RelayState]` as
// RelayState.
const bracketedParameter = (name: string): string | undefined =>
  redirectParameterNames.find(
    (reserved) => name.startsWith(`${reserved}[`) || name.startsWith(`[${reserved}]`),
  );

// A caller who passes `container`, its own parse of the query string, goes on reading it. So a
// signed query string must not let that parse hold a parameter that was not verified, and what
// `container` says about a Signature counts. An unsigned message is still read from it.
function readRedirectParametersBeside(
  container: ParsedQs,
  originalQuery: string,
): RedirectParameters {
  const names = queryParameterNames(originalQuery);
  const bracketed = names.map(bracketedParameter).filter((name) => name !== undefined);
  const claimsSignature =
    container.Signature != null || names.includes("Signature") || bracketed.includes("Signature");
  if (!claimsSignature) {
    const samlMessageType = container.SAMLRequest ? "SAMLRequest" : "SAMLResponse";
    return { samlMessageType, samlMessage: container[samlMessageType] as string };
  }

  if (bracketed.length > 0) {
    throw new Error(`The query string has a ${bracketed[0]} parameter in bracket notation`);
  }
  const parameters = readRedirectParameters(originalQuery);
  // This form returns no RelayState, so the caller's is the one in `container`, and how its
  // parser was set to split or nest the query string is not known here.
  if (container.RelayState != null && container.RelayState !== parameters.relayState) {
    throw new Error("The parsed query has a RelayState that the query string does not");
  }
  return parameters;
}

// `container` is a second reading of the query string, by a parser this library does not choose.
// Accepting both shapes lets callers move to the query string alone before the next major version
// removes the other. Module-level so it adds nothing to the `SAML` class surface.
function resolveRedirectArguments(
  originalQueryOrContainer: string | ParsedQs,
  legacyOriginalQuery: string | undefined,
): { container: ParsedQs; originalQuery: string; parameters: RedirectParameters; legacy: boolean } {
  if (typeof originalQueryOrContainer === "string") {
    const parameters = readRedirectParameters(originalQueryOrContainer);
    const { samlMessageType, samlMessage, relayState, signed } = parameters;
    // No caller of this shape relies on unsigned messages, so it does not accept them. Checked
    // here and not in `hasValidSignatureForRedirect`, which an override can replace.
    if (!signed) {
      throw new Error("The query string has no Signature parameter");
    }
    // An override of `hasValidSignatureForRedirect` is still handed a parse to read.
    const container: ParsedQs = {
      [samlMessageType]: samlMessage,
      SigAlg: signed.sigAlg,
      Signature: signed.signature,
    };
    if (relayState !== undefined) container.RelayState = relayState;
    return { container, originalQuery: originalQueryOrContainer, parameters, legacy: false };
  }

  if (typeof legacyOriginalQuery !== "string") {
    throw new TypeError("originalQuery is required");
  }
  debugLog(
    "validateRedirectAsync was called with a parsed query object. That argument is removed in the next major version; call validateRedirectAsync(originalQuery) and use the relayState it returns in place of your own parse.",
  );
  return {
    container: originalQueryOrContainer,
    originalQuery: legacyOriginalQuery,
    parameters: readRedirectParametersBeside(originalQueryOrContainer, legacyOriginalQuery),
    legacy: true,
  };
}

const resolveAndParseKeyInfosToPem = async ({
  idpCert,
}: Pick<SamlOptions, "idpCert">): Promise<string[]> => {
  const certs =
    typeof idpCert === "function"
      ? await util
          .promisify(idpCert as IdpCertCallback)()
          .then((resolvedCerts) => {
            assertRequired(resolvedCerts, "callback didn't return idpCert");

            return resolvedCerts;
          })
      : idpCert;

  if (Array.isArray(certs)) {
    return certs.map((cert, index) => keyInfoToPem(cert, "CERTIFICATE", `idpCert[${index}]`));
  } else {
    return [keyInfoToPem(certs, "CERTIFICATE", `idpCert`)];
  }
};

class SAML {
  /**
   * Note that some methods in SAML are not yet marked as protected as they are used in testing.
   * Those methods start with an underscore, e.g. _generateLogoutRequest
   */
  options: SamlOptions;
  // This is only for testing
  cacheProvider: CacheProvider;

  // Array of PEM files used to validate signatures.
  pemFiles: string[] = [];

  constructor(ctorOptions: SamlConfig) {
    this.options = this.initialize(ctorOptions);
    this.cacheProvider = this.options.cacheProvider;
  }

  initialize(ctorOptions: SamlConfig): SamlOptions {
    if (!ctorOptions) {
      throw new TypeError("SamlOptions required on construction");
    }

    assertRequired(ctorOptions.callbackUrl, "callbackUrl is required");
    assertRequired(ctorOptions.issuer, "issuer is required");
    assertRequired(ctorOptions.idpCert, "idpCert is required");

    // Prevent a JS user from passing in "false", which is truthy, and doing the wrong thing
    assertBooleanIfPresent(ctorOptions.passive);
    assertBooleanIfPresent(ctorOptions.disableRequestedAuthnContext);
    assertBooleanIfPresent(ctorOptions.forceAuthn);
    assertBooleanIfPresent(ctorOptions.skipRequestCompression);
    assertBooleanIfPresent(ctorOptions.disableRequestAcsUrl);
    assertBooleanIfPresent(ctorOptions.allowCreate);
    assertBooleanIfPresent(ctorOptions.wantAssertionsSigned);
    assertBooleanIfPresent(ctorOptions.wantAuthnResponseSigned);
    assertBooleanIfPresent(ctorOptions.signMetadata);
    assertBooleanIfPresent(ctorOptions.rejectReplayedAssertions);
    assertValidAttributeConsumingServices(ctorOptions.metadataAttributeConsumingServices);
    if (isValidSamlSigningOptions(ctorOptions)) {
      algorithms.assertDigestAlgorithmChosen(
        ctorOptions.signatureAlgorithm,
        ctorOptions.digestAlgorithm,
      );
    }

    const options: SamlOptions = {
      ...ctorOptions,
      passive: ctorOptions.passive ?? false,
      disableRequestedAuthnContext: ctorOptions.disableRequestedAuthnContext ?? false,
      additionalParams: ctorOptions.additionalParams ?? {},
      additionalAuthorizeParams: ctorOptions.additionalAuthorizeParams ?? {},
      additionalLogoutParams: ctorOptions.additionalLogoutParams ?? {},
      forceAuthn: ctorOptions.forceAuthn ?? false,
      skipRequestCompression: ctorOptions.skipRequestCompression ?? false,
      disableRequestAcsUrl: ctorOptions.disableRequestAcsUrl ?? false,
      acceptedClockSkewMs: ctorOptions.acceptedClockSkewMs ?? 0,
      maxAssertionAgeMs: ctorOptions.maxAssertionAgeMs ?? 0,
      rejectReplayedAssertions: ctorOptions.rejectReplayedAssertions ?? false,
      callbackUrl: ctorOptions.callbackUrl,
      issuer: ctorOptions.issuer,
      audience: ctorOptions.audience ?? ctorOptions.issuer ?? "unknown_audience", // use issuer as default
      identifierFormat:
        ctorOptions.identifierFormat === undefined
          ? DEFAULT_IDENTIFIER_FORMAT
          : ctorOptions.identifierFormat,
      allowCreate: ctorOptions.allowCreate ?? true,
      spNameQualifier: ctorOptions.spNameQualifier,
      wantAssertionsSigned: ctorOptions.wantAssertionsSigned ?? DEFAULT_WANT_ASSERTIONS_SIGNED,
      wantAuthnResponseSigned: ctorOptions.wantAuthnResponseSigned ?? true,
      authnContext: ctorOptions.authnContext ?? [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
      ],
      validateInResponseTo: ctorOptions.validateInResponseTo ?? ValidateInResponseTo.never,
      idpCert: ctorOptions.idpCert,
      requestIdExpirationPeriodMs: ctorOptions.requestIdExpirationPeriodMs ?? 28800000, // 8 hours
      cacheProvider:
        ctorOptions.cacheProvider ??
        new InMemoryCacheProvider({
          keyExpirationPeriodMs: ctorOptions.requestIdExpirationPeriodMs,
        }),
      logoutUrl: ctorOptions.logoutUrl ?? ctorOptions.entryPoint ?? "", // Default to Entry Point
      signatureAlgorithm: ctorOptions.signatureAlgorithm ?? "sha1",
      authnRequestBinding: ctorOptions.authnRequestBinding ?? "HTTP-Redirect",
      generateUniqueId: ctorOptions.generateUniqueId ?? generateUniqueId,
      signMetadata: ctorOptions.signMetadata ?? false,
      racComparison: ctorOptions.racComparison ?? "exact",
    };

    if (!Object.values(ValidateInResponseTo).includes(options.validateInResponseTo)) {
      throw new TypeError("validateInResponseTo must be one of ['never', 'ifPresent', 'always']");
    }

    // Inheriting one of these defaults looks exactly like choosing it, so the notice that the
    // next major requires a choice has to come from the option being absent.
    if (ctorOptions.validateInResponseTo === undefined) {
      debugLog(
        "`validateInResponseTo` is not set, so it defaults to `never` and an InResponseTo is not checked against a request this library issued. A SAML response can then be replayed, or delivered unsolicited. The next major version requires it; set it to `always`, `ifPresent`, or `never` now.",
      );
    }

    if (ctorOptions.rejectReplayedAssertions === undefined) {
      debugLog(
        "`rejectReplayedAssertions` is not set, so it defaults to `false`, and an assertion that `validateInResponseTo` does not tie to a request can be presented again until its timestamps expire. The next major version rejects a replayed assertion; set it to `true` now.",
      );
    }

    if (options.rejectReplayedAssertions) {
      if (options.acceptedClockSkewMs === -1) {
        throw new TypeError(
          "rejectReplayedAssertions cannot be used with acceptedClockSkewMs: -1, under which an assertion never expires",
        );
      }
      if (options.cacheProvider.saveIfAbsentAsync == null) {
        throw new TypeError(
          "rejectReplayedAssertions requires a cacheProvider with saveIfAbsentAsync, which saves a key with an expiry only if it is absent, in one step",
        );
      }
    }

    if (
      options.validateInResponseTo !== ValidateInResponseTo.never &&
      options.cacheProvider.consumeAsync == null
    ) {
      debugLog(
        "`cacheProvider` has no `consumeAsync`, so a request ID is read and then removed in separate calls, and two copies of one response validated at the same moment can both be accepted. The next major version requires it; implement it to remove a key and return its value in one step.",
      );
    }

    if (isValidSamlSigningOptions(ctorOptions)) {
      for (const option of ["signatureAlgorithm", "digestAlgorithm"] as const) {
        if (ctorOptions[option] === undefined) {
          algorithms.warnAlgorithmNotSet(option);
        }
      }
    }

    for (const option of ["signatureAlgorithm", "digestAlgorithm"] as const) {
      algorithms.warnIfAlgorithmNotRecognized(option, ctorOptions[option]);
    }

    warnIfContactOrOrganizationInvalid(ctorOptions);
    warnIfRequestExtensionsInvalid(ctorOptions);

    /**
     * List of possible values:
     * - exact : Assertion context must exactly match a context in the list
     * - minimum:  Assertion context must be at least as strong as a context in the list
     * - maximum:  Assertion context must be no stronger than a context in the list
     * - better:  Assertion context must be stronger than all contexts in the list
     */
    if (!["exact", "minimum", "maximum", "better"].includes(options.racComparison)) {
      throw new TypeError("racComparison must be one of ['exact', 'minimum', 'maximum', 'better']");
    }

    return options;
  }

  protected signRequest(samlMessage: querystring.ParsedUrlQueryInput): void {
    assertRequired(this.options.privateKey, "privateKey is required");

    const sigAlg = algorithms.getSigningAlgorithm(this.options.signatureAlgorithm);
    samlMessage.SigAlg = sigAlg;
    const signer = algorithms.findSignatureAlgorithm(sigAlg);
    assertRequired(signer, `${sigAlg} is not supported`);
    // SAML bindings 3.4.4.1: the signature covers these as `_requestToUrlAsync` serializes them.
    // https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
    const signedParameters = new URLSearchParams();
    for (const name of ["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg"]) {
      if (hasValue(samlMessage[name])) {
        signedParameters.set(name, samlMessage[name] as string);
      }
    }
    samlMessage.Signature = signer.getSignature(
      signedParameters.toString(),
      privateKeyToPem(this.options.privateKey, "privateKey"),
    );
  }

  protected async generateAuthorizeRequestAsync(
    this: SAML,
    isPassive: boolean,
    isHttpPostBinding: boolean,
  ): Promise<string> {
    assertRequired(this.options.entryPoint, "entryPoint is required");

    const id = this.options.generateUniqueId();
    const instant = generateInstant();

    if (this.mustValidateInResponseTo(true)) {
      await this.cacheProvider.saveAsync(id, instant);
      // A login issued after a logout shares the current generation; an assertion from a login
      // issued before it must not re-establish the terminated session after a restart.
      await putCacheValueAsync(
        this.cacheProvider,
        loginGenerationKey(this.options.issuer, id),
        String(await currentLogoutGenerationAsync(this.cacheProvider, this.options.issuer)),
      );
    }
    const request: AuthorizeRequestXML = {
      "samlp:AuthnRequest": {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@ID": id,
        "@Version": "2.0",
        "@IssueInstant": instant,
        "@ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "@Destination": this.options.entryPoint,
        "saml:Issuer": {
          "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
          "#text": this.options.issuer,
        },
      },
    };

    if (isPassive) request["samlp:AuthnRequest"]["@IsPassive"] = true;

    if (this.options.forceAuthn === true) {
      request["samlp:AuthnRequest"]["@ForceAuthn"] = true;
    }

    if (!this.options.disableRequestAcsUrl) {
      request["samlp:AuthnRequest"]["@AssertionConsumerServiceURL"] = this.options.callbackUrl;
    }

    const samlAuthnRequestExtensions = this.options.samlAuthnRequestExtensions;
    if (samlAuthnRequestExtensions != null) {
      if (typeof samlAuthnRequestExtensions != "object") {
        throw new TypeError("samlAuthnRequestExtensions should be Object");
      }
      request["samlp:AuthnRequest"]["samlp:Extensions"] = {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        ...samlAuthnRequestExtensions,
      };
    }

    const nameIDPolicy: XMLInput = {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      "@AllowCreate": this.options.allowCreate,
    };

    if (this.options.identifierFormat != null) {
      nameIDPolicy["@Format"] = this.options.identifierFormat;
    }

    if (this.options.spNameQualifier != null) {
      nameIDPolicy["@SPNameQualifier"] = this.options.spNameQualifier;
    }

    request["samlp:AuthnRequest"]["samlp:NameIDPolicy"] = nameIDPolicy;

    if (!this.options.disableRequestedAuthnContext) {
      const authnContextClassRefs: XMLInput[] = [];
      (this.options.authnContext as string[]).forEach(function (value) {
        authnContextClassRefs.push({
          "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
          "#text": value,
        });
      });

      request["samlp:AuthnRequest"]["samlp:RequestedAuthnContext"] = {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@Comparison": this.options.racComparison,
        "saml:AuthnContextClassRef": authnContextClassRefs,
      };
    }

    if (this.options.attributeConsumingServiceIndex != null) {
      request["samlp:AuthnRequest"]["@AttributeConsumingServiceIndex"] =
        this.options.attributeConsumingServiceIndex;
    }

    if (this.options.providerName != null) {
      request["samlp:AuthnRequest"]["@ProviderName"] = this.options.providerName;
    }

    if (this.options.scoping != null) {
      const scoping: XMLInput = { "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol" };

      if (typeof this.options.scoping.proxyCount === "number") {
        scoping["@ProxyCount"] = this.options.scoping.proxyCount;
      }

      if (this.options.scoping.idpList) {
        scoping["samlp:IDPList"] = this.options.scoping.idpList.map(
          (idpListItem: SamlIDPListConfig) => {
            const formattedIdpListItem: XMLInput = {
              "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            };

            if (idpListItem.entries) {
              formattedIdpListItem["samlp:IDPEntry"] = idpListItem.entries.map(
                (entry: SamlIDPEntryConfig) => {
                  const formattedEntry: XMLInput = {
                    "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                  };

                  formattedEntry["@ProviderID"] = entry.providerId;

                  if (entry.name) {
                    formattedEntry["@Name"] = entry.name;
                  }

                  if (entry.loc) {
                    formattedEntry["@Loc"] = entry.loc;
                  }

                  return formattedEntry;
                },
              );
            }

            if (idpListItem.getComplete) {
              formattedIdpListItem["samlp:GetComplete"] = idpListItem.getComplete;
            }

            return formattedIdpListItem;
          },
        );
      }

      if (this.options.scoping.requesterId) {
        scoping["samlp:RequesterID"] = this.options.scoping.requesterId;
      }

      request["samlp:AuthnRequest"]["samlp:Scoping"] = scoping;
    }

    let stringRequest = buildXmlBuilderObject(request, false);
    // TODO: maybe we should always sign here
    if (isHttpPostBinding && isValidSamlSigningOptions(this.options)) {
      stringRequest = signAuthnRequestPost(stringRequest, this.options);
    }
    return stringRequest;
  }

  async _generateLogoutRequest(this: SAML, user: Profile): Promise<string> {
    const id = this.options.generateUniqueId();
    const instant = generateInstant();
    if (
      this.options.samlLogoutRequestExtensions != null &&
      typeof this.options.samlLogoutRequestExtensions !== "object"
    ) {
      throw new TypeError("samlLogoutRequestExtensions should be Object");
    }
    const sessionKey = logoutSessionKey(this.options.issuer, user);
    const currentSession = await this.readLogoutSessionAsync(user);

    let requestId = id;
    let requestInstant = instant;
    let sessionGeneration: number;
    let attempts = 1;
    let frozenUser = user;

    if (currentSession != null && currentSession.terminationResult === "terminated") {
      attempts = currentSession.attempts + 1;
      // A pending or failed request is retried with the same ID and bytes, so the IdP can
      // recognize it as one transaction. A completed request has already consumed its ID; a
      // retry starts a new request and a new generation so a login issued before this logout
      // cannot become current again.
      if (currentSession.responseResult === "success") {
        sessionGeneration = await nextLogoutGenerationAsync(
          this.cacheProvider,
          this.options.issuer,
        );
      } else {
        sessionGeneration = currentSession.sessionGeneration;
        requestId = currentSession.requestId;
        requestInstant = currentSession.requestIssueInstant || instant;
      }
      frozenUser = {
        ...user,
        nameID: currentSession.nameID,
        nameIDFormat: currentSession.nameIDFormat ?? user.nameIDFormat,
        nameQualifier: currentSession.nameQualifier ?? user.nameQualifier,
        spNameQualifier: currentSession.spNameQualifier ?? user.spNameQualifier,
        sessionIndex: currentSession.sessionIndex ?? user.sessionIndex,
      };
    } else {
      sessionGeneration = await nextLogoutGenerationAsync(this.cacheProvider, this.options.issuer);
    }

    const request = {
      "samlp:LogoutRequest": {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "@ID": requestId,
        "@Version": "2.0",
        "@IssueInstant": requestInstant,
        "@Destination": this.options.logoutUrl,
        "saml:Issuer": {
          "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
          "#text": this.options.issuer,
        },
        "samlp:Extensions": {},
        "saml:NameID": { "@Format": frozenUser.nameIDFormat, "#text": frozenUser.nameID },
      },
    } as LogoutRequestXML;

    const samlLogoutRequestExtensions = this.options.samlLogoutRequestExtensions;
    if (samlLogoutRequestExtensions != null) {
      if (typeof samlLogoutRequestExtensions != "object") {
        throw new TypeError("samlLogoutRequestExtensions should be Object");
      }
      request["samlp:LogoutRequest"]["samlp:Extensions"] = {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        ...samlLogoutRequestExtensions,
      };
    } else {
      delete request["samlp:LogoutRequest"]["samlp:Extensions"];
    }

    if (frozenUser.nameQualifier != null) {
      request["samlp:LogoutRequest"]["saml:NameID"]["@NameQualifier"] = frozenUser.nameQualifier;
    }

    if (frozenUser.spNameQualifier != null) {
      request["samlp:LogoutRequest"]["saml:NameID"]["@SPNameQualifier"] =
        frozenUser.spNameQualifier;
    }

    if (frozenUser.sessionIndex) {
      request["samlp:LogoutRequest"]["saml2p:SessionIndex"] = {
        "@xmlns:saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
        "#text": frozenUser.sessionIndex,
      };
    }

    const now = generateInstant();
    const report: LogoutReport = {
      version: 1,
      kind: "logout",
      requestId,
      requestIssueInstant: requestInstant,
      sessionGeneration,
      sessionIndex: frozenUser.sessionIndex ?? null,
      nameID: frozenUser.nameID,
      nameIDFormat: frozenUser.nameIDFormat ?? null,
      nameQualifier: frozenUser.nameQualifier ?? null,
      spNameQualifier: frozenUser.spNameQualifier ?? null,
      state: "pending",
      terminationResult: "terminated",
      responseResult: "none",
      stage: "initiated",
      attempts,
      createdAt: currentSession?.createdAt || now,
      updatedAt: now,
    };
    const state = logoutSessionStateFromReport(report);
    const requestXml = buildXmlBuilderObject(request, false);

    // The session record is written first: it names the request that a retry must reuse even if
    // this process stops before the request itself is recorded or delivered.
    await putCacheValueAsync(this.cacheProvider, sessionKey, JSON.stringify(state));
    await putCacheValueAsync(
      this.cacheProvider,
      logoutReportKey(this.options.issuer, requestId),
      JSON.stringify(report),
    );
    // The request ID itself stays the value existing consumers and `validateInResponseTo` read.
    await putCacheValueAsync(this.cacheProvider, requestId, requestInstant);
    return requestXml;
  }

  private async readLogoutSessionAsync(user: Profile): Promise<LogoutSessionState | null> {
    const value = await this.cacheProvider.getAsync(logoutSessionKey(this.options.issuer, user));
    if (value == null) {
      return null;
    }
    const session = parseLogoutSessionState(value);
    if (session == null) {
      throw new Error("Logout session state is invalid");
    }
    return session;
  }

  private async readStoredLogoutReportAsync(requestId: string): Promise<LogoutReport | null> {
    const value = await this.cacheProvider.getAsync(
      logoutReportKey(this.options.issuer, requestId),
    );
    if (value == null) {
      return null;
    }
    const report = parseLogoutRecord(value);
    if (report == null) {
      throw new Error("Logout report is invalid");
    }
    return report;
  }

  private async readLogoutReportAsync(requestId: string): Promise<LogoutReport | null> {
    const stored = await this.readStoredLogoutReportAsync(requestId);
    if (stored != null) {
      return stored;
    }
    const legacy = await this.cacheProvider.getAsync(requestId);
    if (legacy == null) {
      return null;
    }
    const parsed = parseLogoutRecord(legacy);
    if (parsed != null) {
      return parsed;
    }
    // A pre-existing entry is a bare IssueInstant. It carries no generation, but it is still a
    // complete pending request that existing consumers can validate.
    const createdAt = Number.isNaN(Date.parse(legacy)) ? generateInstant() : legacy;
    return {
      version: 1,
      kind: "logout",
      requestId,
      requestIssueInstant: createdAt,
      sessionGeneration: 0,
      sessionIndex: null,
      nameID: "",
      nameIDFormat: null,
      nameQualifier: null,
      spNameQualifier: null,
      state: "pending",
      terminationResult: "not-terminated",
      responseResult: "none",
      stage: "legacy",
      attempts: 1,
      createdAt,
      updatedAt: createdAt,
    };
  }

  private async writeLogoutReportAsync(report: LogoutReport): Promise<void> {
    const state = logoutSessionStateFromReport(report);
    await putCacheValueAsync(
      this.cacheProvider,
      logoutSessionKey(this.options.issuer, report),
      JSON.stringify(state),
    );
    await putCacheValueAsync(
      this.cacheProvider,
      logoutReportKey(this.options.issuer, report.requestId),
      JSON.stringify(report),
    );
  }

  private async recordLogoutResponseAsync(
    requestId: string | null,
    responseResult: LogoutResponseResult,
    err?: unknown,
    fallbackStage: LogoutStage = "response-validation",
  ): Promise<LogoutReport | null> {
    if (requestId == null) {
      return null;
    }
    const current = await this.readStoredLogoutReportAsync(requestId);
    if (current == null) {
      return null;
    }
    // A duplicate response must not downgrade the one successful commit it duplicates.
    if (current.responseResult === "success") {
      const rejected =
        responseResult === "failure" || responseResult === "replay"
          ? logoutReportWithFailure(current, err, fallbackStage)
          : current;
      attachLogoutReport(err, rejected);
      return rejected;
    }
    const now = generateInstant();
    const failure =
      responseResult === "failure" || responseResult === "replay"
        ? logoutFailureFrom(err, fallbackStage)
        : undefined;
    const report: LogoutReport = {
      ...current,
      state: responseResult === "success" ? "terminated" : "failed",
      terminationResult: "terminated",
      responseResult,
      stage: responseResult === "success" ? "committed" : failure?.stage ?? fallbackStage,
      updatedAt: now,
      failure,
    };
    await this.writeLogoutReportAsync(report);
    attachLogoutReport(err, report);
    return report;
  }

  private async assertLoginSessionGenerationAsync(
    profile: Profile,
    answeredRequestId: string | null,
  ): Promise<void> {
    if (profile.sessionIndex == null) {
      // Without a SessionIndex there is no durable identity to tie an old assertion to a
      // logged-out session, and rejecting would also reject a legitimate anonymous login.
      return;
    }
    const session = await this.readLogoutSessionAsync(profile);
    if (session == null || session.terminationResult !== "terminated") {
      return;
    }
    const loginGeneration =
      answeredRequestId == null
        ? null
        : parseLoginGeneration(
            await this.cacheProvider.getAsync(
              loginGenerationKey(this.options.issuer, answeredRequestId),
            ),
          );
    // A request issued after the logout shares its generation. An older request, or one whose
    // generation cannot be recovered, cannot establish a new session for that SessionIndex.
    if (loginGeneration != null) {
      if (loginGeneration >= session.sessionGeneration) {
        return;
      }
    } else {
      // With InResponseTo validation off there is no request generation to compare. A new login
      // is still distinguishable by its signed IssueInstant: it postdates the logout request.
      let assertionIssueInstant: string | null = null;
      try {
        const assertionXml = profile.getAssertionXml?.();
        if (assertionXml != null) {
          const assertionDoc = (await parseXml2JsFromString(assertionXml)) as XMLOutput;
          const value = assertionDoc.Assertion?.$?.IssueInstant;
          assertionIssueInstant = typeof value === "string" ? value : null;
        }
      } catch {
        assertionIssueInstant = null;
      }
      const issuedAtMs = assertionIssueInstant == null ? NaN : Date.parse(assertionIssueInstant);
      const logoutStartedAtMs = Date.parse(session.createdAt);
      if (!Number.isNaN(issuedAtMs) && issuedAtMs > logoutStartedAtMs) {
        return;
      }
    }
    const message = `The SAML session ${profile.sessionIndex} was terminated by logout request ${session.requestId} (generation ${session.sessionGeneration}); the assertion has login generation ${loginGeneration ?? "unknown"}`;
    const report: LogoutReport = {
      ...logoutReportFromSessionState(session),
      stage: "login-generation",
      failure: {
        stage: "login-generation",
        message,
        location: logoutFailureLocation("login-generation"),
      },
    };
    throw new LogoutSessionTerminatedError(message, report);
  }

  _generateLogoutResponse(this: SAML, logoutRequest: Profile, success: boolean): string {
    const id = this.options.generateUniqueId();
    const instant = generateInstant();

    const successStatus = {
      "samlp:StatusCode": { "@Value": "urn:oasis:names:tc:SAML:2.0:status:Success" },
    };

    const failStatus = {
      "samlp:StatusCode": {
        "@Value": "urn:oasis:names:tc:SAML:2.0:status:Requester",
        "samlp:StatusCode": { "@Value": "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal" },
      },
    };

    const request = {
      "samlp:LogoutResponse": {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "@ID": id,
        "@Version": "2.0",
        "@IssueInstant": instant,
        "@Destination": this.options.logoutUrl,
        "@InResponseTo": logoutRequest.ID,
        "saml:Issuer": { "#text": this.options.issuer },
        "samlp:Status": success ? successStatus : failStatus,
      },
    };

    return buildXmlBuilderObject(request, false);
  }

  async _requestToUrlAsync(
    request: string | null | undefined,
    response: string | null,
    operation: string,
    additionalParameters: querystring.ParsedUrlQuery,
  ): Promise<string> {
    assertRequired(this.options.entryPoint, "entryPoint is required");
    const requestOrResponse = request || response;
    assertRequired(requestOrResponse, "either request or response is required");

    let buffer: Buffer;
    if (this.options.skipRequestCompression) {
      buffer = Buffer.from(requestOrResponse, "utf8");
    } else {
      buffer = await deflateRawAsync(requestOrResponse);
    }

    const base64 = buffer.toString("base64");
    let target = new URL(this.options.entryPoint);

    if (operation === "logout") {
      if (this.options.logoutUrl) {
        target = new URL(this.options.logoutUrl);
      }
    } else if (operation !== "authorize") {
      throw new Error("Unknown operation: " + operation);
    }

    const samlMessage: querystring.ParsedUrlQuery = request
      ? { SAMLRequest: base64 }
      : { SAMLResponse: base64 };
    Object.keys(additionalParameters).forEach((k) => {
      samlMessage[k] = additionalParameters[k];
    });
    // The caller's RelayState, or else the one in the endpoint's own URL. An empty one is not sent:
    // SAML bindings 3.4.4.1 signs none when there is no value, and receivers differ on whether a
    // signature covers an empty one that arrives.
    const relayState = samlMessage.RelayState ?? target.searchParams.get("RelayState");
    if (hasValue(relayState)) {
      samlMessage.RelayState = relayState;
    } else {
      delete samlMessage.RelayState;
      target.searchParams.delete("RelayState");
    }
    if (isValidSamlSigningOptions(this.options)) {
      if (!this.options.entryPoint) {
        throw new Error('"entryPoint" config parameter is required for signed messages');
      }

      // sets .SigAlg and .Signature
      this.signRequest(samlMessage);
    }
    Object.keys(samlMessage).forEach((k) => {
      target.searchParams.set(k, samlMessage[k] as string);
    });

    return target.toString();
  }

  _getAdditionalParams(
    relayState: string,
    operation: "authorize" | "logout",
    overrideParams?: querystring.ParsedUrlQuery,
  ): querystring.ParsedUrlQuery {
    const additionalParams: querystring.ParsedUrlQuery = {};

    if (typeof relayState === "string" && relayState.length > 0) {
      additionalParams.RelayState = relayState;
    }

    return Object.assign(
      additionalParams,
      this.options.additionalParams,
      operation === "logout"
        ? this.options.additionalLogoutParams
        : this.options.additionalAuthorizeParams,
      overrideParams ?? {},
    );
  }

  /**
   * The `host` argument is unused and is removed in the next major version; call
   * `getAuthorizeUrlAsync(RelayState, options)` instead. Passing it logs under `NODE_DEBUG=node-saml`.
   *
   * An override of this method must migrate alongside its callers: a two-argument call reaches
   * the override directly, so one written for the old signature receives `options` as `host`.
   */
  async getAuthorizeUrlAsync(
    RelayState: string,
    hostOrOptions: string | AuthOptions | undefined,
    legacyOptions?: AuthOptions,
  ): Promise<string> {
    const options = resolveAuthOptions(hostOrOptions, legacyOptions, "getAuthorizeUrlAsync");
    const request = await this.generateAuthorizeRequestAsync(this.options.passive, false);
    const operation = "authorize";
    const overrideParams = options ? options.additionalParams || {} : {};
    return await this._requestToUrlAsync(
      request,
      null,
      operation,
      this._getAdditionalParams(RelayState, operation, overrideParams),
    );
  }

  /**
   * The `host` argument is unused and is removed in the next major version; call
   * `getAuthorizeMessageAsync(RelayState, options)` instead. Passing it logs under `NODE_DEBUG=node-saml`.
   *
   * An override of this method must migrate alongside its callers: a two-argument call reaches
   * the override directly, so one written for the old signature receives `options` as `host`.
   */
  async getAuthorizeMessageAsync(
    RelayState: string,
    hostOrOptions?: string | AuthOptions,
    legacyOptions?: AuthOptions,
  ): Promise<querystring.ParsedUrlQueryInput> {
    const options = resolveAuthOptions(hostOrOptions, legacyOptions, "getAuthorizeMessageAsync");
    assertRequired(this.options.entryPoint, "entryPoint is required");

    const request = await this.generateAuthorizeRequestAsync(this.options.passive, true);
    let buffer: Buffer;
    if (this.options.skipRequestCompression) {
      buffer = Buffer.from(request, "utf8");
    } else {
      buffer = await deflateRawAsync(request);
    }

    const operation = "authorize";
    const overrideParams = options ? options.additionalParams || {} : {};
    const additionalParameters = this._getAdditionalParams(RelayState, operation, overrideParams);
    const samlMessage: querystring.ParsedUrlQueryInput = { SAMLRequest: buffer.toString("base64") };

    Object.keys(additionalParameters).forEach((k) => {
      samlMessage[k] = additionalParameters[k] || "";
    });

    return samlMessage;
  }

  /**
   * The `host` argument is unused and is removed in the next major version; call
   * `getAuthorizeFormAsync(RelayState, options)` instead. Passing it logs under `NODE_DEBUG=node-saml`.
   *
   * An override of this method must migrate alongside its callers: a two-argument call reaches
   * the override directly, so one written for the old signature receives `options` as `host`.
   */
  async getAuthorizeFormAsync(
    RelayState: string,
    hostOrOptions?: string | AuthOptions,
    legacyOptions?: AuthOptions,
  ): Promise<string> {
    // Called for the warning; the arguments are forwarded below as they arrived.
    resolveAuthOptions(hostOrOptions, legacyOptions, "getAuthorizeFormAsync");
    assertRequired(this.options.entryPoint, "entryPoint is required");

    // The quoteattr() function is used in a context, where the result will not be evaluated by javascript
    // but must be interpreted by an XML or HTML parser, and it must absolutely avoid breaking the syntax
    // of an element attribute.
    const quoteattr = function (
      s:
        | string
        | number
        | bigint
        | boolean
        | undefined
        | null
        | readonly (string | number | bigint | boolean)[],
      preserveCR?: boolean,
    ) {
      const preserveCRChar = preserveCR ? "&#13;" : "\n";
      return (
        ("" + s) // Forces the conversion to string.
          .replace(/&/g, "&amp;") // This MUST be the 1st replacement.
          .replace(/'/g, "&apos;") // The 4 other predefined entities, required.
          .replace(/"/g, "&quot;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          // Add other replacements here for HTML only
          // Or for XML, only if the named entities are defined in its DTD.
          .replace(/\r\n/g, preserveCRChar) // Must be before the next replacement.
          .replace(/[\r\n]/g, preserveCRChar)
      );
    };

    // Forwarded exactly as received: normalizing would change what a subclass override sees.
    const samlMessage = await this.getAuthorizeMessageAsync(
      RelayState,
      hostOrOptions,
      legacyOptions,
    );

    const formInputs = Object.keys(samlMessage)
      .map((k) => {
        return '<input type="hidden" name="' + k + '" value="' + quoteattr(samlMessage[k]) + '" />';
      })
      .join("\r\n");

    return [
      "<!DOCTYPE html>",
      "<html>",
      "<head>",
      '<meta charset="utf-8">',
      '<meta http-equiv="x-ua-compatible" content="ie=edge">',
      "</head>",
      '<body onload="document.forms[0].submit()">',
      "<noscript>",
      "<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>",
      "</noscript>",
      '<form method="post" action="' + encodeURI(this.options.entryPoint) + '">',
      formInputs,
      '<input type="submit" value="Submit" />',
      "</form>",
      '<script>document.forms[0].style.display="none";</script>', // Hide the form if JavaScript is enabled
      "</body>",
      "</html>",
    ].join("\r\n");
  }

  async getLogoutUrlAsync(
    user: Profile,
    RelayState: string,
    options: AuthOptions,
  ): Promise<string> {
    const request = await this._generateLogoutRequest(user);
    const operation = "logout";
    const overrideParams = options ? options.additionalParams || {} : {};
    try {
      return await this._requestToUrlAsync(
        request,
        null,
        operation,
        this._getAdditionalParams(RelayState, operation, overrideParams),
      );
    } catch (err) {
      try {
        const requestDoc = (await parseXml2JsFromString(request)) as XMLOutput;
        const requestId = requestDoc.LogoutRequest?.$?.ID as string | undefined;
        if (requestId != null) {
          await this.recordLogoutResponseAsync(requestId, "failure", err, "request-url");
        }
      } catch {
        // The URL-building error is the one the caller needs; the report is best effort here.
      }
      throw err;
    }
  }

  /**
   * Starts an SP-initiated logout and returns both the URL and the durable report for it.
   *
   * The local session is terminated when the request is created, before the identity provider
   * answers. If the answer is lost, a retry reuses the same request ID and session generation
   * after a failure, or starts a new request in a new generation after a success. Neither
   * restores the terminated session.
   *
   * @throws {LogoutError} If a report cannot be produced for the request.
   */
  async beginLogoutAsync(
    user: Profile,
    RelayState: string,
    options: AuthOptions,
  ): Promise<LogoutResult> {
    const request = await this._generateLogoutRequest(user);
    const requestDoc = (await parseXml2JsFromString(request)) as XMLOutput;
    const requestId = requestDoc.LogoutRequest?.$?.ID as string | undefined;
    if (requestId == null) {
      throw new Error("Logout request has no ID");
    }
    const report = await this.readLogoutReportAsync(requestId);
    if (report == null) {
      throw new LogoutError("Logout request was created without a transaction report", {
        version: 1,
        kind: "logout",
        requestId,
        requestIssueInstant: generateInstant(),
        sessionGeneration: 0,
        sessionIndex: user.sessionIndex ?? null,
        nameID: user.nameID,
        nameIDFormat: user.nameIDFormat ?? null,
        nameQualifier: user.nameQualifier ?? null,
        spNameQualifier: user.spNameQualifier ?? null,
        state: "pending",
        terminationResult: "terminated",
        responseResult: "none",
        stage: "initiated",
        attempts: 1,
        createdAt: generateInstant(),
        updatedAt: generateInstant(),
      });
    }

    const operation = "logout";
    const overrideParams = options ? options.additionalParams || {} : {};
    try {
      const url = await this._requestToUrlAsync(
        request,
        null,
        operation,
        this._getAdditionalParams(RelayState, operation, overrideParams),
      );
      return { url, report };
    } catch (err) {
      const failed = await this.recordLogoutResponseAsync(requestId, "failure", err, "request-url");
      attachLogoutReport(err, failed ?? report);
      throw err;
    }
  }

  /**
   * Reads the durable report for a logout request ID or for a profile's session.
   *
   * A request ID remains readable after its response was consumed, and a profile remains readable
   * after a restart when the same cache provider (or a shared one) is used. A pre-existing cache
   * entry that holds only an IssueInstant is reported as a legacy transaction.
   */
  async getLogoutReportAsync(requestIdOrUser: string | Profile): Promise<LogoutReport | null> {
    if (typeof requestIdOrUser === "string") {
      return this.readLogoutReportAsync(requestIdOrUser);
    }
    return this.recoverLogoutSessionAsync(requestIdOrUser);
  }

  /**
   * Reads the complete state a consumer should see after a restart: either no logout transaction
   * for the profile's session, or the transaction with its local termination result already
   * committed. It never returns a partially applied logout.
   */
  async recoverLogoutSessionAsync(user: Profile): Promise<LogoutReport | null> {
    const session = await this.readLogoutSessionAsync(user);
    if (session == null) {
      return null;
    }
    const report = await this.readLogoutReportAsync(session.requestId);
    if (report == null) {
      return logoutReportFromSessionState(session);
    }
    // The request record is written after the session record, so it carries the later stage.
    return report.updatedAt >= session.updatedAt ? report : logoutReportFromSessionState(session);
  }

  getLogoutResponseUrl(
    samlLogoutRequest: Profile,
    RelayState: string,
    options: AuthOptions,
    success: boolean,
    callback: (err: Error | null, url?: string) => void,
  ): void {
    util.callbackify(() =>
      this.getLogoutResponseUrlAsync(samlLogoutRequest, RelayState, options, success),
    )(callback);
  }

  async getLogoutResponseUrlAsync(
    samlLogoutRequest: Profile,
    RelayState: string,
    options: AuthOptions,
    success: boolean,
  ): Promise<string> {
    const response = this._generateLogoutResponse(samlLogoutRequest, success);
    const operation = "logout";
    const overrideParams = options ? options.additionalParams || {} : {};
    return await this._requestToUrlAsync(
      null,
      response,
      operation,
      this._getAdditionalParams(RelayState, operation, overrideParams),
    );
  }

  /**
   * @deprecated Pass a function as `idpCert` instead of overriding this: an override can change
   *   the keys a signature is verified with, so the next major version makes this method private.
   */
  protected async getKeyInfosAsPem(): Promise<string[]> {
    if (typeof this.options.idpCert === "function") {
      // Do not cache
      return await resolveAndParseKeyInfosToPem(this.options);
    } else if (this.pemFiles.length > 0) {
      // Return already cached PEM files.
      return this.pemFiles;
    }

    // Load PEM files from different sources and cache.
    this.pemFiles = await resolveAndParseKeyInfosToPem(this.options);
    return this.pemFiles;
  }

  // given actually signed XML, try to get the actual assertion used
  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected async getSignedAssertion(signedXml: string): Promise<string | null> {
    // case 1: Response signed
    const verifiedDoc = await parseDomFromString(signedXml);
    const rootNode = verifiedDoc.documentElement;

    // case 1: response is a verified assertion
    if (rootNode.localName === "Response") {
      // try getting the Xml from the assertions
      const assertions = xpath.selectElements(rootNode, "./*[local-name()='Assertion']");
      // now we can process the assertion as an assertion
      if (assertions.length == 1) {
        return assertions[0].toString();
      }
      // encrypted assertion
      const encryptedAssertions = xpath.selectElements(
        rootNode,
        "./*[local-name()='EncryptedAssertion']",
      );

      if (encryptedAssertions.length === 1) {
        assertRequired(this.options.decryptionPvk, "No decryption key for encrypted SAML response");

        const encryptedAssertionXml = encryptedAssertions[0].toString();

        const decryptedXml = await decryptXml(encryptedAssertionXml, this.options.decryptionPvk);
        const decryptedDoc = await parseDomFromString(decryptedXml);
        const decryptedAssertion = decryptedDoc.documentElement;
        if (decryptedAssertion.localName !== "Assertion") {
          throw new Error("Invalid EncryptedAssertion content");
        }

        return decryptedAssertion.toString();
      }
    } else if (rootNode.localName === "Assertion") {
      return rootNode.toString();
    } else {
      return null;
    }
    return null;
  }

  async validatePostResponseAsync(
    container: Record<string, string>,
  ): Promise<{ profile: Profile | null; loggedOut: boolean; logoutReport?: LogoutReport }> {
    let xml: string;
    let doc: Document;
    let inResponseTo: string | null = null;
    let verifiedInResponseTo: string | null = null;
    let verifiedDestination: string | null = null;
    let verifiedAssertionXml: string | null = null;
    let logoutRequestId: string | null = null;
    let logoutReport: LogoutReport | null = null;
    // Read before a signature is known, but used only to annotate a rejection; never written.
    let logoutEvidence: LogoutReport | null = null;
    let logoutResponseAccepted = false;

    try {
      xml = Buffer.from(container.SAMLResponse, "base64").toString("utf8");
      doc = await parseDomFromString(xml);

      const inResponseToNodes = xpath.selectAttributes(
        doc,
        "/*[local-name()='Response' or local-name()='LogoutResponse']/@InResponseTo",
      );

      if (inResponseToNodes) {
        inResponseTo = inResponseToNodes.length ? inResponseToNodes[0].nodeValue : null;
        if (inResponseTo != null) {
          try {
            logoutEvidence = await this.readStoredLogoutReportAsync(inResponseTo);
          } catch {
            logoutEvidence = null;
          }
        }

        await this.validateInResponseTo(inResponseTo);
      }
      const pemFiles = await this.getKeyInfosAsPem();
      // Check if this document has a valid top-level signature which applies to the entire XML document
      let validSignature = false; // Use `getVerifiedXml()` to collect the actual verified contents

      const responseVerifiedXml = getVerifiedXml(xml, doc.documentElement, pemFiles);
      let assertionVerifiedXml = null;
      let decryptedAssertionVerifiedXml = null;

      if (responseVerifiedXml) {
        validSignature = true;
        const verifiedDom = await parseDomFromString(responseVerifiedXml);
        verifiedInResponseTo = getRootAttribute(verifiedDom, "InResponseTo");
        verifiedDestination = getRootAttribute(verifiedDom, "Destination");
        assertOneIssuer(
          xpath
            .selectElements(verifiedDom, "/*[local-name()='Response']/*[local-name()='Issuer']")
            .map((issuer) => issuer.textContent),
        );
        if (this.options.idpIssuer != null) {
          const verifiedDoc: XMLOutput = await parseXml2JsFromString(responseVerifiedXml);
          // Checked only when present: an error response may omit it even when signed, and a login is
          // checked on its assertion's Issuer, which is required (SAML profiles §4.1.4.2, Errata 05 E17).
          if (verifiedDoc.Response?.Issuer) {
            this.verifyIssuer(verifiedDoc.Response);
          }
        }
      }

      if (this.options.wantAuthnResponseSigned === true && validSignature === false) {
        throw new Error("Invalid document signature");
      }

      const assertions = xpath.selectElements(
        doc,
        "/*[local-name()='Response']/*[local-name()='Assertion']",
      );
      const encryptedAssertions = xpath.selectElements(
        doc,
        "/*[local-name()='Response']/*[local-name()='EncryptedAssertion']",
      );

      if (assertions.length + encryptedAssertions.length > 1) {
        // There's no reason I know of that we want to handle multiple assertions, and it seems like a
        //   potential risk vector for signature scope issues, so treat this as an invalid signature
        throw new Error("Invalid signature: multiple assertions");
      }

      if (assertions.length == 1) {
        if (this.options.wantAssertionsSigned || !validSignature) {
          assertionVerifiedXml = getVerifiedXml(xml, assertions[0], pemFiles);
          if (!assertionVerifiedXml) {
            throw new Error("Invalid signature");
          }
        }
      }

      if (encryptedAssertions.length == 1) {
        assertRequired(this.options.decryptionPvk, "No decryption key for encrypted SAML response");

        const encryptedAssertionXml = encryptedAssertions[0].toString();

        const decryptedXml = await decryptXml(encryptedAssertionXml, this.options.decryptionPvk);
        warnIfDecryptionWillFailInNextMajor(encryptedAssertions[0]);
        const decryptedDoc = await parseDomFromString(decryptedXml);
        const decryptedAssertions = xpath.selectElements(
          decryptedDoc,
          "/*[local-name()='Assertion']",
        );
        if (decryptedAssertions.length != 1) throw new Error("Invalid EncryptedAssertion content");

        if (this.options.wantAssertionsSigned || !validSignature) {
          decryptedAssertionVerifiedXml = getVerifiedXml(
            decryptedXml,
            decryptedAssertions[0],
            pemFiles,
          );
          if (decryptedAssertionVerifiedXml == null) {
            throw new Error("Invalid signature from encrypted assertion");
          }
        }
      }

      // If there's no assertion, fall back on xml2js response parsing for the status &
      //   LogoutResponse code.
      // collect the verified XML's
      const verifiedXml =
        responseVerifiedXml || assertionVerifiedXml || decryptedAssertionVerifiedXml;

      // double check that there is at least 1 assertion
      if (verifiedXml && assertions.length + encryptedAssertions.length == 1) {
        const signedAssertion = await this.getSignedAssertion(verifiedXml);

        if (signedAssertion == null) {
          throw new Error("Cannot obtain assertion from signed data");
        }
        verifiedAssertionXml = signedAssertion;
        if (this.options.rejectReplayedAssertions) {
          await recordAssertionAsync(signedAssertion, this.options);
        }
        const result = await this.processValidlySignedAssertionAsync(
          signedAssertion,
          xml,
          responseVerifiedXml ? verifiedInResponseTo : inResponseTo,
          responseVerifiedXml != null,
        );
        let answeredRequestId: string | null = null;
        if (this.mustValidateInResponseTo(Boolean(inResponseTo))) {
          answeredRequestId = responseVerifiedXml
            ? verifiedInResponseTo
            : ((await getSubjectInResponseTosAsync(signedAssertion)).find(
                (subjectInResponseTo) => subjectInResponseTo === inResponseTo,
              ) ?? null);
        }
        await this.assertLoginSessionGenerationAsync(result.profile, answeredRequestId);
        // Consumed here, not in the overridable method, whose inResponseToIsVerified an override
        // written before that parameter drops. Unless the Response is signed, only the assertion
        // can name the request it answers.
        if (this.mustValidateInResponseTo(Boolean(inResponseTo))) {
          await consumeInResponseToAsync(this.cacheProvider, answeredRequestId ?? null);
        }
        // An unsigned Response's Destination is not verified, so it is not read.
        if (responseVerifiedXml) {
          warnIfDestinationIsNot(
            "callbackUrl",
            this.options.callbackUrl,
            "Response",
            verifiedDestination,
          );
        }
        return result;
      }

      // With no signature on the root nothing here was verified, and every path below rejects.
      const xmljsDoc = (await parseXml2JsFromString(
        responseVerifiedXml ?? xml,
      )) as SamlResponseXmlJs;
      const response = xmljsDoc.Response;
      if (response) {
        if (!("Assertion" in response)) {
          const status = response.Status;
          if (status) {
            const statusCode = status[0].StatusCode;
            if (
              statusCode &&
              statusCode[0].$?.Value === "urn:oasis:names:tc:SAML:2.0:status:Responder"
            ) {
              const nestedStatusCode = statusCode[0].StatusCode;
              if (
                nestedStatusCode &&
                nestedStatusCode[0].$?.Value === "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
              ) {
                if (!validSignature) {
                  throw new Error("Invalid signature: NoPassive");
                }
                if (this.mustValidateInResponseTo(Boolean(verifiedInResponseTo))) {
                  await consumeInResponseToAsync(this.cacheProvider, verifiedInResponseTo);
                }
                warnIfDestinationIsNot(
                  "callbackUrl",
                  this.options.callbackUrl,
                  "Response",
                  verifiedDestination,
                );
                return { profile: null, loggedOut: false };
              }
            }

            // No signature is required to report a failure, since the response is rejected either
            // way. An unsigned one only gets this far under `wantAuthnResponseSigned: false`.
            if (statusCode && statusCode[0].$?.Value) {
              const msgType = statusCode[0].$.Value.match(/[^:]*$/);
              if (msgType && msgType[0] != "Success") {
                let msg = "unspecified";
                if (status[0].StatusMessage) {
                  msg = status[0].StatusMessage[0]._ || msg;
                } else if (statusCode[0].StatusCode) {
                  const msgValues = statusCode[0].StatusCode[0].$?.Value.match(/[^:]*$/);
                  msg = msgValues ? msgValues[0] : msg;
                }
                const statusXml = buildXml2JsObject("Status", status[0]);
                throw new SamlStatusError(
                  "SAML provider returned " + msgType + " error: " + msg,
                  statusXml,
                );
              }
            }
          }
        }
        throw new Error("Missing SAML assertion");
      } else {
        if (!validSignature) {
          throw new Error("Invalid signature: No response found");
        }
        const logoutResponse = xmljsDoc.LogoutResponse;
        if (logoutResponse) {
          logoutRequestId = verifiedInResponseTo;
          await this.verifyLogoutResponse(xmljsDoc);
          if (this.mustValidateInResponseTo(Boolean(verifiedInResponseTo))) {
            await consumeInResponseToAsync(this.cacheProvider, verifiedInResponseTo);
          }
          if (logoutRequestId != null) {
            logoutResponseAccepted = true;
            logoutReport = await this.recordLogoutResponseAsync(logoutRequestId, "success");
          }
          warnIfDestinationIsNot(
            "logoutCallbackUrl",
            this.options.logoutCallbackUrl,
            "LogoutResponse",
            verifiedDestination,
          );
          return withLogoutReport({ profile: null, loggedOut: true }, logoutReport);
        } else {
          throw new Error("Unknown SAML response message");
        }
      }
    } catch (err) {
      debugLog.enabled && debugLog("validatePostResponse resulted in an error: %s", err);
      if (logoutRequestId != null && !logoutResponseAccepted) {
        await this.recordLogoutResponseAsync(logoutRequestId, "failure", err);
      } else if (logoutRequestId == null && logoutEvidence != null && !hasLogoutReport(err)) {
        attachLogoutReport(
          err,
          logoutReportWithFailure(logoutEvidence, err, "response-validation"),
        );
      }
      // A failure the IdP signed means it answered the request, so no other response is coming.
      // An unsigned one proves nothing about the request it names, so that request stays pending.
      // Gated as success is, so under "ifPresent" a failure retires nothing a success would keep.
      // A replay leaves its requests to the first copy, which may still be validating.
      if (
        !(err instanceof ReplayedAssertionError) &&
        this.mustValidateInResponseTo(Boolean(inResponseTo))
      ) {
        const answeredRequestIds = new Set(
          verifiedAssertionXml == null
            ? []
            : await getSubjectInResponseTosAsync(verifiedAssertionXml),
        );
        if (verifiedInResponseTo != null) {
          answeredRequestIds.add(verifiedInResponseTo);
        }
        for (const requestId of answeredRequestIds) {
          await this.cacheProvider.removeAsync(requestId);
        }
      }
      throw err;
    }
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected async validateInResponseTo(inResponseTo: string | null): Promise<void> {
    if (this.mustValidateInResponseTo(Boolean(inResponseTo))) {
      if (inResponseTo) {
        const result = await this.cacheProvider.getAsync(inResponseTo);
        if (!result) throw new Error("InResponseTo is not valid");
        return;
      } else {
        throw new Error("InResponseTo is missing from response");
      }
    }
  }

  // An override written against the two-argument signature has to stay assignable to every
  // signature here, so the one for the query string alone takes the old shape as well. The
  // deprecated signature comes first, so that a two-argument call resolves to it, and is repeated
  // last, so that `Parameters<SAML["validateRedirectAsync"]>` is still what it was.
  /**
   * @deprecated Call `validateRedirectAsync(originalQuery)` and use the `relayState` it returns: a
   *   parse of the query string can hold a parameter that the signature does not cover.
   */
  validateRedirectAsync(
    container: ParsedQs,
    originalQuery: string,
  ): Promise<{ profile: Profile | null; loggedOut: boolean; logoutReport?: LogoutReport }>;
  /**
   * Validates a `LogoutRequest` or `LogoutResponse` received over the HTTP-Redirect binding.
   *
   * Call it with the raw query string of the request: still URL-encoded, without the leading `?`.
   * The message, its `RelayState` and its signature are all read from that string, and the
   * message has to be signed.
   *
   * @returns The profile of a `LogoutRequest`, or `null` for a `LogoutResponse`, and the
   *   `RelayState` that was signed with the message.
   * @throws If the signature is missing or does not verify, if the query string has two
   *   candidates for one of the signed parameters, or if the message fails its own checks.
   */
  validateRedirectAsync(
    ...args: [originalQuery: string] | [container: ParsedQs, originalQuery: string]
  ): Promise<{
    profile: Profile | null;
    loggedOut: boolean;
    relayState?: string | undefined;
    logoutReport?: LogoutReport;
  }>;
  /**
   * @deprecated Call `validateRedirectAsync(originalQuery)` and use the `relayState` it returns: a
   *   parse of the query string can hold a parameter that the signature does not cover.
   */
  // eslint-disable-next-line @typescript-eslint/unified-signatures -- see the note above
  validateRedirectAsync(
    container: ParsedQs,
    originalQuery: string,
  ): Promise<{ profile: Profile | null; loggedOut: boolean; logoutReport?: LogoutReport }>;
  async validateRedirectAsync(
    ...args: [originalQuery: string] | [container: ParsedQs, originalQuery: string]
  ): Promise<{
    profile: Profile | null;
    loggedOut: boolean;
    relayState?: string | undefined;
    logoutReport?: LogoutReport;
  }> {
    const [originalQueryOrContainer, legacyOriginalQuery] = args;
    const { container, originalQuery, parameters, legacy } = resolveRedirectArguments(
      originalQueryOrContainer,
      legacyOriginalQuery,
    );
    const { samlMessageType, samlMessage, signed } = parameters;

    const data = Buffer.from(samlMessage, "base64");
    const inflated = await inflateRawAsync(data);
    let logoutReport: LogoutReport | null = null;

    const dom = await parseDomFromString(inflated.toString());
    const doc: XMLOutput = await parseXml2JsFromString(inflated);
    let logoutEvidence: LogoutReport | null = null;
    if (samlMessageType === "SAMLResponse") {
      const candidate = doc.LogoutResponse?.$?.InResponseTo;
      if (typeof candidate === "string") {
        try {
          logoutEvidence = await this.readStoredLogoutReportAsync(candidate);
        } catch {
          logoutEvidence = null;
        }
      }
    }
    // Before the checks below, so a signed response that fails them still retires its request.
    try {
      await this.hasValidSignatureForRedirect(container, originalQuery);
    } catch (err) {
      if (logoutEvidence != null) {
        attachLogoutReport(err, logoutReportWithFailure(logoutEvidence, err, "response-signature"));
      }
      throw err;
    }
    if (samlMessageType === "SAMLRequest") {
      this.verifyLogoutRequest(doc);
    } else {
      // Retired here, not in the overridable processing method, so an override can't lose track of
      // whether the message was signed. An unsigned one can name anyone's pending request.
      const signedInResponseTo = signed ? doc.LogoutResponse.$.InResponseTo : null;
      const retire = signedInResponseTo != null && this.mustValidateInResponseTo(true);
      try {
        await this.verifyLogoutResponse(doc);
      } catch (err) {
        await this.recordLogoutResponseAsync(signedInResponseTo, "failure", err);
        if (retire) {
          await this.cacheProvider.removeAsync(signedInResponseTo);
        }
        throw err;
      }
      if (retire) {
        try {
          await consumeInResponseToAsync(this.cacheProvider, signedInResponseTo);
        } catch (err) {
          await this.recordLogoutResponseAsync(signedInResponseTo, "replay", err);
          throw err;
        }
      }
      if (signedInResponseTo != null) {
        logoutReport = await this.recordLogoutResponseAsync(signedInResponseTo, "success");
      }
    }
    const result = await this.processValidlySignedSamlLogoutAsync(doc, dom);
    if (signed) {
      const messageName = samlMessageType === "SAMLRequest" ? "LogoutRequest" : "LogoutResponse";
      warnIfDestinationIsNot(
        "logoutCallbackUrl",
        this.options.logoutCallbackUrl,
        messageName,
        getRootAttribute(dom, "Destination"),
      );
    }
    return legacy
      ? withLogoutReport(result, logoutReport)
      : withLogoutReport({ ...result, relayState: parameters.relayState }, logoutReport);
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected async hasValidSignatureForRedirect(
    container: ParsedQs,
    originalQuery: string,
  ): Promise<boolean | void> {
    // A parse can lose a Signature that the query string has, and one can be present and empty.
    // Either way the message claims a signature.
    if (container.Signature != null || queryParameterNames(originalQuery).includes("Signature")) {
      const { signed } = readRedirectParameters(originalQuery);
      if (!signed) {
        throw new Error("The query string has no Signature parameter");
      }

      const pemFiles = await this.getKeyInfosAsPem();
      const hasValidQuerySignature = pemFiles.some((pemFile) => {
        return this.validateSignatureForRedirect(
          signed.octets,
          signed.signature,
          signed.sigAlg,
          pemFile,
        );
      });
      if (!hasValidQuerySignature) {
        throw new Error("Invalid query signature");
      }
    } else {
      // Nothing here is authenticated: the issuer and the timestamps come from the same bytes
      // an attacker supplies. Accepted for compatibility until a future major version rejects it.
      debugLog(
        "Processing a %s over the Redirect binding with no Signature parameter. Its contents are unverified. Configure the identity provider to sign logout messages; a future major version will reject unsigned ones.",
        container.SAMLRequest ? "SAMLRequest" : "SAMLResponse",
      );
      return true;
    }
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected validateSignatureForRedirect(
    urlString: crypto.BinaryLike,
    signature: string,
    alg: string,
    pemFile: string,
  ): boolean {
    // xml-crypto types the signed octets as a string, which is what this library passes.
    const signatureAlgorithm = algorithms.findSignatureAlgorithm(alg);
    if (signatureAlgorithm && typeof urlString === "string") {
      return signatureAlgorithm.verifySignature(urlString, pemFile, signature);
    }

    // An identifier xml-crypto does not implement, such as rsa-sha384, is looked up among
    // OpenSSL's digest names, case-insensitive.
    function hasMatch(ourAlgo: string) {
      // The incoming algorithm is forwarded as a URL.
      // We trim everything before the last # get something we can compare to the Node.js list
      const algFromURI = alg.toLowerCase().replace(/.*#(.*)$/, "$1");
      return ourAlgo.toLowerCase() === algFromURI;
    }
    const i = crypto.getHashes().findIndex(hasMatch);
    let matchingAlgo;
    if (i > -1) {
      matchingAlgo = crypto.getHashes()[i];
    } else {
      throw new Error(alg + " is not supported");
    }

    const verifier = crypto.createVerify(matchingAlgo);
    verifier.update(urlString);

    const verified = verifier.verify(pemFile, signature, "base64");
    // The next major version still verifies rsa-sha384, so it gets no warning.
    if (
      verified &&
      !signatureAlgorithm &&
      alg !== "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    ) {
      debugLog(
        "A Redirect-binding signature was verified under the `SigAlg` %s, which the next major version rejects. Configure the identity provider to sign with rsa-sha256, rsa-sha384 or rsa-sha512, and to name it by its XML Signature identifier, such as http://www.w3.org/2001/04/xmldsig-more#rsa-sha256.",
        alg,
      );
    }
    return verified;
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected verifyLogoutRequest(doc: XMLOutput): void {
    this.verifyIssuer(doc.LogoutRequest);
    const nowMs = new Date().getTime();
    const conditions = doc.LogoutRequest.$;
    const conErr = this.checkTimestampsValidityError(
      nowMs,
      conditions.NotBefore,
      conditions.NotOnOrAfter,
    );
    if (conErr) {
      throw conErr;
    }
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected async verifyLogoutResponse(doc: XMLOutput): Promise<void> {
    const statusCode = doc.LogoutResponse.Status?.[0].StatusCode?.[0].$?.Value;
    if (statusCode !== "urn:oasis:names:tc:SAML:2.0:status:Success")
      throw new Error("Bad status code: " + statusCode);

    this.verifyIssuer(doc.LogoutResponse);
    return this.validateInResponseTo(doc.LogoutResponse.$.InResponseTo ?? null);
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected verifyIssuer(samlMessage: XMLOutput): void {
    assertOneIssuer((samlMessage.Issuer ?? []).map((issuer: XMLOutput) => issuer._));
    if (this.options.idpIssuer != null) {
      const issuer = samlMessage.Issuer;
      if (issuer) {
        if (issuer[0]._ !== this.options.idpIssuer)
          throw new Error(
            "Unknown SAML issuer. Expected: " +
              this.options.idpIssuer +
              " Received: " +
              issuer[0]._,
          );
      } else {
        throw new Error("Missing SAML issuer");
      }
    }
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected async processValidlySignedAssertionAsync(
    this: SAML,
    xml: string, // assertion XML
    samlResponseXml: string, // the response as received, not as verified; backs getSamlResponseXml()
    inResponseTo: string | null,
    inResponseToIsVerified = false, // whether a verified Response signature covers inResponseTo
  ): Promise<{ profile: Profile; loggedOut: boolean }> {
    let msg;
    const nowMs = new Date().getTime();
    const profile = {} as Profile;
    let confirmationMethods: string[] = [];
    let timelyBearerRecipients: (string | undefined)[] = [];
    const doc: XMLOutput = await parseXml2JsFromString(xml);
    const parsedAssertion: XMLOutput = doc;
    const assertion: XMLOutput = doc.Assertion;
    this.verifyIssuer(assertion);
    getInResponseTo: {
      const issuer = assertion.Issuer;
      if (issuer && issuer[0]._) {
        profile.issuer = issuer[0]._;
      }

      const authnStatement = assertion.AuthnStatement;
      if (authnStatement) {
        if (authnStatement[0].$ && authnStatement[0].$.SessionIndex) {
          profile.sessionIndex = authnStatement[0].$.SessionIndex;
        }
      }

      const subject = assertion.Subject;
      let subjectConfirmation: XMLOutput | null | undefined;
      let confirmData: XMLOutput | null = null;
      let subjectConfirmations: XMLOutput[] | null = null;
      if (subject) {
        const nameID = subject[0].NameID;
        if (nameID && nameID[0]._) {
          profile.nameID = nameID[0]._;

          if (nameID[0].$ && nameID[0].$.Format) {
            profile.nameIDFormat = nameID[0].$.Format;
            profile.nameQualifier = nameID[0].$.NameQualifier;
            profile.spNameQualifier = nameID[0].$.SPNameQualifier;
          }
        }
        subjectConfirmations = subject[0].SubjectConfirmation;
        const isTimely = (_subjectConfirmation: XMLOutput) => {
          const _confirmData = _subjectConfirmation.SubjectConfirmationData?.[0];
          if (_confirmData?.$) {
            const subjectNotBefore = _confirmData.$.NotBefore;
            const subjectNotOnOrAfter = _confirmData.$.NotOnOrAfter;
            const maxTimeLimitMs = this.calcMaxAgeAssertionTime(
              this.options.maxAssertionAgeMs,
              subjectNotOnOrAfter,
              assertion.$.IssueInstant,
            );

            const subjErr = this.checkTimestampsValidityError(
              nowMs,
              subjectNotBefore,
              subjectNotOnOrAfter,
              maxTimeLimitMs,
            );
            if (subjErr === null) return true;
          }

          return false;
        };
        // Without a signed Response, only a SubjectConfirmationData can tie the assertion to a
        // request, and verifying any one confirmation is enough (SAML Core §2.4.1).
        if (!inResponseToIsVerified) {
          subjectConfirmation = subjectConfirmations?.find(
            (sc) => sc.SubjectConfirmationData?.[0].$?.InResponseTo != null && isTimely(sc),
          );
        }
        subjectConfirmation ??= subjectConfirmations?.find(isTimely);
        // For the warning only, which must not change the outcome: selection above stops at the
        // first match, so a later confirmation's timestamps may be malformed and throw here.
        const isTimelyForWarning = (_subjectConfirmation: XMLOutput) => {
          try {
            return isTimely(_subjectConfirmation);
          } catch {
            return false;
          }
        };
        confirmationMethods = (subjectConfirmations ?? []).map(
          (sc) => sc.$?.Method ?? "a SubjectConfirmation with no Method",
        );
        timelyBearerRecipients = (subjectConfirmations ?? [])
          .filter(
            (sc) =>
              sc.$?.Method === "urn:oasis:names:tc:SAML:2.0:cm:bearer" && isTimelyForWarning(sc),
          )
          .map((sc) => sc.SubjectConfirmationData[0].$.Recipient);

        if (subjectConfirmation != null) {
          confirmData = subjectConfirmation.SubjectConfirmationData[0];
        }
      }

      // The confirmation window bounds delivery of the assertion whether or not InResponseTo is
      // validated (SAML Profiles §4.1.4.3).
      if (subjectConfirmations != null && subjectConfirmation == null) {
        throw new Error(
          "No valid subject confirmation found among those available in the SAML assertion",
        );
      }

      const verifiedInResponseTo = inResponseToIsVerified
        ? inResponseTo
        : confirmData?.$?.InResponseTo;
      if (verifiedInResponseTo != null) {
        profile.inResponseTo = verifiedInResponseTo;
      }

      /**
       * Test to see that if we have a SubjectConfirmation InResponseTo that it matches
       * the 'InResponseTo' attribute set in the Response
       */
      if (this.mustValidateInResponseTo(Boolean(inResponseTo))) {
        if (subjectConfirmation) {
          if (confirmData?.$) {
            const subjectInResponseTo = confirmData.$.InResponseTo;

            if (inResponseTo && subjectInResponseTo && subjectInResponseTo != inResponseTo) {
              throw new Error("InResponseTo does not match subjectInResponseTo");
            } else if (subjectInResponseTo) {
              let foundValidInResponseTo = false;
              const result = await this.cacheProvider.getAsync(subjectInResponseTo);
              if (result) {
                const createdAt = new Date(result);
                if (nowMs < createdAt.getTime() + this.options.requestIdExpirationPeriodMs)
                  foundValidInResponseTo = true;
              }
              if (!foundValidInResponseTo) {
                throw new Error("SubjectInResponseTo is not valid");
              }
              break getInResponseTo;
            }
          }
          assertResponseInResponseToCanAnswer(
            this.options.validateInResponseTo,
            inResponseToIsVerified,
          );
          break getInResponseTo;
        } else {
          assertResponseInResponseToCanAnswer(
            this.options.validateInResponseTo,
            inResponseToIsVerified,
          );
          break getInResponseTo;
        }
      } else {
        break getInResponseTo;
      }
    }
    const conditions = assertion.Conditions ? assertion.Conditions[0] : null;
    if (assertion.Conditions && assertion.Conditions.length > 1) {
      msg = "Unable to process multiple conditions in SAML assertion";
      throw new Error(msg);
    }
    if (conditions && conditions.$) {
      const maxTimeLimitMs = this.calcMaxAgeAssertionTime(
        this.options.maxAssertionAgeMs,
        conditions.$.NotOnOrAfter,
        assertion.$.IssueInstant,
      );
      const conErr = this.checkTimestampsValidityError(
        nowMs,
        conditions.$.NotBefore,
        conditions.$.NotOnOrAfter,
        maxTimeLimitMs,
      );
      if (conErr) throw conErr;
    }

    if (this.options.audience !== false) {
      const audienceErr = this.checkAudienceValidityError(
        this.options.audience,
        conditions.AudienceRestriction,
      );
      if (audienceErr) throw audienceErr;
    }

    const attributeStatement = assertion.AttributeStatement;
    if (attributeStatement) {
      const attributes: { statement: XMLOutput; attribute: XMLOutput }[] = [].concat(
        ...attributeStatement
          .filter((statement: XMLOutput) => Array.isArray(statement.Attribute))
          .map((statement: XMLOutput) =>
            statement.Attribute.map((attribute: XMLOutput) => ({ statement, attribute })),
          ),
      );

      const attrValueMapper = (value: XMLObject) => {
        const hasChildren = Object.keys(value).some((cur) => {
          return cur !== "_" && cur !== "$";
        });
        return hasChildren ? value : value._;
      };

      if (attributes.length > 0) {
        const profileAttributes: Record<string, XMLValue | XMLValue[]> = {};

        attributes.forEach(({ statement, attribute }) => {
          if (!Object.prototype.hasOwnProperty.call(attribute, "AttributeValue")) {
            if (attribute.$?.Name != null) {
              debugLog(
                'The SAML attribute "%s" has no AttributeValue, so it is left out of the profile and cannot be told apart from an attribute the identity provider did not send. The next major version keeps it with a null value. Code that tests the attribute with `== null`, which is true of both `undefined` and null, works with both versions.',
                attribute.$.Name,
              );
            }
            return;
          }

          const name: string = attribute.$.Name;
          const value: XMLValue | XMLValue[] =
            attribute.AttributeValue.length === 1
              ? attrValueMapper(attribute.AttributeValue[0])
              : attribute.AttributeValue.map(attrValueMapper);

          // An empty AttributeValue is the empty string, or null when it carries xsi:nil: SAML
          // Core 2.7.3.1.1, https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
          const unset = attribute.AttributeValue.filter(
            (one: XMLOutput) => attrValueMapper(one) === undefined,
          );
          const nulls = unset.filter((one: XMLOutput) =>
            isXsiNil(one, [assertion, statement, attribute]),
          );
          if (nulls.length > 0) {
            debugLog(
              'The SAML attribute "%s" has an AttributeValue marked xsi:nil, which reaches the profile as `undefined`. The next major version represents it as null. Code that tests each value with `== null`, which is true of both `undefined` and null, works with both versions.',
              name,
            );
          }
          if (unset.length > nulls.length) {
            debugLog(
              'The SAML attribute "%s" has an empty AttributeValue, which reaches the profile as `undefined`. The next major version represents it as an empty string. Code that reads each value with `?? ""`, which turns `undefined` into an empty string, works with both versions.',
              name,
            );
          }

          profileAttributes[name] = value;

          /**
           * If any property is already present in profile and is also present
           * in attributes, then skip the one from attributes. Handle this
           * conflict gracefully without returning any error
           */
          if (Object.prototype.hasOwnProperty.call(profile, name)) {
            return;
          }

          profile[name] = value;
        });

        profile.attributes = profileAttributes;
      }
    }

    if (!profile.mail && profile["urn:oid:0.9.2342.19200300.100.1.3"]) {
      /**
       * See https://spaces.internet2.edu/display/InCFederation/Supported+Attribute+Summary
       * for definition of attribute OIDs
       */
      profile.mail = profile["urn:oid:0.9.2342.19200300.100.1.3"];
    }

    if (!profile.email && profile.mail) {
      profile.email = profile.mail;
    }

    profile.getAssertionXml = () => xml.toString();
    profile.getAssertion = () => parsedAssertion;
    profile.getSamlResponseXml = () => {
      debugLog(
        "Profile.getSamlResponseXml() returns the SAML response as received, which may include material no signature covered, and does not say which part was verified. Don't treat what it returns as authenticated; use getAssertionXml() or getAssertion() for the verified assertion. This accessor is removed in the next major version.",
      );
      return samlResponseXml;
    };

    warnIfNoBearerConfirmationNames(
      this.options.callbackUrl,
      confirmationMethods,
      timelyBearerRecipients,
    );
    return { profile, loggedOut: false };
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected checkTimestampsValidityError(
    nowMs: number,
    notBefore: string,
    notOnOrAfter: string,
    maxTimeLimitMs?: number,
  ): Error | null {
    if (this.options.acceptedClockSkewMs == -1) return null;

    if (notBefore) {
      const notBeforeMs = dateStringToTimestamp(notBefore, "NotBefore");
      if (nowMs + this.options.acceptedClockSkewMs < notBeforeMs)
        return new Error("SAML assertion not yet valid");
    }
    if (notOnOrAfter) {
      const notOnOrAfterMs = dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter");
      if (nowMs - this.options.acceptedClockSkewMs >= notOnOrAfterMs)
        return new Error("SAML assertion expired: clocks skewed too much");
    }
    if (maxTimeLimitMs != null) {
      if (nowMs - this.options.acceptedClockSkewMs >= maxTimeLimitMs)
        return new Error("SAML assertion expired: assertion too old");
    }

    return null;
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected checkAudienceValidityError(
    expectedAudience: string,
    audienceRestrictions: AudienceRestrictionXML[],
  ): Error | null {
    if (!audienceRestrictions || audienceRestrictions.length < 1) {
      return new Error("SAML assertion has no AudienceRestriction");
    }
    const errors = audienceRestrictions
      .map((restriction) => {
        if (!restriction.Audience || !restriction.Audience[0] || !restriction.Audience[0]._) {
          return new Error("SAML assertion AudienceRestriction has no Audience value");
        }
        if (restriction.Audience.every((audience) => audience._ !== expectedAudience)) {
          return new Error(
            "SAML assertion audience mismatch. Expected: " +
              expectedAudience +
              " Received: " +
              restriction.Audience.map((audience) => audience._).join(", "),
          );
        }
        return null;
      })
      .filter((result) => {
        return result !== null;
      });
    if (errors.length > 0) {
      return errors[0];
    }
    return null;
  }

  // The v5.1 parameter shape kept verbatim, `| undefined` included, and never read.
  // `typeSurface.spec.ts` pins the call and override forms it has to keep accepting.
  async validatePostRequestAsync(
    container: Record<string, string>,
    legacyInjectedDependencies?: {
      _parseDomFromString?: ((xml: string) => Promise<Document>) | undefined;
      _parseXml2JsFromString?: ((xml: string | Buffer) => Promise<XmlJsObject>) | undefined;
      _validateSignature?:
        ((fullXml: string, currentNode: Element, pemFiles: string[]) => boolean) | undefined;
    },
  ): Promise<{ profile: Profile; loggedOut: boolean }> {
    warnIgnoredInjectedDependencies(legacyInjectedDependencies);
    const xml = Buffer.from(container.SAMLRequest, "base64").toString("utf8");
    // The document as received locates the signature; only what that signature covers is read.
    const receivedDom = await parseDomFromString(xml);
    const pemFiles = await this.getKeyInfosAsPem();
    const verifiedXml = getVerifiedXml(xml, receivedDom.documentElement, pemFiles);
    if (verifiedXml == null) {
      throw new Error("Invalid signature on documentElement");
    }
    const verifiedDom = await parseDomFromString(verifiedXml);
    const verifiedDoc = await parseXml2JsFromString(verifiedXml);
    const result = await this.processValidlySignedPostRequestAsync(verifiedDoc, verifiedDom);
    warnIfDestinationIsNot(
      "logoutCallbackUrl",
      this.options.logoutCallbackUrl,
      "LogoutRequest",
      getRootAttribute(verifiedDom, "Destination"),
    );
    return result;
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected async processValidlySignedPostRequestAsync(
    this: SAML,
    doc: XMLOutput,
    dom: Document,
  ): Promise<{ profile: Profile; loggedOut: boolean }> {
    const request = doc.LogoutRequest;
    this.verifyLogoutRequest(doc);
    if (request) {
      const profile = {} as Profile;
      if (request.$.ID) {
        profile.ID = request.$.ID;
      } else {
        throw new Error("Missing SAML LogoutRequest ID");
      }
      const issuer = request.Issuer;
      if (issuer && issuer[0]._) {
        profile.issuer = issuer[0]._;
      } else {
        throw new Error("Missing SAML issuer");
      }
      const nameID = await getNameIdAsync(dom, this.options.decryptionPvk ?? null);
      if (nameID.value) {
        profile.nameID = nameID.value;
        if (nameID.format) {
          profile.nameIDFormat = nameID.format;
        }
      } else {
        throw new Error("Missing SAML NameID");
      }
      const sessionIndex = request.SessionIndex;
      if (sessionIndex) {
        profile.sessionIndex = sessionIndex[0]._;
      }
      return { profile, loggedOut: true };
    } else {
      throw new Error("Unknown SAML request message");
    }
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected async processValidlySignedSamlLogoutAsync(
    this: SAML,
    doc: XMLOutput,
    dom: Document,
  ): Promise<{ profile: Profile | null; loggedOut: boolean }> {
    const response = doc.LogoutResponse;
    const request = doc.LogoutRequest;

    if (response) {
      return { profile: null, loggedOut: true };
    } else if (request) {
      return await this.processValidlySignedPostRequestAsync(doc, dom);
    } else {
      throw new Error("Unknown SAML response message");
    }
  }

  generateServiceProviderMetadata(
    this: SAML,
    decryptionCert: string | null,
    publicCerts?: string | string[] | null,
  ): string {
    return buildServiceProviderMetadata({ ...this.options, decryptionCert, publicCerts });
  }

  /**
   * Process max age assertion and use it if it is more restrictive than the NotOnOrAfter age
   * assertion received in the SAMLResponse.
   *
   * @param maxAssertionAgeMs Max time after IssueInstant that we will accept assertion, in Ms.
   * @param notOnOrAfter Expiration provided in response.
   * @param issueInstant Time when response was issued.
   * @returns {*} The expiration time to be used, in Ms.
   *
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected calcMaxAgeAssertionTime(
    maxAssertionAgeMs: number,
    notOnOrAfter: string,
    issueInstant: string,
  ): number {
    const notOnOrAfterMs = dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter");
    const issueInstantMs = dateStringToTimestamp(issueInstant, "IssueInstant");

    if (maxAssertionAgeMs === 0) {
      return notOnOrAfterMs;
    }

    const maxAssertionTimeMs = issueInstantMs + maxAssertionAgeMs;
    return maxAssertionTimeMs < notOnOrAfterMs ? maxAssertionTimeMs : notOnOrAfterMs;
  }

  /**
   * @deprecated Check what `validatePostResponseAsync`, `validatePostRequestAsync` or
   *   `validateRedirectAsync` returns instead of overriding this: an override can weaken the
   *   validation of an incoming message, so the next major version makes this method private.
   */
  protected mustValidateInResponseTo(hasInResponseTo: boolean): boolean {
    return (
      this.options.validateInResponseTo === ValidateInResponseTo.always ||
      (this.options.validateInResponseTo === ValidateInResponseTo.ifPresent && hasInResponseTo)
    );
  }
}

export { SAML };
