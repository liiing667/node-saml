export type SignatureAlgorithm = "sha1" | "sha256" | "sha256-mgf1" | "sha512";

export type PemLabel = "CERTIFICATE" | "PUBLIC KEY" | "PRIVATE KEY" | "RSA PRIVATE KEY";

export interface SamlSigningOptions {
  privateKey: string | Buffer;
  publicCert?: string;
  signatureAlgorithm?: SignatureAlgorithm;
  xmlSignatureTransforms?: string[];
  digestAlgorithm?: string;
}

export interface AuthOptions {
  samlFallback?: "login-request" | "logout-request";
  additionalParams?: Record<string, string | string[]>;
}

export const isValidSamlSigningOptions = (
  options: Partial<SamlSigningOptions>,
): options is SamlSigningOptions => {
  return options.privateKey != null;
};

export interface AudienceRestrictionXML {
  Audience?: XMLObject[];
}
export interface CacheItem {
  value: string;
  createdAt: number;
}

export interface CacheProvider {
  saveAsync(key: string, value: string): Promise<CacheItem | null>;
  getAsync(key: string): Promise<string | null>;
  removeAsync(key: string | null): Promise<string | null>;
  /**
   * Removes `key` and returns its value, or `null` if it was absent, as one atomic operation.
   * When present, it is used to consume request IDs, so that of two concurrent copies of a
   * response only one is accepted.
   */
  consumeAsync?(key: string): Promise<string | null>;
  /**
   * Saves `value` under `key` unless `key` is already present, as one atomic operation, and keeps it
   * until `expiresAtMs`. Resolves `true` if it saved the key and `false` if the key was present.
   * `rejectReplayedAssertions` requires it, and uses it to remember the ID of each assertion
   * received, so that of two concurrent copies of an assertion only one is accepted.
   */
  saveIfAbsentAsync?(key: string, value: string, expiresAtMs: number): Promise<boolean>;
}

export type XMLValue = string | number | boolean | null | XMLObject | XMLValue[];

export type XMLObject = {
  [key: string]: XMLValue;
};

export type XMLInput = XMLObject;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type XMLOutput = Record<string, any>;

export type AuthorizeRequestXML = {
  "samlp:AuthnRequest": XMLInput;
};

export type XmlJsObject = {
  [key: string]: string | XmlJsObject | XmlJsObject[] | undefined;
  $?: { Value: string };
  _?: string;
};

export type SamlResponseXmlJs = XmlJsObject & {
  Response?: SamlAssertionXmlJs | SamlStatusXmlJs;
  LogoutResponse?: unknown;
};

export type SamlRequestXmlJs = {
  Request: unknown;
};

export type SamlAssertionXmlJs = {
  Assertion: unknown;
};

export type SamlStatusXmlJs = {
  Status: [
    { StatusCode: [XmlJsObject & { StatusCode: [XmlJsObject] }]; StatusMessage: [XmlJsObject] },
  ];
};

export type IdpCertCallback = (
  callback: (err: Error | null, publicCert?: string | string[]) => void,
) => void;

/**
 * A private key used to decrypt encrypted assertions and encrypted name identifiers.
 */
export type DecryptionPvk = string | Buffer;

/**
 * Supplies decryption private keys for one validation. Resolved once per message, so a key
 * rotation that happens while the message is being validated cannot change the key used for it.
 */
export type DecryptionPvkCallback = (
  callback: (err: Error | null, privateKey?: DecryptionPvk | DecryptionPvk[]) => void,
) => void;

/**
 * A decryption key, a rotation window of several keys, or a callback that supplies either.
 */
export type DecryptionPvkOption =
  | DecryptionPvk
  | DecryptionPvk[]
  | DecryptionPvkCallback
  | (() => DecryptionPvk | DecryptionPvk[] | Promise<DecryptionPvk | DecryptionPvk[]>);

/**
 * The point at which an encrypted response was accepted or rejected.
 */
export type EncryptedResponseStage =
  | "admission"
  | "decrypt"
  | "decrypted"
  | "verify-signature"
  | "profile"
  | "complete";

/**
 * The identities that authenticate one encrypted response: the ciphertext, the relying party's
 * decryption key, the assertion it holds, and the stage that accepted or rejected it.
 */
export interface EncryptedResponseReport {
  /** The EncryptedAssertion element as received, before any decryption. */
  cipher: string;
  /** Alias for `cipher`. */
  cipherText: string;
  /** A stable digest of `cipher`. */
  cipherDigest: string;
  /** Alias for `cipherDigest`. */
  ciphertextDigest: string;
  /** The EncryptedAssertion element's XML ID, when it has one. */
  encryptedAssertionId: string | null;
  /** All keys this validation was allowed to use, by public-key fingerprint. */
  decryptionKeys: string[];
  /** Generation identity of the complete key set frozen for this validation. */
  decryptionKeyGeneration: string | null;
  /** Alias for `decryptionKeyGeneration`. */
  decryptKeyGeneration: string | null;
  /** Fingerprint of the key that decrypted the ciphertext, when one did. */
  decryptKey: string | null;
  /** Alias for `decryptKey`. */
  decryptionKey: string | null;
  /** Alias for `decryptKey`. */
  decryptKeyFingerprint: string | null;
  /** Alias for `decryptKey`. */
  decryptionKeyFingerprint: string | null;
  /**
   * The decrypted assertion XML after a signature covered the ciphertext or the assertion. Null on
   * a rejection, where only `assertionId` and `assertionDigest` are reported.
   */
  assertion: string | null;
  /** The decrypted assertion's XML ID, when it has one. */
  assertionId: string | null;
  /** A stable digest of `assertion`. */
  assertionDigest: string | null;
  /** Whether decryption produced an assertion. */
  decrypted: boolean;
  /** Whether a signature covered the ciphertext or the decrypted assertion. */
  signatureVerified: boolean;
  /** The stage reached by this validation. */
  stage: EncryptedResponseStage;
  /** Alias for `stage`. */
  validationStage: EncryptedResponseStage;
  /** The stage that rejected the message, or null while it has not been rejected. */
  failureStage: EncryptedResponseStage | null;
}

/**
 * These are SAML options that must be provided to construct a new SAML Strategy
 */
export interface MandatorySamlOptions {
  idpCert: string | string[] | IdpCertCallback;
  issuer: string;
  callbackUrl: string;
}

export interface SamlIDPListConfig {
  entries: SamlIDPEntryConfig[];
  getComplete?: string;
}

export interface SamlIDPEntryConfig {
  providerId: string;
  name?: string;
  loc?: string;
}

export type LogoutRequestXML = {
  "samlp:LogoutRequest": {
    "saml:NameID": XMLInput;
    [key: string]: XMLValue;
  };
};

export type ServiceMetadataXML = {
  EntityDescriptor: {
    [key: string]: XMLValue;
    SPSSODescriptor: XMLObject;
  };
};

export interface NameID {
  value: string | null;
  format: string | null;
}

export interface XmlSignatureLocation {
  reference: string;
  action: "append" | "prepend" | "before" | "after";
}

export type RacComparison = "exact" | "minimum" | "maximum" | "better";

export interface SamlScopingConfig {
  idpList?: SamlIDPListConfig[];
  proxyCount?: number;
  requesterId?: string[] | string;
}

export enum ValidateInResponseTo {
  never = "never",
  ifPresent = "ifPresent",
  always = "always",
}

/**
 * Describes an AttributeConsumingService element in the SAML metadata.
 * Used by service providers to specify required attributes.
 *
 * @see {@link https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf SAML 2.0 Metadata Specification, Section 2.4.4}
 *
 * @example
 * ```typescript
 * const attributeConsumingService: AttributeConsumingService = {
 *   "@index": "0",
 *   "@isDefault": true,
 *   ServiceName: [{
 *     "@xml:lang": "en",
 *     "#text": "Employee Portal"
 *   }],
 *   ServiceDescription: [{
 *     "@xml:lang": "en",
 *     "#text": "Authentication service for employee portal access"
 *   }],
 *   RequestedAttribute: [
 *     {
 *       "@Name": "urn:oid:2.5.4.42",
 *       "@NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
 *       "@FriendlyName": "givenName",
 *       "@isRequired": true
 *     },
 *     {
 *       "@Name": "urn:oid:2.5.4.4",
 *       "@NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
 *       "@FriendlyName": "sn",
 *       "@isRequired": true
 *     },
 *     {
 *       "@Name": "urn:oid:0.9.2342.19200300.100.1.3",
 *       "@NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
 *       "@FriendlyName": "mail",
 *       "@isRequired": false
 *     }
 *   ]
 * };
 * ```
 */
export interface AttributeConsumingService {
  /**
   * Index for the service within the SP metadata, as a string of digits from
   * "0" to "65535". No two services may use the same index.
   * @example "0", "1", "2"
   */
  "@index": string;

  /**
   * Marks this service as the default for the SP. At most one service may set
   * this to `true`. Leaving it out is not the same as `false`: when no service
   * is `true`, the default is the first one that is not `false`; if all are
   * `false`, the first service is the default.
   * @see {@link https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html SAML 2.0 Approved Errata, E87}
   */
  "@isDefault"?: boolean;

  /**
   * Names of the service in multiple languages.
   * At least one ServiceName is required.
   */
  ServiceName: {
    /**
     * Language tag identifying the language of the text, as defined by BCP 47.
     * Rejected unless it has the form `xs:language` allows, which every BCP 47
     * tag does.
     * @see {@link https://www.rfc-editor.org/info/bcp47 BCP 47}
     * @example "en", "en-GB", "es", "de", "zh-Hant"
     */
    "@xml:lang": string;

    /**
     * The actual service name text
     * @example "My Authentication Service", "Employee Portal"
     */
    "#text": string;
  }[];

  /**
   * Descriptions of the service in multiple languages.
   * Optional but recommended for better user experience.
   */
  ServiceDescription?: {
    /**
     * Language tag identifying the language of the text, as defined by BCP 47.
     * Rejected unless it has the form `xs:language` allows, which every BCP 47
     * tag does.
     * @see {@link https://www.rfc-editor.org/info/bcp47 BCP 47}
     * @example "en", "en-GB", "es", "de", "zh-Hant"
     */
    "@xml:lang": string;

    /**
     * The actual service description text
     * @example "This service provides authentication for the employee portal"
     */
    "#text": string;
  }[];

  /**
   * Attributes requested by the service, with specifications
   */
  RequestedAttribute: {
    /**
     * Name of the requested attribute, typically an OID or URI.
     * @example "urn:oid:2.5.4.42", "urn:oid:0.9.2342.19200300.100.1.3"
     */
    "@Name": string;

    /**
     * Format of the attribute name. SAML 2.0 Core, section 8.2 defines the
     * three listed here; any other absolute URI is permitted. A value that is
     * not an absolute URI, such as `"uri"`, is rejected.
     *
     * Omitting this emits no `NameFormat` attribute, which SAML 2.0 Core,
     * section 2.7.3.1 states is equivalent to
     * `urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified`. Nothing is
     * substituted on your behalf. Set this explicitly to
     * `urn:oasis:names:tc:SAML:2.0:attrname-format:uri` when the attribute is
     * named by an OID or URI, as the examples here do: an identity provider
     * that distinguishes the formats will not match a URI-named attribute
     * against an unspecified request.
     */
    "@NameFormat"?:
      | "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
      | "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
      | "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
      | (string & {});

    /**
     * Human-readable name of the attribute
     * @example "givenName", "sn", "emailAddress", "mail"
     */
    "@FriendlyName"?: string;

    /**
     * Indicates if the attribute is required for the service to function
     * @default false
     */
    "@isRequired"?: boolean;
  }[];
}

/**
 * The options required to use a SAML strategy
 * These may be provided by means of defaults specified in the constructor
 */
export interface SamlOptions extends Partial<SamlSigningOptions>, MandatorySamlOptions {
  // Core
  entryPoint?: string;
  decryptionPvk?: DecryptionPvkOption;

  // Additional SAML behaviors
  additionalParams: Record<string, string>;
  additionalAuthorizeParams: Record<string, string>;
  identifierFormat: string | null;
  allowCreate: boolean;
  spNameQualifier?: string | null;
  acceptedClockSkewMs: number;
  attributeConsumingServiceIndex?: string;
  disableRequestedAuthnContext: boolean;
  authnContext: string[];
  forceAuthn: boolean;
  skipRequestCompression: boolean;
  authnRequestBinding?: string;
  racComparison: RacComparison;
  providerName?: string;
  passive: boolean;
  idpIssuer?: string;
  audience: string | false;
  scoping?: SamlScopingConfig;
  wantAssertionsSigned: boolean;
  wantAuthnResponseSigned: boolean;
  maxAssertionAgeMs: number;
  rejectReplayedAssertions?: boolean;
  generateUniqueId: () => string;
  signMetadata: boolean;

  // InResponseTo Validation
  validateInResponseTo: ValidateInResponseTo;
  requestIdExpirationPeriodMs: number;
  cacheProvider: CacheProvider;

  // Logout
  logoutUrl: string;
  additionalLogoutParams: Record<string, string>;
  logoutCallbackUrl?: string;

  // extras
  disableRequestAcsUrl: boolean;
  samlAuthnRequestExtensions?: Record<string, unknown>;
  samlLogoutRequestExtensions?: Record<string, unknown>;

  /**
   * Attribute consuming services to include in the metadata.
   * These describe the attributes that the service provider wishes to receive.
   *
   * @example
   * ```typescript
   * metadataAttributeConsumingServices: [{
   *   "@index": "0",
   *   "@isDefault": true,
   *   ServiceName: [{
   *     "@xml:lang": "en",
   *     "#text": "My Service"
   *   }],
   *   RequestedAttribute: [{
   *     "@Name": "urn:oid:2.5.4.42",
   *     "@NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
   *     "@FriendlyName": "givenName",
   *     "@isRequired": true
   *   }]
   * }]
   * ```
   */
  metadataAttributeConsumingServices?: AttributeConsumingService[];
  metadataContactPerson?: {
    "@contactType": "technical" | "support" | "administrative" | "billing" | "other";
    /**
     * Extension elements, as an [xmlbuilder](https://www.npmjs.com/package/xmlbuilder) object.
     * Each must be qualified by a namespace that SAML does not define. A string cannot produce
     * valid metadata; the type accepts one only until the next major version.
     */
    Extensions?: Record<string, unknown> | string;
    Company?: string;
    GivenName?: string;
    SurName?: string;
    /** `mailto:` URIs */
    EmailAddress?: string[];
    TelephoneNumber?: string[];
  }[];
  metadataOrganization?: {
    /**
     * Extension elements, as an [xmlbuilder](https://www.npmjs.com/package/xmlbuilder) object.
     * Each must be qualified by a namespace that SAML does not define.
     */
    Extensions?: Record<string, unknown>;
    OrganizationName: {
      "@xml:lang": string;
      "#text": string;
    }[];
    OrganizationDisplayName: {
      "@xml:lang": string;
      "#text": string;
    }[];
    OrganizationURL: {
      "@xml:lang": string;
      "#text": string;
    }[];
  };
}

export interface GenerateServiceProviderMetadataParams {
  decryptionCert?: string | null;
  publicCerts?: string | string[] | null;
  issuer: SamlOptions["issuer"];
  callbackUrl: SamlOptions["callbackUrl"];
  logoutCallbackUrl?: SamlOptions["logoutCallbackUrl"];
  identifierFormat?: SamlOptions["identifierFormat"];
  wantAssertionsSigned?: SamlOptions["wantAssertionsSigned"];
  decryptionPvk?: SamlOptions["decryptionPvk"];
  privateKey?: SamlOptions["privateKey"];
  signatureAlgorithm?: SamlOptions["signatureAlgorithm"];
  xmlSignatureTransforms?: SamlOptions["xmlSignatureTransforms"];
  digestAlgorithm?: SamlOptions["digestAlgorithm"];
  signMetadata?: SamlOptions["signMetadata"];
  metadataAttributeConsumingServices?: SamlOptions["metadataAttributeConsumingServices"];
  metadataContactPerson?: SamlOptions["metadataContactPerson"];
  metadataOrganization?: SamlOptions["metadataOrganization"];
  generateUniqueId?: SamlOptions["generateUniqueId"];
}

export type SamlConfig = Partial<SamlOptions> & MandatorySamlOptions;

export interface Profile {
  issuer: string;
  sessionIndex?: string;
  nameID: string;
  nameIDFormat: string;
  nameQualifier?: string;
  spNameQualifier?: string;
  ID?: string;
  mail?: string; // InCommon Attribute urn:oid:0.9.2342.19200300.100.1.3
  email?: string; // `mail` if not present in the assertion
  ["urn:oid:0.9.2342.19200300.100.1.3"]?: string;
  getAssertionXml?(): string; // get the assertion XML, taken from the verified content
  getAssertion?(): Record<string, unknown>; // get the verified assertion XML parsed as a JavaScript object
  /**
   * Returns the SAML response as received. It may contain material that was not covered by the
   * signature used to authenticate the assertion, and it does not say which part was. Do not
   * treat response-level data returned here as authenticated. Use `getAssertionXml()` or
   * `getAssertion()` for the verified assertion.
   *
   * @deprecated Returns the response as received, not as verified. Removed in the next major
   * version; use `getAssertionXml()` or `getAssertion()`.
   */
  getSamlResponseXml?(): string;
  /**
   * The ciphertext, decryption key, assertion and stage that authenticated this profile. Set only
   * for a response whose assertion arrived as an EncryptedAssertion.
   */
  encryptedResponse?: EncryptedResponseReport;
  /** Alias for `encryptedResponse`. */
  decryption?: EncryptedResponseReport;
  /** The EncryptedAssertion element as received. */
  cipher?: string;
  /** Alias for `cipher`. */
  cipherText?: string;
  /** A stable digest of `cipher`. */
  cipherDigest?: string;
  /** Alias for `cipherDigest`. */
  ciphertextDigest?: string;
  /** Fingerprint of the key that decrypted the ciphertext. */
  decryptKey?: string | null;
  /** Alias for `decryptKey`. */
  decryptionKey?: string | null;
  /** Alias for `decryptKey`. */
  decryptKeyFingerprint?: string | null;
  /** Alias for `decryptKey`. */
  decryptionKeyFingerprint?: string | null;
  /** Generation identity of the decryption key set frozen for this profile. */
  decryptionKeyGeneration?: string | null;
  /** Alias for `decryptionKeyGeneration`. */
  decryptKeyGeneration?: string | null;
  /** The verified decrypted assertion XML. */
  assertion?: string | null;
  /** The verified decrypted assertion's XML ID. */
  assertionId?: string | null;
  /** A stable digest of `assertion`. */
  assertionDigest?: string | null;
  /** Whether a signature covered the ciphertext or the decrypted assertion. */
  signatureVerified?: boolean;
  /** The stage that produced this profile. */
  validationStage?: EncryptedResponseStage;
  /** Alias for `validationStage`. */
  verificationStage?: EncryptedResponseStage;
  /** Alias for `validationStage`. */
  stage?: EncryptedResponseStage;
  [attributeName: string]: unknown; // arbitrary `AttributeValue`s
}

export class SamlStatusError extends Error {
  constructor(
    message: string,
    public readonly xmlStatus: string,
  ) {
    super(message);
  }
}
