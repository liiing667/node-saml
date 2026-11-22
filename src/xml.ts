import * as isDomNode from "@xmldom/is-dom-node";
import * as xmldom from "@xmldom/xmldom";
import * as util from "util";
import * as xmlCrypto from "xml-crypto";
import * as xmlenc from "xml-encryption";
import * as xml2js from "xml2js";
import * as xmlbuilder from "xmlbuilder";
import { select, SelectReturnType } from "xpath";
import * as algorithms from "./algorithms";
import {
  DecryptionPvkOption,
  isValidSamlSigningOptions,
  NameID,
  SamlSigningOptions,
  XmlJsObject,
  XMLOutput,
  XmlSignatureLocation,
} from "./types";
import { assertRequired } from "./utility";
import {
  decryptionPvkFingerprint,
  decryptionPvkToPem,
  keyInfoToPem,
  privateKeyToPem,
} from "./crypto";

const debugLog = util.debuglog("node-saml");

const selectXPath = <T extends Node>(
  guard: (values: SelectReturnType) => values is Array<T>,
  node: Node,
  xpath: string,
): Array<T> => {
  const result = select(xpath, node);
  if (!guard(result)) {
    throw new Error("Invalid xpath return type");
  }
  return result;
};

const attributesXPathTypeGuard = (values: unknown): values is Array<Attr> =>
  isDomNode.isArrayOfNodes(values) && values.every(isDomNode.isAttributeNode);

const elementsXPathTypeGuard = (values: unknown): values is Array<Element> =>
  isDomNode.isArrayOfNodes(values) && values.every(isDomNode.isElementNode);

export const xpath = {
  selectAttributes: (node: Node, xpath: string): Array<Attr> =>
    selectXPath(attributesXPathTypeGuard, node, xpath),
  selectElements: (node: Node, xpath: string): Array<Element> =>
    selectXPath(elementsXPathTypeGuard, node, xpath),
};

const xmlEncryptionNamespace = "http://www.w3.org/2001/04/xmlenc#";
const xmlSignatureNamespace = "http://www.w3.org/2000/09/xmldsig#";

const decryptionKeys = (decryptionPvk: DecryptionPvkOption): Array<string | Buffer> =>
  Array.isArray(decryptionPvk) ? [...decryptionPvk] : [decryptionPvk];

const encryptedKeyId = (element: Element): string | null => {
  const id = element.getAttribute("Id") ?? element.getAttribute("ID");
  return id == null || id === "" ? null : id;
};

const findEncryptedDataElement = (root: Element): Element | null => {
  if (root.localName === "EncryptedData") {
    return root;
  }

  const encryptedData = xpath.selectElements(
    root,
    `.//*[local-name()='EncryptedData' and namespace-uri(.)='${xmlEncryptionNamespace}']`,
  );
  if (encryptedData.length > 1) {
    throw new Error("Invalid EncryptedAssertion content");
  }
  if (encryptedData.length === 1) {
    return encryptedData[0];
  }

  const localNameMatches = xpath.selectElements(root, ".//*[local-name()='EncryptedData']");
  if (localNameMatches.length > 1) {
    throw new Error("Invalid EncryptedAssertion content");
  }
  return localNameMatches[0] ?? null;
};

const findEncryptedKeys = (root: Element, encryptedData: Element): Element[] => {
  const strictKeyInfos = xpath.selectElements(
    encryptedData,
    `./*[local-name()='KeyInfo' and namespace-uri(.)='${xmlSignatureNamespace}']`,
  );
  const keyInfos =
    strictKeyInfos.length > 0
      ? strictKeyInfos
      : xpath.selectElements(encryptedData, "./*[local-name()='KeyInfo']");
  const inlineKeys: Element[] = [];
  const retrievalMethods: Element[] = [];
  for (const keyInfo of keyInfos) {
    const strictInlineKeys = xpath.selectElements(
      keyInfo,
      `./*[local-name()='EncryptedKey' and namespace-uri(.)='${xmlEncryptionNamespace}']`,
    );
    inlineKeys.push(
      ...(strictInlineKeys.length > 0
        ? strictInlineKeys
        : xpath.selectElements(keyInfo, "./*[local-name()='EncryptedKey']")),
    );
    const strictRetrievalMethods = xpath.selectElements(
      keyInfo,
      `./*[local-name()='RetrievalMethod' and namespace-uri(.)='${xmlSignatureNamespace}']`,
    );
    retrievalMethods.push(
      ...(strictRetrievalMethods.length > 0
        ? strictRetrievalMethods
        : xpath.selectElements(keyInfo, "./*[local-name()='RetrievalMethod']")),
    );
  }
  const detachedKeys: Element[] = [];
  for (const retrievalMethod of retrievalMethods) {
    const uri = retrievalMethod.getAttribute("URI");
    if (!uri?.startsWith("#")) {
      throw new Error("Invalid EncryptedAssertion content");
    }
    if (uri.includes("'") || uri.includes('"')) {
      throw new Error("Invalid EncryptedAssertion content");
    }
    const id = uri.slice(1);
    if (id === "") {
      throw new Error("Invalid EncryptedAssertion content");
    }
    const strictMatches = xpath
      .selectElements(
        root,
        `./*[local-name()='EncryptedKey' and namespace-uri(.)='${xmlEncryptionNamespace}']`,
      )
      .filter((key) => encryptedKeyId(key) === id);
    const matches =
      strictMatches.length > 0
        ? strictMatches
        : xpath
            .selectElements(root, "./*[local-name()='EncryptedKey']")
            .filter((key) => encryptedKeyId(key) === id);
    if (matches.length > 1) {
      throw new Error("Invalid EncryptedAssertion content");
    }
    detachedKeys.push(...matches);
  }

  return [...new Set([...inlineKeys, ...detachedKeys])];
};

const findKeyInfoElement = (encryptedData: Element): Element | undefined =>
  xpath.selectElements(
    encryptedData,
    `./*[local-name()='KeyInfo' and namespace-uri(.)='${xmlSignatureNamespace}']`,
  )[0] ??
  xpath.selectElements(encryptedData, "./*[local-name()='KeyInfo']")[0];

const isDescendantOf = (node: Node, ancestor: Element): boolean => {
  let parent = node.parentNode;
  while (parent != null) {
    if (parent === ancestor) {
      return true;
    }
    parent = parent.parentNode;
  }
  return false;
};

const isolateEncryptedKey = async (xml: string, candidateIndex: number): Promise<string> => {
  const doc = await parseDomFromString(xml);
  const root = doc.documentElement;
  const encryptedData = findEncryptedDataElement(root);
  if (encryptedData == null) {
    throw new Error("Invalid EncryptedAssertion content");
  }

  const candidates = findEncryptedKeys(root, encryptedData);
  const selected = candidates[candidateIndex];
  if (selected == null) {
    throw new Error("Invalid EncryptedAssertion content");
  }

  const allKeys = xpath.selectElements(
    doc,
    "//*[local-name()='EncryptedKey']",
  );
  for (const key of allKeys) {
    if (key !== selected) {
      key.parentNode?.removeChild(key);
    }
  }

  // `xml-encryption` otherwise reads the first KeyInfo/EncryptedKey in the document. Move the
  // selected key under the EncryptedData's KeyInfo and remove RetrievalMethods so this attempt can
  // only see the algorithm context and wrapped key that belong to `selected`.
  const keyInfo = findKeyInfoElement(encryptedData);
  if (keyInfo == null) {
    throw new Error("Invalid EncryptedAssertion content");
  }
  for (const otherKeyInfo of xpath.selectElements(doc, "//*[local-name()='KeyInfo']")) {
    if (otherKeyInfo !== keyInfo && !isDescendantOf(otherKeyInfo, keyInfo)) {
      otherKeyInfo.parentNode?.removeChild(otherKeyInfo);
    }
  }
  for (const retrievalMethod of xpath.selectElements(
    encryptedData,
    `./*[local-name()='KeyInfo']/*[local-name()='RetrievalMethod']`,
  )) {
    retrievalMethod.parentNode?.removeChild(retrievalMethod);
  }
  if (selected.parentNode !== keyInfo) {
    selected.parentNode?.removeChild(selected);
    keyInfo.appendChild(selected);
  }

  return new xmldom.XMLSerializer().serializeToString(doc);
};

export interface XmlDecryptionResult {
  xml: string;
  decryptionPvk: string | Buffer;
  decryptionKeyFingerprint: string;
  encryptedDataXml: string | null;
  encryptedKeyId: string | null;
  keyEncryptionAlgorithm: string | null;
  keyEncryptionDigest: string | null;
  contentEncryptionAlgorithm: string | null;
}

/**
 * Decrypt XML with one key or a rotation window of keys. Each attempt is isolated to one
 * `EncryptedKey`, so a failed attempt cannot leave `xml-encryption` reading another key's
 * algorithm context.
 */
export const decryptXmlWithKeys = async (
  xml: string,
  decryptionPvk: DecryptionPvkOption,
): Promise<XmlDecryptionResult> => {
  const decrypt = util.promisify(xmlenc.decrypt).bind(xmlenc);
  const keys = decryptionKeys(decryptionPvk);
  if (keys.length === 0) {
    throw new Error("No decryption key for encrypted SAML response");
  }

  const parsedDoc = await parseDomFromString(xml);
  const parsedRoot = parsedDoc.documentElement;
  const parsedEncryptedData = findEncryptedDataElement(parsedRoot);
  const candidates =
    parsedEncryptedData == null ? [] : findEncryptedKeys(parsedRoot, parsedEncryptedData);
  const encryptedDataXml = parsedEncryptedData?.toString() ?? null;
  const contentEncryptionAlgorithm = parsedEncryptedData
    ? (encryptionMethod(parsedEncryptedData)?.getAttribute("Algorithm") ?? null)
    : null;

  let lastError: unknown;
  for (const decryptionKey of keys) {
    let fingerprint: string;
    try {
      fingerprint = decryptionPvkFingerprint(decryptionKey);
    } catch (error) {
      lastError = error;
      continue;
    }

    if (candidates.length === 0) {
      try {
        const decrypted = (await decrypt(xml, {
          key: decryptionPvkToPem(decryptionKey),
        })) as string;
        return {
          xml: decrypted,
          decryptionPvk: decryptionKey,
          decryptionKeyFingerprint: fingerprint,
          encryptedDataXml,
          encryptedKeyId: null,
          keyEncryptionAlgorithm: null,
          keyEncryptionDigest: null,
          contentEncryptionAlgorithm,
        };
      } catch (error) {
        lastError = error;
        continue;
      }
    }

    for (let candidateIndex = 0; candidateIndex < candidates.length; candidateIndex++) {
      const candidate = candidates[candidateIndex];
      const keyMethod = encryptionMethod(candidate);
      const keyEncryptionAlgorithm = keyMethod?.getAttribute("Algorithm") ?? null;
      const digestMethod =
        keyMethod == null
          ? undefined
          : (xpath.selectElements(
              keyMethod,
              `./*[local-name()='DigestMethod' and namespace-uri(.)='${xmlSignatureNamespace}']`,
            )[0] ?? xpath.selectElements(keyMethod, "./*[local-name()='DigestMethod']")[0]);
      const keyEncryptionDigest = digestMethod?.getAttribute("Algorithm") ?? null;

      let isolatedXml: string;
      try {
        isolatedXml = await isolateEncryptedKey(xml, candidateIndex);
      } catch (error) {
        lastError = error;
        continue;
      }

      try {
        const decrypted = (await decrypt(isolatedXml, {
          key: decryptionPvkToPem(decryptionKey),
        })) as string;
        return {
          xml: decrypted,
          decryptionPvk: decryptionKey,
          decryptionKeyFingerprint: fingerprint,
          encryptedDataXml,
          encryptedKeyId: encryptedKeyId(candidate),
          keyEncryptionAlgorithm,
          keyEncryptionDigest,
          contentEncryptionAlgorithm,
        };
      } catch (error) {
        lastError = error;
        if (debugLog.enabled) {
          debugLog(
            "decryption with key %s and EncryptedKey %s failed: %s",
            fingerprint,
            encryptedKeyId(candidate) ?? "without an ID",
            error,
          );
        }
      }
    }
  }

  throw lastError ?? new Error("No decryption key for encrypted SAML response");
};

export const decryptXml = async (
  xml: string,
  decryptionPvk: DecryptionPvkOption,
): Promise<string> => (await decryptXmlWithKeys(xml, decryptionPvk)).xml;

const encryptionMethod = (element: Element): Element | undefined =>
  xpath.selectElements(
    element,
    "./*[local-name()='EncryptionMethod' and namespace-uri(.)='http://www.w3.org/2001/04/xmlenc#']",
  )[0];

const deprecatedContentAlgorithms = new Set([
  "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
  "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
  "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
]);

const deprecatedOaepDigests = new Set([
  "http://www.w3.org/2001/04/xmlenc#sha256",
  "http://www.w3.org/2001/04/xmlenc#sha512",
  "http://www.w3.org/2000/09/xmldsig#sha256",
  "http://www.w3.org/2000/09/xmldsig#sha512",
]);

const findEncryptedKey = (
  encryptedElement: Element,
  encryptedData: Element,
): Element | undefined => {
  const keyInfo =
    "./*[local-name()='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
  const inlineKey = xpath.selectElements(
    encryptedData,
    `${keyInfo}/*[local-name()='EncryptedKey' and namespace-uri(.)='http://www.w3.org/2001/04/xmlenc#']`,
  )[0];
  if (inlineKey) {
    return inlineKey;
  }

  // SAML core §2.2.4 also allows the key beside the EncryptedData, named by a RetrievalMethod.
  const uri = xpath
    .selectElements(
      encryptedData,
      `${keyInfo}/*[local-name()='RetrievalMethod' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']`,
    )[0]
    ?.getAttribute("URI");
  if (!uri?.startsWith("#")) {
    return undefined;
  }
  const id = uri.slice(1);
  return xpath
    .selectElements(
      encryptedElement,
      "./*[local-name()='EncryptedKey' and namespace-uri(.)='http://www.w3.org/2001/04/xmlenc#']",
    )
    .find((key) => key.getAttribute("Id") === id);
};

export const warnIfDecryptionWillFailInNextMajor = (encryptedElement: Element): void => {
  if (!debugLog.enabled) {
    return;
  }

  const encryptedData = xpath.selectElements(
    encryptedElement,
    "./*[local-name()='EncryptedData' and namespace-uri(.)='http://www.w3.org/2001/04/xmlenc#']",
  )[0];
  if (!encryptedData) {
    return;
  }

  const contentAlgorithm = encryptionMethod(encryptedData)?.getAttribute("Algorithm");
  if (contentAlgorithm && deprecatedContentAlgorithms.has(contentAlgorithm)) {
    debugLog(
      'The %s was decrypted with content encryption algorithm "%s", which the next major version does not decrypt. Configure the identity provider to encrypt with aes128-gcm or aes256-gcm, which this version also decrypts. If it offers neither, and the deployment does not need these contents kept confidential, turn off this encryption at the identity provider: node-saml also accepts the unencrypted form and checks the same signatures either way, but signatures do not hide its contents from the browser or any other system that handles the message.',
      encryptedElement.localName,
      contentAlgorithm,
    );
  }

  const encryptedKey = findEncryptedKey(encryptedElement, encryptedData);
  if (!encryptedKey) {
    return;
  }

  const keyMethod = encryptionMethod(encryptedKey);
  const keyAlgorithm = keyMethod?.getAttribute("Algorithm");
  if (keyAlgorithm === "http://www.w3.org/2001/04/xmlenc#rsa-1_5") {
    debugLog(
      'The %s was decrypted with key transport algorithm "%s", which the next major version does not decrypt. Configure the identity provider to wrap the key with rsa-oaep-mgf1p and its default SHA-1 digest, which this version also decrypts. If it offers no rsa-oaep-mgf1p, and the deployment does not need these contents kept confidential, turn off this encryption at the identity provider: node-saml also accepts the unencrypted form and checks the same signatures either way, but signatures do not hide its contents from the browser or any other system that handles the message.',
      encryptedElement.localName,
      keyAlgorithm,
    );
  }

  if (keyAlgorithm === "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" && keyMethod) {
    const digestAlgorithm = xpath
      .selectElements(
        keyMethod,
        "./*[local-name()='DigestMethod' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      )[0]
      ?.getAttribute("Algorithm");

    if (digestAlgorithm && deprecatedOaepDigests.has(digestAlgorithm)) {
      debugLog(
        'The %s was decrypted with key transport algorithm "%s" and DigestMethod "%s", which the next major version does not decrypt: it uses that digest for OAEP and SHA-1 for MGF1, as XML Encryption 1.1 requires, and this key was wrapped another way. Configure the identity provider to use SHA-1, the default rsa-oaep-mgf1p digest, which both versions decrypt.',
        encryptedElement.localName,
        keyAlgorithm,
        digestAlgorithm,
      );
    }
  }
};

/**
 * // modeled after the current validateSignature method, to maintain consistency for unit tests
 * Input: fullXml, the document for SignedXML context
 * Input: currentNode, this node must have a Signature
 * Input: pemFiles: a list of pem encoded certificates that are trusted. User is responsible for ensuring trust
 * Find's a signature for the currentNode
 * Return the verified contents if verified?
 * Otherwise returns null
 * */
export const getVerifiedXml = (
  fullXml: string,
  currentNode: Element,
  pemFiles: string[],
): string | null => {
  // find any signature
  const signatures = xpath.selectElements(
    currentNode,
    "./*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
  );
  if (signatures.length < 1) {
    return null;
  }

  if (signatures.length > 1) {
    throw new Error("Too many signatures found for this element");
  }

  const signature = signatures[0];

  const xpathTransformQuery =
    ".//*[local-name(.)='Transform' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
  const transforms = xpath.selectElements(signature, xpathTransformQuery);
  // Reject also XMLDSIG with more than 2 Transform
  if (transforms.length > 2) {
    // do not return false, throw an error so that it can be caught by tests differently
    throw new Error("Invalid signature, too many transforms");
  }

  for (const pemFile of pemFiles) {
    const sig = new xmlCrypto.SignedXml();
    sig.publicCert = pemFile; // public certificate to verify
    sig.loadSignature(signature);

    const refs = sig.getReferences();

    if (refs.length !== 1) {
      debugLog(
        "The signature on the %s element has %d references, so it is ignored and the element is treated as unsigned. SAML requires exactly one, to the element signed (SAML core §5.4.2), and the next major version rejects the message. Configure the identity provider to sign the %s with a single reference.",
        currentNode.localName,
        refs.length,
        currentNode.localName,
      );
      return null;
    }

    const ref = refs[0];

    // only allow enveloped signature
    const refUri = ref.uri;

    assertRequired(refUri, "signature reference uri not found");

    // For an ID of "foo" the reference URI must be "#foo"; a bare "foo" names another resource.
    // SAML core 5.4.2: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    if (!refUri.startsWith("#")) {
      throw new Error("Invalid signature: reference URI is not a same-document reference");
    }

    const refId = refUri.substring(1);

    assertRequired(refId, "signature reference uri not found");
    // prevent XPath injection
    if (refId.includes("'") || refId.includes('"')) {
      throw new Error("ref URI included quote character ' or \". Not a valid ID, and not allowed");
    }

    const totalReferencedNodes = xpath.selectElements(
      signature.ownerDocument,
      `//*[@ID="${refId}"]`,
    );

    if (totalReferencedNodes.length !== 1) {
      throw new Error("Invalid signature: ID cannot refer to more than one element");
    }

    if (totalReferencedNodes[0] !== signature.parentNode) {
      throw new Error("Invalid signature: Referenced node does not refer to its parent element");
    }

    // actual cryptographic verification
    // after verification, the referenced XML will be in `sig.signedReferences`
    // do not trust any other xml (including referencedNode)

    try {
      if (!sig.checkSignature(fullXml)) {
        continue; // no signatures verified
      }

      return sig.getSignedReferences()[0];
    } catch {
      // return null; // we don't return null, since we have to verify with another key
    }
  }

  return null;
};

/**
 * This function checks that the |currentNode| in the |fullXml| document contains exactly 1 valid
 *   signature of the |currentNode|.
 *
 * See https://github.com/bergie/passport-saml/issues/19 for references to some of the attack
 *   vectors against SAML signature verification.
 *
 * @deprecated Reports only whether a signature verified, leaving the caller to find the signed
 * content somewhere else — and an attacker controls the difference between what verified and what
 * the caller then reads. Removed in the next major version; use `getVerifiedXml()`, which returns
 * the bytes the signature covers.
 */
export const validateSignature = (
  fullXml: string,
  currentNode: Element,
  pemFiles: string[],
): boolean => {
  const xpathSigQuery = `.//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and descendant::*[local-name(.)='Reference' and @URI='#${currentNode.getAttribute("ID")}']]`;
  const signatures = xpath.selectElements(currentNode, xpathSigQuery);
  // This function is expecting to validate exactly one signature, so if we find more or fewer
  //   than that, reject.
  if (signatures.length !== 1) {
    return false;
  }
  const xpathTransformQuery =
    ".//*[" +
    "local-name(.)='Transform' and " +
    "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and " +
    "ancestor::*[local-name(.)='Reference' and @URI='#" +
    currentNode.getAttribute("ID") +
    "']" +
    "]";
  const transforms = xpath.selectElements(currentNode, xpathTransformQuery);
  // Reject also XMLDSIG with more than 2 Transform
  if (transforms.length > 2) {
    // do not return false, throw an error so that it can be caught by tests differently
    throw new Error("Invalid signature, too many transforms");
  }

  const signature = signatures[0];
  return pemFiles.some((pemFile) => {
    return validateXmlSignatureWithPemFile(signature, pemFile, fullXml, currentNode);
  });
};

/**
 * This function checks that the |signature| is signed with a given |pemFile|.
 * Internally deprecated, users should not be using this for anything new
 */
const validateXmlSignatureWithPemFile = (
  signature: Node,
  pemFile: string,
  fullXml: string,
  currentNode: Element,
): boolean => {
  const sig = new xmlCrypto.SignedXml();
  sig.publicCert = pemFile;
  sig.loadSignature(signature);
  // We expect each signature to contain exactly one reference to the top level of the xml we
  //   are validating, so if we see anything else, reject.
  if (sig.getReferences().length !== 1) return false;
  const t = sig.getReferences();
  const refUri = t[0].uri;
  assertRequired(refUri, "signature reference uri not found");
  const refId = refUri[0] === "#" ? refUri.substring(1) : refUri;
  // If we can't find the reference at the top level, reject
  const idAttribute = currentNode.getAttribute("ID") ? "ID" : "Id";
  if (currentNode.getAttribute(idAttribute) != refId) return false;
  // If we find any extra referenced nodes, reject.  (xml-crypto only verifies one digest, so
  //   multiple candidate references is bad news)
  const totalReferencedNodes = xpath.selectElements(
    currentNode.ownerDocument,
    "//*[@" + idAttribute + "='" + refId + "']",
  );

  if (totalReferencedNodes.length > 1) {
    return false;
  }

  try {
    return sig.checkSignature(fullXml);
  } catch (err) {
    debugLog.enabled && debugLog("signature check resulted in an error: %s", err);
    return false;
  }
};

export const signXml = (
  xml: string,
  xpath: string,
  location: XmlSignatureLocation,
  options: SamlSigningOptions,
): string => {
  const defaultTransforms = [
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
  ];

  if (!xml) throw new Error("samlMessage is required");
  if (!location) throw new Error("location is required");
  if (!options) throw new Error("options is required");
  if (!isValidSamlSigningOptions(options)) throw new Error("options.privateKey is required");

  const transforms = options.xmlSignatureTransforms ?? defaultTransforms;
  const sig = new xmlCrypto.SignedXml();
  if (options.signatureAlgorithm != null) {
    sig.signatureAlgorithm = algorithms.getSigningAlgorithm(options.signatureAlgorithm);
  }
  sig.addReference({
    xpath,
    transforms,
    digestAlgorithm: algorithms.getDigestAlgorithm(options.digestAlgorithm),
  });
  sig.privateKey = privateKeyToPem(options.privateKey, "privateKey");
  if (options.publicCert != null) {
    const publicCert = keyInfoToPem(options.publicCert, "CERTIFICATE", "publicCert");
    // toPem() keeps a PEM's own label, and xml-crypto omits KeyInfo when it finds no certificate.
    assertRequired(
      xmlCrypto.pemCertificates(publicCert).length > 0 || undefined,
      "publicCert must hold at least one certificate",
    );
    sig.publicCert = publicCert;
  }
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  sig.computeSignature(xml, { location });

  return sig.getSignedXml();
};

export const parseDomFromString = (xml: string): Promise<Document> => {
  return new Promise(function (resolve, reject) {
    function errHandler(msg: string) {
      return reject(new Error(msg));
    }

    const dom = new xmldom.DOMParser({
      /**
       * locator is always need for error position info
       */
      locator: {},
      /**
       * you can override the errorHandler for xml parser
       * @link http://www.saxproject.org/apidoc/org/xml/sax/ErrorHandler.html
       */
      errorHandler: { error: errHandler, fatalError: errHandler },
    }).parseFromString(xml, "text/xml");

    if (!Object.prototype.hasOwnProperty.call(dom, "documentElement")) {
      return reject(new Error("Not a valid XML document"));
    }

    return resolve(dom);
  });
};

export const parseXml2JsFromString = async (xml: string | Buffer): Promise<XmlJsObject> => {
  const parserConfig = {
    explicitRoot: true,
    explicitCharkey: true,
    tagNameProcessors: [xml2js.processors.stripPrefix],
  };
  const parser = new xml2js.Parser(parserConfig);
  return parser.parseStringPromise(xml);
};

export const buildXml2JsObject = (rootName: string, xml: XmlJsObject): string => {
  const builderOpts = { rootName, headless: true };
  return new xml2js.Builder(builderOpts).buildObject(xml);
};

export const buildXmlBuilderObject = (xml: XMLOutput, pretty: boolean): string => {
  const options = pretty ? { pretty: true, indent: "  ", newline: "\n" } : {};
  return xmlbuilder.create(xml).end(options);
};

export const promiseWithNameId = async (nameid: Node): Promise<NameID> => {
  const format = xpath.selectAttributes(nameid, "@Format");
  return { value: nameid.textContent, format: format && format[0] && format[0].nodeValue };
};

export const getNameIdAsync = async (
  doc: Node,
  decryptionPvk: DecryptionPvkOption | null,
): Promise<NameID> => {
  const nameIds = xpath.selectElements(
    doc,
    "/*[local-name()='LogoutRequest']/*[local-name()='NameID']",
  );
  const encryptedIds = xpath.selectElements(
    doc,
    "/*[local-name()='LogoutRequest']/*[local-name()='EncryptedID']",
  );

  if (nameIds.length + encryptedIds.length > 1) {
    throw new Error("Invalid LogoutRequest: multiple ID elements");
  }
  if (nameIds.length === 1) {
    return promiseWithNameId(nameIds[0]);
  }
  if (encryptedIds.length === 1) {
    assertRequired(
      decryptionPvk,
      "No decryption key found getting name ID for encrypted SAML response",
    );

    const encryptedData = xpath.selectElements(
      encryptedIds[0],
      "./*[local-name()='EncryptedData']",
    );

    if (encryptedData.length !== 1) {
      throw new Error("Invalid LogoutRequest: no EncryptedData element found");
    }
    const encryptedIdXml = encryptedIds[0].toString();

    const decryptedXml = await decryptXml(encryptedIdXml, decryptionPvk);
    warnIfDecryptionWillFailInNextMajor(encryptedIds[0]);
    const decryptedDoc = await parseDomFromString(decryptedXml);
    const decryptedIds = xpath.selectElements(decryptedDoc, "/*[local-name()='NameID']");
    if (decryptedIds.length !== 1) {
      throw new Error("Invalid EncryptedData content");
    }
    return await promiseWithNameId(decryptedIds[0]);
  }
  throw new Error("Missing SAML NameID");
};
