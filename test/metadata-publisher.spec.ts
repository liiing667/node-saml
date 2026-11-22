"use strict";
import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { expect } from "chai";
import {
  InMemoryMetadataStore,
  MetadataStore,
  PublishedServiceProviderMetadata,
  PublishServiceProviderMetadataParams,
  ServiceProviderMetadataPublisher,
} from "../src";
import { SAML } from "../src/saml";
import { generateServiceProviderMetadata } from "../src/metadata";
import { getVerifiedXml, parseDomFromString } from "../src/xml";

describe("ServiceProviderMetadataPublisher /", function () {
  const staticDir = path.join(__dirname, "static");
  const readStatic = (name: string): string =>
    fs.readFileSync(path.join(staticDir, name), "utf-8");

  const signingKey = readStatic("acme_tools_com.key");
  const signingCert = readStatic("acme_tools_com.cert");
  const rotatedSigningCert = readStatic("cert.pem");
  const decryptionKey = readStatic("testshib encryption pvk.pem");
  const decryptionCert = readStatic("testshib encryption cert.pem");

  const baseParams = {
    issuer: "http://example.serviceprovider.com",
    callbackUrl: "http://example.serviceprovider.com/saml/callback",
    generateUniqueId: () => "_metadata",
  };

  const fingerprintOf = (metadataXml: string): string =>
    crypto.createHash("sha256").update(metadataXml).digest("hex");

  // A store whose save fails after the document has been built, modeling a write that dies
  // mid-publication: a crashed process, a lost database connection, a full disk.
  class FailingStore implements MetadataStore {
    public failNextSave = true;

    constructor(public readonly backing: MetadataStore = new InMemoryMetadataStore()) {}

    async saveIfNewerAsync(
      record: PublishedServiceProviderMetadata,
    ): Promise<PublishedServiceProviderMetadata> {
      if (this.failNextSave) {
        throw new Error("simulated store outage");
      }
      return this.backing.saveIfNewerAsync(record);
    }

    async getLatestAsync(): Promise<PublishedServiceProviderMetadata | null> {
      return this.backing.getLatestAsync();
    }

    async getByGenerationAsync(
      generation: number,
    ): Promise<PublishedServiceProviderMetadata | null> {
      return this.backing.getByGenerationAsync(generation);
    }
  }

  it("publishes nothing before the first publication", async function () {
    const publisher = new ServiceProviderMetadataPublisher();

    expect(await publisher.getLatestAsync()).to.equal(null);
    expect(await publisher.getByGenerationAsync(1)).to.equal(null);
  });

  it("commits a complete first generation and fingerprints its exact bytes", async function () {
    const publisher = new ServiceProviderMetadataPublisher();
    const params: PublishServiceProviderMetadataParams = {
      ...baseParams,
      decryptionPvk: decryptionKey,
      decryptionCert,
      privateKey: signingKey,
      publicCerts: signingCert,
      nowMs: 1000,
    };

    const published = await publisher.publishAsync(params);

    expect(published.generation).to.equal(1);
    expect(published.publishedAtMs).to.equal(1000);
    expect(published.metadataXml).to.equal(generateServiceProviderMetadata(params));
    expect(published.fingerprint).to.equal(fingerprintOf(published.metadataXml));
    expect(await publisher.getLatestAsync()).to.deep.equal(published);
  });

  it("assigns consecutive generations and keeps every committed generation recoverable", async function () {
    const publisher = new ServiceProviderMetadataPublisher();

    const first = await publisher.publishAsync({
      ...baseParams,
      callbackUrl: "http://example.serviceprovider.com/saml/callback-v1",
    });
    const second = await publisher.publishAsync({
      ...baseParams,
      callbackUrl: "http://example.serviceprovider.com/saml/callback-v2",
    });

    expect(first.generation).to.equal(1);
    expect(second.generation).to.equal(2);
    expect(await publisher.getByGenerationAsync(1)).to.deep.equal(first);
    expect(await publisher.getByGenerationAsync(2)).to.deep.equal(second);
    expect(await publisher.getLatestAsync()).to.deep.equal(second);
  });

  it("keeps serving the complete old generation when a rotated publication fails", async function () {
    const publisher = new ServiceProviderMetadataPublisher();

    const oldGeneration = await publisher.publishAsync({
      ...baseParams,
      decryptionPvk: decryptionKey,
      decryptionCert,
      privateKey: signingKey,
      publicCerts: [signingCert],
    });

    // The new certificate reaches the signing material, but the matching decryption cert is
    // malformed. Building the document throws before the store is touched.
    const brokenRotation = {
      ...baseParams,
      decryptionPvk: decryptionKey,
      decryptionCert: "not-a-certificate",
      privateKey: signingKey,
      publicCerts: [signingCert, rotatedSigningCert],
    };

    await assert.rejects(publisher.publishAsync(brokenRotation), {
      message: /decryptionCert is neither valid PEM nor a valid Base64 certificate/,
    });

    // No half generation exists: the store still holds only the old, complete document.
    expect(await publisher.getLatestAsync()).to.deep.equal(oldGeneration);
    expect(await publisher.getByGenerationAsync(2)).to.equal(null);

    // Retrying with a complete rotation publishes the full new generation, which carries both
    // signing certificates (the legal dual-certificate window) together with its decryption cert.
    const retried = await publisher.publishAsync({
      ...baseParams,
      decryptionPvk: decryptionKey,
      decryptionCert,
      privateKey: signingKey,
      publicCerts: [signingCert, rotatedSigningCert],
    });

    expect(retried.generation).to.equal(2);
    expect(retried.metadataXml).to.contain(signingCert.replace(/-----[^-]+-----|\s/g, ""));
    expect(retried.metadataXml).to.contain(rotatedSigningCert.replace(/-----[^-]+-----|\s/g, ""));
    expect(retried.metadataXml).to.contain(decryptionCert.replace(/-----[^-]+-----|\s/g, ""));
    expect(retried.fingerprint).to.equal(fingerprintOf(retried.metadataXml));
    expect(retried.fingerprint).to.not.equal(oldGeneration.fingerprint);
    expect(await publisher.getLatestAsync()).to.deep.equal(retried);
  });

  it("keeps the old ACS location when an ACS change fails, then publishes only the new one", async function () {
    const publisher = new ServiceProviderMetadataPublisher();
    const oldCallbackUrl = "http://example.serviceprovider.com/saml/callback-v1";
    const newCallbackUrl = "http://example.serviceprovider.com/saml/callback-v2";

    const oldGeneration = await publisher.publishAsync({
      ...baseParams,
      callbackUrl: oldCallbackUrl,
    });

    // A failed commit (not a failed build) must likewise leave the old generation as the only one.
    const store = new FailingStore();
    await store.backing.saveIfNewerAsync(oldGeneration);
    const retryingPublisher = new ServiceProviderMetadataPublisher(store);

    await assert.rejects(
      retryingPublisher.publishAsync({ ...baseParams, callbackUrl: newCallbackUrl }),
      { message: "simulated store outage" },
    );

    const stillPublished = await retryingPublisher.getLatestAsync();
    expect(stillPublished).to.deep.equal(oldGeneration);
    expect(stillPublished?.metadataXml).to.contain(`Location="${oldCallbackUrl}"`);
    expect(stillPublished?.metadataXml).to.not.contain(newCallbackUrl);

    // Once the store recovers, the retry is atomic: exactly one ACS location, the new one.
    store.failNextSave = false;
    const newGeneration = await retryingPublisher.publishAsync({
      ...baseParams,
      callbackUrl: newCallbackUrl,
    });
    expect(newGeneration.metadataXml).to.contain(`Location="${newCallbackUrl}"`);
    expect(newGeneration.metadataXml).to.not.contain(oldCallbackUrl);
    expect((newGeneration.metadataXml.match(/AssertionConsumerService/g) ?? []).length).to.equal(1);
  });

  it("publishes the signature over the whole new generation, or leaves the old one", async function () {
    const publisher = new ServiceProviderMetadataPublisher();
    const signedParams = {
      ...baseParams,
      privateKey: signingKey,
      publicCerts: signingCert,
      signMetadata: true,
      signatureAlgorithm: "sha256" as const,
      digestAlgorithm: "sha256",
    };

    const first = await publisher.publishAsync(signedParams);
    const firstDom = await parseDomFromString(first.metadataXml);
    assert.ok(getVerifiedXml(first.metadataXml, firstDom.documentElement, [signingCert]));

    const rotated = await publisher.publishAsync({
      ...signedParams,
      publicCerts: [signingCert, rotatedSigningCert],
    });
    const rotatedDom = await parseDomFromString(rotated.metadataXml);
    // The signature is made with the current private key's certificate and covers the whole
    // document, including both KeyDescriptors of the dual-certificate window.
    assert.ok(getVerifiedXml(rotated.metadataXml, rotatedDom.documentElement, [signingCert]));
    expect(rotated.fingerprint).to.not.equal(first.fingerprint);
  });

  it("gives every consumer reading one generation the same bytes and fingerprint", async function () {
    const store = new InMemoryMetadataStore();
    const publisherA = new ServiceProviderMetadataPublisher(store);
    const publisherB = new ServiceProviderMetadataPublisher(store);

    await publisherA.publishAsync({
      ...baseParams,
      decryptionPvk: decryptionKey,
      decryptionCert,
      privateKey: signingKey,
      publicCerts: [signingCert, rotatedSigningCert],
    });

    const fromA = await publisherA.getLatestAsync();
    const fromB = await publisherB.getLatestAsync();
    assert.ok(fromA !== null && fromB !== null);
    expect(fromA).to.deep.equal(fromB);
    expect(fromA.metadataXml).to.equal(fromB.metadataXml);
    expect(fromA.fingerprint).to.equal(fromB.fingerprint);
    expect(fromA.fingerprint).to.equal(fingerprintOf(fromA.metadataXml));
  });

  it("models a restart: a fresh publisher over the same store resumes at the next generation", async function () {
    const store = new InMemoryMetadataStore();

    const beforeRestart = new ServiceProviderMetadataPublisher(store);
    await beforeRestart.publishAsync({
      ...baseParams,
      callbackUrl: "https://example.com/acs-1",
    });

    // A new process constructs a new publisher around the durable store and only ever sees the
    // complete committed generation; the next publication takes the next consecutive number.
    const afterRestart = new ServiceProviderMetadataPublisher(store);
    expect(await afterRestart.getLatestAsync()).to.deep.equal(
      await beforeRestart.getLatestAsync(),
    );
    const next = await afterRestart.publishAsync({
      ...baseParams,
      callbackUrl: "https://example.com/acs-2",
    });
    expect(next.generation).to.equal(2);
  });

  it("refuses to move the shared view backwards or fork it with a stale generation", async function () {
    const store = new InMemoryMetadataStore();
    const publisher = new ServiceProviderMetadataPublisher(store);

    await publisher.publishAsync(baseParams);

    await assert.rejects(publisher.publishAsync({ ...baseParams, generation: 1 }), {
      message: "metadata generation 1 is not newer than the published generation 1",
    });
    await assert.rejects(publisher.publishAsync({ ...baseParams, generation: 0 }), {
      name: "TypeError",
      message: "metadata generation must be a positive integer",
    });
    await assert.rejects(publisher.publishAsync({ ...baseParams, generation: 1.5 }), {
      name: "TypeError",
      message: "metadata generation must be a positive integer",
    });
    expect((await publisher.getLatestAsync())?.generation).to.equal(1);
  });

  it("honors an explicit increasing generation and resolves a concurrent race via the store", async function () {
    // Two publications targeting the same generation (as two processes can do): one commits, and
    // the store stops the other from overwriting it even though both documents were fully built.
    const store = new InMemoryMetadataStore();
    const first = new ServiceProviderMetadataPublisher(store);
    const racing = new ServiceProviderMetadataPublisher(store);

    await first.publishAsync(baseParams);

    const winner = await first.publishAsync({
      ...baseParams,
      callbackUrl: "https://example.com/acs-winner",
      generation: 2,
    });
    await assert.rejects(
      racing.publishAsync({
        ...baseParams,
        callbackUrl: "https://example.com/acs-loser",
        generation: 2,
      }),
      { message: "metadata generation 2 is not newer than the published generation 2" },
    );

    expect(await store.getLatestAsync()).to.deep.equal(winner);
  });

  it("still supports ordinary unsigned metadata without keys", async function () {
    const publisher = new ServiceProviderMetadataPublisher();

    const published = await publisher.publishAsync({
      issuer: "https://www.example.com",
      callbackUrl: "https://www.example.com/callback",
    });

    expect(published.metadataXml).to.contain('entityID="https://www.example.com"');
    expect(published.metadataXml).to.contain('Location="https://www.example.com/callback"');
    expect(published.metadataXml).to.not.contain("KeyDescriptor");
    expect(published.metadataXml).to.not.contain("Signature");
  });

  it("publishes through a SAML instance and keeps its one-shot metadata call unchanged", async function () {
    const saml = new SAML({
      issuer: baseParams.issuer,
      callbackUrl: baseParams.callbackUrl,
      idpCert: signingCert,
      privateKey: signingKey,
      signMetadata: true,
      signatureAlgorithm: "sha256",
      digestAlgorithm: "sha256",
      generateUniqueId: baseParams.generateUniqueId,
    });

    const store = new InMemoryMetadataStore();
    const publisher = saml.createServiceProviderMetadataPublisher(store);
    const published = await publisher.publishForSamlOptionsAsync(saml.options, {
      publicCerts: [signingCert, rotatedSigningCert],
    });

    // The generation is built from the instance's own options, so it cannot carry material that
    // disagrees with the key the SAML actually holds. Its one-shot metadata call stays available.
    expect(published.metadataXml).to.equal(
      saml.generateServiceProviderMetadata(null, [signingCert, rotatedSigningCert]),
    );
    expect(published.metadataXml).to.contain('AuthnRequestsSigned="true"');
    const dom = await parseDomFromString(published.metadataXml);
    assert.ok(getVerifiedXml(published.metadataXml, dom.documentElement, [signingCert]));

    // Two publishers handed the same store are one shared, recoverable publication surface.
    expect(await saml.createServiceProviderMetadataPublisher(store).getLatestAsync()).to.deep.equal(
      published,
    );
  });
});
