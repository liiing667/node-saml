import * as crypto from "crypto";
import { generateServiceProviderMetadata } from "./metadata";
import { GenerateServiceProviderMetadataParams, SamlOptions } from "./types";

/**
 * One generation of service provider metadata, exactly as it was published. Consumers only ever
 * read a whole record: certificate material, metadata signature and ACS location can never be
 * observed mixed across two publications.
 */
export interface PublishedServiceProviderMetadata {
  /** Monotonic, 1-based generation number. */
  generation: number;
  /** The complete, already signed (when requested) metadata document. */
  metadataXml: string;
  /**
   * SHA-256 fingerprint of `metadataXml`, so separate consumers can prove they share a
   * generation.
   */
  fingerprint: string;
  /** When this generation was committed, as Unix epoch milliseconds. */
  publishedAtMs: number;
}

/**
 * Holds published metadata generations. The default, {@link InMemoryMetadataStore}, keeps them in
 * this process. A multi-process deployment supplies its own implementation backed by shared,
 * durable storage; every method has to complete as one atomic operation so a process restarting
 * mid-publication cannot leave a half-written generation behind.
 */
export interface MetadataStore {
  /**
   * Saves `record` as one atomic operation and returns it. Rejects (or throws) instead of
   * overwriting when a generation with the same or a higher number is already stored, so a
   * retried publication cannot move the shared view backwards or fork it.
   */
  saveIfNewerAsync(
    record: PublishedServiceProviderMetadata,
  ): Promise<PublishedServiceProviderMetadata>;
  /** Returns the generation with the highest number, or `null` when nothing has been published. */
  getLatestAsync(): Promise<PublishedServiceProviderMetadata | null>;
  /** Returns the named generation, or `null` when it is absent. */
  getByGenerationAsync(generation: number): Promise<PublishedServiceProviderMetadata | null>;
}

const fingerprintOf = (metadataXml: string): string =>
  crypto.createHash("sha256").update(metadataXml).digest("hex");

/**
 * The default {@link MetadataStore}. It holds generations in memory only, so it cannot share them
 * across processes or survive a restart; supply a durable store there. Within one process it is
 * safe to share one instance between every `SAML` instance that serves the same entity.
 */
export class InMemoryMetadataStore implements MetadataStore {
  private records = new Map<number, PublishedServiceProviderMetadata>();

  async saveIfNewerAsync(
    record: PublishedServiceProviderMetadata,
  ): Promise<PublishedServiceProviderMetadata> {
    const existing = await this.getLatestAsync();
    if (existing != null && record.generation <= existing.generation) {
      throw new Error(
        `metadata generation ${record.generation} is not newer than the published generation ${
          existing.generation
        }`,
      );
    }
    this.records.set(record.generation, record);
    return record;
  }

  async getLatestAsync(): Promise<PublishedServiceProviderMetadata | null> {
    if (this.records.size === 0) {
      return null;
    }
    const generation = Math.max(...this.records.keys());
    return this.records.get(generation) ?? null;
  }

  async getByGenerationAsync(
    generation: number,
  ): Promise<PublishedServiceProviderMetadata | null> {
    return this.records.get(generation) ?? null;
  }
}

export interface PublishServiceProviderMetadataParams
  extends GenerateServiceProviderMetadataParams {
  /**
   * The generation to publish. It has to be a positive integer strictly greater than every
   * generation already in the store. Omit it to take the next consecutive number.
   */
  generation?: number;
  /** Overrides the clock, which tests use to assert `publishedAtMs`. */
  nowMs?: number;
}

// What a `SAML` instance already holds as mandatory options, so its publisher does not ask for it
// a second time. Everything else, including the certificate arguments, stays overridable per
// publication, because rotating those is the whole point.
type SamlBackedPublishParams = Omit<
  PublishServiceProviderMetadataParams,
  keyof Pick<SamlOptions, "issuer" | "callbackUrl">
>;

/**
 * Publishes service provider metadata as recoverable generations. A publication builds the whole
 * document — its certificate material, its signature when `signMetadata` is set, and its ACS
 * location — before touching the store, and then commits it in one atomic operation. A failure
 * while building leaves the previous generation untouched, so a retry or a restart can only ever
 * serve a complete old document or a complete new one, never a mixture of the two.
 */
export class ServiceProviderMetadataPublisher {
  constructor(private readonly store: MetadataStore = new InMemoryMetadataStore()) {}

  /**
   * Builds and commits one metadata generation. The document is built in full before the store is
   * touched, so any error — an invalid certificate, a failed signature, anything — leaves the
   * currently published generation exactly as it was.
   */
  async publishAsync(
    params: PublishServiceProviderMetadataParams,
  ): Promise<PublishedServiceProviderMetadata> {
    const latest = await this.store.getLatestAsync();
    const generation = params.generation ?? (latest == null ? 1 : latest.generation + 1);

    if (!Number.isInteger(generation) || generation < 1) {
      throw new TypeError("metadata generation must be a positive integer");
    }
    if (latest != null && generation <= latest.generation) {
      throw new Error(
        `metadata generation ${generation} is not newer than the published generation ${
          latest.generation
        }`,
      );
    }

    // Build everything before committing: this is the boundary no partial publication can cross.
    const metadataXml = generateServiceProviderMetadata(params);
    const record: PublishedServiceProviderMetadata = {
      generation,
      metadataXml,
      fingerprint: fingerprintOf(metadataXml),
      publishedAtMs: params.nowMs ?? Date.now(),
    };

    return this.store.saveIfNewerAsync(record);
  }

  /**
   * Returns the complete metadata document of the latest generation, or `null` before the first.
   */
  async getLatestAsync(): Promise<PublishedServiceProviderMetadata | null> {
    return this.store.getLatestAsync();
  }

  /** Returns the complete metadata document of a named generation, or `null` when it is absent. */
  async getByGenerationAsync(
    generation: number,
  ): Promise<PublishedServiceProviderMetadata | null> {
    return this.store.getByGenerationAsync(generation);
  }

  /**
   * Publishes one generation built on a `SAML` instance's own options. The instance's issuer, ACS
   * location, signing key and every other fixed option come from the instance, so a publication
   * cannot silently carry material that differs from what the instance validates and signs with.
   * Per-generation arguments only override what a rotation changes, such as the certificates.
   */
  async publishForSamlOptionsAsync(
    samlOptions: SamlOptions,
    params: SamlBackedPublishParams = {},
  ): Promise<PublishedServiceProviderMetadata> {
    return this.publishAsync({ ...samlOptions, ...params });
  }
}
