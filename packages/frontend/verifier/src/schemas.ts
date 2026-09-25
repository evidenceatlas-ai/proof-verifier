import {
  canonicalSchemaSources,
  schemaValidators,
} from "./generated/schema-validators";

export const CANONICAL_SCHEMA_NAMES = [
  "attestation.v1.schema.json",
  "attestation.v2.schema.json",
  "attestation.v3.schema.json",
  "bundle-manifest.v1.schema.json",
  "bundle-manifest.v2.schema.json",
  "bundle-manifest.v3.schema.json",
  "common.v1.schema.json",
  "jws-protected-header.v1.schema.json",
  "jws-protected-header.v2.schema.json",
  "jws-protected-header.v3.schema.json",
  "key-distrust-event.v1.schema.json",
  "lifecycle-event.v1.schema.json",
  "operational-key-statement.v1.schema.json",
  "package-manifest.v1.schema.json",
  "review-completion.v1.schema.json",
  "status-snapshot.v1.schema.json",
  "timestamp-evidence.v1.schema.json",
  "trust-store.v1.schema.json",
  "verification-result.v1.schema.json",
] as const;

export type CanonicalSchemaName = (typeof CANONICAL_SCHEMA_NAMES)[number];

interface StandaloneValidator {
  (value: unknown): boolean;
}

const validators = schemaValidators as Record<CanonicalSchemaName, StandaloneValidator>;
const sources = canonicalSchemaSources as Record<CanonicalSchemaName, string>;

/** Return a fresh copy of exact UTF-8 schema source embedded at build time. */
export function canonicalSchemaBytes(name: CanonicalSchemaName): Uint8Array {
  return new TextEncoder().encode(sources[name]);
}

/** Run a build-generated JSON Schema validator without runtime code generation. */
export function validateSchema(name: CanonicalSchemaName, value: unknown): boolean {
  return validators[name](value);
}
