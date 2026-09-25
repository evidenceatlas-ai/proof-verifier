import canonicalize from "canonicalize";
import { sha256 } from "@noble/hashes/sha256";

const JSON_SAFE_INTEGER = 9_007_199_254_740_991;
const MAX_PACKAGE_ENTRIES = 100;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const BASE64URL_P256_COORDINATE = /^[A-Za-z0-9_-]{43}$/;
const LONE_SURROGATE = /[\uD800-\uDFFF]/u;
const ENTRY_FIELDS = [
  "byte_length",
  "content_hash",
  "entry_id",
  "media_type",
  "name",
  "position",
  "required",
] as const;

type JsonObject = { [key: string]: JsonValue };
type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
type ProofSide = "left" | "right";

export interface AuditNode {
  hash: string;
  side: ProofSide;
}

export interface PackageInclusionProof {
  audit_path: AuditNode[];
  leaf_index: number;
  schema_version: "rproof.package-inclusion-proof.v1";
  tree_size: number;
}

interface PreparedProof {
  auditPath: Array<{ hash: Uint8Array; side: ProofSide }>;
  canonicalEntry: Uint8Array;
}

/** Return RFC 8785 UTF-8 bytes after ReviewedProof JSON input checks. */
export function canonicalJsonBytes(value: unknown): Uint8Array {
  validateJsonValue(value, new Set<object>());
  const result = canonicalize(value);
  if (typeof result !== "string") {
    throw new Error("canonical JSON serialization failed");
  }
  return new TextEncoder().encode(result);
}

/** Hash exact bytes, yielding between bounded fallback chunks when Web Crypto is absent. */
export async function sha256Bytes(data: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
  if (!(data instanceof Uint8Array)) {
    throw new Error("SHA-256 input must be a Uint8Array");
  }
  signal?.throwIfAborted();
  if (typeof globalThis.crypto?.subtle?.digest === "function") {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", new Uint8Array(data));
    signal?.throwIfAborted();
    return new Uint8Array(digest);
  }
  const hash = sha256.create();
  const chunkBytes = 256 * 1024;
  try {
    for (let offset = 0; offset < data.length; offset += chunkBytes) {
      signal?.throwIfAborted();
      hash.update(data.subarray(offset, offset + chunkBytes));
      if (offset + chunkBytes < data.length) {
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
      }
    }
    signal?.throwIfAborted();
    return hash.digest();
  } finally {
    hash.destroy();
  }
}

/** Hash exact input bytes as lowercase hexadecimal. */
export async function sha256Hex(data: Uint8Array, signal?: AbortSignal): Promise<string> {
  return bytesToHex(await sha256Bytes(data, signal));
}

/** Hash RFC 8785 bytes for one JSON value. */
export async function canonicalSha256Hex(value: unknown): Promise<string> {
  return sha256Hex(canonicalJsonBytes(value));
}

/** Hash one validated package entry with the RFC 6962 leaf prefix. */
export async function packageEntryLeafHash(entry: unknown): Promise<string> {
  return bytesToHex(await leafHash(canonicalJsonBytes(validateEntry(entry))));
}

/** Calculate package root after ordering entries by explicit position. */
export async function packageRoot(entries: readonly unknown[]): Promise<string> {
  return bytesToHex(await merkleTreeHash(orderedCanonicalEntries(entries)));
}

/** Hash exact supplied manifest JSON; its consumer validates schema and bindings. */
export async function packageManifestDigest(manifest: unknown): Promise<string> {
  return canonicalSha256Hex(manifest);
}

/** Create bottom-up RFC 6962 proof for a position-ordered package. */
export async function createPackageInclusionProof(
  entries: readonly unknown[],
  leafIndex: number,
): Promise<PackageInclusionProof> {
  const canonicalEntries = orderedCanonicalEntries(entries);
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= canonicalEntries.length) {
    throw new Error("leafIndex must identify an entry");
  }

  return {
    audit_path: await inclusionPath(canonicalEntries, leafIndex),
    leaf_index: leafIndex,
    schema_version: "rproof.package-inclusion-proof.v1",
    tree_size: canonicalEntries.length,
  };
}

/**
 * Verify against root and entry count supplied by the trusted frozen manifest.
 * A proof's own tree_size does not authenticate either trusted value.
 */
export async function verifyPackageInclusionProof(
  entry: unknown,
  proof: unknown,
  expectedRoot: string,
  expectedTreeSize: number,
): Promise<boolean> {
  const prepared = prepareProof(entry, proof, expectedRoot, expectedTreeSize);
  if (prepared === null) {
    return false;
  }

  let current = await leafHash(prepared.canonicalEntry);
  for (const node of prepared.auditPath) {
    current =
      node.side === "left"
        ? await nodeHash(node.hash, current)
        : await nodeHash(current, node.hash);
  }

  return bytesToHex(current) === expectedRoot;
}

/** Calculate ReviewedProof's RFC 7638-derived P-256 fingerprint. */
export async function p256FingerprintSha256(jwk: unknown): Promise<string> {
  if (!isPlainObject(jwk)) {
    throw new Error("P-256 JWK must be a plain object");
  }

  const projected: JsonObject = {};
  for (const field of ["crv", "kty", "x", "y"] as const) {
    const value = jwk[field];
    if (typeof value !== "string") {
      throw new Error(`P-256 JWK ${field} must be a string`);
    }
    projected[field] = value;
  }

  if (projected.crv !== "P-256" || projected.kty !== "EC") {
    throw new Error("unsupported JWK key type or curve");
  }
  for (const field of ["x", "y"] as const) {
    const value = projected[field];
    if (typeof value !== "string" || !BASE64URL_P256_COORDINATE.test(value)) {
      throw new Error(
        `P-256 JWK ${field} must be an unpadded 32-byte base64url value`,
      );
    }
  }

  return canonicalSha256Hex(projected);
}

function validateJsonValue(value: unknown, activeContainers: Set<object>): asserts value is JsonValue {
  if (value === null || typeof value === "boolean") {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Math.abs(value) > JSON_SAFE_INTEGER) {
      throw new Error("JSON numbers must be safe integers");
    }
    return;
  }
  if (typeof value === "string") {
    if (LONE_SURROGATE.test(value)) {
      throw new Error("JSON strings and object keys must not contain lone Unicode surrogates");
    }
    if (value.normalize("NFC") !== value) {
      throw new Error("JSON strings and object keys must use Unicode NFC");
    }
    return;
  }
  if (typeof value !== "object") {
    throw new Error(
      "canonical JSON accepts only null, booleans, integers, strings, arrays, and objects",
    );
  }
  if (activeContainers.has(value)) {
    throw new Error("canonical JSON cannot contain cycles");
  }

  activeContainers.add(value);
  try {
    if (Array.isArray(value)) {
      validateJsonArray(value, activeContainers);
      return;
    }
    if (!isPlainObject(value)) {
      throw new Error("canonical JSON objects must be plain objects");
    }
    if (typeof value.toJSON === "function") {
      throw new Error("canonical JSON objects must not define toJSON functions");
    }
    validateJsonObject(value, activeContainers);
  } finally {
    activeContainers.delete(value);
  }
}

function validateJsonArray(value: unknown[], activeContainers: Set<object>): void {
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) {
      throw new Error("canonical JSON arrays must not contain empty slots");
    }
    validateJsonValue(value[index], activeContainers);
  }

  for (const key of Reflect.ownKeys(value)) {
    if (key === "length") {
      continue;
    }
    if (
      typeof key !== "string" ||
      !/^(?:0|[1-9][0-9]*)$/.test(key) ||
      Number(key) >= value.length
    ) {
      throw new Error("canonical JSON arrays must not have non-index properties");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
      throw new Error("canonical JSON arrays must contain enumerable data values");
    }
  }
}

function validateJsonObject(
  value: Record<string, unknown>,
  activeContainers: Set<object>,
): void {
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      throw new Error("JSON object keys must be strings");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
      throw new Error("canonical JSON objects must contain enumerable data properties");
    }
    validateJsonValue(key, activeContainers);
    validateJsonValue(descriptor.value, activeContainers);
  }
}

function validateEntry(entry: unknown): JsonObject {
  if (!isPlainObject(entry) || !hasExactFields(entry, ENTRY_FIELDS)) {
    throw new Error("package entry fields must match rproof.package-manifest.v1 exactly");
  }
  validateJsonValue(entry, new Set<object>());

  const byteLength = entry.byte_length;
  const position = entry.position;
  if (!Number.isSafeInteger(byteLength) || (byteLength as number) < 0) {
    throw new Error("package entry byte_length must be a non-negative integer");
  }
  if (!Number.isSafeInteger(position) || (position as number) < 0) {
    throw new Error("package entry position must be a non-negative integer");
  }
  if (typeof entry.required !== "boolean") {
    throw new Error("package entry required must be a boolean");
  }

  for (const field of ["entry_id", "media_type"] as const) {
    if (typeof entry[field] !== "string" || entry[field].length === 0) {
      throw new Error(`package entry ${field} must be a non-empty string`);
    }
  }
  if (entry.name !== null && (typeof entry.name !== "string" || entry.name.length === 0)) {
    throw new Error("package entry name must be a non-empty string or explicit null");
  }

  const contentHash = entry.content_hash;
  if (!isPlainObject(contentHash) || !hasExactFields(contentHash, ["algorithm", "value"])) {
    throw new Error("package entry content_hash fields are invalid");
  }
  if (contentHash.algorithm !== "sha-256") {
    throw new Error("unsupported package content hash algorithm");
  }
  if (typeof contentHash.value !== "string" || !SHA256_HEX.test(contentHash.value)) {
    throw new Error("package content hash must be 64 lowercase hexadecimal characters");
  }

  return entry;
}

function orderedCanonicalEntries(entries: readonly unknown[]): Uint8Array[] {
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > MAX_PACKAGE_ENTRIES) {
    throw new Error("package must contain between 1 and 100 entries");
  }
  const validated = entries.map((entry) => validateEntry(entry));
  const ordered = [...validated].sort(
    (left, right) => (left.position as number) - (right.position as number),
  );
  if (ordered.some((entry, index) => entry.position !== index)) {
    throw new Error("package positions must be unique and consecutive from zero");
  }
  return ordered.map((entry) => canonicalJsonBytes(entry));
}

async function leafHash(canonicalEntry: Uint8Array): Promise<Uint8Array> {
  return sha256Bytes(concatBytes(Uint8Array.of(0), canonicalEntry));
}

async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256Bytes(concatBytes(Uint8Array.of(1), left, right));
}

function largestPowerOfTwoBelow(size: number): number {
  let result = 1;
  while (result * 2 < size) {
    result *= 2;
  }
  return result;
}

async function merkleTreeHash(canonicalEntries: readonly Uint8Array[]): Promise<Uint8Array> {
  if (canonicalEntries.length === 0) {
    return sha256Bytes(new Uint8Array());
  }
  if (canonicalEntries.length === 1) {
    return leafHash(canonicalEntries[0] as Uint8Array);
  }
  const split = largestPowerOfTwoBelow(canonicalEntries.length);
  const [left, right] = await Promise.all([
    merkleTreeHash(canonicalEntries.slice(0, split)),
    merkleTreeHash(canonicalEntries.slice(split)),
  ]);
  return nodeHash(left, right);
}

async function inclusionPath(
  canonicalEntries: readonly Uint8Array[],
  leafIndex: number,
): Promise<AuditNode[]> {
  if (canonicalEntries.length === 1) {
    return [];
  }
  const split = largestPowerOfTwoBelow(canonicalEntries.length);
  if (leafIndex < split) {
    const [path, sibling] = await Promise.all([
      inclusionPath(canonicalEntries.slice(0, split), leafIndex),
      merkleTreeHash(canonicalEntries.slice(split)),
    ]);
    return [...path, { hash: bytesToHex(sibling), side: "right" }];
  }

  const [path, sibling] = await Promise.all([
    inclusionPath(canonicalEntries.slice(split), leafIndex - split),
    merkleTreeHash(canonicalEntries.slice(0, split)),
  ]);
  return [...path, { hash: bytesToHex(sibling), side: "left" }];
}

function inclusionSides(leafIndex: number, treeSize: number): ProofSide[] {
  if (treeSize === 1) {
    return [];
  }
  const split = largestPowerOfTwoBelow(treeSize);
  if (leafIndex < split) {
    return [...inclusionSides(leafIndex, split), "right"];
  }
  return [...inclusionSides(leafIndex - split, treeSize - split), "left"];
}

function prepareProof(
  entry: unknown,
  proof: unknown,
  expectedRoot: string,
  expectedTreeSize: number,
): PreparedProof | null {
  try {
    const validatedEntry = validateEntry(entry);
    if (!isPlainObject(proof)) {
      return null;
    }
    validateJsonValue(proof, new Set<object>());
    if (!hasExactFields(proof, ["audit_path", "leaf_index", "schema_version", "tree_size"])) {
      return null;
    }
    if (proof.schema_version !== "rproof.package-inclusion-proof.v1") {
      return null;
    }

    const leafIndex = proof.leaf_index;
    const treeSize = proof.tree_size;
    if (!Number.isSafeInteger(leafIndex) || !Number.isSafeInteger(treeSize)) {
      return null;
    }
    if (
      (treeSize as number) < 1 ||
      (treeSize as number) > MAX_PACKAGE_ENTRIES ||
      (leafIndex as number) < 0 ||
      (leafIndex as number) >= (treeSize as number)
    ) {
      return null;
    }
    if (!Number.isSafeInteger(expectedTreeSize) || treeSize !== expectedTreeSize) {
      return null;
    }
    if (validatedEntry.position !== leafIndex) {
      return null;
    }
    if (typeof expectedRoot !== "string" || !SHA256_HEX.test(expectedRoot)) {
      return null;
    }

    const auditPath = proof.audit_path;
    if (!Array.isArray(auditPath)) {
      return null;
    }
    const expectedSides = inclusionSides(leafIndex as number, treeSize as number);
    if (auditPath.length !== expectedSides.length) {
      return null;
    }

    const preparedPath: PreparedProof["auditPath"] = [];
    for (let index = 0; index < auditPath.length; index += 1) {
      const node = auditPath[index];
      const expectedSide = expectedSides[index];
      if (expectedSide === undefined) {
        return null;
      }
      if (!isPlainObject(node) || !hasExactFields(node, ["hash", "side"])) {
        return null;
      }
      if (
        typeof node.hash !== "string" ||
        !SHA256_HEX.test(node.hash) ||
        node.side !== expectedSide
      ) {
        return null;
      }
      preparedPath.push({ hash: hexToBytes(node.hash), side: expectedSide });
    }

    return {
      auditPath: preparedPath,
      canonicalEntry: canonicalJsonBytes(validatedEntry),
    };
  } catch {
    return null;
  }
}

function hasExactFields(
  value: Record<string, unknown>,
  expectedFields: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...expectedFields].sort();
  return actual.length === expected.length && actual.every((field, index) => field === expected[index]);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value: string): Uint8Array {
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}
