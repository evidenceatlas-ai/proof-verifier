import {
  Uint8ArrayReader,
  Uint8ArrayWriter,
  ZipReader,
  configure,
} from "@zip.js/zip.js/index-native.js";
import { canonicalJsonBytes, sha256Hex } from "@reviewedproof/hashing";

import {
  canonicalSchemaBytes,
  validateSchema,
  type CanonicalSchemaName,
} from "./schemas";

export const MAX_ARCHIVE_BYTES = 20 * 1024 * 1024;
export const MAX_COMPONENT_BYTES = 10 * 1024 * 1024;
export const MAX_EXPANDED_BYTES = 50 * 1024 * 1024;
export const MAX_ARCHIVE_MEMBERS = 502;

const MAX_COMPRESSION_RATIO = 100;
const EOCD_LENGTH = 22;
const EOCD_SIGNATURE = 0x0605_4b50;
const CENTRAL_SIGNATURE = 0x0201_4b50;
const ZIP64_LOCATOR_SIGNATURE = 0x0706_4b50;
const ZIP64_EXTRA = 0x0001;
const MANIFEST_PATH = "META-INF/bundle-manifest.json";
const MANIFEST_JWS_PATH = "META-INF/bundle-manifest.jws";
const EVENT_JSON = /^evidence\/lifecycle\/events\/([0-9]{4})\.json$/;
const STATEMENT =
  /^trust\/operational-key-statements\/([A-Za-z0-9][A-Za-z0-9._-]{0,127})\.(json|jws)$/;
const COMMON_BUNDLE_SCHEMA_NAMES = [
  "common.v1.schema.json",
  "operational-key-statement.v1.schema.json",
  "package-manifest.v1.schema.json",
  "status-snapshot.v1.schema.json",
  "timestamp-evidence.v1.schema.json",
] as const;
export type BundleVersion = "rproof.bundle-manifest.v1" | "rproof.bundle-manifest.v2" | "rproof.bundle-manifest.v3";
export interface BundleProfile {
  readonly bundleVersion: BundleVersion;
  readonly manifestSchemaName: CanonicalSchemaName;
  readonly attestationSchemaVersion: "rproof.attestation.v1" | "rproof.attestation.v2" | "rproof.attestation.v3";
  readonly attestationSchemaName: CanonicalSchemaName;
  readonly protectedHeaderSchemaName: CanonicalSchemaName;
  readonly schemaNames: readonly CanonicalSchemaName[];
}
const BUNDLE_PROFILES: Readonly<Record<BundleVersion, BundleProfile>> = {
  "rproof.bundle-manifest.v1": bundleProfile(
    "rproof.bundle-manifest.v1",
    "bundle-manifest.v1.schema.json",
    "rproof.attestation.v1",
    "attestation.v1.schema.json",
    "jws-protected-header.v1.schema.json",
  ),
  "rproof.bundle-manifest.v2": bundleProfile(
    "rproof.bundle-manifest.v2",
    "bundle-manifest.v2.schema.json",
    "rproof.attestation.v2",
    "attestation.v2.schema.json",
    "jws-protected-header.v2.schema.json",
  ),
  "rproof.bundle-manifest.v3": bundleProfile(
    "rproof.bundle-manifest.v3",
    "bundle-manifest.v3.schema.json",
    "rproof.attestation.v3",
    "attestation.v3.schema.json",
    "jws-protected-header.v3.schema.json",
  ),
};
const ALL_PROFILE_SCHEMA_NAMES = new Set(
  Object.values(BUNDLE_PROFILES).flatMap((profile) => profile.schemaNames),
);
const BASE_PATHS = new Set([
  "README.txt",
  "evidence/lifecycle/status-snapshot.json",
  "evidence/lifecycle/status-snapshot.jws",
  "evidence/timestamp/attestation.tsr",
  "evidence/timestamp/evidence.json",
  "evidence/timestamp/tsa-chain.pem",
  "package/manifest.json",
  "receipt/attestation.json",
  "receipt/attestation.jws",
  "receipt/human-receipt.pdf",
  "trust/root-fingerprint.txt",
  "trust/root-public-key.jwk",
]);
const FIXED_MEDIA_TYPES = new Map([
  ["README.txt", "text/plain; charset=utf-8"],
  ["evidence/timestamp/attestation.tsr", "application/timestamp-reply"],
  ["evidence/timestamp/tsa-chain.pem", "application/pem-certificate-chain"],
  ["receipt/human-receipt.pdf", "application/pdf"],
  ["trust/root-fingerprint.txt", "text/plain; charset=utf-8"],
]);
const decoder = new TextDecoder("utf-8", { fatal: true });

configure({
  transferStreams: false,
  useCompressionStream: true,
  useWebWorkers: false,
});

export class BundleSafetyError extends Error {
  readonly checkName = "archive_safety";

  constructor(message: string) {
    super(message);
    this.name = "BundleSafetyError";
  }
}

export class BundleValidationError extends Error {
  readonly checkName: string;

  constructor(message: string, checkName = "bundle_manifest") {
    super(message);
    this.name = "BundleValidationError";
    this.checkName = checkName;
  }
}

export class BundleIncompleteError extends BundleValidationError {
  constructor(message: string, checkName?: string) {
    super(message, checkName);
    this.name = "BundleIncompleteError";
  }
}

export class BundleUnsupportedError extends BundleValidationError {
  constructor(message: string, checkName?: string) {
    super(message, checkName);
    this.name = "BundleUnsupportedError";
  }
}

export interface ParsedRproofBundle {
  readonly archiveBytes: Uint8Array;
  readonly manifest: Readonly<Record<string, unknown>>;
  readonly manifestBytes: Uint8Array;
  readonly manifestJws: Uint8Array;
  readonly components: ReadonlyMap<string, Uint8Array>;
  readonly profile: BundleProfile;
}

interface CentralEntry {
  readonly compressedSize: number;
  readonly path: string;
  readonly rawPath: Uint8Array;
  readonly uncompressedSize: number;
}

interface ComponentDescriptor {
  readonly byte_length: number;
  readonly media_type: string;
  readonly path: string;
  readonly sha256: string;
}

/** Parse one bounded supported `.rproof` archive entirely in memory. */
export async function parseRproofBundle(input: Uint8Array): Promise<ParsedRproofBundle> {
  if (!(input instanceof Uint8Array) || input.byteLength === 0) {
    throw new BundleSafetyError("bundle must be non-empty bytes");
  }
  if (input.byteLength > MAX_ARCHIVE_BYTES) {
    throw new BundleSafetyError("bundle exceeds 20 MiB compressed limit");
  }

  const archiveBytes = new Uint8Array(input);
  const centralEntries = scanCentralDirectory(archiveBytes);
  const components = await readMembers(archiveBytes, centralEntries);
  const manifestBytes = components.get(MANIFEST_PATH);
  const manifestJws = components.get(MANIFEST_JWS_PATH);
  if (manifestBytes === undefined || manifestJws === undefined) {
    throw new BundleIncompleteError("bundle manifest JSON/JWS pair is required");
  }
  components.delete(MANIFEST_PATH);
  components.delete(MANIFEST_JWS_PATH);

  const profile = manifestBundleProfile(manifestBytes);
  const manifest = canonicalManifest(manifestBytes, profile);
  await validateManifestBindings(manifest, components);
  validateComponentLayout(components, profile);
  return {
    archiveBytes,
    components,
    manifest,
    manifestBytes,
    manifestJws,
    profile,
  };
}

function scanCentralDirectory(data: Uint8Array): readonly CentralEntry[] {
  if (data.byteLength < EOCD_LENGTH) {
    throw new BundleSafetyError("bundle has no valid ZIP end record");
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const eocdOffset = data.byteLength - EOCD_LENGTH;
  if (view.getUint32(eocdOffset, true) !== EOCD_SIGNATURE) {
    throw new BundleSafetyError("bundle has no unambiguous ZIP end record");
  }
  if (
    eocdOffset >= 20 &&
    view.getUint32(eocdOffset - 20, true) === ZIP64_LOCATOR_SIGNATURE
  ) {
    throw new BundleSafetyError("Zip64 bundles are not supported");
  }

  const disk = view.getUint16(eocdOffset + 4, true);
  const centralDisk = view.getUint16(eocdOffset + 6, true);
  const diskEntries = view.getUint16(eocdOffset + 8, true);
  const totalEntries = view.getUint16(eocdOffset + 10, true);
  const centralSize = view.getUint32(eocdOffset + 12, true);
  const centralStart = view.getUint32(eocdOffset + 16, true);
  const commentLength = view.getUint16(eocdOffset + 20, true);
  if (commentLength !== 0) {
    throw new BundleSafetyError("bundle ZIP comment is not supported");
  }
  if (disk !== 0 || centralDisk !== 0 || diskEntries !== totalEntries) {
    throw new BundleSafetyError("split ZIP bundles are not supported");
  }
  if (
    diskEntries === 0xffff ||
    centralSize === 0xffff_ffff ||
    centralStart === 0xffff_ffff
  ) {
    throw new BundleSafetyError("Zip64 bundles are not supported");
  }
  if (totalEntries > MAX_ARCHIVE_MEMBERS) {
    throw new BundleSafetyError("bundle contains too many members");
  }
  if (centralStart + centralSize !== eocdOffset) {
    throw new BundleSafetyError("bundle central-directory bounds are inconsistent");
  }

  const entries: CentralEntry[] = [];
  const seen = new Set<string>();
  const seenCaseless = new Set<string>();
  let declaredTotal = 0;
  let cursor = centralStart;
  while (cursor < eocdOffset) {
    if (entries.length >= MAX_ARCHIVE_MEMBERS || cursor + 46 > eocdOffset) {
      throw new BundleSafetyError("bundle contains too many or malformed members");
    }
    if (view.getUint32(cursor, true) !== CENTRAL_SIGNATURE) {
      throw new BundleSafetyError("bundle central directory is malformed");
    }
    const flags = view.getUint16(cursor + 8, true);
    const compressionMethod = view.getUint16(cursor + 10, true);
    const compressedSize = view.getUint32(cursor + 20, true);
    const uncompressedSize = view.getUint32(cursor + 24, true);
    const pathLength = view.getUint16(cursor + 28, true);
    const extraLength = view.getUint16(cursor + 30, true);
    const memberCommentLength = view.getUint16(cursor + 32, true);
    const diskStart = view.getUint16(cursor + 34, true);
    const externalAttributes = view.getUint32(cursor + 38, true);
    const localHeaderOffset = view.getUint32(cursor + 42, true);
    const entryEnd = cursor + 46 + pathLength + extraLength + memberCommentLength;
    if (entryEnd > eocdOffset) {
      throw new BundleSafetyError("bundle central directory is malformed");
    }
    if (
      compressedSize === 0xffff_ffff ||
      uncompressedSize === 0xffff_ffff ||
      localHeaderOffset === 0xffff_ffff
    ) {
      throw new BundleSafetyError("Zip64 bundle members are not supported");
    }
    rejectZip64Extra(data.subarray(cursor + 46 + pathLength, cursor + 46 + pathLength + extraLength));
    if (diskStart !== 0) {
      throw new BundleSafetyError("split ZIP bundles are not supported");
    }
    if ((flags & 1) !== 0) {
      throw new BundleSafetyError("encrypted bundle members are not supported");
    }
    if (compressionMethod !== 0 && compressionMethod !== 8) {
      throw new BundleSafetyError("bundle member uses unsupported compression");
    }
    const mode = externalAttributes >>> 16;
    const fileType = mode & 0xf000;
    if ((fileType !== 0 && fileType !== 0x8000) || (mode & 0o111) !== 0) {
      throw new BundleSafetyError("bundle members must be non-executable regular files");
    }
    if (uncompressedSize > MAX_COMPONENT_BYTES) {
      throw new BundleSafetyError("bundle component exceeds 10 MiB limit");
    }
    if (
      uncompressedSize > 0 &&
      (compressedSize === 0 || uncompressedSize > compressedSize * MAX_COMPRESSION_RATIO)
    ) {
      throw new BundleSafetyError("bundle component exceeds 100:1 compression ratio");
    }
    declaredTotal += uncompressedSize;
    if (declaredTotal > MAX_EXPANDED_BYTES) {
      throw new BundleSafetyError("bundle exceeds 50 MiB expanded limit");
    }
    if (localHeaderOffset >= centralStart) {
      throw new BundleSafetyError("bundle member offset is outside the local-file area");
    }

    const rawPath = new Uint8Array(data.subarray(cursor + 46, cursor + 46 + pathLength));
    const path = decodePath(rawPath);
    validatePath(path);
    const caselessPath = path.toUpperCase();
    if (seen.has(path)) {
      throw new BundleSafetyError("bundle contains duplicate paths");
    }
    if (seenCaseless.has(caselessPath)) {
      throw new BundleSafetyError("bundle contains case-colliding paths");
    }
    seen.add(path);
    seenCaseless.add(caselessPath);
    entries.push({ compressedSize, path, rawPath, uncompressedSize });
    cursor = entryEnd;
  }
  if (cursor !== eocdOffset || entries.length !== totalEntries) {
    throw new BundleSafetyError("bundle central-directory count is inconsistent");
  }
  return entries;
}

async function readMembers(
  archiveBytes: Uint8Array,
  expectedEntries: readonly CentralEntry[],
): Promise<Map<string, Uint8Array>> {
  const reader = new ZipReader(new Uint8ArrayReader(archiveBytes), {
    filenameEncoding: "utf-8",
    strictness: "strict",
    useCompressionStream: true,
    useWebWorkers: false,
  });
  try {
    const entries = await reader.getEntries({
      filenameEncoding: "utf-8",
      strictness: "strict",
    });
    if (entries.length !== expectedEntries.length) {
      throw new BundleSafetyError("bundle central-directory count is inconsistent");
    }
    const components = new Map<string, Uint8Array>();
    let actualTotal = 0;
    for (const [index, entry] of entries.entries()) {
      const expected = expectedEntries[index];
      if (
        expected === undefined ||
        entry.filename !== expected.path ||
        !bytesEqual(entry.rawFilename, expected.rawPath) ||
        entry.compressedSize !== expected.compressedSize ||
        entry.uncompressedSize !== expected.uncompressedSize ||
        entry.directory ||
        entry.encrypted ||
        entry.zip64
      ) {
        throw new BundleSafetyError("bundle member metadata is inconsistent");
      }
      const content = await entry.getData(new Uint8ArrayWriter(), {
        checkCrc32: true,
        strictness: "strict",
        useCompressionStream: true,
        useWebWorkers: false,
      });
      if (content.byteLength !== expected.uncompressedSize) {
        throw new BundleSafetyError("bundle member size differs from central directory");
      }
      actualTotal += content.byteLength;
      if (content.byteLength > MAX_COMPONENT_BYTES || actualTotal > MAX_EXPANDED_BYTES) {
        throw new BundleSafetyError("bundle expansion exceeds declared limits");
      }
      components.set(expected.path, new Uint8Array(content));
    }
    return components;
  } catch (error) {
    if (error instanceof BundleSafetyError) {
      throw error;
    }
    throw new BundleSafetyError("bundle is not a readable single-disk ZIP");
  } finally {
    try {
      await reader.close();
    } catch {
      // A read failure above is already reported as an archive-safety failure.
    }
  }
}

function decodePath(rawPath: Uint8Array): string {
  try {
    return decoder.decode(rawPath);
  } catch {
    throw new BundleSafetyError("bundle member path is not valid UTF-8");
  }
}

function validatePath(path: string): void {
  if (
    path.length === 0 ||
    [...path].length > 512 ||
    path.startsWith("/") ||
    path.includes("\\") ||
    path.includes("\0") ||
    path.includes("//") ||
    path.split("/").some((part) => part === "" || part === "." || part === "..") ||
    path.normalize("NFC") !== path
  ) {
    throw new BundleSafetyError("bundle member path is unsafe");
  }
}

function rejectZip64Extra(extra: Uint8Array): void {
  const view = new DataView(extra.buffer, extra.byteOffset, extra.byteLength);
  let cursor = 0;
  while (cursor < extra.byteLength) {
    if (cursor + 4 > extra.byteLength) {
      throw new BundleSafetyError("bundle member extra field is malformed");
    }
    const fieldId = view.getUint16(cursor, true);
    const fieldSize = view.getUint16(cursor + 2, true);
    cursor += 4;
    if (cursor + fieldSize > extra.byteLength) {
      throw new BundleSafetyError("bundle member extra field is malformed");
    }
    if (fieldId === ZIP64_EXTRA) {
      throw new BundleSafetyError("Zip64 bundle members are not supported");
    }
    cursor += fieldSize;
  }
}

function canonicalManifest(
  content: Uint8Array,
  profile: BundleProfile,
): Readonly<Record<string, unknown>> {
  try {
    const value: unknown = JSON.parse(decoder.decode(content));
    if (
      !isRecord(value) ||
      !bytesEqual(canonicalJsonBytes(value), content) ||
      !validateSchema(profile.manifestSchemaName, value)
    ) {
      throw new Error("invalid manifest");
    }
    return value;
  } catch (error) {
    if (error instanceof BundleValidationError) {
      throw error;
    }
    throw new BundleValidationError("bundle manifest does not satisfy its schema");
  }
}

function manifestBundleProfile(content: Uint8Array): BundleProfile {
  try {
    const value: unknown = JSON.parse(decoder.decode(content));
    if (!isRecord(value) || typeof value.schema_version !== "string") {
      throw new BundleValidationError("bundle manifest lacks a schema version");
    }
    if (!Object.hasOwn(BUNDLE_PROFILES, value.schema_version)) {
      throw new BundleUnsupportedError("bundle manifest schema version is unsupported");
    }
    const profile = BUNDLE_PROFILES[value.schema_version as BundleVersion];
    if (profile === undefined) {
      throw new BundleUnsupportedError("bundle manifest schema version is unsupported");
    }
    return profile;
  } catch (error) {
    if (error instanceof BundleValidationError) {
      throw error;
    }
    throw new BundleValidationError("bundle manifest is not valid JSON");
  }
}

async function validateManifestBindings(
  manifest: Readonly<Record<string, unknown>>,
  components: ReadonlyMap<string, Uint8Array>,
): Promise<void> {
  const descriptors = manifest.components as readonly ComponentDescriptor[];
  const paths = descriptors.map((descriptor) => descriptor.path);
  const sortedPaths = [...paths].sort();
  if (!paths.every((path, index) => path === sortedPaths[index])) {
    throw new BundleValidationError("bundle manifest components must be path-sorted");
  }
  if (new Set(paths).size !== paths.length || !sameStringSet(paths, components.keys())) {
    throw new BundleValidationError("bundle manifest must declare every component exactly once");
  }
  for (const descriptor of descriptors) {
    const content = components.get(descriptor.path);
    if (
      content === undefined ||
      descriptor.byte_length !== content.byteLength ||
      descriptor.sha256 !== (await sha256Hex(content))
    ) {
      throw new BundleValidationError(`bundle manifest binding failed for ${descriptor.path}`);
    }
    if (descriptor.media_type !== bundleComponentMediaType(descriptor.path)) {
      throw new BundleValidationError(`bundle manifest media type failed for ${descriptor.path}`);
    }
  }
}

function validateComponentLayout(
  components: ReadonlyMap<string, Uint8Array>,
  profile: BundleProfile,
): void {
  const paths = new Set(components.keys());
  if (![...BASE_PATHS].every((path) => paths.has(path))) {
    throw new BundleIncompleteError("bundle lacks required components");
  }

  const eventPaths = [...paths].filter((path) => EVENT_JSON.test(path)).sort();
  const expectedEvents = eventPaths.map(
    (_, index) => `evidence/lifecycle/events/${String(index + 1).padStart(4, "0")}.json`,
  );
  if (!eventPaths.every((path, index) => path === expectedEvents[index])) {
    throw new BundleValidationError("lifecycle event names must be consecutive from 0001");
  }

  const completionPresent = paths.has("review/completion.json") || paths.has("review/completion.jws");
  if (
    completionPresent &&
    (!paths.has("review/completion.json") || !paths.has("review/completion.jws"))
  ) {
    throw new BundleIncompleteError("review completion must be an exact JSON/JWS pair");
  }

  const statementFiles = new Map<string, Set<string>>();
  for (const path of paths) {
    const match = STATEMENT.exec(path);
    if (match !== null) {
      const kid = match[1];
      const suffix = match[2];
      if (kid !== undefined && suffix !== undefined) {
        const parts = statementFiles.get(kid) ?? new Set<string>();
        parts.add(suffix);
        statementFiles.set(kid, parts);
      }
    }
  }
  if (
    statementFiles.size === 0 ||
    [...statementFiles.values()].some((parts) => !sameStringSet(parts, ["json", "jws"]))
  ) {
    throw new BundleIncompleteError("operational key statements must be exact JSON/JWS pairs");
  }

  const requiredSchemaNames = new Set<string>(profile.schemaNames);
  if (eventPaths.length > 0) {
    requiredSchemaNames.add("lifecycle-event.v1.schema.json");
  }
  if (completionPresent) {
    requiredSchemaNames.add("review-completion.v1.schema.json");
  }
  const schemaPaths = new Set([...paths].filter((path) => path.startsWith("schemas/")));
  const expectedSchemaPaths = new Set(
    [...requiredSchemaNames].map((name) => `schemas/${name}`),
  );
  const unexpectedSchemaNames = [...schemaPaths]
    .map((path) => path.slice("schemas/".length))
    .filter((name) => !requiredSchemaNames.has(name));
  if (unexpectedSchemaNames.some((name) => ALL_PROFILE_SCHEMA_NAMES.has(name as CanonicalSchemaName))) {
    throw new BundleValidationError("bundle mixes supported schema profiles");
  }
  if (![...expectedSchemaPaths].every((path) => schemaPaths.has(path))) {
    throw new BundleIncompleteError("bundle lacks a required schema");
  }
  if (!sameStringSet(schemaPaths, expectedSchemaPaths)) {
    throw new BundleUnsupportedError("bundle carries an unsupported schema");
  }
  for (const name of requiredSchemaNames) {
    const carried = components.get(`schemas/${name}`);
    if (
      carried === undefined ||
      !bytesEqual(carried, canonicalSchemaBytes(name as CanonicalSchemaName))
    ) {
      throw new BundleValidationError(`bundle schema ${name} is not the canonical source`);
    }
  }

  const expectedPaths = new Set([...BASE_PATHS, ...schemaPaths]);
  for (const eventPath of eventPaths) {
    expectedPaths.add(eventPath);
    expectedPaths.add(`${eventPath.slice(0, -5)}.jws`);
  }
  for (const kid of statementFiles.keys()) {
    expectedPaths.add(`trust/operational-key-statements/${kid}.json`);
    expectedPaths.add(`trust/operational-key-statements/${kid}.jws`);
  }
  if (completionPresent) {
    expectedPaths.add("review/completion.json");
    expectedPaths.add("review/completion.jws");
  }
  if (![...expectedPaths].every((path) => paths.has(path))) {
    throw new BundleIncompleteError("bundle contains incomplete components");
  }
  if (!sameStringSet(paths, expectedPaths)) {
    throw new BundleUnsupportedError("bundle contains unsupported components");
  }
}

function bundleComponentMediaType(path: string): string {
  const fixed = FIXED_MEDIA_TYPES.get(path);
  if (fixed !== undefined) {
    return fixed;
  }
  if (path.endsWith(".schema.json")) {
    return "application/schema+json";
  }
  if (path.endsWith(".json") || path.endsWith(".jwk")) {
    return "application/json";
  }
  if (path.endsWith(".jws")) {
    return "application/jose";
  }
  throw new BundleUnsupportedError(`bundle contains unsupported component path ${path}`);
}

function sameStringSet(left: Iterable<string>, right: Iterable<string>): boolean {
  const leftSet = left instanceof Set ? left : new Set(left);
  const rightSet = right instanceof Set ? right : new Set(right);
  return leftSet.size === rightSet.size && [...leftSet].every((item) => rightSet.has(item));
}

function bundleProfile(
  bundleVersion: BundleVersion,
  manifestSchemaName: CanonicalSchemaName,
  attestationSchemaVersion: BundleProfile["attestationSchemaVersion"],
  attestationSchemaName: CanonicalSchemaName,
  protectedHeaderSchemaName: CanonicalSchemaName,
): BundleProfile {
  return {
    attestationSchemaName,
    attestationSchemaVersion,
    bundleVersion,
    manifestSchemaName,
    protectedHeaderSchemaName,
    schemaNames: [
      attestationSchemaName,
      manifestSchemaName,
      ...COMMON_BUNDLE_SCHEMA_NAMES,
      protectedHeaderSchemaName,
    ],
  };
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((value, index) => value === right[index]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
