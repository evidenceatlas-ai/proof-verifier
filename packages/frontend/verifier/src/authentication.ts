import {
  canonicalJsonBytes,
  p256FingerprintSha256,
  packageRoot,
  sha256Hex,
} from "@reviewedproof/hashing";

import {
  BundleIncompleteError,
  BundleUnsupportedError,
  BundleValidationError,
  parseRproofBundle,
  type ParsedRproofBundle,
} from "./archive";
import { validateSchema, type CanonicalSchemaName } from "./schemas";
import {
  authenticateArchivedTimestamp,
  parsePortableUtcTime,
  TimestampUnsupportedError,
  TimestampVerificationError,
  type AuthenticatedTimestamp,
  type PortableUtcInstant,
  type TimestampEvidence,
  type TsaPolicy,
} from "./timestamp";

const MANIFEST_PATH = "META-INF/bundle-manifest.json";
const MANIFEST_JWS_PATH = "META-INF/bundle-manifest.jws";
const ATTESTATION_PATH = "receipt/attestation.json";
const STATUS_PATH = "evidence/lifecycle/status-snapshot.json";
const COMPLETION_PATH = "review/completion.json";
const STATEMENT_PREFIX = "trust/operational-key-statements/";
const EVENT_PATH = /^evidence\/lifecycle\/events\/\d{4}\.json$/;
const STATEMENT_PATH =
  /^trust\/operational-key-statements\/([A-Za-z0-9][A-Za-z0-9._-]{0,127})\.json$/;
const SHA256_LINE = /^sha256:([0-9a-f]{64})\n$/;
const MAX_PACKAGE_BYTES = 200_000_000;
const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const utf8 = new TextDecoder("utf-8", { fatal: true });

const RECORD_PROFILES = {
  "rproof.attestation.v1": {
    cty: "application/rproof-attestation+json",
    purpose: "attestation-signing",
    typ: "application/rproof-attestation+jws",
  },
  "rproof.attestation.v2": {
    cty: "application/rproof-attestation+json",
    purpose: "attestation-signing",
    typ: "application/rproof-attestation+jws",
  },
  "rproof.attestation.v3": {
    cty: "application/rproof-attestation+json",
    purpose: "attestation-signing",
    typ: "application/rproof-attestation+jws",
  },
  "rproof.bundle-manifest.v1": {
    cty: "application/rproof-bundle-manifest+json",
    purpose: "bundle-signing",
    typ: "application/rproof-bundle-manifest+jws",
  },
  "rproof.bundle-manifest.v2": {
    cty: "application/rproof-bundle-manifest+json",
    purpose: "bundle-signing",
    typ: "application/rproof-bundle-manifest+jws",
  },
  "rproof.bundle-manifest.v3": {
    cty: "application/rproof-bundle-manifest+json",
    purpose: "bundle-signing",
    typ: "application/rproof-bundle-manifest+jws",
  },
  "rproof.lifecycle-event.v1": {
    cty: "application/rproof-lifecycle-event+json",
    purpose: "lifecycle-status-signing",
    typ: "application/rproof-lifecycle-event+jws",
  },
  "rproof.review-completion.v1": {
    cty: "application/rproof-review-completion+json",
    purpose: "lifecycle-status-signing",
    typ: "application/rproof-review-completion+jws",
  },
  "rproof.status-snapshot.v1": {
    cty: "application/rproof-status-snapshot+json",
    purpose: "lifecycle-status-signing",
    typ: "application/rproof-status-snapshot+jws",
  },
} as const;

const SUPPORTED_SIGNED_SCHEMA_VERSIONS = new Set<string>([
  ...Object.keys(RECORD_PROFILES),
  "rproof.key-distrust-event.v1",
  "rproof.operational-key-statement.v1",
  "rproof.package-manifest.v1",
  "rproof.timestamp-evidence.v1",
]);

type RecordSchemaVersion = keyof typeof RECORD_PROFILES;
type JsonRecord = Readonly<Record<string, unknown>>;

interface TrustStoreView extends JsonRecord {
  readonly environment: string;
  readonly reviewedproof_roots: readonly RootEntryView[];
  readonly trust_store_version: string;
  readonly tsa_policies: readonly TsaPolicy[];
}

interface RootEntryView extends JsonRecord {
  readonly fingerprint_sha256: string;
  readonly jwk: JsonRecord;
  readonly kid: string;
  readonly not_after: string | null;
  readonly not_before: string;
  readonly operational_key_distrust_events: readonly DistrustEntryView[];
  readonly status: string;
}

interface DistrustEntryView extends JsonRecord {
  readonly event: DistrustEventView;
  readonly jws: string;
}

interface DistrustEventView extends JsonRecord {
  readonly affected_key_statement_sha256: string;
  readonly affected_kid: string;
  readonly affected_signing_time_range: {
    readonly from: string;
    readonly through: string | null;
  };
  readonly effective_at: string;
  readonly environment: string;
  readonly event_id: string;
  readonly previous_distrust_event_sha256: string | null;
  readonly recorded_at: string;
  readonly sequence: number;
}

interface OperationalStatementView extends JsonRecord {
  readonly environment: string;
  readonly jwk: JsonRecord;
  readonly kid: string;
  readonly not_after: string;
  readonly not_before: string;
  readonly purpose: string;
  readonly root_fingerprint_sha256: string;
}

interface PackageView extends JsonRecord {
  readonly entries: readonly JsonRecord[];
  readonly entry_count: number;
  readonly package_root: string;
}

interface AttestationView extends JsonRecord {
  readonly completed_at: string;
  readonly expires_at?: string | null;
  readonly identity_assurance: { readonly assessed_at: string };
  readonly manifest_digest: { readonly value: string };
  readonly package_root: { readonly value: string };
  readonly receipt_id: string;
}

interface ParsedCompactJws {
  readonly kid: string;
  readonly signature: Uint8Array;
  readonly signingInput: Uint8Array;
}

export interface SignedRecordReference {
  readonly path: string;
  readonly jwsPath: string;
  readonly schemaVersion: RecordSchemaVersion;
  readonly purpose: string;
  readonly kid: string;
}

export interface AuthenticatedOperationalKey {
  readonly kid: string;
  readonly purpose: string;
  readonly environment: string;
  readonly publicJwk: JsonRecord;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly statementSha256: string;
}

export interface AuthenticatedRproof {
  readonly parsed: ParsedRproofBundle;
  readonly records: readonly SignedRecordReference[];
  readonly operationalKeys: ReadonlyMap<string, AuthenticatedOperationalKey>;
  readonly root: JsonRecord;
  readonly operationalKeyDistrustEvents: readonly JsonRecord[];
  readonly packageManifest: JsonRecord;
  readonly attestation: JsonRecord;
  readonly timestamp: AuthenticatedTimestamp;
  readonly trustStoreVersion: string;
  readonly trustStoreSha256: string;
  readonly environment: string;
}

export interface AuthenticateRproofOptions {
  readonly trustStoreBytes: Uint8Array;
  readonly verifiedAt: string;
  readonly allowNonProduction?: boolean;
}

export class AuthenticationPolicyError extends Error {
  readonly checkName: string;

  constructor(message: string, checkName = "operational_key_statements", options?: ErrorOptions) {
    super(message, options);
    this.name = "AuthenticationPolicyError";
    this.checkName = checkName;
  }
}

export class EvidenceAuthenticationError extends Error {
  readonly checkName: string;

  constructor(message: string, checkName: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EvidenceAuthenticationError";
    this.checkName = checkName;
  }
}

/** Authenticate the non-lifecycle prefix of the mandatory portable pipeline. */
export async function authenticateRproof(
  archiveBytes: Uint8Array,
  {
    trustStoreBytes,
    verifiedAt,
    allowNonProduction = false,
  }: AuthenticateRproofOptions,
): Promise<AuthenticatedRproof> {
  requireWholeSecondVerificationTime(verifiedAt);
  requireNativeJwsCrypto("operational_key_statements");
  const parsed = await parseRproofBundle(archiveBytes);

  const trustStore = parseTrustStore(trustStoreBytes);
  const environment = trustStore.environment;
  if (environment !== "production" && !allowNonProduction) {
    throw new AuthenticationPolicyError(
      "non-production evidence requires explicit test-mode policy",
    );
  }
  const root = await selectRoot(parsed, trustStore);
  const tsaPolicy = selectTsaPolicy(parsed, trustStore);
  const distrustEvents = await authenticateDistrustEvents(root, environment);

  const records = discoverSignedRecords(parsed);
  const layout = await validateOperationalKeyLayout(parsed, records);
  if (
    layout.rootKid !== root.kid ||
    layout.environment !== environment ||
    layout.rootFingerprint !== root.fingerprint_sha256
  ) {
    throw new AuthenticationPolicyError(
      "bundle signing authority does not match external trust policy",
    );
  }
  const operationalKeys = await authenticateOperationalKeys(
    parsed,
    records,
    root,
    layout.environment,
  );

  const manifestRecord = requiredRecord(records, MANIFEST_PATH);
  await authenticateRecordSignature(
    parsed,
    manifestRecord,
    requiredKey(operationalKeys, manifestRecord),
  );
  requireAuthenticatedRecordTime(
    root,
    requiredKey(operationalKeys, manifestRecord),
    manifestRecord,
    stringField(parsed.manifest, "created_at"),
    distrustEvents,
    verifiedAt,
  );

  const packageManifest = await validatePackageManifest(parsed);
  const attestation = await validateAttestation(parsed, packageManifest);
  const attestationRecord = requiredRecord(records, ATTESTATION_PATH);
  await authenticateRecordSignature(
    parsed,
    attestationRecord,
    requiredKey(operationalKeys, attestationRecord),
  );

  const timestampEvidence = parseCanonicalRecord(
    requiredComponent(parsed, "evidence/timestamp/evidence.json"),
    "timestamp-evidence.v1.schema.json",
    "rproof.timestamp-evidence.v1",
    "timestamp evidence",
    "timestamp",
  ) as unknown as TimestampEvidence;
  let timestamp: AuthenticatedTimestamp;
  try {
    timestamp = await authenticateArchivedTimestamp({
      evidence: timestampEvidence,
      tokenBytes: requiredComponent(parsed, "evidence/timestamp/attestation.tsr"),
      certificateChainBytes: requiredComponent(parsed, "evidence/timestamp/tsa-chain.pem"),
      attestationJwsBytes: requiredComponent(parsed, "receipt/attestation.jws"),
      tsaPolicy,
    });
  } catch (error) {
    if (error instanceof TimestampUnsupportedError) {
      throw new BundleUnsupportedError(error.message, "timestamp");
    }
    if (error instanceof TimestampVerificationError) {
      throw new EvidenceAuthenticationError(error.message, "timestamp", { cause: error });
    }
    throw error;
  }
  requireAuthenticatedRecordTime(
    root,
    requiredKey(operationalKeys, attestationRecord),
    attestationRecord,
    timestamp.tokenGenTime,
    distrustEvents,
    verifiedAt,
  );
  requireAttestationChronology(
    attestation as AttestationView,
    timestamp.tokenGenTime,
    stringField(parsed.manifest, "created_at"),
  );

  return {
    parsed,
    records,
    operationalKeys,
    root,
    operationalKeyDistrustEvents: distrustEvents,
    packageManifest,
    attestation,
    timestamp,
    trustStoreVersion: trustStore.trust_store_version,
    trustStoreSha256: await sha256Hex(trustStoreBytes),
    environment,
  };
}

/** Authenticate one carried lifecycle record after its schema validation. */
export async function authenticateSignedRecord(
  authenticated: AuthenticatedRproof,
  record: SignedRecordReference,
  { verifiedAt }: { readonly verifiedAt: string },
): Promise<void> {
  requireWholeSecondVerificationTime(verifiedAt);
  if (!authenticated.records.includes(record)) {
    throw new BundleValidationError("signed record is not part of the parsed bundle", "lifecycle");
  }
  const key = requiredKey(authenticated.operationalKeys, record);
  await authenticateRecordSignature(authenticated.parsed, record, key);
  requireAuthenticatedRecordTime(
    authenticated.root as RootEntryView,
    key,
    record,
    recordSigningTime(authenticated, record),
    authenticated.operationalKeyDistrustEvents as readonly DistrustEventView[],
    verifiedAt,
  );
}

function parseTrustStore(content: Uint8Array): TrustStoreView {
  if (!(content instanceof Uint8Array) || content.byteLength === 0) {
    throw new AuthenticationPolicyError("external trust store must be non-empty bytes");
  }
  let value: JsonRecord;
  try {
    const decoded: unknown = JSON.parse(utf8.decode(content));
    if (!isRecord(decoded)) throw new Error("JSON root is not an object");
    value = decoded;
  } catch (error) {
    throw new AuthenticationPolicyError("external trust store does not satisfy its schema", undefined, {
      cause: error,
    });
  }
  if (
    typeof value.schema_version === "string" &&
    value.schema_version !== "rproof.trust-store.v1"
  ) {
    throw new BundleUnsupportedError(
      "external trust store schema version is unsupported",
      "operational_key_statements",
    );
  }
  try {
    if (
      !bytesEqual(canonicalJsonBytes(value), content) ||
      !validateSchema("trust-store.v1.schema.json", value)
    ) {
      throw new Error("schema or canonical JSON mismatch");
    }
  } catch (error) {
    throw new AuthenticationPolicyError("external trust store does not satisfy its schema");
  }
  return value as TrustStoreView;
}

async function selectRoot(
  parsed: ParsedRproofBundle,
  trustStore: TrustStoreView,
): Promise<RootEntryView> {
  const fingerprintBytes = requiredComponent(parsed, "trust/root-fingerprint.txt");
  let fingerprintText: string;
  try {
    fingerprintText = ascii(fingerprintBytes, "bundled root fingerprint");
  } catch (error) {
    throw new BundleValidationError("bundled root fingerprint is not ASCII");
  }
  const match = SHA256_LINE.exec(fingerprintText);
  if (!match?.[1]) {
    throw new BundleValidationError("bundled root fingerprint is invalid");
  }
  const fingerprint = match[1];
  const candidates = trustStore.reviewedproof_roots.filter(
    (root) => root.fingerprint_sha256 === fingerprint,
  );
  if (candidates.length !== 1) {
    throw new AuthenticationPolicyError("bundle root is not uniquely trusted by this release");
  }
  const root = candidates[0] as RootEntryView;
  if (root.status === "distrusted") {
    throw new AuthenticationPolicyError("bundle root is distrusted by this release");
  }
  let actualFingerprint: string;
  try {
    actualFingerprint = await p256FingerprintSha256(root.jwk);
  } catch (error) {
    throw new AuthenticationPolicyError("external root JWK is invalid", undefined, {
      cause: error,
    });
  }
  if (actualFingerprint !== fingerprint) {
    throw new AuthenticationPolicyError("external root JWK does not match its fingerprint");
  }
  return root;
}

function selectTsaPolicy(parsed: ParsedRproofBundle, trustStore: TrustStoreView): TsaPolicy {
  const evidence = parseJsonObject(
    requiredComponent(parsed, "evidence/timestamp/evidence.json"),
    "timestamp evidence",
    "timestamp",
  );
  const provider = evidence.provider;
  const policyOid = evidence.policy_oid;
  if (typeof provider !== "string" || typeof policyOid !== "string") {
    throw new BundleValidationError("timestamp evidence cannot select external policy", "timestamp");
  }
  const candidates = trustStore.tsa_policies.filter(
    (policy) => policy.tsa_id === provider && policy.policy_oids.includes(policyOid),
  );
  if (candidates.length !== 1) {
    throw new AuthenticationPolicyError(
      "timestamp authority and policy are not uniquely trusted",
      "timestamp",
    );
  }
  return candidates[0] as TsaPolicy;
}

async function authenticateDistrustEvents(
  root: RootEntryView,
  environment: string,
): Promise<readonly DistrustEventView[]> {
  const events: DistrustEventView[] = [];
  const eventIds = new Set<string>();
  let previousDigest: string | null = null;
  for (const [index, entry] of root.operational_key_distrust_events.entries()) {
    const event = entry.event;
    const canonical = canonicalJsonBytes(event);
    await verifyCompactJws(
      entry.jws,
      canonical,
      {
        cty: "application/rproof-key-distrust-event+json",
        kid: root.kid,
        schemaVersion: "rproof.key-distrust-event.v1",
        typ: "application/rproof-key-distrust-event+jws",
      },
      root.jwk,
      "operational_key_statements",
    );
    const startsAt = policyTime(event.affected_signing_time_range.from, "distrust range start");
    const through = event.affected_signing_time_range.through;
    if (
      event.sequence !== index + 1 ||
      event.previous_distrust_event_sha256 !== previousDigest ||
      event.environment !== environment ||
      eventIds.has(event.event_id) ||
      (through !== null && compareInstants(startsAt, policyTime(through, "distrust range end")) > 0)
    ) {
      throw new AuthenticationPolicyError("operational key distrust event chain is invalid");
    }
    requireRootValidAt(root, event.recorded_at);
    eventIds.add(event.event_id);
    previousDigest = await sha256Hex(canonical);
    events.push(event);
  }
  return events;
}

function discoverSignedRecords(parsed: ParsedRproofBundle): readonly SignedRecordReference[] {
  const sources: Array<[string, string, RecordSchemaVersion]> = [
    [MANIFEST_PATH, MANIFEST_JWS_PATH, parsed.profile.bundleVersion],
    [ATTESTATION_PATH, "receipt/attestation.jws", parsed.profile.attestationSchemaVersion],
    [STATUS_PATH, "evidence/lifecycle/status-snapshot.jws", "rproof.status-snapshot.v1"],
  ];
  if (parsed.components.has(COMPLETION_PATH)) {
    sources.push([
      COMPLETION_PATH,
      "review/completion.jws",
      "rproof.review-completion.v1",
    ]);
  }
  for (const path of [...parsed.components.keys()].filter((value) => EVENT_PATH.test(value)).sort()) {
    sources.push([path, `${path.slice(0, -5)}.jws`, "rproof.lifecycle-event.v1"]);
  }

  const purposes = new Map<string, string>();
  return sources.map(([path, jwsPath, schemaVersion]) => {
    const payload = path === MANIFEST_PATH ? parsed.manifestBytes : requiredComponent(parsed, path);
    const jws = path === MANIFEST_PATH ? parsed.manifestJws : requiredComponent(parsed, jwsPath);
    const profile = RECORD_PROFILES[schemaVersion];
    const parsedJws = parseCompactJws(
      jws,
      payload,
      {
        cty: profile.cty,
        schemaVersion,
        typ: profile.typ,
      },
      schemaVersion === parsed.profile.bundleVersion
        ? "bundle_signature"
        : schemaVersion === parsed.profile.attestationSchemaVersion
          ? "attestation_signature"
          : "lifecycle",
      parsed.profile.protectedHeaderSchemaName,
    );
    const previous = purposes.get(parsedJws.kid);
    if (previous !== undefined && previous !== profile.purpose) {
      throw new BundleValidationError("one operational key cannot cross record purposes");
    }
    purposes.set(parsedJws.kid, profile.purpose);
    return { path, jwsPath, schemaVersion, purpose: profile.purpose, kid: parsedJws.kid };
  });
}

async function validateOperationalKeyLayout(
  parsed: ParsedRproofBundle,
  records: readonly SignedRecordReference[],
): Promise<{ rootKid: string; environment: string; rootFingerprint: string }> {
  const carriedRoot = parseCanonicalPublicJwk(
    requiredComponent(parsed, "trust/root-public-key.jwk"),
  );
  let rootFingerprint: string;
  try {
    rootFingerprint = await p256FingerprintSha256(carriedRoot);
  } catch {
    throw new BundleValidationError(
      "bundled root public key is invalid",
      "operational_key_statements",
    );
  }
  const fingerprintLine = requiredComponent(parsed, "trust/root-fingerprint.txt");
  if (!bytesEqual(new TextEncoder().encode(`sha256:${rootFingerprint}\n`), fingerprintLine)) {
    throw new BundleValidationError("bundled root fingerprint does not match public JWK");
  }

  const purposeByKid = new Map(records.map((record) => [record.kid, record.purpose]));
  const statementKids = [...parsed.components.keys()]
    .map((path) => STATEMENT_PATH.exec(path)?.[1])
    .filter((kid): kid is string => kid !== undefined);
  const uniqueStatementKids = new Set(statementKids);
  if ([...purposeByKid.keys()].some((kid) => !uniqueStatementKids.has(kid))) {
    throw new BundleIncompleteError("bundle lacks a signing-key statement");
  }
  if (
    uniqueStatementKids.size !== purposeByKid.size ||
    [...uniqueStatementKids].some((kid) => !purposeByKid.has(kid))
  ) {
    throw new BundleValidationError("bundle has an unrelated signing-key statement");
  }

  const rootKids = new Set<string>();
  const environments = new Set<string>();
  for (const kid of uniqueStatementKids) {
    const stem = `${STATEMENT_PREFIX}${kid}`;
    const statementBytes = requiredComponent(parsed, `${stem}.json`);
    const statement = parseCanonicalRecord(
      statementBytes,
      "operational-key-statement.v1.schema.json",
      "rproof.operational-key-statement.v1",
      `operational key statement ${kid}`,
      "operational_key_statements",
    ) as OperationalStatementView;
    if (
      statement.kid !== kid ||
      statement.purpose !== purposeByKid.get(kid) ||
      statement.root_fingerprint_sha256 !== rootFingerprint
    ) {
      throw new BundleValidationError(
        "operational key statement binding is invalid",
        "operational_key_statements",
      );
    }
    environments.add(statement.environment);
    rootKids.add(
      parseCompactJws(
        requiredComponent(parsed, `${stem}.jws`),
        statementBytes,
        {
          cty: "application/rproof-operational-key-statement+json",
          schemaVersion: "rproof.operational-key-statement.v1",
          typ: "application/rproof-operational-key-statement+jws",
        },
        "operational_key_statements",
        parsed.profile.protectedHeaderSchemaName,
      ).kid,
    );
  }
  if (rootKids.size !== 1 || environments.size !== 1) {
    throw new BundleValidationError(
      "bundle key statements must share one root and environment",
      "operational_key_statements",
    );
  }
  return {
    rootKid: [...rootKids][0] as string,
    environment: [...environments][0] as string,
    rootFingerprint,
  };
}

async function authenticateOperationalKeys(
  parsed: ParsedRproofBundle,
  records: readonly SignedRecordReference[],
  root: RootEntryView,
  environment: string,
): Promise<ReadonlyMap<string, AuthenticatedOperationalKey>> {
  const keys = new Map<string, AuthenticatedOperationalKey>();
  for (const record of records) {
    if (keys.has(record.kid)) continue;
    const stem = `${STATEMENT_PREFIX}${record.kid}`;
    const statementBytes = requiredComponent(parsed, `${stem}.json`);
    const statement = parseCanonicalRecord(
      statementBytes,
      "operational-key-statement.v1.schema.json",
      "rproof.operational-key-statement.v1",
      `operational key statement ${record.kid}`,
      "operational_key_statements",
    ) as OperationalStatementView;
    await verifyCompactJws(
      requiredComponent(parsed, `${stem}.jws`),
      statementBytes,
      {
        cty: "application/rproof-operational-key-statement+json",
        kid: root.kid,
        schemaVersion: "rproof.operational-key-statement.v1",
        typ: "application/rproof-operational-key-statement+jws",
      },
      root.jwk,
      "operational_key_statements",
      parsed.profile.protectedHeaderSchemaName,
    );
    if (
      statement.root_fingerprint_sha256 !== root.fingerprint_sha256 ||
      statement.purpose !== record.purpose ||
      statement.environment !== environment ||
      compareInstants(
        evidenceTime(statement.not_before, "key not_before", "operational_key_statements"),
        evidenceTime(statement.not_after, "key not_after", "operational_key_statements"),
      ) >= 0
    ) {
      throw new EvidenceAuthenticationError(
        "operational key statement authentication failed",
        "operational_key_statements",
      );
    }
    await importP256Key(statement.jwk, "operational_key_statements");
    keys.set(record.kid, {
      kid: record.kid,
      purpose: record.purpose,
      environment,
      publicJwk: statement.jwk,
      notBefore: statement.not_before,
      notAfter: statement.not_after,
      statementSha256: await sha256Hex(statementBytes),
    });
  }
  return keys;
}

async function authenticateRecordSignature(
  parsed: ParsedRproofBundle,
  record: SignedRecordReference,
  key: AuthenticatedOperationalKey,
): Promise<void> {
  if (key.purpose !== record.purpose) {
    throw new EvidenceAuthenticationError(
      "operational key purpose does not match fixed record policy",
      recordCheckName(record),
    );
  }
  const payload = record.path === MANIFEST_PATH
    ? parsed.manifestBytes
    : requiredComponent(parsed, record.path);
  const compact = record.path === MANIFEST_PATH
    ? parsed.manifestJws
    : requiredComponent(parsed, record.jwsPath);
  const profile = RECORD_PROFILES[record.schemaVersion];
  await verifyCompactJws(
    compact,
    payload,
    {
      cty: profile.cty,
      kid: key.kid,
      schemaVersion: record.schemaVersion,
      typ: profile.typ,
    },
    key.publicJwk,
    recordCheckName(record),
    parsed.profile.protectedHeaderSchemaName,
  );
}

async function validatePackageManifest(parsed: ParsedRproofBundle): Promise<JsonRecord> {
  const packageBytes = requiredComponent(parsed, "package/manifest.json");
  const packageManifest = parseCanonicalRecord(
    packageBytes,
    "package-manifest.v1.schema.json",
    "rproof.package-manifest.v1",
    "package manifest",
    "package_manifest",
  ) as PackageView;
  const entryIds = packageManifest.entries.map((entry) => stringField(entry, "entry_id"));
  const totalBytes = packageManifest.entries.reduce(
    (total, entry) => total + numberField(entry, "byte_length"),
    0,
  );
  let calculatedRoot: string;
  try {
    calculatedRoot = await packageRoot(packageManifest.entries);
  } catch (error) {
    throw new EvidenceAuthenticationError(
      "package manifest validation failed",
      "package_manifest",
      { cause: error },
    );
  }
  if (
    packageManifest.entry_count !== packageManifest.entries.length ||
    new Set(entryIds).size !== entryIds.length ||
    totalBytes > MAX_PACKAGE_BYTES ||
    packageManifest.package_root !== calculatedRoot
  ) {
    throw new EvidenceAuthenticationError(
      "package manifest root, entries or total size is invalid",
      "package_manifest",
    );
  }
  return packageManifest;
}

async function validateAttestation(
  parsed: ParsedRproofBundle,
  packageManifest: JsonRecord,
): Promise<JsonRecord> {
  const bytes = requiredComponent(parsed, ATTESTATION_PATH);
  const attestation = parseCanonicalRecord(
    bytes,
    parsed.profile.attestationSchemaName,
    parsed.profile.attestationSchemaVersion,
    "attestation",
    "attestation",
  ) as AttestationView;
  if (
    stringField(parsed.manifest, "receipt_id") !== attestation.receipt_id ||
    attestation.manifest_digest.value !== (await sha256Hex(requiredComponent(parsed, "package/manifest.json"))) ||
    attestation.package_root.value !== stringField(packageManifest, "package_root")
  ) {
    throw new EvidenceAuthenticationError(
      "attestation does not bind the package and receipt",
      "attestation",
    );
  }
  return attestation;
}

function requireAttestationChronology(
  attestation: AttestationView,
  tokenTime: string,
  manifestTime: string,
): void {
  const assessed = evidenceTime(attestation.identity_assurance.assessed_at, "identity assessed_at", "attestation");
  const completed = evidenceTime(attestation.completed_at, "attestation completed_at", "attestation");
  const token = evidenceTime(tokenTime, "timestamp generation time", "timestamp");
  const created = evidenceTime(manifestTime, "bundle creation time", "bundle_signature");
  if (
    compareInstants(assessed, completed) > 0 ||
    compareInstants(completed, token) > 0 ||
    compareInstants(token, created) > 0
  ) {
    throw new EvidenceAuthenticationError(
      "authenticated attestation chronology is invalid",
      "timestamp",
    );
  }
}

function requireAuthenticatedRecordTime(
  root: RootEntryView,
  key: AuthenticatedOperationalKey,
  record: SignedRecordReference,
  signingTimeText: string,
  distrustEvents: readonly DistrustEventView[],
  verifiedAtText: string,
): void {
  const signingTime = evidenceTime(signingTimeText, "record signing time", recordCheckName(record));
  const verifiedAt = policyTime(verifiedAtText, "verification time");
  if (
    compareInstants(
      signingTime,
      evidenceTime(key.notBefore, "key not_before", "operational_key_statements"),
    ) < 0 ||
    compareInstants(
      signingTime,
      evidenceTime(key.notAfter, "key not_after", "operational_key_statements"),
    ) >= 0
  ) {
    throw new EvidenceAuthenticationError(
      `signing authority was not valid for ${record.path}`,
      "operational_key_statements",
    );
  }
  requireRootValidAt(root, signingTimeText);
  for (const event of distrustEvents) {
    if (compareInstants(policyTime(event.effective_at, "distrust effective_at"), verifiedAt) > 0) {
      continue;
    }
    const range = event.affected_signing_time_range;
    if (
      event.affected_kid === record.kid &&
      event.affected_key_statement_sha256 === key.statementSha256 &&
      compareInstants(signingTime, policyTime(range.from, "distrust range start")) >= 0 &&
      (range.through === null ||
        compareInstants(signingTime, policyTime(range.through, "distrust range end")) <= 0)
    ) {
      throw new EvidenceAuthenticationError(
        `signing key is distrusted for ${record.path} at its authenticated time`,
        "operational_key_statements",
      );
    }
  }
}

function requireRootValidAt(root: RootEntryView, timeText: string): void {
  const moment = policyTime(timeText, "authenticated root time");
  const notBefore = policyTime(root.not_before, "root not_before");
  const notAfter = root.not_after === null ? null : policyTime(root.not_after, "root not_after");
  if (
    (notAfter !== null && compareInstants(notBefore, notAfter) >= 0) ||
    compareInstants(moment, notBefore) < 0 ||
    (notAfter !== null && compareInstants(moment, notAfter) >= 0)
  ) {
    throw new AuthenticationPolicyError(
      "external root is not valid at authenticated record time",
    );
  }
}

function recordSigningTime(
  authenticated: AuthenticatedRproof,
  record: SignedRecordReference,
): string {
  if (record.path === MANIFEST_PATH) return stringField(authenticated.parsed.manifest, "created_at");
  if (
    record.schemaVersion === "rproof.attestation.v1" ||
    record.schemaVersion === "rproof.attestation.v2" ||
    record.schemaVersion === "rproof.attestation.v3"
  ) {
    return authenticated.timestamp.tokenGenTime;
  }
  const fields: Partial<Record<RecordSchemaVersion, string>> = {
    "rproof.lifecycle-event.v1": "recorded_at",
    "rproof.review-completion.v1": "satisfied_at",
    "rproof.status-snapshot.v1": "generated_at",
  };
  const field = fields[record.schemaVersion];
  if (!field) {
    throw new BundleUnsupportedError(
      "signed record has no supported signing-time policy",
      recordCheckName(record),
    );
  }
  const payload = parseJsonObject(
    requiredComponent(authenticated.parsed, record.path),
    "signed record",
    recordCheckName(record),
  );
  return stringField(payload, field);
}

function parseCanonicalRecord(
  content: Uint8Array,
  schemaName: CanonicalSchemaName,
  expectedVersion: string,
  label: string,
  checkName: string,
): JsonRecord {
  const value = parseJsonObject(content, label, checkName);
  if (typeof value.schema_version === "string" && value.schema_version !== expectedVersion) {
    if (SUPPORTED_SIGNED_SCHEMA_VERSIONS.has(value.schema_version)) {
      throw new BundleValidationError(`${label} mixes supported schema profiles`, checkName);
    }
    throw new BundleUnsupportedError(`${label} schema version is unsupported`, checkName);
  }
  try {
    if (!bytesEqual(canonicalJsonBytes(value), content) || !validateSchema(schemaName, value)) {
      throw new Error("schema or canonical JSON mismatch");
    }
  } catch (error) {
    throw new EvidenceAuthenticationError(`${label} does not satisfy its schema`, checkName, {
      cause: error,
    });
  }
  return value;
}

function parseCanonicalPublicJwk(content: Uint8Array): JsonRecord {
  const value = parseJsonObject(content, "root public key", "operational_key_statements");
  try {
    if (
      !bytesEqual(canonicalJsonBytes(value), content) ||
      !sameStringSet(Object.keys(value), ["crv", "kty", "x", "y"])
    ) {
      throw new Error("public JWK layout mismatch");
    }
  } catch {
    throw new BundleValidationError(
      "root public key must be canonical public P-256 JWK",
      "operational_key_statements",
    );
  }
  return value;
}

function parseJsonObject(content: Uint8Array, label: string, checkName: string): JsonRecord {
  try {
    const value: unknown = JSON.parse(utf8.decode(content));
    if (!isRecord(value)) throw new Error("JSON root is not an object");
    return value;
  } catch (error) {
    throw new EvidenceAuthenticationError(`${label} is not valid UTF-8 JSON`, checkName, {
      cause: error,
    });
  }
}

function parseCompactJws(
  compact: Uint8Array | string,
  expectedPayload: Uint8Array,
  profile: {
    readonly cty: string;
    readonly kid?: string;
    readonly schemaVersion: string;
    readonly typ: string;
  },
  checkName: string,
  protectedHeaderSchemaName: CanonicalSchemaName = "jws-protected-header.v1.schema.json",
): ParsedCompactJws {
  try {
    const text = typeof compact === "string" ? compact : ascii(compact, "compact JWS");
    const segments = text.split(".");
    if (segments.length !== 3) {
      throw new Error("compact JWS must contain three segments");
    }
    const protectedBytes = decodeBase64Url(segments[0] as string);
    const payload = decodeBase64Url(segments[1] as string);
    const signature = decodeBase64Url(segments[2] as string);
    if (!bytesEqual(payload, expectedPayload) || signature.byteLength !== 64) {
      throw new Error("compact JWS does not bind exact payload bytes");
    }
    const headerValue: unknown = JSON.parse(utf8.decode(protectedBytes));
    if (!isRecord(headerValue)) throw new Error("JWS protected header is not an object");
    const header = headerValue;
    if (typeof header.alg === "string" && header.alg !== "ES256") {
      throw new BundleUnsupportedError("compact JWS algorithm is unsupported", checkName);
    }
    if (
      typeof header.rproof_schema === "string" &&
      header.rproof_schema !== profile.schemaVersion
    ) {
      if (SUPPORTED_SIGNED_SCHEMA_VERSIONS.has(header.rproof_schema)) {
        throw new BundleValidationError("compact JWS mixes supported schema profiles", checkName);
      }
      throw new BundleUnsupportedError("compact JWS schema version is unsupported", checkName);
    }
    if (
      !bytesEqual(canonicalJsonBytes(header), protectedBytes) ||
      !validateSchema(protectedHeaderSchemaName, header)
    ) {
      throw new Error("compact JWS protected header is invalid");
    }
    const kid = stringField(header, "kid");
    const expectedHeader = canonicalJsonBytes({
      alg: "ES256",
      cty: profile.cty,
      kid: profile.kid ?? kid,
      rproof_schema: profile.schemaVersion,
      typ: profile.typ,
    });
    if (!bytesEqual(protectedBytes, expectedHeader)) {
      throw new Error("compact JWS protected header does not match fixed profile");
    }
    requireP256SignatureScalars(signature);
    return {
      kid,
      signature,
      signingInput: new TextEncoder().encode(`${segments[0]}.${segments[1]}`),
    };
  } catch (error) {
    if (error instanceof BundleUnsupportedError || error instanceof BundleValidationError) {
      throw error;
    }
    throw new BundleValidationError("compact JWS profile or payload binding is invalid", checkName);
  }
}

async function verifyCompactJws(
  compact: Uint8Array | string,
  expectedPayload: Uint8Array,
  profile: {
    readonly cty: string;
    readonly kid: string;
    readonly schemaVersion: string;
    readonly typ: string;
  },
  jwk: JsonRecord,
  checkName: string,
  protectedHeaderSchemaName: CanonicalSchemaName = "jws-protected-header.v1.schema.json",
): Promise<void> {
  let parsed: ParsedCompactJws;
  try {
    parsed = parseCompactJws(
      compact,
      expectedPayload,
      profile,
      checkName,
      protectedHeaderSchemaName,
    );
  } catch (error) {
    if (error instanceof BundleUnsupportedError) throw error;
    throw new EvidenceAuthenticationError("compact JWS profile is invalid", checkName, {
      cause: error,
    });
  }
  const key = await importP256Key(jwk, checkName);
  try {
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      parsed.signature.slice().buffer,
      parsed.signingInput.slice().buffer,
    );
    if (!valid) {
      throw new EvidenceAuthenticationError("compact JWS signature is invalid", checkName);
    }
  } catch (error) {
    if (error instanceof EvidenceAuthenticationError) throw error;
    if (error instanceof Error && error.name === "NotSupportedError") {
      throw new BundleUnsupportedError("native ES256 verification is unsupported", checkName);
    }
    throw new EvidenceAuthenticationError("compact JWS signature is invalid", checkName, {
      cause: error,
    });
  }
}

async function importP256Key(jwk: JsonRecord, checkName: string): Promise<CryptoKey> {
  try {
    await p256FingerprintSha256(jwk);
    return await crypto.subtle.importKey(
      "jwk",
      jwk as JsonWebKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch (error) {
    if (error instanceof Error && error.name === "NotSupportedError") {
      throw new BundleUnsupportedError("native ES256 verification is unsupported", checkName);
    }
    throw new EvidenceAuthenticationError("P-256 public JWK is invalid", checkName, {
      cause: error,
    });
  }
}

function decodeBase64Url(segment: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) {
    throw new Error("compact JWS segment is not unpadded base64url");
  }
  const paddingLength = (4 - (segment.length % 4)) % 4;
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(paddingLength);
  let binary: string;
  try {
    binary = atob(padded);
  } catch (error) {
    throw new Error("compact JWS segment is invalid base64url", { cause: error });
  }
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(decoded) !== segment) {
    throw new Error("compact JWS segment is not canonical base64url");
  }
  return decoded;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function requireP256SignatureScalars(signature: Uint8Array): void {
  const r = bytesToBigInt(signature.subarray(0, 32));
  const s = bytesToBigInt(signature.subarray(32));
  if (r < 1n || r >= P256_ORDER || s < 1n || s >= P256_ORDER) {
    throw new Error("ES256 signature scalar is outside the P-256 range");
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function requiredRecord(
  records: readonly SignedRecordReference[],
  path: string,
): SignedRecordReference {
  const matches = records.filter((record) => record.path === path);
  if (matches.length !== 1) {
    throw new BundleIncompleteError(`bundle lacks one required signed record at ${path}`);
  }
  return matches[0] as SignedRecordReference;
}

function requiredKey(
  keys: ReadonlyMap<string, AuthenticatedOperationalKey>,
  record: SignedRecordReference,
): AuthenticatedOperationalKey {
  const key = keys.get(record.kid);
  if (!key) {
    throw new BundleIncompleteError(
      "signed record has no authenticated operational key",
      "operational_key_statements",
    );
  }
  return key;
}

function requiredComponent(parsed: ParsedRproofBundle, path: string): Uint8Array {
  const value = parsed.components.get(path);
  if (!value) throw new BundleIncompleteError(`bundle lacks ${path}`);
  return value;
}

function recordCheckName(record: SignedRecordReference): string {
  if (record.path === MANIFEST_PATH) return "bundle_signature";
  if (record.schemaVersion === "rproof.attestation.v1") return "attestation_signature";
  return "lifecycle";
}

function requireWholeSecondVerificationTime(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
    throw new AuthenticationPolicyError("verification time must use exact whole-second UTC");
  }
  policyTime(value, "verification time");
}

function policyTime(value: string, label: string): PortableUtcInstant {
  try {
    return parsePortableUtcTime(value);
  } catch (error) {
    throw new AuthenticationPolicyError(`${label} is not valid portable UTC time`, undefined, {
      cause: error,
    });
  }
}

function evidenceTime(value: string, label: string, checkName: string): PortableUtcInstant {
  try {
    return parsePortableUtcTime(value);
  } catch (error) {
    throw new EvidenceAuthenticationError(`${label} is not valid portable UTC time`, checkName, {
      cause: error,
    });
  }
}

function compareInstants(left: PortableUtcInstant, right: PortableUtcInstant): number {
  if (left.epochSeconds < right.epochSeconds) return -1;
  if (left.epochSeconds > right.epochSeconds) return 1;
  return Math.sign(left.nanoseconds - right.nanoseconds);
}

function requireNativeJwsCrypto(checkName: string): void {
  if (
    typeof globalThis.crypto?.subtle?.importKey !== "function" ||
    typeof globalThis.crypto.subtle.verify !== "function"
  ) {
    throw new BundleUnsupportedError("native ES256 verification is unavailable", checkName);
  }
}

function ascii(bytes: Uint8Array, label: string): string {
  for (const byte of bytes) {
    if (byte > 0x7f) throw new Error(`${label} must be ASCII`);
  }
  return utf8.decode(bytes);
}

function stringField(record: JsonRecord, field: string): string {
  const value = record[field];
  if (typeof value !== "string") throw new Error(`${field} must be a string`);
  return value;
}

function numberField(record: JsonRecord, field: string): number {
  const value = record[field];
  if (typeof value !== "number") throw new Error(`${field} must be a number`);
  return value;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((value, index) => value === right[index]);
}

function sameStringSet(left: Iterable<string>, right: Iterable<string>): boolean {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  return leftSet.size === rightSet.size && [...leftSet].every((value) => rightSet.has(value));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
