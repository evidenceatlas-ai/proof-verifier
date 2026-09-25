import { canonicalJsonBytes, sha256Hex } from "@reviewedproof/hashing";

import {
  BundleIncompleteError,
  BundleSafetyError,
  BundleUnsupportedError,
  BundleValidationError,
  type ParsedRproofBundle,
} from "./archive";
import { matchArtefacts, type ArtefactInput, type ArtefactMatchCheck } from "./artefacts";
import {
  AuthenticationPolicyError,
  EvidenceAuthenticationError,
  authenticateRproof,
  authenticateSignedRecord,
  type AuthenticatedRproof,
} from "./authentication";
import {
  LifecycleValidationError,
  applyPredefinedExpiry,
  evaluateLifecycle,
  validateCompletion,
  type CarriedLifecycleEvent,
  type LifecycleEvaluation,
  type LifecycleStatus,
} from "./lifecycle";
import { validateSchema, type CanonicalSchemaName } from "./schemas";
import {
  TimestampUnsupportedError,
  TimestampVerificationError,
  parsePortableUtcTime,
} from "./timestamp";

const CHECK_NAMES = [
  "archive_safety",
  "bundle_manifest",
  "bundle_signature",
  "operational_key_statements",
  "package_manifest",
  "attestation",
  "attestation_signature",
  "identity_assurance",
  "organisation_authority",
  "timestamp",
  "lifecycle",
] as const;

export type VerificationCheckName = (typeof CHECK_NAMES)[number];
export type VerificationStatus = LifecycleStatus | "unsupported";

export interface VerificationCheck {
  readonly reason_code: string;
  readonly state: "valid" | "invalid" | "not_present" | "not_checked" | "unsupported";
}

export interface VerificationResult {
  readonly artefact_match: ArtefactMatchCheck;
  readonly bundle_sha256: string | null;
  readonly checks: Readonly<Record<VerificationCheckName, VerificationCheck>>;
  readonly current_status_checked: false;
  readonly environment: "production" | "staging" | "development" | null;
  readonly execution_mode: "offline";
  readonly matched_entry_ids: readonly string[];
  readonly receipt_id: string | null;
  readonly receipt_integrity: VerificationCheck;
  readonly schema_version: "rproof.verification-result.v1";
  readonly status: VerificationStatus;
  readonly trust_store_sha256: string;
  readonly trust_store_version: string;
  readonly verified_as_of: string | null;
  readonly verified_at: string;
  readonly verifier_version: string;
  readonly warnings: readonly string[];
}

/** Authenticated values for the in-memory S03 presentation layer; never part of result JSON. */
export interface VerificationDetails {
  readonly attestation: Readonly<Record<string, unknown>>;
  readonly attestationJws: string;
  readonly packageManifest: Readonly<Record<string, unknown>>;
  readonly statusSnapshot: Readonly<Record<string, unknown>>;
  readonly statusSnapshotJws: string;
  readonly lifecycleEvents: readonly Readonly<Record<string, unknown>>[];
  readonly completion: Readonly<Record<string, unknown>> | null;
  readonly timestamp: { readonly tokenGenTime: string };
  readonly rootFingerprintSha256: string;
}

export interface VerificationOutcome {
  readonly result: VerificationResult;
  readonly exitCode: number;
  readonly details?: VerificationDetails;
}

export interface VerifyRproofOptions {
  readonly trustStoreBytes: Uint8Array;
  readonly verifiedAt: string;
  readonly allowNonProduction?: boolean;
  readonly artefacts?: readonly ArtefactInput[];
  readonly verifierVersion?: string;
  readonly signal?: AbortSignal;
}

interface LifecycleRecords {
  readonly statusSnapshot: Readonly<Record<string, unknown>>;
  readonly events: readonly CarriedLifecycleEvent[];
  readonly completion: Readonly<Record<string, unknown>> | null;
}

const P1_VALID_REASONS = {
  archive_safety: "archive_safe",
  bundle_manifest: "bundle_manifest_valid",
  bundle_signature: "bundle_signature_valid",
  operational_key_statements: "operational_keys_valid",
  package_manifest: "package_manifest_valid",
  attestation: "attestation_valid",
  attestation_signature: "attestation_signature_valid",
  timestamp: "timestamp_valid",
} as const;
const ADVERSE_STATUSES = new Set<VerificationStatus>([
  "valid_but_revoked",
  "superseded",
  "expired",
]);
const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Verify one portable bundle entirely from supplied bytes and external trust policy.
 *
 * The returned JSON-shaped `result` matches the Python verifier contract while
 * `details` contains only records authenticated during this same verification run.
 */
export async function verifyRproof(
  archiveBytes: Uint8Array,
  options: VerifyRproofOptions,
): Promise<VerificationOutcome> {
  const {
    trustStoreBytes,
    verifiedAt,
    allowNonProduction = false,
    artefacts = [],
    verifierVersion = "0.1.0",
    signal,
  } = options;
  requireInputs(archiveBytes, trustStoreBytes, verifiedAt, verifierVersion);
  signal?.throwIfAborted();

  let authenticated: AuthenticatedRproof;
  try {
    authenticated = await authenticateRproof(archiveBytes, {
      trustStoreBytes,
      verifiedAt,
      allowNonProduction,
    });
    signal?.throwIfAborted();
  } catch (error) {
    if (!isVerificationError(error)) throw error;
    return failureOutcome({
      archiveBytes,
      trustStoreBytes,
      verifiedAt,
      verifierVersion,
      error,
      authenticated: null,
      signal,
    });
  }

  let records: LifecycleRecords;
  let lifecycle: LifecycleEvaluation;
  let status: LifecycleStatus;
  try {
    records = parseLifecycleRecords(authenticated.parsed);
    await authenticateLifecycleRecords(authenticated, records, verifiedAt, signal);
    lifecycle = await evaluateLifecycle({
      attestation: authenticated.attestation,
      bundleManifest: authenticated.parsed.manifest,
      statusSnapshot: records.statusSnapshot,
      events: records.events,
      signal,
    });
    if (records.completion !== null) {
      validateCompletion({
        attestation: authenticated.attestation,
        bundleManifest: authenticated.parsed.manifest,
        completion: records.completion,
      });
    }
    requireTimestampBeforeStatus(authenticated, lifecycle.generatedAt);
    status = applyPredefinedExpiry({
      attestation: authenticated.attestation,
      status: lifecycle.status,
      evaluatedAt: verifiedAt,
    });
    signal?.throwIfAborted();
  } catch (error) {
    if (!isVerificationError(error)) throw error;
    return failureOutcome({
      archiveBytes,
      trustStoreBytes,
      verifiedAt,
      verifierVersion,
      error,
      authenticated,
      failedCheck: error instanceof LifecycleValidationError ? "lifecycle" : undefined,
      signal,
    });
  }

  const artefactMatch = await matchArtefacts(authenticated.packageManifest, artefacts, signal);
  signal?.throwIfAborted();
  const checks = p1Checks(authenticated);
  checks.lifecycle = check("valid", "lifecycle_valid");
  const exitCode = status === "invalid"
    ? 2
    : status === "incomplete_proof"
      ? 4
      : artefactMatch.check.state === "invalid"
        ? 3
        : ADVERSE_STATUSES.has(status)
          ? 7
          : 0;
  const result: VerificationResult = {
    artefact_match: artefactMatch.check,
    bundle_sha256: await sha256Hex(archiveBytes, signal),
    checks,
    current_status_checked: false,
    environment: authenticated.environment as VerificationResult["environment"],
    execution_mode: "offline",
    matched_entry_ids: artefactMatch.matchedEntryIds,
    receipt_id: authenticated.attestation.receipt_id as string,
    receipt_integrity: check("valid", "receipt_integrity_valid"),
    schema_version: "rproof.verification-result.v1",
    status,
    trust_store_sha256: authenticated.trustStoreSha256,
    trust_store_version: authenticated.trustStoreVersion,
    verified_as_of: records.statusSnapshot.generated_at as string,
    verified_at: verifiedAt,
    verifier_version: verifierVersion,
    warnings: successWarnings(
      authenticated,
      lifecycle,
      artefactMatch.check,
      records.completion !== null,
      verifiedAt,
    ),
  };
  validateResult(result);
  signal?.throwIfAborted();
  return {
    result,
    exitCode,
    details: {
      attestation: authenticated.attestation,
      attestationJws: decoder.decode(
        requiredComponent(authenticated.parsed, "receipt/attestation.jws"),
      ),
      packageManifest: authenticated.packageManifest,
      statusSnapshot: records.statusSnapshot,
      statusSnapshotJws: decoder.decode(
        requiredComponent(
          authenticated.parsed,
          "evidence/lifecycle/status-snapshot.jws",
        ),
      ),
      lifecycleEvents: records.events.map((event) => event.payload),
      completion: records.completion,
      timestamp: { tokenGenTime: authenticated.timestamp.tokenGenTime },
      rootFingerprintSha256: authenticated.root.fingerprint_sha256 as string,
    },
  };
}

function parseLifecycleRecords(parsed: ParsedRproofBundle): LifecycleRecords {
  const statusBytes = requiredComponent(parsed, "evidence/lifecycle/status-snapshot.json");
  const statusSnapshot = parseCanonicalRecord(
    statusBytes,
    "status-snapshot.v1.schema.json",
    "rproof.status-snapshot.v1",
    "status snapshot",
  );
  const events = [...parsed.components]
    .filter(([path]) => /^evidence\/lifecycle\/events\/[0-9]{4}\.json$/.test(path))
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([path, canonicalBytes]) => ({
      canonicalBytes,
      payload: parseCanonicalRecord(
        canonicalBytes,
        "lifecycle-event.v1.schema.json",
        "rproof.lifecycle-event.v1",
        path,
      ),
    }));
  const completionBytes = parsed.components.get("review/completion.json");
  return {
    statusSnapshot,
    events,
    completion: completionBytes === undefined
      ? null
      : parseCanonicalRecord(
          completionBytes,
          "review-completion.v1.schema.json",
          "rproof.review-completion.v1",
          "review completion",
        ),
  };
}

function parseCanonicalRecord(
  bytes: Uint8Array,
  schemaName: CanonicalSchemaName,
  schemaVersion: string,
  label: string,
): Readonly<Record<string, unknown>> {
  let value: unknown;
  try {
    value = JSON.parse(decoder.decode(bytes));
  } catch (error) {
    throw new BundleValidationError(`${label} is not valid UTF-8 JSON`, "lifecycle");
  }
  if (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as Record<string, unknown>).schema_version === "string" &&
    (value as Record<string, unknown>).schema_version !== schemaVersion
  ) {
    throw new BundleUnsupportedError(`${label} schema version is unsupported`, "lifecycle");
  }
  try {
    if (
      typeof value !== "object" ||
      value === null ||
      Array.isArray(value) ||
      !bytesEqual(canonicalJsonBytes(value), bytes) ||
      !validateSchema(schemaName, value)
    ) {
      throw new Error("invalid canonical schema");
    }
  } catch (error) {
    throw new BundleValidationError(`${label} does not satisfy its canonical schema`, "lifecycle");
  }
  return value as Readonly<Record<string, unknown>>;
}

async function authenticateLifecycleRecords(
  authenticated: AuthenticatedRproof,
  records: LifecycleRecords,
  verifiedAt: string,
  signal?: AbortSignal,
): Promise<void> {
  const paths = ["evidence/lifecycle/status-snapshot.json"];
  paths.push(
    ...records.events.map((_, index) =>
      `evidence/lifecycle/events/${String(index + 1).padStart(4, "0")}.json`),
  );
  if (records.completion !== null) paths.push("review/completion.json");
  const byPath = new Map(authenticated.records.map((record) => [record.path, record]));
  for (const path of paths) {
    signal?.throwIfAborted();
    const record = byPath.get(path);
    if (record === undefined) {
      throw new BundleValidationError(`bundle lacks signed lifecycle record ${path}`, "lifecycle");
    }
    await authenticateSignedRecord(authenticated, record, { verifiedAt });
  }
}

function requireTimestampBeforeStatus(authenticated: AuthenticatedRproof, generatedAt: string): void {
  const statusTime = parsePortableUtcTime(generatedAt);
  const tokenTime = authenticated.timestamp.instant;
  if (
    tokenTime.epochSeconds > statusTime.epochSeconds ||
    (tokenTime.epochSeconds === statusTime.epochSeconds &&
      tokenTime.nanoseconds > statusTime.nanoseconds)
  ) {
    throw new LifecycleValidationError(
      "signed status snapshot predates the authenticated timestamp",
    );
  }
}

async function failureOutcome({
  archiveBytes,
  trustStoreBytes,
  verifiedAt,
  verifierVersion,
  error,
  authenticated,
  failedCheck,
  signal,
}: {
  readonly archiveBytes: Uint8Array;
  readonly trustStoreBytes: Uint8Array;
  readonly verifiedAt: string;
  readonly verifierVersion: string;
  readonly error: Error;
  readonly authenticated: AuthenticatedRproof | null;
  readonly failedCheck?: VerificationCheckName;
  readonly signal?: AbortSignal;
}): Promise<VerificationOutcome> {
  const errorCheck = "checkName" in error ? error.checkName : undefined;
  const checkName = failedCheck ?? (
    typeof errorCheck === "string" && isCheckName(errorCheck) ? errorCheck : "bundle_manifest"
  );
  let state: VerificationCheck["state"];
  let reasonCode: string;
  let status: VerificationStatus;
  let exitCode: number;
  if (error instanceof BundleSafetyError) {
    [state, reasonCode, status, exitCode] = ["invalid", "unsafe_archive", "invalid", 6];
  } else if (error instanceof BundleIncompleteError) {
    [state, reasonCode, status, exitCode] = [
      "not_present",
      "required_evidence_missing",
      "incomplete_proof",
      4,
    ];
  } else if (
    error instanceof BundleUnsupportedError ||
    error instanceof TimestampUnsupportedError
  ) {
    [state, reasonCode, status, exitCode] = [
      "unsupported",
      "unsupported_evidence",
      "unsupported",
      5,
    ];
  } else {
    [state, reasonCode, status, exitCode] = [
      "invalid",
      `${checkName}_invalid`,
      "invalid",
      2,
    ];
  }
  const checks = p1Checks(authenticated);
  checks[checkName] = check(state, reasonCode);
  const warnings = [
    "Current receipt status was not established by this verification.",
    "Local artefact comparison was not performed because required evidence verification failed.",
    "Later operational-key distrust information may be unknown to this verifier release.",
  ];
  if (authenticated !== null && authenticated.environment !== "production") {
    warnings.unshift("Non-production evidence accepted under explicit test-mode policy.");
  }
  signal?.throwIfAborted();
  const result: VerificationResult = {
    artefact_match: { reason_code: "evidence_verification_failed", state: "not_checked" },
    bundle_sha256: await sha256Hex(archiveBytes, signal),
    checks,
    current_status_checked: false,
    environment: authenticated === null
      ? null
      : authenticated.environment as VerificationResult["environment"],
    execution_mode: "offline",
    matched_entry_ids: [],
    receipt_id: authenticated === null ? null : authenticated.attestation.receipt_id as string,
    receipt_integrity: check(state, reasonCode),
    schema_version: "rproof.verification-result.v1",
    status,
    trust_store_sha256: await sha256Hex(trustStoreBytes, signal),
    trust_store_version: authenticated === null ? "unknown" : authenticated.trustStoreVersion,
    verified_as_of: null,
    verified_at: verifiedAt,
    verifier_version: verifierVersion,
    warnings,
  };
  validateResult(result);
  signal?.throwIfAborted();
  return { result, exitCode };
}

function p1Checks(
  authenticated: AuthenticatedRproof | null,
): Record<VerificationCheckName, VerificationCheck> {
  const checks = uncheckedChecks();
  if (authenticated === null) return checks;
  for (const [name, reason] of Object.entries(P1_VALID_REASONS)) {
    checks[name as keyof typeof P1_VALID_REASONS] = check("valid", reason);
  }
  checks.identity_assurance = check("valid", "identity_assurance_claim_authenticated");
  checks.organisation_authority = authenticated.attestation.organisation_authority === null
    ? check("not_present", "no_authority_claim")
    : check("valid", "organisation_authority_claim_authenticated");
  return checks;
}

function uncheckedChecks(): Record<VerificationCheckName, VerificationCheck> {
  return Object.fromEntries(
    CHECK_NAMES.map((name) => [
      name,
      check("not_checked", "not_checked_due_to_earlier_failure"),
    ]),
  ) as Record<VerificationCheckName, VerificationCheck>;
}

function successWarnings(
  authenticated: AuthenticatedRproof,
  lifecycle: LifecycleEvaluation,
  artefactCheck: ArtefactMatchCheck,
  completionPresent: boolean,
  verifiedAt: string,
): string[] {
  const warnings: string[] = [];
  if (authenticated.environment !== "production") {
    warnings.push("Non-production evidence accepted under explicit test-mode policy.");
  }
  warnings.push(
    "Cryptographic evidence is valid as of the signed status snapshot. Current revocation status after that time was not checked.",
    "Later operational-key distrust information may be unknown to this verifier release.",
  );
  if (lifecycle.generatedAt > verifiedAt) {
    warnings.push(
      "The signed evidence time is later than the local verifier clock; check the local clock.",
    );
  } else if (verifiedAt >= lifecycle.nextUpdateDueAt) {
    warnings.push(
      "The signed status update horizon has passed; later withdrawal status remains unknown.",
    );
  }
  if (artefactCheck.state === "not_checked") {
    warnings.push(
      `Local artefact comparison was not completed: ${artefactCheck.reason_code}.`,
    );
  } else if (artefactCheck.state === "invalid") {
    warnings.push("One or more selected artefacts did not match the authenticated package.");
  }
  warnings.push(
    "Identity and organisation authority are authenticated issuer-carried claims; no live provider or organisation check was performed.",
    "The timestamp certificate path was checked at genTime without an online certificate-revocation lookup.",
    "The proof authenticates the carried review statement; it does not establish reviewer competence or review correctness.",
  );
  if (completionPresent) {
    warnings.push(
      "Completion validates the frozen carried policy only; other linked receipts and current quorum were not independently checked.",
    );
  }
  return warnings;
}

function requireInputs(
  archiveBytes: Uint8Array,
  trustStoreBytes: Uint8Array,
  verifiedAt: string,
  verifierVersion: string,
): void {
  if (!(archiveBytes instanceof Uint8Array) || !(trustStoreBytes instanceof Uint8Array)) {
    throw new TypeError("bundle and trust store inputs must be Uint8Array values");
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(verifiedAt)) {
    throw new RangeError("verifiedAt must use exact whole-second UTC");
  }
  parsePortableUtcTime(verifiedAt);
  if (typeof verifierVersion !== "string" || verifierVersion.length < 1 || verifierVersion.length > 100) {
    throw new RangeError("verifierVersion must contain 1 to 100 characters");
  }
}

function requiredComponent(parsed: ParsedRproofBundle, path: string): Uint8Array {
  const bytes = parsed.components.get(path);
  if (bytes === undefined) throw new BundleIncompleteError(`bundle lacks ${path}`, "lifecycle");
  return bytes;
}

function validateResult(result: VerificationResult): void {
  if (!validateSchema("verification-result.v1.schema.json", result)) {
    throw new Error("verification result does not satisfy its normative schema");
  }
}

function check(
  state: VerificationCheck["state"],
  reasonCode: string,
): VerificationCheck {
  return { reason_code: reasonCode, state };
}

function isCheckName(value: string): value is VerificationCheckName {
  return (CHECK_NAMES as readonly string[]).includes(value);
}

function isVerificationError(error: unknown): error is Error {
  return error instanceof BundleValidationError ||
    error instanceof BundleSafetyError ||
    error instanceof AuthenticationPolicyError ||
    error instanceof EvidenceAuthenticationError ||
    error instanceof LifecycleValidationError ||
    error instanceof TimestampVerificationError;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
