import { canonicalJsonBytes, sha256Hex } from "@reviewedproof/hashing";

const ADR0010_POLICY = "adr0010-2026-09-09";
const PRIVATE_REASON = /^private_reason_sha256:[0-9a-f]{64}$/;
const REPLACEMENT_PURPOSE = /^replacement_review:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} private_reason_sha256:[0-9a-f]{64}$/;
const ADR0010_REVOKE_AUTHORITIES = new Set([
  "reviewer_self_revocation",
  "org_admin_review_withdrawal",
]);
const ADR0010_SUPERSEDE_AUTHORITIES = new Set([
  "requester_review_supersession",
  "org_admin_review_supersession",
]);

export type LifecycleStatus =
  | "valid"
  | "valid_but_revoked"
  | "superseded"
  | "expired"
  | "incomplete_proof"
  | "invalid";

export interface CarriedLifecycleEvent {
  readonly payload: Readonly<Record<string, unknown>>;
  readonly canonicalBytes: Uint8Array;
}

export interface LifecycleEvaluation {
  readonly status: LifecycleStatus;
  readonly generatedAt: string;
  readonly nextUpdateDueAt: string;
}

export class LifecycleValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LifecycleValidationError";
  }
}

/**
 * Evaluate status only at the carried snapshot's historical generation time.
 *
 * The caller must first validate every record's canonical schema and exact bytes,
 * authenticate its JWS, and validate its signing-key authority at the signed time.
 * This function does not check current revocation status. Display corrections never
 * alter the authoritative attestation supplied here.
 */
export async function evaluateLifecycle({
  attestation,
  bundleManifest,
  statusSnapshot,
  events,
  signal,
}: {
  readonly attestation: Readonly<Record<string, unknown>>;
  readonly bundleManifest: Readonly<Record<string, unknown>>;
  readonly statusSnapshot: Readonly<Record<string, unknown>>;
  readonly events: readonly CarriedLifecycleEvent[];
  readonly signal?: AbortSignal;
}): Promise<LifecycleEvaluation> {
  signal?.throwIfAborted();
  const receiptId = attestation.receipt_id as string;
  if (bundleManifest.receipt_id !== receiptId) {
    throw new LifecycleValidationError("bundle and attestation receipt identifiers differ");
  }
  if (statusSnapshot.receipt_id !== receiptId) {
    throw new LifecycleValidationError("status and attestation receipt identifiers differ");
  }

  const completedAt = attestation.completed_at as string;
  const generatedAt = statusSnapshot.generated_at as string;
  const nextUpdateDueAt = statusSnapshot.next_update_due_at as string;
  const bundleCreatedAt = bundleManifest.created_at as string;
  if (completedAt > generatedAt || generatedAt > bundleCreatedAt) {
    throw new LifecycleValidationError("receipt lifecycle chronology is inconsistent");
  }
  if (nextUpdateDueAt <= generatedAt) {
    throw new LifecycleValidationError("status next update must follow its generation time");
  }

  const eventIds = new Set<string>();
  const effectiveTypes = new Set<string>();
  let previousDigest: string | null = null;
  let previousRecordedAt: string | null = null;
  for (const [index, carried] of events.entries()) {
    signal?.throwIfAborted();
    const event = carried.payload;
    if (!bytesEqual(canonicalJsonBytes(event), carried.canonicalBytes)) {
      throw new LifecycleValidationError("lifecycle event mapping differs from its exact bytes");
    }
    if (event.receipt_id !== receiptId) {
      throw new LifecycleValidationError(
        "lifecycle event and attestation receipt identifiers differ",
      );
    }
    if (event.sequence !== index + 1) {
      throw new LifecycleValidationError("lifecycle event sequence is not contiguous");
    }
    if (event.previous_event_sha256 !== previousDigest) {
      throw new LifecycleValidationError("lifecycle event digest chain is invalid");
    }

    const eventId = event.event_id as string;
    if (eventIds.has(eventId)) {
      throw new LifecycleValidationError("lifecycle event identifiers must be unique");
    }
    eventIds.add(eventId);

    const recordedAt = event.recorded_at as string;
    if (recordedAt < completedAt || recordedAt > generatedAt) {
      throw new LifecycleValidationError("lifecycle event falls outside the snapshot chronology");
    }
    if (previousRecordedAt !== null && recordedAt < previousRecordedAt) {
      throw new LifecycleValidationError("lifecycle event recorded times must not decrease");
    }
    previousRecordedAt = recordedAt;

    const eventType = event.event_type as string;
    validateEventAuthority(attestation, event);
    if (eventType === "supersede" && event.replacement_receipt_id === receiptId) {
      throw new LifecycleValidationError("a receipt cannot supersede itself");
    }
    if ((event.effective_at as string) <= generatedAt) {
      effectiveTypes.add(eventType);
    }
    previousDigest = await sha256Hex(carried.canonicalBytes, signal);
  }

  if (statusSnapshot.event_chain_head_sha256 !== previousDigest) {
    throw new LifecycleValidationError("status snapshot does not bind the lifecycle chain head");
  }
  const declared = statusSnapshot.status as LifecycleStatus;
  const expiresAt = predefinedExpiry(attestation);
  const projected = projectStatus(
    declared,
    effectiveTypes,
    expiresAt !== null && generatedAt >= expiresAt,
  );
  if (declared !== projected) {
    throw new LifecycleValidationError(
      "signed status is inconsistent with effective lifecycle events",
    );
  }
  return { generatedAt, nextUpdateDueAt, status: projected };
}

/**
 * Validate one authenticated historical completion claim.
 *
 * The caller must first validate canonical schemas and exact bytes, authenticate
 * the completion JWS, and validate its signing key at `satisfied_at`. Linked
 * receipts absent from this bundle remain unverified. This makes no claim about
 * quorum after `satisfied_at`.
 */
export function validateCompletion({
  attestation,
  bundleManifest,
  completion,
}: {
  readonly attestation: Readonly<Record<string, unknown>>;
  readonly bundleManifest: Readonly<Record<string, unknown>>;
  readonly completion: Readonly<Record<string, unknown>>;
}): void {
  const attestationReceipt = attestation.receipt_id as string;
  if (bundleManifest.receipt_id !== attestationReceipt) {
    throw new LifecycleValidationError("bundle and attestation receipt identifiers differ");
  }
  if (completion.review_id !== attestation.review_id) {
    throw new LifecycleValidationError("completion and attestation review identifiers differ");
  }
  const satisfiedAt = completion.satisfied_at as string;
  if ((attestation.completed_at as string) > satisfiedAt) {
    throw new LifecycleValidationError("completion predates its included attestation");
  }
  const expiresAt = predefinedExpiry(attestation);
  if (expiresAt !== null && satisfiedAt >= expiresAt) {
    throw new LifecycleValidationError("completion includes an expired attestation");
  }
  if (satisfiedAt > (bundleManifest.created_at as string)) {
    throw new LifecycleValidationError("completion postdates bundle creation");
  }

  const policy = completion.policy_snapshot as Readonly<Record<string, unknown>>;
  const eligible = policy.eligible_reviewers as readonly Readonly<Record<string, unknown>>[];
  const assignmentIds = eligible.map((reviewer) => reviewer.assignment_id as string);
  if (new Set(assignmentIds).size !== assignmentIds.length) {
    throw new LifecycleValidationError("eligible assignment identifiers must be unique");
  }
  if (!isSorted(assignmentIds)) {
    throw new LifecycleValidationError("eligible reviewers must be sorted by assignment identifier");
  }
  const eligibleById = new Map(
    eligible.map((reviewer) => [reviewer.assignment_id as string, reviewer]),
  );

  const requiredRoles = policy.required_roles as readonly string[];
  if (!isSorted(requiredRoles) || new Set(requiredRoles).size !== requiredRoles.length) {
    throw new LifecycleValidationError("required roles must be unique and sorted");
  }

  const links = completion.receipt_links as readonly Readonly<Record<string, unknown>>[];
  const linkAssignments = links.map((link) => link.assignment_id as string);
  const linkReceipts = links.map((link) => link.receipt_id as string);
  const linkAttestations = links.map((link) => link.attestation_id as string);
  for (const [values, label] of [
    [linkAssignments, "assignment"],
    [linkReceipts, "receipt"],
    [linkAttestations, "attestation"],
  ] as const) {
    if (new Set(values).size !== values.length) {
      throw new LifecycleValidationError(`completion link ${label} identifiers must be unique`);
    }
  }
  if (linkReceipts.includes(completion.receipt_id as string)) {
    throw new LifecycleValidationError("completion receipt must differ from contributing receipts");
  }

  for (const link of links) {
    const eligibleReviewer = eligibleById.get(link.assignment_id as string);
    if (eligibleReviewer === undefined) {
      throw new LifecycleValidationError("completion link assignment is not eligible");
    }
    if (link.role_code !== eligibleReviewer.role_code) {
      throw new LifecycleValidationError(
        "completion link role differs from the frozen eligible role",
      );
    }
  }

  const exactLinks = links.filter(
    (link) =>
      link.receipt_id === attestationReceipt &&
      link.attestation_id === attestation.attestation_id,
  );
  if (exactLinks.length !== 1) {
    throw new LifecycleValidationError("bundle attestation lacks one exact completion link");
  }

  const linkedAssignments = new Set(linkAssignments);
  const requiredAssignments = new Set(
    eligible
      .filter((reviewer) => reviewer.required === true)
      .map((reviewer) => reviewer.assignment_id as string),
  );
  if (![...requiredAssignments].every((assignmentId) => linkedAssignments.has(assignmentId))) {
    throw new LifecycleValidationError("completion omits a required assignment");
  }
  validatePolicySatisfaction(policy, eligibleById, links, requiredRoles, requiredAssignments);
}

export function applyPredefinedExpiry({
  attestation,
  status,
  evaluatedAt,
}: {
  readonly attestation: Readonly<Record<string, unknown>>;
  readonly status: LifecycleStatus;
  readonly evaluatedAt: string;
}): LifecycleStatus {
  const evaluatedAtMilliseconds = Date.parse(evaluatedAt);
  if (!Number.isFinite(evaluatedAtMilliseconds)) {
    throw new LifecycleValidationError("expiry evaluation time is invalid");
  }
  const expiresAt = predefinedExpiry(attestation);
  if (
    status === "invalid" ||
    status === "incomplete_proof" ||
    status === "valid_but_revoked" ||
    status === "superseded" ||
    status === "expired"
  ) {
    return status;
  }
  return expiresAt !== null && evaluatedAtMilliseconds >= Date.parse(expiresAt)
    ? "expired"
    : status;
}

function validateEventAuthority(
  attestation: Readonly<Record<string, unknown>>,
  event: Readonly<Record<string, unknown>>,
): void {
  const authority = event.actor_authority;
  if (!isRecord(authority)) return;
  const authorityType = authority.authority_type;
  const policyVersion = authority.policy_version;
  const recognised =
    (typeof authorityType === "string" &&
      (ADR0010_REVOKE_AUTHORITIES.has(authorityType) ||
        ADR0010_SUPERSEDE_AUTHORITIES.has(authorityType))) ||
    policyVersion === ADR0010_POLICY;
  if (!recognised) return;

  const eventType = event.event_type;
  const allowed = eventType === "revoke"
    ? ADR0010_REVOKE_AUTHORITIES
    : eventType === "supersede"
      ? ADR0010_SUPERSEDE_AUTHORITIES
      : new Set<string>();
  if (
    policyVersion !== ADR0010_POLICY ||
    typeof authorityType !== "string" ||
    !allowed.has(authorityType)
  ) {
    throw new LifecycleValidationError("lifecycle event authority vocabulary is invalid");
  }
  const actor = event.actor;
  if (!isRecord(actor) || actor.display_name !== null) {
    throw new LifecycleValidationError("ADR 0010 lifecycle actor display name must be null");
  }
  if ((event.effective_at as string) > (event.recorded_at as string)) {
    throw new LifecycleValidationError("ADR 0010 lifecycle event cannot postdate its record");
  }

  const reference = authority.authority_reference;
  if (eventType === "revoke") {
    if (typeof event.explanation !== "string" || !PRIVATE_REASON.test(event.explanation)) {
      throw new LifecycleValidationError("ADR 0010 revocation must commit its private reason");
    }
    if (authorityType === "reviewer_self_revocation") {
      const reviewer = attestation.reviewer;
      if (
        reference !== `attestation_id:${String(attestation.attestation_id)}` ||
        !isRecord(reviewer) ||
        actor.subject_id !== reviewer.subject_id
      ) {
        throw new LifecycleValidationError(
          "reviewer self-revocation authority does not bind the attestation",
        );
      }
      return;
    }
  }
  if (reference !== `review_id:${String(attestation.review_id)}`) {
    throw new LifecycleValidationError(
      "review lifecycle authority does not bind the source review",
    );
  }
  if (
    eventType === "supersede" &&
    (typeof event.purpose !== "string" || !REPLACEMENT_PURPOSE.test(event.purpose))
  ) {
    throw new LifecycleValidationError(
      "ADR 0010 supersession must bind the replacement review and private reason",
    );
  }
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function projectStatus(
  declared: LifecycleStatus,
  effectiveTypes: ReadonlySet<string>,
  predefinedExpired = false,
): LifecycleStatus {
  if (declared === "invalid") {
    return "invalid";
  }
  if (declared === "incomplete_proof") {
    return "incomplete_proof";
  }
  if (effectiveTypes.has("revoke")) {
    return "valid_but_revoked";
  }
  if (effectiveTypes.has("supersede")) {
    return "superseded";
  }
  if (effectiveTypes.has("expire") || predefinedExpired) {
    return "expired";
  }
  return "valid";
}

function predefinedExpiry(attestation: Readonly<Record<string, unknown>>): string | null {
  const schemaVersion = attestation.schema_version;
  if (schemaVersion === "rproof.attestation.v1") {
    return null;
  }
  if (schemaVersion !== "rproof.attestation.v2" && schemaVersion !== "rproof.attestation.v3") {
    throw new LifecycleValidationError("attestation schema version is unsupported");
  }
  if (!("expires_at" in attestation)) {
    throw new LifecycleValidationError("attestation lacks predefined expiry");
  }
  const expiresAt = attestation.expires_at;
  if (expiresAt === null) {
    return null;
  }
  if (typeof expiresAt !== "string") {
    throw new LifecycleValidationError("attestation expiry must follow completion");
  }
  const expiresAtMilliseconds = Date.parse(expiresAt);
  const completedAtMilliseconds = Date.parse(attestation.completed_at as string);
  if (
    !Number.isFinite(expiresAtMilliseconds) ||
    !Number.isFinite(completedAtMilliseconds) ||
    expiresAtMilliseconds <= completedAtMilliseconds
  ) {
    throw new LifecycleValidationError("attestation expiry must follow completion");
  }
  return expiresAt;
}

function validatePolicySatisfaction(
  policy: Readonly<Record<string, unknown>>,
  eligibleById: ReadonlyMap<string, Readonly<Record<string, unknown>>>,
  links: readonly Readonly<Record<string, unknown>>[],
  requiredRoles: readonly string[],
  requiredAssignments: ReadonlySet<string>,
): void {
  const policyType = policy.type;
  const threshold = policy.threshold;
  if (policyType === "threshold") {
    if (
      typeof threshold !== "number" ||
      threshold > eligibleById.size
    ) {
      throw new LifecycleValidationError("threshold policy has an invalid threshold");
    }
    if (requiredRoles.length > 0 || links.length < threshold) {
      throw new LifecycleValidationError("threshold policy is not satisfied");
    }
    return;
  }
  if (threshold !== null) {
    throw new LifecycleValidationError("non-threshold policy must not carry a threshold");
  }
  if (policyType === "all_required") {
    if (requiredRoles.length > 0 || requiredAssignments.size === 0) {
      throw new LifecycleValidationError("all-required policy shape is invalid");
    }
    return;
  }
  if (policyType === "any_reviewer") {
    if (requiredRoles.length > 0 || requiredAssignments.size > 0 || links.length === 0) {
      throw new LifecycleValidationError("any-reviewer policy shape is invalid");
    }
    return;
  }
  if (policyType === "role_quorum") {
    if (requiredRoles.length === 0) {
      throw new LifecycleValidationError("role-quorum policy must name required roles");
    }
    const eligibleRoles = new Set([...eligibleById.values()].map((reviewer) => reviewer.role_code));
    const linkedRoles = new Set(links.map((link) => link.role_code));
    if (
      !requiredRoles.every((role) => eligibleRoles.has(role)) ||
      !requiredRoles.every((role) => linkedRoles.has(role))
    ) {
      throw new LifecycleValidationError("role-quorum policy is not satisfied");
    }
    return;
  }
  throw new LifecycleValidationError("completion policy type is unsupported");
}

function isSorted(values: readonly string[]): boolean {
  return values.every(
    (value, index) =>
      index === 0 || compareCodePoints(values[index - 1] as string, value) <= 0,
  );
}

function compareCodePoints(left: string, right: string): number {
  const leftPoints = [...left];
  const rightPoints = [...right];
  for (let index = 0; index < Math.min(leftPoints.length, rightPoints.length); index += 1) {
    const difference =
      (leftPoints[index] as string).codePointAt(0)! -
      (rightPoints[index] as string).codePointAt(0)!;
    if (difference !== 0) {
      return difference;
    }
  }
  return leftPoints.length - rightPoints.length;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((value, index) => value === right[index]);
}
