import logoSymbol from "../../../assets/logo-notext.svg?raw";
import verificationHelp from '../../../documentation/helpfiles/verification.md?raw';
import {
  verifyRproof,
  type ArtefactInput,
  type VerificationCheck,
  type VerificationOutcome,
  type VerificationResult,
} from "@reviewedproof/verifier";

import { TRUST_STORE_BYTES, VERIFIER_VERSION } from "./generated/release-inputs";
import "./style.css";

const MAX_BUNDLE_BYTES = 20 * 1024 * 1024;
const MAX_ARTEFACTS = 100;
const MAX_ARTEFACT_BYTES = 200_000_000;

interface SelectedArtefact {
  readonly content: Uint8Array;
  readonly file: File;
  entryId?: string;
}

const bundleInput = element<HTMLInputElement>("bundle-input");
const bundleDropZone = element<HTMLElement>("bundle-drop-zone");
const artefactsInput = element<HTMLInputElement>("artefacts-input");
const allowNonProduction = element<HTMLInputElement>("allow-non-production");
const developmentWarning = element<HTMLElement>("development-warning");
const cancelButton = element<HTMLButtonElement>("cancel-button");
const exportButton = element<HTMLButtonElement>("export-result");
const printButton = element<HTMLButtonElement>("print-result");
const progress = element<HTMLElement>("verification-progress");
const inputError = element<HTMLElement>("input-error");
const resultElement = element<HTMLElement>("verification-result");

let bundleBytes: Uint8Array | null = null;
let artefacts: SelectedArtefact[] = [];
let outcome: VerificationOutcome | null = null;
let activeRun = 0;
let abortController: AbortController | null = null;

element("footer-version").textContent = VERIFIER_VERSION;
element("brand-symbol").innerHTML = logoSymbol
  .replace('viewBox="0 0 1024 1024"', 'viewBox="42 299 939 310"')
  .replace('stroke: #FFFFFF', 'stroke: currentColor');
configureTheme();

bundleInput.addEventListener("change", () => {
  const files = bundleInput.files;
  const file = files?.length === 1 ? files[0] as File : null;
  bundleInput.value = "";
  if (file !== null) void selectBundle(file);
});
for (const eventName of ["dragenter", "dragover"]) {
  bundleDropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    bundleDropZone.classList.add("is-dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  bundleDropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    bundleDropZone.classList.remove("is-dragging");
  });
}
bundleDropZone.addEventListener("drop", (event) => {
  const files = (event as DragEvent).dataTransfer?.files;
  if (files?.length !== 1) {
    showInputError("Select exactly one .rproof evidence package.");
    return;
  }
  void selectBundle(files[0] as File);
});

artefactsInput.addEventListener("change", () => {
  const files = artefactsInput.files;
  const selected = files === null ? [] : Array.from(files);
  artefactsInput.value = "";
  if (selected.length > 0) void selectArtefacts(selected);
});
allowNonProduction.addEventListener("change", () => {
  developmentWarning.hidden = !allowNonProduction.checked;
  if (bundleBytes !== null) void startVerification(false);
});
cancelButton.addEventListener("click", cancelVerification);
exportButton.addEventListener("click", exportResult);
printButton.addEventListener("click", () => window.print());

async function selectBundle(file: File): Promise<void> {
  element("bundle-name").textContent = "Select or drop one .rproof file";
  element("bundle-help").textContent = "Maximum compressed size: 20 MiB";
  const run = beginRun("Reading the evidence package…");
  clearInputError();
  outcome = null;
  bundleBytes = null;
  artefacts = [];
  clearResult();
  if (file.size === 0 || file.size > MAX_BUNDLE_BYTES) {
    finishRun(run);
    showInputError("The evidence package must be between 1 byte and 20 MiB.");
    return;
  }
  try {
    const content = new Uint8Array(await file.arrayBuffer());
    if (run !== activeRun) return;
    bundleBytes = content;
    element("bundle-name").textContent = file.name;
    element("bundle-help").textContent = "Selected on this device. Select or drop another file to replace it.";
    await verify(run);
  } catch (error) {
    handleRunError(error, run);
  }
}

async function selectArtefacts(files: readonly File[]): Promise<void> {
  clearInputError();
  if (files.length > MAX_ARTEFACTS) {
    abandonRun();
    showInputError("Select no more than 100 reviewed files.");
    progress.textContent = "The previous verification result remains displayed.";
    return;
  }
  const total = files.reduce((sum, file) => sum + file.size, 0);
  if (total > MAX_ARTEFACT_BYTES) {
    abandonRun();
    showInputError("The selected reviewed files exceed the 200 MB total limit.");
    progress.textContent = "The previous verification result remains displayed.";
    return;
  }
  const run = beginRun("Reading the selected reviewed files…");
  outcome = null;
  exportButton.disabled = true;
  printButton.disabled = true;
  progress.textContent = "Reading the selected reviewed files…";
  try {
    const selected: SelectedArtefact[] = [];
    for (const file of files) {
      const content = new Uint8Array(await file.arrayBuffer());
      if (run !== activeRun) return;
      selected.push({ content, file });
    }
    artefacts = selected;
    await verify(run);
  } catch (error) {
    handleRunError(error, run);
  }
}

function startVerification(preserveResult = true): Promise<void> {
  outcome = null;
  if (preserveResult) {
    exportButton.disabled = true;
    printButton.disabled = true;
    resultElement.setAttribute("aria-busy", "true");
  } else {
    clearResult();
  }
  const run = beginRun(
    artefacts.length === 0
      ? "Verifying the signed evidence…"
      : `Verifying the evidence and comparing ${artefacts.length} selected file${artefacts.length === 1 ? "" : "s"}…`,
  );
  return verify(run).catch((error: unknown) => handleRunError(error, run));
}

async function verify(run: number): Promise<void> {
  if (bundleBytes === null || abortController === null || run !== activeRun) return;
  progress.textContent = artefacts.length === 0
    ? "Verifying the signed evidence…"
    : `Verifying the evidence and comparing ${artefacts.length} selected file${artefacts.length === 1 ? "" : "s"}…`;
  const selected: ArtefactInput[] = artefacts.map(({ content, entryId }) =>
    entryId === undefined ? { content } : { content, entryId });
  const verified = await verifyRproof(bundleBytes, {
    trustStoreBytes: TRUST_STORE_BYTES,
    verifiedAt: currentWholeSecondUtc(),
    allowNonProduction: allowNonProduction.checked,
    artefacts: selected,
    verifierVersion: VERIFIER_VERSION,
    signal: abortController.signal,
  });
  if (run !== activeRun) return;
  outcome = verified;
  renderOutcome(verified);
  resultElement.removeAttribute("aria-busy");
  progress.textContent = "Verification complete.";
  finishRun(run);
}

function renderOutcome(verified: VerificationOutcome): void {
  const { result, details } = verified;
  resultElement.hidden = false;
  resultElement.dataset.status = result.status;
  element("result-heading").textContent = statusTitle(
    result.status,
    details?.lifecycleEvents ?? [],
  );
  element("status-summary").textContent = statusSummary(verified);
  element("verified-as-of").textContent = result.verified_as_of ?? "Not established";
  element("next-update").textContent = details === undefined
    ? "Not established"
    : details.statusSnapshot.next_update_due_at as string;
  renderCheck("integrity", result.receipt_integrity);
  renderCheck("match", result.artefact_match);
  renderTechnicalDetails(result, details?.rootFingerprintSha256);
  renderWarnings(result.warnings);

  const hasAuthenticatedDetails = details !== undefined;
  element<HTMLElement>("artefact-controls").hidden = !hasAuthenticatedDetails;
  artefactsInput.disabled = !hasAuthenticatedDetails;
  if (details === undefined) {
    renderUnavailableDetails();
  } else {
    renderAttestation(details.attestation);
    renderAssurance(details.attestation);
    renderSignatureAndTimestamp(verified);
    renderLifecycle(verified);
    renderArtefacts(details.packageManifest, result);
  }
  developmentWarning.hidden = !allowNonProduction.checked &&
    (result.environment === null || result.environment === "production");
  exportButton.disabled = false;
  printButton.disabled = false;
}

function statementText(value: unknown, property: "purpose" | "scope"): string {
  if (typeof value !== "string") return String(value ?? "");
  try {
    const parsed: unknown = JSON.parse(value);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed) &&
        Object.keys(parsed).length === 1 &&
        typeof (parsed as Record<string, unknown>)[property] === "string") {
      return (parsed as Record<string, string>)[property]!;
    }
  } catch { /* Plain statement text needs no decoding. */ }
  return value;
}

function renderAttestation(attestation: Readonly<Record<string, unknown>>): void {
  const statement = attestation.statement as Readonly<Record<string, unknown>>;
  element("attestation-text").textContent = statement.exact_text as string;
  setDefinitions("attestation-details", [
    ["Purpose", statementText(statement.purpose, "purpose")],
    ["Scope", statementText(statement.scope, "scope")],
    ["Completed at", attestation.completed_at],
    ["Signed predefined expiry", predefinedExpiryText(attestation)],
    ["Receipt ID", attestation.receipt_id],
    ["Review ID", attestation.review_id],
    ["Reviewer declarations and comments", statement.comment ?? "None"],
  ]);
  const declarations = statement.declarations as readonly string[];
  const block = element<HTMLElement>("declarations-block");
  block.hidden = declarations.length === 0;
  replaceList("declarations", declarations);
}

function renderAssurance(attestation: Readonly<Record<string, unknown>>): void {
  const reviewer = attestation.reviewer as Readonly<Record<string, unknown>>;
  const identity = attestation.identity_assurance as Readonly<Record<string, unknown>>;
  setDefinitions("identity-details", [
    ["Reviewer", reviewer.display_name ?? "Name not disclosed"],
    ["Subject ID", reviewer.subject_id],
    ["Assurance level", identity.level],
    ["Methods", (identity.methods as readonly string[]).join(", ")],
    ["Provider", identity.provider],
    ["Assessed at", identity.assessed_at],
    ["Policy", identity.policy_version],
  ]);
  const authority = attestation.organisation_authority;
  if (authority === null) {
    setDefinitions("authority-details", [
      ["Claim", "No organisation authority claim is carried by this attestation."],
    ]);
    return;
  }
  const claim = authority as Readonly<Record<string, unknown>>;
  setDefinitions("authority-details", [
    ["Authority type", claim.authority_type],
    ["Organisation ID", claim.organisation_id],
    ["Valid at attestation", claim.valid_at_attestation === true ? "Yes" : "No"],
    ["Grant digest", claim.grant_digest],
  ]);
}

function renderSignatureAndTimestamp(verified: VerificationOutcome): void {
  const details = verified.details as NonNullable<VerificationOutcome["details"]>;
  element("signature-summary").textContent =
    `The attestation, bundle manifest and their operational signing-key statements were authenticated. ReviewedProof issuer root fingerprint: ${details.rootFingerprintSha256}`;
  setDefinitions("timestamp-details", [
    ["Token generation time", details.timestamp.tokenGenTime],
    ["Timestamp check", checkLabel(verified.result.checks.timestamp)],
  ]);
}

function renderLifecycle(verified: VerificationOutcome): void {
  const details = verified.details as NonNullable<VerificationOutcome["details"]>;
  const status = details.statusSnapshot;
  element("lifecycle-summary").textContent =
    `The signed snapshot carried “${statusLabel(verified.result.status)}” at ${String(status.generated_at)}. Its informational next-update horizon is ${String(status.next_update_due_at)}.`;
  const items = details.lifecycleEvents.map((event) => {
    const parts = [
      `${lifecycleEventLabel(event)} effective ${String(event.effective_at)}`,
      `recorded ${String(event.recorded_at)}`,
    ];
    if (hasPrivateAuditCommitment(event)) {
      parts.push("a private audit reason is retained by ReviewedProof");
    } else if (event.reason_code !== undefined) {
      parts.push(`reason ${String(event.reason_code).replaceAll("_", " ")}`);
    }
    if (event.replacement_receipt_id !== undefined) {
      parts.push(`replacement receipt ${String(event.replacement_receipt_id)}`);
    }
    return parts.join("; ");
  });
  replaceList("lifecycle-events", items.length === 0 ? ["No lifecycle events are carried."] : items);

  const completionBlock = element<HTMLElement>("completion-block");
  completionBlock.hidden = details.completion === null;
  if (details.completion !== null) {
    const heading = completionBlock.querySelector("h3");
    if (heading !== null) heading.textContent = "Historical review completion";
    const policy = details.completion.policy_snapshot as Readonly<Record<string, unknown>>;
    const links = details.completion.receipt_links as readonly unknown[];
    setDefinitions("completion-details", [
      ["First policy satisfaction", details.completion.satisfied_at],
      [
        "Meaning",
        "This signed record shows when the frozen policy was first satisfied. It does not guarantee current completion; later withdrawals or expiry can change current contributors.",
      ],
      ["Policy type", policy.type],
      ["Contributing receipt count", links.length],
      ["Completion ID", details.completion.completion_id],
    ]);
  }
}

function renderArtefacts(
  packageManifest: Readonly<Record<string, unknown>>,
  result: VerificationResult,
): void {
  const entries = [
    ...(packageManifest.entries as readonly Readonly<Record<string, unknown>>[]),
  ].sort((left, right) => (left.position as number) - (right.position as number));
  const matched = new Set(result.matched_entry_ids);
  const rows = element<HTMLTableSectionElement>("package-entries");
  rows.replaceChildren();
  for (const entry of entries) {
    const contentHash = entry.content_hash as Readonly<Record<string, unknown>>;
    const row = document.createElement("tr");
    appendCells(row, [
      entry.position,
      entry.name,
      formatBytes(entry.byte_length as number),
      abbreviate(contentHash.value as string),
      matched.has(entry.entry_id as string)
        ? "Matched"
        : artefacts.length === 0
          ? "Not selected"
          : "Not matched",
    ]);
    rows.append(row);
  }
  renderSelectedFiles(entries);
}

function renderSelectedFiles(
  entries: readonly Readonly<Record<string, unknown>>[],
): void {
  const list = element<HTMLUListElement>("selected-files");
  list.replaceChildren();
  for (const [index, selected] of artefacts.entries()) {
    const item = document.createElement("li");
    const name = document.createElement("span");
    name.className = "selected-file-name";
    name.textContent = `${selected.file.name} (${formatBytes(selected.file.size)})`;
    const label = document.createElement("label");
    label.textContent = "Assign to ";
    const select = document.createElement("select");
    select.setAttribute("aria-label", `Manifest assignment for selected file ${index + 1}`);
    const automatic = document.createElement("option");
    automatic.value = "";
    automatic.textContent = "Match automatically";
    select.append(automatic);
    for (const entry of entries) {
      const option = document.createElement("option");
      option.value = entry.entry_id as string;
      option.textContent = `Position ${String(entry.position)} — ${String(entry.name)}`;
      select.append(option);
    }
    select.value = selected.entryId ?? "";
    select.addEventListener("change", () => {
      selected.entryId = select.value === "" ? undefined : select.value;
      void startVerification();
    });
    label.append(select);
    item.append(name, label);
    list.append(item);
  }
}

function renderTechnicalDetails(
  result: VerificationResult,
  issuerRootFingerprint?: string,
): void {
  setDefinitions("technical-details", [
    ["Verifier version", result.verifier_version],
    ["Trust-store version", result.trust_store_version],
    ["Trust-store SHA-256", result.trust_store_sha256],
    ["Bundle SHA-256", result.bundle_sha256 ?? "Not calculated"],
    ["Evidence environment", result.environment ?? "Not authenticated"],
    ["Receipt ID", result.receipt_id ?? "Not authenticated"],
    ["Verification time", result.verified_at],
    ["Execution mode", result.execution_mode],
    ["ReviewedProof issuer root fingerprint", issuerRootFingerprint ?? "Not authenticated"],
  ]);
  const body = element<HTMLTableSectionElement>("checks");
  body.replaceChildren();
  for (const [name, check] of Object.entries(result.checks)) {
    const row = document.createElement("tr");
    appendCells(row, [name.replaceAll("_", " "), stateLabel(check.state), check.reason_code]);
    body.append(row);
  }
}

function renderWarnings(warnings: readonly string[]): void {
  replaceList("warnings", warnings);
}

function renderUnavailableDetails(): void {
  element("attestation-text").textContent =
    "Authenticated attestation detail is unavailable because required evidence verification did not complete.";
  setDefinitions("attestation-details", []);
  element<HTMLElement>("declarations-block").hidden = true;
  setDefinitions("identity-details", [["State", "Authenticated identity detail is unavailable."]]);
  setDefinitions("authority-details", [["State", "Authenticated authority detail is unavailable."]]);
  element("signature-summary").textContent = "Required signature evidence was not fully authenticated.";
  setDefinitions("timestamp-details", [["State", "Authenticated timestamp detail is unavailable."]]);
  element("lifecycle-summary").textContent = "Authenticated lifecycle detail is unavailable.";
  replaceList("lifecycle-events", []);
  element<HTMLElement>("completion-block").hidden = true;
}

function renderCheck(prefix: "integrity" | "match", value: VerificationCheck): void {
  element(`${prefix}-state`).textContent = stateLabel(value.state);
  element(`${prefix}-reason`).textContent = plainCheckReason(prefix, value);
}

function setDefinitions(
  id: string,
  values: readonly (readonly [string, unknown])[],
): void {
  const list = element<HTMLDListElement>(id);
  list.replaceChildren();
  for (const [term, value] of values) {
    const group = document.createElement("div");
    const name = document.createElement("dt");
    const description = document.createElement("dd");
    name.textContent = term;
    description.textContent = String(value);
    group.append(name, description);
    list.append(group);
  }
}

function replaceList(id: string, values: readonly string[]): void {
  const list = element<HTMLUListElement>(id);
  list.replaceChildren();
  for (const value of values) {
    const item = document.createElement("li");
    item.textContent = value;
    list.append(item);
  }
}

function appendCells(row: HTMLTableRowElement, values: readonly unknown[]): void {
  for (const value of values) {
    const cell = document.createElement("td");
    cell.textContent = String(value);
    row.append(cell);
  }
}

function exportResult(): void {
  if (outcome === null) return;
  const content = `${JSON.stringify(outcome.result, null, 2)}\n`;
  const url = URL.createObjectURL(new Blob([content], { type: "application/json" }));
  const link = document.createElement("a");
  link.download = "verification-result.json";
  link.href = url;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function beginRun(message: string): number {
  abortController?.abort();
  abortController = new AbortController();
  activeRun += 1;
  cancelButton.disabled = false;
  progress.textContent = message;
  return activeRun;
}

function finishRun(run: number): void {
  if (run !== activeRun) return;
  abortController = null;
  cancelButton.disabled = true;
}

function cancelVerification(): void {
  if (abortController === null) return;
  abortController.abort();
  abortController = null;
  activeRun += 1;
  cancelButton.disabled = true;
  resultElement.removeAttribute("aria-busy");
  progress.textContent = resultElement.hidden
    ? "Verification cancelled. No validity result was produced."
    : "Verification cancelled. The previous verification result remains displayed.";
}

function handleRunError(error: unknown, run: number): void {
  if (run !== activeRun) return;
  finishRun(run);
  resultElement.removeAttribute("aria-busy");
  if (isAbort(error)) {
    progress.textContent = "Verification cancelled. No validity result was produced.";
    return;
  }
  showInputError("Verification could not be completed in this browser.");
  progress.textContent = "Verification stopped without a validity result.";
}

function clearResult(): void {
  resultElement.hidden = true;
  resultElement.removeAttribute("aria-busy");
  delete resultElement.dataset.status;
  exportButton.disabled = true;
  printButton.disabled = true;
  artefactsInput.disabled = true;
}

function abandonRun(): void {
  abortController?.abort();
  abortController = null;
  activeRun += 1;
  cancelButton.disabled = true;
  resultElement.removeAttribute("aria-busy");
}

function showInputError(message: string): void {
  inputError.textContent = message;
  inputError.hidden = false;
}

function clearInputError(): void {
  inputError.textContent = "";
  inputError.hidden = true;
}

function configureTheme(): void {
  const button = element<HTMLButtonElement>("theme-toggle");
  const dark = typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
  setTheme(dark);
  button.addEventListener("click", () => {
    setTheme(document.documentElement.dataset.rpTheme !== "dark");
  });
}

function setTheme(dark: boolean): void {
  document.documentElement.dataset.rpTheme = dark ? "dark" : "light";
  const button = element<HTMLButtonElement>("theme-toggle");
  button.title = dark ? "Switch to light theme" : "Switch to dark theme";
  button.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    (dark ? '<circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5" />' :
      '<path d="M20.9 13A9 9 0 0 1 11 3.1 9 9 0 1 0 20.9 13Z" />') + '</svg>';
  button.setAttribute("aria-pressed", String(dark));
}

function currentWholeSecondUtc(): string {
  return new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

function statusTitle(
  status: VerificationResult["status"],
  lifecycleEvents: readonly Readonly<Record<string, unknown>>[],
): string {
  if (status === "valid_but_revoked") {
    const withdrawal = latestWithdrawalLabel(lifecycleEvents);
    if (withdrawal !== null) return withdrawal;
  }
  return {
    valid: "Evidence valid at the signed status time",
    valid_but_revoked: "Evidence valid, receipt revoked",
    superseded: "Receipt superseded",
    expired: "Receipt expired",
    incomplete_proof: "Evidence package incomplete",
    unsupported: "Evidence unsupported by this verifier",
    invalid: "Evidence verification failed",
  }[status];
}

function statusSummary(verified: VerificationOutcome): string {
  const { result, details } = verified;
  if (result.status === "unsupported") {
    return "This evidence needs a newer trusted ReviewedProof verifier that supports its required contract. This verifier did not treat the evidence as valid.";
  }
  if (result.receipt_integrity.state !== "valid") {
    return "The signed status and current revocation state were not established by this verification.";
  }
  const horizon = "Current lifecycle status after the signed snapshot time was not checked.";
  if (result.status === "valid_but_revoked") {
    const withdrawal = latestWithdrawalLabel(details?.lifecycleEvents ?? []);
    if (withdrawal !== null) return `${withdrawal}. ${horizon}`;
  }
  if (result.status === "superseded") {
    const replacement = [...(details?.lifecycleEvents ?? [])]
      .reverse()
      .find((event) => event.event_type === "supersede")?.replacement_receipt_id;
    if (typeof replacement === "string") {
      return `This receipt was superseded by replacement receipt ${replacement}. ${horizon}`;
    }
  }
  return `Cryptographic evidence is valid as of the signed status snapshot. ${horizon}`;
}

function latestWithdrawalLabel(
  lifecycleEvents: readonly Readonly<Record<string, unknown>>[],
): string | null {
  for (const event of [...lifecycleEvents].reverse()) {
    const label = withdrawalLabel(event);
    if (label !== null) return label;
  }
  return null;
}

function lifecycleEventLabel(event: Readonly<Record<string, unknown>>): string {
  const withdrawal = withdrawalLabel(event);
  if (withdrawal !== null) return withdrawal;
  return {
    revoke: "Revoked",
    supersede: "Superseded by replacement receipt",
    expire: "Expired",
    correct_display_metadata: "Display information corrected",
  }[String(event.event_type)] ?? "Lifecycle event";
}

function withdrawalLabel(event: Readonly<Record<string, unknown>>): string | null {
  if (event.event_type !== "revoke" || !isRecord(event.actor_authority)) return null;
  if (event.actor_authority.authority_type === "reviewer_self_revocation") {
    return "Attestation withdrawn by reviewer";
  }
  if (event.actor_authority.authority_type === "org_admin_review_withdrawal") {
    return "Review withdrawn by organisation administrator";
  }
  return null;
}

function hasPrivateAuditCommitment(event: Readonly<Record<string, unknown>>): boolean {
  return (typeof event.explanation === "string" &&
      /^private_reason_sha256:[0-9a-f]{64}$/u.test(event.explanation)) ||
    (typeof event.purpose === "string" &&
      /^replacement_review:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} private_reason_sha256:[0-9a-f]{64}$/u.test(event.purpose));
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stateLabel(state: VerificationCheck["state"]): string {
  return state.replaceAll("_", " ").replace(/^./, (value) => value.toUpperCase());
}

function statusLabel(status: VerificationResult["status"]): string {
  return status.replaceAll("_", " ");
}

function predefinedExpiryText(attestation: Readonly<Record<string, unknown>>): string {
  if (attestation.schema_version === "rproof.attestation.v2" || attestation.schema_version === "rproof.attestation.v3") {
    if (attestation.expires_at === null) return "No predefined expiry";
    return typeof attestation.expires_at === "string" ? attestation.expires_at : "Not available";
  }
  if (attestation.schema_version === "rproof.attestation.v1") {
    return "No predefined expiry in this evidence contract";
  }
  return "Not available";
}

function checkLabel(value: VerificationCheck): string {
  return `${stateLabel(value.state)} (${value.reason_code})`;
}

function plainCheckReason(prefix: "integrity" | "match", value: VerificationCheck): string {
  if (prefix === "integrity") {
    if (value.state === "valid") return "Signed evidence is authentic and internally consistent.";
    if (value.state === "unsupported") return "This verifier cannot evaluate required evidence.";
    if (value.state === "not_present") return "Required receipt evidence is missing.";
    return "Required receipt evidence did not pass verification.";
  }
  const reasons: Readonly<Record<string, string>> = {
    no_artefacts_selected: "No local reviewed files were selected for comparison.",
    artefacts_match_package: "Every selected file matches the authenticated package.",
    artefact_content_mismatch: "At least one selected file differs from the authenticated package.",
    partial_artefact_selection: "Only part of the authenticated package was selected.",
    ambiguous_artefact_assignment: "Identical file content needs an explicit manifest assignment.",
    duplicate_artefact_assignment: "More than one selected file was assigned to the same entry.",
    unknown_artefact_entry: "A selected file was assigned to an unknown package entry.",
    evidence_verification_failed: "Files were not compared because receipt verification failed.",
  };
  return reasons[value.reason_code] ?? "The local file comparison did not complete.";
}

function abbreviate(value: string): string {
  return value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (value === null) throw new Error(`Offline Verifier element is missing: ${id}`);
  return value as T;
}

// Bundled help keeps the standalone verifier usable without network access.
const helpDrawer = element<HTMLDialogElement>("help-drawer");
const helpContent = element<HTMLElement>("help-content");
for (const paragraph of verificationHelp.trim().split(/\n\s*\n/)) {
  const heading = /^(#{1,3}) (.+)$/.exec(paragraph);
  const node = document.createElement(heading ? `h${Math.min(heading[1]!.length + 1, 4)}` : "p");
  node.textContent = heading ? heading[2]! : paragraph.replace(/\n/g, " ");
  helpContent.append(node);
}
element<HTMLButtonElement>("help-toggle").addEventListener("click", () => helpDrawer.showModal());
element<HTMLButtonElement>("help-close").addEventListener("click", () => helpDrawer.close());
