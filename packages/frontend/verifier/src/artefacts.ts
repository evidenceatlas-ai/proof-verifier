import { packageRoot, sha256Hex } from "@reviewedproof/hashing";

const MAX_ARTEFACTS = 100;
const MAX_TOTAL_BYTES = 200_000_000;

export interface ArtefactInput {
  readonly content: Uint8Array;
  readonly entryId?: string;
}

export interface ArtefactMatchCheck {
  readonly reason_code: string;
  readonly state: "valid" | "invalid" | "not_checked";
}

export interface ArtefactMatchResult {
  readonly check: ArtefactMatchCheck;
  readonly matchedEntryIds: readonly string[];
}

interface PreparedArtefact {
  readonly artefact: ArtefactInput;
  readonly byteLength: number;
  readonly digest: string;
}

/**
 * Match local bytes to an authenticated, schema-valid package manifest.
 *
 * The caller preserves receipt-integrity results independently. File names,
 * paths, and selection order have no matching meaning and are never returned.
 */
export async function matchArtefacts(
  packageManifest: Readonly<Record<string, unknown>>,
  artefacts: readonly ArtefactInput[],
  signal?: AbortSignal,
): Promise<ArtefactMatchResult> {
  signal?.throwIfAborted();
  const entries = [
    ...(packageManifest.entries as readonly Readonly<Record<string, unknown>>[]),
  ].sort((left, right) => (left.position as number) - (right.position as number));
  if (artefacts.length === 0) {
    return result("not_checked", "no_artefacts_selected", []);
  }
  if (artefacts.length > MAX_ARTEFACTS) {
    return result("invalid", "too_many_artefacts_selected", []);
  }
  if (artefacts.reduce((total, artefact) => total + artefact.content.byteLength, 0) > MAX_TOTAL_BYTES) {
    return result("invalid", "artefact_selection_too_large", []);
  }

  const entriesById = new Map(entries.map((entry) => [entry.entry_id as string, entry]));
  const candidatesByContent = new Map<string, readonly Readonly<Record<string, unknown>>[]>();
  for (const entry of entries) {
    const contentHash = entry.content_hash as Readonly<Record<string, unknown>>;
    const key = contentKey(contentHash.value as string, entry.byte_length as number);
    candidatesByContent.set(key, [...(candidatesByContent.get(key) ?? []), entry]);
  }

  const prepared: PreparedArtefact[] = [];
  for (const artefact of artefacts) {
    prepared.push({
      artefact,
      byteLength: artefact.content.byteLength,
      digest: await sha256Hex(artefact.content, signal),
    });
  }

  const assigned = new Map<string, PreparedArtefact>();
  const invalidReasons = new Set<string>();
  let ambiguous = false;
  for (const item of prepared) {
    const entryId = item.artefact.entryId;
    if (entryId === undefined) {
      continue;
    }
    const entry = entriesById.get(entryId);
    if (entry === undefined) {
      invalidReasons.add("unknown_artefact_entry");
      continue;
    }
    if (assigned.has(entryId)) {
      invalidReasons.add("duplicate_artefact_assignment");
      continue;
    }
    if (!matches(entry, item.digest, item.byteLength)) {
      invalidReasons.add("artefact_content_mismatch");
      continue;
    }
    assigned.set(entryId, item);
  }

  for (const item of prepared) {
    if (item.artefact.entryId !== undefined) {
      continue;
    }
    const candidates = candidatesByContent.get(contentKey(item.digest, item.byteLength)) ?? [];
    if (candidates.length === 0) {
      invalidReasons.add("artefact_content_mismatch");
      continue;
    }
    const candidateIds = candidates
      .map((entry) => entry.entry_id as string)
      .filter((entryId) => !assigned.has(entryId));
    if (candidateIds.length === 0) {
      invalidReasons.add("duplicate_artefact_assignment");
      continue;
    }
    if (candidateIds.length > 1) {
      ambiguous = true;
      continue;
    }
    assigned.set(candidateIds[0] as string, item);
  }

  const matchedEntryIds = entries
    .map((entry) => entry.entry_id as string)
    .filter((entryId) => assigned.has(entryId));
  for (const reasonCode of [
    "unknown_artefact_entry",
    "duplicate_artefact_assignment",
    "artefact_content_mismatch",
  ]) {
    if (invalidReasons.has(reasonCode)) {
      return result("invalid", reasonCode, matchedEntryIds);
    }
  }
  if (ambiguous) {
    return result("not_checked", "ambiguous_artefact_assignment", matchedEntryIds);
  }
  if (assigned.size !== entries.length) {
    return result("not_checked", "partial_artefact_selection", matchedEntryIds);
  }

  const rebuiltEntries = entries.map((entry) => {
    const matched = assigned.get(entry.entry_id as string) as PreparedArtefact;
    return {
      ...entry,
      byte_length: matched.byteLength,
      content_hash: { algorithm: "sha-256", value: matched.digest },
    };
  });
  signal?.throwIfAborted();
  if ((await packageRoot(rebuiltEntries)) !== packageManifest.package_root) {
    return result("invalid", "artefact_package_root_mismatch", matchedEntryIds);
  }
  signal?.throwIfAborted();
  return result("valid", "artefacts_match_package", matchedEntryIds);
}

function matches(
  entry: Readonly<Record<string, unknown>>,
  digest: string,
  byteLength: number,
): boolean {
  const contentHash = entry.content_hash as Readonly<Record<string, unknown>>;
  return entry.byte_length === byteLength && contentHash.value === digest;
}

function contentKey(digest: string, byteLength: number): string {
  return `${digest}:${byteLength}`;
}

function result(
  state: ArtefactMatchCheck["state"],
  reasonCode: string,
  matchedEntryIds: readonly string[],
): ArtefactMatchResult {
  return { check: { reason_code: reasonCode, state }, matchedEntryIds };
}
