// THE PREVIOUS NAME OF THE ADMIN_GOVERNED TIER, AND THE ONE MODULE THAT STILL SPELLS IT.
//
// Until the Q98 naming migration (issue #16 section 12) the tier was called "organization-locked" in the schema: the
// capability file and its `family` and `lock` values, the compiled table's `organizationLocked` field, the provenance
// layer strings. The canonical term is ADMIN_GOVERNED (`admin-governed` in a file, `adminGoverned` in the table). Data
// written under the old name is in the wild — a control-plane fork an organization maintains, a policy cache on a
// developer's machine, a table a CI job kept to diff against — and it must keep its MEANING. So the old spelling is a
// READ alias: it is accepted where it is read, translated once, and reported in one line per file; nothing here
// changes a verdict, an alias never widens what the canonical spelling would refuse (the loader still rejects a tier
// declared outside the core layer), and a value this module does not recognise is left for its caller to reject.
//
// Why a rename is safe for pins and caches: the pin (`.harness/harness.md`) records version, integrity, sources,
// schemas, node and profile and NOT the authority-table hash, so no pin names the old table. The policy cache
// (`.harness/generated/policy.json`) is gitignored, per machine, and keyed on the runtime identity, so every release
// already regenerates it; what the rename adds is that a cache written before it is recognised (`isLegacyTable`),
// reported as POLICY_STALE, and upgraded in memory rather than discarded — discarding it would have forgotten which
// layer widenings a human accepted and turned each into a pending one. The table hash itself does change (the field
// name and the provenance strings are part of the hashed body); the CHANGELOG records it as a MAJOR change under Q84
// with the consumer action.
import { sha256Canonical } from '../util/hash.ts';
import type { CompiledAuthorityTable } from '../authority/compile.ts';

/** the canonical `lock:` / `family:` value of the ADMIN_GOVERNED tier in an authored file */
export const ADMIN_GOVERNED_VALUE = 'admin-governed';

/** the old `lock:` value */
const LEGACY_LOCK_VALUE = 'organization';
/** the old `family:` / `id:` value, and the old file name stem */
const LEGACY_FAMILY_VALUE = 'organization-locked';

/** A `lock:` value as the previous release wrote it, read as the canonical one. */
export function readLockValue(raw: string): { value: string; legacy: boolean } {
  return raw === LEGACY_LOCK_VALUE
    ? { value: ADMIN_GOVERNED_VALUE, legacy: true }
    : { value: raw, legacy: false };
}

/** A `family:` value as the previous release wrote it, read as the canonical one. */
export function readFamilyValue(raw: string): { value: string; legacy: boolean } {
  return raw === LEGACY_FAMILY_VALUE
    ? { value: ADMIN_GOVERNED_VALUE, legacy: true }
    : { value: raw, legacy: false };
}

/** The single line reported for a file that still uses the old spelling. */
export function legacyNamingNotice(file: string, spelled: string[]): string {
  return `DEPRECATED: ${file} spells ${spelled.join(' and ')} under the previous name of the ADMIN_GOVERNED tier (${LEGACY_FAMILY_VALUE}); it is read as ${ADMIN_GOVERNED_VALUE} and means the same. Write ${ADMIN_GOVERNED_VALUE} instead (the capability file is named ${ADMIN_GOVERNED_VALUE}.md) before the alias is removed in a future MAJOR release (Q84).`;
}

/** True for a compiled authority table written before the migration: it names the tier in `organizationLocked`. */
export function isLegacyTable(t: unknown): boolean {
  return (
    t !== null &&
    typeof t === 'object' &&
    'organizationLocked' in (t as object) &&
    !('adminGoverned' in (t as object))
  );
}

const renameFile = (file: string): string =>
  file.replace(/organization-locked\.md$/, `${ADMIN_GOVERNED_VALUE}.md`);

/**
 * A compiled table written under the old naming, in the current shape. Only names change — the tier field, the `lock`
 * and `family` values, the provenance layer strings and file names, the source-hash keys — and the hash is recomputed
 * over the renamed body, so the result is exactly the table the current compiler would write for the same inputs. A
 * table that is already current is returned as it is.
 */
export function upgradeLegacyTable(t: unknown): CompiledAuthorityTable {
  if (!isLegacyTable(t)) return t as CompiledAuthorityTable;
  const {
    organizationLocked,
    tableHash: _stale,
    ...rest
  } = structuredClone(t) as Record<string, unknown> & {
    organizationLocked: string[];
    tableHash?: string;
  };
  const body = { ...rest, adminGoverned: [...organizationLocked].sort() } as Record<string, unknown>;
  const capabilities = body['capabilities'] as Record<string, { lock?: string; family?: string }> | undefined;
  for (const c of Object.values(capabilities ?? {})) {
    if (c.lock !== undefined) c.lock = readLockValue(c.lock).value;
    if (c.family !== undefined) c.family = readFamilyValue(c.family).value;
  }
  const provenance = body['provenance'] as Record<string, Array<{ layer: string; file: string }>> | undefined;
  for (const trace of Object.values(provenance ?? {}))
    for (const step of trace) {
      step.layer = step.layer.replaceAll(LEGACY_FAMILY_VALUE, ADMIN_GOVERNED_VALUE);
      step.file = renameFile(step.file);
    }
  const hashes = body['sourceHashes'] as Record<string, string> | undefined;
  if (hashes)
    body['sourceHashes'] = Object.fromEntries(Object.entries(hashes).map(([k, v]) => [renameFile(k), v]));
  return { ...body, tableHash: sha256Canonical(body) } as unknown as CompiledAuthorityTable;
}
