// THE CANONICAL VOCABULARY OF Q98, AND THE ONE READER OF "WHERE DID THIS VERDICT COME FROM" (issue #16 sections 10 and
// 12). Five terms name what a human reads in a refusal, in `ego capabilities`, in `ego explain` and in `ego doctor`:
//
//   LOCAL_WORKSPACE   a capability whose effect stays on this machine, inside the governed development surface
//   EXTERNAL_EFFECT   one that reaches state outside it (a remote, a forge, a service, a shared cluster)
//   HARD_LOCK         the tier no layer may widen (the `absolute` lock)
//   ADMIN_GOVERNED    the tier only the organization policy layer may widen, and then no further than ASK
//   TASK_APPROVAL     one bounded human approval of one ASK, never a durable grant
//
// The compiled table keeps its short stable keys (`effect: local|external`, `lock: absolute|admin-governed|none`);
// the labels below are the ONLY place a key is turned into a word for a person. Three printers (the refusal text, the
// capability table and the doctor) used to be three readers of the same question; they read this module now.
import { VERDICT_RANK, type CapabilityLock, type Verdict } from '../control-plane/types.ts';
import type { CompiledAuthorityTable, EffectScope } from './compile.ts';

export type EffectClass = 'LOCAL_WORKSPACE' | 'EXTERNAL_EFFECT';
export type LockTierLabel = 'HARD_LOCK' | 'ADMIN_GOVERNED' | 'none';

export const EFFECT_CLASS_LABEL: Record<EffectScope, EffectClass> = {
  local: 'LOCAL_WORKSPACE',
  external: 'EXTERNAL_EFFECT',
};

export const LOCK_TIER_LABEL: Record<CapabilityLock, LockTierLabel> = {
  absolute: 'HARD_LOCK',
  'admin-governed': 'ADMIN_GOVERNED',
  none: 'none',
};

/** Identifiers that say "where this lands could not be classified" rather than naming an act: the target-resolution
 *  fallbacks (`k8s.target.unclassified`, `db.target.unclassified`, `container.target.unclassified`) and the two
 *  families whose destination nothing resolves yet (an MCP tool whose server is not in a trust file, a URL no matcher
 *  names). */
export function isTargetUnclassified(capability: string): boolean {
  return (
    capability.endsWith('.target.unclassified') ||
    capability === 'mcp.unknown' ||
    capability === 'network.unknown'
  );
}

/** The layer that SET a verdict, and the file it was read from. */
export interface VerdictSource {
  /** `core`, `absolute`, `admin-governed`, `organization (…)`, `overlay`, `profile P` or `mode M` */
  layer: string;
  /** the file the layer was read from; core files are relative to the control plane root, layer files to the project */
  file: string | null;
}

/** Where a file named in a provenance trace lives, for a person: core files sit in the control plane. */
export function displayFile(layer: string, file: string | null): string | null {
  if (file === null) return null;
  return /^(core|absolute|admin-governed)$/.test(layer) ? `control-plane/${file}` : file;
}

/** `layer (file)` as one phrase. */
export function describeSource(s: VerdictSource): string {
  const f = displayFile(s.layer, s.file);
  return f ? `${s.layer} (${f})` : s.layer;
}

/** The verdict a capability has in a profile × mode cell, falling back to the layered one when the cell is unknown. */
export function cellVerdict(
  table: CompiledAuthorityTable,
  profile: string,
  mode: string,
  id: string,
): Verdict {
  return table.profiles[profile]?.modes[mode]?.[id] ?? table.effective[id] ?? 'DENY';
}

/**
 * WHICH LAYER DECIDED THE VERDICT THAT IS IN FORCE. The provenance trace records core → organization → overlay; the
 * profile and the mode apply after it and leave no trace, so a cell that differs from the layered verdict was moved by
 * one of them. If every mode of the profile agrees on the cell it is the profile's doing, otherwise the mode's. Grant
 * annotations at the end of a trace explain a clamp; they are not a decision and are skipped.
 */
export function verdictSource(
  table: CompiledAuthorityTable,
  profile: string,
  mode: string,
  id: string,
): VerdictSource {
  const cell = cellVerdict(table, profile, mode, id);
  const layered = table.effective[id];
  const prof = table.profiles[profile];
  if (layered !== undefined && cell !== layered && prof) {
    const cells = Object.values(prof.modes).map((m) => m[id]);
    return cells.every((v) => v === cell)
      ? { layer: `profile ${profile}`, file: null }
      : { layer: `mode ${mode}`, file: null };
  }
  const last = (table.provenance[id] ?? []).filter((t) => !t.layer.startsWith('grant')).at(-1);
  return { layer: last?.layer ?? 'core', file: last?.file ?? null };
}

/**
 * THE WIDEST VERDICT ANY CONFIGURATION PATH CAN REACH, short of a human approving one operation. It is read from the
 * table, not from a list: a HARD_LOCK is DENY; an ADMIN_GOVERNED capability is ASK (the organization may enable it and
 * the clamp stops it there); anything else is the widest cell of any profile × mode, and a recognised grant phrase
 * lifts a LOCAL capability from ASK to ALLOW for the session while an EXTERNAL one stays at ASK (`applyGrants`).
 */
export function capabilityCeiling(table: CompiledAuthorityTable, id: string): Verdict {
  const c = table.capabilities[id];
  if (!c || c.lock === 'absolute') return 'DENY';
  if (c.lock === 'admin-governed') return 'ASK';
  let widest: Verdict = table.effective[id] ?? c.core;
  for (const p of Object.values(table.profiles))
    for (const m of Object.values(p.modes)) {
      const v = m[id];
      if (v !== undefined && VERDICT_RANK[v] < VERDICT_RANK[widest]) widest = v;
    }
  if (c.effect === 'local' && widest === 'ASK' && table.grants.some((g) => g.capability === id))
    widest = 'ALLOW';
  return widest;
}

/** The other profiles and modes in which a capability is wider than it is in this cell. */
export function widerElsewhere(
  table: CompiledAuthorityTable,
  profile: string,
  mode: string,
  id: string,
): { profiles: string[]; modes: string[] } {
  const here = VERDICT_RANK[cellVerdict(table, profile, mode, id)];
  const profiles = Object.keys(table.profiles)
    .filter((p) => p !== profile && VERDICT_RANK[cellVerdict(table, p, mode, id)] < here)
    .sort();
  const modes = Object.keys(table.profiles[profile]?.modes ?? {})
    .filter((m) => m !== mode && VERDICT_RANK[cellVerdict(table, profile, m, id)] < here)
    .sort();
  return { profiles, modes };
}
