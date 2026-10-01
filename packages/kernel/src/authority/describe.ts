// THE PER-CAPABILITY VIEW (issue #16 section 12: "Every external capability should expose effect class, selected verdict,
// maximum ceiling, scope/target constraints, availability and rule provenance"). `ego capabilities`, `ego explain
// capability` and `ego doctor` print the same fields because they read this module and nothing else; every field is
// derived from the compiled table (the effect class and lock tier are the table's own keys, the ceiling is
// `capabilityCeiling`, the source is `verdictSource`, the target rule is the resolver's own table) and none is listed by
// hand, so a capability added to the control plane appears in all three the day it compiles.
import type { Verdict } from '../control-plane/types.ts';
import type { CompiledAuthorityTable } from './compile.ts';
import { targetGroups, targetRuleFor } from './evaluate.ts';
import {
  EFFECT_CLASS_LABEL,
  LOCK_TIER_LABEL,
  capabilityCeiling,
  cellVerdict,
  describeSource,
  verdictSource,
  type EffectClass,
  type LockTierLabel,
} from './vocabulary.ts';

export interface CapabilityView {
  id: string;
  description: string;
  family: string;
  effectClass: EffectClass;
  lockTier: LockTierLabel;
  /** the verdict in force in the profile × mode asked about */
  verdict: Verdict;
  /** the widest verdict any configuration path can reach (ASK for an ADMIN_GOVERNED external write) */
  ceiling: Verdict;
  /** the layer that decided the verdict, with its file */
  source: string;
  /** the target-classification rule, for a capability whose verdict depends on where the command points */
  targetRule?: string;
}

export function describeCapability(
  table: CompiledAuthorityTable,
  profile: string,
  mode: string,
  id: string,
): CapabilityView | undefined {
  const c = table.capabilities[id];
  if (!c) return undefined;
  const view: CapabilityView = {
    id,
    description: c.description,
    family: c.family,
    effectClass: EFFECT_CLASS_LABEL[c.effect],
    lockTier: LOCK_TIER_LABEL[c.lock],
    verdict: cellVerdict(table, profile, mode, id),
    ceiling: capabilityCeiling(table, id),
    source: describeSource(verdictSource(table, profile, mode, id)),
  };
  const rule = targetRuleFor(table, id);
  if (rule !== undefined) view.targetRule = rule;
  return view;
}

export function describeCapabilities(
  table: CompiledAuthorityTable,
  profile: string,
  mode: string,
): CapabilityView[] {
  return Object.keys(table.capabilities)
    .sort()
    .map((id) => describeCapability(table, profile, mode, id)!);
}

/** What `ego doctor` lists by default (issue #16 section 12): every capability an administrator decides
 *  (ADMIN_GOVERNED), one by one, and the target-dependent ones grouped by the kind of target that decides them, each
 *  group with the one rule that classifies it. The rest are counted in the summary; `ego doctor --capabilities` and
 *  `ego capabilities` print every capability. */
export function governedSurface(
  table: CompiledAuthorityTable,
  views: CapabilityView[],
): {
  adminGoverned: CapabilityView[];
  targets: Array<{ kind: string; capabilities: string[]; rule: string }>;
} {
  return {
    adminGoverned: views.filter((v) => v.lockTier === 'ADMIN_GOVERNED'),
    targets: targetGroups(table),
  };
}

/** One line per capability: verdict, id, then the five facts. */
export function formatCapabilityRow(v: CapabilityView): string {
  return `${v.verdict.padEnd(5)} ${v.id} | ${v.effectClass} | lock ${v.lockTier} | ceiling ${v.ceiling} | source ${v.source} — ${v.description}`;
}

/** The facts as `key value` pairs for the places that already print `item: detail` (doctor). */
export function formatCapabilityFacts(v: CapabilityView): string {
  return `${v.effectClass}, lock ${v.lockTier}, ${v.verdict} here, ceiling ${v.ceiling}, source ${v.source}${v.targetRule ? `; target: ${v.targetRule}` : ''}`;
}

/** Counts for the doctor's summary line. */
export function summarize(views: CapabilityView[]): string {
  const n = (f: (v: CapabilityView) => boolean): number => views.filter(f).length;
  return `${views.length} capabilities: ${n((v) => v.lockTier === 'HARD_LOCK')} HARD_LOCK, ${n((v) => v.lockTier === 'ADMIN_GOVERNED')} ADMIN_GOVERNED, ${n((v) => v.lockTier === 'none')} unlocked; ${n((v) => v.effectClass === 'LOCAL_WORKSPACE')} LOCAL_WORKSPACE, ${n((v) => v.effectClass === 'EXTERNAL_EFFECT')} EXTERNAL_EFFECT`;
}
