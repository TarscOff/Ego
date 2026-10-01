// The AUTHORITY DIFF `ego init` prints after a change (issue #16 section 7: "reconfiguration must be versioned and
// diffable with no silent widening"). The comparison is `diffAuthorityTables` and the grading is
// `classifyAuthorityChanges`; this file only decides which of the changes WIDEN what EGO allows and says each in a line.
import {
  classifyAuthorityChanges,
  diffAuthorityTables,
  type AuthorityChange,
  type CompiledAuthorityTable,
} from '../authority/compile.ts';
import { VERDICT_RANK } from '../control-plane/types.ts';

/** Kinds that move authority outward by their nature, whatever verdict they carry. */
const WIDENING_KINDS = new Set<AuthorityChange['kind']>([
  'matcher-removed',
  'matcher-repartitioned',
  'lock-changed',
  'sanitizer-weakened',
  'grants-widened',
  'protection-removed',
  'local-target-added',
  'production-marker-removed',
]);

/** Whether a change gives an agent more room than it had. */
export function wideningChange(c: AuthorityChange): boolean {
  if (WIDENING_KINDS.has(c.kind)) return true;
  if (c.kind === 'changed' && c.from && c.to) return VERDICT_RANK[c.to] < VERDICT_RANK[c.from];
  if (c.kind === 'added') return c.to === 'ALLOW';
  return false;
}

export function describeChange(c: AuthorityChange): string {
  const where = c.cell ? ` [${c.cell}]` : '';
  const verdict = c.from || c.to ? ` ${c.from ?? '-'} -> ${c.to ?? '-'}` : '';
  const detail = c.detail ? ` (${c.detail})` : '';
  const subject = c.capability === '*' ? '' : ` ${c.capability}`;
  return `${c.kind}${subject}${where}${verdict}${detail}`;
}

export interface AuthorityDiffReport {
  level: 'none' | 'minor' | 'major';
  changes: AuthorityChange[];
  /** one line per change that widens, ready to print */
  widenings: string[];
  /** every change, widenings first, capped for a terminal */
  lines: string[];
}

const MAX_LINES = 24;

export function authorityDiffReport(
  prev: CompiledAuthorityTable,
  next: CompiledAuthorityTable,
): AuthorityDiffReport {
  const changes = diffAuthorityTables(prev, next);
  const widening = changes.filter(wideningChange);
  const rest = changes.filter((c) => !wideningChange(c));
  const all = [
    ...widening.map((c) => `WIDENS ${describeChange(c)}`),
    ...rest.map((c) => `narrows/neutral ${describeChange(c)}`),
  ];
  const lines =
    all.length > MAX_LINES ? [...all.slice(0, MAX_LINES), `... and ${all.length - MAX_LINES} more`] : all;
  return {
    level: classifyAuthorityChanges(changes, next),
    changes,
    widenings: widening.map((c) => `WIDENS ${describeChange(c)}`),
    lines,
  };
}
