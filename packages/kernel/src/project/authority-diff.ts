// The AUTHORITY DIFF `ego init` prints after a change (issue #16 section 7: "reconfiguration must be versioned and
// diffable with no silent widening"). The comparison is `diffAuthorityTables`, the grade is `classifyAuthorityChanges` and
// the question "does this change widen" is `isWideningChange` - the same three the pending-widening gate and `ego authority
// diff` read (`authority/table-diff.ts`). This file only says each change in a line: it holds NO predicate of its own, because
// the one it used to hold marked a different set than `ego authority diff` did (a new ALLOW matcher, the removal of a
// capability) for the same pair of tables.
import {
  classifyAuthorityChanges,
  describeAuthorityChange,
  diffAuthorityTables,
  isWideningChange,
  type AuthorityChange,
  type CompiledAuthorityTable,
} from '../authority/compile.ts';

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
  const widening = changes.filter((c) => isWideningChange(c, next));
  const rest = changes.filter((c) => !isWideningChange(c, next));
  const all = [
    ...widening.map((c) => `WIDENS ${describeAuthorityChange(c)}`),
    ...rest.map((c) => `narrows/neutral ${describeAuthorityChange(c)}`),
  ];
  const lines =
    all.length > MAX_LINES ? [...all.slice(0, MAX_LINES), `... and ${all.length - MAX_LINES} more`] : all;
  return {
    level: classifyAuthorityChanges(changes, next),
    changes,
    widenings: widening.map((c) => `WIDENS ${describeAuthorityChange(c)}`),
    lines,
  };
}
