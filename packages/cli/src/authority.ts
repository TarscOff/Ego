// `ego authority diff <old> <new>`: the classified changes between two compiled authority tables, every widening marked.
// `diffAuthorityTables` and `classifyAuthorityChanges` were written for the release pipeline (Q84) and referenced by no
// command, so a reconfiguration — a new organization policy, an overlay edit, an upgrade — could not be reviewed by the
// person who has to accept it (issue #16 section 7: "versioned and diffable with no silent widening"). This is that
// review. It only reads: nothing here applies, accepts or writes a policy.
import { readFileSync } from 'node:fs';
import type { CliIo } from './io.ts';
import type { ProjectContext } from './commands.ts';
import {
  classifyAuthorityChanges,
  compileAuthority,
  diffAuthorityTables,
  isWideningChange,
  type AuthorityChange,
  type CompiledAuthorityTable,
} from '../../kernel/src/authority/compile.ts';
import { LOCK_TIER_LABEL } from '../../kernel/src/authority/vocabulary.ts';
import { compileProjectPolicy, ensurePolicyCache, readAsCurrentTable } from '../../kernel/src/policy/cache.ts';
import { sealFor } from '../../kernel/src/policy/seal.ts';
import { loadControlPlane } from '../../kernel/src/control-plane/load.ts';
import { controlPlaneDir, selfIdentity, selfVersion } from '../../kernel/src/launcher/self.ts';

const USAGE =
  'usage: ego authority diff <old> <new> [--fail-on-widening]\n  an operand is `core` (the control plane with no layer), `current` (the policy in force here), `proposed` (the layer files as they are in the working tree, before a human accepts them), or the path of a policy cache or compiled table file, including one written by an earlier release';

class OperandError extends Error {}

/** A compiled table out of a policy cache or a bare table, written by this release or an earlier one. */
function tableFromJson(label: string, text: string): CompiledAuthorityTable {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new OperandError(`${label}: not an authority table (it is not JSON)`);
  }
  const candidate = (raw as { table?: unknown } | null)?.table ?? raw;
  // (one reader gives a table from an earlier release the shape this release reads - the cache reader's)
  const t = readAsCurrentTable(candidate, true);
  if (!t || t.schema !== 'ego.authority-table/1')
    throw new OperandError(
      `${label}: not an authority table (expected schema ego.authority-table/1, or a policy cache holding one)`,
    );
  return t;
}

function loadOperand(spec: string, project: ProjectContext, env: NodeJS.ProcessEnv): CompiledAuthorityTable {
  const self = { runtimeSha256: selfIdentity().runtimeSha256, version: selfVersion() };
  switch (spec) {
    case 'core':
      return compileAuthority(loadControlPlane(controlPlaneDir()), { projectRoot: project.root });
    case 'current':
      return ensurePolicyCache(controlPlaneDir(), project.root, self, { seal: sealFor(env) }).cache.table;
    case 'proposed':
      return compileProjectPolicy(controlPlaneDir(), project.root, self).table;
  }
  let text: string;
  try {
    text = readFileSync(spec, 'utf8');
  } catch (e) {
    throw new OperandError(`cannot read ${spec}: ${(e as Error).message.split('\n')[0]}`);
  }
  return tableFromJson(spec, text);
}

/** The profile × mode cells a verdict change was observed in, grouped by profile: `STANDARD 4/4, STRICT 4/4`. */
function cellsOf(prev: CompiledAuthorityTable, next: CompiledAuthorityTable, c: AuthorityChange): string {
  if (c.kind !== 'changed' || c.capability === '*' || c.from === undefined || c.to === undefined) return '';
  const parts: string[] = [];
  for (const p of Object.keys(next.profiles).sort()) {
    const modes = Object.keys(next.profiles[p]!.modes);
    const hit = modes.filter(
      (m) =>
        prev.profiles[p]?.modes[m]?.[c.capability] === c.from &&
        next.profiles[p]!.modes[m]![c.capability] === c.to,
    );
    if (hit.length) parts.push(`${p} ${hit.length}/${modes.length}`);
  }
  return parts.length ? ` [${parts.join(', ')}]` : '';
}

function describeChange(
  prev: CompiledAuthorityTable,
  next: CompiledAuthorityTable,
  c: AuthorityChange,
): string {
  const what =
    c.kind === 'lock-changed'
      ? `${LOCK_TIER_LABEL[c.fromLock!]} -> ${LOCK_TIER_LABEL[c.toLock!]}`
      : c.from !== undefined && c.to !== undefined
        ? `${c.from} -> ${c.to}`
        : c.to !== undefined
          ? `new, ${c.to}`
          : c.from !== undefined
            ? `was ${c.from}`
            : '';
  return `${c.kind.padEnd(21)} ${c.capability}${what ? `  ${what}` : ''}${cellsOf(prev, next, c)}${c.detail ? `  ${c.detail}` : ''}`;
}

export function authorityCommand(
  io: CliIo,
  project: ProjectContext | null,
  positional: string[],
  flags: Record<string, string | boolean>,
): number {
  if (!project) {
    io.err('not initialized; run `ego init`');
    return 2;
  }
  const [sub, oldSpec, newSpec] = positional;
  if (sub !== 'diff' || !oldSpec || !newSpec || positional.length > 3) {
    io.err(USAGE);
    return 2;
  }
  let prev: CompiledAuthorityTable;
  let next: CompiledAuthorityTable;
  try {
    prev = loadOperand(oldSpec, project, io.env);
    next = loadOperand(newSpec, project, io.env);
  } catch (e) {
    if (!(e instanceof OperandError)) throw e;
    io.err(`${e.message}\n${USAGE}`);
    return 2;
  }
  const changes = diffAuthorityTables(prev, next);
  const widening = changes.filter((c) => isWideningChange(c, next));
  if (changes.length === 0) {
    io.out(`authority diff ${oldSpec} -> ${newSpec}: no authority changes`);
    return 0;
  }
  io.out(
    `authority diff ${oldSpec} -> ${newSpec}: ${classifyAuthorityChanges(changes, next).toUpperCase()}, ${changes.length} change${changes.length === 1 ? '' : 's'}, ${widening.length} widening`,
  );
  // widenings first: they are the lines a reviewer has to decide on
  const ordered = [...widening, ...changes.filter((c) => !isWideningChange(c, next))];
  for (const c of ordered)
    io.out(`${isWideningChange(c, next) ? 'WIDENING' : '        '} ${describeChange(prev, next, c)}`);
  io.out(
    widening.length
      ? 'no silent widening: each WIDENING line takes effect only after a human accepts it with `ego init` from their own terminal'
      : 'no widening: every change above narrows what the table allows, or is not an authority change',
  );
  return flags['fail-on-widening'] === true && widening.length ? 1 : 0;
}
