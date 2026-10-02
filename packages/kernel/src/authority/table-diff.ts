// "IS THIS TABLE WIDER" HAS ONE READER, AND IT IS DERIVED FROM ONE DESCRIPTION OF THE TABLE (closure audit 2026-10-02, AUTH-3).
//
// Four things answer the question "does this authority table give an agent more room than that one":
//   - the RELEASE gate and `ego authority diff` (Q84: a MAJOR change, every widening marked);
//   - the AUTHORITY DIFF `ego init` prints after a change;
//   - the PENDING-WIDENING gate (`policy/cache.ts`): a layer file that widens is never applied from the working tree by a hook;
//   - the CLAMP that holds a pending widening back.
// They were four hand-written readers, each covering the dimensions its author had met. The compiled table has twenty-three
// fields and the hash covers every one of them, but the diff read the verdict cells, the matchers, the locks, the grants, the
// protected paths, the sanitizer minimums and the local-target declarations, and the gate read three of those. A change to the
// bounded-command vocabulary lists, to the kernel's own local-target lists, to the default mode, to a profile's trust
// requirement or to the ORDER of the matchers (the first one that matches wins) changed the hash and was reported as "no change"
// to the person who had to accept it, and `ego init` and `ego authority diff` marked widenings with two different predicates.
//
// Now there is one description - `AUTHORITY_TABLE_FIELDS` - with an entry for every field of the table, typed so that adding a
// field to `CompiledAuthorityTable` without saying what it is does not compile. An entry is either an AUTHORITY field (it carries
// the function that reads its changes), or says why it carries no authority (DERIVED from other fields, or PROVENANCE: why and
// where, never a verdict). The diff is the loop over that record; "widening" is one predicate over its changes; the gate is the
// widening subset of it; and the clamp falls back to the baseline's value of any field the diff still finds wider. A test derives
// the field names from a compiled table and proves each authority field is seen.
import { diffLocalTargets } from '../control-plane/local-targets.ts';
import {
  VERDICT_RANK,
  type CapabilityLock,
  type ExecutionBudgets,
  type Verdict,
} from '../control-plane/types.ts';
import { shownText } from '../util/shown-text.ts';
import type { CompiledAuthorityTable, CompiledMatcher } from './compile.ts';

/** every field the table hash covers */
export type TableBody = Omit<CompiledAuthorityTable, 'tableHash'>;
export type TableField = keyof TableBody;

export interface AuthorityChange {
  capability: string;
  kind:
    | 'added'
    | 'removed'
    | 'changed'
    | 'matcher-repartitioned'
    | 'matcher-removed'
    | 'matcher-added'
    | 'matcher-reordered'
    | 'lock-changed'
    | 'budget-changed'
    | 'sanitizer-weakened'
    | 'grants-widened'
    | 'grants-narrowed'
    | 'protection-removed'
    | 'local-target-added'
    | 'local-target-removed'
    | 'production-marker-added'
    | 'production-marker-removed'
    | 'vocabulary-widened'
    | 'vocabulary-narrowed'
    | 'profile-requirement-relaxed'
    | 'profile-requirement-added'
    | 'default-mode-changed';
  /** profile/mode cell where a verdict change was observed (first one found); `effective` for the layered verdict; absent for table-wide changes */
  cell?: string;
  from?: Verdict;
  to?: Verdict;
  fromLock?: CapabilityLock;
  toLock?: CapabilityLock;
  detail?: string;
  /** for the kinds whose direction is only known by comparing the two tables (the default mode) */
  widening?: boolean;
}

type Push = (c: AuthorityChange) => void;

const FIELD_OF = new WeakMap<AuthorityChange, TableField>();
/** The table field a change returned by `diffAuthorityTables` was read from (the clamp reverts a field the diff still finds wider). */
export const fieldOfChange = (c: AuthorityChange): TableField | undefined => FIELD_OF.get(c);
type FieldDiff = (prev: TableBody, next: TableBody, push: Push) => void;

type FieldReader =
  | {
      /** a change in this field can give an agent more room: the function reads every way it can */
      role: 'authority';
      diff: FieldDiff;
      note: string;
    }
  | {
      /** computed from other fields; the diff reads the fields it is computed from (`deriveMatcherViews`) */
      role: 'derived';
      from: readonly TableField[];
      note: string;
    }
  | {
      /** where a value came from or how it is shown: never decides a verdict */
      role: 'provenance';
      note: string;
    };

/* ------------------------------------------------------------------------------------------------------------- *
 * THE FIELD READERS
 * ------------------------------------------------------------------------------------------------------------- */

/** what makes two matchers THE SAME RULE: where it comes from, what it maps to, and the pattern it reads */
export function matcherIdentity(m: CompiledMatcher): string {
  return JSON.stringify([m.layer, m.capability, m.tool, m.command ?? null, m.path ?? null, m.url ?? null, m.additive === true]);
}
/**
 * WHETHER WHERE A RULE SITS MEANS ANYTHING. A command rule that is ADDITIVE contributes its hit beside the core's and the strictest
 * wins; an overlay path or url rule is combined with the core's by the path and url judges the same way. Neither is first-match-wins,
 * so adding one anywhere, or moving it, narrows (the compiler refuses one that maps to ALLOW). Every other rule is read in order.
 */
const orderless = (m: CompiledMatcher): boolean => m.additive === true || (m.layer === 'overlay' && m.command === undefined);
/** the pattern alone: what a rule READS, whichever capability it maps it to */
const matcherPattern = (m: CompiledMatcher): string => `${m.tool}|${m.command ?? ''}|${m.path ?? ''}|${m.url ?? ''}`;

const group = <T>(items: readonly T[], key: (x: T) => string): Map<string, T[]> => {
  const out = new Map<string, T[]>();
  for (const x of items) out.set(key(x), [...(out.get(key(x)) ?? []), x]);
  return out;
};

function diffEffective(prev: TableBody, next: TableBody, push: Push): void {
  const ids = new Set([...Object.keys(prev.effective), ...Object.keys(next.effective)]);
  for (const id of [...ids].sort()) {
    if (!(id in prev.effective)) push({ capability: id, kind: 'added', to: next.effective[id]! });
    else if (!(id in next.effective)) push({ capability: id, kind: 'removed', from: prev.effective[id]! });
    // (the layered verdict before profile and mode: a change here that no cell shows is one the profiles pin)
    else if (prev.effective[id] !== next.effective[id])
      push({ capability: id, kind: 'changed', cell: 'effective', from: prev.effective[id]!, to: next.effective[id]! });
  }
}

function diffProfiles(prev: TableBody, next: TableBody, push: Push): void {
  const cells = new Set<string>();
  for (const t of [prev, next])
    for (const p of Object.keys(t.profiles)) for (const m of Object.keys(t.profiles[p]!.modes)) cells.add(`${p}/${m}`);
  const ids = new Set([...Object.keys(prev.effective), ...Object.keys(next.effective)]);
  for (const cell of [...cells].sort()) {
    const [p, m] = cell.split('/') as [string, string];
    const a = prev.profiles[p]?.modes[m];
    const b = next.profiles[p]?.modes[m];
    if (!a || !b) {
      push({
        capability: '*',
        kind: a ? 'removed' : 'added',
        cell,
        detail: `profile/mode cell ${cell} ${a ? 'removed' : 'added'}`,
      });
      // a new cell is judged against the default mode of its profile: any capability it makes wider is a verdict change
      const base = b ? next.profiles[p]?.modes[next.defaultMode] : undefined;
      if (b && base)
        for (const id of Object.keys(b).sort())
          if (base[id] && VERDICT_RANK[b[id]!] < VERDICT_RANK[base[id]!])
            push({
              capability: id,
              kind: 'changed',
              cell,
              from: base[id]!,
              to: b[id]!,
              detail: `new cell ${cell} is wider than ${p}/${next.defaultMode}`,
            });
      continue;
    }
    for (const id of [...ids].sort()) if (id in a && id in b && a[id] !== b[id]) push({ capability: id, kind: 'changed', cell, from: a[id]!, to: b[id]! });
  }
  for (const p of Object.keys(next.profiles).sort()) {
    const a = prev.profiles[p];
    const b = next.profiles[p]!;
    if (!a) continue;
    // A PROFILE'S REQUIREMENT DROPPED is a widening that moves no verdict cell: the profile asks less of the runtime it governs
    for (const key of ['requiresSignedReleaseTrust', 'requiresManagedTier'] as const) {
      if (a[key] && !b[key]) push({ capability: '*', kind: 'profile-requirement-relaxed', detail: `${p}.${key}: true -> false` });
      else if (!a[key] && b[key]) push({ capability: '*', kind: 'profile-requirement-added', detail: `${p}.${key}: false -> true` });
    }
    for (const key of ['budgetTokens', 'ceilingTokens'] as const)
      if (a[key] !== b[key]) push({ capability: '*', kind: 'budget-changed', detail: `${p}.${key}: ${String(a[key])} -> ${String(b[key])}` });
    for (const k of Object.keys(b.budgets) as Array<keyof ExecutionBudgets>)
      if (a.budgets[k] !== b.budgets[k])
        push({ capability: '*', kind: 'budget-changed', detail: `${p}.${k}: ${String(a.budgets[k])} -> ${String(b.budgets[k])}` });
  }
}

function diffCapabilities(prev: TableBody, next: TableBody, push: Push): void {
  const ids = new Set([...Object.keys(prev.capabilities), ...Object.keys(next.capabilities)]);
  for (const id of [...ids].sort()) {
    const fromLock = prev.capabilities[id]?.lock;
    const toLock = next.capabilities[id]?.lock;
    if (fromLock && toLock && fromLock !== toLock) push({ capability: id, kind: 'lock-changed', fromLock, toLock });
    // a capability that stops leaving the machine stops being clamped: every grant phrase for it now lifts it
    if (prev.capabilities[id]?.effect === 'external' && next.capabilities[id]?.effect === 'local')
      push({
        capability: id,
        kind: 'grants-widened',
        detail: 'effect external -> local: a session grant now lifts it from ASK to ALLOW',
      });
  }
}

/** a tier list (`absoluteDenies`, `adminGoverned`) that loses a member loses a lock, whatever the capability map says */
function diffTier(tier: 'absolute' | 'admin-governed', list: 'absoluteDenies' | 'adminGoverned'): FieldDiff {
  return (prev, next, push) => {
    for (const id of prev[list]) {
      if (next[list].includes(id)) continue;
      // (the list is what the evaluator and the explain commands read; a capability map that still says otherwise is a table that disagrees with itself, and the list wins)
      const said = next.capabilities[id]?.lock;
      push({ capability: id, kind: 'lock-changed', fromLock: tier, toLock: said && said !== tier ? said : 'none' });
    }
  };
}

function diffMatchers(prev: TableBody, next: TableBody, push: Push): void {
  const prevIds = new Set(prev.matchers.map(matcherIdentity));
  const nextIds = new Set(next.matchers.map(matcherIdentity));
  const prevByPattern = group(prev.matchers, matcherPattern);
  const nextByPattern = group(next.matchers, matcherPattern);
  const shown = (m: CompiledMatcher): string => shownText(matcherPattern(m), 160);
  next.matchers.forEach((x, i) => {
    if (prevIds.has(matcherIdentity(x))) return;
    if (orderless(x)) {
      push({ capability: x.capability, kind: 'matcher-added', detail: shown(x) });
      return;
    }
    const was = prevByPattern.get(matcherPattern(x)) ?? [];
    if (was.some((y) => y.capability === x.capability)) return; // the same rule in another layer or another spelling of additive
    const moved = was[0];
    if (moved) {
      push({ capability: x.capability, kind: 'matcher-repartitioned', detail: `${shown(x)}: ${moved.capability} -> ${x.capability}` });
      return;
    }
    // a new matcher placed before an existing matcher of the same tool with a different verdict re-partitions the
    // operations that existing matcher used to classify (Q84: MAJOR); appended after every peer it only narrows what
    // was unknown (MINOR when its capability is not ALLOW)
    const mine = next.effective[x.capability] ?? 'ASK';
    const shadowed = next.matchers
      .slice(i + 1)
      .some(
        (z) =>
          !orderless(z) &&
          prevByPattern.has(matcherPattern(z)) &&
          (z.tool === x.tool || z.tool === 'any' || x.tool === 'any') &&
          (next.effective[z.capability] ?? 'ASK') !== mine,
      );
    push({
      capability: x.capability,
      kind: shadowed ? 'matcher-repartitioned' : 'matcher-added',
      detail: shadowed ? `${shown(x)}: inserted before existing matchers of a different verdict` : shown(x),
    });
  });
  for (const y of prev.matchers) {
    if (nextIds.has(matcherIdentity(y))) continue;
    const now = nextByPattern.get(matcherPattern(y)) ?? [];
    // the same rule spelled in another layer loses nothing; a CORE rule that now maps elsewhere was reported above, from the
    // side that holds the new capability; an OVERLAY narrowing that is gone is reported even when a core rule reads the same
    // pattern, because the core rule is the one it narrowed
    if (now.some((x) => x.capability === y.capability)) continue;
    if (y.layer === 'core' && now.length > 0) continue;
    push({ capability: y.capability, kind: 'matcher-removed', detail: shown(y) });
  }
  // THE FIRST MATCHING RULE WINS, so the ORDER of rules is part of what each one means. Two rules that swap places change the
  // verdict of every command both match and add, remove and re-map nothing: `git stash --all` was DENY (the runtime-tamper rule
  // first) and became ALLOW (the stash rule first) and the diff reported "no change".
  // (the rules whose place means something; see `orderless`)
  const before = prev.matchers.filter((m) => !orderless(m) && nextIds.has(matcherIdentity(m)));
  const after = next.matchers.filter((m) => !orderless(m) && prevIds.has(matcherIdentity(m)));
  for (let i = 0; i < Math.max(before.length, after.length); i++) {
    if (before[i] !== undefined && after[i] !== undefined && matcherIdentity(before[i]!) === matcherIdentity(after[i]!)) continue;
    const moved = after[i] ?? before[i]!;
    push({
      capability: moved.capability,
      kind: 'matcher-reordered',
      detail: `rule order changed (first match wins): ${shown(moved)} now sits where ${before[i] ? shown(before[i]!) : 'nothing'} did`,
    });
    break;
  }
}

const phrasesOf = (t: TableBody): Set<string> => new Set(t.grants.flatMap((g) => g.phrases.map((ph) => `${g.capability}|${ph}`)));

function diffGrants(prev: TableBody, next: TableBody, push: Push): void {
  // grant phrases turn ASK into ALLOW: a new phrase widens, a removed phrase narrows
  const gp = phrasesOf(prev);
  const gn = phrasesOf(next);
  for (const k of gn)
    if (!gp.has(k)) push({ capability: k.split('|')[0]!, kind: 'grants-widened', detail: `grant phrase added: ${shownText(k.split('|').slice(1).join('|'), 80)}` });
  for (const k of gp)
    if (!gn.has(k)) push({ capability: k.split('|')[0]!, kind: 'grants-narrowed', detail: `grant phrase removed: ${shownText(k.split('|').slice(1).join('|'), 80)}` });
}

function diffProtections(prev: TableBody, next: TableBody, push: Push): void {
  const pp = (t: TableBody) => new Set(t.protectedPaths.map((x) => `${x.tool}|${x.path}|${x.capability}`));
  const nextPp = pp(next);
  for (const k of pp(prev))
    // (a path that drops out because its capability's verdict moved is the verdict's change, reported there: said once)
    if (!nextPp.has(k) && prev.effective[k.split('|')[2]!] === next.effective[k.split('|')[2]!]) push({ capability: k.split('|')[2]!, kind: 'protection-removed', detail: `protected path removed: ${shownText(k, 160)}` });
}

function diffPreDenied(prev: TableBody, next: TableBody, push: Push): void {
  for (const c of prev.preDeniedCommandClasses)
    // (a class that drops out because its capability's verdict moved is the verdict's change, reported there: said once)
    if (!next.preDeniedCommandClasses.includes(c) && prev.effective[c] === next.effective[c]) push({ capability: c, kind: 'protection-removed', detail: `pre-denied command class removed: ${c}` });
}

function diffSanitizer(prev: TableBody, next: TableBody, push: Push): void {
  // locked redaction minimums are part of the contract: a removed or lowered minimum is a MAJOR change
  for (const [id, sev] of Object.entries(prev.sanitizerLockedMinimums)) {
    const now = next.sanitizerLockedMinimums[id];
    if (!now) push({ capability: '*', kind: 'sanitizer-weakened', detail: `locked detector ${id} removed` });
    else if (sev === 'block' && now === 'warn')
      push({ capability: '*', kind: 'sanitizer-weakened', detail: `locked detector ${id} lowered from block to warn` });
  }
}

function diffLocalRegistry(prev: TableBody, next: TableBody, push: Push): void {
  // THE LOCAL-DEVELOPMENT REGISTRY IS AUTHORITY. Declaring a target local turns a refusal into an allowed operation without
  // changing a single capability verdict, so a diff that compared verdicts alone reported the widening as no change at all.
  for (const c of diffLocalTargets(prev.localTargets, next.localTargets))
    push({
      capability: '*',
      kind: (
        {
          'target-added': 'local-target-added',
          'target-removed': 'local-target-removed',
          'marker-added': 'production-marker-added',
          'marker-removed': 'production-marker-removed',
        } as const
      )[c.kind],
      detail: c.detail,
    });
  // ...and so are the kernel's own lists of what is "this machine" (kube contexts, database hosts): a pattern added to either is
  // a name that is now local, and `diffLocalTargets` reads only what a layer DECLARED
  for (const [list, noun] of [
    ['k8sLocalContexts', 'kube context'],
    ['dbLocalHosts', 'database host'],
  ] as const) {
    const had = new Set(prev.localTargets[list]);
    const has = new Set(next.localTargets[list]);
    for (const e of next.localTargets[list])
      if (!had.has(e)) push({ capability: '*', kind: 'local-target-added', detail: `${noun} pattern ${shownText(e, 80)} added to the kernel's local list` });
    for (const e of prev.localTargets[list])
      if (!has.has(e)) push({ capability: '*', kind: 'local-target-removed', detail: `${noun} pattern ${shownText(e, 80)} removed from the kernel's local list` });
  }
}

/** For each list of the bounded-command vocabulary: what a MEMBER of it means to the evaluator, which decides which way a change goes. */
const VOCABULARY: ReadonlyArray<{ list: keyof TableBody['boundedCommands']; means: string; widensWhen: 'added' | 'removed' }> = [
  { list: 'bounded', means: 'bounded vocabulary: {} declared to introduce no executable closure', widensWhen: 'added' },
  { list: 'installsDependencies', means: 'installs-dependencies vocabulary: {} no longer treated as acquiring third-party code', widensWhen: 'removed' },
  { list: 'discoversContent', means: 'discovers-content vocabulary: {} no longer treated as running the content it discovers', widensWhen: 'removed' },
  { list: 'discoversConfig', means: 'discovers-config vocabulary: {} no longer treated as importing the configuration it finds', widensWhen: 'removed' },
];

function diffVocabulary(prev: TableBody, next: TableBody, push: Push): void {
  // Declaring a command head BOUNDED widens what may hold a positive semantic claim without changing any capability verdict;
  // taking a tool out of a DISCOVERING list does the same. The other direction asks more and narrows.
  for (const { list, means, widensWhen } of VOCABULARY) {
    const had = new Set(prev.boundedCommands?.[list] ?? []);
    const has = new Set(next.boundedCommands?.[list] ?? []);
    for (const e of has)
      if (!had.has(e))
        push({
          capability: '*',
          kind: widensWhen === 'added' ? 'vocabulary-widened' : 'vocabulary-narrowed',
          detail: widensWhen === 'added' ? means.replace('{}', shownText(e, 80)) : `${list}: ${shownText(e, 80)} added`,
        });
    for (const e of had)
      if (!has.has(e))
        push({
          capability: '*',
          kind: widensWhen === 'removed' ? 'vocabulary-widened' : 'vocabulary-narrowed',
          detail: widensWhen === 'removed' ? means.replace('{}', shownText(e, 80)) : `${list}: ${shownText(e, 80)} removed`,
        });
  }
}

function diffDefaultMode(prev: TableBody, next: TableBody, push: Push): void {
  if (prev.defaultMode === next.defaultMode) return;
  // the mode every session starts in decides every verdict until a person says otherwise: it widens unless it can be proved not to
  let widening = false;
  for (const p of Object.keys(next.profiles)) {
    const a = prev.profiles[p]?.modes[prev.defaultMode];
    const b = next.profiles[p]?.modes[next.defaultMode];
    if (!b) continue;
    if (!a) {
      widening = true;
      continue;
    }
    for (const id of Object.keys(b)) if (id in a && VERDICT_RANK[b[id]!] < VERDICT_RANK[a[id]!]) widening = true;
  }
  push({ capability: '*', kind: 'default-mode-changed', widening, detail: `default mode ${shownText(prev.defaultMode, 60)} -> ${shownText(next.defaultMode, 60)}` });
}

function diffNegations(prev: TableBody, next: TableBody, push: Push): void {
  for (const n of prev.grantNegations)
    if (!next.grantNegations.includes(n)) push({ capability: '*', kind: 'grants-widened', detail: `grant negation removed: ${shownText(n, 60)}` });
}

function diffNegationWindow(prev: TableBody, next: TableBody, push: Push): void {
  if (next.grantNegationWindowTokens < prev.grantNegationWindowTokens)
    push({
      capability: '*',
      kind: 'grants-widened',
      detail: `negation window ${prev.grantNegationWindowTokens} -> ${next.grantNegationWindowTokens}`,
    });
}

/**
 * THE ONE DESCRIPTION OF THE COMPILED TABLE. Typed over every field the hash covers: a field added to `CompiledAuthorityTable`
 * and not named here is a compile error, and a test derives the field names from a compiled table and mutates each AUTHORITY
 * field to prove the diff sees it.
 */
export const AUTHORITY_TABLE_FIELDS: { readonly [K in TableField]: FieldReader } = {
  schema: { role: 'provenance', note: 'the format of the table: a table of another schema is not comparable' },
  sourceHashes: { role: 'provenance', note: 'the hashes of the authored files the table was compiled from' },
  provenance: { role: 'provenance', note: 'which layer set each verdict, and in which file' },
  capabilities: { role: 'authority', diff: diffCapabilities, note: 'the lock tier and whether the effect leaves the machine (what a grant may lift)' },
  absoluteDenies: { role: 'authority', diff: diffTier('absolute', 'absoluteDenies'), note: 'the HARD_LOCK members' },
  adminGoverned: { role: 'authority', diff: diffTier('admin-governed', 'adminGoverned'), note: 'the ADMIN_GOVERNED members' },
  effective: { role: 'authority', diff: diffEffective, note: 'the verdict after core, organization and overlay, before profile and mode' },
  profiles: { role: 'authority', diff: diffProfiles, note: 'every profile x mode verdict cell, each profile\'s trust requirements and its budgets' },
  defaultMode: { role: 'authority', diff: diffDefaultMode, note: 'the mode every session starts in' },
  matchers: { role: 'authority', diff: diffMatchers, note: 'what an operation IS, in first-match-wins order' },
  grants: { role: 'authority', diff: diffGrants, note: 'the phrases that lift an ASK to an ALLOW' },
  grantNegations: { role: 'authority', diff: diffNegations, note: 'the words that cancel a grant phrase' },
  grantNegationWindowTokens: { role: 'authority', diff: diffNegationWindow, note: 'how far before a phrase a negation counts' },
  protectedPaths: { role: 'authority', diff: diffProtections, note: 'paths whose read or write is DENY' },
  preDeniedCommandClasses: { role: 'authority', diff: diffPreDenied, note: 'command classes that are DENY before they are analysed' },
  readOnlyCommandPatterns: { role: 'derived', from: ['matchers'], note: 'the command.read-only matchers, as patterns' },
  sanitizerLockedMinimums: { role: 'authority', diff: diffSanitizer, note: 'the redaction severities no layer may lower' },
  localTargets: { role: 'authority', diff: diffLocalRegistry, note: 'what is "this machine" or a declared development target, and what marks production' },
  boundedCommands: { role: 'authority', diff: diffVocabulary, note: 'the vocabulary of command heads that introduce no executable closure, and the lists that make a tool ask' },
};

/* ------------------------------------------------------------------------------------------------------------- *
 * THE DIFF, THE PREDICATE, THE GRADE
 * ------------------------------------------------------------------------------------------------------------- */

/**
 * Diff two compiled tables for `authority_changes` (Q84) across EVERY field of the table: a verdict change in any profile x mode
 * cell counts, matcher removals, re-partitions and re-orderings count, lock-tier moves count, vocabulary and local-target lists
 * count, budget changes are reported separately.
 */
export function diffAuthorityTables(prev: CompiledAuthorityTable, next: CompiledAuthorityTable): AuthorityChange[] {
  const out: AuthorityChange[] = [];
  const seen = new Set<string>();
  const { tableHash: _p, ...a } = prev;
  const { tableHash: _n, ...b } = next;
  // (a field order that puts the cells before the layered verdict, so a change is attributed to the cell that shows it)
  const order: TableField[] = [
    'capabilities',
    'absoluteDenies',
    'adminGoverned',
    'profiles',
    'effective',
    'defaultMode',
    'matchers',
    'grants',
    'grantNegations',
    'grantNegationWindowTokens',
    'protectedPaths',
    'preDeniedCommandClasses',
    'sanitizerLockedMinimums',
    'localTargets',
    'boundedCommands',
  ];
  for (const field of order) {
    const reader = AUTHORITY_TABLE_FIELDS[field];
    if (reader.role !== 'authority') continue;
    reader.diff(a, b, (c) => {
      const k = `${c.kind}|${c.capability}|${c.from ?? ''}|${c.to ?? ''}|${c.detail ?? ''}`;
      if (seen.has(k)) return;
      seen.add(k);
      const own = { ...c };
      FIELD_OF.set(own, field);
      out.push(own);
    });
  }
  return out;
}

/**
 * SemVer classification of a set of authority changes (Q84): any effective verdict change, removal, re-partition,
 * matcher removal (an operation loses its classification), lock move, or a new ALLOW is MAJOR; a new ASK/DENY id, a
 * new matcher that narrows, or a budget change is MINOR. A change that WIDENS is MAJOR whatever its kind.
 */
export function classifyAuthorityChanges(
  changes: AuthorityChange[],
  next: CompiledAuthorityTable,
): 'none' | 'minor' | 'major' {
  if (changes.length === 0) return 'none';
  let level: 'minor' | 'major' = 'minor';
  for (const c of changes) {
    if (
      c.kind === 'changed' ||
      c.kind === 'removed' ||
      c.kind === 'matcher-repartitioned' ||
      c.kind === 'matcher-removed' ||
      c.kind === 'lock-changed' ||
      c.kind === 'sanitizer-weakened' ||
      c.kind === 'grants-widened' ||
      c.kind === 'protection-removed' ||
      c.kind === 'local-target-added' ||
      c.kind === 'production-marker-removed'
    )
      level = 'major';
    if (isWideningChange(c, next)) level = 'major';
    if (c.kind === 'added' && c.to === 'ALLOW') level = 'major';
    if (
      c.kind === 'added' &&
      c.capability !== '*' &&
      (next.absoluteDenies.includes(c.capability) || next.adminGoverned.includes(c.capability))
    )
      level = 'major';
    if (c.kind === 'matcher-added' && next.effective[c.capability] === 'ALLOW') level = 'major';
  }
  return level;
}

const LOCK_RANK: Record<CapabilityLock, number> = { none: 0, 'admin-governed': 1, absolute: 2 };

/**
 * WHETHER A CHANGE MAKES THE TABLE MORE PERMISSIVE, or removes something that held it back: the changes a human must
 * see before they apply (issue #16 section 7: "versioned and diffable with no silent widening"). Narrowings, new
 * ASK or DENY capabilities and budget changes are listed but not marked; anything this cannot prove narrower is
 * marked, because a missed widening costs more than a spurious mark. `ego authority diff`, the AUTHORITY DIFF `ego init`
 * prints and the pending-widening gate all ask THIS function.
 */
export function isWideningChange(c: AuthorityChange, next: CompiledAuthorityTable): boolean {
  switch (c.kind) {
    case 'changed':
      return c.from !== undefined && c.to !== undefined && VERDICT_RANK[c.to] < VERDICT_RANK[c.from];
    case 'added':
      return c.to === 'ALLOW';
    case 'removed':
      return c.from !== 'ALLOW';
    case 'lock-changed':
      return c.fromLock !== undefined && c.toLock !== undefined && LOCK_RANK[c.toLock] < LOCK_RANK[c.fromLock];
    case 'matcher-added':
      return next.effective[c.capability] === 'ALLOW';
    case 'default-mode-changed':
      return c.widening === true;
    // (declaring a target local, or removing a production marker, turns a refusal into an allowed operation without
    // changing a single capability verdict: it is a widening even though no cell moves)
    case 'matcher-removed':
    case 'matcher-repartitioned':
    case 'matcher-reordered':
    case 'sanitizer-weakened':
    case 'grants-widened':
    case 'protection-removed':
    case 'local-target-added':
    case 'production-marker-removed':
    case 'vocabulary-widened':
    case 'profile-requirement-relaxed':
      return true;
    case 'grants-narrowed':
    case 'budget-changed':
    case 'local-target-removed':
    case 'production-marker-added':
    case 'vocabulary-narrowed':
    case 'profile-requirement-added':
      return false;
  }
}

/** One change as one line for a person: its kind, the capability, the cell, the verdicts and what it says. */
export function describeAuthorityChange(c: AuthorityChange): string {
  const where = c.cell ? ` [${c.cell}]` : '';
  const verdict = c.from || c.to ? ` ${c.from ?? '-'} -> ${c.to ?? '-'}` : '';
  const detail = c.detail ? ` (${c.detail})` : '';
  const subject = c.capability === '*' ? '' : ` ${c.capability}`;
  return `${c.kind}${subject}${where}${verdict}${detail}`;
}
