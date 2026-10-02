// Compiled policy cache for a project: `.harness/generated/policy.json`. Compiled from the runtime's control plane
// plus the project's layers (organization policy, product overlay, overlay matchers). Hooks read the cache; `check`
// verifies its freshness by recompiling and comparing hashes. Generated: never edited by hand.
import { basename, join } from 'node:path';
import { loadControlPlane, loadOverlayCapabilities } from '../control-plane/load.ts';
import type { ControlPlane } from '../control-plane/types.ts';
import {
  AUTHORITY_TABLE_FIELDS,
  compileAuthority,
  deriveMatcherViews,
  describeAuthorityChange,
  diffAuthorityTables,
  fieldOfChange,
  isWideningChange,
  matcherIdentity,
  type CompiledAuthorityTable,
  type CompiledMatcher,
} from '../authority/compile.ts';
import { parseMarkdown, optionalString } from '../util/markdown.ts';
import { isFile, readJsonIfReadable, readText, writeJsonAtomic } from '../util/fs.ts';
import { sha256Hex, sha256Canonical } from '../util/hash.ts';
import { ControlPlaneValidationError, VERDICT_RANK } from '../control-plane/types.ts';
import { PENDING_LAYER } from '../authority/vocabulary.ts';
import { isLegacyTable, upgradeLegacyTable } from '../control-plane/legacy-names.ts';
import { POLICY_INVALID_RULE, POLICY_STALE_RULE, renderFailure } from '../authority/reasons.ts';
import {
  clampLocalTargets,
  loadLocalTargetsLayer,
  type LocalTargetsLayerDoc,
} from '../control-plane/local-targets.ts';
import type { YamlValue } from '../util/yaml.ts';
import { shownText } from '../util/shown-text.ts';
import { sealOf, sealVerifies, type SealKey } from './seal.ts';

export interface PolicyCache {
  schema: 'ego.policy-cache/1';
  /** HMAC of this record under the key in EGO_HOME (`policy/seal.ts`): the proof that THIS machine wrote it. Absent in a record no key sealed. */
  seal?: string;
  /** layer hashes whose widenings a human accepted (init from a human terminal) */
  acceptedLayerSources?: Record<string, string>;
  /** widenings found in the current layer files and not applied until a human accepts them */
  pendingWidening?: { layerSources: Record<string, string>; widenings: string[] };
  runtimeSha256: string;
  runtimeVersion: string;
  controlPlaneRoot: string;
  /** project-relative layer files with their hashes (absent files omitted) */
  layerSources: Record<string, string>;
  table: CompiledAuthorityTable;
  /** what the loaders translated or tolerated when this cache was compiled (a file still written under a previous
   *  naming). Not part of the table, so it never changes the table hash; `ego doctor` prints it. */
  notices?: string[];
  /** SET BY `readPolicyCache`, NEVER WRITTEN: this cache was written under the previous naming of the ADMIN_GOVERNED
   *  tier. Its table has been upgraded in memory (the policy it records is unchanged) and it is stale by definition. */
  legacyNaming?: true;
}

export const POLICY_CACHE_RELATIVE = join('.harness', 'generated', 'policy.json');

export const LAYER_FILES = {
  organization: join('policies', 'organization', 'permissions.md'),
  /** The organization may declare command heads BOUNDED that the kernel does not. Moving a tool out of the
   *  discovering lists is a WIDENING, so it travels the same road as an organization capability widening: written
   *  out of band, reported by doctor as pending, and accepted by a human running `ego init`. Documenting that
   *  escape hatch while it did not exist was the one promise this contract made and could not keep. */
  organizationBounded: join('policies', 'organization', 'bounded-commands.md'),
  overlay: join('.harness', 'permissions.md'),
  overlayMatchers: join('.harness', 'overlay', 'matchers.md'),
  /** The organization's and the project's additions to the local-development target registry (see
   *  `control-plane/local-targets.ts`). Declaring a target LOCAL turns a refusal into an allowed operation, so both
   *  files are a widening and travel the road every widening travels: pending until a human runs `ego init`. */
  organizationLocalTargets: join('policies', 'organization', 'local-targets.md'),
  projectLocalTargets: join('.harness', 'local-targets.md'),
} as const;

/** The organization's additions to the bounded-command vocabulary: heads it declares introduce no further
 *  executable closure. Only `bounded` may be extended — an organization may take responsibility for a tool, it
 *  may not make the kernel treat more things as discovering by deleting entries it does not control. */
/**
 * WHAT A BOUNDED-COMMAND ENTRY MAY BE: a command name (`pytest`, `node_modules/.bin/eslint`) optionally followed by the words that decide its
 * shape (`go test`, `cmake --version`). A POSITIVE GRAMMAR: the characters a name and an argument can carry, no quoting, no operator, no
 * substitution, no whitespace but the space between words, at most 80 characters. The entry is compared against a command's words and printed
 * to a person and to the model in the pending-widening lines, and it came from a teammate's commit; one that is not this is not a command
 * name, is not taken, and is reported once (AUTH-6).
 */
const BOUNDED_ENTRY = /^[A-Za-z0-9_.+@:/-]+(?: [A-Za-z0-9_.+@:/=,-]+)*$/;
const BOUNDED_ENTRY_MAX = 80;

export function loadOverlayBounded(file: string, notices?: string[]): string[] {
  if (!isFile(file)) return [];
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.bounded-commands/1')
    throw new ControlPlaneValidationError([`${file}: schema must be ego.bounded-commands/1`]);
  const raw = doc.frontmatter['bounded'];
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) throw new ControlPlaneValidationError([`${file}: frontmatter "bounded" must be a list`]);
  const taken: string[] = [];
  for (const v of raw) {
    const entry = String(v);
    if (entry.length <= BOUNDED_ENTRY_MAX && BOUNDED_ENTRY.test(entry)) taken.push(entry);
    else
      notices?.push(
        `ignored by the bounded-command vocabulary: ${shownText(entry, 60)} from ${shownText(basename(file), 60)} is not a command name (letters, digits and . _ + @ : / -, then words of the same, at most ${BOUNDED_ENTRY_MAX} characters)`,
      );
  }
  return taken;
}

export function loadOverlayMatchers(file: string): CompiledMatcher[] {
  if (!isFile(file)) return [];
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.matchers/1')
    throw new ControlPlaneValidationError([`${file}: schema must be ego.matchers/1`]);
  const raw = doc.frontmatter['matchers'];
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw))
    throw new ControlPlaneValidationError([`${file}: frontmatter "matchers" must be a list`]);
  const out: CompiledMatcher[] = [];
  raw.forEach((entry, i) => {
    const m = entry as Record<string, YamlValue>;
    if (!m || typeof m !== 'object' || Array.isArray(m) || typeof m['capability'] !== 'string')
      throw new ControlPlaneValidationError([`${file}: overlay matcher #${i + 1} must have a capability`]);
    const tool = typeof m['tool'] === 'string' ? m['tool'] : 'any';
    if (!['Bash', 'Read', 'Write', 'Edit', 'WebFetch', 'any'].includes(tool))
      throw new ControlPlaneValidationError([
        `${file}: overlay matcher #${i + 1} has invalid tool "${tool}"`,
      ]);
    const cm: CompiledMatcher = { capability: m['capability'], tool, layer: 'overlay' };
    if (typeof m['command'] === 'string') {
      new RegExp(m['command']);
      cm.command = m['command'];
    }
    if (typeof m['path'] === 'string') cm.path = m['path'];
    if (typeof m['url'] === 'string') {
      new RegExp(m['url']);
      cm.url = m['url'];
    }
    if (!cm.command && !cm.path && !cm.url)
      throw new ControlPlaneValidationError([
        `${file}: overlay matcher #${i + 1} has no command, path or url`,
      ]);
    out.push(cm);
  });
  return out;
}

export function compileProjectPolicy(
  controlPlaneRoot: string,
  projectRoot: string,
  self: { runtimeSha256: string; version: string },
): PolicyCache {
  // THE HASHES A CACHE RECORDS MUST BE THE HASHES OF THE BYTES IT WAS COMPILED FROM. A layer file is hashed and then read again
  // by its loader, so a file rewritten in between gave a table compiled from one text under the name of another - and the
  // acceptance of a widening is bound to those names (AUTH-4). The compile is repeated when the files are not the same after it
  // as before it, and refused when they will not keep still.
  for (let attempt = 0; attempt < 3; attempt++) {
    const compiled = compileProjectPolicyOnce(controlPlaneRoot, projectRoot, self);
    if (sameLayerSources(compiled.layerSources, currentLayerSources(projectRoot))) return compiled;
  }
  throw new ControlPlaneValidationError([
    'the layer files changed while the policy was being compiled, three times in a row; nothing was compiled or accepted - run the command again when they are still',
  ]);
}

let afterLayerHashed: ((rel: string) => void) | null = null;
/** Test seam: `fn` runs right after a layer file is hashed and before its loader reads it (the moment a rewrite is a race). Only a test calls this. */
export function probeLayerHashing(fn: ((rel: string) => void) | null): void {
  afterLayerHashed = fn;
}

const sameLayerSources = (a: Record<string, string>, b: Record<string, string>): boolean => {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const k of keys) if (a[k] !== b[k]) return false;
  return true;
};

function compileProjectPolicyOnce(
  controlPlaneRoot: string,
  projectRoot: string,
  self: { runtimeSha256: string; version: string },
): PolicyCache {
  const cp: ControlPlane = loadControlPlane(controlPlaneRoot);
  const layerSources: Record<string, string> = {};
  const rec = (rel: string) => {
    const f = join(projectRoot, rel);
    if (isFile(f)) layerSources[rel.split('\\').join('/')] = sha256Hex(readText(f));
    afterLayerHashed?.(rel.split('\\').join('/'));
    return f;
  };
  const notices = [...cp.notices];
  const organization = loadOverlayCapabilities(rec(LAYER_FILES.organization), 'organization', notices);
  const organizationBounded = loadOverlayBounded(rec(LAYER_FILES.organizationBounded), notices);
  const overlay = loadOverlayCapabilities(rec(LAYER_FILES.overlay), 'overlay', notices);
  const overlayMatchers = loadOverlayMatchers(rec(LAYER_FILES.overlayMatchers));
  rec(LAYER_FILES.organizationLocalTargets);
  rec(LAYER_FILES.projectLocalTargets);
  const localTargetLayers = [
    loadLocalTargetsLayer(projectRoot, LAYER_FILES.organizationLocalTargets, 'organization'),
    loadLocalTargetsLayer(projectRoot, LAYER_FILES.projectLocalTargets, 'project'),
  ].filter((l): l is LocalTargetsLayerDoc => l !== null);
  const table = compileAuthority(cp, {
    organization,
    overlay,
    overlayMatchers,
    organizationBounded,
    localTargetLayers,
    projectRoot,
  });
  return {
    schema: 'ego.policy-cache/1',
    runtimeSha256: self.runtimeSha256,
    runtimeVersion: self.version,
    controlPlaneRoot,
    layerSources,
    table,
    ...(notices.length ? { notices } : {}),
  };
}

/**
 * Writes the cache, sealed. `seal` is the key (`sealFor(env)`); `undefined` writes the record as it is (the unit tests of the compiler have no
 * home); `null` - a seal is required and this machine has no key - writes NOTHING: a record no reader could verify would only be read as absent.
 */
export function writePolicyCache(projectRoot: string, cache: PolicyCache, seal?: SealKey | null): string {
  const path = join(projectRoot, POLICY_CACHE_RELATIVE);
  if (seal === null) return path;
  const { seal: _old, legacyNaming: _derived, ...body } = cache;
  writeJsonAtomic(path, seal === undefined ? body : { ...body, seal: sealOf(body as Record<string, unknown>, seal) });
  return path;
}

const isRecordOfStrings = (v: unknown): v is Record<string, string> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && Object.values(v as object).every((x) => typeof x === 'string');

/**
 * A table read from DISK, in the shape this build reads: written under the previous naming (upgraded in memory), or by an
 * earlier build of the current naming (the registry lists it did not have yet are empty - doctor read `declared.map` on a
 * cache that predated it and exited 2 - AUTH-10). Null when it is not a table at all, or lacks a field no default can stand in
 * for (a cache from before the bounded-command vocabulary): the caller treats that as absent and recompiles. ONE function, so
 * the cache reader and `ego authority diff <file>` (`lenient`: a table to compare against may predate the registry and the
 * vocabulary) give an old table the same shape.
 */
export function readAsCurrentTable(candidate: unknown, lenient = false): CompiledAuthorityTable | null {
  if (candidate === null || typeof candidate !== 'object' || Array.isArray(candidate)) return null;
  const t = { ...((isLegacyTable(candidate) ? upgradeLegacyTable(candidate) : candidate) as unknown as Record<string, unknown>) };
  // (a field that only says where a verdict came from, and that a table of an earlier build did not record, is empty in it: a refusal
  // then names its source the way it always did)
  t['cellOrigins'] ??= {};
  // (a table to DIFF against - not one to serve - may predate the registry and the vocabulary: they are empty in it, which is
  // what the diff reads a table that never had them as)
  if (lenient) {
    t['localTargets'] ??= { k8sLocalContexts: [], dbLocalHosts: [], productionMarkers: [], file: '', declared: [], ignored: [] };
    t['boundedCommands'] ??= { bounded: [], installsDependencies: [], discoversContent: [], discoversConfig: [] };
  }
  for (const field of Object.keys(AUTHORITY_TABLE_FIELDS)) if (!(field in t)) return null;
  const lt = t['localTargets'];
  if (lt === null || typeof lt !== 'object' || Array.isArray(lt)) return null;
  const targets = lt as Record<string, unknown>;
  if (Array.isArray(targets['declared']) && Array.isArray(targets['ignored'])) return t as unknown as CompiledAuthorityTable;
  return {
    ...t,
    localTargets: { ...targets, declared: targets['declared'] ?? [], ignored: targets['ignored'] ?? [] },
  } as unknown as CompiledAuthorityTable;
}

/**
 * Reads the cache and verifies its internal integrity: the table hash must equal the canonical hash of the table body.
 * A corrupted, truncated, empty or hand-edited cache is ABSENT (the caller recompiles) - it must not throw: the cache is
 * derived state, and a reader that threw on a zero-byte file made every hook event, `ego doctor` and `ego init` (the remedy
 * the error named) exit 2 (AUTH-2). The in-band write paths to the cache are pre-denied (`ego.runtime.tamper`), out-of-band
 * forgery is detected by `check` (K1).
 */
export function readPolicyCache(projectRoot: string, seal?: SealKey | null): PolicyCache | null {
  const c = readJsonIfReadable<PolicyCache>(join(projectRoot, POLICY_CACHE_RELATIVE));
  // A CACHE THIS MACHINE DID NOT WRITE IS NOT READ (AUTH-5): with a key, the record must verify under it; with none, nothing can
  if (seal === null && c) return null;
  if (seal && c && typeof c === 'object' && !sealVerifies(c as unknown as Record<string, unknown>, seal)) return null;
  if (
    !c ||
    typeof c !== 'object' ||
    c.schema !== 'ego.policy-cache/1' ||
    typeof c.runtimeSha256 !== 'string' ||
    typeof c.runtimeVersion !== 'string' ||
    !isRecordOfStrings(c.layerSources) ||
    (c.acceptedLayerSources !== undefined && !isRecordOfStrings(c.acceptedLayerSources)) ||
    (c.pendingWidening !== undefined &&
      !(isRecordOfStrings(c.pendingWidening?.layerSources) && Array.isArray(c.pendingWidening?.widenings))) ||
    !c.table ||
    typeof c.table !== 'object' ||
    typeof c.table.tableHash !== 'string'
  )
    return null;
  const { tableHash, ...body } = c.table;
  // integrity is judged on the bytes as written: a cache from the previous naming is intact under ITS hash
  if (sha256Canonical(body) !== tableHash) return null;
  // A cache written under the previous naming is neither corrupt nor current. Discarding it would forget which layer
  // widenings a human accepted (each would come back as a pending one); trusting it as is would hand the readers a
  // table without the field they read. It is upgraded in memory, flagged, and regenerated by the next hook.
  const table = readAsCurrentTable(c.table);
  if (!table) return null;
  return isLegacyTable(c.table) ? { ...c, table, legacyNaming: true } : { ...c, table };
}

export interface FreshnessReport {
  fresh: boolean;
  reasons: string[];
  /** why it is not fresh: stale (behind what is on disk or required) or invalid (the policy no longer compiles) */
  code?: 'POLICY_STALE' | 'POLICY_INVALID';
}

/** A freshness report as one message for a person: the code, what is behind, the rule source, what can change it. */
export function formatFreshness(r: FreshnessReport): string {
  if (r.fresh) return 'fresh';
  const code = r.code ?? 'POLICY_STALE';
  return renderFailure(code, r.reasons.join('; '), code === 'POLICY_INVALID' ? POLICY_INVALID_RULE : POLICY_STALE_RULE);
}

/** Fresh = same runtime identity, same table hash after recompilation, same layer sources. */
export function policyCacheFreshness(
  controlPlaneRoot: string,
  projectRoot: string,
  self: { runtimeSha256: string; version: string },
  seal?: SealKey | null,
): FreshnessReport {
  const cached = readPolicyCache(projectRoot, seal);
  if (!cached)
    return {
      fresh: false,
      reasons: [
        seal !== undefined && readPolicyCache(projectRoot) !== null
          ? 'policy cache was not written by this machine (its seal does not verify under the key in EGO_HOME); it is regenerated by the next hook or by `ego init`, and nothing it says was accepted is believed'
          : 'policy cache is missing',
      ],
      code: 'POLICY_STALE',
    };
  const reasons: string[] = [];
  if (cached.legacyNaming)
    reasons.push(
      'policy cache was written under the previous naming of the ADMIN_GOVERNED tier; it records the same policy and is regenerated by the next hook or by `ego init`',
    );
  if (cached.runtimeSha256 !== self.runtimeSha256)
    reasons.push(
      `policy cache was compiled by runtime ${cached.runtimeSha256.slice(0, 12)}, executing runtime is ${self.runtimeSha256.slice(0, 12)}`,
    );
  let fresh: PolicyCache;
  try {
    fresh = compileProjectPolicy(controlPlaneRoot, projectRoot, self);
  } catch (e) {
    return {
      fresh: false,
      reasons: [...reasons, `recompilation failed: ${(e as Error).message.split('\n')[0]}`],
      code: 'POLICY_INVALID',
    };
  }
  if (cached.pendingWidening)
    reasons.push(
      `policy widening pending human acceptance (${cached.pendingWidening.widenings.length}: ${cached.pendingWidening.widenings.slice(0, 3).join('; ')}${cached.pendingWidening.widenings.length > 3 ? '; …' : ''}); a human runs \`ego init\` from their own terminal to accept`,
    );
  else if (fresh.table.tableHash !== cached.table.tableHash)
    reasons.push('compiled authority table differs from the cache (control plane or overlay changed)');
  const keys = new Set([...Object.keys(fresh.layerSources), ...Object.keys(cached.layerSources)]);
  for (const k of keys)
    if (fresh.layerSources[k] !== cached.layerSources[k]) reasons.push(`layer source changed: ${k}`);
  return reasons.length === 0 ? { fresh: true, reasons } : { fresh: false, reasons, code: 'POLICY_STALE' };
}

/**
 * THE PENDING-WIDENING GATE. Every way `next` is wider than `baseline`, as the lines a human is shown. It is the WIDENING subset
 * of `diffAuthorityTables` - the same function `ego authority diff` and the AUTHORITY DIFF `ego init` print are built from - so
 * there is no dimension the gate can miss that the diff sees (AUTH-3: the gate read the verdict cells, the bounded vocabulary,
 * the local-target registry and the removed overlay rules, and the diff read a different set).
 *
 * A REMOVED NARROWING IS A WIDENING. An overlay rule is a narrowing - it can only add a gate - and the file that holds it is
 * writable by anything that can write the working tree: the Write tool, `rm`, a checkout or a pull that drops it. Comparing only
 * the verdict cells missed it entirely (no cell changes when a PATTERN goes), so emptying `.harness/overlay/matchers.md` removed an
 * organization's path and command rules and the very next hook applied the wider table with nothing pending (exit review 11, #119).
 */
export function tableWidenings(baseline: CompiledAuthorityTable, next: CompiledAuthorityTable): string[] {
  return diffAuthorityTables(baseline, next)
    .filter((c) => isWideningChange(c, next))
    .map(describeAuthorityChange)
    .sort();
}

/** the overlay's rules in `baseline` that `next` no longer has: each is a narrowing that was taken away */
function removedOverlayMatchers(baseline: CompiledAuthorityTable, next: CompiledAuthorityTable): CompiledMatcher[] {
  const kept = new Set((next.matchers ?? []).map(matcherIdentity));
  return (baseline.matchers ?? []).filter((m) => m.layer === 'overlay' && !kept.has(matcherIdentity(m)));
}

const withHash = (body: Omit<CompiledAuthorityTable, 'tableHash'>): CompiledAuthorityTable =>
  ({ ...body, tableHash: sha256Canonical(body) }) as CompiledAuthorityTable;

/**
 * `next` with every cell raised to at least the baseline verdict: narrowings apply, widenings do not. The specific clamps below
 * are the ones a LAYER can need (a verdict cell, a vocabulary entry, a removed overlay rule, a local-target declaration); the
 * last step is the guarantee: whatever the diff still reads as wider than the baseline - a field a layer cannot reach today, a
 * view derived from cells that were just clamped - is replaced by the baseline's value of that field, so what is reported as
 * pending is never applied, whichever reader found it.
 */
export function clampToBaseline(
  next: CompiledAuthorityTable,
  baseline: CompiledAuthorityTable,
): CompiledAuthorityTable {
  const t = structuredClone(next);
  // an unaccepted vocabulary addition is dropped, not merely reported
  if (t.boundedCommands && baseline.boundedCommands) {
    const allowed = new Set(baseline.boundedCommands.bounded);
    t.boundedCommands.bounded = t.boundedCommands.bounded.filter((e) => allowed.has(e));
  }
  for (const [cap, v] of Object.entries(t.effective)) {
    const b = baseline.effective[cap];
    if (b && VERDICT_RANK[v] < VERDICT_RANK[b]) {
      t.effective[cap] = b;
      // THE SOURCE IS THE BASELINE'S, AND THE TRACE SAYS A WIDENING IS WAITING: the verdict that stays in force is the core's, and
      // citing the organization's file as its source (it is not in force) sent a reader to the wrong rule (AUTH-8)
      const was = t.provenance[cap]?.at(-1);
      t.provenance[cap] = [
        ...structuredClone(baseline.provenance[cap] ?? []),
        { layer: `${PENDING_LAYER} \`ego init\`)`, file: was?.file ?? '', verdict: b },
      ];
    }
  }
  for (const [p, prof] of Object.entries(t.profiles))
    for (const [m, cells] of Object.entries(prof.modes)) {
      const base = baseline.profiles[p]?.modes[m];
      if (!base) continue;
      for (const [cap, v] of Object.entries(cells)) {
        const b = base[cap];
        if (b && VERDICT_RANK[v] < VERDICT_RANK[b]) {
          cells[cap] = b;
          // (and the cell's origin is the baseline's: whatever moved it there, the unaccepted layer did not)
          const origin = baseline.cellOrigins?.[p]?.[m]?.[cap];
          const mine = ((t.cellOrigins[p] ??= {})[m] ??= {});
          if (origin) mine[cap] = origin;
          else delete mine[cap];
        }
      }
    }
  // a removed overlay narrowing is put back, and the views derived from the matchers with it
  const restored = removedOverlayMatchers(baseline, t);
  if (restored.length > 0) {
    t.matchers = [...t.matchers, ...structuredClone(restored)];
    Object.assign(t, deriveMatcherViews(t.matchers, t.effective, t.capabilities));
  }
  // an unaccepted local-target declaration is dropped, and so is the removal of a production marker
  t.localTargets = clampLocalTargets(t.localTargets, baseline.localTargets);
  for (let pass = 0; pass < 2; pass++) {
    const { tableHash: _old, ...body } = t;
    const clamped = withHash(body);
    const residual = diffAuthorityTables(baseline, clamped).filter((c) => isWideningChange(c, clamped));
    if (residual.length === 0) return clamped;
    for (const c of residual)
      {
        const field = fieldOfChange(c);
        if (field) (t as unknown as Record<string, unknown>)[field] = structuredClone((baseline as unknown as Record<string, unknown>)[field]);
      }
  }
  // (unreachable while every field of the table has a baseline value to fall back to; the throw is the refusal to serve a table
  // that is reported as held back and is not)
  throw new Error('internal error: a pending widening could not be held back');
}

const sameSources = (a: Record<string, string> | undefined, b: Record<string, string>): boolean =>
  a !== undefined && sameLayerSources(a, b);

const sameLines = (a: readonly string[], b: readonly string[]): boolean =>
  a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);

/** The layer files as they are NOW, by hash. The one reader of "what is on disk": the acceptance, the fast path and the compile all use it. */
export function currentLayerSources(projectRoot: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rel of Object.values(LAYER_FILES)) {
    const f = join(projectRoot, rel);
    if (isFile(f)) out[rel.split('\\').join('/')] = sha256Hex(readText(f));
  }
  return out;
}

/**
 * WHAT A HUMAN ACCEPTS IS WHAT THEY WERE SHOWN (AUTH-4). `true` accepts what the compile of THIS call finds (a caller that
 * showed nobody anything: a test, a non-interactive run). An object accepts only if the layer files are byte-for-byte the ones
 * the person was shown - the hashes in `layerSources`, and, when `widenings` is given, exactly those lines - and otherwise
 * accepts NOTHING: the recompile of whatever is on disk a moment later is not what was displayed. The window it closes is the
 * length of the y/N answer, and a writer that can race it is an agent still running with write access to a layer file.
 */
export type WideningAcceptance = boolean | { layerSources: Record<string, string>; widenings?: string[] };

/**
 * Loads the cache, recompiling when the runtime or a layer file changed. A layer edit that NARROWS applies at once. A layer edit
 * that WIDENS anything (an organization widening, a removed overlay narrowing) is never applied from the working tree by a hook:
 * the table is clamped to the last accepted one (or to the core table when none was accepted) and the widening is recorded as
 * pending until a human runs `ego init` from their own terminal (Q98, K1).
 */
export function ensurePolicyCache(
  controlPlaneRoot: string,
  projectRoot: string,
  self: { runtimeSha256: string; version: string },
  opts: { acceptWidening?: WideningAcceptance; seal?: SealKey | null } = {},
): { cache: PolicyCache; regenerated: boolean; acceptanceRefused?: string } {
  const cached = readPolicyCache(projectRoot, opts.seal);
  const currentSources = currentLayerSources(projectRoot);
  const accept = opts.acceptWidening ?? false;
  const acceptNow = accept !== false;
  if (
    cached &&
    cached.runtimeSha256 === self.runtimeSha256 &&
    !cached.legacyNaming &&
    sameSources(cached.layerSources, currentSources) &&
    !(acceptNow && cached.pendingWidening)
  )
    return { cache: cached, regenerated: false };
  const fresh = compileProjectPolicy(controlPlaneRoot, projectRoot, self);
  // a cache written under the previous naming never serves as the baseline a widening is measured against
  const baseline =
    cached && cached.runtimeSha256 === self.runtimeSha256 && !cached.legacyNaming
      ? cached.table
      : compileAuthority(loadControlPlane(controlPlaneRoot), { projectRoot });
  let acceptHere = accept === true;
  let refused: string | undefined;
  if (typeof accept === 'object') {
    const shown = accept.layerSources;
    if (!sameSources(shown, fresh.layerSources))
      refused = `the layer files are not the ones that were shown (changed since: ${
        [...new Set([...Object.keys(shown), ...Object.keys(fresh.layerSources)])].filter((k) => shown[k] !== fresh.layerSources[k]).join(', ')
      })`;
    else if (accept.widenings && !sameLines(accept.widenings, tableWidenings(baseline, fresh.table)))
      refused = 'the widenings the layer files produce now are not the ones that were shown';
    else acceptHere = true;
  }
  if (acceptHere || sameSources(cached?.acceptedLayerSources, fresh.layerSources)) {
    fresh.acceptedLayerSources = { ...fresh.layerSources };
    writePolicyCache(projectRoot, fresh, opts.seal);
    return { cache: fresh, regenerated: true };
  }
  const widenings = tableWidenings(baseline, fresh.table);
  if (widenings.length === 0) {
    fresh.acceptedLayerSources = { ...fresh.layerSources };
    writePolicyCache(projectRoot, fresh, opts.seal);
    return { cache: fresh, regenerated: true };
  }
  const clamped: PolicyCache = {
    ...fresh,
    table: clampToBaseline(fresh.table, baseline),
    acceptedLayerSources: cached?.acceptedLayerSources ?? {},
    pendingWidening: { layerSources: { ...fresh.layerSources }, widenings },
  };
  writePolicyCache(projectRoot, clamped, opts.seal);
  return { cache: clamped, regenerated: true, ...(refused ? { acceptanceRefused: refused } : {}) };
}
