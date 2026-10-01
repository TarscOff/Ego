// Compiled policy cache for a project: `.harness/generated/policy.json`. Compiled from the runtime's control plane
// plus the project's layers (organization policy, product overlay, overlay matchers). Hooks read the cache; `check`
// verifies its freshness by recompiling and comparing hashes. Generated: never edited by hand.
import { join } from 'node:path';
import { loadControlPlane, loadOverlayCapabilities } from '../control-plane/load.ts';
import type { ControlPlane } from '../control-plane/types.ts';
import { compileAuthority, type CompiledAuthorityTable, type CompiledMatcher } from '../authority/compile.ts';
import { parseMarkdown, optionalString } from '../util/markdown.ts';
import { isFile, readJsonIfExists, readText, writeJsonAtomic } from '../util/fs.ts';
import { sha256Hex, sha256Canonical } from '../util/hash.ts';
import { ControlPlaneValidationError, VERDICT_RANK } from '../control-plane/types.ts';
import {
  clampLocalTargets,
  diffLocalTargets,
  loadLocalTargetsLayer,
  type LocalTargetsLayerDoc,
} from '../control-plane/local-targets.ts';
import type { YamlValue } from '../util/yaml.ts';

export interface PolicyCache {
  schema: 'ego.policy-cache/1';
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
export function loadOverlayBounded(file: string): string[] {
  if (!isFile(file)) return [];
  const doc = parseMarkdown(file, readText(file));
  if (optionalString(doc, 'schema') !== 'ego.bounded-commands/1')
    throw new ControlPlaneValidationError([`${file}: schema must be ego.bounded-commands/1`]);
  const raw = doc.frontmatter['bounded'];
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw))
    throw new ControlPlaneValidationError([`${file}: frontmatter "bounded" must be a list`]);
  return raw.map((v) => String(v));
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
  const cp: ControlPlane = loadControlPlane(controlPlaneRoot);
  const layerSources: Record<string, string> = {};
  const rec = (rel: string) => {
    const f = join(projectRoot, rel);
    if (isFile(f)) layerSources[rel.split('\\').join('/')] = sha256Hex(readText(f));
    return f;
  };
  const organization = loadOverlayCapabilities(rec(LAYER_FILES.organization), 'organization');
  const organizationBounded = loadOverlayBounded(rec(LAYER_FILES.organizationBounded));
  const overlay = loadOverlayCapabilities(rec(LAYER_FILES.overlay), 'overlay');
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
  };
}

export function writePolicyCache(projectRoot: string, cache: PolicyCache): string {
  const path = join(projectRoot, POLICY_CACHE_RELATIVE);
  writeJsonAtomic(path, cache);
  return path;
}

/**
 * Reads the cache and verifies its internal integrity: the table hash must equal the canonical hash of the table body.
 * A corrupted, truncated or hand-edited cache is treated as absent (the caller recompiles); the in-band write paths to
 * the cache are pre-denied (`ego.runtime.tamper`), out-of-band forgery is detected by `check` (K1).
 */
export function readPolicyCache(projectRoot: string): PolicyCache | null {
  const c = readJsonIfExists<PolicyCache>(join(projectRoot, POLICY_CACHE_RELATIVE));
  if (!c || c.schema !== 'ego.policy-cache/1' || !c.table || typeof c.table !== 'object') return null;
  const { tableHash, ...body } = c.table;
  if (sha256Canonical(body) !== tableHash) return null;
  return c;
}

export interface FreshnessReport {
  fresh: boolean;
  reasons: string[];
}

/** Fresh = same runtime identity, same table hash after recompilation, same layer sources. */
export function policyCacheFreshness(
  controlPlaneRoot: string,
  projectRoot: string,
  self: { runtimeSha256: string; version: string },
): FreshnessReport {
  const cached = readPolicyCache(projectRoot);
  if (!cached) return { fresh: false, reasons: ['policy cache is missing'] };
  const reasons: string[] = [];
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
  return { fresh: reasons.length === 0, reasons };
}

/** Loads the cache, compiling and writing it when missing or stale. Hooks call this: a stale cache is never used silently. */
/** Every (profile/mode, capability) cell and effective verdict where `next` is wider than `baseline`. */
export function tableWidenings(baseline: CompiledAuthorityTable, next: CompiledAuthorityTable): string[] {
  const out: string[] = [];
  for (const [cap, v] of Object.entries(next.effective)) {
    const b = baseline.effective[cap];
    if (b && VERDICT_RANK[v] < VERDICT_RANK[b]) out.push(`effective ${cap}: ${b} -> ${v}`);
  }
  for (const [p, prof] of Object.entries(next.profiles))
    for (const [m, cells] of Object.entries(prof.modes)) {
      const base = baseline.profiles[p]?.modes[m];
      if (!base) continue;
      for (const [cap, v] of Object.entries(cells)) {
        const b = base[cap];
        if (b && VERDICT_RANK[v] < VERDICT_RANK[b]) out.push(`${p}/${m} ${cap}: ${b} -> ${v}`);
      }
    }
  // Declaring a command head BOUNDED widens what may hold a positive semantic claim without changing any
  // capability verdict, so comparing verdicts alone let the vocabulary layer apply straight from the working
  // tree — the one thing the organization layer exists to prevent.
  const baseBounded = new Set(baseline.boundedCommands?.bounded ?? []);
  for (const e of next.boundedCommands?.bounded ?? [])
    if (!baseBounded.has(e))
      out.push(`bounded vocabulary: "${e}" declared to introduce no executable closure`);
  // Declaring a target local, or un-marking a production name, changes no capability verdict and still turns a
  // refusal into an allowed operation. It is judged by the same reader the authority diff uses.
  for (const c of diffLocalTargets(baseline.localTargets, next.localTargets))
    if (c.widening) out.push(`local targets: ${c.detail}`);
  return out.sort();
}

/** `next` with every cell raised to at least the baseline verdict: narrowings apply, widenings do not. */
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
    if (b && VERDICT_RANK[v] < VERDICT_RANK[b]) t.effective[cap] = b;
  }
  for (const [p, prof] of Object.entries(t.profiles))
    for (const [m, cells] of Object.entries(prof.modes)) {
      const base = baseline.profiles[p]?.modes[m];
      if (!base) continue;
      for (const [cap, v] of Object.entries(cells)) {
        const b = base[cap];
        if (b && VERDICT_RANK[v] < VERDICT_RANK[b]) cells[cap] = b;
      }
    }
  // an unaccepted local-target declaration is dropped, and so is the removal of a production marker
  t.localTargets = clampLocalTargets(t.localTargets, baseline.localTargets);
  const { tableHash: _old, ...body } = t;
  return { ...body, tableHash: sha256Canonical(body) } as CompiledAuthorityTable;
}

function sameSources(a: Record<string, string> | undefined, b: Record<string, string>): boolean {
  if (!a) return false;
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const k of keys) if (a[k] !== b[k]) return false;
  return true;
}

/**
 * Loads the cache, recompiling when the runtime or a layer file changed. A layer edit that NARROWS applies at once. A
 * layer edit that WIDENS anything (an organization widening, a removed overlay narrowing) is never applied from the
 * working tree by a hook: the table is clamped to the last accepted one (or to the core table when none was accepted)
 * and the widening is recorded as pending until a human runs `ego init` from their own terminal (Q98, K1).
 */
export function ensurePolicyCache(
  controlPlaneRoot: string,
  projectRoot: string,
  self: { runtimeSha256: string; version: string },
  opts: { acceptWidening?: boolean } = {},
): { cache: PolicyCache; regenerated: boolean } {
  const cached = readPolicyCache(projectRoot);
  const currentSources: Record<string, string> = {};
  for (const rel of Object.values(LAYER_FILES)) {
    const f = join(projectRoot, rel);
    if (isFile(f)) currentSources[rel.split('\\').join('/')] = sha256Hex(readText(f));
  }
  if (
    cached &&
    cached.runtimeSha256 === self.runtimeSha256 &&
    sameSources(cached.layerSources, currentSources) &&
    !(opts.acceptWidening && cached.pendingWidening)
  )
    return { cache: cached, regenerated: false };
  const fresh = compileProjectPolicy(controlPlaneRoot, projectRoot, self);
  if (opts.acceptWidening || sameSources(cached?.acceptedLayerSources, fresh.layerSources)) {
    fresh.acceptedLayerSources = { ...fresh.layerSources };
    writePolicyCache(projectRoot, fresh);
    return { cache: fresh, regenerated: true };
  }
  const baseline =
    cached && cached.runtimeSha256 === self.runtimeSha256
      ? cached.table
      : compileAuthority(loadControlPlane(controlPlaneRoot), { projectRoot });
  const widenings = tableWidenings(baseline, fresh.table);
  if (widenings.length === 0) {
    fresh.acceptedLayerSources = { ...fresh.layerSources };
    writePolicyCache(projectRoot, fresh);
    return { cache: fresh, regenerated: true };
  }
  const clamped: PolicyCache = {
    ...fresh,
    table: clampToBaseline(fresh.table, baseline),
    acceptedLayerSources: cached?.acceptedLayerSources ?? {},
    pendingWidening: { layerSources: { ...fresh.layerSources }, widenings },
  };
  writePolicyCache(projectRoot, clamped);
  return { cache: clamped, regenerated: true };
}
