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
import { ControlPlaneValidationError } from '../control-plane/types.ts';
import type { YamlValue } from '../util/yaml.ts';

export interface PolicyCache {
  schema: 'ego.policy-cache/1';
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
  overlay: join('.harness', 'permissions.md'),
  overlayMatchers: join('.harness', 'overlay', 'matchers.md'),
} as const;

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
  const overlay = loadOverlayCapabilities(rec(LAYER_FILES.overlay), 'overlay');
  const overlayMatchers = loadOverlayMatchers(rec(LAYER_FILES.overlayMatchers));
  const table = compileAuthority(cp, { organization, overlay, overlayMatchers, projectRoot });
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
 * the cache are pre-denied (`harness.runtime.tamper`), out-of-band forgery is detected by `check` (K1).
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
  if (fresh.table.tableHash !== cached.table.tableHash)
    reasons.push('compiled authority table differs from the cache (control plane or overlay changed)');
  const keys = new Set([...Object.keys(fresh.layerSources), ...Object.keys(cached.layerSources)]);
  for (const k of keys)
    if (fresh.layerSources[k] !== cached.layerSources[k]) reasons.push(`layer source changed: ${k}`);
  return { fresh: reasons.length === 0, reasons };
}

/** Loads the cache, compiling and writing it when missing or stale. Hooks call this: a stale cache is never used silently. */
export function ensurePolicyCache(
  controlPlaneRoot: string,
  projectRoot: string,
  self: { runtimeSha256: string; version: string },
): { cache: PolicyCache; regenerated: boolean } {
  const cached = readPolicyCache(projectRoot);
  if (cached && cached.runtimeSha256 === self.runtimeSha256) {
    // cheap freshness: layer source hashes only (full recompilation is `check`'s job)
    let stale = false;
    for (const rel of Object.values(LAYER_FILES)) {
      const f = join(projectRoot, rel);
      const key = rel.split('\\').join('/');
      const current = isFile(f) ? sha256Hex(readText(f)) : undefined;
      if (current !== cached.layerSources[key]) stale = true;
    }
    if (!stale) return { cache: cached, regenerated: false };
  }
  const fresh = compileProjectPolicy(controlPlaneRoot, projectRoot, self);
  writePolicyCache(projectRoot, fresh);
  return { cache: fresh, regenerated: true };
}
