// Compiles the authored control plane plus overlays into the compiled authority table: the single generated object
// that hooks evaluate, `harness capabilities` renders, `explain capability` justifies and CI diffs for
// `authority_changes` (decision Q84). Deterministic and reproducible: no timestamps, sorted keys.
import { sha256Canonical } from '../util/hash.ts';
import { ControlPlaneValidationError, VERDICT_RANK, type CapabilityDoc, type ControlPlane, type Verdict } from '../control-plane/types.ts';

export interface CompiledCapability {
  family: string;
  description: string;
  absolute: boolean;
  /** verdict from the core layer before any narrowing */
  core: Verdict;
}

export interface CompiledMatcher {
  capability: string;
  tool: string;
  command?: string;
  path?: string;
  url?: string;
  layer: 'core' | 'overlay';
}

export interface LayerTrace {
  layer: string;
  file: string;
  verdict: Verdict;
}

export interface CompiledAuthorityTable {
  schema: 'ego.authority-table/1';
  /** sha256 over the table content excluding this field */
  tableHash: string;
  sourceHashes: Record<string, string>;
  capabilities: Record<string, CompiledCapability>;
  absoluteDenies: string[];
  /** effective verdict after core → organization → overlay, before profile and mode */
  effective: Record<string, Verdict>;
  /** provenance per capability: which layer set the effective verdict */
  provenance: Record<string, LayerTrace[]>;
  /** per profile × mode → capability → verdict */
  profiles: Record<string, { budgetTokens: number; ceilingTokens: number; requiresSignedReleaseTrust: boolean; requiresManagedTier: boolean; modes: Record<string, Record<string, Verdict>> }>;
  defaultMode: string;
  matchers: CompiledMatcher[];
  grants: Array<{ capability: string; phrases: string[] }>;
  grantNegations: string[];
  grantNegationWindowTokens: number;
  /** path patterns whose read or write is DENY at the core layer (credential stores, hook config, generated) */
  protectedPaths: Array<{ path: string; tool: string; capability: string }>;
  /** capabilities matched by Bash matchers that are absolute denies (pre-denied command classes) */
  preDeniedCommandClasses: string[];
  /** command regex sources for read-only commands (STRICT shell allowlist base) */
  readOnlyCommandPatterns: string[];
  /** detector id → minimum severity that overlays may not lower */
  sanitizerLockedMinimums: Record<string, 'block' | 'warn'>;
}

export interface CompileOptions {
  organization?: CapabilityDoc | null;
  overlay?: CapabilityDoc | null;
  overlayMatchers?: CompiledMatcher[];
}

export function compileAuthority(cp: ControlPlane, opts: CompileOptions = {}): CompiledAuthorityTable {
  const problems: string[] = [];
  const capabilities: Record<string, CompiledCapability> = {};
  const effective: Record<string, Verdict> = {};
  const provenance: Record<string, LayerTrace[]> = {};
  const absoluteDenies: string[] = [];

  for (const c of cp.absoluteDenies.capabilities) {
    capabilities[c.id] = { family: c.family, description: c.description, absolute: true, core: 'DENY' };
    effective[c.id] = 'DENY';
    provenance[c.id] = [{ layer: 'absolute', file: rel(cp.root, c.file), verdict: 'DENY' }];
    absoluteDenies.push(c.id);
  }
  for (const doc of cp.capabilityDocs) {
    for (const c of doc.capabilities) {
      capabilities[c.id] = { family: c.family, description: c.description, absolute: false, core: c.verdict };
      effective[c.id] = c.verdict;
      provenance[c.id] = [{ layer: 'core', file: rel(cp.root, c.file), verdict: c.verdict }];
    }
  }

  const applyLayer = (doc: CapabilityDoc | null | undefined, layerName: string) => {
    if (!doc) return;
    for (const c of doc.capabilities) {
      if (!(c.id in capabilities)) {
        problems.push(`${c.file}:${c.line}: ${layerName} layer references unknown capability "${c.id}"`);
        continue;
      }
      if (capabilities[c.id]!.absolute) {
        problems.push(`${c.file}:${c.line}: ${layerName} layer may not reference absolute deny "${c.id}"`);
        continue;
      }
      const current = effective[c.id]!;
      if (VERDICT_RANK[c.verdict] < VERDICT_RANK[current]) {
        problems.push(`${c.file}:${c.line}: ${layerName} layer attempts to widen "${c.id}" from ${current} to ${c.verdict}; lower layers may only narrow`);
        continue;
      }
      effective[c.id] = c.verdict;
      provenance[c.id]!.push({ layer: layerName, file: c.file, verdict: c.verdict });
    }
  };
  applyLayer(opts.organization, 'organization');
  applyLayer(opts.overlay, 'overlay');

  const profiles: CompiledAuthorityTable['profiles'] = {};
  const modeIds = cp.modes.map((m) => m.id);
  const defaultMode = cp.modes.find((m) => m.isDefault)?.id ?? modeIds[0] ?? 'NORMAL_DELIVERY';
  for (const p of [...cp.profiles].sort((a, b) => a.id.localeCompare(b.id))) {
    const afterProfile: Record<string, Verdict> = { ...effective };
    for (const n of p.narrow) {
      if (!(n.capability in capabilities)) continue; // validated at load
      if (capabilities[n.capability]!.absolute) {
        problems.push(`${p.file}: profile may not reference absolute deny "${n.capability}"`);
        continue;
      }
      const current = afterProfile[n.capability]!;
      if (VERDICT_RANK[n.verdict] < VERDICT_RANK[current]) continue; // profile cannot widen; keep the narrower effective verdict
      afterProfile[n.capability] = n.verdict;
    }
    const modes: Record<string, Record<string, Verdict>> = {};
    for (const m of [...cp.modes].sort((a, b) => a.id.localeCompare(b.id))) {
      const table: Record<string, Verdict> = { ...afterProfile };
      for (const o of m.overrides) {
        if (capabilities[o.capability]?.absolute) continue; // validated at load; never widen absolute
        table[o.capability] = o.verdict;
      }
      // absolute denies are DENY in every mode regardless of anything
      for (const id of absoluteDenies) table[id] = 'DENY';
      modes[m.id] = sortRecord(table);
    }
    profiles[p.id] = {
      budgetTokens: p.contextBudgetTokens,
      ceilingTokens: p.organizationCeilingTokens,
      requiresSignedReleaseTrust: p.requiresSignedReleaseTrust,
      requiresManagedTier: p.requiresManagedTier,
      modes,
    };
  }

  const matchers: CompiledMatcher[] = cp.matchers.map((m) => {
    const out: CompiledMatcher = { capability: m.capability, tool: m.tool, layer: 'core' };
    if (m.commandSource) out.command = m.commandSource;
    if (m.path) out.path = m.path;
    if (m.urlSource) out.url = m.urlSource;
    return out;
  });
  for (const om of opts.overlayMatchers ?? []) {
    const v = effective[om.capability];
    if (!v) {
      problems.push(`overlay matcher references unknown capability "${om.capability}"`);
      continue;
    }
    if (v === 'ALLOW') {
      problems.push(`overlay matcher may not map "${om.command ?? om.path ?? om.url}" to ALLOW capability "${om.capability}"; overlay matchers only narrow`);
      continue;
    }
    matchers.push({ ...om, layer: 'overlay' });
  }

  const protectedPaths = matchers
    .filter((m) => m.path && (m.tool === 'Read' || m.tool === 'Write' || m.tool === 'Edit') && effective[m.capability] === 'DENY')
    .map((m) => ({ path: m.path!, tool: m.tool, capability: m.capability }));
  const preDeniedCommandClasses = [...new Set(matchers.filter((m) => m.command && capabilities[m.capability]?.absolute).map((m) => m.capability))].sort();
  const readOnlyCommandPatterns = matchers.filter((m) => m.command && m.capability === 'command.read-only').map((m) => m.command!);
  const sanitizerLockedMinimums: Record<string, 'block' | 'warn'> = {};
  for (const s of cp.secrets) for (const d of s.detectors) if (d.locked) sanitizerLockedMinimums[d.id] = d.severity;

  if (problems.length) throw new ControlPlaneValidationError(problems);

  const body = {
    schema: 'ego.authority-table/1' as const,
    sourceHashes: sortRecord(cp.sourceHashes),
    capabilities: sortRecord(capabilities),
    absoluteDenies: [...absoluteDenies].sort(),
    effective: sortRecord(effective),
    provenance: sortRecord(provenance),
    profiles: sortRecord(profiles),
    defaultMode,
    matchers,
    grants: cp.grants.grants.map((g) => ({ capability: g.capability, phrases: [...g.phrases] })),
    grantNegations: [...cp.grants.negations],
    grantNegationWindowTokens: cp.grants.negationWindowTokens,
    protectedPaths,
    preDeniedCommandClasses,
    readOnlyCommandPatterns,
    sanitizerLockedMinimums: sortRecord(sanitizerLockedMinimums),
  };
  return { ...body, tableHash: sha256Canonical(body) };
}

function sortRecord<T>(r: Record<string, T>): Record<string, T> {
  const out: Record<string, T> = {};
  for (const k of Object.keys(r).sort()) out[k] = r[k]!;
  return out;
}

function rel(root: string, file: string): string {
  return file.startsWith(root) ? file.slice(root.length + 1) : file;
}

/** Diff two compiled tables for `authority_changes` (Q84): effective verdict changes, added and removed IDs. */
export interface AuthorityChange {
  capability: string;
  kind: 'added' | 'removed' | 'changed' | 'matcher-repartitioned';
  from?: Verdict;
  to?: Verdict;
}

export function diffAuthorityTables(prev: CompiledAuthorityTable, next: CompiledAuthorityTable, profile = 'STRICT', mode?: string): AuthorityChange[] {
  const m = mode ?? next.defaultMode;
  const a = prev.profiles[profile]?.modes[m] ?? prev.effective;
  const b = next.profiles[profile]?.modes[m] ?? next.effective;
  const out: AuthorityChange[] = [];
  for (const id of Object.keys(b).sort()) {
    if (!(id in a)) out.push({ capability: id, kind: 'added', to: b[id]! });
    else if (a[id] !== b[id]) out.push({ capability: id, kind: 'changed', from: a[id]!, to: b[id]! });
  }
  for (const id of Object.keys(a).sort()) if (!(id in b)) out.push({ capability: id, kind: 'removed', from: a[id]! });
  const prevMatchers = new Set(prev.matchers.map((x) => `${x.tool}|${x.command ?? ''}|${x.path ?? ''}|${x.url ?? ''}`));
  for (const x of next.matchers) {
    const key = `${x.tool}|${x.command ?? ''}|${x.path ?? ''}|${x.url ?? ''}`;
    const prevForCap = prev.matchers.find((y) => y.capability === x.capability && `${y.tool}|${y.command ?? ''}|${y.path ?? ''}|${y.url ?? ''}` === key);
    if (!prevMatchers.has(key) && !prevForCap && a[x.capability] !== undefined) {
      out.push({ capability: x.capability, kind: 'matcher-repartitioned' });
    }
  }
  return out;
}

/** SemVer classification of a set of authority changes (Q84). */
export function classifyAuthorityChanges(changes: AuthorityChange[], next: CompiledAuthorityTable): 'none' | 'minor' | 'major' {
  if (changes.length === 0) return 'none';
  let level: 'minor' | 'major' = 'minor';
  for (const c of changes) {
    if (c.kind === 'changed' || c.kind === 'removed' || c.kind === 'matcher-repartitioned') level = 'major';
    if (c.kind === 'added' && c.to === 'ALLOW') level = 'major';
    if (c.kind === 'added' && next.absoluteDenies.includes(c.capability)) level = 'major';
  }
  return level;
}
