// Compiles the authored control plane plus overlays into the compiled authority table: the single generated object
// that hooks evaluate, `ego capabilities` renders, `explain capability` justifies and CI diffs for
// `authority_changes` (decision Q84). Deterministic and reproducible: no timestamps, sorted keys.
import { basename } from 'node:path';
import { sha256Canonical } from '../util/hash.ts';
import {
  diffLocalTargets,
  mergeLocalTargets,
  type LocalTargetsLayerDoc,
} from '../control-plane/local-targets.ts';
import {
  ControlPlaneValidationError,
  VERDICT_RANK,
  type CapabilityDoc,
  type CapabilityLock,
  type ControlPlane,
  type ExecutionBudgets,
  type LocalTargets,
  type Verdict,
} from '../control-plane/types.ts';

/** Where a capability's effect LANDS: on this machine and inside the governed workspace, or somewhere else. */
export type EffectScope = 'local' | 'external';

/** The second segment of an identifier says where its effect lands when it is one of these. */
const OFF_MACHINE_SCOPES = new Set(['remote', 'nonlocal', 'registry', 'target', 'production', 'public', 'external']);
/** Namespaces whose identifiers describe THIS machine unless their scope segment says otherwise (`git.local.*` and
 *  `git.remote.*` share a namespace; `db.local.*` and `db.nonlocal.*` do too). */
const LOCAL_NAMESPACES = new Set(['fs', 'command', 'ego', 'git', 'container']);

/**
 * WHETHER A CAPABILITY LEAVES THE MACHINE, derived from the identifier (issue #16 sections 4 and 8: an external
 * effect has a standing ceiling of ASK, and a human phrase is a bounded approval, never a durable grant). It is a
 * positive grammar, not a list of the external ones: an effect is `local` only when the identifier says so —
 * `*.local.*`, or a namespace that describes this machine (`fs`, `command`, `ego`, `git`, `container`) whose scope
 * segment is not one that points elsewhere. Everything else is external, including a namespace nobody has classified
 * yet (`forge`, `network`, `mcp`, `cloud`, `production`, and the next one), so a new family is clamped until someone
 * decides otherwise. `*.target.unclassified` is external because "could not be resolved to a local target" is the
 * one claim a grant must never turn into a yes.
 */
export function effectScope(id: string): EffectScope {
  const [ns = '', scope = ''] = id.split('.');
  if (OFF_MACHINE_SCOPES.has(scope)) return 'external';
  if (scope === 'local') return 'local';
  return LOCAL_NAMESPACES.has(ns) ? 'local' : 'external';
}

/** THE PROFILES FROM THE WEAKEST ASSURANCE TO THE STRONGEST. The compiler refuses a control plane in which a profile
 *  is looser, for any capability in any mode, than the one before it. */
export const PROFILE_ORDER = ['STANDARD', 'STRICT', 'HIGH_ASSURANCE'] as const;

export interface CompiledCapability {
  family: string;
  description: string;
  absolute: boolean;
  /** lock tier (Q98): absolute (HARD_LOCK), admin-governed (ADMIN_GOVERNED: widenable only by the organization layer, never past ASK) or none */
  lock: CapabilityLock;
  /** verdict from the core layer before any narrowing */
  core: Verdict;
  /** where the effect lands. A session grant lifts only `local` capabilities; an `external` one has a standing
   *  ceiling of ASK that no phrase, mode or host setting removes */
  effect: EffectScope;
}

export interface CompiledMatcher {
  capability: string;
  tool: string;
  command?: string;
  path?: string;
  url?: string;
  /** contributes a hit but never wins the segment's semantic class */
  additive?: boolean;
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
  /** ADMIN_GOVERNED capabilities: DENY at the core, widenable only by the organization layer, never past ASK (Q98) */
  adminGoverned: string[];
  /** effective verdict after core → organization → overlay, before profile and mode */
  effective: Record<string, Verdict>;
  /** provenance per capability: which layer set the effective verdict */
  provenance: Record<string, LayerTrace[]>;
  /** per profile × mode → capability → verdict */
  profiles: Record<
    string,
    {
      budgetTokens: number;
      ceilingTokens: number;
      requiresSignedReleaseTrust: boolean;
      requiresManagedTier: boolean;
      budgets: ExecutionBudgets;
      modes: Record<string, Record<string, Verdict>>;
    }
  >;
  defaultMode: string;
  matchers: CompiledMatcher[];
  grants: Array<{ capability: string; phrases: string[] }>;
  grantNegations: string[];
  grantNegationWindowTokens: number;
  /** path patterns whose read or write is DENY at the core layer (credential stores, hook config, generated) */
  protectedPaths: Array<{ path: string; tool: string; capability: string }>;
  /** capabilities matched by Bash matchers that are HARD_LOCK or ADMIN_GOVERNED and effectively DENY (pre-denied command classes) */
  preDeniedCommandClasses: string[];
  /** command regex sources for read-only commands (STRICT shell allowlist base) */
  readOnlyCommandPatterns: string[];
  /** detector id → minimum severity that overlays may not lower */
  sanitizerLockedMinimums: Record<string, 'block' | 'warn'>;
  /** Q98: the authored local-development targets, so authorization can be target-aware */
  localTargets: LocalTargets;
  /** the authored bounded / discovering command vocabulary (UNCLAIMED-HEAD CLOSURE). ARRAYS, not Sets: the
   *  compiled table is cached as JSON and a Set does not survive the round trip. */
  boundedCommands: {
    bounded: string[];
    installsDependencies: string[];
    discoversContent: string[];
    discoversConfig: string[];
  };
}

export interface CompileOptions {
  organization?: CapabilityDoc | null;
  overlay?: CapabilityDoc | null;
  overlayMatchers?: CompiledMatcher[];
  /** heads the ORGANIZATION declares bounded, on top of the kernel's vocabulary (see LAYER_FILES) */
  organizationBounded?: string[];
  /** the organization's and the project's local-targets files, read (see `control-plane/local-targets.ts`) */
  localTargetLayers?: LocalTargetsLayerDoc[];
  /** project root used to relativize layer file paths so the table hash never depends on the checkout location */
  projectRoot?: string;
}

export function compileAuthority(cp: ControlPlane, opts: CompileOptions = {}): CompiledAuthorityTable {
  const problems: string[] = [];
  const capabilities: Record<string, CompiledCapability> = {};
  const effective: Record<string, Verdict> = {};
  const provenance: Record<string, LayerTrace[]> = {};
  const absoluteDenies: string[] = [];
  const adminGoverned: string[] = [];

  for (const c of cp.absoluteDenies.capabilities) {
    capabilities[c.id] = {
      family: c.family,
      description: c.description,
      absolute: true,
      lock: 'absolute',
      core: 'DENY',
      effect: effectScope(c.id),
    };
    effective[c.id] = 'DENY';
    provenance[c.id] = [{ layer: 'absolute', file: rel(cp.root, c.file), verdict: 'DENY' }];
    absoluteDenies.push(c.id);
  }
  for (const doc of cp.capabilityDocs) {
    for (const c of doc.capabilities) {
      capabilities[c.id] = {
        family: c.family,
        description: c.description,
        absolute: false,
        lock: c.lock,
        core: c.verdict,
        effect: effectScope(c.id),
      };
      effective[c.id] = c.verdict;
      provenance[c.id] = [
        {
          layer: c.lock === 'admin-governed' ? 'admin-governed' : 'core',
          file: rel(cp.root, c.file),
          verdict: c.verdict,
        },
      ];
      if (c.lock === 'admin-governed') adminGoverned.push(c.id);
    }
  }

  const applyLayer = (doc: CapabilityDoc | null | undefined, layerName: 'organization' | 'overlay') => {
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
      const widening = VERDICT_RANK[c.verdict] < VERDICT_RANK[current];
      // Q98: only the organization layer may widen an ADMIN_GOVERNED capability; nothing else may widen anything.
      if (widening && !(layerName === 'organization' && capabilities[c.id]!.lock === 'admin-governed')) {
        problems.push(
          `${c.file}:${c.line}: ${layerName} layer attempts to widen "${c.id}" from ${current} to ${c.verdict}; lower layers may only narrow`,
        );
        continue;
      }
      // Q98: an ADMIN_GOVERNED capability is always administrable — the organization may enable
      // it — but enabling an EXTERNAL effect never makes it unattended. Widening to ALLOW lands on ASK (the bounded
      // human approval) and the provenance says so, rather than being silently accepted.
      const clamped = widening && c.verdict === 'ALLOW' ? 'ASK' : c.verdict;
      effective[c.id] = clamped;
      provenance[c.id]!.push({
        layer: widening
          ? clamped === c.verdict
            ? 'organization (widened admin-governed deny)'
            : 'organization (widened admin-governed deny, clamped to the ASK ceiling)'
          : layerName,
        file: opts.projectRoot ? rel(opts.projectRoot, c.file) : basename(c.file),
        verdict: clamped,
      });
    }
  };
  applyLayer(opts.organization, 'organization');
  applyLayer(opts.overlay, 'overlay');

  // Q98 (issue #16 sections 4 and 8): a human phrase is a bounded task approval, never a durable authority grant, so a
  // grant lifts ASK to ALLOW only for a capability whose effect stays on this machine. For one that leaves it, the grant
  // is clamped at the ASK ceiling — recorded here, in the same trace the organization's ASK-ceiling clamp lives in,
  // so `explain capability` can say why a recognised phrase changed nothing instead of leaving it silently ignored.
  // The evaluator enforces it (`applyGrants`) and the hook says so when it hears the phrase.
  for (const g of cp.grants.grants) {
    const cap = capabilities[g.capability];
    if (!cap || cap.effect !== 'external') continue;
    provenance[g.capability]!.push({
      layer: 'grant (external effect: a session grant cannot lift it above the ASK ceiling)',
      file: rel(cp.root, cp.grants.file),
      verdict: effective[g.capability] === 'DENY' ? 'DENY' : 'ASK',
    });
  }

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
      budgets: { ...p.budgets },
      modes,
    };
  }

  // A STRICTER PROFILE IS NEVER LOOSER THAN A WEAKER ONE, for any capability in any mode. A profile's `narrow` list is
  // its own - it is not inherited - so the order is a property of three hand-written lists, and a list that falls
  // behind turns the strongest profile into a hole in the middle one: exit review 10 added `git.local.merge` and
  // `git.local.cherry-pick` to STRICT, HIGH_ASSURANCE was not touched, and `git merge --no-ff topic` was ASK under
  // STRICT and ALLOW under HIGH_ASSURANCE. The compiled cells are compared, so a mode override or a layer cannot hide it.
  const present = PROFILE_ORDER.filter((id) => id in profiles);
  for (let i = 1; i < present.length; i++) {
    const weaker = present[i - 1]!;
    const stricter = present[i]!;
    const looser = new Map<string, { mode: string; was: Verdict; is: Verdict; modes: number }>();
    for (const [mode, caps] of Object.entries(profiles[stricter]!.modes))
      for (const [cap, is] of Object.entries(caps)) {
        const was = profiles[weaker]!.modes[mode]?.[cap];
        if (was === undefined || VERDICT_RANK[is] >= VERDICT_RANK[was]) continue;
        const seen = looser.get(cap);
        if (seen) seen.modes++;
        else looser.set(cap, { mode, was, is, modes: 1 });
      }
    const file = (id: string): string => `profiles/${basename(cp.profiles.find((p) => p.id === id)?.file ?? id)}`;
    for (const [cap, l] of looser)
      problems.push(
        `${file(stricter)}: profile ${stricter} is looser than ${weaker} for "${cap}" (${l.is} against ${l.was}, first in mode ${l.mode}${l.modes > 1 ? ` and ${l.modes - 1} more` : ''}); a stricter profile lists at least what a weaker one narrows, because narrow is not inherited`,
      );
  }

  const matchers: CompiledMatcher[] = cp.matchers.map((m) => {
    const out: CompiledMatcher = { capability: m.capability, tool: m.tool, layer: 'core' };
    if (m.additive) out.additive = true;
    if (m.commandSource) out.command = m.commandSource;
    if (m.path) out.path = m.path;
    if (m.urlSource) out.url = m.urlSource;
    return out;
  });
  // A MODE CAN RELEASE A CAPABILITY THE BASE TABLE HOLDS. EGO_MAINTENANCE overrides `ego.hooks.edit` to ALLOW, so an
  // overlay matcher that maps `**/*` to it looked like a narrowing (the base verdict is not ALLOW) and became, in that
  // mode, an ALLOW for every path - including the outside-workspace write the default classification would have
  // asked about (exit review 10). "Overlay matchers only narrow" has to hold in every mode, not only the default one.
  const modeAllows = new Set(
    cp.modes.flatMap((m) => m.overrides.filter((o) => o.verdict === 'ALLOW').map((o) => o.capability)),
  );
  for (const om of opts.overlayMatchers ?? []) {
    const v = effective[om.capability];
    if (v && v !== 'ALLOW' && modeAllows.has(om.capability)) {
      problems.push(
        `overlay matcher may not map "${om.command ?? om.path ?? om.url}" to "${om.capability}": a mode can release that capability to ALLOW, so the mapping would widen; overlay matchers only narrow`,
      );
      continue;
    }
    if (!v) {
      problems.push(`overlay matcher references unknown capability "${om.capability}"`);
      continue;
    }
    if (v === 'ALLOW') {
      problems.push(
        `overlay matcher may not map "${om.command ?? om.path ?? om.url}" to ALLOW capability "${om.capability}"; overlay matchers only narrow`,
      );
      continue;
    }
    matchers.push({ ...om, layer: 'overlay' });
  }

  const protectedPaths = matchers
    .filter(
      (m) =>
        m.path &&
        (m.tool === 'Read' || m.tool === 'Write' || m.tool === 'Edit') &&
        effective[m.capability] === 'DENY',
    )
    .map((m) => ({ path: m.path!, tool: m.tool, capability: m.capability }));
  const preDeniedCommandClasses = [
    ...new Set(
      matchers
        .filter(
          (m) =>
            m.command && capabilities[m.capability]?.lock !== 'none' && effective[m.capability] === 'DENY',
        )
        .map((m) => m.capability),
    ),
  ].sort();
  const readOnlyCommandPatterns = matchers
    .filter((m) => m.command && m.capability === 'command.read-only')
    .map((m) => m.command!);
  const sanitizerLockedMinimums: Record<string, 'block' | 'warn'> = {};
  for (const s of cp.secrets)
    for (const d of s.detectors) if (d.locked) sanitizerLockedMinimums[d.id] = d.severity;

  if (problems.length) throw new ControlPlaneValidationError(problems);

  const body = {
    schema: 'ego.authority-table/1' as const,
    sourceHashes: sortRecord(cp.sourceHashes),
    capabilities: sortRecord(capabilities),
    absoluteDenies: [...absoluteDenies].sort(),
    adminGoverned: [...adminGoverned].sort(),
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
    boundedCommands: {
      // the organization's additions are merged in, and take precedence by being MORE SPECIFIC where they are:
      // dispatch picks the longest matching entry across the lists, so `pytest -q` declared bounded by an
      // organization beats the kernel's `pytest`
      bounded: [...new Set([...cp.boundedCommands.bounded, ...(opts.organizationBounded ?? [])])].sort(),
      installsDependencies: [...cp.boundedCommands.installsDependencies].sort(),
      discoversContent: [...cp.boundedCommands.discoversContent].sort(),
      discoversConfig: [...cp.boundedCommands.discoversConfig].sort(),
    },
    localTargets: {
      // the kernel's default with the layers' additions merged in: a layer can add a local target and a production
      // marker and can take nothing away, and the merged result is what the table hash covers
      ...mergeLocalTargets(cp.localTargets, opts.localTargetLayers ?? []),
      k8sLocalContexts: [...cp.localTargets.k8sLocalContexts].sort(),
      dbLocalHosts: [...cp.localTargets.dbLocalHosts].sort(),
      file: rel(opts.projectRoot ?? '', cp.localTargets.file),
    },
  };
  return { ...body, tableHash: sha256Canonical(body) };
}

function sortRecord<T>(r: Record<string, T>): Record<string, T> {
  const out: Record<string, T> = {};
  for (const k of Object.keys(r).sort()) out[k] = r[k]!;
  return out;
}

function rel(root: string, file: string): string {
  // a root written with a trailing separator must not cost the first character of the name (`ermissions/…`)
  const base = root.endsWith('/') ? root.slice(0, -1) : root;
  return base !== '' && file.startsWith(base + '/') ? file.slice(base.length + 1) : file;
}

/** Diff two compiled tables for `authority_changes` (Q84): effective verdict changes, added and removed IDs. */
export interface AuthorityChange {
  capability: string;
  kind:
    | 'added'
    | 'removed'
    | 'changed'
    | 'matcher-repartitioned'
    | 'matcher-removed'
    | 'matcher-added'
    | 'lock-changed'
    | 'budget-changed'
    | 'sanitizer-weakened'
    | 'grants-widened'
    | 'grants-narrowed'
    | 'protection-removed'
    | 'local-target-added'
    | 'local-target-removed'
    | 'production-marker-added'
    | 'production-marker-removed';
  /** profile/mode cell where a verdict change was observed (first one found); absent for table-wide changes */
  cell?: string;
  from?: Verdict;
  to?: Verdict;
  fromLock?: CapabilityLock;
  toLock?: CapabilityLock;
  detail?: string;
}

function matcherKey(x: CompiledMatcher): string {
  return `${x.tool}|${x.command ?? ''}|${x.path ?? ''}|${x.url ?? ''}`;
}

/**
 * Diff two compiled tables for `authority_changes` (Q84) across EVERY profile × mode cell: a verdict change in any
 * cell counts, matcher removals and re-partitions count, lock-tier moves count, budget changes are reported separately.
 */
export function diffAuthorityTables(
  prev: CompiledAuthorityTable,
  next: CompiledAuthorityTable,
): AuthorityChange[] {
  const out: AuthorityChange[] = [];
  const seen = new Set<string>();
  const push = (c: AuthorityChange) => {
    const k = `${c.kind}|${c.capability}|${c.from ?? ''}|${c.to ?? ''}|${c.detail ?? ''}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push(c);
  };
  const ids = new Set([...Object.keys(prev.effective), ...Object.keys(next.effective)]);
  for (const id of [...ids].sort()) {
    if (!(id in prev.effective)) push({ capability: id, kind: 'added', to: next.effective[id]! });
    else if (!(id in next.effective)) push({ capability: id, kind: 'removed', from: prev.effective[id]! });
  }
  const cells = new Set<string>();
  for (const t of [prev, next])
    for (const p of Object.keys(t.profiles))
      for (const m of Object.keys(t.profiles[p]!.modes)) cells.add(`${p}/${m}`);
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
    for (const id of [...ids].sort()) {
      if (id in a && id in b && a[id] !== b[id])
        push({ capability: id, kind: 'changed', cell, from: a[id]!, to: b[id]! });
    }
  }
  for (const id of [...ids].sort()) {
    const fromLock = prev.capabilities[id]?.lock;
    const toLock = next.capabilities[id]?.lock;
    if (fromLock && toLock && fromLock !== toLock)
      push({ capability: id, kind: 'lock-changed', fromLock, toLock });
    // a capability that stops leaving the machine stops being clamped: every grant phrase for it now lifts it
    if (prev.capabilities[id]?.effect === 'external' && next.capabilities[id]?.effect === 'local')
      push({
        capability: id,
        kind: 'grants-widened',
        detail: 'effect external -> local: a session grant now lifts it from ASK to ALLOW',
      });
  }
  const prevByKey = new Map(prev.matchers.map((x) => [matcherKey(x), x] as const));
  const nextByKey = new Map(next.matchers.map((x) => [matcherKey(x), x] as const));
  next.matchers.forEach((x, i) => {
    const k = matcherKey(x);
    const y = prevByKey.get(k);
    if (!y) {
      // a new matcher placed before an existing matcher of the same tool with a different verdict re-partitions the
      // operations that existing matcher used to classify (Q84: MAJOR); appended after every peer it only narrows what
      // was unknown (MINOR when its capability is not ALLOW)
      const mine = next.effective[x.capability] ?? 'ASK';
      const shadowed = next.matchers
        .slice(i + 1)
        .some(
          (z) =>
            prevByKey.has(matcherKey(z)) &&
            (z.tool === x.tool || z.tool === 'any' || x.tool === 'any') &&
            (next.effective[z.capability] ?? 'ASK') !== mine,
        );
      push({
        capability: x.capability,
        kind: shadowed ? 'matcher-repartitioned' : 'matcher-added',
        detail: shadowed ? `${k}: inserted before existing matchers of a different verdict` : k,
      });
    } else if (y.capability !== x.capability)
      push({
        capability: x.capability,
        kind: 'matcher-repartitioned',
        detail: `${k}: ${y.capability} -> ${x.capability}`,
      });
  });
  // grant phrases turn ASK into ALLOW: a new phrase or a removed negation widens, a removed phrase narrows
  const phrases = (t: CompiledAuthorityTable) =>
    new Set(t.grants.flatMap((g) => g.phrases.map((ph) => `${g.capability}|${ph}`)));
  const gp = phrases(prev);
  const gn = phrases(next);
  for (const k of gn)
    if (!gp.has(k))
      push({ capability: k.split('|')[0]!, kind: 'grants-widened', detail: `grant phrase added: ${k}` });
  for (const k of gp)
    if (!gn.has(k))
      push({ capability: k.split('|')[0]!, kind: 'grants-narrowed', detail: `grant phrase removed: ${k}` });
  for (const n of prev.grantNegations)
    if (!next.grantNegations.includes(n))
      push({ capability: '*', kind: 'grants-widened', detail: `grant negation removed: ${n}` });
  if (next.grantNegationWindowTokens < prev.grantNegationWindowTokens)
    push({
      capability: '*',
      kind: 'grants-widened',
      detail: `negation window ${prev.grantNegationWindowTokens} -> ${next.grantNegationWindowTokens}`,
    });
  const pp = (t: CompiledAuthorityTable) =>
    new Set(t.protectedPaths.map((x) => `${x.tool}|${x.path}|${x.capability}`));
  const nextPp = pp(next);
  for (const k of pp(prev))
    if (!nextPp.has(k))
      push({
        capability: k.split('|')[2]!,
        kind: 'protection-removed',
        detail: `protected path removed: ${k}`,
      });
  for (const c of prev.preDeniedCommandClasses)
    if (!next.preDeniedCommandClasses.includes(c))
      push({ capability: c, kind: 'protection-removed', detail: `pre-denied command class removed: ${c}` });
  // locked redaction minimums are part of the contract: a removed or lowered minimum is a MAJOR change
  for (const [id, sev] of Object.entries(prev.sanitizerLockedMinimums)) {
    const now = next.sanitizerLockedMinimums[id];
    if (!now) push({ capability: '*', kind: 'sanitizer-weakened', detail: `locked detector ${id} removed` });
    else if (sev === 'block' && now === 'warn')
      push({
        capability: '*',
        kind: 'sanitizer-weakened',
        detail: `locked detector ${id} lowered from block to warn`,
      });
  }
  // THE LOCAL-DEVELOPMENT REGISTRY IS AUTHORITY. Declaring a target local turns a refusal into an allowed
  // operation without changing a single capability verdict, so a diff that compared verdicts alone reported the
  // widening as no change at all. Both the human gate (`tableWidenings`) and this diff read the same function.
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
  for (const [k, y] of prevByKey)
    if (!nextByKey.has(k)) push({ capability: y.capability, kind: 'matcher-removed', detail: k });
  for (const p of Object.keys(next.profiles).sort()) {
    const a = prev.profiles[p]?.budgets;
    const b = next.profiles[p]!.budgets;
    if (!a) continue;
    for (const k of Object.keys(b) as Array<keyof ExecutionBudgets>)
      if (a[k] !== b[k])
        push({
          capability: '*',
          kind: 'budget-changed',
          detail: `${p}.${k}: ${String(a[k])} -> ${String(b[k])}`,
        });
  }
  return out;
}

/**
 * SemVer classification of a set of authority changes (Q84): any effective verdict change, removal, re-partition,
 * matcher removal (an operation loses its classification), lock move, or a new ALLOW is MAJOR; a new ASK/DENY id, a
 * new matcher that narrows, or a budget change is MINOR.
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
 * marked, because a missed widening costs more than a spurious mark. `ego authority diff` prints the mark and
 * `--fail-on-widening` turns it into an exit code.
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
    // (declaring a target local, or removing a production marker, turns a refusal into an allowed operation without
    // changing a single capability verdict: it is a widening even though no cell moves)
    case 'matcher-removed':
    case 'matcher-repartitioned':
    case 'sanitizer-weakened':
    case 'grants-widened':
    case 'protection-removed':
    case 'local-target-added':
    case 'production-marker-removed':
      return true;
    case 'grants-narrowed':
    case 'budget-changed':
    case 'local-target-removed':
    case 'production-marker-added':
      return false;
  }
}
