// Compiles the authored control plane plus overlays into the compiled authority table: the single generated object
// that hooks evaluate, `ego capabilities` renders, `explain capability` justifies and CI diffs for
// `authority_changes` (decision Q84). Deterministic and reproducible: no timestamps, sorted keys.
import { basename } from 'node:path';
import { sha256Canonical } from '../util/hash.ts';
import { shownText } from '../util/shown-text.ts';
import { overlayPathGlobs } from './overlay-paths.ts';
import { PRODUCTION_LANDINGS } from './target-kinds.ts';
import {
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
  /** @untrusted a regular expression an overlay file wrote: any text */
  command?: string;
  /** @untrusted a glob an overlay file wrote */
  path?: string;
  /** @untrusted a regular expression an overlay file wrote */
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
  /** WHO MOVED A PROFILE × MODE CELL away from the layered verdict, for the cells that something moved: `mode` when the mode's override
   *  changed what the profile left, `profile` when the profile's narrowing did. Not derivable from the cells (a profile's ASK that one mode
   *  turns into DENY looks, from the other modes, like the mode's doing), so the compiler, which applies both, writes it down - and
   *  `verdictSource` reads it: a refusal names the rule that is really the source (AUTH-8). */
  cellOrigins: Record<string, Record<string, Record<string, 'profile' | 'mode'>>>;
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
    /** @untrusted the organization's file adds to it */
    bounded: string[];
    installsDependencies: string[];
    discoversContent: string[];
    discoversConfig: string[];
    /** @untrusted the organization's file adds to it */
    imageSetup: string[];
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
  const cellOrigins: CompiledAuthorityTable['cellOrigins'] = {};
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
      const moved: Record<string, 'profile' | 'mode'> = {};
      for (const [id, v] of Object.entries(afterProfile)) if (v !== effective[id]) moved[id] = 'profile';
      for (const o of m.overrides) {
        if (capabilities[o.capability]?.absolute) continue; // validated at load; never widen absolute
        if (table[o.capability] !== o.verdict) moved[o.capability] = 'mode';
        table[o.capability] = o.verdict;
      }
      // absolute denies are DENY in every mode regardless of anything
      for (const id of absoluteDenies) table[id] = 'DENY';
      modes[m.id] = sortRecord(table);
      if (Object.keys(moved).length > 0) ((cellOrigins[p.id] ??= {})[m.id] = sortRecord(moved));
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
        `overlay matcher may not map ${shownText(om.command ?? om.path ?? om.url, 160)} to "${om.capability}": a mode can release that capability to ALLOW, so the mapping would widen; overlay matchers only narrow`,
      );
      continue;
    }
    if (!v) {
      problems.push(`overlay matcher references unknown capability "${om.capability}"`);
      continue;
    }
    if (v === 'ALLOW') {
      problems.push(
        `overlay matcher may not map ${shownText(om.command ?? om.path ?? om.url, 160)} to ALLOW capability "${om.capability}"; overlay matchers only narrow`,
      );
      continue;
    }
    // A RULE THAT NOTHING CONSULTS IS A PROTECTION THAT DOES NOT EXIST, and it must not compile as one. Each field is read by one kind
    // of judge: a `command` by the shell classifier (tool Bash), a `path` by the path judge (Read, Write and Edit - the shell layer
    // asks it too, so a protected path is protected from `cat` and `>` as well), a `url` by the fetch judge (WebFetch). A rule that
    // pairs a field with a tool that never asks about it (`tool: Bash, path: 'ops/**'`, `tool: WebFetch, command: …`) loaded without
    // a word and protected nothing (exit review 11, #121). `any` is every tool that reads the field.
    const where = om.command ?? om.path ?? om.url;
    if (om.command !== undefined && om.tool !== 'Bash' && om.tool !== 'any') {
      problems.push(`overlay matcher ${shownText(where, 160)} has a command pattern and tool "${om.tool}", which never classifies a command: use tool Bash (or any)`);
      continue;
    }
    if (om.path !== undefined && om.tool !== 'Read' && om.tool !== 'Write' && om.tool !== 'Edit' && om.tool !== 'any') {
      problems.push(
        `overlay matcher ${shownText(where, 160)} has a path pattern and tool "${om.tool}", which is never asked about a path: use tool Read to protect reading it, Write to protect writing it (the shell and the edit tools both ask), or any`,
      );
      continue;
    }
    if (om.url !== undefined && om.tool !== 'WebFetch' && om.tool !== 'any') {
      problems.push(`overlay matcher ${shownText(where, 160)} has a url pattern and tool "${om.tool}", which never fetches: use tool WebFetch (or any)`);
      continue;
    }
    // AN OVERLAY ONLY NARROWS, SO IT NEVER REPLACES THE CORE'S ANSWER: a command pattern is ADDITIVE - it contributes its hit beside the
    // one the core's first matching rule gave, and the strictest wins. Appended after the core's matchers and first-match-wins, a
    // narrowing for `make deploy` never ran, because the core's `make` rule (an ALLOW) matched first (exit review 11, #120).
    // The path and url judges combine the two layers the same way (classifyResolved, classifyUrl).
    // (a matcher that names more than one field is one rule per field: each judge reads its own)
    if (om.command !== undefined)
      matchers.push({ capability: om.capability, tool: om.tool, command: om.command, layer: 'overlay', additive: true });
    if (om.path !== undefined) {
      // a path rule is read as a `.gitignore` line is (overlay-paths.ts), and protects every way the path is written: the Write and
      // the Edit tool are one act, and `any` is a read and a write
      const tools = om.tool === 'any' ? ['Read', 'Write', 'Edit'] : om.tool === 'Read' ? ['Read'] : ['Write', 'Edit'];
      for (const glob of overlayPathGlobs(om.path))
        for (const tool of tools) matchers.push({ capability: om.capability, tool, path: glob, layer: 'overlay' });
    }
    if (om.url !== undefined) matchers.push({ capability: om.capability, tool: om.tool, url: om.url, layer: 'overlay' });
  }

  const { protectedPaths, preDeniedCommandClasses, readOnlyCommandPatterns } = deriveMatcherViews(matchers, effective, capabilities);
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
    cellOrigins: sortRecord(cellOrigins),
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
      imageSetup: [...cp.boundedCommands.imageSetup].sort(),
    },
    localTargets: {
      // the kernel's default with the layers' additions merged in: a layer can add a local target and a production
      // marker and can take nothing away, and the merged result is what the table hash covers
      ...mergeLocalTargets(cp.localTargets, opts.localTargetLayers ?? []),
      k8sLocalContexts: [...cp.localTargets.k8sLocalContexts].sort(),
      dbLocalHosts: [...cp.localTargets.dbLocalHosts].sort(),
      // (relative to the control plane, not to the project: the hash is the same wherever either of them sits - AUTH-11)
      file: `control-plane/${rel(cp.root, cp.localTargets.file)}`,
    },
  };
  return { ...body, tableHash: sha256Canonical(body) };
}

/**
 * The three views of the matcher list the table also carries: the paths whose read or write is DENY, the command classes that are
 * pre-denied, and the read-only command patterns. They are DERIVED from the matchers, so there is one function that derives them -
 * the compiler calls it, and so does the cache when it puts back a narrowing a working-tree edit removed.
 */
export function deriveMatcherViews(
  matchers: readonly CompiledMatcher[],
  effective: Readonly<Record<string, Verdict>>,
  capabilities: Readonly<Record<string, { lock?: CapabilityLock }>>,
): Pick<CompiledAuthorityTable, 'protectedPaths' | 'preDeniedCommandClasses' | 'readOnlyCommandPatterns'> {
  const protectedPaths = matchers
    .filter(
      (m) =>
        m.path &&
        (m.tool === 'Read' || m.tool === 'Write' || m.tool === 'Edit') &&
        effective[m.capability] === 'DENY',
    )
    .map((m) => ({ path: m.path!, tool: m.tool, capability: m.capability }));
  // ...plus the production capabilities the TARGET MODEL lands on (target-kinds.ts). `production.k8s.mutate` and
  // `production.helm.mutate` were pre-denied by two patterns that read the production names a second time; the target model
  // is their only reader now, and a protection that moved is not one that was removed
  const preDeniedCommandClasses = [
    ...new Set([
      ...matchers
        .filter(
          (m) =>
            m.command && capabilities[m.capability]?.lock !== 'none' && effective[m.capability] === 'DENY',
        )
        .map((m) => m.capability),
      ...PRODUCTION_LANDINGS.filter((id) => capabilities[id] !== undefined && capabilities[id]!.lock !== 'none' && effective[id] === 'DENY'),
    ]),
  ].sort();
  const readOnlyCommandPatterns = matchers
    .filter((m) => m.command && m.capability === 'command.read-only')
    .map((m) => m.command!);
  return { protectedPaths, preDeniedCommandClasses, readOnlyCommandPatterns };
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

// The diff of two compiled tables, the grade of a set of changes and the predicate "this change widens" are ONE description of the
// table and live in `table-diff.ts`; they are re-exported here because this is where the release pipeline and the commands have
// always imported them from.
export {
  AUTHORITY_TABLE_FIELDS,
  classifyAuthorityChanges,
  describeAuthorityChange,
  diffAuthorityTables,
  fieldOfChange,
  isWideningChange,
  matcherIdentity,
  type AuthorityChange,
  type TableBody,
  type TableField,
} from './table-diff.ts';
