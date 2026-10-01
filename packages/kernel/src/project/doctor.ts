// `ego doctor`: every guarantee reported as SATISFIED / NOT SATISFIED / SKIPPED / UNVERIFIED, never claimed.
import { join, resolve, sep } from 'node:path';
import { detectProject } from './detect.ts';
import { readPin, hasPin, type Pin } from '../launcher/pin.ts';
import {
  selfIdentity,
  selfVersion,
  selfIsDevelopment,
  controlPlaneDir,
  isEgoSourceRepository,
} from '../launcher/self.ts';
import { egoHome, isRuntimeCached, readIndex, effectiveTrust, isSignedTrust } from '../launcher/home.ts';
import { loadTrustStore, revokedKeyIds } from '../launcher/trust.ts';
import { formatFreshness, policyCacheFreshness, readPolicyCache } from '../policy/cache.ts';
import { POLICY_STALE_RULE, renderFailure } from '../authority/reasons.ts';
import {
  describeCapabilities,
  formatCapabilityFacts,
  governedSurface,
  summarize,
} from '../authority/describe.ts';
import { runtimeRootDir } from '../runtime/root.ts';
import { readGeneratedManifest } from './init.ts';
import { gitHookStatus } from './githooks.ts';
import { gitConfigScope } from '../util/git.ts';
import { isFile, readJsonIfExists, readTextIfExists } from '../util/fs.ts';
import { packageRoot } from '../launcher/self.ts';
import { sha256Hex } from '../util/hash.ts';
import { resolveLauncher } from '../util/path-resolve.ts';
import { HOST_MATRIX, HOST_IDS, type HostId } from '../hosts/matrix.ts';
import { loadControlPlane } from '../control-plane/load.ts';
import { CONTROL_KINDS, type Profile } from '../control-plane/types.ts';
import { approxTokens } from '../context/root-instructions.ts';

export type DoctorState = 'SATISFIED' | 'NOT SATISFIED' | 'SKIPPED' | 'UNVERIFIED' | 'INFO';

export interface DoctorLine {
  section: string;
  item: string;
  state: DoctorState;
  detail: string;
  /** a NOT SATISFIED line that counts against the exit code */
  required: boolean;
}

export interface DoctorReport {
  ok: boolean;
  lines: DoctorLine[];
  projectRoot: string | null;
}

export interface DoctorOptions {
  cwd: string;
  env: NodeJS.ProcessEnv;
  now: () => string;
  offline: boolean;
  /** host to evaluate containment against; detected from environment markers when absent */
  host?: HostId;
  /** how much of the capability matrix the `authority` section lists: `summary` is the counts, `governed` (the
   *  default) adds every ADMIN_GOVERNED capability and the target-dependent groups, `all` lists every capability */
  authority?: 'summary' | 'governed' | 'all';
}

interface DeclaredOnlySetting {
  /** the key as an operator writes it in a profile's front matter */
  key: string;
  /** the field the loader puts it in */
  field: keyof Profile;
  /** the value that asks for nothing: the loader's default, which STANDARD keeps */
  baseline: unknown;
  /** an unmet requirement fails doctor; a policy about a situation EGO cannot yet detect does not */
  requirement: boolean;
  /** what is missing, in one clause */
  missing: string;
}

/**
 * Profile settings the control plane parses, validates and compiles and that NO code reads: the package sources
 * mention each field only in the loader, the type and the compiler's copy. Setting one to a stricter value changes
 * nothing, and the profile documents described several of them as enforced (audit X8, D28). When a setting gains a
 * consumer, take it out of this list and out of the "declared, not enforced" paragraph of the profile documents.
 * `requires_signed_release_trust` is not here because its requirement IS enforced — by the profile's identity (any
 * profile but STANDARD), not by reading the setting; the profile documents say so.
 */
export const DECLARED_ONLY_PROFILE_SETTINGS: readonly DeclaredOnlySetting[] = [
  {
    key: 'requires_managed_tier',
    field: 'requiresManagedTier',
    baseline: false,
    requirement: true,
    missing: 'EGO neither installs nor verifies a managed tier (issue #26)',
  },
  {
    key: 'requires_remote_verify_backstop',
    field: 'requiresRemoteVerifyBackstop',
    baseline: false,
    requirement: true,
    missing: '`ego verify --range` is a phase-6 command and does not exist yet',
  },
  {
    key: 'shell_uncertain_mutation_with_foreign_live_session',
    field: 'shellUncertainMutation',
    baseline: 'DETECT_AFTER',
    requirement: false,
    missing:
      'no foreign live session is detected until held scopes exist (phase 2), so nothing is denied for this',
  },
  {
    key: 'grilling_review_unavailable',
    field: 'grillingReviewUnavailable',
    baseline: 'CONTINUE_WITH_DISCLOSURE',
    requirement: false,
    missing: 'the Stop hook never blocks DONE, and the Grilling review is phase 4',
  },
  {
    key: 'forge_unreachable_at_done',
    field: 'forgeUnreachableAtDone',
    baseline: 'CONTINUE_WITH_DISCLOSURE',
    requirement: false,
    missing: 'the Stop hook never blocks DONE, and the forge snapshot is phase 2',
  },
  {
    key: 'owner_weakening_plain_policy',
    field: 'ownerWeakeningPlainPolicy',
    baseline: 'AUTO_WITH_INFORM',
    requirement: false,
    missing: 'the human decision gate is phase 5',
  },
  {
    key: 'model_flagged_conflict_on_control',
    field: 'modelFlaggedConflictOnControl',
    baseline: 'INFORM',
    requirement: false,
    missing: 'the human decision gate is phase 5',
  },
];

export function detectHost(env: NodeJS.ProcessEnv): HostId | null {
  if (env['CLAUDECODE'] === '1' || env['CLAUDE_CODE'] === '1' || env['CLAUDE_PID']) return 'claude-code';
  if (env['CODEX_SANDBOX'] || env['CODEX_THREAD_ID'] || env['CODEX_CLI'] === '1') return 'codex-cli';
  return null;
}

export function runDoctor(opts: DoctorOptions): DoctorReport {
  const lines: DoctorLine[] = [];
  const add = (section: string, item: string, state: DoctorState, detail: string, required = true) =>
    lines.push({ section, item, state, detail, required });
  const det = detectProject(opts.cwd);
  const home = egoHome(opts.env);
  const self = selfIdentity();
  const version = selfVersion();
  const dev = selfIsDevelopment();

  // runtime identity and trust
  const idx = readIndex(home, self.name, version);
  const trust = idx ? effectiveTrust(idx, revokedKeyIds(loadTrustStore(home))) : null;
  add(
    'runtime',
    'executing runtime',
    'INFO',
    `${version} identity ${self.runtimeSha256.slice(0, 12)}… ${dev ? '(development identity)' : ''}`,
    false,
  );
  add(
    'runtime',
    'acquisition',
    'INFO',
    idx ? idx.records.map((r) => r.source).join(', ') : 'not indexed',
    false,
  );
  add('runtime', 'trust', 'INFO', trust ?? 'none (not indexed)', false);
  add(
    'runtime',
    'node',
    process.versions.node.split('.')[0]! >= '24' ? 'SATISFIED' : 'NOT SATISFIED',
    `node ${process.versions.node} (floor >= 24)`,
  );
  const launcher = resolveLauncher(opts.env);
  add(
    'runtime',
    'launcher on PATH',
    launcher ? 'SATISFIED' : 'NOT SATISFIED',
    launcher ?? '`ego` is not resolvable on PATH; hook shims fail closed (K25)',
    false,
  );

  if (!det.gitRoot || !hasPin(det.gitRoot)) {
    add(
      'project',
      'pin',
      'NOT SATISFIED',
      det.gitRoot ? 'not initialized; run `ego init`' : 'not a git repository',
    );
    return { ok: false, lines, projectRoot: det.gitRoot };
  }
  const root = det.gitRoot;
  let pin: Pin;
  try {
    pin = readPin(root);
  } catch (e) {
    add('project', 'pin', 'NOT SATISFIED', (e as Error).message);
    return { ok: false, lines, projectRoot: root };
  }
  add(
    'project',
    'pin',
    'INFO',
    `${pin.version} (${pin.integrity.slice(0, 12)}…) profile ${pin.profile} task source ${pin.taskSource ?? 'ad-hoc'}`,
    false,
  );
  const pinMatch = pin.integrity === self.runtimeSha256;
  add(
    'project',
    'pin matches executing runtime',
    pinMatch ? 'SATISFIED' : 'NOT SATISFIED',
    pinMatch
      ? 'same identity'
      : renderFailure(
          'POLICY_STALE',
          `pin ${pin.integrity.slice(0, 12)} vs executing ${self.runtimeSha256.slice(0, 12)}; the launcher delegates to the pinned runtime when cached`,
          {
            source: 'the project pin, .harness/harness.md, against the executing runtime',
            changeable: true,
            changeBy: '`ego sync` fetches the pinned runtime, `ego upgrade` changes the pin (a human act)',
          },
        ),
  );
  const pinIdx = readIndex(home, pin.name, pin.version);
  const pinTrust = pinIdx ? effectiveTrust(pinIdx, revokedKeyIds(loadTrustStore(home))) : null;
  const requiresSigned = pin.profile !== 'STANDARD';
  add(
    'project',
    'trust transition',
    'INFO',
    `${pinIdx?.records[0]?.trust ?? 'none'}${pinTrust && pinIdx && pinIdx.records.length > 1 ? ` -> ${pinTrust}` : ''}`,
    false,
  );
  add(
    'project',
    `profile requirement (${pin.profile}): signed release trust`,
    requiresSigned ? (isSignedTrust(pinTrust) ? 'SATISFIED' : 'NOT SATISFIED') : 'INFO',
    requiresSigned
      ? isSignedTrust(pinTrust)
        ? `${pinTrust}`
        : `trust is ${pinTrust ?? 'none'}; only the pre-promotion set runs until \`ego sync\` promotes it (Q96)`
      : 'STANDARD operates at any trust level with disclosure',
  );
  add(
    'project',
    'runtime cached',
    isRuntimeCached(home, pin.integrity) || pinMatch ? 'SATISFIED' : 'NOT SATISFIED',
    isRuntimeCached(home, pin.integrity)
      ? `${home.runtimes}/${pin.integrity.slice(0, 12)}…`
      : pinMatch
        ? 'executing from the equal launcher runtime'
        : 'pinned runtime missing from the cache; run `ego sync`',
  );

  // generated freshness and policy
  const cpRoot = controlPlaneDir();
  const fresh = policyCacheFreshness(cpRoot, root, { runtimeSha256: self.runtimeSha256, version });
  add(
    'policy',
    'compiled policy cache',
    fresh.fresh ? 'SATISFIED' : 'NOT SATISFIED',
    formatFreshness(fresh),
  );
  const cache = readPolicyCache(root);
  if (cache?.pendingWidening)
    add(
      'policy',
      'pending widening',
      'NOT SATISFIED',
      renderFailure(
        'POLICY_STALE',
        `${cache.pendingWidening.widenings.length} widening(s) in the layer files are not applied until a human runs \`ego init\` from their own terminal: ${cache.pendingWidening.widenings.slice(0, 3).join('; ')}`,
        POLICY_STALE_RULE,
      ),
      false,
    );
  if (cache) {
    add(
      'policy',
      'authority table',
      'INFO',
      `hash ${cache.table.tableHash.slice(0, 12)}…, ${cache.table.absoluteDenies.length} HARD_LOCK, ${cache.table.adminGoverned.length} ADMIN_GOVERNED, ${Object.keys(cache.table.capabilities).length} capabilities`,
      false,
    );
    for (const n of cache.notices ?? []) add('policy', 'notice', 'INFO', n, false);
    const layered = Object.keys(cache.layerSources);
    add(
      'policy',
      'layers',
      'INFO',
      layered.length ? layered.join(', ') : 'core only (no organization policy, no overlay narrowing)',
      false,
    );
    // THE CAPABILITY MATRIX (issue #16 section 12): effect class, lock tier, the verdict in force, the ceiling, the layer
    // that decided and, for a capability that depends on a target, the rule that classifies the target. Every field is
    // derived from the compiled table by the same module `ego capabilities` and `ego explain` read.
    const mode = cache.table.defaultMode;
    const level = opts.authority ?? 'governed';
    const views = describeCapabilities(cache.table, pin.profile, mode);
    add(
      'authority',
      'capability matrix',
      'INFO',
      `${summarize(views)} (profile ${pin.profile}, mode ${mode}); ${level === 'all' ? 'every capability is listed below' : level === 'governed' ? 'the ADMIN_GOVERNED capabilities and the target-dependent groups are listed below; `ego doctor --capabilities` or `ego capabilities` lists every one' : '`ego doctor` lists the ADMIN_GOVERNED capabilities and the target-dependent groups, `ego capabilities` every one'}`,
      false,
    );
    if (level === 'all') for (const v of views) add('authority', v.id, 'INFO', formatCapabilityFacts(v), false);
    else if (level === 'governed') {
      const surface = governedSurface(cache.table, views);
      for (const v of surface.adminGoverned) add('authority', v.id, 'INFO', formatCapabilityFacts(v), false);
      for (const g of surface.targets)
        add('authority', `target-dependent (${g.kind})`, 'INFO', `${g.capabilities.join(', ')}: ${g.rule}`, false);
    }
  }
  const manifest = readGeneratedManifest(root);
  if (!manifest) add('generated', 'artifacts', 'NOT SATISFIED', 'no generated manifest; run `ego init`');
  else {
    const stale = [
      ...Object.entries(manifest.files)
        .filter(
          ([rel, hash]) =>
            !isFile(join(root, rel)) || sha256Hex(readTextIfExists(join(root, rel)) ?? '') !== hash,
        )
        .map(([rel]) => rel),
      ...Object.entries(manifest.sources ?? {})
        .filter(
          ([rel, hash]) =>
            (isFile(join(root, rel)) ? sha256Hex(readTextIfExists(join(root, rel)) ?? '') : null) !== hash,
        )
        .map(([rel]) => `${rel} (source changed)`),
    ];
    add(
      'generated',
      'artifacts',
      stale.length ? 'NOT SATISFIED' : 'SATISFIED',
      stale.length
        ? `stale or hand-edited: ${stale.join(', ')}`
        : `${Object.keys(manifest.files).length} files fresh`,
    );
  }
  const agents = readTextIfExists(join(root, 'AGENTS.md'));
  const budget = cache?.table.profiles[pin.profile]?.budgetTokens ?? 2000;
  add(
    'context',
    'root instructions budget',
    agents && approxTokens(agents) <= budget ? 'SATISFIED' : 'NOT SATISFIED',
    agents ? `~${approxTokens(agents)} of ${budget} tokens` : 'AGENTS.md missing',
  );

  // hooks and hosts
  for (const h of HOST_IDS) {
    const m = HOST_MATRIX[h];
    const present = det.hosts[h].hooksPresent;
    const blocking = m.capabilities['blocking-pre-tool-hook'].status;
    add(
      'hooks',
      `${h} hooks installed`,
      present ? 'SATISFIED' : 'NOT SATISFIED',
      present
        ? h === 'claude-code'
          ? '.claude/settings.json'
          : '.codex/hooks.json'
        : 'missing; run `ego init`',
      h === 'claude-code',
    );
    // `blocking` is a status EGO authored in its own host matrix, not a fact it measured here. Printing the note
    // alone read as "EGO checked that deny blocks the call"; it did not. Conformance is phase 6.
    add(
      'hooks',
      `${h} blocking PreToolUse`,
      blocking === 'SUPPORTED' ? 'SATISFIED' : 'UNVERIFIED',
      `${m.capabilities['blocking-pre-tool-hook'].note}${blocking === 'SUPPORTED' ? ' (declared in EGO\u2019s own host matrix; verified against a running host by the phase-6 conformance suite)' : ''}`,
      false,
    );
  }
  // The shim's PRESENCE was reported as satisfaction. `.harness/hooks` is a protected path, so an agent cannot
  // write it through a governed tool — but "the file is there" is not "the file is the one EGO installed", and
  // EGO ships the original, so it can say which.
  const shim = join(root, '.harness', 'hooks', 'ego-hook.sh');
  const shimMatches = ((): boolean | null => {
    if (!isFile(shim)) return null;
    try {
      return readTextIfExists(shim) === readTextIfExists(join(packageRoot(), 'runtime', 'posix', 'ego-hook.sh'));
    } catch {
      return null;
    }
  })();
  add(
    'hooks',
    'fail-closed shim',
    shimMatches === true ? 'SATISFIED' : shimMatches === null && !isFile(shim) ? 'NOT SATISFIED' : 'UNVERIFIED',
    shimMatches === true
      ? '.harness/hooks/ego-hook.sh matches the copy EGO installs'
      : isFile(shim)
        ? '.harness/hooks/ego-hook.sh is present but does NOT match the copy EGO installs'
        : 'missing',
  );
  // the directory git actually runs hooks from (husky user hooks resolved), the shim and the husky runner
  const hooks = gitHookStatus(root);
  const insideRepo =
    resolveInside(root, hooks.dir) ||
    resolveInside(det.mainWorktree ?? root, hooks.dir) ||
    gitConfigScope(root, 'core.hooksPath') !== 'global';
  add(
    'hooks',
    'git hooks',
    insideRepo && hooks.ok ? 'SATISFIED' : 'NOT SATISFIED',
    !insideRepo
      ? `core.hooksPath comes from the global git configuration and resolves outside this repository (${hooks.dir}); EGO never writes there. Set a repository-local hooks path and run \`ego init\``
      : hooks.ok
        ? `${hooks.dir.startsWith(root) ? hooks.dir.slice(root.length + 1) : hooks.dir}/pre-commit, pre-push (bypassable with --no-verify: backstop is \`ego verify --range\` on a protected branch, phase 6)`
        : `${hooks.problems.join('; ')} (run \`ego init\`)`,
    true,
  );

  // workspace and forge
  add(
    'workspace',
    'git root',
    'INFO',
    `${root}${det.isWorktree ? ` (worktree of ${det.mainWorktree})` : ''}`,
    false,
  );
  add(
    'workspace',
    'runtime root',
    isFile(join(runtimeRootDir(root), 'stamp.json')) ? 'SATISFIED' : 'NOT SATISFIED',
    runtimeRootDir(root),
  );
  add(
    'workspace',
    'stack',
    'INFO',
    `${det.stack.tags.join(', ') || 'undetected'} (fingerprint ${det.stack.hash})`,
    false,
  );
  add(
    'workspace',
    'registry',
    'INFO',
    `workspace registry lands in phase 2; discovery: this repository plus a bounded one-level sibling listing (${det.siblings.length} sibling repositor${det.siblings.length === 1 ? 'y' : 'ies'} seen, none registered)`,
    false,
  );
  // open item 13 / K14: the prompt hook's caller is verified only heuristically until the phase-6 conformance suite
  add(
    'hooks',
    'prompt hook caller authentication',
    pin.profile === 'STANDARD' ? 'INFO' : 'NOT SATISFIED',
    pin.profile === 'STANDARD'
      ? 'INPUT_CALLER_UNVERIFIED: heuristic (host project-dir marker, pre-denied invocation spellings); STANDARD continues with disclosure'
      : 'CHANNEL_UNVERIFIED: a conformance-verified presentation and input channel is required by this profile (phase 6); until then grants recorded through the prompt hook are disclosed in the receipt',
    pin.profile !== 'STANDARD',
  );
  add(
    'forge',
    'provider',
    'INFO',
    `${det.forge}${det.remotes[0]?.path ? ` (${det.remotes[0].path})` : ''}`,
    false,
  );
  add(
    'forge',
    'access',
    opts.offline ? 'SKIPPED' : 'UNVERIFIED',
    opts.offline ? 'offline' : 'forge adapters land in phase 2',
    false,
  );
  add('forge', 'tracker', 'INFO', pin.taskSource ?? 'ad-hoc', false);

  // secrets, network, containment, gate integrity
  try {
    const cp = loadControlPlane(cpRoot);
    add(
      'secrets',
      'detectors',
      'SATISFIED',
      `${cp.secrets.flatMap((s) => s.detectors).length} detectors, locked minimums enforced, structured curl parsing`,
      false,
    );
    // controls are judged against the active host; without a determined host nothing is claimed SATISFIED and
    // nothing fails: the line says how to determine it (never fake parity, never fake failure)
    const active = opts.host ?? detectHost(opts.env);
    add(
      'controls',
      'active host',
      'INFO',
      active ?? 'undetermined: run doctor from inside the host or pass --host <claude-code|codex-cli>',
      false,
    );
    // A control the profile only RECOMMENDS used to be invisible: nothing read `recommended_in`, so the sandbox — the
    // single most important absent control — never appeared in a HIGH_ASSURANCE report. It is printed now, and it
    // cannot fail the run: only a control the profile REQUIRES counts against the exit code. Lines are grouped by the
    // control's `kind`, so a worktree is reported as isolation and never under the word containment (criterion 6).
    const controls = cp.containment
      .filter((c) => c.requiredIn.includes(pin.profile) || c.recommendedIn.includes(pin.profile))
      .sort((a, b) => CONTROL_KINDS.indexOf(a.kind) - CONTROL_KINDS.indexOf(b.kind));
    for (const c of controls) {
      const isRequired = c.requiredIn.includes(pin.profile);
      const need = isRequired
        ? `required in ${pin.profile}`
        : c.requiredIn.length
          ? `recommended in ${pin.profile}, required in ${c.requiredIn.join(', ')}`
          : `recommended in ${pin.profile}, required by no profile`;
      const hosts: HostId[] = active ? [active] : [...HOST_IDS];
      for (const h of hosts) {
        const status = c.hosts[h] ?? 'UNVERIFIED';
        // SATISFIED means EGO VERIFIED the property, not that a host claims it. A control EGO records but never
        // checks is UNVERIFIED; one EGO only partly provides is reported as not satisfied with the gap named.
        // Reporting SATISFIED on a host's word was how `managed-settings-lock` and `secret-redaction-boundary`
        // came to assert protection that does not exist (challenge 4).
        const state: DoctorState = !active
          ? 'UNVERIFIED'
          : status === 'SUPPORTED'
            ? 'SATISFIED'
            : status === 'UNVERIFIED'
              ? 'UNVERIFIED'
              : 'NOT SATISFIED';
        // The word EGO prints must say where the claim COMES FROM. `SUPPORTED` is a status EGO authored in
        // control-plane/containment/controls.md; nothing here consults a runtime fact, so calling it "verified"
        // told an auditor EGO had checked something it had not (challenge 5, finding 20). "Declared" is the
        // honest word until the phase-6 conformance suite can turn a declaration into a verification.
        const why =
          status === 'UNVERIFIED'
            ? 'EGO records this capability but does not verify it; conformance is phase 6'
            : status === 'PARTIAL'
              ? 'only partly provided — see the control description for what is and is not covered'
              : status === 'UNAVAILABLE'
                ? 'not in force: EGO neither establishes nor detects it on this host today — see the control description'
                : 'declared SUPPORTED in EGO\u2019s own control plane; not verified against the running host (phase 6)';
        add(
          c.kind,
          `${c.id} on ${h}`,
          state,
          `${need}; host status ${status} (${why})`,
          isRequired && active !== null,
        );
      }
    }
    // A setting the control plane accepts, validates and compiles, but that NO consumer reads, is decoration: an
    // operator can tighten it, see it compile, and get nothing. Say so rather than letting the profile document's
    // promise stand (challenge 5, finding 22). The list is DECLARED_ONLY_PROFILE_SETTINGS.
    const profile = cp.profiles.find((p) => p.id === pin.profile);
    const asked = profile
      ? DECLARED_ONLY_PROFILE_SETTINGS.filter((s) => profile[s.field] !== s.baseline)
      : [];
    for (const s of asked.filter((x) => x.requirement))
      add(
        'profile',
        s.key,
        'NOT SATISFIED',
        `${pin.profile} declares ${s.key}: ${String(profile![s.field])}, but no consumer reads it — ${s.missing}`,
        true,
      );
    // The other settings are policies about a situation EGO cannot yet detect (a foreign live session, an unreachable
    // forge, a decision gate). Listing each as a failure would make every STRICT project fail for a feature that has
    // not shipped, so they are named once, and the profile documents say the same thing.
    const policies = asked.filter((x) => !x.requirement);
    if (policies.length)
      add(
        'profile',
        'profile settings declared, not enforced',
        'INFO',
        policies.map((s) => `${s.key}=${String(profile![s.field])} (${s.missing})`).join('; '),
        false,
      );
    const budgets = cp.profiles.find((p) => p.id === pin.profile)?.budgets;
    if (budgets)
      add(
        'budgets',
        'execution budgets',
        'INFO',
        `duration ${budgets.maxDurationMinutes}m, iterations ${budgets.maxIterations}, tool calls ${budgets.maxToolCalls}, retries ${budgets.maxRetriesPerStep}, depth ${budgets.maxDelegationDepth}, subagents ${budgets.maxConcurrentSubagents}, network ${budgets.maxNetworkOperations}, tokens ${budgets.maxTokens ?? 'unobservable'}, cost ${budgets.maxCostUsd ?? 'unobservable'}, on exceed ${budgets.onExceed}`,
        false,
      );
  } catch (e) {
    add('secrets', 'control plane', 'NOT SATISFIED', (e as Error).message.split('\n')[0]!);
  }
  add(
    'network',
    'forge / sync / skills / model-through-runtime',
    'INFO',
    `${opts.offline ? 'offline: forge, sync and skills SKIPPED' : 'online: sync uses cache and file: sources (remote adapters phase 6); forge phase 2; skills phase 3'}; EGO emits no telemetry`,
    false,
  );
  add(
    'human gate',
    'integrity',
    'INFO',
    // This line used to end "managed tier in HIGH_ASSURANCE" while the same HIGH_ASSURANCE run printed that EGO neither
    // installs nor verifies one. In-band prevention is the hooks classifying a call before it runs; out-of-band
    // detection is only the hash comparison of generated files that `ego check` and this command run on demand.
    'prevent-in-band (hooks classify a call before it runs); detect-out-of-band on demand only (`ego check` and `ego doctor` compare the generated files with their manifest); no managed tier is installed or verified by EGO in any profile (issue #26)',
    false,
  );
  add(
    'hosts',
    'EGO_MAINTENANCE',
    'INFO',
    isEgoSourceRepository(root)
      ? 'available (EGO source repository)'
      : 'unavailable outside the EGO source repository',
    false,
  );
  const ok = !lines.some((l) => l.required && l.state === 'NOT SATISFIED');
  return { ok, lines, projectRoot: root };
}

function resolveInside(root: string, dir: string): boolean {
  const r = resolve(root);
  const d = resolve(dir);
  return d === r || d.startsWith(r + sep);
}

export function formatDoctor(r: DoctorReport): string {
  const out: string[] = [];
  let section = '';
  for (const l of r.lines) {
    if (l.section !== section) {
      section = l.section;
      out.push(`[${section}]`);
    }
    out.push(`  ${l.state.padEnd(13)} ${l.item}: ${l.detail}`);
  }
  out.push(r.ok ? 'doctor: OK' : 'doctor: NOT SATISFIED (see lines above)');
  return out.join('\n');
}

export { readJsonIfExists };
