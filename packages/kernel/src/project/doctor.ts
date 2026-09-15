// `harness doctor`: every guarantee reported as SATISFIED / NOT SATISFIED / SKIPPED / UNVERIFIED, never claimed.
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
import { policyCacheFreshness, readPolicyCache } from '../policy/cache.ts';
import { runtimeRootDir } from '../runtime/root.ts';
import { readGeneratedManifest } from './init.ts';
import { gitHookStatus } from './githooks.ts';
import { gitConfigScope } from '../util/git.ts';
import { isFile, readJsonIfExists, readTextIfExists } from '../util/fs.ts';
import { sha256Hex } from '../util/hash.ts';
import { resolveOnPath } from '../util/path-resolve.ts';
import { HOST_MATRIX, HOST_IDS, type HostId } from '../hosts/matrix.ts';
import { loadControlPlane } from '../control-plane/load.ts';
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
}

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
  const launcher = resolveOnPath('harness', opts.env);
  add(
    'runtime',
    'launcher on PATH',
    launcher ? 'SATISFIED' : 'NOT SATISFIED',
    launcher ?? 'harness is not resolvable; hook shims fail closed (K25)',
    false,
  );

  if (!det.gitRoot || !hasPin(det.gitRoot)) {
    add(
      'project',
      'pin',
      'NOT SATISFIED',
      det.gitRoot ? 'not initialized; run `harness init`' : 'not a git repository',
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
      : `pin ${pin.integrity.slice(0, 12)} vs executing ${self.runtimeSha256.slice(0, 12)}; the launcher delegates to the pinned runtime when cached`,
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
        : `trust is ${pinTrust ?? 'none'}; only the pre-promotion set runs until \`harness sync\` promotes it (Q96)`
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
        : 'pinned runtime missing from the cache; run `harness sync`',
  );

  // generated freshness and policy
  const cpRoot = controlPlaneDir();
  const fresh = policyCacheFreshness(cpRoot, root, { runtimeSha256: self.runtimeSha256, version });
  add(
    'policy',
    'compiled policy cache',
    fresh.fresh ? 'SATISFIED' : 'NOT SATISFIED',
    fresh.fresh ? 'fresh' : fresh.reasons.join('; '),
  );
  const cache = readPolicyCache(root);
  if (cache?.pendingWidening)
    add(
      'policy',
      'pending widening',
      'NOT SATISFIED',
      `${cache.pendingWidening.widenings.length} widening(s) in the layer files are not applied until a human runs \`harness init\` from their own terminal: ${cache.pendingWidening.widenings.slice(0, 3).join('; ')}`,
      false,
    );
  if (cache) {
    add(
      'policy',
      'authority table',
      'INFO',
      `hash ${cache.table.tableHash.slice(0, 12)}…, ${cache.table.absoluteDenies.length} absolute, ${cache.table.organizationLocked.length} organization-locked, ${Object.keys(cache.table.capabilities).length} capabilities`,
      false,
    );
    const layered = Object.keys(cache.layerSources);
    add(
      'policy',
      'layers',
      'INFO',
      layered.length ? layered.join(', ') : 'core only (no organization policy, no overlay narrowing)',
      false,
    );
  }
  const manifest = readGeneratedManifest(root);
  if (!manifest) add('generated', 'artifacts', 'NOT SATISFIED', 'no generated manifest; run `harness init`');
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
        : 'missing; run `harness init`',
      h === 'claude-code',
    );
    add(
      'hooks',
      `${h} blocking PreToolUse`,
      blocking === 'SUPPORTED' ? 'SATISFIED' : 'UNVERIFIED',
      m.capabilities['blocking-pre-tool-hook'].note,
      false,
    );
  }
  const shim = join(root, '.harness', 'hooks', 'ego-hook.sh');
  add(
    'hooks',
    'fail-closed shim',
    isFile(shim) ? 'SATISFIED' : 'NOT SATISFIED',
    isFile(shim) ? '.harness/hooks/ego-hook.sh' : 'missing',
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
      ? `core.hooksPath comes from the global git configuration and resolves outside this repository (${hooks.dir}); EGO never writes there. Set a repository-local hooks path and run \`harness init\``
      : hooks.ok
        ? `${hooks.dir.startsWith(root) ? hooks.dir.slice(root.length + 1) : hooks.dir}/pre-commit, pre-push (bypassable with --no-verify: backstop is \`harness verify --range\` on a protected branch, phase 6)`
        : `${hooks.problems.join('; ')} (run \`harness init\`)`,
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
    // required containment controls are judged against the active host; without a determined host nothing is
    // claimed SATISFIED and nothing fails: the line says how to determine it (never fake parity, never fake failure)
    const active = opts.host ?? detectHost(opts.env);
    add(
      'containment',
      'active host',
      'INFO',
      active ?? 'undetermined: run doctor from inside the host or pass --host <claude-code|codex-cli>',
      false,
    );
    const containment = cp.containment.filter((c) => c.requiredIn.includes(pin.profile));
    for (const c of containment) {
      const hosts: HostId[] = active ? [active] : [...HOST_IDS];
      for (const h of hosts) {
        const status = c.hosts[h] ?? 'UNVERIFIED';
        // only SUPPORTED satisfies a required control; PARTIAL and UNVERIFIED never do
        const state: DoctorState = !active
          ? 'UNVERIFIED'
          : status === 'SUPPORTED'
            ? 'SATISFIED'
            : 'NOT SATISFIED';
        add(
          'containment',
          `${c.id} on ${h}`,
          state,
          `required in ${pin.profile}; host status ${status}`,
          active !== null,
        );
      }
    }
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
    'prevent-in-band / detect-out-of-band; managed tier in HIGH_ASSURANCE',
    false,
  );
  add(
    'hosts',
    'HARNESS_MAINTENANCE',
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
