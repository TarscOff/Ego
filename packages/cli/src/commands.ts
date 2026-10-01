// Commands executed by the runtime that governs a project (or by the global runtime outside a project). Every
// command answers with the response contract: what happened, current state, what next, one suggested phrase.
import { join } from 'node:path';
import { parseFlags, flagString, type CliIo } from './io.ts';
import { initProject } from '../../kernel/src/project/init.ts';
import { runDoctor, formatDoctor } from '../../kernel/src/project/doctor.ts';
import { runCheck, formatCheck } from '../../kernel/src/project/check.ts';
import { runGitHook, isAgentShell } from '../../kernel/src/project/githooks.ts';
import { writePin, type Pin } from '../../kernel/src/launcher/pin.ts';
import {
  selfIdentity,
  selfVersion,
  controlPlaneDir,
  isEgoSourceRepository,
  packageRoot,
} from '../../kernel/src/launcher/self.ts';
import { egoHome } from '../../kernel/src/launcher/home.ts';
import { ensurePolicyCache, readPolicyCache } from '../../kernel/src/policy/cache.ts';
import { handleHook } from '../../kernel/src/hooks/handle.ts';
import { isHookEventName } from '../../kernel/src/hooks/events.ts';
import { parseClaudeCodeEvent, renderClaudeCodeOutput } from '../../adapter-claude-code/src/dialect.ts';
import { parseCodexEvent, renderCodexOutput } from '../../adapter-codex-cli/src/dialect.ts';
import { isHostId } from '../../kernel/src/hosts/matrix.ts';
import {
  openRuntimeRoot,
  listSessions,
  readSession,
  writeSession,
  withSessionLock,
} from '../../kernel/src/runtime/root.ts';
import { contextInventory } from '../../kernel/src/context/root-instructions.ts';
import { loadControlPlane } from '../../kernel/src/control-plane/load.ts';
import { redact, allDetectors } from '../../kernel/src/redaction/redact.ts';
import { indexSummary, parseSource } from '../../kernel/src/launcher/sync.ts';
import { isSignedTrust } from '../../kernel/src/launcher/home.ts';
import { isFile, readTextIfExists } from '../../kernel/src/util/fs.ts';
import { detectProject } from '../../kernel/src/project/detect.ts';
import {
  describeCapabilities,
  describeCapability,
  formatCapabilityRow,
} from '../../kernel/src/authority/describe.ts';
import { authorityCommand } from './authority.ts';

/** a deprecation note is one line, said once per process however many times the control plane is loaded */
const noticesSaid = new Set<string>();
export function sayNoticesOnce(io: CliIo, notices: readonly string[] | undefined): void {
  for (const n of notices ?? [])
    if (!noticesSaid.has(n)) {
      noticesSaid.add(n);
      io.err(n);
    }
}

export interface ProjectContext {
  root: string;
  pin: Pin;
  prePromotion: boolean;
}

/** Commands that run before trust promotion under STRICT and HIGH_ASSURANCE (Q96). */
export const PRE_PROMOTION_SET = new Set([
  'version',
  'doctor',
  'bootstrap',
  'sync',
  'sources',
  'distribution',
  'help',
  'status',
  'check',
  'context',
  'capabilities',
  'explain',
  'authority',
  'modes',
  'catalog',
  'init',
  'hook',
  'redact',
  'upgrade',
  'rollback',
]);

export const PHASE_LATER: Record<string, string> = {
  task: 'phase 2 (durable tasks and held scopes)',
  claim: 'phase 2 (held scopes)',
  issue: 'phase 2 (forge issues)',
  workspace: 'phase 2 (workspace registry)',
  handoff: 'phase 2',
  conflict: 'phase 2',
  skills: 'phase 3 (skills and routing)',
  catalog: 'phase 3',
  ask: 'phase 3 (model-assisted help)',
  grill: 'phase 4 (Grilling Room)',
  evidence: 'phase 4',
  benchmark: 'phase 4',
  policy: 'phase 5 (policies and stakeholder packs)',
  decision: 'phase 5 (human decision gate)',
  adapters: 'phase 6 (adapter conformance)',
  conformance: 'phase 6',
  upgrade: 'phase 6 (upgrade protocol)',
  rollback: 'phase 6 (rollback protocol)',
  verify: 'phase 6 (`ego verify --range`)',
};

export async function runCommand(argv: string[], io: CliIo, project: ProjectContext | null): Promise<number> {
  const [cmd = 'help', ...rest] = argv;
  const { positional, flags } = parseFlags(rest);
  if (project && project.prePromotion && !PRE_PROMOTION_SET.has(cmd)) {
    io.err(
      `EGO: profile ${project.pin.profile} permits only the pre-promotion set until the pinned runtime reaches signed-release trust (Q96). Run \`ego sync\`; \`ego doctor\` shows the trust transition.`,
    );
    return 2;
  }
  switch (cmd) {
    case 'help':
      return help(io, project, positional);
    case 'init':
      return init(io, flags);
    case 'doctor': {
      const hostFlag = flagString(flags, 'host');
      if (hostFlag !== undefined && !isHostId(hostFlag)) {
        io.err(`--host must be claude-code or codex-cli`);
        return 2;
      }
      const dopts: Parameters<typeof runDoctor>[0] = {
        cwd: io.cwd,
        env: io.env,
        now: io.now,
        offline: flags['offline'] === true || io.env['EGO_OFFLINE'] === '1',
        authority: flags['capabilities'] === true ? 'all' : 'governed',
      };
      if (hostFlag !== undefined && isHostId(hostFlag)) dopts.host = hostFlag;
      const r = runDoctor(dopts);
      io.out(formatDoctor(r));
      io.out(
        r.ok ? 'next: `ego status`' : 'next: fix the NOT SATISFIED lines, then `ego doctor` again',
      );
      return r.ok ? 0 : 1;
    }
    case 'check': {
      if (!project) return notInitialized(io);
      const r = runCheck(project.root);
      io.out(formatCheck(r));
      return r.ok ? 0 : 1;
    }
    case 'status':
      return status(io, project);
    case 'capabilities':
      return capabilities(io, project, positional, flags);
    case 'explain':
      return explain(io, project, positional, flags);
    case 'authority':
      return authorityCommand(io, project, positional, flags);
    case 'modes':
      return modes(io, project, positional, flags);
    case 'context':
      return context(io, project, positional);
    case 'sources':
      return sources(io, project, positional);
    case 'budget':
      return budget(io, project, positional, flags);
    case 'redact': {
      const cp = loadControlPlane(controlPlaneDir());
      const r = redact(io.stdin, allDetectors(cp.secrets));
      io.out(r.text);
      if (r.findings.length)
        io.err(
          `redacted: ${r.findings.map((f) => `${f.detector}×${f.count}`).join(', ')}${r.blocked ? ' (blocking severity present)' : ''}`,
        );
      return 0;
    }
    case 'hook':
      return hook(io, project, positional);
    default: {
      const later = PHASE_LATER[cmd];
      if (later) {
        io.err(
          `ego ${cmd}: not available yet; it lands in ${later}. This is honest scope, not a fallback.`,
        );
        return 2;
      }
      io.err(`unknown command "${cmd}". Try \`ego help\`.`);
      return 2;
    }
  }
}

function notInitialized(io: CliIo): number {
  io.err('not initialized; run `ego init`');
  return 2;
}

function help(io: CliIo, project: ProjectContext | null, positional: string[]): number {
  const topic = positional[0];
  if (topic === 'installation') {
    const doc = join(packageRoot(), 'docs', 'installation', 'offline.md');
    io.out(
      isFile(doc)
        ? (readTextIfExists(doc) ?? '')
        : 'Installation docs ship with the runtime under docs/installation/ (authored in a later phase). Online: `npm install -g @tarscoff/ego` then `ego init`. Offline: `npm install -g ./ego-X.Y.Z.tgz`, `ego distribution import <bundle>`, `ego init --offline`.',
    );
    return 0;
  }
  const lines: string[] = [];
  if (!project) {
    const det = detectProject(io.cwd);
    lines.push(
      `You are ${det.gitRoot ? `in ${det.gitRoot} (not initialized)` : 'outside a git repository'}.`,
      'What you can do now: `ego init` (in a git checkout), `ego version`, `ego bootstrap doctor`, `ego distribution verify <tarball>`, `ego help installation`.',
      'Next: `ego init`',
      'Say: "Initialize EGO."',
    );
  } else {
    const idx = indexSummary(egoHome(io.env), project.pin.name, project.pin.version);
    lines.push(
      `You are in ${project.root}, governed by EGO ${project.pin.version} (${project.pin.integrity.slice(0, 12)}), profile ${project.pin.profile}, task source ${project.pin.taskSource ?? 'ad-hoc'}, trust ${idx.trust ?? 'none'}.`,
      project.prePromotion
        ? 'Only the pre-promotion set is available until `ego sync` promotes trust.'
        : 'Available now: `status`, `doctor`, `check`, `capabilities`, `explain capability <id>`, `authority diff <old> <new>`, `modes`, `context explain`, `sources`, `budget extend`, `redact`, `sync`, `version`.',
      'Coming in later phases: tasks and issues (2), skills and catalog (3), grilling and benchmark (4), policies and decisions (5), upgrade and conformance (6).',
      'Next: `ego status`',
      'Say: "Is EGO healthy?"',
    );
  }
  io.out(lines.join('\n'));
  return 0;
}

function init(io: CliIo, flags: Record<string, string | boolean>): number {
  const opts: Parameters<typeof initProject>[0] = {
    cwd: io.cwd,
    now: io.now,
    env: io.env,
    offline: flags['offline'] === true || io.env['EGO_OFFLINE'] === '1',
  };
  const profile = flagString(flags, 'profile');
  const taskSource = flagString(flags, 'task-source');
  if (profile) opts.profile = profile;
  if (taskSource) opts.taskSource = taskSource;
  if (flags['repin'] === true) {
    if (isAgentShell(io.env)) {
      io.err('refused: --repin is a human act from your own terminal, never from an agent shell');
      return 2;
    }
    opts.repin = true;
  }
  const r = initProject(opts);
  const lines = [
    `EGO ${r.pinned === 'created' ? 'initialized' : 're-synchronized'} ${r.projectRoot}`,
    `detected: forge ${r.detection.forge}, stack ${r.detection.stack.tags.join(', ') || 'undetected'}, hosts ${Object.entries(
      r.detection.hosts,
    )
      .map(([h, v]) => `${h}${v.hooksPresent ? ' (hooks)' : ''}`)
      .join(', ')}${
      r.detection.siblings.length
        ? `, siblings ${r.detection.siblings
            .slice(0, 8)
            .map((s) => s.name)
            .join(
              ', ',
            )}${r.detection.siblings.length > 8 ? ` (+${r.detection.siblings.length - 8} more)` : ''}`
        : ''
    }`,
    ...r.notes.map((n) => `- ${n}`),
    ...r.moved.map((m) => `- moved ${m.from} -> ${m.to}`),
    `generated: ${r.generated.join(', ')}`,
    '',
    r.doctorText,
    'next: `ego doctor` any time; `ego help` for what you can do here',
    'Say: "What can I do here?"',
  ];
  io.out(lines.join('\n'));
  return r.doctorOk ? 0 : 1;
}

function status(io: CliIo, project: ProjectContext | null): number {
  if (!project) return notInitialized(io);
  const home = egoHome(io.env);
  const idx = indexSummary(home, project.pin.name, project.pin.version);
  const root = openRuntimeRoot(
    project.root,
    { runtimeSha256: selfIdentity().runtimeSha256, version: selfVersion() },
    io.now(),
  );
  const cp = loadControlPlane(controlPlaneDir());
  sayNoticesOnce(io, cp.notices);
  const ttl = cp.coordination.heartbeatTtlSeconds * 1000;
  const now = Date.parse(io.now());
  const sessions = listSessions(root).filter((s) => !s.endedAt && now - Date.parse(s.heartbeatAt) < ttl);
  const lines = [
    `pin: ${project.pin.version} (${project.pin.integrity.slice(0, 12)}) profile ${project.pin.profile} task source ${project.pin.taskSource ?? 'ad-hoc'} trust ${idx.trust ?? 'none'}${project.prePromotion ? ' (pre-promotion: governed mutation refused)' : ''}`,
    `runtime root: ${root.dir} (stamp ${root.stamp.version}, state schema ${root.stamp.runtimeStateSchema})`,
    'task: none open (durable tasks land in phase 2)',
    `live sessions: ${sessions.length}`,
    ...sessions.map(
      (s) =>
        `  ${s.sessionId} on ${s.host} mode ${s.mode} grants [${s.grants.join(', ')}] tool calls ${s.counters.toolCalls} network ${s.counters.networkOperations} subagents ${s.counters.concurrentSubagents}${s.budgetState ? ` BUDGET ${s.budgetState.action}` : ''}${s.activeCorrections.length ? ` corrections ${s.activeCorrections.length}` : ''}`,
    ),
    'decisions waiting: none (decision gate lands in phase 5)',
    'next: `ego help`',
  ];
  io.out(lines.join('\n'));
  return 0;
}

function tableFor(io: CliIo, project: ProjectContext) {
  const self = { runtimeSha256: selfIdentity().runtimeSha256, version: selfVersion() };
  const { cache } = ensurePolicyCache(controlPlaneDir(), project.root, self);
  sayNoticesOnce(io, cache.notices);
  return cache.table;
}

function capabilities(
  io: CliIo,
  project: ProjectContext | null,
  positional: string[],
  flags: Record<string, string | boolean>,
): number {
  if (!project) return notInitialized(io);
  const table = tableFor(io, project);
  const profile = flagString(flags, 'profile') ?? project.pin.profile;
  const mode = flagString(flags, 'mode') ?? table.defaultMode;
  const verdicts = table.profiles[profile]?.modes[mode];
  if (!verdicts) {
    io.err(`unknown profile/mode ${profile}/${mode}`);
    return 2;
  }
  const family = positional[0];
  const rows = describeCapabilities(table, profile, mode).filter(
    (v) => !family || v.family === family || v.id.startsWith(family + '.'),
  );
  io.out(`profile ${profile}, mode ${mode} (${rows.length} capabilities)`);
  for (const v of rows) {
    io.out(formatCapabilityRow(v));
    if (v.targetRule) io.out(`  target: ${v.targetRule}`);
  }
  io.out('next: `ego explain capability <id>`');
  return 0;
}

function explain(
  io: CliIo,
  project: ProjectContext | null,
  positional: string[],
  flags: Record<string, string | boolean>,
): number {
  if (!project) return notInitialized(io);
  const [what, id] = positional;
  if (what !== 'capability' || !id) {
    io.err('usage: ego explain capability <id>');
    return 2;
  }
  const table = tableFor(io, project);
  const c = table.capabilities[id];
  if (!c) {
    io.err(`unknown capability "${id}"; see \`ego capabilities\``);
    return 2;
  }
  const profile = flagString(flags, 'profile') ?? project.pin.profile;
  const mode = flagString(flags, 'mode') ?? table.defaultMode;
  const v = describeCapability(table, profile, mode, id)!;
  const lines = [
    `${id}: ${c.description}`,
    `effect class ${v.effectClass}; lock tier ${v.lockTier}; family ${c.family}; core verdict ${c.core}; effective ${v.verdict} (profile ${profile}, mode ${mode}); ceiling ${v.ceiling}; source ${v.source}`,
    `provenance: ${(table.provenance[id] ?? []).map((p) => `${p.layer} (${p.file}) -> ${p.verdict}`).join('; ')}`,
    ...(v.targetRule ? [`target rule: ${v.targetRule}`] : []),
    ...Object.keys(table.profiles)
      .sort()
      .map(
        (p) =>
          `  ${p}: ${Object.entries(table.profiles[p]!.modes)
            .map(([m, vv]) => `${m}=${vv[id]}`)
            .join(', ')}`,
      ),
  ];
  const matchers = table.matchers.filter((m) => m.capability === id);
  if (matchers.length)
    lines.push(
      `matchers: ${matchers.map((m) => `${m.tool} ${m.command ? `/${m.command}/` : (m.path ?? m.url)}`).join(' | ')}`,
    );
  const grants = table.grants.filter((g) => g.capability === id);
  if (grants.length)
    lines.push(
      `human grant phrases: ${grants
        .flatMap((g) => g.phrases)
        .slice(0, 6)
        .join(' / ')}${
        c.effect === 'local'
          ? ''
          : ' (recognised, but they lift nothing: this effect leaves the machine, so every occurrence asks)'
      }`,
    );
  if (c.lock === 'absolute')
    lines.push(
      'This is a HARD_LOCK capability (an absolute core deny): no organization policy, profile, overlay, grant, mode, skill, issue, task approval or model can widen it.',
    );
  else if (c.lock === 'admin-governed')
    lines.push(
      'This is an ADMIN_GOVERNED capability: only the organization policy layer (policies/organization/permissions.md, read from this checkout; a human accepts any widening with `ego init`) can enable it; overlays, grants, modes, skills and models never can. Enabled, it still asks a human for every use: the ceiling is ASK (TASK_APPROVAL, one bounded approval, never a durable grant).',
    );
  lines.push(`next: \`ego capabilities ${c.family}\` for profile ${profile}`);
  io.out(lines.join('\n'));
  return 0;
}

function modes(
  io: CliIo,
  project: ProjectContext | null,
  positional: string[],
  flags: Record<string, string | boolean>,
): number {
  if (!project) return notInitialized(io);
  const cp = loadControlPlane(controlPlaneDir());
  sayNoticesOnce(io, cp.notices);
  const inEgo = isEgoSourceRepository(project.root);
  if (positional[0] === 'set') {
    const mode = positional[1];
    const sessionId = flagString(flags, 'session');
    if (!mode || !sessionId) {
      io.err('usage: ego modes set <MODE> --session <id> (a human act from your own terminal)');
      return 2;
    }
    if (isAgentShell(io.env)) {
      io.err(
        'refused: authority modes are set by a human from their own terminal, never from an agent shell',
      );
      return 2;
    }
    const m = cp.modes.find((x) => x.id === mode);
    if (!m) {
      io.err(`unknown mode ${mode}`);
      return 2;
    }
    if (m.onlyInEgoRepository && !inEgo) {
      io.err(`${mode} is available only in the EGO source repository`);
      return 2;
    }
    const root = openRuntimeRoot(
      project.root,
      { runtimeSha256: selfIdentity().runtimeSha256, version: selfVersion() },
      io.now(),
    );
    return withSessionLock(root, sessionId, () => {
      const s = readSession(root, sessionId);
      if (!s) {
        io.err(`no session ${sessionId}`);
        return 2;
      }
      s.mode = mode;
      writeSession(root, s);
      io.out(`session ${sessionId}: mode ${mode}`);
      return 0;
    });
  }
  for (const m of cp.modes)
    io.out(
      `${m.id}${m.isDefault ? ' (default)' : ''}${m.onlyInEgoRepository ? (inEgo ? ' (available here)' : ' (EGO source repository only)') : ''}: ${m.title}; overrides ${m.overrides.length ? m.overrides.map((o) => `${o.capability}=${o.verdict}`).join(', ') : 'none'}`,
    );
  io.out(
    'Intents (audit, documentation, grilling-room, ego-upgrade, policy-review, workspace-discovery) route work and never change authority.',
  );
  io.out(
    'next: put `EGO MODE: <MODE>` on its own line in a prompt (EGO_MAINTENANCE only in the EGO repository), or `ego modes set <MODE> --session <id>`',
  );
  return 0;
}

function context(io: CliIo, project: ProjectContext | null, positional: string[]): number {
  if (!project) return notInitialized(io);
  if (positional[0] !== 'explain') {
    io.err('usage: ego context explain');
    return 2;
  }
  const inv = contextInventory(project.root, project.pin, tableFor(io, project));
  io.out(`budget ${inv.budget} tokens (profile ${project.pin.profile}); loaded ~${inv.loadedTokens}`);
  for (const i of inv.items)
    io.out(
      `${i.loaded ? 'LOADED    ' : 'NOT LOADED'} ~${String(i.tokens).padStart(5)} ${i.item}: ${i.reason}`,
    );
  io.out(
    'next: edit .harness/overlay/standing-rules.md to change what is always loaded, then `ego init`',
  );
  return 0;
}

function sources(io: CliIo, project: ProjectContext | null, positional: string[]): number {
  if (!project) return notInitialized(io);
  const [sub, value] = positional;
  if (!sub || sub === 'list') {
    for (const s of project.pin.sources) io.out(s);
    io.out(
      'order governs acquisition; any release-metadata source may promote trust. next: `ego sources add file:/path/to/releases`',
    );
    return 0;
  }
  if (isAgentShell(io.env)) {
    io.err('refused: sources are changed by a human from their own terminal');
    return 2;
  }
  if (!value) {
    io.err('usage: ego sources add|remove <source>');
    return 2;
  }
  parseSource(value);
  const base: Omit<Pin, 'stamp'> = { ...project.pin };
  delete (base as Partial<Pin>).stamp;
  if (sub === 'add')
    base.sources = project.pin.sources.includes(value)
      ? project.pin.sources
      : [...project.pin.sources, value];
  else if (sub === 'remove') base.sources = project.pin.sources.filter((s) => s !== value);
  else {
    io.err('usage: ego sources add|remove <source>');
    return 2;
  }
  writePin(project.root, base);
  io.out(`sources: ${base.sources.join(', ')}`);
  return 0;
}

function budget(
  io: CliIo,
  project: ProjectContext | null,
  positional: string[],
  flags: Record<string, string | boolean>,
): number {
  if (!project) return notInitialized(io);
  if (positional[0] !== 'extend') {
    io.err(
      'usage: ego budget extend --session <id> [--tool-calls N] [--iterations N] [--duration-minutes N] [--network-operations N] [--retries N] [--subagents N] [--delegation-depth N]',
    );
    return 2;
  }
  if (isAgentShell(io.env)) {
    io.err(
      'refused: ego.budget.extend is a human act from your own terminal (ASK), never from an agent shell',
    );
    return 2;
  }
  const sessionId = flagString(flags, 'session');
  if (!sessionId) {
    io.err('--session <id> is required (see `ego status`)');
    return 2;
  }
  const root = openRuntimeRoot(
    project.root,
    { runtimeSha256: selfIdentity().runtimeSha256, version: selfVersion() },
    io.now(),
  );
  return withSessionLock(root, sessionId, () => {
    const s = readSession(root, sessionId);
    if (!s) {
      io.err(`no session ${sessionId}`);
      return 2;
    }
    const map: Record<string, string> = {
      'tool-calls': 'maxToolCalls',
      iterations: 'maxIterations',
      'duration-minutes': 'maxDurationMinutes',
      'network-operations': 'maxNetworkOperations',
      retries: 'maxRetriesPerStep',
      subagents: 'maxConcurrentSubagents',
      'delegation-depth': 'maxDelegationDepth',
    };
    let changed = 0;
    for (const [flag, key] of Object.entries(map)) {
      const v = flagString(flags, flag);
      if (v === undefined) continue;
      const n = Number(v);
      if (!Number.isInteger(n) || n <= 0) {
        io.err(`--${flag} must be a positive integer`);
        return 2;
      }
      s.budgetExtensions[key] = n;
      changed++;
    }
    if (!changed) {
      io.err('nothing to extend');
      return 2;
    }
    delete s.budgetState;
    writeSession(root, s);
    io.out(
      `session ${sessionId}: budget extended (${Object.entries(s.budgetExtensions)
        .map(([k, v]) => `${k}=${v}`)
        .join(', ')}); the breach state is cleared for this session only`,
    );
    return 0;
  });
}

function hook(io: CliIo, project: ProjectContext | null, positional: string[]): number {
  const [host, event] = positional;
  if (host === 'git') {
    if (!project) return notInitialized(io);
    const r = runGitHook(event ?? '', project.root, io.env, io.stdin);
    for (const m of r.messages) io.err(`EGO ${event}: ${m}`);
    return r.ok ? 0 : 1;
  }
  if (!host || !event || !isHostId(host) || !isHookEventName(event)) {
    io.err(
      'usage: ego hook <claude-code|codex-cli> <HookEvent> (payload on stdin) | ego hook git <pre-commit|pre-push>',
    );
    return 2;
  }
  if (!project) {
    io.err('EGO hook: not inside an initialized project; failing closed');
    return 2;
  }
  let payload: Record<string, unknown> = {};
  if (io.stdin.trim()) {
    try {
      payload = JSON.parse(io.stdin) as Record<string, unknown>;
    } catch {
      io.err('EGO hook: unparsable payload; failing closed');
      return 2;
    }
  }
  const rt = {
    projectRoot: project.root,
    pin: project.pin,
    now: io.now,
    prePromotion: project.prePromotion,
    env: io.env,
  };
  if (host === 'claude-code') {
    const ev = parseClaudeCodeEvent(event, payload, io.env, io.cwd);
    const r = renderClaudeCodeOutput(handleHook(ev, rt));
    io.out(r.stdout);
    return r.exitCode;
  }
  const ev = parseCodexEvent(event, payload, io.cwd);
  const r = renderCodexOutput(handleHook(ev, rt));
  io.out(r.stdout);
  return r.exitCode;
}

export function projectPrePromotion(pin: Pin, env: NodeJS.ProcessEnv): boolean {
  if (pin.profile === 'STANDARD') return false;
  const idx = indexSummary(egoHome(env), pin.name, pin.version);
  return !isSignedTrust(idx.trust);
}

export { readPolicyCache };
