import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { handleHook, type HookRuntime } from '../src/hooks/handle.ts';
import type { HookEvent } from '../src/hooks/events.ts';
import { writePin, readPin } from '../src/launcher/pin.ts';
import { selfIdentity, selfVersion } from '../src/launcher/self.ts';
import {
  parseClaudeCodeEvent,
  renderClaudeCodeOutput,
  mergeClaudeSettings,
} from '../../adapter-claude-code/src/dialect.ts';
import {
  parseCodexEvent,
  renderCodexOutput,
  normalizeCodexTool,
  writeCodexHooks,
  CODEX_HOOK_EVENTS,
} from '../../adapter-codex-cli/src/dialect.ts';
import { readSession, writeSession, openRuntimeRoot, readLedger } from '../src/runtime/root.ts';
import { recognizeGrants, recognizeCorrection, recognizeModeMarker } from '../src/session/grants.ts';
import { loadControlPlane } from '../src/control-plane/load.ts';
import { compileAuthority } from '../src/authority/compile.ts';

const CP = new URL('../../../control-plane/', import.meta.url).pathname;

function project(profile = 'STANDARD'): { root: string; rt: HookRuntime } {
  const root = mkdtempSync(join(tmpdir(), 'ego-hooks-'));
  spawnSync('git', ['init', '-q'], { cwd: root });
  writeFileSync(
    join(root, 'package.json'),
    JSON.stringify({ name: 'demo', scripts: { deploy: 'git push', ship: 'gh pr create' } }),
  );
  const self = selfIdentity();
  writePin(root, {
    name: self.name,
    version: selfVersion(),
    integrity: self.runtimeSha256,
    sources: [],
    schemas: {},
    node: '>=24',
    profile,
    taskSource: 'ad-hoc',
  });
  let t = 0;
  const rt: HookRuntime = {
    projectRoot: root,
    pin: readPin(root),
    now: () => new Date(Date.UTC(2026, 8, 14, 10, 0, t++)).toISOString(),
    controlPlaneRoot: CP,
    env: { EGO_HOME: mkdtempSync(join(tmpdir(), 'ego-h-')), CLAUDE_PROJECT_DIR: root },
  };
  return { root, rt };
}

function ev(root: string, event: HookEvent['event'], extra: Partial<HookEvent> = {}): HookEvent {
  return { host: 'claude-code', event, sessionId: 's1', cwd: root, raw: {}, ...extra };
}

test('PreToolUse: deny, ask, allow; effect-based denial; ledger and session counters', () => {
  const { root, rt } = project();
  assert.equal(
    handleHook(ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'git push' } } }), rt).action,
    'deny',
  );
  assert.equal(
    handleHook(ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'npm run ship' } } }), rt)
      .action,
    'deny',
  );
  assert.equal(
    handleHook(
      ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'curl https://example.com' } } }),
      rt,
    ).action,
    'ask',
  );
  assert.equal(
    handleHook(ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'ls' } } }), rt).action,
    'allow',
  );
  assert.equal(
    handleHook(
      ev(root, 'PreToolUse', { tool: { name: 'Write', input: { file_path: join(root, 'src', 'x.ts') } } }),
      rt,
    ).action,
    'allow',
  );
  assert.equal(
    handleHook(
      ev(root, 'PreToolUse', {
        tool: { name: 'Write', input: { file_path: join(root, '.claude', 'settings.json') } },
      }),
      rt,
    ).action,
    'deny',
  );
  const rr = openRuntimeRoot(root, { runtimeSha256: rt.pin.integrity, version: rt.pin.version }, rt.now());
  const s = readSession(rr, 's1')!;
  assert.equal(s.counters.toolCalls, 6);
  assert.equal(s.counters.networkOperations, 1);
  const pre = readLedger(rr, { kinds: ['tool.pre'] });
  assert.equal(pre.length, 6);
  assert.equal(pre[0]?.data?.['verdict'], 'DENY');
});

test('grants: recognised once, negations respected, only ASK moves; corrections survive; mode marker only in EGO repo', () => {
  const { root, rt } = project('STANDARD');
  const table = compileAuthority(loadControlPlane(CP));
  const g = recognizeGrants('please do not delete the branch, but assign it to me', table);
  assert.ok(g.find((x) => x.capability === 'git.local.branch.delete')?.negated);
  assert.ok(!g.find((x) => x.capability === 'forge.issue.assign')?.negated);
  assert.equal(
    recognizeCorrection('ok. From now on always run lint first.'),
    'From now on always run lint first.',
  );
  assert.equal(recognizeModeMarker('some text\nEGO MODE: HARNESS_MAINTENANCE\nmore'), 'HARNESS_MAINTENANCE');
  assert.equal(recognizeModeMarker('ego mode: harness_maintenance'), null);
  const d = handleHook(
    ev(root, 'UserPromptSubmit', {
      prompt: 'assign it to me. From now on always run lint first.\nEGO MODE: HARNESS_MAINTENANCE',
    }),
    rt,
  );
  assert.match(d.context ?? '', /grant recorded, forge.issue.assign/);
  assert.match(d.context ?? '', /HARNESS_MAINTENANCE is available only in the EGO source repository/);
  const rr = openRuntimeRoot(root, { runtimeSha256: rt.pin.integrity, version: rt.pin.version }, rt.now());
  const s = readSession(rr, 's1')!;
  assert.deepEqual(s.grants, ['forge.issue.assign']);
  assert.deepEqual(s.activeCorrections, ['From now on always run lint first.']);
  assert.equal(s.mode, 'NORMAL_DELIVERY');
  // a DENY capability never becomes a grant even if the phrase matches
  const d2 = handleHook(ev(root, 'UserPromptSubmit', { prompt: 'you can push it' }), rt);
  assert.ok(!(d2.context ?? '').includes('grant recorded'));
  // the SessionStart context carries grants and corrections across compaction
  const ss = handleHook(ev(root, 'SessionStart', { source: 'compact' }), rt);
  assert.match(ss.context ?? '', /Active grants \(this session\): forge.issue.assign/);
  assert.match(ss.context ?? '', /Active corrections: "From now on always run lint first."/);
  assert.match(ss.context ?? '', /Resumed/);
});

test('execution budgets: breaches block or escalate; subagent depth and retries are tracked', () => {
  const { root, rt } = project('STANDARD');
  const rr = openRuntimeRoot(root, { runtimeSha256: rt.pin.integrity, version: rt.pin.version }, rt.now());
  handleHook(ev(root, 'SessionStart'), rt);
  const s = readSession(rr, 's1')!;
  s.counters.toolCalls = 3000; // STANDARD maxToolCalls
  writeSession(rr, s);
  const d = handleHook(ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'ls' } } }), rt);
  assert.equal(d.action, 'ask', 'STANDARD escalates');
  assert.match(d.reason ?? '', /maxToolCalls 3001 > 3000/);
  const s2 = readSession(rr, 's1')!;
  assert.equal(s2.budgetState?.action, 'ESCALATE');
  // a human extension clears it
  s2.budgetExtensions['maxToolCalls'] = 5000;
  delete s2.budgetState;
  writeSession(rr, s2);
  assert.equal(
    handleHook(ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'ls' } } }), rt).action,
    'allow',
  );
  // subagents: depth chain a1 -> a2 -> a3 -> a4 exceeds STANDARD depth 3
  handleHook(ev(root, 'SubagentStart', { agentId: 'a1' }), rt);
  handleHook(ev(root, 'SubagentStart', { agentId: 'a2', parentAgentId: 'a1' }), rt);
  handleHook(ev(root, 'SubagentStart', { agentId: 'a3', parentAgentId: 'a2' }), rt);
  const deep = handleHook(ev(root, 'SubagentStart', { agentId: 'a4', parentAgentId: 'a3' }), rt);
  assert.match(deep.context ?? '', /maxDelegationDepth 4 > 3/);
  handleHook(ev(root, 'SubagentStop', { agentId: 'a4' }), rt);
  assert.equal(readSession(rr, 's1')!.counters.concurrentSubagents, 3);
  // retries: the fourth failure of one step tells the model to stop
  for (let i = 0; i < 3; i++)
    handleHook(
      ev(root, 'PostToolUse', {
        tool: { name: 'Bash', input: { command: 'npm test' }, response: { exit_code: 1 } },
      }),
      rt,
    );
  const post = handleHook(
    ev(root, 'PostToolUse', {
      tool: { name: 'Bash', input: { command: 'npm test' }, response: { exit_code: 1 } },
    }),
    rt,
  );
  assert.match(post.context ?? '', /failed 4 times/);
});

test('STRICT before trust promotion permits reads and refuses governed mutation (Q96)', () => {
  const { root, rt } = project('STANDARD');
  const strict: HookRuntime = { ...rt, pin: { ...rt.pin, profile: 'STRICT' }, prePromotion: true };
  assert.equal(
    handleHook(ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'git status' } } }), strict)
      .action,
    'allow',
  );
  assert.equal(
    handleHook(
      ev(root, 'PreToolUse', { tool: { name: 'Read', input: { file_path: join(root, 'package.json') } } }),
      strict,
    ).action,
    'allow',
  );
  const d = handleHook(
    ev(root, 'PreToolUse', { tool: { name: 'Write', input: { file_path: join(root, 'x.ts') } } }),
    strict,
  );
  assert.equal(d.action, 'deny');
  assert.match(d.reason ?? '', /signed-release trust/);
  assert.equal(
    handleHook(
      ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'git commit -m x' } } }),
      strict,
    ).action,
    'deny',
  );
});

test('claude-code dialect: payload parsing, output shapes, settings merge keeps foreign hooks and puts EGO first', () => {
  const p = parseClaudeCodeEvent(
    'PreToolUse',
    {
      session_id: 'abc',
      cwd: '/x',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'ls' },
      agent_id: 'ag1',
      permission_mode: 'bypassPermissions',
    },
    { CLAUDE_PID: '4242' },
    '/fallback',
  );
  assert.equal(p.sessionId, 'abc');
  assert.equal(p.tool?.name, 'Bash');
  assert.equal(p.hostPid, 4242);
  assert.equal(p.agentId, 'ag1');
  const deny = renderClaudeCodeOutput({
    event: 'PreToolUse',
    action: 'deny',
    reason: 'no',
    userMessage: 'msg',
    exitCode: 0,
  });
  assert.deepEqual(JSON.parse(deny.stdout), {
    systemMessage: 'msg',
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: 'no',
    },
  });
  const stop = renderClaudeCodeOutput({ event: 'Stop', action: 'block', reason: 'gate', exitCode: 0 });
  assert.deepEqual(JSON.parse(stop.stdout), { decision: 'block', reason: 'gate' });
  const ss = renderClaudeCodeOutput({
    event: 'SessionStart',
    action: 'continue',
    context: 'ctx',
    exitCode: 0,
  });
  assert.equal(JSON.parse(ss.stdout).hookSpecificOutput.additionalContext, 'ctx');
  assert.throws(() => parseClaudeCodeEvent('Bogus', {}, {}, '/'), /unknown hook event/);
  const merged = mergeClaudeSettings({
    permissions: { allow: ['Bash(ls:*)'] },
    hooks: {
      PreToolUse: [
        { matcher: 'Bash', hooks: [{ type: 'command', command: 'foreign-hook' }] },
        { hooks: [{ type: 'command', command: 'sh ego-hook.sh old' }] },
      ],
    },
  });
  const pre = (merged['hooks'] as Record<string, Array<{ hooks: Array<{ command: string }> }>>)[
    'PreToolUse'
  ]!;
  assert.equal(pre.length, 2);
  assert.match(pre[0]!.hooks[0]!.command, /ego-hook\.sh/);
  assert.equal(pre[1]!.hooks[0]!.command, 'foreign-hook');
  assert.deepEqual(merged['permissions'], { allow: ['Bash(ls:*)'] });
});

test('codex-cli dialect: neutral parsing, tool normalization, deny exits 2', () => {
  const p = parseCodexEvent('PreToolUse', { thread_id: 't1', tool: 'shell', arguments: 'git push' }, '/cwd');
  assert.equal(p.sessionId, 't1');
  assert.equal(p.tool?.name, 'Bash');
  assert.equal(p.tool?.input['command'], 'git push');
  assert.equal(normalizeCodexTool('apply_patch'), 'apply_patch');
  const r = renderCodexOutput({ event: 'PreToolUse', action: 'deny', reason: 'no', exitCode: 0 });
  assert.equal(r.exitCode, 2);
  assert.equal(JSON.parse(r.stdout).decision, 'deny');
  assert.equal(renderCodexOutput({ event: 'PreToolUse', action: 'allow', exitCode: 0 }).exitCode, 0);
});

export { mkdirSync };

function egoLikeProject(): { root: string; rt: HookRuntime } {
  // a fake EGO source repository: package name, control-plane marker and kernel package (isEgoSourceRepository)
  const root = mkdtempSync(join(tmpdir(), 'ego-fake-src-'));
  spawnSync('git', ['init', '-q'], { cwd: root });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: '@tarscoff/ego', version: '0.0.1' }));
  mkdirSync(join(root, 'control-plane', 'permissions'), { recursive: true });
  writeFileSync(join(root, 'control-plane', 'permissions', 'absolute-denies.md'), '# x\n');
  mkdirSync(join(root, 'packages', 'kernel'), { recursive: true });
  writeFileSync(join(root, 'packages', 'kernel', 'package.json'), '{}');
  const self = selfIdentity();
  writePin(root, {
    name: self.name,
    version: selfVersion(),
    integrity: self.runtimeSha256,
    sources: [],
    schemas: {},
    node: '>=24',
    profile: 'STANDARD',
    taskSource: 'ad-hoc',
  });
  let t = 0;
  return {
    root,
    rt: {
      projectRoot: root,
      pin: readPin(root),
      now: () => new Date(Date.UTC(2026, 8, 14, 11, 0, t++)).toISOString(),
      controlPlaneRoot: CP,
      env: { EGO_HOME: mkdtempSync(join(tmpdir(), 'ego-h-')), CLAUDE_PROJECT_DIR: root },
    },
  };
}

test('mode marker: HARNESS_MAINTENANCE only inside the EGO repository, PRODUCTION_ADVISORY anywhere, BENCHMARK never by prompt', () => {
  const { root, rt } = egoLikeProject();
  const d = handleHook(ev(root, 'UserPromptSubmit', { prompt: 'EGO MODE: HARNESS_MAINTENANCE' }), rt);
  assert.match(d.context ?? '', /authority mode is now HARNESS_MAINTENANCE/);
  const rr = openRuntimeRoot(root, { runtimeSha256: rt.pin.integrity, version: rt.pin.version }, rt.now());
  assert.equal(readSession(rr, 's1')!.mode, 'HARNESS_MAINTENANCE');
  assert.ok(readLedger(rr, { kinds: ['mode.set'] }).some((e) => e.data?.['mode'] === 'HARNESS_MAINTENANCE'));
  // control-plane edits become ALLOW under maintenance; absolute denies stay DENY
  assert.equal(
    handleHook(
      ev(root, 'PreToolUse', {
        tool: {
          name: 'Write',
          input: { file_path: join(root, 'control-plane', 'permissions', 'capabilities', 'x.md') },
        },
      }),
      rt,
    ).action,
    'allow',
  );
  assert.equal(
    handleHook(ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'git push' } } }), rt).action,
    'deny',
  );
  assert.match(
    handleHook(ev(root, 'UserPromptSubmit', { prompt: 'EGO MODE: PRODUCTION_ADVISORY' }), rt).context ?? '',
    /now PRODUCTION_ADVISORY/,
  );
  assert.equal(
    handleHook(
      ev(root, 'PreToolUse', { tool: { name: 'Write', input: { file_path: join(root, 'src', 'a.ts') } } }),
      rt,
    ).action,
    'deny',
  );
  assert.match(
    handleHook(ev(root, 'UserPromptSubmit', { prompt: 'EGO MODE: BENCHMARK' }), rt).context ?? '',
    /BENCHMARK mode is entered by/,
  );
  assert.equal(readSession(rr, 's1')!.mode, 'PRODUCTION_ADVISORY');
});

test('runtime state never holds a secret: corrections and ledger summaries are redacted; env is injected, not ambient', () => {
  const { root, rt } = project('STANDARD');
  const home = mkdtempSync(join(tmpdir(), 'ego-h-'));
  const rtEnv: HookRuntime = { ...rt, env: { EGO_HOME: home } };
  handleHook(
    ev(root, 'UserPromptSubmit', {
      prompt: 'From now on always use token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef012345 for the API.',
    }),
    rtEnv,
  );
  const rr = openRuntimeRoot(root, { runtimeSha256: rt.pin.integrity, version: rt.pin.version }, rt.now());
  const s = readSession(rr, 's1')!;
  assert.equal(s.activeCorrections.length, 1);
  assert.ok(!s.activeCorrections[0]!.includes('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef012345'));
  assert.match(s.activeCorrections[0]!, /REDACTED/);
  handleHook(
    ev(root, 'PreToolUse', {
      tool: {
        name: 'Bash',
        input: {
          command:
            'curl -H "Authorization: Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef012345" https://api.example.com',
        },
      },
    }),
    rtEnv,
  );
  const raw = readLedger(rr)
    .map((e) => JSON.stringify(e))
    .join('\n');
  assert.ok(!raw.includes('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef012345'), 'ledger holds no raw token');
  const ss = handleHook(ev(root, 'SessionStart', { source: 'compact' }), rtEnv);
  assert.ok(!(ss.context ?? '').includes('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef012345'));
});

test('retry hard stop: the same failing step cannot run past the profile retries; BLOCK profiles deny, ESCALATE profiles ask', () => {
  const { root, rt } = project('STANDARD');
  const strict: HookRuntime = {
    ...rt,
    pin: { ...rt.pin, profile: 'STRICT' },
    env: { EGO_HOME: mkdtempSync(join(tmpdir(), 'ego-h-')), CLAUDE_PROJECT_DIR: root },
  };
  const fail = () =>
    handleHook(
      ev(root, 'PostToolUse', {
        tool: { name: 'Bash', input: { command: 'npm test' }, response: { exit_code: 1 } },
      }),
      strict,
    );
  const attempt = () =>
    handleHook(ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'npm test' } } }), strict);
  for (let i = 0; i < 4; i++) {
    assert.equal(attempt().action, 'allow', `attempt ${i + 1} (1 first + 3 retries) allowed`);
    fail();
  }
  const fifth = attempt();
  assert.equal(fifth.action, 'deny', 'STRICT blocks the fifth identical attempt');
  assert.match(fifth.reason ?? '', /already failed 4 times/);
  assert.equal(
    handleHook(ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'npm run lint' } } }), strict)
      .action,
    'allow',
    'a different step still runs',
  );
  // STANDARD escalates instead
  const standard: HookRuntime = { ...rt, env: strict.env! };
  const rr = openRuntimeRoot(root, { runtimeSha256: rt.pin.integrity, version: rt.pin.version }, rt.now());
  const s = readSession(rr, 's1')!;
  s.profile = 'STANDARD';
  writeSession(rr, s);
  assert.equal(
    handleHook(ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'npm test' } } }), standard)
      .action,
    'ask',
  );
});

test('a grant phrase for a capability narrowed to DENY never grants; HIGH_ASSURANCE budgets block at their smaller limits', () => {
  const { root, rt } = project('STANDARD');
  writeFileSync(
    join(root, '.harness', 'permissions.md'),
    '---\nschema: ego.capabilities/1\nid: overlay\nfamily: overlay\n---\n# o\n\n## Denied\n\n- [x] `forge.issue.assign` — never\n',
  );
  mkdirSync(join(root, '.harness'), { recursive: true });
  const ha: HookRuntime = {
    ...rt,
    pin: { ...rt.pin, profile: 'HIGH_ASSURANCE' },
    env: { EGO_HOME: mkdtempSync(join(tmpdir(), 'ego-h-')), CLAUDE_PROJECT_DIR: root },
  };
  const d = handleHook(ev(root, 'UserPromptSubmit', { prompt: 'assign it to me' }), ha);
  assert.match(d.context ?? '', /forge.issue.assign is DENY here; a grant changes nothing/);
  const rr = openRuntimeRoot(root, { runtimeSha256: rt.pin.integrity, version: rt.pin.version }, rt.now());
  assert.deepEqual(readSession(rr, 's1')!.grants, []);
  const s = readSession(rr, 's1')!;
  s.counters.toolCalls = 1000; // HIGH_ASSURANCE maxToolCalls
  writeSession(rr, s);
  const blocked = handleHook(
    ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'ls' } } }),
    ha,
  );
  assert.equal(blocked.action, 'deny');
  assert.match(blocked.reason ?? '', /maxToolCalls 1001 > 1000/);
  // Stop under a breach carries the fact to the user
  const stop = handleHook(ev(root, 'Stop'), ha);
  assert.match(stop.userMessage ?? '', /ended under a budget breach/);
  // SubagentStop persists the decremented count
  handleHook(ev(root, 'SubagentStart', { agentId: 'x1' }), ha);
  handleHook(ev(root, 'SubagentStop', { agentId: 'x1' }), ha);
  assert.equal(readSession(rr, 's1')!.counters.concurrentSubagents, 0);
});

test('in-process hook latency stays under the 60 ms kernel budget (K26)', () => {
  const { root, rt } = project('STANDARD');
  const rtEnv: HookRuntime = {
    ...rt,
    env: { EGO_HOME: mkdtempSync(join(tmpdir(), 'ego-h-')), CLAUDE_PROJECT_DIR: root },
  };
  handleHook(ev(root, 'SessionStart'), rtEnv); // warm caches, create the session
  const samples: number[] = [];
  for (let i = 0; i < 15; i++) {
    const t0 = performance.now();
    handleHook(
      ev(root, 'PreToolUse', { tool: { name: 'Bash', input: { command: 'npm run build && ls -la src' } } }),
      rtEnv,
    );
    samples.push(performance.now() - t0);
  }
  samples.sort((a, b) => a - b);
  const median = samples[Math.floor(samples.length / 2)]!;
  assert.ok(
    median < 60,
    `median PreToolUse handling ${median.toFixed(1)} ms exceeds the 60 ms kernel budget`,
  );
});

test('caller heuristic (K14): a grant or mode marker without the host project-dir marker records nothing', () => {
  const { root, rt } = project('STANDARD');
  const unmarked: HookRuntime = { ...rt, env: { EGO_HOME: rt.env!['EGO_HOME']! } };
  const d = handleHook(
    ev(root, 'UserPromptSubmit', { prompt: 'assign it to me\nEGO MODE: PRODUCTION_ADVISORY' }),
    unmarked,
  );
  assert.match(d.context ?? '', /INPUT_CALLER_UNVERIFIED/);
  const rr = openRuntimeRoot(root, { runtimeSha256: rt.pin.integrity, version: rt.pin.version }, rt.now());
  const s = readSession(rr, 's1')!;
  assert.deepEqual(s.grants, []);
  assert.equal(s.mode, 'NORMAL_DELIVERY');
  assert.ok(readLedger(rr, { kinds: ['prompt.caller-unverified'] }).length === 1);
  // a plain prompt without authority-bearing content is unaffected
  assert.equal(
    handleHook(ev(root, 'UserPromptSubmit', { prompt: 'please run the tests' }), unmarked).context,
    undefined,
  );
  // a tool-less PreToolUse payload fails closed
  const bad = handleHook(ev(root, 'PreToolUse'), rt);
  assert.equal(bad.action, 'deny');
  assert.equal(bad.exitCode, 2);
});

test('codex-cli renderer fails closed on every non-ALLOW verdict for every event', () => {
  const events = ['PreToolUse', 'PostToolUse', 'Stop', 'SubagentStop', 'UserPromptSubmit'] as const;
  for (const event of events) {
    for (const action of ['deny', 'block'] as const) {
      const r = renderCodexOutput({ event, action, reason: 'no', exitCode: 0 });
      assert.equal(r.exitCode, 2, `${event}/${action}`);
    }
    assert.equal(
      renderCodexOutput({ event, action: event === 'PreToolUse' ? 'allow' : 'continue', exitCode: 0 })
        .exitCode,
      0,
      `${event} pass-through`,
    );
  }
  const ask = renderCodexOutput({ event: 'PreToolUse', action: 'ask', reason: 'network', exitCode: 0 });
  assert.equal(ask.exitCode, 2);
  assert.equal(JSON.parse(ask.stdout).decision, 'deny');
  assert.match(JSON.parse(ask.stdout).reason, /codex-cli: ASK is refused/);
});

test('generated codex hooks.json finds the shim from any subdirectory and exits 2 when the shim is missing', () => {
  const root = mkdtempSync(join(tmpdir(), 'ego-codex-cmd-'));
  spawnSync('git', ['init', '-q'], { cwd: root });
  const { content } = writeCodexHooks(root);
  const hooks = (
    JSON.parse(content) as { hooks: Record<string, Array<{ hooks: Array<{ command: string }> }>> }
  ).hooks;
  assert.deepEqual(Object.keys(hooks).sort(), [...CODEX_HOOK_EVENTS].sort());
  const command = hooks['PreToolUse']![0]!.hooks[0]!.command;
  const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', HOME: process.env['HOME'] ?? '/tmp' };
  // no shim in the repository: the command itself fails closed
  const missing = spawnSync('/bin/sh', ['-c', command], { cwd: root, encoding: 'utf8', env, input: '{}' });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /hook shim missing; failing closed/);
  // outside any git repository: fails closed too
  const outside = spawnSync('/bin/sh', ['-c', command], {
    cwd: mkdtempSync(join(tmpdir(), 'ego-nogit-')),
    encoding: 'utf8',
    env,
    input: '{}',
  });
  assert.equal(outside.status, 2);
  // with a shim, a hook fired from a subdirectory reaches it with the host and event arguments
  mkdirSync(join(root, '.harness', 'hooks'), { recursive: true });
  writeFileSync(join(root, '.harness', 'hooks', 'ego-hook.sh'), '#!/bin/sh\necho "SHIM $1 $2"\nexit 0\n');
  mkdirSync(join(root, 'sub', 'dir'), { recursive: true });
  const found = spawnSync('/bin/sh', ['-c', command], {
    cwd: join(root, 'sub', 'dir'),
    encoding: 'utf8',
    env,
    input: '{}',
  });
  assert.equal(found.status, 0, found.stderr);
  assert.match(found.stdout, /SHIM codex-cli PreToolUse/);
});
