// CLOSURE AUDIT 2026-10-02, WAVE 5 - AUTHORITY AND ROBUSTNESS (independent reviewers 'authority' and 'robust': AUTH-2..AUTH-12,
// AUTH-14, RB-2, RB-3, RB-6, RB-7), and the two general properties the review proposed as cross-cutting invariants.
//
// Every test here was written BEFORE the change it pins and failed on the tree it was written against. They are grouped by the
// reader that was wrong, not by the spelling the reviewer used, because the lesson of this repository is that a fix at one
// spelling leaves its siblings open:
//
//   A. THE POLICY CACHE IS DERIVED STATE (AUTH-2, AUTH-10, AUTH-11). A generated file that cannot be read is absent, never fatal;
//      a cache written by an earlier build is read by every consumer with the same tolerance; the table a cache holds does not
//      depend on where the checkout is.
//   B. "IS THIS TABLE WIDER" HAS ONE READER (AUTH-3). The release gate, the pending-widening gate, `ego authority diff` and the
//      AUTHORITY DIFF `ego init` prints are one function over one description of the table, and a field the description does not
//      name does not compile.
//   C. AN ACCEPTANCE IS BOUND TO WHAT THE HUMAN WAS SHOWN (AUTH-4, AUTH-5).
//   D. A PRESENTATION NEVER TURNS AN ASK INTO A BLOCK (AUTH-12) and a host payload is read by one reader (RB-6).
//   E. THE WORK A DECISION SPENDS DEPENDS ON THE COMMAND AND THE DECLARED CONFIGURATION ONLY (RB-7), and EVERY READER OF UNBOUNDED
//      INPUT PAYS FOR IT (general property I).
//   F. SESSION STATE UNDER CONCURRENCY AND IDLE TIME (RB-2, RB-3).
//   G. A GRANT PHRASE LIFTS THE REAL COMMAND IT NAMES (AUTH-7), every capability has a producer or is reserved (AUTH-14), a
//      refusal names the rule that is really the source (AUTH-8, AUTH-9).
//   H. CHANNEL INTEGRITY (AUTH-6, general property II): text from a layer file, a repository file, a command line or a tool input
//      is shown in EGO's own voice only as quoted, bounded, escaped data.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { main } from '../../cli/src/main.ts';
import { parseCodexEvent, renderCodexOutput } from '../../adapter-codex-cli/src/dialect.ts';
import { approvalPresentation, externalAskHit } from '../src/authority/approval.ts';
import { describeCapability } from '../src/authority/describe.ts';
import { verdictSource } from '../src/authority/vocabulary.ts';
import { handleHook, type HookRuntime } from '../src/hooks/handle.ts';
import type { HookEvent } from '../src/hooks/events.ts';
import { readPin, writePin } from '../src/launcher/pin.ts';
import { selfIdentity, selfVersion } from '../src/launcher/self.ts';
import { evaluate } from '../src/authority/evaluate.ts';
import { initProject } from '../src/project/init.ts';
import { runDoctor, formatDoctor } from '../src/project/doctor.ts';
import { readGeneratedManifest } from '../src/project/init.ts';
import { loadControlPlane } from '../src/control-plane/load.ts';
import {
  AUTHORITY_TABLE_FIELDS,
  compileAuthority,
  diffAuthorityTables,
  classifyAuthorityChanges,
  isWideningChange,
} from '../src/authority/compile.ts';
import { authorityDiffReport } from '../src/project/authority-diff.ts';
import {
  clampToBaseline,
  ensurePolicyCache,
  policyCacheFreshness,
  POLICY_CACHE_RELATIVE,
  probeLayerHashing,
  readPolicyCache,
  tableWidenings,
  writePolicyCache,
  type PolicyCache,
} from '../src/policy/cache.ts';
import { sha256Canonical, sha256Hex } from '../src/util/hash.ts';
import { ctx, table, workspace } from './support/corpus.ts';

const CP = new URL('../../../control-plane/', import.meta.url).pathname;
const SELF = { runtimeSha256: 'closure-authority2-test', version: '0.0.0-test' };

// EVERY FIXTURE LIVES UNDER ONE PARENT, not directly in the system temp directory (see the note in support/corpus.ts).
const PARENT = mkdtempSync(join(tmpdir(), 'ego-ca2-root-'));

const gitEnv = (): NodeJS.ProcessEnv => {
  const e: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!/^GIT_/.test(k)) e[k] = v;
  return e;
};
/** a human terminal: nothing marks it as an agent shell */
const humanEnv = (home: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv => ({
  PATH: process.env['PATH'],
  HOME: home,
  EGO_HOME: join(home, '.ego'),
  LANG: 'C',
  ...extra,
});
const homeDir = (): string => mkdtempSync(join(PARENT, 'home-'));

/** a real git repository (init, doctor and the hooks read Git itself) with the given files committed */
function repo(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(PARENT, 'repo-'));
  for (const a of [['init', '-q'], ['config', 'user.email', 't@example.com'], ['config', 'user.name', 't']])
    spawnSync('git', a, { env: gitEnv(), cwd: dir });
  spawnSync('git', ['remote', 'add', 'origin', 'git@github.com:acme/demo.git'], { env: gitEnv(), cwd: dir });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'demo', version: '1.0.0' }));
  for (const [name, content] of Object.entries(files)) put(dir, name, content);
  spawnSync('git', ['add', '-A'], { env: gitEnv(), cwd: dir });
  spawnSync('git', ['commit', '-qm', 'init'], { env: gitEnv(), cwd: dir });
  return dir;
}
function put(dir: string, name: string, content: string): void {
  mkdirSync(dirname(join(dir, name)), { recursive: true });
  writeFileSync(join(dir, name), content);
}

async function ego(argv: string[], cwd: string, env: NodeJS.ProcessEnv, stdin = ''): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(argv, {
    cwd,
    env,
    stdin,
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    now: () => '2026-10-02T10:00:00.000Z',
  });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

/** the hook entry point as a host calls it, for the project's pinned runtime */
async function hookCall(dir: string, env: NodeJS.ProcessEnv, event: string, payload: Record<string, unknown> = {}) {
  const r = await ego(
    ['hook', 'claude-code', event],
    dir,
    env,
    JSON.stringify({ session_id: 'ca2', cwd: dir, hook_event_name: event, ...payload }),
  );
  return r;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * A. THE POLICY CACHE IS DERIVED STATE (AUTH-2, AUTH-10, AUTH-11)
 * ------------------------------------------------------------------------------------------------------------- */

/** every way a file that should be JSON turns out not to be one: a sync tool's zero-byte file, a crash mid-write, a hand edit */
const UNREADABLE: Array<[label: string, bytes: string | Buffer]> = [
  ['an empty file', ''],
  ['whitespace only', '  \n\t\n'],
  ['a truncated document', '{"schema":"ego.policy-cache/1","table":{"schema":'],
  ['prose', 'not json'],
  ['binary bytes', Buffer.from([0x00, 0xff, 0xfe, 0x7b, 0x22, 0x80])],
  ['a byte-order mark and nothing else', '﻿'],
  ['a JSON string', '"x"'],
  ['a JSON number', '42'],
  ['an empty object', '{}'],
  ['an array', '[]'],
  ['null', 'null'],
  ['a document of the right shape with a table that is not one', '{"schema":"ego.policy-cache/1","table":"x"}'],
  ['a conflict marker', '<<<<<<< HEAD\n{}\n=======\n{}\n>>>>>>> topic\n'],
];

test('A. AUTH-2: a policy cache that cannot be read is ABSENT in every spelling, and the next ensure regenerates it', () => {
  const failures: string[] = [];
  for (const [label, bytes] of UNREADABLE) {
    const dir = repo();
    put(dir, '.harness/generated/policy.json', '');
    writeFileSync(join(dir, POLICY_CACHE_RELATIVE), bytes);
    try {
      assert.equal(readPolicyCache(dir), null, `${label}: read as absent`);
      const r = ensurePolicyCache(CP, dir, SELF);
      assert.equal(r.regenerated, true, `${label}: regenerated`);
      assert.ok(readPolicyCache(dir), `${label}: the regenerated cache reads back`);
      const f = policyCacheFreshness(CP, dir, SELF);
      assert.equal(f.fresh, true, `${label}: fresh after regeneration (${f.reasons.join('; ')})`);
    } catch (e) {
      failures.push(`${label}: ${(e as Error).message.split('\n')[0]}`);
    }
  }
  assert.deepEqual(failures, []);
});

test('A. AUTH-2: a directory where the cache should be is absent too, not an EISDIR for every hook', () => {
  const dir = repo();
  mkdirSync(join(dir, POLICY_CACHE_RELATIVE), { recursive: true });
  assert.equal(readPolicyCache(dir), null);
});

test('A. AUTH-2: every consumer of the cache survives an unreadable one, and `ego init` - the remedy the error names - repairs it', async () => {
  const dir = repo();
  const home = homeDir();
  const env = humanEnv(home);
  assert.equal((await ego(['init'], dir, env)).code, 0);
  const cache = join(dir, POLICY_CACHE_RELATIVE);
  const hostEnv = { ...env, CLAUDE_PROJECT_DIR: dir };
  for (const [label, bytes] of UNREADABLE.slice(0, 5)) {
    writeFileSync(cache, bytes);
    for (const [what, run] of [
      ['SessionStart', () => hookCall(dir, hostEnv, 'SessionStart', { source: 'startup' })],
      ['UserPromptSubmit', () => hookCall(dir, hostEnv, 'UserPromptSubmit', { prompt: 'hello' })],
      ['PreToolUse', () => hookCall(dir, hostEnv, 'PreToolUse', { tool_name: 'Bash', tool_input: { command: 'ls' } })],
      ['PostToolUse', () => hookCall(dir, hostEnv, 'PostToolUse', { tool_name: 'Bash', tool_input: { command: 'ls' }, tool_response: {} })],
      ['ego doctor', () => ego(['doctor'], dir, env)],
      ['ego check', () => ego(['check'], dir, env)],
    ] as const) {
      const r = await run();
      assert.ok(!/Unexpected|SyntaxError|JSON/.test(r.err), `${label} / ${what}: ${r.err.split('\n')[0]}`);
      if (what !== 'ego check' && what !== 'ego doctor') assert.equal(r.code, 0, `${label} / ${what}: exit ${r.code} ${r.err.split('\n')[0]}`);
    }
    // the hook regenerated the cache (a stale or absent cache is recompiled by the next hook); init repairs it from a person's terminal too
    writeFileSync(cache, bytes);
    const init = await ego(['init'], dir, env);
    assert.equal(init.code, 0, `${label}: ego init exit ${init.code} ${init.err.split('\n')[0]}`);
    assert.ok(readPolicyCache(dir), `${label}: init wrote a readable cache`);
  }
});

test('A. AUTH-2 sibling: the other generated file a command reads (the manifest) is derived state too', async () => {
  const dir = repo();
  const env = humanEnv(homeDir());
  await ego(['init'], dir, env);
  const manifest = join(dir, '.harness', 'generated', 'manifest.json');
  for (const bytes of ['', 'garbage', '{"schema":']) {
    writeFileSync(manifest, bytes);
    assert.equal(readGeneratedManifest(dir), null, `manifest ${JSON.stringify(bytes)} reads as absent`);
    const doctor = await ego(['doctor'], dir, env);
    assert.ok(!/SyntaxError|Unexpected/.test(doctor.err), doctor.err);
    assert.match(doctor.out, /no generated manifest/);
    const check = await ego(['check'], dir, env);
    assert.ok(!/SyntaxError|Unexpected/.test(check.err), check.err);
    assert.match(check.out, /manifest missing/);
    assert.equal((await ego(['init'], dir, env)).code, 0, 'init regenerates it');
    assert.ok(readGeneratedManifest(dir), 'and it reads back');
  }
});

test('A. AUTH-10: a cache written by an earlier build, with a localTargets object that has no declared or ignored list, does not crash doctor', async () => {
  const dir = repo();
  const env = humanEnv(homeDir());
  await ego(['init'], dir, env);
  const path = join(dir, POLICY_CACHE_RELATIVE);
  const cache = JSON.parse(readFileSync(path, 'utf8')) as PolicyCache;
  const lt = cache.table.localTargets as unknown as Record<string, unknown>;
  delete lt['declared'];
  delete lt['ignored'];
  const { tableHash: _drop, ...body } = cache.table;
  cache.table = { ...body, tableHash: sha256Canonical(body) } as PolicyCache['table'];
  cache.runtimeSha256 = 'f'.repeat(64);
  writeFileSync(path, JSON.stringify(cache, null, 2));
  const doctor = await ego(['doctor'], dir, env);
  assert.ok(!/Cannot read properties|undefined/.test(doctor.err), doctor.err);
  assert.match(doctor.out, /local targets/);
  assert.ok(doctor.code === 0 || doctor.code === 1, `exit ${doctor.code}: ${doctor.err}`);
  // the same table through every other reader of a compiled table
  const check = await ego(['check'], dir, env);
  assert.ok(!/Cannot read properties/.test(check.err), check.err);
  const caps = await ego(['capabilities'], dir, env);
  assert.ok(!/Cannot read properties/.test(caps.err), caps.err);
});

test('A. AUTH-10: doctor reads a table that lacks the registry lists an earlier build did not write', () => {
  const stale = structuredClone(table);
  const lt = stale.localTargets as unknown as Record<string, unknown>;
  delete lt['declared'];
  delete lt['ignored'];
  const { tableHash: _drop, ...body } = stale;
  const dir = repo();
  const env = humanEnv(homeDir());
  initProject({ cwd: dir, env, offline: true });
  const cache = readPolicyCache(dir)!;
  writePolicyCache(dir, { ...cache, table: { ...body, tableHash: sha256Canonical(body) } as typeof table });
  const lines = formatDoctor(runDoctor({ cwd: dir, env, now: () => '2026-10-02T10:00:00.000Z', offline: true })).split('\n');
  assert.ok(lines.some((l) => /local targets/.test(l)));
});

test('A. AUTH-11: the compiled table does not depend on where the control plane or the project sits', () => {
  const copy = join(mkdtempSync(join(PARENT, 'cp-')), 'control-plane');
  cpSync(CP, copy, { recursive: true });
  const a = compileAuthority(loadControlPlane(CP), { projectRoot: '/tmp/ca2-project-one' });
  const b = compileAuthority(loadControlPlane(copy), { projectRoot: '/tmp/ca2-project-one' });
  const c = compileAuthority(loadControlPlane(copy), { projectRoot: '/var/elsewhere/ca2-project-two' });
  const d = compileAuthority(loadControlPlane(copy));
  assert.equal(a.tableHash, b.tableHash, 'the control plane at another path');
  assert.equal(a.tableHash, c.tableHash, 'the control plane and the project at other paths');
  assert.equal(a.tableHash, d.tableHash, 'no project root at all');
  for (const t of [a, b, c, d]) {
    const text = JSON.stringify(t);
    assert.ok(!text.includes(copy) && !text.includes(CP.replace(/\/$/, '')), 'no absolute location of the control plane is in the table');
    assert.ok(!text.includes('/tmp/ca2-project-one') && !text.includes('/var/elsewhere'), 'nor of the project');
  }
});

test('A. AUTH-11: the same project compiled by two caches at two locations yields the same table hash', () => {
  const files = { '.harness/local-targets.md': '---\nschema: ego.local-targets/1\nk8s_local_contexts:\n  - team-dev\n---\n' };
  const one = repo(files);
  const two = repo(files);
  const a = ensurePolicyCache(CP, one, SELF, { acceptWidening: true }).cache.table;
  const b = ensurePolicyCache(CP, two, SELF, { acceptWidening: true }).cache.table;
  assert.equal(a.tableHash, b.tableHash);
  assert.ok(!JSON.stringify(a).includes(one));
});

/* ------------------------------------------------------------------------------------------------------------- *
 * B. "IS THIS TABLE WIDER" HAS ONE READER (AUTH-3)
 * ------------------------------------------------------------------------------------------------------------- */

type Table = typeof table;
const rehash = (t: Table): Table => {
  const { tableHash: _drop, ...body } = t;
  return { ...body, tableHash: sha256Canonical(body) } as Table;
};
/** the core table, edited in place by `edit`, and hashed again as the compiler would */
const edited = (edit: (t: Table) => void): Table => {
  const t = structuredClone(table);
  edit(t);
  return rehash(t);
};
/** the index of the first matcher whose pattern matches `command` */
const matcherIndex = (t: Table, capability: string): number => t.matchers.findIndex((m) => m.capability === capability && m.layer === 'core');

/** every way the table can GET WIDER that the review found the diff blind to, plus the neighbours of each: one per field of the description */
const WIDENING_EDITS: Array<[label: string, edit: (t: Table) => void]> = [
  ['the bounded vocabulary gains a head', (t) => t.boundedCommands.bounded.push('zzz-new-head')],
  ['the bounded vocabulary gains a head with a space (a longer, more specific entry)', (t) => t.boundedCommands.bounded.push('pytest -q')],
  ['the kernel list of local kube contexts gains a pattern', (t) => t.localTargets.k8sLocalContexts.push('shared-*')],
  ['the kernel list of local database hosts gains a pattern', (t) => t.localTargets.dbLocalHosts.push('*.corp.example')],
  ['the default mode becomes EGO_MAINTENANCE', (t) => void (t.defaultMode = 'EGO_MAINTENANCE')],
  ['HIGH_ASSURANCE stops requiring signed release trust', (t) => void (t.profiles['HIGH_ASSURANCE']!.requiresSignedReleaseTrust = false)],
  ['HIGH_ASSURANCE stops requiring a managed tier', (t) => void (t.profiles['HIGH_ASSURANCE']!.requiresManagedTier = false)],
  ['STRICT stops requiring signed release trust', (t) => void (t.profiles['STRICT']!.requiresSignedReleaseTrust = false)],
  ['the install-dependencies list is emptied', (t) => void (t.boundedCommands.installsDependencies = [])],
  ['the discovers-content list is emptied', (t) => void (t.boundedCommands.discoversContent = [])],
  ['the discovers-config list is emptied', (t) => void (t.boundedCommands.discoversConfig = [])],
  ['one tool leaves the discovers-content list', (t) => void t.boundedCommands.discoversContent.shift()],
  [
    'two core rules swap places (first match wins), `git stash --all` goes from DENY to ALLOW',
    (t) => {
      const deny = matcherIndex(t, 'ego.runtime.tamper');
      const allow = matcherIndex(t, 'git.local.stash');
      assert.ok(deny >= 0 && allow >= 0);
      [t.matchers[deny], t.matchers[allow]] = [t.matchers[allow]!, t.matchers[deny]!];
    },
  ],
  ['one core rule moves to the front of the list', (t) => void t.matchers.unshift(t.matchers.splice(matcherIndex(t, 'git.local.stash'), 1)[0]!)],
  ['one core rule moves to the end of the list', (t) => void t.matchers.push(t.matchers.splice(matcherIndex(t, 'ego.runtime.tamper'), 1)[0]!)],
  ['a member leaves the HARD_LOCK list', (t) => void t.absoluteDenies.pop()],
  ['a member leaves the ADMIN_GOVERNED list', (t) => void t.adminGoverned.pop()],
  ['a production marker is removed', (t) => void t.localTargets.productionMarkers.pop()],
  ['a grant negation is removed', (t) => void t.grantNegations.pop()],
  ['the negation window shrinks', (t) => void (t.grantNegationWindowTokens = 1)],
  ['a protected path is removed', (t) => void t.protectedPaths.shift()],
  ['a pre-denied command class is removed', (t) => void t.preDeniedCommandClasses.shift()],
  ['a locked redaction minimum is removed', (t) => void delete t.sanitizerLockedMinimums[Object.keys(t.sanitizerLockedMinimums)[0]!]],
  ['a core-layer verdict becomes ALLOW in the layered table', (t) => void (t.effective['git.remote.push'] = 'ALLOW')],
];

test('B. AUTH-3: every way the table can widen is a WIDENING change, a MAJOR grade, and a pending widening', () => {
  const blind: string[] = [];
  for (const [label, edit] of WIDENING_EDITS) {
    const next = edited(edit);
    const changes = diffAuthorityTables(table, next);
    const widening = changes.filter((c) => isWideningChange(c, next));
    if (widening.length === 0) blind.push(`${label}: the diff marks nothing`);
    else if (classifyAuthorityChanges(changes, next) !== 'major') blind.push(`${label}: graded ${classifyAuthorityChanges(changes, next)}`);
    if (tableWidenings(table, next).length === 0) blind.push(`${label}: the pending-widening gate sees nothing`);
  }
  assert.deepEqual(blind, []);
});

test('B. AUTH-3: the same edits the other way round are narrowings: listed, never marked', () => {
  const wrong: string[] = [];
  for (const [label, edit] of WIDENING_EDITS) {
    const wide = edited(edit);
    const changes = diffAuthorityTables(wide, table);
    const marked = changes.filter((c) => isWideningChange(c, table));
    if (marked.length > 0) wrong.push(`${label}: ${marked.map((c) => c.kind).join(', ')}`);
  }
  // (`added`/`removed` of a capability and a re-partition are not narrowings: only the edits that move one field are judged here)
  const skip = new Set(['a member leaves the HARD_LOCK list', 'a member leaves the ADMIN_GOVERNED list', 'one core rule moves to the front of the list', 'one core rule moves to the end of the list', 'two core rules swap places (first match wins), `git stash --all` goes from DENY to ALLOW']);
  assert.deepEqual(
    wrong.filter((w) => ![...skip].some((s) => w.startsWith(s))),
    [],
  );
});

test('B. AUTH-3: the table has ONE description: every field of a compiled table is named in it, and each authority field is seen when it changes', () => {
  const fields = Object.keys(table)
    .filter((k) => k !== 'tableHash')
    .sort();
  assert.deepEqual(Object.keys(AUTHORITY_TABLE_FIELDS).sort(), fields, 'a field of the table that the description does not name (or the other way round)');
  // a mutation per authority field, derived from the description: if a field gains authority, this list must say how to move it
  const MOVE: Record<string, (t: Table) => void> = {
    capabilities: (t) => void (t.capabilities['git.remote.push']!.effect = 'local'),
    absoluteDenies: (t) => void t.absoluteDenies.pop(),
    adminGoverned: (t) => void t.adminGoverned.pop(),
    effective: (t) => void (t.effective['git.remote.push'] = 'ALLOW'),
    profiles: (t) => void (t.profiles['STANDARD']!.modes['NORMAL_DELIVERY']!['git.remote.push'] = 'ALLOW'),
    defaultMode: (t) => void (t.defaultMode = 'EGO_MAINTENANCE'),
    matchers: (t) => void t.matchers.pop(),
    grants: (t) => void t.grants[0]!.phrases.push('zzz new phrase'),
    grantNegations: (t) => void t.grantNegations.pop(),
    grantNegationWindowTokens: (t) => void (t.grantNegationWindowTokens = 0),
    protectedPaths: (t) => void t.protectedPaths.pop(),
    preDeniedCommandClasses: (t) => void t.preDeniedCommandClasses.pop(),
    sanitizerLockedMinimums: (t) => void delete t.sanitizerLockedMinimums[Object.keys(t.sanitizerLockedMinimums)[0]!],
    localTargets: (t) => void t.localTargets.dbLocalHosts.push('*.corp.example'),
    boundedCommands: (t) => void t.boundedCommands.bounded.push('zzz-new-head'),
  };
  const authority = Object.entries(AUTHORITY_TABLE_FIELDS)
    .filter(([, r]) => r.role === 'authority')
    .map(([k]) => k)
    .sort();
  assert.deepEqual(Object.keys(MOVE).sort(), authority, 'every authority field has a way to move it in this test');
  const unseen = authority.filter((f) => diffAuthorityTables(table, edited(MOVE[f]!)).length === 0);
  assert.deepEqual(unseen, [], 'a field the hash covers and the diff does not read');
  // every other field says why it carries no authority
  for (const [k, r] of Object.entries(AUTHORITY_TABLE_FIELDS)) if (r.role !== 'authority') assert.ok(r.note.length > 10, `${k} says why it is not authority`);
});

test('B. AUTH-3: `ego init` and `ego authority diff` mark the same changes (one predicate), and the gate is its widening subset', () => {
  for (const [label, edit] of WIDENING_EDITS) {
    const next = edited(edit);
    const marked = diffAuthorityTables(table, next).filter((c) => isWideningChange(c, next)).length;
    assert.equal(authorityDiffReport(table, next).widenings.length, marked, `${label}: the AUTHORITY DIFF init prints`);
    assert.equal(tableWidenings(table, next).length, marked, `${label}: the gate`);
  }
  // a new ALLOW matcher and a removed capability: the two cases the init diff's own predicate answered differently
  const allowMatcher = edited((t) => {
    t.effective['command.read-only'] = 'ALLOW';
    t.matchers.push({ capability: 'command.read-only', tool: 'Bash', command: '^zzz-new-tool', layer: 'core' });
  });
  assert.equal(authorityDiffReport(table, allowMatcher).widenings.length, diffAuthorityTables(table, allowMatcher).filter((c) => isWideningChange(c, allowMatcher)).length);
  assert.ok(authorityDiffReport(table, allowMatcher).widenings.some((l) => /matcher-added/.test(l)), 'a new rule that maps to an ALLOW capability widens');
  const root = new URL('../src/', import.meta.url);
  const gate = readFileSync(new URL('policy/cache.ts', root), 'utf8');
  assert.match(gate.slice(gate.indexOf('export function tableWidenings')), /^export function tableWidenings[\s\S]{0,400}diffAuthorityTables\(baseline, next\)[\s\S]{0,120}isWideningChange/);
  const init = readFileSync(new URL('project/authority-diff.ts', root), 'utf8');
  assert.ok(!/function\s+wideningChange|WIDENING_KINDS/.test(init), 'the init diff holds no predicate of its own');
  assert.match(init, /isWideningChange/);
});

test('B. AUTH-3: whatever the gate reports as pending is not applied: the clamp falls back to the baseline of any field the diff still finds wider', () => {
  const failures: string[] = [];
  for (const [label, edit] of WIDENING_EDITS) {
    const next = edited(edit);
    let clamped: Table;
    try {
      clamped = clampToBaseline(next, table);
    } catch (e) {
      failures.push(`${label}: ${(e as Error).message}`);
      continue;
    }
    const still = diffAuthorityTables(table, clamped).filter((c) => isWideningChange(c, clamped));
    if (still.length) failures.push(`${label}: still wider after the clamp (${still.map((c) => c.kind).join(', ')})`);
  }
  assert.deepEqual(failures, []);
});

test('B. AUTH-3: an overlay rule added anywhere in the overlay is a narrowing, not a pending widening; one that is gone is a widening', () => {
  const dir = repo({
    '.harness/overlay/matchers.md': '---\nschema: ego.matchers/1\nmatchers:\n  - capability: command.destructive\n    tool: Bash\n    command: "^zzz-one"\n---\n',
  });
  const first = ensurePolicyCache(CP, dir, SELF, { acceptWidening: true }).cache;
  assert.equal(first.pendingWidening, undefined);
  // a second rule placed BEFORE the first: an overlay rule is additive, so where it sits changes nothing
  put(dir, '.harness/overlay/matchers.md', '---\nschema: ego.matchers/1\nmatchers:\n  - capability: command.destructive\n    tool: Bash\n    command: "^zzz-two"\n  - capability: command.destructive\n    tool: Bash\n    command: "^zzz-one"\n---\n');
  const narrowed = ensurePolicyCache(CP, dir, SELF).cache;
  assert.equal(narrowed.pendingWidening, undefined, 'a narrowing applies at once');
  assert.equal(narrowed.table.matchers.filter((m) => m.layer === 'overlay').length, 2);
  // one rule gone: a widening
  put(dir, '.harness/overlay/matchers.md', '---\nschema: ego.matchers/1\nmatchers:\n  - capability: command.destructive\n    tool: Bash\n    command: "^zzz-two"\n---\n');
  const widened = ensurePolicyCache(CP, dir, SELF).cache;
  assert.ok(widened.pendingWidening, 'a removed narrowing is pending');
  assert.match(widened.pendingWidening!.widenings.join('\n'), /matcher-removed/);
  assert.equal(widened.table.matchers.filter((m) => m.layer === 'overlay').length, 2, 'and it is put back');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * C. AN ACCEPTANCE IS BOUND TO WHAT THE HUMAN WAS SHOWN (AUTH-4, AUTH-5)
 * ------------------------------------------------------------------------------------------------------------- */

const layerFile = (lists: Record<string, string[]>): string =>
  '---\nschema: ego.local-targets/1\n' +
  Object.entries(lists)
    .map(([k, v]) => `${k}:\n${v.map((x) => `  - '${x}'`).join('\n')}\n`)
    .join('') +
  '---\n# Local targets\n';
const PROJECT_TARGETS = '.harness/local-targets.md';
const ORG_BOUNDED = 'policies/organization/bounded-commands.md';
const boundedFile = (...heads: string[]): string => `---\nschema: ego.bounded-commands/1\nbounded:\n${heads.map((h) => `  - ${h}`).join('\n')}\n---\n`;

test('C. AUTH-4: initProject binds the acceptance to the layer files it asked about: a file rewritten while the person is asked accepts nothing', () => {
  const dir = repo({ [PROJECT_TARGETS]: layerFile({ k8s_local_contexts: ['team-dev'] }) });
  const home = homeDir();
  const env = humanEnv(home);
  const first = initProject({ cwd: dir, env, offline: true, confirmWidening: () => false });
  assert.equal(readPolicyCache(dir)!.table.localTargets.declared.length, 0, 'a no accepts nothing');
  assert.ok(first.notes.join('\n').includes('policy widening NOT applied'));
  // the person is asked about ONE declaration; while they read it the file is rewritten to hold three; they answer yes
  const asked: string[][] = [];
  const raced = initProject({
    cwd: dir,
    env,
    offline: true,
    confirmWidening: (w) => {
      asked.push(w);
      put(dir, PROJECT_TARGETS, layerFile({ k8s_local_contexts: ['team-dev', 'shared-cluster-eu'], db_local_hosts: ['db1.shared.acme.test'] }));
      return true;
    },
  });
  assert.equal(asked.length, 1);
  assert.match(asked[0]!.join('\n'), /team-dev/);
  assert.ok(!asked[0]!.join('\n').includes('shared-cluster-eu'), 'they were shown the one declaration');
  const cache = readPolicyCache(dir)!;
  assert.deepEqual(cache.table.localTargets.declared, [], 'NOTHING was accepted: the files are not the ones that were shown');
  assert.ok(cache.pendingWidening, 'all three wait for a human');
  assert.match(cache.pendingWidening!.widenings.join('\n'), /shared-cluster-eu/);
  assert.match(raced.notes.join('\n'), /policy widening NOT accepted: .*not the ones that were shown/);
  // asked again, they are shown all three and the answer takes effect
  let shown = '';
  initProject({ cwd: dir, env, offline: true, confirmWidening: (w) => ((shown = w.join('\n')), true) });
  assert.match(shown, /shared-cluster-eu/);
  assert.equal(readPolicyCache(dir)!.table.localTargets.declared.length, 3);
});

test('C. AUTH-4: a file rewritten between "nothing to accept" and the acceptance is not accepted either', () => {
  const dir = repo();
  ensurePolicyCache(CP, dir, SELF, { acceptWidening: true });
  const seen = ensurePolicyCache(CP, dir, SELF).cache;
  assert.equal(seen.pendingWidening, undefined);
  // the binding a caller takes from "nothing is waiting": the files as they are, and no widening
  const bound = { layerSources: { ...seen.layerSources }, widenings: [] as string[] };
  put(dir, PROJECT_TARGETS, layerFile({ k8s_local_contexts: ['shared-cluster-eu'] }));
  const r = ensurePolicyCache(CP, dir, SELF, { acceptWidening: bound });
  assert.ok(r.acceptanceRefused, 'refused');
  assert.deepEqual(r.cache.table.localTargets.declared, []);
  assert.ok(r.cache.pendingWidening);
  // the same call with the files as they were shown is accepted
  const ok = ensurePolicyCache(CP, dir, SELF, { acceptWidening: { layerSources: r.cache.pendingWidening!.layerSources, widenings: r.cache.pendingWidening!.widenings } });
  assert.equal(ok.acceptanceRefused, undefined);
  assert.equal(ok.cache.table.localTargets.declared.length, 1);
});

test('C. AUTH-4: the widenings must be the ones that were listed, not only the files: a baseline that moved between the question and the answer is refused', () => {
  const dir = repo({ [ORG_BOUNDED]: boundedFile('zzz-one') });
  const pending = ensurePolicyCache(CP, dir, SELF).cache.pendingWidening!;
  assert.ok(pending);
  const r = ensurePolicyCache(CP, dir, SELF, { acceptWidening: { layerSources: pending.layerSources, widenings: ['bounded vocabulary: "something else"'] } });
  assert.match(r.acceptanceRefused ?? '', /not the ones that were shown/);
  assert.deepEqual(r.cache.table.boundedCommands.bounded.filter((h) => h === 'zzz-one'), [], 'and nothing was applied');
  const ok = ensurePolicyCache(CP, dir, SELF, { acceptWidening: pending });
  assert.equal(ok.acceptanceRefused, undefined);
  assert.ok(ok.cache.table.boundedCommands.bounded.includes('zzz-one'));
});

test('C. AUTH-4: `true` still accepts what the compile of that call finds (a caller that showed nobody anything), in one pass', () => {
  const dir = repo({ [PROJECT_TARGETS]: layerFile({ k8s_local_contexts: ['team-dev'] }) });
  const r = ensurePolicyCache(CP, dir, SELF, { acceptWidening: true });
  assert.equal(r.cache.table.localTargets.declared.length, 1);
  assert.equal(r.acceptanceRefused, undefined);
});

test('C. AUTH-4: an adoption flag is written on top of the file the person was shown, and no other', () => {
  const dir = repo({ [PROJECT_TARGETS]: layerFile({ k8s_local_contexts: ['team-dev'] }) });
  const env = humanEnv(homeDir());
  initProject({ cwd: dir, env, offline: true, confirmWidening: () => false });
  const racing = layerFile({ k8s_local_contexts: ['team-dev', 'shared-cluster-eu'] });
  assert.throws(
    () =>
      initProject({
        cwd: dir,
        env,
        offline: true,
        localTargets: ['kube:x-dev'],
        confirmWidening: () => (put(dir, PROJECT_TARGETS, racing), true),
      }),
    /changed after the widenings were shown/,
  );
  assert.equal(readFileSync(join(dir, PROJECT_TARGETS), 'utf8'), racing, 'the adoption was NOT written over the rewritten file');
  assert.deepEqual(readPolicyCache(dir)!.table.localTargets.declared, []);
});

test('C. AUTH-4: a person who is shown the widenings and adopts a target with a flag gets both, bound to the files they saw plus the text init wrote', () => {
  const dir = repo({ [ORG_BOUNDED]: boundedFile('zzz-one') });
  const env = humanEnv(homeDir());
  initProject({ cwd: dir, env, offline: true, confirmWidening: () => true, localTargets: ['kube:x-dev'] });
  const cache = readPolicyCache(dir)!;
  assert.equal(cache.pendingWidening, undefined);
  assert.ok(cache.table.boundedCommands.bounded.includes('zzz-one'));
  assert.deepEqual(cache.table.localTargets.declared.map((d) => `${d.kind}:${d.name}`), ['kube:x-dev']);
});

test('C. AUTH-4: the hashes a cache records are the hashes of the bytes it was compiled from: a layer file rewritten between its hash and its read is compiled again', () => {
  const dir = repo({ [PROJECT_TARGETS]: layerFile({ k8s_local_contexts: ['team-dev'] }) });
  const target = join(dir, PROJECT_TARGETS);
  let fired = 0;
  probeLayerHashing((rel) => {
    if (rel !== PROJECT_TARGETS || fired++ > 0) return;
    writeFileSync(target, layerFile({ k8s_local_contexts: ['other-dev'] }));
  });
  try {
    const c = ensurePolicyCache(CP, dir, SELF, { acceptWidening: true }).cache;
    assert.equal(fired >= 1, true, 'the race happened');
    assert.equal(c.layerSources[PROJECT_TARGETS], sha256Hex(readFileSync(target, 'utf8')), 'the recorded hash names the bytes on disk');
    assert.deepEqual(c.table.localTargets.declared.map((d) => d.name), ['other-dev'], 'and the table was compiled from those bytes');
  } finally {
    probeLayerHashing(null);
  }
});

test('C. AUTH-4: a layer file that will not keep still is refused, not compiled under a hash that is not its own', () => {
  const dir = repo({ [PROJECT_TARGETS]: layerFile({ k8s_local_contexts: ['team-dev'] }) });
  let n = 0;
  probeLayerHashing((rel) => {
    if (rel === PROJECT_TARGETS) writeFileSync(join(dir, PROJECT_TARGETS), layerFile({ k8s_local_contexts: [`dev-${n++}`] }));
  });
  try {
    assert.throws(() => ensurePolicyCache(CP, dir, SELF), /changed while the policy was being compiled/);
  } finally {
    probeLayerHashing(null);
  }
});

/* ------------------------------------------------------------------------------------------------------------- *
 * D. A PRESENTATION NEVER TURNS AN ASK INTO A BLOCK (AUTH-12); A HOST PAYLOAD IS READ BY ONE READER (RB-6)
 * ------------------------------------------------------------------------------------------------------------- */

/** the most permissive legal table: every administrable external capability enabled at ASK by an organization */
const ORG_ENABLES_ALL = `---\nschema: ego.capabilities/1\nid: org\nfamily: organization\ntitle: org\n---\n# org\n\n## Requires human approval\n\n${table.adminGoverned.map((id) => `- [x] \`${id}\` - enabled\n`).join('')}`;

test('D. AUTH-12: a malformed percent escape in a forge endpoint is text: the presentation does not throw', () => {
  const dir = repo({ 'policies/organization/permissions.md': ORG_ENABLES_ALL });
  const t = ensurePolicyCache(CP, dir, SELF, { acceptWidening: true }).cache.table;
  const ctx = { profile: 'STANDARD', mode: 'NORMAL_DELIVERY', repoRoots: [dir], cwd: dir };
  const endpoints = ['repos/octo/%zz/issues', 'repos/octo/%/issues', 'repos/octo/%2/issues', 'repos/%E0%A4%A/r/issues', 'repos/%ud800/x/issues', 'repos/o%00/r/issues', 'repos/%FF%FF/r/issues', 'repos/%C0%AF/r/issues', 'repos/ok/%252F/issues'];
  const failures: string[] = [];
  let presented = 0;
  for (const head of ['gh', 'glab'])
    for (const e of endpoints) {
      const cmd = head === 'gh' ? `gh api ${e} -X POST -f title=x` : `glab api projects/${e.replace(/^repos\//, '')} -X POST -f title=x`;
      const req = { tool: 'Bash', input: { command: cmd } };
      const ev = evaluate(t, ctx, req);
      const hit = externalAskHit(t, ev.hits);
      if (!hit) continue;
      try {
        const p = approvalPresentation(t, ctx, req, hit, { summary: cmd });
        if (p) presented++;
      } catch (err) {
        failures.push(`${cmd}: ${(err as Error).message}`);
      }
    }
  assert.deepEqual(failures, []);
  assert.ok(presented > 0, 'the cases reached a presentation');
});

test('D. AUTH-12: every external capability, with hostile arguments, is presented or declined - never thrown', () => {
  const dir = repo({ 'policies/organization/permissions.md': ORG_ENABLES_ALL });
  const t = ensurePolicyCache(CP, dir, SELF, { acceptWidening: true }).cache.table;
  const ctx = { profile: 'STANDARD', mode: 'NORMAL_DELIVERY', repoRoots: [dir], cwd: dir };
  // a seeded generator of command lines that put hostile text where each presenter reads: a URL, a remote, a context, an endpoint
  let seed = 20261002;
  const rnd = (n: number): number => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff), seed % n);
  const hostile = ['%zz', '%', '%E0%A4%A', '\u0000', '‮', '\ud800', 'a'.repeat(400), '\x1b[2K', '[::1', 'http://', '@', ':::', '..%2f..', '%u0041', '\n', 'é%C3', '{}', '""'];
  const heads = [
    (h: string) => `gh api repos/o/${h}/issues -X POST -f t=x`,
    (h: string) => `gh api graphql -f query=${h}`,
    (h: string) => `glab api projects/${h}/issues -X POST`,
    (h: string) => `gh pr create --repo ${h} --title x`,
    (h: string) => `curl -X POST http://${h}/x -d a=b`,
    (h: string) => `curl -X DELETE https://${h}`,
    (h: string) => `git push ${h} main`,
    (h: string) => `git push origin ${h}`,
    (h: string) => `git remote add ${h} https://${h}`,
    (h: string) => `kubectl --context ${h} apply -f x.yaml`,
    (h: string) => `psql -h ${h} -c "drop table t"`,
    (h: string) => `docker push ${h}/img:1`,
    (h: string) => `aws s3 rm s3://${h} --region ${h}`,
    (h: string) => `terraform -chdir=${h} apply`,
    (h: string) => `helm --kube-context ${h} upgrade r ./c`,
  ];
  const failures: string[] = [];
  let reached = 0;
  for (let i = 0; i < 400; i++) {
    const h = hostile[rnd(hostile.length)]! + (rnd(3) === 0 ? hostile[rnd(hostile.length)]! : '');
    const cmd = heads[rnd(heads.length)]!(h.split('\n').join('_').split('\u0000').join('_'));
    const req = { tool: 'Bash', input: { command: cmd } };
    try {
      const ev = evaluate(t, ctx, req);
      const hit = externalAskHit(t, ev.hits);
      if (!hit) continue;
      reached++;
      approvalPresentation(t, ctx, req, hit, { summary: cmd });
    } catch (err) {
      failures.push(`${JSON.stringify(cmd).slice(0, 120)}: ${(err as Error).message}`);
    }
  }
  assert.deepEqual(failures, []);
  assert.ok(reached > 40, `the generator reached ${reached} presentations`);
});

test('D. AUTH-12: through the hook, an ASK whose presentation cannot be built is still an ASK (the evaluator\'s own reason), not an exit 2', async () => {
  const dir = repo({ 'policies/organization/permissions.md': ORG_ENABLES_ALL });
  const env = humanEnv(homeDir());
  assert.equal((await ego(['init'], dir, env)).code, 0);
  const hostEnv = { ...env, CLAUDE_PROJECT_DIR: dir };
  for (const cmd of ['gh api repos/octo/%zz/issues -X POST -f title=x', 'glab api projects/%E0%A4%A/issues -X POST -f t=x']) {
    const r = await hookCall(dir, hostEnv, 'PreToolUse', { tool_name: 'Bash', tool_input: { command: cmd } });
    assert.equal(r.code, 0, `${cmd}: ${r.err}`);
    assert.equal(JSON.parse(r.out).hookSpecificOutput.permissionDecision, 'ask', cmd);
  }
});

test('D. AUTH-12: no source decodes a percent escape without a fallback: `decodeURIComponent` is called in one place that catches', () => {
  const root = new URL('../../', import.meta.url);
  const offenders: string[] = [];
  const walk = (dir: URL): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const u = new URL(e.name + (e.isDirectory() ? '/' : ''), dir);
      if (e.isDirectory()) walk(u);
      else if (e.name.endsWith('.ts')) {
        const lines = readFileSync(u, 'utf8').split('\n');
        lines.forEach((l, i) => {
          if (!/\bdecodeURI(Component)?\(/.test(l.replace(/\/\/.*$/, ''))) return;
          // a decode is allowed inside a `try {` opened within the three lines above it
          if (!lines.slice(Math.max(0, i - 3), i + 1).some((x) => /\btry\s*\{/.test(x))) offenders.push(`${u.pathname.split('/packages/')[1]}:${i + 1}`);
        });
      }
    }
  };
  for (const pkg of readdirSync(root, { withFileTypes: true })) if (pkg.isDirectory() && existsSync(new URL(`${pkg.name}/src/`, root))) walk(new URL(`${pkg.name}/src/`, root));
  assert.deepEqual(offenders, [], 'a percent-decode that can throw on hostile input; use decodeUriComponentOrRaw (util/uri.ts)');
});

/** the verdict the kernel gives the tool call a Codex payload becomes */
function codexVerdict(payload: Record<string, unknown>, files: Record<string, string> = {}): { verdict: string; command: string | undefined; code: number } {
  const dir = workspace(files);
  const ev = parseCodexEvent('PreToolUse', { session_id: 's', cwd: dir, ...payload }, dir);
  const r = evaluate(table, ctx(dir), { tool: ev.tool!.name, input: ev.tool!.input });
  const out = renderCodexOutput({ event: 'PreToolUse', action: r.verdict === 'ALLOW' ? 'allow' : r.verdict === 'ASK' ? 'ask' : 'deny', reason: r.reason, exitCode: 0 });
  return { verdict: r.verdict, command: ev.tool!.input['command'] as string | undefined, code: out.exitCode };
}

test('D. RB-6: the same argv is the same verdict however the host nests it (flat, `action`, a JSON text, `arguments`)', () => {
  const argv = ['ls', '-la'];
  const shapes: Array<[string, Record<string, unknown>]> = [
    ['flat command argv', { tool_name: 'local_shell', tool_input: { command: argv } }],
    ['shell, flat', { tool_name: 'shell', tool_input: { command: argv } }],
    ['local_shell action.exec (the Responses API item)', { tool_name: 'local_shell', tool_input: { action: { type: 'exec', command: argv, working_directory: '/tmp' } } }],
    ['local_shell action without a type', { tool_name: 'local_shell', tool_input: { action: { command: argv } } }],
    ['action as JSON text', { tool_name: 'local_shell', tool_input: JSON.stringify({ action: { type: 'exec', command: argv } }) }],
    ['arguments carrying the action', { tool_name: 'local_shell', arguments: { action: { type: 'exec', command: argv } } }],
    ['arguments as a JSON text', { tool_name: 'shell', arguments: JSON.stringify({ command: argv, workdir: '/tmp' }) }],
    ['exec_command cmd', { tool_name: 'exec_command', tool_input: { cmd: 'ls -la' } }],
    ['action with a timeout and no workdir', { tool_name: 'local_shell', tool_input: { action: { type: 'exec', command: argv, timeout_ms: 1000 } } }],
  ];
  const got = shapes.map(([label, p]) => `${label}: ${codexVerdict(p).verdict}`);
  assert.deepEqual(got, shapes.map(([label]) => `${label}: ALLOW`));
  // the SAME holds for a command that must not be allowed: nesting does not change what it is
  const push = ['git', 'push', 'origin', 'main'];
  for (const [label, p] of [
    ['flat', { tool_name: 'local_shell', tool_input: { command: push } }],
    ['nested', { tool_name: 'local_shell', tool_input: { action: { type: 'exec', command: push } } }],
    ['bash -lc nested', { tool_name: 'local_shell', tool_input: { action: { type: 'exec', command: ['bash', '-lc', 'git push origin main'] } } }],
  ] as const)
    assert.equal(codexVerdict(p).verdict, 'DENY', label);
});

test('D. RB-6: what the nested action carries that changes the command is part of the command: an env, a user, a working directory', () => {
  // a working directory becomes the `cd` it is, in the nested form as in the flat one
  const flat = codexVerdict({ tool_name: 'shell', tool_input: { command: ['cat', 'id_rsa'], workdir: '/home/x/.ssh' } });
  const nested = codexVerdict({ tool_name: 'local_shell', tool_input: { action: { type: 'exec', command: ['cat', 'id_rsa'], working_directory: '/home/x/.ssh' } } });
  assert.equal(nested.verdict, flat.verdict);
  assert.match(nested.command ?? '', /^cd .*\.ssh.* && cat id_rsa$/);
  // an environment the action sets reaches the command as the assignments it is (the evaluator judges `LD_PRELOAD=… ls`), never dropped
  const withEnv = codexVerdict({ tool_name: 'local_shell', tool_input: { action: { type: 'exec', command: ['ls'], env: { LD_PRELOAD: '/tmp/x.so' } } } });
  assert.notEqual(withEnv.verdict, 'ALLOW', 'LD_PRELOAD is part of what runs');
  assert.match(withEnv.command ?? '', /LD_PRELOAD/);
  const harmless = codexVerdict({ tool_name: 'local_shell', tool_input: { action: { type: 'exec', command: ['ls'], env: { FOO: 'bar' } } } });
  assert.equal(harmless.verdict, 'ALLOW');
  // a user other than the caller is another program with another authority: not read, asked about
  const user = codexVerdict({ tool_name: 'local_shell', tool_input: { action: { type: 'exec', command: ['ls'], user: 'root' } } });
  assert.notEqual(user.verdict, 'ALLOW');
  // an action that is not an exec is not a command
  const other = codexVerdict({ tool_name: 'local_shell', tool_input: { action: { type: 'something-else', command: ['ls'] } } });
  assert.notEqual(other.verdict, 'ALLOW');
  // an operand named twice is still refused, nested or not (the second key is not dropped on the way in)
  const twice = codexVerdict({ tool_name: 'local_shell', tool_input: { action: { type: 'exec', command: ['ls'], cmd: 'git push origin main' } } });
  assert.equal(twice.verdict, 'DENY');
  // an env that is not a plain name/value map is not read
  const odd = codexVerdict({ tool_name: 'local_shell', tool_input: { action: { type: 'exec', command: ['ls'], env: { 'A B': 'x' } } } });
  assert.notEqual(odd.verdict, 'ALLOW');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * E. THE WORK A DECISION SPENDS DEPENDS ON THE COMMAND ONLY (RB-7), AND EVERY READER OF UNBOUNDED INPUT PAYS FOR IT (property I)
 * ------------------------------------------------------------------------------------------------------------- */

const PROBE = new URL('./support/units-probe.ts', import.meta.url).pathname;
interface UnitsRun {
  commands: string[];
  first: string[];
  second: string[];
}
/** the probe in a child process: its own HOME and TMPDIR, its own checkout, and nothing else of this process's environment */
function unitsRun(home: string, tmp: string, dir: string, ...flags: string[]): UnitsRun {
  mkdirSync(dir, { recursive: true });
  const r = spawnSync(process.execPath, [PROBE, dir, ...flags], {
    env: { PATH: process.env['PATH'], HOME: home, TMPDIR: tmp, LANG: 'C' },
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    timeout: 240_000,
  });
  assert.equal(r.status, 0, `the probe failed: ${r.stderr.slice(0, 600)}`);
  return JSON.parse(r.stdout) as UnitsRun;
}
// (a command that names a directory of the machine it was made on - the corpus fixtures do - is not the same command on the other one)
const differing = (a: UnitsRun, b: UnitsRun, which: 'first' | 'second' = 'first'): string[] =>
  a.commands.flatMap((c, i) => (c !== b.commands[i] || a[which][i] === b[which][i] ? [] : [`${c.slice(0, 80)}: ${a[which][i]} | ${b[which][i]}`]));

test('E. RB-7: the units a decision spends do not depend on where the machine keeps HOME and its temporary files', () => {
  // ONE checkout (where it sits is part of the declared configuration), two machines: a HOME and a temporary directory with much
  // longer names
  const checkout = join(PARENT, 'checkout-a');
  const a = unitsRun(homeDir(), mkdtempSync(join(PARENT, 'tmp-')), checkout);
  const longHome = join(PARENT, 'a', 'home', 'directory', 'with', 'a', 'name', 'that', 'is', 'much', 'longer');
  const longTmp = join(PARENT, 'a', 'temporary', 'directory', 'with', 'a', 'much', 'longer', 'name');
  mkdirSync(longHome, { recursive: true });
  mkdirSync(longTmp, { recursive: true });
  const b = unitsRun(longHome, longTmp, checkout);
  assert.ok(a.commands.length > 250, `${a.commands.length} commands compared`);
  assert.equal(a.commands.filter((c, i) => c !== b.commands[i]).length < 8, true, 'nearly all of the commands compared are the same commands on both machines');
  assert.deepEqual(differing(a, b), [], 'the same command, a different machine');
});

test('E. RB-7: a HOME that is not there is not a different amount of work', () => {
  const checkout = join(PARENT, 'checkout-b');
  const a = unitsRun(homeDir(), mkdtempSync(join(PARENT, 'tmp-')), checkout);
  const b = unitsRun('/nonexistent/very/deep/home/directory', mkdtempSync(join(PARENT, 'tmp-')), checkout);
  // a command that MOVES INTO the home directory runs somewhere else when there is none: that is a different command line to analyse,
  // not a different price for the same one
  const moves = /cd\s+(~|\$\{?HOME)/;
  assert.deepEqual(
    differing(a, b).filter((l) => !moves.test(l.split(': ')[0]!)),
    [],
    'the same command, a machine with no home directory',
  );
});

test('E. RB-7: a process that has already decided a command spends the same units on it again (a memo saves time, not the bound)', () => {
  const run = unitsRun(homeDir(), mkdtempSync(join(PARENT, 'tmp-')), join(PARENT, 'checkout-warm'), '--twice');
  assert.deepEqual(differing(run, { ...run, first: run.second }, 'first'), [], 'cold against warm, in one process');
  assert.ok(run.first.some((l) => /git/.test(run.commands[run.first.indexOf(l)] ?? '')));
});

/* ------------------------------------------------------------------------------------------------------------- *
 * F. SESSION STATE UNDER CONCURRENCY AND IDLE TIME (RB-2, RB-3)
 * ------------------------------------------------------------------------------------------------------------- */

/** a governed project and a hook runtime in process, with a clock a test moves */
function hookProject(profile = 'STANDARD'): { root: string; rt: HookRuntime; advance: (ms: number) => void } {
  const root = repo();
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
  let clock = Date.UTC(2026, 8, 14, 10, 0, 0);
  const rt: HookRuntime = {
    projectRoot: root,
    pin: readPin(root),
    now: () => new Date((clock += 1000)).toISOString(),
    controlPlaneRoot: CP,
    env: { EGO_HOME: mkdtempSync(join(PARENT, 'h-')), CLAUDE_PROJECT_DIR: root },
  };
  return { root, rt, advance: (ms) => void (clock += ms) };
}
const hookEv = (root: string, event: HookEvent['event'], extra: Partial<HookEvent> = {}): HookEvent => ({
  host: 'claude-code',
  event,
  sessionId: 's1',
  cwd: root,
  raw: {},
  ...extra,
});
const pre = (root: string, command: string, sessionId = 's1'): HookEvent =>
  hookEv(root, 'PreToolUse', { sessionId, tool: { name: 'Bash', input: { command } } });
const post = (root: string, command: string, response: unknown, sessionId = 's1'): HookEvent =>
  hookEv(root, 'PostToolUse', { sessionId, tool: { name: 'Bash', input: { command }, response } });
const MINUTE = 60_000;

test('F. RB-3: the duration budget counts ACTIVITY: a session that sat idle overnight is not over its time', () => {
  for (const profile of ['STANDARD', 'STRICT'] as const) {
    const { root, rt, advance } = hookProject(profile);
    assert.equal(handleHook(pre(root, 'ls'), rt).action, 'allow', `${profile}: at the start`);
    advance(9 * 60 * MINUTE);
    const later = handleHook(pre(root, 'ls'), rt);
    assert.equal(later.action, 'allow', `${profile}: the same session nine hours later (${later.reason?.slice(0, 120)})`);
    // a host session that sends no session id shares one record, and the gap between two host sessions is idle time too
    assert.equal(handleHook(pre(root, 'ls', 'unknown-session'), rt).action, 'allow');
    advance(9 * 60 * MINUTE);
    assert.equal(handleHook(pre(root, 'ls', 'unknown-session'), rt).action, 'allow', `${profile}: a second host session without an id`);
  }
});

test('F. RB-3: ...and a session that is really at work for longer than its budget still is over it', () => {
  const { root, rt, advance } = hookProject('STANDARD'); // 480 minutes
  let action = 'allow';
  let at = 0;
  // an event every twenty minutes, the way a working session behaves: no gap is long enough to be idle
  for (let i = 0; i < 40 && action === 'allow'; i++) {
    advance(20 * MINUTE);
    action = handleHook(pre(root, 'ls'), rt).action;
    at = (i + 1) * 20;
  }
  assert.equal(action, 'ask', 'the budget escalates');
  assert.ok(at > 470 && at < 520, `after ${at} active minutes`);
});

test('F. RB-3: the retry key is the whole step: two commands that share an eighty-character prefix are two steps', () => {
  const { root, rt } = hookProject('STANDARD');
  // (read-only commands: the steps are ALLOW on their own, so that what the hook says about them is about the retries and nothing else)
  const common = 'echo checking the project at some long directory name that goes on and on before the last segment: ';
  assert.ok(common.length >= 80, `${common.length}`);
  for (let k = 0; k < 4; k++) handleHook(post(root, `${common}alpha`, { is_error: true }), rt);
  assert.equal(handleHook(pre(root, `${common}alpha`), rt).action, 'ask', 'the step that failed is stopped');
  assert.equal(handleHook(pre(root, `${common}beta`), rt).action, 'allow', 'an unrelated step that begins the same way is not');
  assert.equal(handleHook(pre(root, 'ls'), rt).action, 'allow');
  // spelled with other whitespace or a trailing comment it is still the same step
  assert.equal(handleHook(pre(root, `${common}alpha   # again`), rt).action, 'ask');
});

test('F. RB-3: a failed tool call is read from every field a host puts a failure in', () => {
  const shapes: Array<[string, unknown]> = [
    ['exit_code', { exit_code: 1 }],
    ['exitCode', { exitCode: 2 }],
    ['is_error', { is_error: true }],
    ['isError', { isError: true }],
    ['interrupted', { stdout: '', stderr: '', interrupted: true, isImage: false }],
    ['success false', { success: false }],
    ['an error text', { error: 'command failed' }],
  ];
  const missed: string[] = [];
  for (const [label, response] of shapes) {
    const { root, rt } = hookProject('STANDARD');
    for (let k = 0; k < 4; k++) handleHook(post(root, 'make flaky', response), rt);
    if (handleHook(pre(root, 'make flaky'), rt).action !== 'ask') missed.push(label);
  }
  assert.deepEqual(missed, []);
  // a response that says nothing of failure is not one
  const { root, rt } = hookProject('STANDARD');
  for (let k = 0; k < 6; k++) handleHook(post(root, 'make fine', { stdout: 'ok', stderr: '', interrupted: false, isImage: false }), rt);
  assert.equal(handleHook(pre(root, 'make fine'), rt).action, 'allow');
});

test('F. RB-2: parallel hooks of one session are serialised, not refused: forty concurrent PreToolUse, every counter exact', async () => {
  const dir = repo();
  const env = humanEnv(homeDir());
  assert.equal((await ego(['init'], dir, env)).code, 0);
  const N = 40;
  const MAIN = new URL('../../cli/src/main.ts', import.meta.url).pathname;
  const hostEnv = { ...env, CLAUDE_PROJECT_DIR: dir };
  // a line that takes real time to decide (three git commands: processes are spawned), so that the decisions overlap
  const command = 'git status --short && git log -1 --format=%h && git diff --stat';
  const children = Array.from({ length: N }, () =>
    new Promise<{ code: number | null; err: string }>((resolve) => {
      const c = spawn(process.execPath, [MAIN, 'hook', 'claude-code', 'PreToolUse'], { cwd: dir, env: hostEnv });
      let err = '';
      c.stderr.on('data', (d) => (err += d));
      c.stdin.end(JSON.stringify({ session_id: 'shared', cwd: dir, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } }));
      c.on('close', (code) => resolve({ code, err }));
    }),
  );
  const results = await Promise.all(children);
  const refused = results.filter((r) => r.code !== 0).map((r) => r.err.split('\n')[0]);
  assert.deepEqual(refused, [], 'no hook was refused for waiting');
  const session = JSON.parse(readFileSync(join(dir, '.harness', 'runtime', 'sessions', 'shared.json'), 'utf8'));
  assert.equal(session.counters.toolCalls, N, 'no counter update was lost');
  const ledger = readdirSync(join(dir, '.harness', 'runtime', 'ledger'))
    .flatMap((f) => readFileSync(join(dir, '.harness', 'runtime', 'ledger', f), 'utf8').split('\n'))
    .filter((l) => l.includes('"tool.pre"') && l.includes('"shared"'));
  assert.equal(ledger.length, N, 'and every decision is in the ledger');
});

test('F. RB-2: the decision is made outside the lock: what is held is the read-modify-write of the record, in milliseconds', () => {
  const src = readFileSync(new URL('../src/hooks/handle.ts', import.meta.url), 'utf8');
  const handle = src.slice(src.indexOf('export function handleHook'), src.indexOf('function handleLocked'));
  assert.match(handle, /precomputeEvaluation\(/, 'handleHook evaluates before it takes the lock');
  assert.ok(handle.indexOf('precomputeEvaluation(') < handle.indexOf('withSessionLock('), 'the evaluation precedes the lock');
  const root = readFileSync(new URL('../src/runtime/root.ts', import.meta.url), 'utf8');
  const lock = /opts\.timeoutMs \?\? (\d+)/.exec(root)?.[1];
  assert.ok(lock && Number(lock) >= 8000, `a waiter waits at least 8 s (it holds nothing but milliseconds), not ${lock}`);
  const stale = /opts\.staleMs \?\? (\d+)/.exec(root)?.[1];
  assert.ok(stale && Number(stale) > 30_000, `a live holder is never displaced inside the host's 30 s hook budget, not ${stale}`);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * G. A GRANT PHRASE LIFTS THE REAL COMMAND IT NAMES (AUTH-7); A REFUSAL NAMES THE RULE THAT IS REALLY ITS SOURCE (AUTH-8, AUTH-9);
 *    EVERY CAPABILITY HAS A PRODUCER OR IS RESERVED (AUTH-14)
 * ------------------------------------------------------------------------------------------------------------- */

const cpData = loadControlPlane(CP);
const enabledTable = (() => {
  const dir = repo({ 'policies/organization/permissions.md': ORG_ENABLES_ALL });
  return ensurePolicyCache(CP, dir, SELF, { acceptWidening: true }).cache.table;
})();
const decide = (t: Table, command: string, over: Partial<Parameters<typeof evaluate>[1]> = {}) => {
  const dir = workspace({ x: 'echo hi\n' });
  return evaluate(t, { ...ctx(dir), ...over }, { tool: 'Bash', input: { command } });
};

test('G. AUTH-8: the source a refusal names is the rule that set the verdict, for every capability in every profile and mode', () => {
  const wrong: string[] = [];
  for (const p of cpData.profiles)
    for (const m of cpData.modes)
      for (const id of Object.keys(table.capabilities)) {
        // the oracle is the authored files, not the table: the layered verdict, then the profile's narrowing (never a widening), then the mode's override
        const layered = table.effective[id]!;
        const narrow = p.narrow.find((n) => n.capability === id);
        const afterProfile = narrow && RANK_OF[narrow.verdict]! >= RANK_OF[layered]! ? narrow.verdict : layered;
        const override = table.capabilities[id]!.absolute ? undefined : m.overrides.find((o) => o.capability === id);
        const cell = override ? override.verdict : afterProfile;
        const truth = override && override.verdict !== afterProfile ? `mode ${m.id}` : afterProfile !== layered ? `profile ${p.id}` : null;
        const got = verdictSource(table, p.id, m.id, id).layer;
        const gotMoved = /^(profile|mode) /.test(got) ? got : null;
        if (gotMoved !== truth) wrong.push(`${p.id}/${m.id} ${id} (${cell}): ${gotMoved ?? 'layered'} against ${truth ?? 'layered'}`);
      }
  assert.deepEqual(wrong, []);
});

const RANK_OF: Record<string, number> = { ALLOW: 0, ASK: 1, DENY: 2 };

test('G. AUTH-8: `git commit` in the default profile of a consumer repository cites STRICT, not a mode that has no override', () => {
  for (const cmd of ['git commit -m x', 'git merge topic']) {
    const r = decide(table, cmd, { profile: 'STRICT', mode: 'NORMAL_DELIVERY' });
    assert.equal(r.verdict, 'ASK', cmd);
    assert.match(r.reason, /Rule source: profile STRICT/, `${cmd}: ${r.reason}`);
    assert.doesNotMatch(r.reason, /Rule source: mode NORMAL_DELIVERY/);
  }
  const v = describeCapability(table, 'STRICT', 'NORMAL_DELIVERY', 'git.local.commit')!;
  assert.match(v.source, /^profile STRICT/);
  // and where a MODE did move it, the mode is named
  assert.match(describeCapability(table, 'STRICT', 'PRODUCTION_ADVISORY', 'git.local.commit')!.source, /^mode PRODUCTION_ADVISORY/);
});

test('G. AUTH-8: while an organization widening is pending, the DENY in force cites the rule that is in force and says a widening waits', () => {
  const dir = repo({ 'policies/organization/permissions.md': ORG_ENABLES_ALL });
  const pending = ensurePolicyCache(CP, dir, SELF).cache;
  assert.ok(pending.pendingWidening);
  const r = evaluate(pending.table, { ...ctx(dir), repoRoots: [dir], cwd: dir }, { tool: 'Bash', input: { command: 'git push origin feature' } });
  assert.equal(r.verdict, 'DENY');
  assert.doesNotMatch(r.reason, /organization \(widened/, r.reason);
  assert.match(r.reason, /Rule source: ADMIN_GOVERNED, admin-governed/);
  assert.match(r.reason, /awaiting|awaits/, 'and it says the widening is waiting for a human');
  assert.equal(describeCapability(pending.table, 'STANDARD', 'NORMAL_DELIVERY', 'git.remote.push')!.source.startsWith('organization'), false);
  // after acceptance the organization is the source, as it should be
  const accepted = ensurePolicyCache(CP, dir, SELF, { acceptWidening: true }).cache;
  assert.match(describeCapability(accepted.table, 'STANDARD', 'NORMAL_DELIVERY', 'git.remote.push')!.source, /^organization/);
});

test('G. AUTH-9: a mode may narrow an ADMIN_GOVERNED capability and never widen one: BENCHMARK and PRODUCTION_ADVISORY keep their word once an organization enables the writes', () => {
  const failures: string[] = [];
  const adminGoverned = enabledTable.adminGoverned;
  assert.ok(adminGoverned.length > 15);
  for (const profile of Object.keys(enabledTable.profiles)) {
    for (const id of adminGoverned) {
      const cell = (mode: string) => enabledTable.profiles[profile]!.modes[mode]![id];
      // the ordinary mode: the organization's enablement is in force, at the ceiling
      if (cell('NORMAL_DELIVERY') !== 'ASK' && profile !== 'HIGH_ASSURANCE') failures.push(`${profile}/NORMAL_DELIVERY ${id}: ${cell('NORMAL_DELIVERY')}`);
      // "denies every forge write" - and a push to a real remote is the same leak
      if ((id.startsWith('forge.') || id.startsWith('git.remote.')) && cell('BENCHMARK') !== 'DENY') failures.push(`${profile}/BENCHMARK ${id}: ${cell('BENCHMARK')}`);
      // "nothing executes"
      if (cell('PRODUCTION_ADVISORY') !== 'DENY') failures.push(`${profile}/PRODUCTION_ADVISORY ${id}: ${cell('PRODUCTION_ADVISORY')}`);
    }
  }
  assert.deepEqual(failures, []);
});

test('G. AUTH-9: ...through the real commands: push, PR create and an API write are refused in both modes, and still ask in the ordinary one', () => {
  for (const cmd of ['git push origin feature', 'gh pr create --title x --body y', 'gh api repos/o/r/issues -X POST -f title=x', 'gh issue create --title x --body y', 'git push origin --delete old']) {
    assert.equal(decide(enabledTable, cmd, { mode: 'NORMAL_DELIVERY' }).verdict, 'ASK', `${cmd} in NORMAL_DELIVERY`);
    for (const mode of ['BENCHMARK', 'PRODUCTION_ADVISORY']) assert.equal(decide(enabledTable, cmd, { mode }).verdict, 'DENY', `${cmd} in ${mode}`);
  }
  // BENCHMARK keeps denying the comment (it always did) and nothing else changed for a read
  assert.equal(decide(enabledTable, 'gh issue comment 3 --body x', { mode: 'BENCHMARK' }).verdict, 'DENY');
  assert.equal(decide(enabledTable, 'gh pr view 3', { mode: 'BENCHMARK' }).verdict, 'ALLOW');
});

test('G. AUTH-9: the loader lets a mode DENY an ADMIN_GOVERNED capability and refuses every other verdict for one', () => {
  const copy = (verdict: string): (() => unknown) => () => {
    const dir = mkdtempSync(join(PARENT, 'cp-'));
    cpSync(CP, dir, { recursive: true });
    const f = join(dir, 'modes', 'benchmark.md');
    writeFileSync(f, readFileSync(f, 'utf8').replace(/(- capability: forge\.pr\.create\n\s+verdict: )DENY/, `$1${verdict}`));
    return loadControlPlane(dir);
  };
  assert.doesNotThrow(copy('DENY'));
  for (const v of ['ASK', 'ALLOW']) assert.throws(copy(v), /mode may not widen ADMIN_GOVERNED capability "forge\.pr\.create"/, v);
  // the authored modes list every administrable write they name by id, and a new one fails here until it is listed
  const modes = new Map(cpData.modes.map((m) => [m.id, new Set(m.overrides.filter((o) => o.verdict === 'DENY').map((o) => o.capability))]));
  const admin = table.adminGoverned;
  assert.deepEqual(admin.filter((id) => (id.startsWith('forge.') || id.startsWith('git.remote.')) && !modes.get('BENCHMARK')!.has(id)), [], 'BENCHMARK');
  assert.deepEqual(admin.filter((id) => !modes.get('PRODUCTION_ADVISORY')!.has(id)), [], 'PRODUCTION_ADVISORY');
});

/** For every row of grants.md: a command that REALLY IS the capability, and whether the phrase lifts it. A row without an entry here fails
 *  the test that reads the table, so a phrase added to the vocabulary cannot be added without the command it is for. */
const GRANT_SPELLINGS: Record<string, { command: string; lifts: boolean; why?: string }> = {
  'git.local.commit': { command: 'git commit -m x', lifts: true },
  'git.local.amend': { command: 'git commit --amend --no-edit', lifts: true },
  'git.local.rebase': { command: 'git rebase main', lifts: true },
  'git.local.reset': { command: 'git reset --hard', lifts: true },
  'git.local.restore': { command: 'git restore src/a.ts', lifts: true },
  'git.local.clean': { command: 'git clean -fd', lifts: true },
  'git.local.branch.delete': { command: 'git branch -D topic', lifts: true },
  'forge.issue.assign': { command: 'gh issue edit 3 --add-assignee octocat', lifts: false, why: 'an external effect: the ceiling is ASK' },
  'forge.issue.comment': { command: 'gh issue comment 3 --body x', lifts: false, why: 'an external effect: the ceiling is ASK' },
  'forge.review.thread.resolve': { command: 'gh pr review 3 --comment --body x', lifts: false, why: 'an external effect: the ceiling is ASK' },
  'forge.review.comment': { command: 'gh pr review 3 --comment --body x', lifts: false, why: 'an external effect: the ceiling is ASK' },
  'db.local.drop': { command: 'psql -h localhost -c "DROP DATABASE app"', lifts: true },
  'container.prune': { command: 'docker system prune -f', lifts: true },
  'k8s.local.delete': { command: 'kubectl --context kind-dev delete namespace foo', lifts: true },
  'ego.skills.install': { command: 'ego skills install some-skill', lifts: true },
  'ego.pin.change': { command: 'ego upgrade', lifts: true },
  'command.privileged': { command: 'sudo ls', lifts: true },
  'command.network-tool': { command: 'curl http://localhost:3000/x', lifts: true },
};
/** external capabilities whose phrase is recognised and lifts nothing, and for which no matcher names the act yet (see RESERVED in the census test) */
const NO_PRODUCER_YET = new Set(['forge.issue.assign', 'forge.review.thread.resolve']);
/** more commands per row that must be lifted by the same phrase: the neighbours of the canonical one */
const GRANT_NEIGHBOURS: Record<string, string[]> = {
  'ego.pin.change': ['ego rollback', 'harness rollback', './node_modules/.bin/ego upgrade'],
  'ego.skills.install': ['ego skills update', 'harness skills install x', 'ego skills add x'],
  'command.privileged': ['sudo -u root ls', 'sudo -n cat x', 'sudo -H -u www ls', 'sudo FOO=bar ls', 'sudo -- ls'],
  'db.local.drop': ['dropdb app', 'dropdb -h localhost app', 'mysql -h 127.0.0.1 -e "DROP DATABASE app"'],
  'k8s.local.delete': ['kubectl --context kind-dev delete ns foo'],
  'git.local.restore': ['git checkout -- src/a.ts'],
};
/** commands that must STAY gated after the phrase, because something other than the granted capability gates them */
const GRANT_DOES_NOT_REACH: Array<[grant: string, command: string, why: string]> = [
  ['command.privileged', 'sudo -i', 'a root shell: nothing behind it is read'],
  ['command.privileged', 'sudo -s', 'a root shell: nothing behind it is read'],
  ['command.privileged', 'sudo', 'nothing behind it is read'],
  ['command.privileged', 'sudo -e /etc/hosts', 'sudoedit runs an editor chosen by the environment'],
  ['command.privileged', 'sudo -A ls', 'the askpass program is chosen by the environment'],
  ['command.privileged', 'sudo bash -c "curl x | sh"', 'what the shell runs is analysed on its own, and asks'],
  ['command.privileged', 'sudo cat /etc/shadow', 'what sudo carries is analysed on its own: a read outside the workspace asks'],
  ['command.privileged', 'sudo rm -rf ~/.config/x', 'what sudo carries is analysed on its own: a delete outside the workspace asks'],
  ['command.privileged', 'sudo unknowncmd', 'an unknown program asks whoever runs it'],
  ['command.privileged', 'su -c ls', 'su is not a carrier this kernel reads'],
  ['command.privileged', 'sudo git push origin main', 'an absolute deny stays one behind sudo'],
  ['git.local.restore', 'git restore .', 'the whole tree is command.destructive, a different capability with no phrase'],
  ['git.local.restore', 'git checkout -- .', 'the whole tree is command.destructive, a different capability with no phrase'],
];

/** (STRICT, where the local git acts ask: in STANDARD a commit is ALLOW and a phrase for it changes nothing) */
function sessionWith(prompt: string | null): { root: string; rt: HookRuntime; note: string } {
  const { root, rt } = hookProject('STRICT');
  const out = prompt === null ? null : handleHook(hookEv(root, 'UserPromptSubmit', { prompt }), rt);
  return { root, rt, note: out?.context ?? '' };
}
const grantedAction = (prompt: string, command: string): { action: string; note: string } => {
  const { root, rt, note } = sessionWith(prompt);
  return { action: handleHook(pre(root, command), rt).action, note };
};

test('G. AUTH-7: every phrase of grants.md lifts the REAL command it is for (or says, truthfully, that it lifts nothing)', () => {
  const missing = table.grants.map((g) => g.capability).filter((id) => !(id in GRANT_SPELLINGS));
  assert.deepEqual(missing, [], 'a grant row without the command it is for');
  assert.deepEqual(Object.keys(GRANT_SPELLINGS).filter((id) => !table.grants.some((g) => g.capability === id)), [], 'a spelling for a row that is gone');
  const failures: string[] = [];
  for (const g of table.grants) {
    const { command, lifts, why } = GRANT_SPELLINGS[g.capability]!;
    // the command IS the capability: without the phrase, the capability is among the hits and the call asks
    const bare = decide(table, command);
    if (!NO_PRODUCER_YET.has(g.capability) && !bare.hits.some((h) => h.capability === g.capability)) failures.push(`${g.capability}: \`${command}\` does not reach it (${bare.hits.map((h) => h.capability).join(', ')})`);
    const phrase = g.phrases.find((p) => /^[a-z' ]+$/.test(p)) ?? g.phrases[0]!;
    const r = grantedAction(phrase, command);
    if (lifts && r.action !== 'allow') failures.push(`${g.capability}: "${phrase}" then \`${command}\` is ${r.action}`);
    if (!lifts && r.action === 'allow') failures.push(`${g.capability}: "${phrase}" lifted an external effect (${why})`);
    // what the hook says about the phrase is true of the command
    if (lifts && !/grant recorded/.test(r.note)) failures.push(`${g.capability}: the hook did not record it (${r.note})`);
    if (!lifts && !/does not lift it|a grant changes nothing|is an external effect/.test(r.note)) failures.push(`${g.capability}: the hook claims more than it does (${r.note})`);
  }
  assert.deepEqual(failures, []);
});

test('G. AUTH-7: ...in every neighbouring spelling of the command, in every phrase of the row', () => {
  const failures: string[] = [];
  for (const [id, commands] of Object.entries(GRANT_NEIGHBOURS)) {
    const row = table.grants.find((g) => g.capability === id)!;
    for (const c of commands) {
      const bare = decide(table, c);
      if (bare.verdict === 'ALLOW') failures.push(`${id}: \`${c}\` is ALLOW without the phrase`);
      const r = grantedAction(row.phrases.find((p) => /^[a-z' ]+$/.test(p)) ?? row.phrases[0]!, c);
      if (r.action !== 'allow') failures.push(`${id}: \`${c}\` stays ${r.action} (${bare.hits.map((h) => `${h.verdict} ${h.capability}`).join(', ')})`);
    }
    for (const phrase of row.phrases.filter((p) => /^[a-z' ]+$/.test(p))) {
      const r = grantedAction(phrase, GRANT_SPELLINGS[id]!.command);
      if (GRANT_SPELLINGS[id]!.lifts && r.action !== 'allow') failures.push(`${id}: the phrase "${phrase}" does not lift it`);
    }
  }
  assert.deepEqual(failures, []);
});

test('G. AUTH-7: a grant lifts the capability it names and NOTHING else gating the same command', () => {
  const lifted: string[] = [];
  for (const [grant, command, why] of GRANT_DOES_NOT_REACH) {
    const row = table.grants.find((g) => g.capability === grant)!;
    const r = grantedAction(row.phrases.find((p) => /^[a-z' ]+$/.test(p)) ?? row.phrases[0]!, command);
    if (r.action === 'allow') lifted.push(`"${row.phrases[0]}" lifted \`${command}\` (${why})`);
  }
  assert.deepEqual(lifted, []);
  // and what the hook tells the person is true: it names the limit
  const note = sessionWith('you can use sudo').note;
  assert.match(note, /grant recorded, command\.privileged is ALLOW for this session/);
  assert.match(note, /other rules|also gate/, 'a command that other rules also gate still asks: the hook says so');
});

test('G. AUTH-7: the commands the ego.* grant rows are for exist as matchers: `ego upgrade` and `ego skills install` are no longer an unknown command', () => {
  for (const [cmd, cap] of [
    ['ego upgrade', 'ego.pin.change'],
    ['ego rollback', 'ego.pin.change'],
    ['ego skills install x', 'ego.skills.install'],
    ['ego skills update', 'ego.skills.install'],
  ] as const) {
    const r = decide(table, cmd);
    assert.equal(r.decisive?.capability, cap, cmd);
    assert.equal(r.verdict, 'ASK', cmd);
  }
  // ...and BENCHMARK's "every Harness self-change is denied" is true of them at last
  assert.equal(decide(table, 'ego upgrade', { mode: 'BENCHMARK' }).verdict, 'DENY');
  assert.equal(decide(table, 'ego skills install x', { mode: 'BENCHMARK' }).verdict, 'DENY');
  // reading about them is not them
  for (const c of ['grep -rn "ego upgrade" docs/', 'echo ego upgrade', 'cat docs/ego-skills-install.md']) assert.notEqual(decide(table, c).decisive?.capability, 'ego.pin.change', c);
});

test('G. AUTH-7: `ego init` and `ego sync`, run from a tool call, ask as what they are: the acceptance of whatever the layer files hold', () => {
  for (const c of ['ego init', 'ego sync', 'npx ego init', 'ego init --profile STANDARD', 'harness init']) {
    const r = decide(table, c);
    assert.equal(r.decisive?.capability, 'ego.policy.accept', c);
    assert.equal(r.verdict, 'ASK', c);
    assert.match(r.reason, /accept/i);
  }
  for (const c of ['ego doctor', 'ego status', 'ego check', 'ego capabilities']) assert.notEqual(decide(table, c).decisive?.capability, 'ego.policy.accept', `${c}: a command that accepts nothing is not that`);
  // no phrase lifts it: it is not a row of grants.md
  assert.ok(!table.grants.some((g) => g.capability === 'ego.policy.accept'));
});

test('G. AUTH-14: every capability has a producer - a matcher, a place in the evaluator, or a spelling the corpus reaches - or is RESERVED, with the reason', () => {
  const RESERVED: Record<string, string> = {
    // db.local.* verbs beyond the four the evaluator classifies: a database client's verbs are read as statements, not as capabilities
    'db.local.analyze': 'statements are classified as db.local.query / migrate / drop; a finer verb has no reader yet',
    'db.local.backup': 'statements are classified as db.local.query / migrate / drop; a finer verb has no reader yet',
    'db.local.create': 'statements are classified as db.local.query / migrate / drop; a finer verb has no reader yet',
    'db.local.restore': 'statements are classified as db.local.query / migrate / drop; a finer verb has no reader yet',
    'db.local.seed': 'statements are classified as db.local.query / migrate / drop; a finer verb has no reader yet',
    // the MCP families: every mcp__server__tool call is mcp.unknown until the trust resolver exists (EGO issue #10, deferred)
    'mcp.local.browser': 'MCP trust resolver (issue #10, phase 2): every MCP tool is mcp.unknown until it exists',
    'mcp.local.container': 'MCP trust resolver (issue #10, phase 2)',
    'mcp.local.database': 'MCP trust resolver (issue #10, phase 2)',
    'mcp.local.execute': 'MCP trust resolver (issue #10, phase 2)',
    'mcp.local.filesystem': 'MCP trust resolver (issue #10, phase 2)',
    'mcp.local.kubernetes': 'MCP trust resolver (issue #10, phase 2)',
    'mcp.local.privileged': 'MCP trust resolver (issue #10, phase 2); HARD_LOCK, so nothing widens it before it exists',
    'mcp.local.write': 'MCP trust resolver (issue #10, phase 2)',
    'mcp.remote.discover': 'MCP trust resolver (issue #10, phase 2)',
    'mcp.remote.narrow-write': 'MCP trust resolver (issue #10, phase 2)',
    'mcp.remote.privileged': 'MCP trust resolver (issue #10, phase 2); HARD_LOCK',
    'mcp.remote.production.mutate': 'MCP trust resolver (issue #10, phase 2); HARD_LOCK',
    'mcp.remote.read': 'MCP trust resolver (issue #10, phase 2)',
    // forge verbs the CLI matchers do not name separately: they are judged as forge.api.mutate / forge.issue.comment today
    'forge.issue.assign': 'forge adapters (phase 2): `gh issue edit --add-assignee` is forge.issue.edit today; the phrase is recognised and lifts nothing (external)',
    'forge.review.thread.reply': 'forge adapters (phase 2): a review-thread reply is a GraphQL mutation, forge.api.mutate today',
    'forge.review.thread.resolve': 'forge adapters (phase 2): a thread resolution is a GraphQL mutation, forge.api.mutate today',
    // the local file families whose only producers are the path rules of other capabilities
    'fs.local-config.write': 'no path rule maps a local configuration file to it yet; such a write is fs.repo.write / ego.* today',
    'fs.repo.mkdir': '`mkdir` is command.local-mutation today',
    'fs.runtime.write': 'the kernel writes the runtime tree itself; an agent write to it is ego.runtime.tamper (absolute)',
    // the ego.* self-capabilities that are the KERNEL'S OWN acts, not an agent's command
    'ego.evidence.export': 'evidence bundles are phase 4; no command exports them yet',
    'ego.generated.regenerate': 'the kernel regenerates generated artifacts itself; the commands that do (init, sync) are ego.policy.accept',
    'ego.overlay.edit': 'an edit of the overlay is an ordinary workspace write today (and a narrowing, by construction)',
    'ego.sync.network': 'the sync network reads are phase 6 (remote adapters)',
    'ego.decision.answer': 'the human decision gate is phase 5; `ego decision answer` is ego.gate.bypass (absolute) today, which is the same refusal',
    // HARD_LOCK network and production families whose finer attribution is judged as the umbrella today
    'network.internal-dev': 'no matcher separates an internal development endpoint from network.external-write / network.localhost',
    'network.production': 'a request to production is judged by its host: network.external-write, or production.* for a cloud CLI',
    'network.public-write': 'a public write is network.external-write today (ASK; DENY in HIGH_ASSURANCE)',
    'production.feature-flags.mutate': 'cloud-CLI production mutations are production.cloud.mutate (the same HARD_LOCK DENY); a finer attribution has no reader',
    'production.messaging.mutate': 'cloud-CLI production mutations are production.cloud.mutate (the same HARD_LOCK DENY); a finer attribution has no reader',
    'production.storage.mutate': 'cloud-CLI production mutations are production.cloud.mutate (the same HARD_LOCK DENY); a finer attribution has no reader',
  };
  const root = new URL('../../', import.meta.url);
  let code = '';
  const walk = (dir: URL): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const u = new URL(e.name + (e.isDirectory() ? '/' : ''), dir);
      if (e.isDirectory()) walk(u);
      else if (e.name.endsWith('.ts')) code += `\n${readFileSync(u, 'utf8')}`;
    }
  };
  for (const pkg of ['kernel', 'cli']) walk(new URL(`${pkg}/src/`, root));
  const viaMatcher = new Set(table.matchers.map((m) => m.capability));
  const unproduced = Object.keys(table.capabilities)
    .filter((id) => !viaMatcher.has(id) && !code.includes(`'${id}'`) && !code.includes(`"${id}"`) && !code.includes(`\`${id}\``))
    .sort();
  assert.deepEqual(unproduced, Object.keys(RESERVED).sort(), 'a capability gained or lost its producer: list it as reserved (with the reason) or give it one');
  for (const [id, why] of Object.entries(RESERVED)) assert.ok(why.length > 20, `${id} says why`);
});
