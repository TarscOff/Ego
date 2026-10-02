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
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { main } from '../../cli/src/main.ts';
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
import { table } from './support/corpus.ts';

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
