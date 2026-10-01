// CLOSURE OF THE STRUCTURED-TOOL SURFACE (audit of 2026-10-01, items 7, 8, 9, 10, 13 and criterion C3).
//
// Everything here is a call that is NOT a Bash string — Write, Edit, MultiEdit, NotebookEdit, apply_patch, Read, Grep,
// Glob, LS, WebFetch, WebSearch, an MCP tool, a tool nobody modelled — and the two host adapters that turn a raw
// host payload into one. The earlier pins covered the REPORTED spelling of each finding (`Move to:` in column 0, a
// Write with no operand); the audit re-ran them and found the class still open one spelling away. So each group
// below pins the class, at the evaluator AND through the real hook path (raw host JSON -> parse*Event ->
// handleHook -> render*), and every group was written to fail on the tree it was found on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { evaluate, type EvaluationContext, type Evaluation } from '../src/authority/evaluate.ts';
import { writePin, readPin } from '../src/launcher/pin.ts';
import { selfIdentity, selfVersion } from '../src/launcher/self.ts';
import { runCommand, type ProjectContext } from '../../cli/src/commands.ts';
import { table, workspace } from './support/corpus.ts';

const HOME = homedir();

type Profile = 'STANDARD' | 'STRICT' | 'HIGH_ASSURANCE';
const egoHome = mkdtempSync(join(tmpdir(), 'ego-closure-home-'));

/** the evaluator, in a throwaway repository, in `profile` (STANDARD / NORMAL_DELIVERY unless said otherwise) */
function evalIn(
  dir: string,
  tool: string,
  input: Record<string, unknown>,
  profile: Profile = 'STANDARD',
): Evaluation {
  const ctx: EvaluationContext = { profile, mode: 'NORMAL_DELIVERY', repoRoots: [dir], cwd: dir, egoHome };
  return evaluate(table, ctx, { tool, input });
}

const caps = (e: Evaluation): string => e.hits.map((h) => h.capability).join(',');

/** a fresh consumer project pinned to `profile`, for the REAL hook path */
function project(
  profile: Profile = 'STANDARD',
  prePromotion = false,
): { root: string; project: ProjectContext; env: NodeJS.ProcessEnv } {
  const root = mkdtempSync(join(tmpdir(), 'ego-closure-proj-'));
  const gitEnv: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!/^GIT_/.test(k)) gitEnv[k] = v;
  spawnSync('git', ['init', '-q'], { env: gitEnv, cwd: root });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'demo', scripts: {} }));
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
  const env: NodeJS.ProcessEnv = { ...process.env, EGO_HOME: mkdtempSync(join(tmpdir(), 'ego-closure-h-')), CLAUDE_PROJECT_DIR: root };
  return { root, project: { root, pin: readPin(root), prePromotion }, env };
}

let tick = 0;
interface HookResult {
  code: number;
  /** what the host is told: claude-code `permissionDecision`, codex-cli `decision` */
  action: string;
  reason: string;
  out: string;
}
/** `ego hook <host> PreToolUse` with the host's raw JSON on stdin: the path a real host drives */
async function hook(
  p: ReturnType<typeof project>,
  host: 'claude-code' | 'codex-cli',
  payload: Record<string, unknown>,
): Promise<HookResult> {
  let out = '';
  const code = await runCommand(
    ['hook', host, 'PreToolUse'],
    {
      cwd: p.root,
      env: p.env,
      stdin: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: `s${tick}`, cwd: p.root, ...payload }),
      out: (s) => (out += s),
      err: () => undefined,
      now: () => new Date(Date.UTC(2026, 9, 1, 10, 0, tick++ % 59)).toISOString(),
    },
    p.project,
  );
  const j = JSON.parse(out || '{}') as {
    hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string };
    decision?: string;
    reason?: string;
  };
  return host === 'claude-code'
    ? {
        code,
        action: String(j.hookSpecificOutput?.permissionDecision ?? 'none'),
        reason: String(j.hookSpecificOutput?.permissionDecisionReason ?? ''),
        out,
      }
    : { code, action: String(j.decision ?? 'none'), reason: String(j.reason ?? ''), out };
}
/** claude-code spells a call `tool_name` + `tool_input` */
const cc = (name: string, input: unknown) => ({ tool_name: name, tool_input: input });

/** an apply_patch body: the lines between Begin and End */
const patch = (...lines: string[]) => `*** Begin Patch\n${lines.join('\n')}\n*** End Patch`;
const BODY = ['@@', '-a', '+b'];

/* ------------------------------------------------------------------------------------------------------------- *
 * 2. A PATH IS JUDGED BY WHAT IT RESOLVES TO (audit C3)
 *
 * `realpath` fails on a link whose target does not exist yet exactly as it fails on a file that was never created, and
 * the fallback judged the link's own name — an ordinary repository path — while `open(O_CREAT)` follows the link and
 * creates the target. A link shipped inside a cloned repository is enough; nothing has to make it in-session.
 * ------------------------------------------------------------------------------------------------------------- */

let seq = 0;
/** a name under ~/.ssh that is never created: the tests only make LINKS to it */
const newCred = () => `${HOME}/.ssh/zz-closure-${process.pid}-${seq++}`;

/** a repository with `links` (name -> target; a relative target resolves beside the link) and real `dirs` */
function linked(links: Record<string, string>, dirs: string[] = []): string {
  const dir = workspace();
  for (const d of dirs) mkdirSync(join(dir, d), { recursive: true });
  for (const [name, target] of Object.entries(links)) {
    mkdirSync(join(dir, name, '..'), { recursive: true });
    symlinkSync(target, join(dir, name));
  }
  return dir;
}

const WRITERS: Array<[string, (path: string) => [string, Record<string, unknown>]]> = [
  ['Write', (p) => ['Write', { file_path: p, content: 'x' }]],
  ['Edit', (p) => ['Edit', { file_path: p, old_string: 'a', new_string: 'b' }]],
  ['MultiEdit', (p) => ['MultiEdit', { file_path: p, edits: [] }]],
  ['NotebookEdit', (p) => ['NotebookEdit', { notebook_path: p, new_source: 'x' }]],
  ['apply_patch Add', (p) => ['apply_patch', { command: patch(`*** Add File: ${p}`, '+x') }]],
  ['apply_patch Update', (p) => ['apply_patch', { command: patch(`*** Update File: ${p}`, ...BODY) }]],
  ['apply_patch Delete', (p) => ['apply_patch', { command: patch(`*** Delete File: ${p}`) }]],
  [
    'apply_patch Move to',
    (p) => ['apply_patch', { command: patch('*** Update File: src/a.ts', `*** Move to: ${p}`, ...BODY) }],
  ],
];

test('a write through a link whose target does not exist yet is judged by the target', () => {
  const target = newCred();
  const dir = linked({
    lnk: target,
    'sub/lnk': target,
    // a chain of links, none of which points at anything yet
    first: 'second',
    second: target,
    // a link to a directory that does not exist: the name beneath it lands in the credential store too
    lnkdir: `${HOME}/.ssh/zz-closure-dir-${process.pid}`,
    // relative targets resolve beside the link, and may go through `..`
    'deep/er/rel': '../../.git/hooks/zz-new',
    cfg: '.claude/settings.json',
    // a link to a missing file in a missing directory under a protected tree
    hk: '.git/hooks/zz-dir/zz-new',
  });
  for (const [name, mk] of WRITERS) {
    for (const [path, want] of [
      [join(dir, 'lnk'), 'fs.credential-store.write'],
      [join(dir, 'sub', 'lnk'), 'fs.credential-store.write'],
      [join(dir, 'first'), 'fs.credential-store.write'],
      [join(dir, 'lnkdir', 'inner.txt'), 'fs.credential-store.write'],
      [join(dir, 'lnkdir', 'a', 'b', 'inner.txt'), 'fs.credential-store.write'],
      [join(dir, 'deep', 'er', 'rel'), 'fs.hook-config.write'],
      [join(dir, 'cfg'), 'fs.hook-config.write'],
      [join(dir, 'hk'), 'fs.hook-config.write'],
      // and as a relative path from the working directory
      ['lnk', 'fs.credential-store.write'],
      ['first', 'fs.credential-store.write'],
      ['deep/er/rel', 'fs.hook-config.write'],
    ] as const) {
      const [tool, input] = mk(path);
      const e = evalIn(dir, tool, input);
      assert.equal(e.verdict, 'DENY', `${name} ${path}: ${e.verdict} [${caps(e)}]`);
      assert.ok(e.hits.some((h) => h.capability === want), `${name} ${path}: wanted ${want}, got [${caps(e)}]`);
    }
  }
});

test('a write through a link follows it the way the kernel does: loops end, links inside the workspace stay ordinary', () => {
  const dir = linked({ a: 'b', b: 'a', ok: 'new-file.txt', okdir: 'newdir' });
  // a loop cannot be opened at all; the point is that it is judged, once, and does not hang
  const loop = evalIn(dir, 'Write', { file_path: join(dir, 'a') });
  assert.ok(['ALLOW', 'ASK', 'DENY'].includes(loop.verdict));
  // a link to a missing file inside the workspace is an ordinary repository write
  const inside = evalIn(dir, 'Write', { file_path: join(dir, 'ok') });
  assert.equal(inside.verdict, 'ALLOW', `[${caps(inside)}]`);
  assert.equal(evalIn(dir, 'Write', { file_path: join(dir, 'okdir', 'x.txt') }).verdict, 'ALLOW');
  // a link to a missing path outside every root is not a repository write
  const out = linked({ away: '/zz-closure-nowhere/file.txt' });
  assert.notEqual(evalIn(out, 'Write', { file_path: join(out, 'away') }).verdict, 'ALLOW');
  // a link whose target EXISTS was already followed, and stays so
  const existing = linked({ real: join(dir, 'new-file.txt') });
  assert.equal(evalIn(existing, 'Write', { file_path: join(existing, 'real') }).verdict, 'ALLOW');
});

test('links are followed the way the kernel follows them: trailing slashes, `..` through a missing link, chains, and a farm of links', () => {
  const dir = linked({
    slash: `${HOME}/.ssh/zz-closure-slash-${process.pid}/`,
    // `b` points at nothing yet; `x/..` from it is the directory ABOVE its target
    via: 'b/../zz-closure-up',
    b: `${HOME}/.ssh/zz-closure-b-${process.pid}`,
  });
  for (const [name, want] of [
    ['slash', 'fs.credential-store.write'],
    ['via', 'fs.credential-store.write'],
  ] as const) {
    const e = evalIn(dir, 'Write', { file_path: join(dir, name) });
    assert.equal(e.verdict, 'DENY', `${name}: [${caps(e)}]`);
    assert.ok(e.hits.some((h) => h.capability === want), `${name}: [${caps(e)}]`);
  }
  // a chain the kernel would follow is followed; one it would refuse (ELOOP past 40) is not a hang
  const chain = (n: number): string => {
    const links: Record<string, string> = { [`c${n}`]: newCred() };
    for (let i = 0; i < n; i++) links[`c${i}`] = `c${i + 1}`;
    return linked(links);
  };
  assert.equal(evalIn(chain(30), 'Write', { file_path: 'c0' }).verdict, 'DENY');
  const started = Date.now();
  assert.ok(['ALLOW', 'ASK', 'DENY'].includes(evalIn(chain(80), 'Write', { file_path: 'c0' }).verdict));
  // every level names the next level TWICE, so an unbudgeted walk does 2^25 link resolutions
  const farm: Record<string, string> = { m25: newCred() };
  for (let i = 0; i < 25; i++) farm[`m${i}`] = `m${i + 1}/m${i + 1}`;
  assert.ok(['ALLOW', 'ASK', 'DENY'].includes(evalIn(linked(farm), 'Write', { file_path: 'm0' }).verdict));
  assert.ok(Date.now() - started < 5000, `resolution took ${Date.now() - started} ms: the link budget is shared by the whole walk`);
});

test('the shell shares the resolver: a redirection or a writer through a not-yet-existing link is judged by the target', () => {
  const dir = linked({ lnk: '.git/hooks/zz-new', cred: newCred() });
  const bash = (command: string) => evalIn(dir, 'Bash', { command });
  for (const command of [
    'echo x > lnk',
    'echo x >> lnk',
    ': > lnk',
    'printf x > ./lnk',
    'tee lnk < /dev/null',
    'cp package.json lnk',
    `echo x > ${join(dir, 'lnk')}`,
  ]) {
    const e = bash(command);
    assert.notEqual(e.verdict, 'ALLOW', `${command}: ${e.verdict} [${caps(e)}]`);
  }
  assert.equal(bash('echo x > cred').verdict, 'DENY');
  // ...and an ordinary redirection is untouched
  assert.equal(bash('echo x > out.txt').verdict, 'ALLOW');
});

test('a write through a not-yet-existing link is refused through the hook of the host that sends it', async () => {
  const p = project('STANDARD');
  symlinkSync(newCred(), join(p.root, 'lnk'));
  symlinkSync(`${HOME}/.ssh/zz-closure-dir-${process.pid}`, join(p.root, 'lnkdir'));
  for (const input of [
    { file_path: join(p.root, 'lnk'), content: 'x' },
    { file_path: join(p.root, 'lnkdir', 'f'), content: 'x' },
  ]) {
    const a = await hook(p, 'claude-code', cc('Write', input));
    assert.equal(a.action, 'deny', a.reason);
    assert.match(a.reason, /fs\.credential-store\.write/);
    const x = await hook(p, 'codex-cli', { tool_name: 'write_file', tool_input: { ...input, path: input.file_path } });
    assert.notEqual(x.action, 'allow', x.reason);
    assert.equal(x.code, 2);
  }
  assert.equal((await hook(p, 'claude-code', cc('Write', { file_path: join(p.root, 'src', 'a.ts'), content: 'x' }))).action, 'allow');
});

