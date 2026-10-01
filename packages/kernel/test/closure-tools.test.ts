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
import { parseCodexEvent } from '../../adapter-codex-cli/src/dialect.ts';
import { argvToCommandLine } from '../src/util/shell-quote.ts';
import { table, workspace } from './support/corpus.ts';

const HOME = homedir();
const CRED = `${HOME}/.ssh/authorized_keys`;

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

test('`..` after a link names the parent of the link target, not the text before it', () => {
  const dir = linked({ d: '.claude/sub' }, ['.claude/sub']);
  // (string concatenation, not `join`: `join` would collapse the `..` before the evaluator ever saw it)
  for (const p of [`${dir}/d/../settings.json`, 'd/../settings.json', `${dir}/d/./../settings.json`, `${dir}/d//../settings.json`]) {
    const e = evalIn(dir, 'Write', { file_path: p });
    assert.equal(e.verdict, 'DENY', `${p}: ${e.verdict} [${caps(e)}]`);
    assert.ok(e.hits.some((h) => h.capability === 'fs.hook-config.write'), `${p}: [${caps(e)}]`);
  }
  // with no link in the way the same shape is the ordinary file it looks like
  assert.equal(evalIn(dir, 'Write', { file_path: `${dir}/src/../x.ts` }).verdict, 'ALLOW');
});

test('a path with leading or trailing whitespace, or a NUL, is never judged as if it were trimmed', () => {
  const dir = workspace();
  const cases: Array<[string, string]> = [
    [` ${CRED}`, 'DENY'], // a trimming host opens the credential file; the classifier saw a RELATIVE path
    [`${CRED} `, 'DENY'],
    [`\t${CRED}`, 'DENY'],
    [`\u00a0${CRED}`, 'DENY'],
    [`${CRED}\n`, 'DENY'],
    [`${CRED}\0.txt`, 'DENY'], // a C string ends at the NUL
    [`src/a.ts\0${CRED}`, 'ASK'],
    [' src/a.ts', 'ASK'],
    ['src/a.ts ', 'ASK'],
    ['src/a.ts\r', 'ASK'],
    ['   ', 'ASK'],
  ];
  for (const [path, atLeast] of cases) {
    for (const [name, mk] of WRITERS.slice(0, 4)) {
      const [tool, input] = mk(path);
      const e = evalIn(dir, tool, input);
      assert.notEqual(e.verdict, 'ALLOW', `${name} ${JSON.stringify(path)}: ${e.verdict} [${caps(e)}]`);
      if (atLeast === 'DENY')
        assert.equal(e.verdict, 'DENY', `${name} ${JSON.stringify(path)}: ${e.verdict} [${caps(e)}]`);
    }
    const read = evalIn(dir, 'Read', { file_path: path.replace(/authorized_keys/, 'id_rsa') });
    assert.notEqual(read.verdict, 'ALLOW', `Read ${JSON.stringify(path)}`);
  }
  // search tools take the path the same way
  for (const tool of ['Grep', 'Glob', 'LS']) {
    for (const path of [` ${HOME}/.ssh`, `${HOME}/.ssh `, '\t~/.ssh']) {
      const e = evalIn(dir, tool, { path, pattern: '*' });
      assert.equal(e.verdict, 'DENY', `${tool} ${JSON.stringify(path)}: ${e.verdict} [${caps(e)}]`);
    }
    assert.notEqual(evalIn(dir, tool, { path: ' src', pattern: '*' }).verdict, 'ALLOW', `${tool} padded repo path`);
  }
  // an ordinary, clean path is not touched by any of this
  assert.equal(evalIn(dir, 'Write', { file_path: join(dir, 'src', 'a.ts') }).verdict, 'ALLOW');
  assert.equal(evalIn(dir, 'Read', { file_path: 'src/a.ts' }).verdict, 'ALLOW');
});

test('a leading-space path is refused through the hook of both hosts', async () => {
  const p = project('STANDARD');
  for (const file_path of [` ${CRED}`, `${CRED} `, `\t${CRED}`]) {
    const a = await hook(p, 'claude-code', cc('Write', { file_path, content: 'x' }));
    assert.equal(a.action, 'deny', a.reason);
    assert.match(a.reason, /fs\.credential-store\.write/);
    const x = await hook(p, 'codex-cli', { tool_name: 'write_file', tool_input: { file_path, content: 'x' } });
    assert.notEqual(x.action, 'allow', x.reason);
    assert.equal(x.code, 2);
  }
  // an ordinary, clean path is not touched
  assert.equal((await hook(p, 'claude-code', cc('Write', { file_path: join(p.root, 'src', 'a.ts'), content: 'x' }))).action, 'allow');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 1. apply_patch HEADERS ARE READ THE WAY THE HOST'S PARSER READS THEM (audit 7)
 *
 * The header test was a column-0 regular expression. Codex's own parser trims every line before it looks for a
 * header, so `  *** Add File: ~/.ssh/authorized_keys` — after a benign Add, after a Delete, directly after an
 * Update (for its `Move to`) — was invisible to EGO and ALLOW while Codex applied it: an arbitrary-path write.
 * ------------------------------------------------------------------------------------------------------------- */

/** every kind of space a parser might trim: ASCII, tab, NBSP, EM SPACE, IDEOGRAPHIC SPACE, NEXT LINE, BOM, VT, FF */
const PADS = [' ', '  ', '\t', ' \t ', '\u00a0', '\u2003', '\u3000', '\u0085', '\ufeff', '\u000b', '\u000c'];
test('apply_patch: a header indented by ANY whitespace is still a header (Add, Delete, Move to)', () => {
  const dir = workspace();
  for (const pad of PADS) {
    const shown = JSON.stringify(pad);
    const spellings: Array<[string, string]> = [
      ['an Add after a benign Add', patch('*** Add File: ok.txt', '+x', `${pad}*** Add File: ${CRED}`, '+evil')],
      ['a Delete after a Delete', patch('*** Delete File: a.txt', `${pad}*** Delete File: ${CRED}`)],
      ['a Move to right after an Update', patch('*** Update File: src/a.ts', `${pad}*** Move to: ${CRED}`, ...BODY)],
      ['an Add after an Update hunk', patch('*** Update File: src/a.ts', ...BODY, `${pad}*** Add File: ${CRED}`, '+evil')],
      ['an Update of a credential', patch('*** Add File: ok.txt', '+x', `${pad}*** Update File: ${CRED}`, ...BODY)],
      // trailing padding on the header line is trimmed too
      ['a header with trailing padding', patch('*** Add File: ok.txt', '+x', `*** Add File: ${CRED}${pad}`, '+evil')],
    ];
    for (const [what, text] of spellings) {
      const e = evalIn(dir, 'apply_patch', { command: text });
      assert.equal(e.verdict, 'DENY', `${what}, pad ${shown}: ${e.verdict} [${caps(e)}]`);
      assert.equal(e.decisive?.capability, 'fs.credential-store.write', `${what}, pad ${shown}`);
    }
  }
});

test('apply_patch: CRLF, lone CR and Unicode line separators do not hide a header', () => {
  const dir = workspace();
  const crlf = patch('*** Add File: ok.txt', '+x', `  *** Add File: ${CRED}`, '+evil').replace(/\n/g, '\r\n');
  assert.equal(evalIn(dir, 'apply_patch', { command: crlf }).decisive?.capability, 'fs.credential-store.write');
  for (const sep of ['\r', '\u2028', '\u2029']) {
    const text = patch('*** Add File: ok.txt', '+x', `${sep}  *** Add File: ${CRED}`, '+evil');
    const e = evalIn(dir, 'apply_patch', { command: text });
    assert.equal(e.decisive?.capability, 'fs.credential-store.write', `separator ${JSON.stringify(sep)}`);
  }
  // the `patch` key is the same operand
  const viaPatch = evalIn(dir, 'apply_patch', { patch: patch('*** Delete File: a', `\t*** Delete File: ${CRED}`) });
  assert.equal(viaPatch.verdict, 'DENY');
});

test('apply_patch: a header the parser does not recognise makes the whole patch unparseable', () => {
  const dir = workspace();
  for (const odd of ['*** Rename File: a -> b', '  *** Frobnicate: x', '\t*** Add Files: x', '*** Begin Patch: evil', '*** Update File', '*** Move to']) {
    const text = patch('*** Add File: ok.txt', '+x', odd);
    const e = evalIn(dir, 'apply_patch', { command: text });
    assert.equal(e.verdict, 'DENY', `${JSON.stringify(odd)}: ${e.verdict}`);
    assert.deepEqual(e.hits, [], 'refused before any path is classified');
  }
  // a header that names no path is not a header the host can apply either
  assert.equal(evalIn(dir, 'apply_patch', { command: patch('*** Add File: ', '+x') }).verdict, 'DENY');
});

test('apply_patch: what is not a header stays ordinary — content lines and context lines are not refused', () => {
  const dir = workspace();
  const ok = (text: string, what: string) => {
    const e = evalIn(dir, 'apply_patch', { command: text });
    assert.equal(e.verdict, 'ALLOW', `${what}: ${e.verdict} [${caps(e)}]`);
  };
  ok(patch('*** Update File: src/a.ts', ...BODY), 'a plain update');
  ok(patch('*** Update File: src/a.ts', '@@', ' context', '-old', '+new', '*** End of File'), 'End of File marker');
  ok(patch('*** Add File: docs/x.md', '+*** Add File: example/in/a/doc', '+  *** nested note'), 'header-looking text in added content');
  ok(patch('*** Update File: notes.org', '@@', ' *** TODO a heading', '-old', '+new'), 'an org-mode heading as a context line');
  ok(patch('*** Update File: src/a.ts', '@@', '-*** a removed line', '+*** an added line'), 'removed/added lines');
  ok(patch('*** Update File: src/a.ts', '*** Move to: src/b.ts', ...BODY), 'a plain rename');
  ok(`*** Begin Patch\r\n*** Update File: src/a.ts\r\n@@\r\n-a\r\n+b\r\n*** End Patch\r\n`, 'CRLF throughout');
});

test('apply_patch: a path inside a header is judged as written, not as trimmed', () => {
  const dir = workspace();
  // whitespace INSIDE the path survives the host's line trim; whichever way the host reads it, the stricter reading counts
  const padded = evalIn(dir, 'apply_patch', { command: patch(`*** Add File:  ${CRED}`, '+evil') });
  assert.equal(padded.verdict, 'DENY');
  const tab = evalIn(dir, 'apply_patch', { command: patch('*** Add File:\tsrc/a.ts', '+x') });
  assert.notEqual(tab.verdict, 'ALLOW', 'a path that starts with whitespace is never judged as if it were trimmed');
  assert.equal(evalIn(dir, 'apply_patch', { command: patch('*** Add File: src/a\0.ts', '+x') }).verdict, 'ASK');
});

test('apply_patch, through the hook of BOTH hosts: an indented header is refused', async () => {
  const claudeText = patch('*** Add File: ok.txt', '+x', `  *** Add File: ${CRED}`, '+evil');
  const moveText = patch('*** Update File: src/a.ts', `\u00a0*** Move to: ${CRED}`, ...BODY);
  const crlfText = claudeText.replace(/\n/g, '\r\n');
  for (const profile of ['STANDARD', 'STRICT', 'HIGH_ASSURANCE'] as const) {
    const p = project(profile);
    for (const text of [claudeText, moveText, crlfText]) {
      const a = await hook(p, 'claude-code', cc('apply_patch', { command: text }));
      assert.equal(a.action, 'deny', `claude-code ${profile}: ${a.reason}`);
      assert.equal(a.code, 0, 'claude-code carries the decision in the output');
      for (const shape of [
        { tool: 'apply_patch', arguments: text }, // the string form: parsed as `command`
        { tool_name: 'apply_patch', tool_input: { command: text } },
      ]) {
        const x = await hook(p, 'codex-cli', shape);
        assert.equal(x.action, 'deny', `codex-cli ${profile}: ${x.reason}`);
        assert.equal(x.code, 2, 'codex-cli refuses with exit 2');
        assert.match(x.reason, /fs\.credential-store\.write/);
      }
    }
    // the ordinary patch still goes through on both
    const fine = patch('*** Update File: src/a.ts', ...BODY);
    assert.equal((await hook(p, 'claude-code', cc('apply_patch', { command: fine }))).action, 'allow');
    const cx = await hook(p, 'codex-cli', { tool_name: 'apply_patch', tool_input: { command: fine } });
    assert.equal(cx.action, 'allow');
    assert.equal(cx.code, 0);
  }
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 3. ONLY A FETCH HAS A URL (audit 9)
 * ------------------------------------------------------------------------------------------------------------- */

test('WebSearch is public egress whatever other keys it carries; only WebFetch consults a url', async () => {
  const dir = workspace();
  const local = ['http://localhost:3000', 'http://127.0.0.1:8080/x', 'localhost:3000', 'http://[::1]:1/'];
  for (const url of local) {
    const search = { query: 'secret', url };
    assert.equal(evalIn(dir, 'WebSearch', search, 'HIGH_ASSURANCE').verdict, 'DENY', `HIGH_ASSURANCE ${url}`);
    for (const profile of ['STANDARD', 'STRICT'] as const) {
      const e = evalIn(dir, 'WebSearch', search, profile);
      assert.equal(e.verdict, 'ASK', `${profile} ${url}: ${e.verdict} [${caps(e)}]`);
      assert.ok(e.hits.some((h) => h.capability === 'network.public-read'), `[${caps(e)}]`);
      assert.ok(!e.hits.some((h) => h.capability === 'network.localhost'), 'the url is not what the search is judged by');
    }
  }
  // the fetch that really is local is still local, in every profile
  for (const profile of ['STANDARD', 'STRICT', 'HIGH_ASSURANCE'] as const)
    assert.equal(evalIn(dir, 'WebFetch', { url: 'http://localhost:3000', prompt: 'p' }, profile).verdict, 'ALLOW', profile);
  assert.equal(evalIn(dir, 'WebFetch', { url: 'https://docs.example.com', prompt: 'p' }).verdict, 'ASK');
  assert.equal(evalIn(dir, 'WebFetch', { url: 'https://docs.example.com', prompt: 'p' }, 'HIGH_ASSURANCE').verdict, 'DENY');
  // a fetch whose url is not text is not a local fetch either
  for (const url of [5, ['http://localhost'], null, { a: 1 }]) {
    const e = evalIn(dir, 'WebFetch', { url }, 'HIGH_ASSURANCE');
    assert.equal(e.verdict, 'DENY', JSON.stringify(url));
    assert.notEqual(evalIn(dir, 'WebFetch', { url }).verdict, 'ALLOW', JSON.stringify(url));
  }
  // ...through the real hook
  const p = project('HIGH_ASSURANCE');
  const a = await hook(p, 'claude-code', cc('WebSearch', { query: 'secret', url: 'http://localhost:3000' }));
  assert.equal(a.action, 'deny', a.reason);
  assert.equal((await hook(p, 'claude-code', cc('WebFetch', { url: 'http://localhost:3000', prompt: 'p' }))).action, 'allow');
  const std = project('STANDARD');
  assert.equal((await hook(std, 'claude-code', cc('WebSearch', { query: 'q', url: 'http://localhost:3000' }))).action, 'ask');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 4. AN OPTIONAL OPERAND IS NOT A LICENCE TO GUESS, AND A TOOL HAS ONE OPERAND (audit 13)
 * ------------------------------------------------------------------------------------------------------------- */

test('Grep, Glob and LS: an operand that is present and not a string is a call nobody understands, not the working directory', () => {
  const dir = workspace();
  const asks = (tool: string, input: Record<string, unknown>, what: string) => {
    const e = evalIn(dir, tool, input);
    assert.equal(e.verdict, 'ASK', `${what}: ${e.verdict} [${caps(e)}]`);
    assert.ok(e.hits.some((h) => h.capability === 'command.unknown'), `${what}: [${caps(e)}]`);
  };
  asks('Grep', {}, 'Grep with nothing');
  asks('Grep', { pattern: 5 }, 'Grep pattern a number');
  asks('Grep', { pattern: ['x'] }, 'Grep pattern an array');
  asks('Grep', { pattern: 'x', path: 5 }, 'Grep path a number');
  asks('Grep', { pattern: 'x', path: [`${HOME}/.ssh`] }, 'Grep path an array');
  asks('Grep', { pattern: 'x', path: null }, 'Grep path null');
  asks('Grep', { pattern: 'x', path: { a: 1 } }, 'Grep path an object');
  asks('Grep', { pattern: 'x', glob: ['**/.env'] }, 'Grep glob an array');
  asks('Glob', {}, 'Glob with nothing');
  asks('Glob', { pattern: ['~/.ssh/*'] }, 'Glob pattern an array');
  asks('Glob', { pattern: '*.ts', path: 7 }, 'Glob path a number');
  asks('LS', { path: [`${HOME}/.ssh`] }, 'LS path an array');
  asks('LS', { path: 5 }, 'LS path a number');
  // the ordinary calls, with the keys the hosts really send, are untouched
  const ok = (tool: string, input: Record<string, unknown>) => {
    const e = evalIn(dir, tool, input);
    assert.equal(e.verdict, 'ALLOW', `${tool} ${JSON.stringify(input)}: ${e.verdict} [${caps(e)}]`);
  };
  ok('Grep', { pattern: 'TODO' });
  ok('Grep', { pattern: 'TODO', path: 'src', glob: '*.ts', output_mode: 'content', '-i': true, '-n': true, type: 'ts', head_limit: 20 });
  ok('Glob', { pattern: '**/*.ts' });
  ok('Glob', { pattern: '**/*.ts', path: dir });
  ok('LS', { path: dir, ignore: ['node_modules'] });
  ok('LS', {});
});

test('a tool has ONE operand: a second operand-shaped key is read too and the call asks', () => {
  const dir = workspace();
  const ok = join(dir, 'src', 'a.ts');
  // the key the host does NOT name may be the one it honours: judged both ways, the stricter wins
  const deny = (tool: string, input: Record<string, unknown>) => {
    const e = evalIn(dir, tool, input);
    assert.equal(e.verdict, 'DENY', `${tool} ${JSON.stringify(input)}: ${e.verdict} [${caps(e)}]`);
  };
  const ask = (tool: string, input: Record<string, unknown>) => {
    const e = evalIn(dir, tool, input);
    assert.equal(e.verdict, 'ASK', `${tool} ${JSON.stringify(input)}: ${e.verdict} [${caps(e)}]`);
  };
  deny('NotebookEdit', { file_path: ok, notebook_path: CRED });
  deny('NotebookEdit', { notebook_path: ok, file_path: CRED });
  deny('Write', { file_path: ok, notebook_path: CRED });
  deny('Write', { file_path: ok, path: CRED });
  deny('Write', { file_path: ok, filePath: CRED });
  deny('Edit', { file_path: ok, path: CRED });
  deny('MultiEdit', { file_path: ok, filename: CRED });
  deny('Read', { file_path: ok, path: `${HOME}/.ssh/id_rsa` });
  deny('Read', { file_path: ok, file: `${HOME}/.ssh/id_rsa` });
  deny('Grep', { pattern: 'x', file_path: `${HOME}/.ssh/id_rsa` });
  deny('Bash', { command: 'ls', cmd: 'git push origin main' });
  deny('Bash', { command: 'ls', script: 'git push origin main' });
  deny('Bash', { command: 'ls', argv: ['git', 'push', 'origin', 'main'] });
  deny('apply_patch', { command: patch('*** Update File: src/a.ts', ...BODY), patch: patch(`*** Add File: ${CRED}`, '+x') });
  deny('apply_patch', { command: patch(`*** Add File: ${CRED}`, '+x'), patch: patch('*** Update File: src/a.ts', ...BODY) });
  // ordinary values in the second key still ask: nobody can tell which one the host would honour
  ask('Write', { file_path: ok, filePath: join(dir, 'src', 'b.ts') });
  ask('NotebookEdit', { notebook_path: ok, file_path: join(dir, 'src', 'b.ts') });
  ask('Read', { file_path: ok, path: join(dir, 'src', 'b.ts') });
  ask('Bash', { command: 'ls', cmd: 'ls' });
  ask('Bash', { command: 'ls', file_path: ok });
  ask('WebSearch', { query: 'q', url: 'https://docs.example.com' });
  ask('WebFetch', { url: 'https://docs.example.com', path: ok });
  ask('apply_patch', {
    command: patch('*** Update File: src/a.ts', ...BODY),
    patch: patch('*** Update File: src/b.ts', ...BODY),
  });
  // the same text under two operand keys is one patch
  const same = patch('*** Update File: src/a.ts', ...BODY);
  assert.equal(evalIn(dir, 'apply_patch', { command: same, patch: same }).verdict, 'ALLOW');
  // ...and the operand each tool really has is the only one it is judged by when it is alone
  assert.equal(evalIn(dir, 'NotebookEdit', { notebook_path: ok, new_source: 'x', cell_id: 'c', edit_mode: 'replace' }).verdict, 'ALLOW');
  assert.equal(evalIn(dir, 'Write', { file_path: ok, content: 'x' }).verdict, 'ALLOW');
  assert.equal(evalIn(dir, 'Edit', { file_path: ok, old_string: 'a', new_string: 'b', replace_all: false }).verdict, 'ALLOW');
  assert.equal(evalIn(dir, 'Read', { file_path: ok, offset: 1, limit: 10 }).verdict, 'ALLOW');
  assert.equal(evalIn(dir, 'Bash', { command: 'ls', description: 'list', timeout: 1000, run_in_background: false }).verdict, 'ALLOW');
  // a NotebookEdit that names its path the way a Write does has no operand at all
  assert.equal(evalIn(dir, 'NotebookEdit', { file_path: ok }).verdict, 'ASK');
  assert.equal(evalIn(dir, 'Write', { notebook_path: ok }).verdict, 'ASK');
});

test('a tool operand that is present and is not a string asks, for every tool', () => {
  const dir = workspace();
  for (const [tool, key] of [
    ['Bash', 'command'],
    ['shell', 'command'],
    ['Read', 'file_path'],
    ['Write', 'file_path'],
    ['Edit', 'file_path'],
    ['MultiEdit', 'file_path'],
    ['NotebookEdit', 'notebook_path'],
  ] as const) {
    for (const bad of [5, null, true, [`${HOME}/.ssh/authorized_keys`], { a: 1 }]) {
      const e = evalIn(dir, tool, { [key]: bad });
      assert.equal(e.verdict, 'ASK', `${tool} ${key}=${JSON.stringify(bad)}: ${e.verdict} [${caps(e)}]`);
    }
  }
  for (const bad of [5, null, [patch('*** Add File: x', '+x')], { a: 1 }])
    assert.equal(evalIn(dir, 'apply_patch', { command: bad }).verdict, 'DENY', JSON.stringify(bad));
});

test('operand pollution and shapes are refused through the hook of both hosts', async () => {
  const p = project('STANDARD');
  const bad: Array<[string, unknown]> = [
    ['NotebookEdit', { file_path: 'src/a.ts', notebook_path: CRED }],
    ['Write', { file_path: 'src/a.ts', path: CRED }],
    ['Bash', { command: 'ls', cmd: 'git push origin main' }],
  ];
  for (const [name, input] of bad) {
    const a = await hook(p, 'claude-code', cc(name, input));
    assert.equal(a.action, 'deny', `${name}: ${a.reason}`);
  }
  assert.equal((await hook(p, 'claude-code', cc('Grep', { pattern: 'x', path: [`${HOME}/.ssh`] }))).action, 'ask');
  assert.equal((await hook(p, 'claude-code', cc('Glob', { pattern: ['~/.ssh/*'] }))).action, 'ask');
  assert.equal((await hook(p, 'claude-code', cc('LS', { path: 5 }))).action, 'ask');
  assert.equal((await hook(p, 'claude-code', cc('Grep', { pattern: 'x' }))).action, 'allow');
  const x = await hook(p, 'codex-cli', { tool_name: 'shell', tool_input: { command: 'ls', cmd: 'git push' } });
  assert.equal(x.action, 'deny');
  assert.equal(x.code, 2);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 6. HOST TOOLS THAT CANNOT ACT ON ANYTHING (audit 8: the undocumented cost of the fix)
 * ------------------------------------------------------------------------------------------------------------- */

test('a tool nobody modelled asks; the few that cannot act on anything are listed by name, and only those', async () => {
  const dir = workspace();
  for (const profile of ['STANDARD', 'STRICT', 'HIGH_ASSURANCE'] as const) {
    for (const [tool, input] of [
      ['TodoWrite', { todos: [{ content: 'x', status: 'pending', activeForm: 'x' }] }],
      ['TodoWrite', {}],
      ['BashOutput', { bash_id: 'b1' }],
    ] as Array<[string, Record<string, unknown>]>) {
      const e = evalIn(dir, tool, input, profile);
      assert.equal(e.verdict, 'ALLOW', `${profile} ${tool}: ${e.verdict}`);
      assert.deepEqual(e.hits, [], 'no capability: the tool touches no file, network or process');
      assert.match(e.reason, new RegExp(tool));
    }
    for (const tool of [
      'SomeFutureTool',
      'Task',
      'Agent',
      'Skill',
      'KillShell',
      'SlashCommand',
      // the host's own prompt IS the function of these two; an allow would answer for the human
      'ExitPlanMode',
      'AskUserQuestion',
      // a name has to be spelled exactly
      'todowrite',
      'TODOWRITE',
      'TodoWrite ',
      ' TodoWrite',
      'TodoWrite\n',
      'bashoutput',
      'TodoWrite\u200b',
      // names that are properties of every object
      '__proto__',
      'constructor',
      'toString',
      'hasOwnProperty',
    ]) {
      const e = evalIn(dir, tool, { x: 1 }, profile);
      assert.equal(e.verdict, 'ASK', `${profile} ${JSON.stringify(tool)}: ${e.verdict} [${caps(e)}]`);
      assert.match(e.reason, /no governed operation could be resolved/);
    }
  }
  // ...through the real hook: claude-code allows the bookkeeping and asks about the rest; codex-cli refuses the rest
  for (const profile of ['STANDARD', 'HIGH_ASSURANCE'] as const) {
    const p = project(profile);
    assert.equal((await hook(p, 'claude-code', cc('TodoWrite', { todos: [] }))).action, 'allow', profile);
    assert.equal((await hook(p, 'claude-code', cc('BashOutput', { bash_id: 'b' }))).action, 'allow');
    for (const name of ['Task', 'ExitPlanMode', 'AskUserQuestion', 'SomeFutureTool'])
      assert.equal((await hook(p, 'claude-code', cc(name, {}))).action, 'ask', `${profile} ${name}`);
    const cx = await hook(p, 'codex-cli', { tool_name: 'frobnicate', tool_input: { x: 1 } });
    assert.equal(cx.action, 'deny');
    assert.equal(cx.code, 2);
    assert.match(cx.reason, /ASK is refused/);
    assert.equal((await hook(p, 'codex-cli', { tool_name: 'TodoWrite', tool_input: {} })).action, 'allow');
  }
  // before trust promotion the bookkeeping still works and the governed mutation still does not
  const pre = project('HIGH_ASSURANCE', true);
  assert.equal((await hook(pre, 'claude-code', cc('TodoWrite', { todos: [] }))).action, 'allow');
  assert.equal((await hook(pre, 'claude-code', cc('Write', { file_path: join(pre.root, 'a.ts'), content: 'x' }))).action, 'deny');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * 5. CODEX SENDS AN ARGV, NOT A STRING (audit 13)
 *
 * Every real Codex shell call carries `["bash","-lc","git push"]`, directly or inside a JSON text in `arguments`.
 * The dialect wrapped the whole JSON as the command, so each one was an unknown head: refused — safe, and
 * unusable. The argv is now flattened into the shell-quoted line that executes as that vector.
 * ------------------------------------------------------------------------------------------------------------- */

const codexCommand = (extra: Record<string, unknown>): unknown =>
  parseCodexEvent('PreToolUse', { session_id: 's', cwd: '/w', ...extra }, '/fallback').tool?.input['command'];

test('codex-cli dialect: an argv array or a JSON `arguments` becomes the shell line the host will execute', () => {
  assert.equal(argvToCommandLine(['ls', '-la']), 'ls -la');
  assert.equal(argvToCommandLine(['bash', '-lc', 'git push origin main']), "bash -lc 'git push origin main'");
  assert.equal(argvToCommandLine(['echo', 'a b; rm -rf /', "it's", '', '$(id)']), "echo 'a b; rm -rf /' 'it'\\''s' '' '$(id)'");
  assert.equal(argvToCommandLine(['FOO=bar', 'ls']), "'FOO=bar' ls", 'a leading NAME=value is a program name to execve');
  assert.equal(argvToCommandLine(['ls', 'a=b']), 'ls a=b');
  for (const notArgv of [[], ['ls', 5], 'ls', null, [['ls']]]) assert.equal(argvToCommandLine(notArgv), null);

  // the shapes Codex really uses, under every key the dialect reads
  const argv = ['bash', '-lc', 'git push origin main'];
  const line = 'git push origin main'; // the host's own `bash -lc` wrapper is not part of what is judged
  for (const tool of ['shell', 'local_shell', 'exec_command', 'shell_command', 'container.exec']) {
    assert.equal(codexCommand({ tool_name: tool, tool_input: { command: argv } }), line, `${tool} tool_input.command`);
    assert.equal(codexCommand({ tool, input: { command: argv } }), line, `${tool} input.command`);
    assert.equal(codexCommand({ tool_name: tool, arguments: JSON.stringify({ command: argv }) }), line, `${tool} arguments`);
    assert.equal(codexCommand({ tool_name: tool, arguments: JSON.stringify(argv) }), line, `${tool} arguments as a bare array`);
  }
  assert.equal(codexCommand({ tool_name: 'shell', tool_input: { command: ['ls', '-la'] } }), 'ls -la');
  assert.equal(codexCommand({ tool_name: 'shell', tool_input: { command: ['git', 'push', 'origin', 'main'] } }), 'git push origin main');
  // only the exact wrapper is unwrapped (a shell, -c / -lc / -cl, one script); every other shape keeps its words
  for (const [argv2, want] of [
    [['/bin/sh', '-c', 'ls'], 'ls'],
    [['zsh', '-cl', 'ls'], 'ls'],
    [['bash', '-ic', 'ls'], 'bash -ic ls'],
    [['bash', '-lc', 'ls', 'arg0'], 'bash -lc ls arg0'],
    [['bash', '--rcfile', 'x', '-c', 'ls'], 'bash --rcfile x -c ls'],
    [['bash', 'script.sh'], 'bash script.sh'],
    [['python3', '-c', 'print(1)'], "python3 -c 'print(1)'"],
    [['bash', '-lc', 'echo a; git push'], 'echo a; git push'],
  ] as Array<[string[], string]>)
    assert.equal(codexCommand({ tool_name: 'shell', tool_input: { command: argv2 } }), want, JSON.stringify(argv2));
  assert.equal(codexCommand({ tool_name: 'shell', arguments: '{"command":"git push"}' }), 'git push');
  assert.equal(codexCommand({ tool_name: 'exec_command', tool_input: { cmd: 'git push' } }), 'git push');
  assert.equal(codexCommand({ tool_name: 'exec_command', arguments: '{"cmd":"git push"}' }), 'git push');
  assert.equal(codexCommand({ tool_name: 'shell', arguments: '{"argv":["git","push"]}' }), 'git push');
  // the flat shapes that always worked are unchanged
  assert.equal(codexCommand({ tool: 'shell', arguments: 'git push' }), 'git push');
  assert.equal(codexCommand({ tool_name: 'shell', tool_input: { command: 'git push' } }), 'git push');
  assert.equal(codexCommand({ tool_name: 'shell', arguments: '[ -f x ] && ls' }), '[ -f x ] && ls', 'a command that looks like JSON is still a command');
  assert.equal(codexCommand({ tool_name: 'shell', arguments: '{ ls; }' }), '{ ls; }');
  // a workdir is the cd it is, so a relative path is judged where it will be opened
  assert.equal(codexCommand({ tool_name: 'shell', tool_input: { command: ['ls'], workdir: '/some dir' } }), "cd '/some dir' && ls");
  assert.equal(codexCommand({ tool_name: 'shell', arguments: '{"command":["ls"],"workdir":"/w"}' }), 'cd /w && ls');
  // the keys the line was built from do not stay behind to be read a second time
  const ev = parseCodexEvent('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: 'ls', workdir: '/w', yield_time_ms: 5 } }, '/c');
  assert.deepEqual(ev.tool?.input, { yield_time_ms: 5, command: 'cd /w && ls' });
  // an apply_patch is not a shell call, and its string form is still the patch
  assert.equal(codexCommand({ tool_name: 'apply_patch', arguments: '*** Begin Patch' }), '*** Begin Patch');
});

test('codex-cli dialect: a shape it does not recognise is left as it arrived, so the kernel asks', async () => {
  for (const extra of [
    { tool_name: 'shell', tool_input: { command: 5 } },
    { tool_name: 'shell', tool_input: { command: [] } },
    { tool_name: 'shell', tool_input: { command: ['ls', 5] } },
    { tool_name: 'shell', tool_input: { command: [['ls']] } },
    { tool_name: 'shell', tool_input: { command: ['ls'], workdir: 5 } },
    { tool_name: 'shell', tool_input: { command: ['ls'], workdir: '' } },
    { tool_name: 'shell', tool_input: { nothing: 'here' } },
    { tool_name: 'shell', arguments: '{"foo":1}' },
    { tool_name: 'shell', arguments: '{"command": ' },
    { tool_name: 'shell', arguments: 5 },
    { tool_name: 'shell', arguments: null },
    { tool_name: 'shell', arguments: '[1,2]' },
    { tool_name: 'shell' },
  ]) {
    const p = project('STANDARD');
    const x = await hook(p, 'codex-cli', extra);
    assert.equal(x.action, 'deny', JSON.stringify(extra));
    assert.equal(x.code, 2, JSON.stringify(extra));
    assert.match(x.reason, /ASK is refused|is DENY/, `${JSON.stringify(extra)}: refused as a call nobody can read, not allowed: ${x.reason}`);
  }
});

test('codex-cli hook: a flattened argv is judged as what it is', async () => {
  for (const profile of ['STANDARD', 'STRICT', 'HIGH_ASSURANCE'] as const) {
    const p = project(profile);
    const shapes = (argv: string[], more: Record<string, unknown> = {}): Array<Record<string, unknown>> => [
      { tool_name: 'shell', tool_input: { command: argv, ...more } },
      { tool_name: 'shell', arguments: JSON.stringify({ command: argv, ...more }) },
      { tool: 'local_shell', input: { command: argv, ...more } },
    ];
    for (const payload of shapes(['bash', '-lc', 'git push origin main'])) {
      const x = await hook(p, 'codex-cli', payload);
      assert.equal(x.action, 'deny', `${profile} ${JSON.stringify(payload)}`);
      assert.equal(x.code, 2);
      assert.match(x.reason, /git\.remote\.push is DENY/, 'refused for what it is, not for being unreadable');
    }
    for (const payload of shapes(['bash', '-lc', 'rm -rf /'])) assert.match((await hook(p, 'codex-cli', payload)).reason, /is DENY/);
    for (const payload of shapes(['ls', '-la'])) {
      const x = await hook(p, 'codex-cli', payload);
      assert.equal(x.action, 'allow', `${profile} ${JSON.stringify(payload)}: ${x.reason}`);
      assert.equal(x.code, 0);
    }
    assert.equal((await hook(p, 'codex-cli', shapes(['bash', '-lc', 'ls -la && git status'])[0]!)).action, 'allow');
    // an argv element is ONE word: the metacharacters in it do not run
    const quoted = await hook(p, 'codex-cli', { tool_name: 'shell', tool_input: { command: ['echo', 'hello; git push origin main'] } });
    assert.equal(quoted.action, 'allow', quoted.reason);
    // ...and the one that is a program name is the program
    assert.match((await hook(p, 'codex-cli', { tool_name: 'shell', tool_input: { command: ['git', 'push', 'origin', 'main'] } })).reason, /is DENY/);
    // a command that is merely unknown to the classifier is refused, as before
    const ask = await hook(p, 'codex-cli', { tool_name: 'shell', tool_input: { command: ['bash', '-lc', 'curl https://example.com'] } });
    assert.equal(ask.action, 'deny');
    assert.match(ask.reason, /ASK is refused|network-tool is DENY/); // HIGH_ASSURANCE denies the network tool outright
    // a wrapper that is not the host's exact one keeps its words, and a shell run on a script is an unknown head
    const odd = await hook(p, 'codex-cli', { tool_name: 'shell', tool_input: { command: ['bash', '-ic', 'ls'] } });
    assert.match(odd.reason, /ASK is refused/);
    // exec_command carries `cmd`
    assert.match((await hook(p, 'codex-cli', { tool_name: 'exec_command', tool_input: { cmd: 'git push' } })).reason, /is DENY/);
    assert.equal((await hook(p, 'codex-cli', { tool_name: 'exec_command', tool_input: { cmd: 'ls' } })).action, 'allow');
    // the directory the command runs in is the directory it is judged in
    const wd = await hook(p, 'codex-cli', {
      tool_name: 'shell',
      tool_input: { command: ['bash', '-lc', 'echo x > authorized_keys'], workdir: `${HOME}/.ssh` },
    });
    assert.equal(wd.action, 'deny');
    assert.match(wd.reason, /fs\.credential-store\.write|is DENY/, wd.reason);
    const here = await hook(p, 'codex-cli', { tool_name: 'shell', tool_input: { command: ['bash', '-lc', 'echo x > out.txt'], workdir: p.root } });
    assert.equal(here.action, 'allow', here.reason);
  }
});

