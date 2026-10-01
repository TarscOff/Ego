// CLOSURE AUDIT 2026-10-01, FINDING F1 - "WHICH MANIFEST" IS ANSWERED BY EXISTENCE, AT EVERY DIRECTORY A COMMAND RUNS IN.
//
// A declared class (`npm|pnpm|yarn run|test|build`, `make`, `lint-staged`, `npm install`) keeps ALLOW only when the
// file that selects what runs was PROVED ABSENT. A file that is there and that EGO will not read - because it is
// outside the registered roots, behind a link to somewhere outside them, or has no read permission - is "something
// will run that could not be read", and that is the human gate. The manifest branch used to decide this only for the
// directories INSIDE the registered roots: the working directory itself, when it lay outside them, was never looked
// in, and a manifest whose canonical path left the roots was skipped as if it were not there. The Makefile branch
// asks "does it exist" of the candidate paths directly and never had the hole, so every arrangement below is run for
// BOTH producers: the same arrangement of the same file must be the same gate whichever tool reads it.
//
// The scratch exemption (isScratchPath) exists so that ordinary scratch WRITES are not gated. It must not make a
// directory in which a command will RUN invisible, and the temp directory is where an agent can plant a file and run
// it in one command line - so the outside directories here are in the OS temp directory on purpose.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, relative } from 'node:path';
import { evaluate, type EvaluationContext } from '../src/authority/evaluate.ts';
import { table, workspace } from './support/corpus.ts';

/** what the files below would do if they were READ: an absolute-class act, so "read" and "gated unread" differ */
const RECIPE = 'git push --force origin main';
const MAKEFILE = `build:\n\t${RECIPE}\n`;
const MANIFEST = JSON.stringify({
  scripts: { build: RECIPE, test: RECIPE, lint: RECIPE, start: RECIPE },
  'lint-staged': { '*.js': RECIPE },
});
/** the same act, behind a lint-staged configuration of its own */
const LS_RC = JSON.stringify({ '*.js': RECIPE });
const BENIGN_LS_RC = JSON.stringify({ '*.js': 'eslint --fix' });
const IS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0;

const SCRATCH = mkdtempSync(join(tmpdir(), 'ego-manifests-'));
let counter = 0;
/** a directory OUTSIDE every registered root, in the OS temp directory (the scratch exemption covers it) */
function outside(files: Record<string, string> = {}): string {
  const dir = join(SCRATCH, `o${counter++}`);
  mkdirSync(dir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), content);
  }
  return dir;
}

const run = (command: string, dir: string, over: Partial<EvaluationContext> = {}) =>
  evaluate(table, { profile: 'STANDARD', mode: 'NORMAL_DELIVERY', repoRoots: [dir], cwd: dir, ...over }, { tool: 'Bash', input: { command } });

/** the human gate for something unread: ASK, and the reason is opacity - not the act the file would have named.
 *  Returns the failure rather than throwing, so one run lists EVERY arrangement that is wrong, not the first. */
function gap(command: string, dir: string, label: string, over: Partial<EvaluationContext> = {}): string | null {
  const r = run(command, dir, over);
  if (r.verdict !== 'ASK') return `${label}: ${command.replaceAll(SCRATCH, '$S')} -> ${r.verdict}`;
  if (!r.hits.some((h) => h.capability === 'command.script-opaque'))
    return `${label}: ${command.replaceAll(SCRATCH, '$S')} is gated for the act it names, not as UNREAD (${r.reason})`;
  return null;
}
function gated(command: string, dir: string, label: string, over: Partial<EvaluationContext> = {}): void {
  assert.equal(gap(command, dir, label, over), null);
}

interface Arranged {
  /** the registered workspace */
  ws: string;
  /** the command, with whatever moves the shell to where the file is */
  wrap: (command: string) => string;
}
interface Arrangement {
  name: string;
  /** places `file` (or, with a null body, nothing) the way this arrangement spells it; null = not runnable here */
  set: (file: string, body: string | null) => Arranged | null;
}

const ARRANGEMENTS: Arrangement[] = [
  {
    name: 'the working directory itself is outside the workspace',
    set: (file, body) => {
      const o = outside(body === null ? {} : { [file]: body });
      return { ws: workspace(), wrap: (c) => `cd ${o} && ${c}` };
    },
  },
  {
    name: 'the same, through pushd',
    set: (file, body) => {
      const o = outside(body === null ? {} : { [file]: body });
      return { ws: workspace(), wrap: (c) => `pushd ${o} && ${c}` };
    },
  },
  {
    name: 'the same, inside a subshell',
    set: (file, body) => {
      const o = outside(body === null ? {} : { [file]: body });
      return { ws: workspace(), wrap: (c) => `(cd ${o} && ${c})` };
    },
  },
  {
    name: 'the file is a link to a file outside the workspace',
    set: (file, body) => {
      const ws = workspace();
      if (body !== null) {
        const real = outside({ [file]: body });
        rmSync(join(ws, file), { force: true });
        symlinkSync(join(real, file), join(ws, file));
      }
      return { ws, wrap: (c) => c };
    },
  },
  {
    name: 'the working directory is reached through a link to a directory outside the workspace',
    set: (file, body) => {
      const ws = workspace();
      symlinkSync(outside(body === null ? {} : { [file]: body }), join(ws, 'link'));
      return { ws, wrap: (c) => `cd link && ${c}` };
    },
  },
  {
    name: 'the file has no read permission',
    set: (file, body) => {
      if (IS_ROOT) return null; // root reads a mode-000 file, so there is nothing unread to pin
      const ws = workspace(body === null ? {} : { [file]: body });
      if (body !== null) chmodSync(join(ws, file), 0o000);
      return { ws, wrap: (c) => c };
    },
  },
];

// `bun run build` is not here: bun is an interpreter, and ASK for that reason whatever the manifest holds
const PRODUCERS: Array<{ file: string; body: string; commands: string[] }> = [
  { file: 'Makefile', body: MAKEFILE, commands: ['make build', 'make -s build'] },
  {
    file: 'package.json',
    body: MANIFEST,
    commands: [
      'npm run build',
      'npm test',
      'pnpm build',
      'pnpm test',
      'yarn build',
      'yarn test',
      'npm run build --silent',
      'npm install --ignore-scripts',
      'npx lint-staged',
    ],
  },
];

test('an existing file that will not be read is gated wherever it sits, for every producer that reads it', () => {
  const failures: string[] = [];
  // one arrangement per (arrangement, producer): evaluating a command changes nothing on disk, and every fixture is a
  // temporary repository, so placing one per command only makes every later evaluation list a longer directory
  for (const a of ARRANGEMENTS)
    for (const p of PRODUCERS) {
      const placed = a.set(p.file, p.body);
      if (placed === null) continue;
      for (const c of p.commands) {
        const f = gap(placed.wrap(c), placed.ws, a.name);
        if (f !== null) failures.push(f);
      }
    }
  assert.deepEqual(failures, []);
});

test('...and the SAME arrangement with the file genuinely absent is ordinary work', () => {
  // the proportionality half: the fix is the existence of the file, not distrust of the place
  const failures: string[] = [];
  for (const a of ARRANGEMENTS)
    for (const p of PRODUCERS) {
      const placed = a.set(p.file, null);
      if (placed === null) continue;
      for (const c of p.commands) {
        const v = run(placed.wrap(c), placed.ws).verdict;
        if (v !== 'ALLOW') failures.push(`${a.name} / ${c} -> ${v}`);
      }
    }
  assert.deepEqual(failures, []);
});

test('a file inside the workspace is still READ, and judged by what it does', () => {
  // the link points INSIDE the registered root, so it is readable and the act it names is what is decided
  const ws = workspace({ 'real/package.json': MANIFEST, 'real/Makefile': MAKEFILE });
  rmSync(join(ws, 'package.json'));
  symlinkSync(join(ws, 'real', 'package.json'), join(ws, 'package.json'));
  assert.equal(run('npm run build', ws).verdict, 'DENY');
  assert.equal(run('npm run build', ws).decisive?.capability, 'git.remote.push.force');
  symlinkSync(join(ws, 'real'), join(ws, 'inner'));
  assert.equal(run('cd inner && make build', ws).decisive?.capability, 'git.remote.push.force');
  assert.equal(run('make -C real build', ws).decisive?.capability, 'git.remote.push.force');
});

test('a manifest the working directory inherits from an outer directory is found through the same search', () => {
  // `cd outer/sub && npm test`: no manifest in `sub`, the nearest is in `outer` - outside the roots, so unread
  const o = outside({ 'package.json': MANIFEST, 'sub/keep': 'x' });
  for (const c of ['npm test', 'npm run build', 'pnpm build', 'yarn test', 'npx lint-staged'])
    gated(`cd ${join(o, 'sub')} && ${c}`, workspace(), 'inherited');
  // ...and a link in the middle of the path changes nothing: npm walks the PHYSICAL parents
  const ws = workspace();
  symlinkSync(join(o, 'sub'), join(ws, 'via'));
  gated('cd via && npm test', ws, 'inherited through a link');
  // a lint-staged configuration that is not a manifest, in a directory above one that has nothing: a directory the
  // roots never covered has no edge to stop the search at
  const rc = outside({ '.lintstagedrc': LS_RC, 'sub/keep': 'x' });
  gated(`cd ${join(rc, 'sub')} && npx lint-staged`, workspace(), 'inherited rc');
});

test('a directory that cannot be searched is not an absence', () => {
  // "I could not look" is not "it is not there": EACCES says nothing about the entry, and only ENOENT and ENOTDIR do
  if (IS_ROOT) return; // root searches any directory
  const ws = workspace({ 'sub/package.json': MANIFEST, 'sub/Makefile': MAKEFILE });
  chmodSync(join(ws, 'sub'), 0o000);
  try {
    for (const c of ['cd sub && npm test', 'cd sub && pnpm build', 'cd sub && npm install --ignore-scripts', 'cd sub && npx lint-staged'])
      gated(c, ws, 'unsearchable');
  } finally {
    chmodSync(join(ws, 'sub'), 0o755);
  }
});

test('the search follows the PHYSICAL parents of the directory the command runs in', () => {
  // npm walks up from the directory it is really in. A session that started in `a/link`, a link to `b/real`, looks
  // in `b/real` and then `b` - not in `a`, which is only where the link happens to be written
  const ws = workspace({ 'a/package.json': JSON.stringify({ scripts: { test: 'tsc' } }), 'b/package.json': MANIFEST, 'b/real/keep': 'x' });
  symlinkSync(join(ws, 'b', 'real'), join(ws, 'a', 'link'));
  assert.equal(run('npm test', ws, { cwd: join(ws, 'a', 'link') }).decisive?.capability, 'git.remote.push.force');
  // the same through a `cd`, which already resolved the link
  assert.equal(run('cd a/link && npm test', ws).decisive?.capability, 'git.remote.push.force');
});

test('an entry that is there but leads nowhere is not an absence', () => {
  // a dangling link is a directory entry the tool's own search sees; "I could not read it" is not "it is not there"
  const ws = workspace();
  rmSync(join(ws, 'package.json'));
  symlinkSync(join(SCRATCH, 'nowhere'), join(ws, 'package.json'));
  symlinkSync(join(SCRATCH, 'nowhere'), join(ws, 'Makefile'));
  for (const c of ['npm test', 'pnpm build', 'make build']) gated(c, ws, 'dangling');
});

test('a command that CREATES the manifest it then runs is not judged from the one that was there', () => {
  // `printf … > package.json && npm run build` was already STALE for the manifest it found; the manifest that did
  // not exist yet - nearer than the one found, or the only one - was never asked about, so the file the command
  // writes decided nothing and `npm run build` was "no such script"
  const made = (n: number) => join(SCRATCH, `made${n}`);
  const write = (dir: string) => `mkdir -p ${dir} && printf '%s' '${MANIFEST}' > ${dir}/package.json`;
  gated(`${write(made(1))} && cd ${made(1)} && npm run build`, workspace(), 'created outside');
  gated(`${write(made(2))} && cd ${made(2)} && npm test`, workspace(), 'created outside');
  gated(`${write(made(3))} && cd ${made(3)} && pnpm build`, workspace(), 'created outside');
  gated(`${write(made(4))} && cd ${made(4)} && yarn build`, workspace(), 'created outside');
  gated(`${write(made(5))} && cd ${made(5)} && npx lint-staged`, workspace(), 'created outside');
  // written after the `cd`, relative to where the shell now is
  gated(`mkdir -p ${made(6)} && cd ${made(6)} && printf '%s' '${MANIFEST}' > package.json && npm test`, workspace(), 'created after cd');
  // the nearer manifest INSIDE the workspace, with an older one above it
  const ws = workspace();
  gated(`mkdir sub && printf '%s' '${MANIFEST}' > sub/package.json && cd sub && npm run build`, ws, 'nearer, inside');
  gated(`mkdir sub && printf '%s' '${MANIFEST}' > sub/package.json && cd sub && npm test`, ws, 'nearer, inside');
  // the Makefile branch already tests the candidate NAMES; the manifest branch now does the same
  gated(`printf 'build:\\n\\t${RECIPE}\\n' > Makefile && make build`, ws, 'created Makefile');
  // a manifest written in place and run is a question, because the command wrote it
  gated(`printf '%s' '${MANIFEST}' > package.json && npm test`, ws, 'rewritten in place');
  // a lint-staged configuration the same command writes is not the one that was there
  gated(`printf '%s' '${LS_RC}' > .lintstagedrc && npx lint-staged`, ws, 'created lint-staged rc');
  // and a command that writes something ELSE leaves the manifest found where it was
  assert.equal(run('mkdir sub && echo x > sub/notes.txt && cd sub && npm run build', workspace()).verdict, 'ALLOW');
  assert.equal(run('touch a.ts && npm test', workspace()).verdict, 'ALLOW');
  assert.equal(run('mkdir app && cd app && npm init -y', workspace()).verdict, 'ALLOW');
});

test('a Makefile in a directory that is outside the workspace or cannot be listed is not an absence', () => {
  // `make -C ../sibling build`: the sibling is outside the registered root
  const ws = workspace();
  const sib = join(dirname(ws), `sib-${counter++}`);
  mkdirSync(sib);
  writeFileSync(join(sib, 'Makefile'), MAKEFILE);
  const rel = relative(ws, sib);
  for (const c of [
    `make -C ${rel} build`,
    `make -C ${sib} build`,
    `make -f ${rel}/Makefile build`,
    `make --directory=${rel} build`,
    `cd ${rel} && make build`,
    `cd ${sib} && make build`,
  ])
    gated(c, ws, 'sibling');
  // a directory that can be entered but not listed still has its Makefile: judged by the file, not the listing
  if (!IS_ROOT) {
    const locked = workspace({ 'sub/Makefile': MAKEFILE });
    chmodSync(join(locked, 'sub'), 0o111);
    try {
      assert.equal(run('make -C sub build', locked).decisive?.capability, 'git.remote.push.force');
      assert.equal(run('cd sub && make build', locked).decisive?.capability, 'git.remote.push.force');
    } finally {
      chmodSync(join(locked, 'sub'), 0o755);
    }
    const empty = workspace({ 'sub/notes.txt': 'x' });
    chmodSync(join(empty, 'sub'), 0o111);
    try {
      assert.equal(run('make -C sub build', empty).verdict, 'ALLOW');
    } finally {
      chmodSync(join(empty, 'sub'), 0o755);
    }
  }
});

test('behind one level of indirection the same file is the same gate', () => {
  // an npm script, a make recipe and a shell script that each change into the outside directory and run what is
  // there: a declared class one level up must not cancel the gate the inner one raises
  const o = outside({ 'package.json': MANIFEST, Makefile: MAKEFILE });
  const inners = [
    `cd ${o} && npm test`,
    `cd ${o} && pnpm build`,
    `(cd ${o}; yarn test)`,
    `cd ${o} && make build`,
    `pushd ${o} && npx lint-staged`,
  ];
  for (const inner of inners) {
    gated('npm run lint', workspace({ 'package.json': JSON.stringify({ scripts: { lint: inner } }) }), `npm script: ${inner}`);
    gated('make lint', workspace({ Makefile: `lint:\n\t${inner}\n` }), `make recipe: ${inner}`);
    gated('./l.sh', workspace({ 'l.sh': `#!/bin/sh\n${inner}\n` }), `shell script: ${inner}`);
    gated('npm run lint', workspace({ 'package.json': JSON.stringify({ scripts: { lint: 'make -C sub lint' } }), 'sub/Makefile': `lint:\n\t${inner}\n` }), `npm -> make -C: ${inner}`);
  }
  // the directory is reached through a link, and the link is inside the workspace
  const ws = workspace({ 'package.json': JSON.stringify({ scripts: { lint: 'cd link && npm run lint' } }) });
  symlinkSync(o, join(ws, 'link'));
  gated('npm run lint', ws, 'a script that changes into a linked directory');
  // a harmless inner command keeps the outer one ordinary
  const quiet = outside({ 'notes.txt': 'x' });
  assert.equal(run('npm run lint', workspace({ 'package.json': JSON.stringify({ scripts: { lint: `cd ${quiet} && npm test` } }) })).verdict, 'ALLOW');
});

test('the gate holds in every profile', () => {
  const o = outside({ 'package.json': MANIFEST });
  for (const profile of ['STANDARD', 'STRICT', 'HIGH_ASSURANCE'])
    gated(`cd ${o} && npm test`, workspace(), profile, { profile });
});

test('a search that was cut off is not an absence, and one that reaches the manifest is ordinary work', () => {
  const ws = workspace();
  const deep = (n: number) => join(ws, ...Array<string>(n).fill('d'));
  mkdirSync(deep(140), { recursive: true });
  gated(`cd ${deep(140)} && npm test`, ws, 'cut off');
  assert.equal(run(`cd ${deep(100)} && npm test`, ws).verdict, 'ALLOW', 'a manifest 100 levels up is still found');
});

test('lint-staged reads every configuration on the way up, not the first name that happens to be listed', () => {
  // a JavaScript configuration ABOVE the working directory is code that runs, wherever the tool is started from
  for (const name of ['lint-staged.config.js', '.lintstagedrc.cjs', 'lint-staged.config.mjs', '.lintstagedrc.ts'])
    gated('cd sub && npx lint-staged', workspace({ [name]: 'module.exports = {}', 'sub/package.json': '{}' }), name);
  // the NEARER configuration is read even when a farther one is listed first and is harmless
  const near = workspace({ '.lintstagedrc': BENIGN_LS_RC, 'sub/.lintstagedrc.json': LS_RC, 'sub/package.json': '{}' });
  assert.equal(run('cd sub && npx lint-staged', near).decisive?.capability, 'git.remote.push.force');
  // a manifest that names no `lint-staged` is not a configuration: the search goes on to the one above it
  const above = workspace({ 'package.json': MANIFEST, 'sub/package.json': '{}' });
  assert.equal(run('cd sub && npx lint-staged', above).decisive?.capability, 'git.remote.push.force');
  // package.yaml is a configuration source when it names lint-staged, and nothing when it does not
  gated('npx lint-staged', workspace({ 'package.yaml': "lint-staged:\n  '*.js': eslint --fix\n" }), 'package.yaml');
  assert.equal(run('npx lint-staged', workspace({ 'package.yaml': 'name: x\n' })).verdict, 'ALLOW');
  // one readable hostile entry beside one unreadable one is judged by the entry that can be read
  const mixed = workspace({ 'package.json': MANIFEST, 'sub/lint-staged.config.js': 'module.exports = {}', 'sub/package.json': '{}' });
  assert.equal(run('cd sub && npx lint-staged', mixed).decisive?.capability, 'git.remote.push.force');
  // the ordinary shapes stay out of the way
  const ordinary = JSON.stringify({ 'lint-staged': { '*.ts': ['eslint --fix', 'prettier -w'] } });
  assert.equal(run('npx lint-staged', workspace({ 'package.json': ordinary })).verdict, 'ALLOW');
  assert.equal(run('cd sub && npx lint-staged', workspace({ '.lintstagedrc': BENIGN_LS_RC, 'sub/package.json': '{}' })).verdict, 'ALLOW');
  assert.equal(run('cd sub && lint-staged', workspace({ 'sub/package.json': '{}' })).verdict, 'ALLOW');
});

test('a package manager reads every rc file beside the manifest, not the first one found', () => {
  const pkg = JSON.stringify({ scripts: { build: 'tsc' } });
  const rc = (files: Record<string, string>) => workspace({ 'package.json': pkg, 'sub/package.json': pkg, ...files });
  // a harmless `.npmrc` used to hide the `.yarnrc.yml` that points yarn at a program of the repository's choosing
  gated('yarn build', rc({ '.npmrc': 'registry=https://registry.npmjs.org/\n', '.yarnrc.yml': 'yarnPath: ./evil.cjs\n' }), 'beside');
  gated('cd sub && yarn build', rc({ 'sub/.npmrc': 'registry=https://registry.npmjs.org/\n', '.yarnrc.yml': 'yarnPath: ./evil.cjs\n' }), 'above');
  // yarn MERGES the file of every directory on the way up
  gated('cd sub && yarn build', rc({ 'sub/.yarnrc.yml': 'enableTelemetry: false\n', '.yarnrc.yml': 'yarnPath: ./evil.cjs\n' }), 'merged');
  // an rc file that sets nothing of the kind is not a reason to ask
  assert.equal(run('yarn build', rc({ '.npmrc': 'registry=https://registry.npmjs.org/\n', '.yarnrc.yml': 'enableTelemetry: false\n' })).verdict, 'ALLOW');
});
