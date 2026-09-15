import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, existsSync, readdirSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { installGitHooks, shimScript } from '../src/project/githooks.ts';

test('git hooks are never installed into an enclosing repository of a non-toplevel directory', () => {
  const outer = mkdtempSync(join(tmpdir(), 'ego-outer-'));
  spawnSync('git', ['init', '-q'], {
    cwd: outer,
    env: Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^GIT_/.test(k))),
  });
  const inner = join(outer, 'not-a-repo');
  mkdirSync(inner);
  const r = installGitHooks(inner, null);
  assert.equal(r.installed.length, 0);
  assert.match(r.refused ?? '', /is not the top level of a git repository \(enclosing repository: /);
  const hooks = readdirSync(join(outer, '.git', 'hooks')).filter((f) => !f.endsWith('.sample'));
  assert.deepEqual(hooks, [], 'the enclosing repository hooks are untouched');
  assert.ok(!existsSync(join(inner, '.harness')), 'nothing written into the non-repository directory either');
  // a directory outside any repository is refused too
  const plain = mkdtempSync(join(tmpdir(), 'ego-plain-'));
  assert.match(installGitHooks(plain, null).refused ?? '', /is not the top level of a git repository/);
  // the toplevel itself installs normally
  const ok = installGitHooks(outer, null);
  assert.equal(ok.refused, null);
  assert.ok(existsSync(join(outer, '.git', 'hooks', 'pre-commit')));
});

test('chained hooks run and do not word-split when the repository path contains a space', () => {
  const noGit = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^GIT_/.test(k)));
  // a real repo whose absolute path contains a space, plus a fake `harness` on PATH so the shim exits 0
  const base = mkdtempSync(join(tmpdir(), 'ego sp-'));
  const repo = join(base, 'my repo');
  mkdirSync(repo, { recursive: true });
  spawnSync('git', ['init', '-q'], { cwd: repo, env: noGit() });
  const bin = join(base, 'bin');
  mkdirSync(bin);
  writeFileSync(join(bin, 'harness'), '#!/bin/sh\nexit 0\n');
  chmodSync(join(bin, 'harness'), 0o755);
  const env = { ...noGit(), PATH: `${bin}:${process.env.PATH ?? ''}` };

  // (1) governed path: a pre-existing executable pre-commit hook is chained by installGitHooks (runs git-hook.sh)
  const preCommit = join(repo, '.git', 'hooks', 'pre-commit');
  const marker = join(repo, 'CHAINED_RAN');
  writeFileSync(preCommit, `#!/bin/sh\ntouch '${marker}'\n`);
  chmodSync(preCommit, 0o755);
  const install = installGitHooks(repo, null);
  assert.equal(install.refused, null, install.refused ?? '');
  const run = spawnSync('sh', [preCommit], { cwd: repo, env });
  assert.equal(run.status, 0, `exit ${run.status}; stderr: ${run.stderr}`);
  assert.ok(existsSync(marker), 'the chained hook must run (no word-splitting on the spaced path)');
  assert.doesNotMatch(String(run.stderr), /No such file or directory/, 'no spaced-path split error');

  // (2) ungoverned checkout branch of shimScript: same spaced path, no .harness at all
  const base2 = mkdtempSync(join(tmpdir(), 'ego sp2-'));
  const repo2 = join(base2, 'my repo');
  mkdirSync(repo2, { recursive: true });
  spawnSync('git', ['init', '-q'], { cwd: repo2, env: noGit() });
  const shimPath = join(repo2, '.git', 'hooks', 'pre-commit');
  writeFileSync(shimPath, shimScript('pre-commit'));
  chmodSync(shimPath, 0o755);
  const marker2 = join(repo2, 'CHAINED_RAN');
  const chained = join(repo2, '.git', 'hooks', 'pre-commit.pre-ego');
  writeFileSync(chained, `#!/bin/sh\ntouch '${marker2}'\n`);
  chmodSync(chained, 0o755);
  const run2 = spawnSync('sh', [shimPath], { cwd: repo2, env: noGit() });
  assert.equal(run2.status, 0, `ungoverned exit ${run2.status}; stderr: ${run2.stderr}`);
  assert.ok(existsSync(marker2), 'ungoverned shimScript must run the chained hook on a spaced path');
  assert.doesNotMatch(String(run2.stderr), /No such file or directory/, 'no spaced-path split error');
});
