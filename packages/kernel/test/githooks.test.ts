import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { installGitHooks } from '../src/project/githooks.ts';

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
