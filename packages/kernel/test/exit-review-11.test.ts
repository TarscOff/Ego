// EXIT REVIEW 11 (2026-09-30): 258 confirmed (209 unauthorized ALLOW, 16 CRITICAL, 119 HIGH), ZERO new classes, two lenses
// clean. This file pins the subset that was fixed in the same sitting - my own regressions, the CRITICAL findings and the
// cheap structural ones. The rest is recorded in docs/architecture/phase-1-residuals.md as OPEN, by cause.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { workspace, verdict } from './support/corpus.ts';

test('regressions of mine that the fresh review found', () => {
  const dir = workspace({ 'x.yaml': 'kind: Deployment\n' });
  // `help` last is a pseudo-command of the cloud CLIs only: for git it is a branch name
  for (const c of ['git push origin help', 'git branch help && git push origin help', 'docker volume rm pgdata help'])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  assert.equal(verdict('git push origin help', dir), 'DENY');
  assert.equal(verdict('aws ec2 terminate-instances help', dir), 'ALLOW');
  // the LAST dry-run flag decides
  assert.equal(verdict('kubectl --context production apply -f x.yaml --dry-run=client --dry-run=none', dir), 'DENY');
  assert.equal(verdict('kubectl --context production apply -f x.yaml --dry-run=none --dry-run=client', dir), 'ALLOW');
  // a `#` is a comment only where a word STARTS
  for (const c of ['echo $(true)#x; git push origin main', 'echo a\\ #b; git push origin main', 'echo ${x:- #}; git push origin main', 'echo a #b; git push origin main'])
    assert.equal(verdict(c, dir), 'DENY', c);
  assert.equal(verdict('echo hi # git push origin main', dir), 'ALLOW');
  // a message flag's VALUE is data even when it looks like the flag: `-m -m -n` has the flag -n
  for (const c of ['git commit -m -m -n', 'git commit -m x $"--no-verify"', 'git commit -m x -n>/dev/null', "git commit --allow-empty-message -m {'',} -n", "git commit -m x {-$'n',-$'n'}"])
    assert.equal(verdict(c, dir), 'DENY', c);
  assert.equal(verdict('git commit -m "-n"', dir), 'ALLOW');
});

test('a brace result is not quoted around a redirection operator, and an operator ends a word first', () => {
  const dir = workspace();
  for (const c of [
    'echo x 1>.harnes{s..s}/runtime/pin.json',
    'echo x>.harnes{s..s}/runtime/pin.json',
    'echo x &>.harnes{s..s}/runtime/pin.json',
    'echo x >|.harnes{s..s}/runtime/pin.json',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  assert.equal(verdict('echo {a,b} > out.txt', dir), 'ALLOW');
});

test('a writer whose operand is built at run time asks, and a variable the line assigned is substituted', () => {
  const dir = workspace({ 'README.md': 'x' });
  for (const c of [
    'f=.claude/settings.json; tee $f',
    'f=control-plane/permissions/matchers.md; sed -i s/a/b/ "$f"',
    'V=.claude/settings.json; echo x | tee $V',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  for (const c of ['touch "$(echo .harness/runtime/pin.json)"', 'tee $(find . -name matchers.md)', 'find . -name pre-commit -exec cp src/a.ts {} \\;', 'cp a "$DEST"'])
    assert.equal(verdict(c, dir), 'ASK', c);
  assert.equal(verdict('f=README.md; tee $f', dir), 'ALLOW');
  assert.equal(verdict('echo $HOME', dir), 'ALLOW');
});

test('function bindings: removed by any spelling of unset, never made by a short-circuit or a substitution', () => {
  const dir = workspace();
  for (const c of [
    'git() { true; }; builtin unset -f git; git push origin main',
    'git() { true; }; command unset -f git; git push origin main',
    'git() { true; }; FOO=1 unset -f git; git push origin main',
    'false && git() { true; }; git push origin main',
    'true || git() { true; }; git push origin main',
    'echo `git() { true; }`; git push origin main',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  assert.equal(verdict('log() { echo hi; }; log start', dir), 'ALLOW');
});

test('variables reach the make two producers down', () => {
  const nested = workspace({ Makefile: 'CMD = echo hi\nrun:\n\tmake other\nother:\n\t$(CMD)\n' });
  assert.equal(verdict('make run CMD="git push origin main"', nested), 'DENY');
  assert.equal(verdict('make run', nested), 'ALLOW');
  const viaNpm = workspace({ 'package.json': '{"scripts":{"build":"make other"}}', Makefile: 'CMD ?= echo hi\nother:\n\t$(CMD)\n' });
  assert.equal(verdict('CMD="git push origin main" npm run build', viaNpm), 'DENY');
  assert.equal(verdict('npm run build', viaNpm), 'ALLOW');
});

test('small closed gaps: a value option kubectl has, venv --clear, mongosh inline JavaScript, a documentation grep', () => {
  const dir = workspace();
  assert.equal(verdict('kubectl --context eks-customer --as-user-extra get delete pod x', dir), 'DENY');
  assert.equal(verdict('python3 -m venv --clear .', dir), 'DENY');
  assert.equal(verdict('python3 -m venv .venv', dir), 'ALLOW');
  assert.notEqual(verdict(`mongosh --eval 'require("child_process").execSync("git push origin main")'`, dir), 'ALLOW');
  assert.equal(verdict(`mongosh --eval 'db.stats()'`, dir), 'ALLOW');
  assert.equal(verdict('grep -rn "ego hook" docs/', dir), 'ALLOW');
  assert.equal(verdict('ego hook claude-code PreToolUse', dir), 'DENY');
});
