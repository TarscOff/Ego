import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadControlPlane } from '../src/control-plane/load.ts';
import { compileAuthority } from '../src/authority/compile.ts';
import { evaluate, type EvaluationContext } from '../src/authority/evaluate.ts';

const ROOT = new URL('../../../control-plane/', import.meta.url).pathname;
const table = compileAuthority(loadControlPlane(ROOT));

function workspace(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'ego-effects-'));
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(join(dir, rel, '..'), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

function ctx(cwd: string, extra: Partial<EvaluationContext> = {}): EvaluationContext {
  return { profile: 'STANDARD', mode: 'NORMAL_DELIVERY', repoRoots: [cwd], cwd, ...extra };
}

const bash = (command: string, c: EvaluationContext) =>
  evaluate(table, c, { tool: 'Bash', input: { command } });

test('npm run scripts are classified by their effect (alignment item 5)', () => {
  const dir = workspace({
    'package.json': JSON.stringify({
      scripts: {
        deploy: 'npm run build && git push origin main',
        build: 'node scripts/build.mjs',
        release: 'gh pr create --fill',
        ship: 'npm run deploy',
        loop: 'npm run loop',
        prodkill: 'kubectl --context prod-eu delete deployment api -n production',
        lint: 'eslint .',
        clean: 'rm -rf dist',
      },
    }),
  });
  const c = ctx(dir);
  const deploy = bash('npm run deploy', c);
  assert.equal(deploy.verdict, 'DENY');
  assert.equal(deploy.decisive?.capability, 'git.remote.push');
  assert.match(deploy.reason, /effect of package\.json script "deploy"/);
  // nested: ship → deploy → git push
  assert.equal(bash('npm run ship', c).decisive?.capability, 'git.remote.push');
  assert.equal(bash('npm run release', c).decisive?.capability, 'forge.pr.create');
  assert.equal(bash('npm run prodkill', c).decisive?.capability, 'production.k8s.mutate');
  // a declared class (command.build) is not escalated by an opaque interpreter script inside it
  assert.equal(bash('npm run build', c).verdict, 'ALLOW');
  // an undeclared script whose body is unknown stays ASK
  assert.equal(bash('npm run lint', c).verdict, 'ALLOW'); // lint is a declared build class
  assert.equal(bash('npm run clean', c).verdict, 'ASK');
  assert.equal(bash('npm run clean', c).decisive?.capability, 'command.destructive');
  // self-recursion terminates
  assert.notEqual(bash('npm run loop', c).verdict, 'DENY');
  // a missing script is opaque
  assert.equal(bash('npm run nothing', c).decisive?.capability, 'command.script-opaque');
  // yarn / pnpm shorthand
  assert.equal(bash('yarn deploy', c).decisive?.capability, 'git.remote.push');
  assert.equal(bash('pnpm release', c).decisive?.capability, 'forge.pr.create');
  // the grant cannot open an organization-locked deny found inside an effect
  assert.equal(bash('npm run deploy', ctx(dir, { grants: ['git.remote.push'] })).verdict, 'DENY');
  // organization-locked denies are explained as such
  assert.match(deploy.reason, /organization-locked deny/);
});

test('shell scripts are read and classified when static and inside the workspace', () => {
  const dir = workspace({
    'scripts/safe.sh':
      '#!/usr/bin/env bash\nset -euo pipefail\n# comment\nnpm test\nif npm run build; then\n  echo ok # trailing\nfi\nfor f in a b; do ls "$f"; done\n',
    'scripts/push.sh': '#!/bin/bash\nset -e\nnpm test\ngit push origin HEAD\n',
    'scripts/dynamic.sh': '#!/bin/bash\nCMD="git push"\n$CMD\n',
    'scripts/evil-eval.sh': '#!/bin/bash\neval "$(cat cmd.txt)"\n',
    'scripts/nested.sh': '#!/bin/bash\n./scripts/push.sh\n',
    'scripts/heredoc.sh': '#!/bin/bash\ncat <<EOF\ngit push origin main\nEOF\nls\n',
    'scripts/curl.sh': '#!/bin/bash\ncurl -X POST https://example.com/hook\n',
    'bin/tool': '#!/usr/bin/env python3\nprint(1)\n',
  });
  const c = ctx(dir);
  assert.equal(bash('./scripts/safe.sh', c).verdict, 'ALLOW');
  assert.equal(bash('bash scripts/safe.sh', c).verdict, 'ALLOW');
  assert.equal(bash('sh ./scripts/safe.sh --flag', c).verdict, 'ALLOW');
  const push = bash('./scripts/push.sh', c);
  assert.equal(push.verdict, 'DENY');
  assert.equal(push.decisive?.capability, 'git.remote.push');
  assert.equal(bash('./scripts/dynamic.sh', c).decisive?.capability, 'command.script-opaque');
  assert.equal(bash('./scripts/evil-eval.sh', c).decisive?.capability, 'command.script-opaque');
  assert.equal(bash('./scripts/nested.sh', c).decisive?.capability, 'git.remote.push');
  assert.equal(bash('source scripts/push.sh', c).decisive?.capability, 'git.remote.push');
  assert.equal(bash('. scripts/push.sh', c).decisive?.capability, 'git.remote.push');
  // heredoc bodies are data, not commands
  assert.equal(bash('./scripts/heredoc.sh', c).verdict, 'ALLOW');
  assert.equal(bash('./scripts/curl.sh', c).decisive?.capability, 'command.network-tool');
  // a non-shell executable is opaque
  assert.equal(bash('./bin/tool', c).decisive?.capability, 'command.script-opaque');
  // outside the workspace: never read
  assert.equal(bash('/etc/profile', c).decisive?.capability, 'command.script-opaque');
  // missing script
  assert.equal(bash('./scripts/missing.sh', c).decisive?.capability, 'command.script-opaque');
  // oversized script is opaque
  const big = workspace({ 'big.sh': '#!/bin/bash\n' + 'ls\n'.repeat(40000) });
  assert.equal(bash('./big.sh', ctx(big)).decisive?.capability, 'command.script-opaque');
});

test('interpreters and inline code never bypass policy', () => {
  const dir = workspace({ 'deploy.js': 'require("child_process").execSync("git push")', 'x.py': 'print(1)' });
  const c = ctx(dir);
  assert.equal(bash('node deploy.js', c).decisive?.capability, 'command.interpreter-script');
  assert.equal(bash('python x.py', c).decisive?.capability, 'command.interpreter-script');
  assert.equal(bash('python3 x.py --flag', c).verdict, 'ASK');
  assert.equal(bash('tsx scripts/run.ts', c).verdict, 'ASK');
  assert.equal(
    bash("node -e \"require('fs').rmSync('x')\"", c).decisive?.capability,
    'command.interpreter-inline',
  );
  assert.equal(bash('node -e "console.log(1)"', c).verdict, 'ALLOW');
  assert.equal(bash('node --version', c).verdict, 'ALLOW');
  assert.equal(bash('node --test', c).verdict, 'ALLOW');
});

test('make targets are classified by their recipe', () => {
  const dir = workspace({
    Makefile:
      '.PHONY: all build deploy\nall: build\n\nbuild:\n\t@npm run typecheck\n\tnpm test\n\ndeploy: build\n\tgit push origin main\n\ndyn:\n\t$(DEPLOY_CMD)\n',
    'package.json': JSON.stringify({ scripts: { typecheck: 'tsc --noEmit' } }),
  });
  const c = ctx(dir);
  assert.equal(bash('make build', c).verdict, 'ALLOW');
  assert.equal(bash('make deploy', c).decisive?.capability, 'git.remote.push');
  // make is a declared build class, and opacity INSIDE a resolved recipe still does not escalate it.
  // But a recipe built from a variable (`dyn: $(DEPLOY_CMD)`) is not resolved at all: something WILL run that
  // could not be read. The layered security contract (decision "option B", 2026-09-22) narrows September
  // alignment item 5 here — unknown execution asks a human while EGO claims no containment. This assertion
  // deliberately replaces the previous `ALLOW`.
  assert.equal(bash('make dyn', c).verdict, 'ASK');
  assert.equal(bash('make dyn', c).decisive?.capability, 'command.script-opaque');
  // a target that simply does not exist fails harmlessly and is not escalated
  assert.equal(bash('make nosuchtarget', c).verdict, 'ALLOW');
  assert.equal(bash('make', c).verdict, 'ALLOW');
});

test('EGO_HOME trust store writes are ego.trust.tamper in every profile', () => {
  const dir = workspace({});
  const home = join(dir, 'home');
  for (const profile of ['STANDARD', 'STRICT', 'HIGH_ASSURANCE']) {
    for (const mode of ['NORMAL_DELIVERY', 'EGO_MAINTENANCE']) {
      const c = ctx(dir, { profile, mode, egoHome: home, inEgoRepository: true });
      const r = evaluate(table, c, { tool: 'Write', input: { file_path: join(home, 'trust', 'keys.json') } });
      assert.equal(r.verdict, 'DENY', `${profile}/${mode}`);
      assert.equal(r.decisive?.capability, 'ego.trust.tamper');
    }
  }
  const c = ctx(dir, { egoHome: home });
  assert.equal(
    evaluate(table, c, { tool: 'Read', input: { file_path: join(home, 'trust', 'keys.json') } }).verdict,
    'ALLOW',
  );
  assert.equal(bash(`rm -rf ~/.ego/trust/keys.json`, c).decisive?.capability, 'ego.trust.tamper');
});

test('layered contract: unknown execution never becomes a silent ALLOW without containment', () => {
  // Decision "option B", 2026-09-22. EGO claims NO containment today (real sandboxing is issue #26 and will be
  // required only in HIGH_ASSURANCE), so every path where something WILL run that could not be read must reach a
  // human. A target that simply does not exist is NOT such a path: the command fails harmlessly.
  const dir = workspace({
    Makefile: 'dyn:\n\t$(DEPLOY_CMD)\n\nreal:\n\techo hello\n',
    'package.json': JSON.stringify({ scripts: { build: 'tsc -p .' } }),
    'scripts/opaque.sh': '#!/bin/sh\n"$UNKNOWN_CMD"\n',
  });
  const c = ctx(dir);

  // something WILL run that could not be read -> the human gate
  for (const cmd of ['make dyn']) {
    const r = bash(cmd, c);
    assert.equal(r.verdict, 'ASK', cmd);
    assert.equal(r.decisive?.capability, 'command.script-opaque', cmd);
  }

  // the target does not exist: the command fails on its own, so it is not escalated
  for (const cmd of ['make nosuchtarget', 'npm test', 'npm run nosuchscript-build'])
    assert.notEqual(bash(cmd, c).verdict, 'DENY', cmd);

  // a resolved effect keeps being judged by what it actually does, in both directions
  assert.equal(bash('make real', c).verdict, 'ALLOW');
  assert.equal(bash('npm run build', c).verdict, 'ALLOW');

  // and an undeclared opaque command still asks, as it always did
  assert.equal(bash('./unknown-binary --do-it', c).decisive?.capability, 'command.script-opaque');
});

test('layered contract, round 2: missing vs unread is decided by EXISTENCE, at every depth', () => {
  // Challenge finding 1: the discriminator used to be a prose regex over the reason string, and it collapsed
  // "the file is not there" into "the file is there but I could not read it". With the identical recipe behind an
  // oversized, unreadable, malformed or out-of-workspace manifest, a declared class kept ALLOW.
  const RECIPE = 'git push --force origin main';
  const BIG = '# pad\n'.repeat(12000); // > MAX_SCRIPT_BYTES

  const readable = workspace({ Makefile: `build:\n\t${RECIPE}\n` });
  assert.equal(bash('make build', ctx(readable)).decisive?.capability, 'git.remote.push.force');

  // the SAME recipe, only the readability changes -> the human gate, in every profile
  const oversized = workspace({ Makefile: BIG + `build:\n\t${RECIPE}\n` });
  for (const profile of ['STANDARD', 'STRICT', 'HIGH_ASSURANCE']) {
    const r = bash('make build', ctx(oversized, { profile }));
    assert.equal(r.verdict, 'ASK', profile);
    assert.equal(r.decisive?.capability, 'command.script-opaque', profile);
  }

  // no Makefile at all: `make` fails on its own, nothing runs, ordinary work is not interrupted
  assert.equal(bash('make build', ctx(workspace({}))).verdict, 'ALLOW');
  assert.equal(bash('npm test', ctx(workspace({}))).verdict, 'ALLOW');

  // the same for a manifest: oversized and malformed are unread; absent is missing
  const bigPkg = workspace({ 'package.json': JSON.stringify({ pad: BIG, scripts: { test: RECIPE } }) });
  assert.equal(bash('npm test', ctx(bigPkg)).decisive?.capability, 'command.script-opaque');
  const bomPkg = workspace({ 'package.json': '﻿' + JSON.stringify({ scripts: { test: RECIPE } }) });
  assert.equal(bash('npm test', ctx(bomPkg)).decisive?.capability, 'command.script-opaque');
  // an install lifecycle behind an unread manifest is unread too
  assert.equal(bash('npm install', ctx(bigPkg)).decisive?.capability, 'command.script-opaque');

  // ONE LEVEL OF INDIRECTION must not cancel the gate (challenge findings 2, 16, 20)
  const indirect = workspace({
    'package.json': JSON.stringify({ scripts: { lint: 'sh ./big.sh', build: 'make -f big.mk all' } }),
    'big.sh': '#!/bin/sh\n' + BIG + RECIPE + '\n',
    'big.mk': BIG + `all:\n\t${RECIPE}\n`,
  });
  assert.equal(bash('npm run lint', ctx(indirect)).decisive?.capability, 'command.script-opaque');
  assert.equal(bash('npm run build', ctx(indirect)).decisive?.capability, 'command.script-opaque');

  // a resolved effect is still judged by what it actually does, in both directions
  assert.equal(bash('make build', ctx(workspace({ Makefile: 'build:\n\techo hi\n' }))).verdict, 'ALLOW');
});
