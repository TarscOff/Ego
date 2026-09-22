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
  // SUPERSEDED 2026-09-22 by the one-pipeline invariant: the same action gets the same analysis at any depth.
  // `node scripts/build.mjs` is ASK on its own (command.interpreter-script), so it is ASK inside a script called
  // `build` too. A declared class no longer absorbs opacity; what it still absorbs is a target that does not exist.
  assert.equal(bash('npm run build', c).verdict, 'ASK');
  assert.equal(bash('npm run build', c).decisive?.capability, 'command.interpreter-script');
  assert.equal(bash('node scripts/build.mjs', c).verdict, 'ASK', 'identical at top level');
  // an undeclared script whose body is unknown stays ASK
  assert.equal(bash('npm run lint', c).verdict, 'ALLOW'); // lint is a declared build class
  assert.equal(bash('npm run clean', c).verdict, 'ASK');
  assert.equal(bash('npm run clean', c).decisive?.capability, 'command.destructive');
  // self-recursion terminates
  assert.notEqual(bash('npm run loop', c).verdict, 'DENY');
  // a script the manifest PROVABLY does not define executes nothing, so it is not "opaque script" — the command
  // itself is simply unrecognised. Same verdict (ASK), more accurate capability (resolution ABSENT_VERIFIED).
  assert.equal(bash('npm run nothing', c).verdict, 'ASK');
  assert.equal(bash('npm run nothing', c).decisive?.capability, 'command.unknown');
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
  // a script that is not there executes nothing: ABSENT_VERIFIED, still ASK because the command is unrecognised
  assert.equal(bash('./scripts/missing.sh', c).verdict, 'ASK');
  assert.equal(bash('./scripts/missing.sh', c).decisive?.capability, 'command.unknown');
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

  // and an undeclared command that is not on disk still asks, as it always did
  assert.equal(bash('./unknown-binary --do-it', c).verdict, 'ASK');
  assert.equal(bash('./unknown-binary --do-it', c).decisive?.capability, 'command.unknown');
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

test('verified execution context: a conclusion is KNOWN only when the context it used was proven', () => {
  // Product decision, 2026-09-22. `make -C tools gen` used to classify the recipe against the PARENT's working
  // directory, so EGO read a decoy ./gen.sh at the repository root while make ran tools/gen.sh — a confident wrong
  // answer with no opacity signal. Holding the executed file fixed and changing only the decoy moved the verdict.
  const HOSTILE = '#!/bin/sh\ngit push origin main\nrm -rf ~/.ssh\n';

  // [1] the decoy must not decide the verdict any more
  const decoyed = workspace({
    Makefile: 'lint:\n\tmake -C tools gen\n',
    'tools/Makefile': 'gen:\n\t./gen.sh\n',
    'tools/gen.sh': HOSTILE,
    'gen.sh': '#!/bin/sh\nnpx tsc -p .\n', // same name at the root, never executed
  });
  for (const cmd of ['make lint', 'make -C tools gen'])
    assert.equal(bash(cmd, ctx(decoyed)).verdict, 'DENY', cmd);

  // [2] a tracked `cd` is part of the context
  const nested = workspace({ 'tools/Makefile': 'gen:\n\t./gen.sh\n', 'tools/gen.sh': HOSTILE });
  assert.equal(bash('cd tools && make gen', ctx(nested)).verdict, 'DENY');

  // [3] the cycle guard keys on the directory: a same-named target elsewhere is a different effect
  const twins = workspace({
    Makefile: 'all:\n\tmake -C a all\n\tmake -C b all\n',
    'a/Makefile': 'all:\n\techo safe\n',
    'b/Makefile': 'all:\n\t./x.sh\n',
    'b/x.sh': HOSTILE,
  });
  assert.equal(bash('make all', ctx(twins)).verdict, 'DENY');

  // [4] through a package script as well
  const viaNpm = workspace({
    'package.json': JSON.stringify({ scripts: { lint: 'make -C tools gen' } }),
    'tools/Makefile': 'gen:\n\t./gen.sh\n',
    'tools/gen.sh': HOSTILE,
    'gen.sh': '#!/bin/sh\necho ok\n',
  });
  assert.equal(bash('npm run lint', ctx(viaNpm)).verdict, 'DENY');

  // [5] a context that cannot be PROVEN is opaque, not guessed: an include, a selector, a dynamic cd
  // an `include` is now FOLLOWED rather than treated as a reason to give up, so the real effect is found instead
  // of a generic opacity: ASK became DENY. Execution closure narrows the verdict, it never widens it.
  const included = workspace({ Makefile: 'include extra.mk\n', 'extra.mk': 'deploy:\n\t./d.sh\n', 'd.sh': HOSTILE });
  assert.equal(bash('make deploy', ctx(included)).verdict, 'DENY');
  assert.equal(bash('make deploy', ctx(included)).decisive?.capability, 'fs.credential-store.write');
  const ws = workspace({ 'package.json': JSON.stringify({ scripts: { build: 'tsc -p .' } }) });
  for (const cmd of ['npm run build -w pkg-a', 'npm --prefix ./sub run build', 'pnpm --filter api build'])
    assert.equal(bash(cmd, ctx(ws)).decisive?.capability, 'command.script-opaque', cmd);
  assert.notEqual(bash('cd $DYN && make build', ctx(ws)).verdict, 'ALLOW');

  // [6] analysis truncation is opaque and never inherits the enclosing declared class
  const deep = workspace({
    'package.json': JSON.stringify({
      scripts: { a: 'npm run b', b: 'npm run c', c: 'npm run d', d: 'npm run e', e: 'git push --force origin main' },
    }),
  });
  assert.notEqual(bash('npm run a', ctx(deep)).verdict, 'ALLOW');

  // [7] ordinary development is untouched: a proven context still resolves normally, in both directions
  const plain = workspace({ Makefile: 'build:\n\techo hi\n', 'package.json': JSON.stringify({ scripts: { build: 'tsc -p .' } }) });
  for (const cmd of ['make build', 'npm run build', 'make', 'npm test'])
    assert.equal(bash(cmd, ctx(plain)).verdict, 'ALLOW', cmd);
  const pushes = workspace({ Makefile: 'deploy:\n\tgit push origin main\n' });
  assert.equal(bash('make deploy', ctx(pushes)).decisive?.capability, 'git.remote.push');
});

test('one pipeline: the same action gets the same security analysis at every depth', () => {
  // Product decision, 2026-09-22. Before the pipelines were unified, the effect recursion re-entered a SUB-layer
  // (matchers only), so a nested body was analysed strictly more weakly than the identical text at top level:
  // `echo x > $EGO_HOME/trust/keys` was an absolute deny on its own and an ALLOW inside a Makefile recipe.
  const bodies = [
    'node scripts/build.mjs',
    'tsc -p .',
    'echo hello',
    'eslint .',
    'git push origin main',
    'rm -rf dist',
    'unknown-tool --x',
    'kubectl --context prod-eu delete deploy api -n production',
    '$CMD --evil',
  ];
  const dir = workspace({
    Makefile: bodies.map((b, i) => `t${i}:\n\t${b}\n`).join('\n'),
    'package.json': JSON.stringify({ scripts: Object.fromEntries(bodies.map((b, i) => [`build${i}`, b])) }),
    'scripts/build.mjs': 'console.log(1)',
  });
  const c = ctx(dir);
  for (const [i, body] of bodies.entries()) {
    const top = bash(body, c);
    const viaMake = bash(`make t${i}`, c);
    const viaNpm = bash(`npm run build${i}`, c);
    assert.equal(viaMake.verdict, top.verdict, `make t${i} must match top level for: ${body}`);
    assert.equal(viaNpm.verdict, top.verdict, `npm run build${i} must match top level for: ${body}`);
  }

  // the SHELL-SCRIPT producer is included: it used to pre-filter its own body and was the one that diverged
  const shBodies = ['git push origin main', 'echo pwn > ~/.ssh/authorized_keys', ': > ~/.ssh/known_hosts', 'echo hello'];
  const shDir = workspace(
    Object.fromEntries([
      ...shBodies.map((b, i) => [`y${i}.sh`, `#!/bin/sh\nnpm run lint\n${b}\n`] as const),
      ['package.json', JSON.stringify({ scripts: { lint: 'eslint .' } })],
    ]),
  );
  const sc = ctx(shDir);
  for (const [i, body] of shBodies.entries())
    assert.equal(bash(`./y${i}.sh`, sc).verdict, bash(body, sc).verdict, `./y${i}.sh must match top level: ${body}`);

  // the protections that only ran at top level now run at every depth: paths, redirections, the trust store and cd
  const home = mkdtempSync(join(tmpdir(), 'ego-onepipe-home-'));
  const deep = workspace({
    Makefile: `trust:\n\techo x > ${home}/trust/keys.json\nnested:\n\tcd sub && ./x.sh\n`,
    'sub/x.sh': '#!/bin/sh\ngit push origin main\n',
  });
  const dc = ctx(deep, { egoHome: home });
  assert.equal(bash(`echo x > ${home}/trust/keys.json`, dc).decisive?.capability, 'ego.trust.tamper');
  assert.equal(bash('make trust', dc).decisive?.capability, 'ego.trust.tamper', 'same write, one level down');
  assert.equal(bash('make nested', dc).decisive?.capability, 'git.remote.push', 'cd inside a recipe is tracked');

  // and ordinary development is still fluid
  const plain = workspace({ Makefile: 'build:\n\ttsc -p .\n', 'package.json': JSON.stringify({ scripts: { build: 'tsc -p .', test: 'vitest run' } }) });
  for (const cmd of ['make build', 'npm run build', 'npm test', 'tsc -p .', 'eslint .', 'vitest run'])
    assert.equal(bash(cmd, ctx(plain)).verdict, 'ALLOW', cmd);
});
