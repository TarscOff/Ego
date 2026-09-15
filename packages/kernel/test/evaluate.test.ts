import { test } from 'node:test';
import assert from 'node:assert/strict';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { loadControlPlane } from '../src/control-plane/load.ts';
import { compileAuthority } from '../src/authority/compile.ts';
import {
  evaluate,
  splitShellSegments,
  normalizeSegment,
  type EvaluationContext,
} from '../src/authority/evaluate.ts';

const ROOT = new URL('../../../control-plane/', import.meta.url).pathname;
const table = compileAuthority(loadControlPlane(ROOT));
const repo = mkdtempSync(join(tmpdir(), 'ego-eval-repo-'));
const ctx = (over: Partial<EvaluationContext> = {}): EvaluationContext => ({
  profile: 'STRICT',
  mode: 'NORMAL_DELIVERY',
  repoRoots: [repo],
  cwd: repo,
  ...over,
});

const bash = (command: string, c = ctx()) => evaluate(table, c, { tool: 'Bash', input: { command } });

test('shell segmentation handles operators, quotes and substitutions', () => {
  assert.deepEqual(splitShellSegments('git add . && git commit -m "a; b" || echo no; ls | wc -l'), [
    'git add .',
    'git commit -m "a; b"',
    'echo no',
    'ls',
    'wc -l',
  ]);
  assert.deepEqual(splitShellSegments('echo $(git push origin main)'), [
    'git push origin main',
    'echo $SUBST',
  ]);
  assert.deepEqual(normalizeSegment('FOO=1 BAR="x y" env time git status'), ['git status']);
  assert.deepEqual(normalizeSegment("bash -c 'git push'"), ['bash -c', 'git push']);
});

test('absolute denies win in every profile and mode, including compound commands', () => {
  for (const profile of ['STANDARD', 'STRICT', 'HIGH_ASSURANCE']) {
    for (const mode of ['NORMAL_DELIVERY', 'HARNESS_MAINTENANCE', 'PRODUCTION_ADVISORY', 'BENCHMARK']) {
      const c = ctx({ profile, mode });
      assert.equal(bash('git push origin main', c).verdict, 'DENY', `${profile}/${mode}`);
      assert.equal(bash('git push --force', c).decisive?.capability, 'git.remote.push.force');
      assert.equal(bash('ls && git push', c).verdict, 'DENY');
      assert.equal(bash('gh pr merge 12 --squash', c).verdict, 'DENY');
      assert.equal(bash('glab mr merge 7', c).verdict, 'DENY');
      assert.equal(bash('kubectl --context prod-eu apply -f x.yaml', c).verdict, 'DENY');
      assert.equal(bash('rm -rf /', c).decisive?.capability, 'fs.destructive-root');
      assert.equal(
        bash('harness decision answer "D-1 option 2"', c).decisive?.capability,
        'harness.gate.bypass',
      );
      assert.equal(bash('echo x | harness hook UserPromptSubmit', c).verdict, 'DENY');
      assert.equal(
        bash('claude -p "D-1 option 2"', c).decisive?.capability,
        'harness.launcher.invoke-nested',
      );
    }
  }
});

test('grants only move ASK to ALLOW and never touch DENY', () => {
  assert.equal(bash('git commit -m x').verdict, 'ASK');
  assert.equal(bash('git commit -m x', ctx({ grants: ['git.local.commit'] })).verdict, 'ALLOW');
  assert.equal(bash('git push', ctx({ grants: ['git.remote.push'] })).verdict, 'DENY');
  assert.equal(bash('git commit -m x', ctx({ profile: 'STANDARD' })).verdict, 'ALLOW');
});

test('read-only, build and test commands are allowed; unknown commands ask', () => {
  assert.equal(bash('ls -la && grep -r foo src').verdict, 'ALLOW');
  assert.equal(bash('npm test').verdict, 'ALLOW');
  assert.equal(bash('npm run build').verdict, 'ALLOW');
  assert.equal(bash('some-unknown-tool --flag').verdict, 'ASK');
  assert.equal(bash('some-unknown-tool --flag').decisive?.capability, 'command.unknown');
  assert.equal(bash('sudo rm -rf ./build').verdict, 'ASK');
});

test('PRODUCTION_ADVISORY denies local mutation while leaving reads allowed', () => {
  const c = ctx({ mode: 'PRODUCTION_ADVISORY', profile: 'STANDARD' });
  assert.equal(bash('git status', c).verdict, 'ALLOW');
  assert.equal(bash('npm install left-pad', c).verdict, 'DENY');
  assert.equal(
    evaluate(table, c, { tool: 'Write', input: { file_path: join(repo, 'src/a.ts') } }).verdict,
    'DENY',
  );
});

test('paths: credential stores denied, hook config denied, repo writes allowed, outside workspace asks', () => {
  const c = ctx();
  assert.equal(
    evaluate(table, c, { tool: 'Read', input: { file_path: join(homedir(), '.ssh/id_ed25519') } }).decisive
      ?.capability,
    'fs.credential-store.read',
  );
  assert.equal(
    evaluate(table, c, { tool: 'Write', input: { file_path: join(homedir(), '.aws/credentials') } }).verdict,
    'DENY',
  );
  assert.equal(
    evaluate(table, c, { tool: 'Edit', input: { file_path: join(repo, '.claude/settings.json') } }).decisive
      ?.capability,
    'fs.hook-config.write',
  );
  assert.equal(
    evaluate(table, c, { tool: 'Write', input: { file_path: join(repo, '.harness/generated/policy.json') } })
      .verdict,
    'DENY',
  );
  assert.equal(
    evaluate(table, c, { tool: 'Write', input: { file_path: join(repo, 'src/x.ts') } }).verdict,
    'ALLOW',
  );
  assert.equal(evaluate(table, c, { tool: 'Write', input: { file_path: '/etc/hosts' } }).verdict, 'DENY');
  assert.equal(
    evaluate(table, c, { tool: 'Read', input: { file_path: '/var/log/system.log' } }).verdict,
    'ASK',
  );
  assert.equal(
    evaluate(table, c, { tool: 'Read', input: { file_path: join(repo, '.env') } }).decisive?.capability,
    'fs.env-file.read',
  );
  assert.equal(
    evaluate(table, c, { tool: 'Write', input: { file_path: join(repo, '.env.local') } }).verdict,
    'DENY',
  );
});

test('apply_patch without parseable headers is denied; with headers it is classified per path', () => {
  const c = ctx();
  assert.equal(evaluate(table, c, { tool: 'apply_patch', input: { command: 'garbage' } }).verdict, 'DENY');
  const ok = evaluate(table, c, {
    tool: 'apply_patch',
    input: { command: '*** Begin Patch\n*** Update File: src/a.ts\n@@\n*** End Patch' },
  });
  assert.equal(ok.verdict, 'ALLOW');
});

test('URLs: localhost allowed, public read asks in STRICT and is denied in HIGH_ASSURANCE', () => {
  assert.equal(
    evaluate(table, ctx(), { tool: 'WebFetch', input: { url: 'http://localhost:3000/health' } }).verdict,
    'ALLOW',
  );
  assert.equal(
    evaluate(table, ctx(), { tool: 'WebFetch', input: { url: 'https://docs.example.com' } }).verdict,
    'ASK',
  );
  assert.equal(
    evaluate(table, ctx({ profile: 'HIGH_ASSURANCE' }), {
      tool: 'WebFetch',
      input: { url: 'https://docs.example.com' },
    }).verdict,
    'DENY',
  );
});

test('unknown MCP tools are denied by default', () => {
  assert.equal(evaluate(table, ctx(), { tool: 'mcp__foo__bar', input: {} }).verdict, 'DENY');
});
