// Adversarial regression tests from the phase-1 independent review: every case here was a reproduced bypass.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { loadControlPlane } from '../src/control-plane/load.ts';
import { compileAuthority } from '../src/authority/compile.ts';
import {
  evaluate,
  normalizeSegment,
  redirectionTargets,
  stripToolGlobalOptions,
  type EvaluationContext,
} from '../src/authority/evaluate.ts';

const ROOT = new URL('../../../control-plane/', import.meta.url).pathname;
const table = compileAuthority(loadControlPlane(ROOT));
const repo = mkdtempSync(join(tmpdir(), 'ego-bypass-'));
mkdirSync(join(repo, '.git', 'hooks'), { recursive: true });
writeFileSync(join(repo, 'package.json'), '{}');
const home = mkdtempSync(join(tmpdir(), 'ego-bypass-home-'));
const ctx = (over: Partial<EvaluationContext> = {}): EvaluationContext => ({
  profile: 'STANDARD',
  mode: 'NORMAL_DELIVERY',
  repoRoots: [repo],
  cwd: repo,
  egoHome: home,
  ...over,
});
const bash = (command: string, c = ctx()) => evaluate(table, c, { tool: 'Bash', input: { command } });

test('global option flags before the subcommand never hide a push or a PR mutation', () => {
  for (const cmd of [
    'git -C . push origin main',
    'git -c protocol.version=2 push origin main',
    'git --git-dir=.git --work-tree=. push origin main',
    'git --no-pager -C /tmp/other push --force origin main',
    'git -C . push origin :refs/tags/v1',
    '/usr/bin/git -C . push',
    'gh -R owner/repo pr create --fill',
    'gh --repo owner/repo pr merge 3 --squash',
    'gh --repo=owner/repo pr merge 3',
    'glab -R owner/repo mr merge 3',
    'git -C . -c core.hooksPath=/dev/null push',
  ]) {
    const r = bash(cmd);
    assert.equal(r.verdict, 'DENY', cmd);
    assert.notEqual(r.decisive?.capability, 'command.unknown', cmd);
  }
  assert.ok(
    ['git.remote.push', 'git.hooks.bypass'].includes(
      bash('git -C . push --no-verify origin main').decisive?.capability ?? '',
    ),
  );
  assert.equal(bash('git -c core.hooksPath=/dev/null commit -m x').decisive?.capability, 'git.hooks.bypass');
  assert.equal(bash('git commit --no-verify -m x').decisive?.capability, 'git.hooks.bypass');
  assert.deepEqual(
    stripToolGlobalOptions('git', ['git', '-C', 'x', '-c', 'a=b', '--no-pager', 'status']).rest,
    ['git', 'status'],
  );
  assert.deepEqual(normalizeSegment('git -C sub status'), ['git status']);
  // ordinary work is unaffected
  assert.equal(bash('git -C . status').verdict, 'ALLOW');
  assert.equal(bash('gh -R owner/repo pr view 3').verdict, 'ALLOW');
});

test('production mutation is denied whichever order the verb and the context flag come in', () => {
  for (const cmd of [
    'kubectl apply -f x.yaml --context prod-eu',
    'kubectl delete deployment api -n production',
    'kubectl -n prod-eu rollout restart deploy/api',
    'kubectl --kubeconfig ~/prod.kubeconfig scale deploy/api --replicas=0',
    'kubectl exec -it api-1 --context production -- sh',
    'helm upgrade api ./chart --namespace production',
    'helm -n prod-eu uninstall api',
    'oc delete pod x -n production',
  ]) {
    const r = bash(cmd);
    assert.equal(r.verdict, 'DENY', cmd);
    assert.ok(r.decisive?.capability.startsWith('production.'), `${cmd} -> ${r.decisive?.capability}`);
  }
  // non-production contexts stay local k8s (ASK), reads stay reads
  assert.equal(bash('kubectl get pods -n production').decisive?.capability, 'k8s.local.apply');
  assert.notEqual(
    bash('kubectl apply -f x.yaml --context kind-dev').decisive?.capability,
    'production.k8s.mutate',
  );
});

test('credential stores: any read of a credential path is denied, any write is absolute', () => {
  for (const cmd of [
    'cut -c1-10 ~/.ssh/id_rsa',
    'strings $HOME/.aws/credentials',
    'python3 -c "print(open(\'/Users/me/.ssh/id_ed25519\').read())"',
    'tar czf x.tgz ~/.kube',
    'openssl rsa -in ~/.ssh/id_rsa -check',
    'find ~/.ssh -type f',
    'ls -la ~/.config/gcloud',
    'cat .ssh/id_rsa',
  ]) {
    const r = bash(cmd);
    assert.equal(r.verdict, 'DENY', cmd);
    assert.ok(
      r.decisive?.capability.startsWith('fs.credential-store.'),
      `${cmd} -> ${r.decisive?.capability}`,
    );
  }
  for (const cmd of [
    'echo "ssh-rsa AAA" >> ~/.ssh/authorized_keys',
    'cp key ~/.ssh/id_rsa',
    'tee ~/.aws/credentials < creds',
    'ssh-keygen -f ~/.ssh/id_new',
    'aws configure set aws_access_key_id X --profile x',
  ]) {
    const r = bash(cmd);
    assert.equal(r.verdict, 'DENY', cmd);
    assert.equal(r.decisive?.capability, 'fs.credential-store.write', cmd);
    assert.ok(r.decisive?.absolute, cmd);
  }
});

test('shell redirections are path-known writes', () => {
  assert.deepEqual(redirectionTargets('echo x > .git/hooks/pre-commit'), ['.git/hooks/pre-commit']);
  assert.deepEqual(redirectionTargets('cmd 2>/dev/null >> "out file.txt"'), ['out file.txt']);
  assert.deepEqual(redirectionTargets('cat <<EOF\nx\nEOF'), []);
  assert.equal(bash('echo x > .git/hooks/pre-commit').decisive?.capability, 'fs.hook-config.write');
  assert.equal(bash('echo x > .claude/settings.json').decisive?.capability, 'fs.hook-config.write');
  assert.equal(
    bash('echo "{}" > .harness/generated/policy.json').decisive?.capability,
    'harness.runtime.tamper',
  );
  assert.equal(
    bash('printf "" > .harness/runtime/sessions/s1.json').decisive?.capability,
    'harness.runtime.tamper',
  );
  assert.equal(bash('echo pin > .harness/harness.md').decisive?.capability, 'harness.runtime.tamper');
  assert.equal(bash('echo x > .env').decisive?.capability, 'fs.env-file.write');
  assert.equal(bash('echo x > src/out.txt').verdict, 'ALLOW');
  assert.equal(bash('echo x > /etc/hosts').decisive?.capability, 'fs.outside-workspace.write');
  assert.equal(bash('echo x > /tmp/scratch.txt').verdict, 'ALLOW');
  assert.equal(bash('echo x > $OUT/file').verdict, 'ASK');
});

test('runtime state, generated artifacts, hooks and git internals cannot be written in band', () => {
  const c = ctx();
  const write = (p: string) => evaluate(table, c, { tool: 'Write', input: { file_path: join(repo, p) } });
  assert.equal(write('.harness/runtime/sessions/s1.json').decisive?.capability, 'harness.runtime.tamper');
  assert.equal(write('.harness/generated/policy.json').decisive?.capability, 'harness.runtime.tamper');
  assert.equal(write('.harness/harness.md').decisive?.capability, 'harness.runtime.tamper');
  assert.equal(write('.git/hooks/pre-push').decisive?.capability, 'fs.hook-config.write');
  assert.equal(write('.husky/pre-commit').decisive?.capability, 'fs.hook-config.write');
  assert.equal(write('.git/config').decisive?.capability, 'fs.git-internals.write');
  assert.equal(write('.harness/permissions.md').verdict, 'ALLOW', 'the authored overlay stays editable');
  for (const cmd of [
    'cp policy.json .harness/generated/policy.json',
    'sed -i s/DENY/ALLOW/ .harness/generated/policy.json',
    "node -e \"require('fs').writeFileSync('.harness/runtime/sessions/s1.json', '{}')\"",
    'rm -rf .harness/runtime',
    'touch .harness/hooks/x',
  ]) {
    assert.equal(bash(cmd).decisive?.capability, 'harness.runtime.tamper', cmd);
  }
  for (const cmd of [
    'cp hook .git/hooks/pre-commit',
    'chmod +x .husky/pre-commit',
    'git config core.hooksPath /tmp/x',
  ]) {
    const cap = bash(cmd).decisive?.capability;
    assert.ok(cap === 'fs.hook-config.write' || cap === 'git.hooks.bypass', `${cmd} -> ${cap}`);
  }
  assert.equal(bash('cp x .git/refs/heads/main').decisive?.capability, 'fs.git-internals.write');
  assert.equal(bash(`cp keys.json ${home}/trust/keys.json`).verdict, 'DENY');
});

test('every spelling of the hook entry points is gate bypass', () => {
  for (const cmd of [
    'harness hook claude-code UserPromptSubmit',
    'echo "{}" | ego hook claude-code UserPromptSubmit',
    'sh .harness/hooks/ego-hook.sh claude-code UserPromptSubmit',
    'sh "$CLAUDE_PROJECT_DIR/.harness/hooks/ego-hook.sh" claude-code SessionStart',
    `node ${home}/runtimes/abc/dist/ego.js hook claude-code UserPromptSubmit`,
    'node dist/ego.js hook codex-cli PreToolUse',
    'node bin/harness.js hook claude-code Stop',
    'npx harness hook claude-code UserPromptSubmit',
    'npx @tarscoff/ego hook claude-code UserPromptSubmit',
    'harness budget extend --session s1 --tool-calls 9999',
    'harness modes set HARNESS_MAINTENANCE --session s1',
    'harness sources add file:/tmp/x',
    '$(which harness) hook claude-code UserPromptSubmit',
  ]) {
    const r = bash(cmd);
    assert.equal(r.verdict, 'DENY', cmd);
    assert.equal(r.decisive?.capability, 'harness.gate.bypass', cmd);
  }
  assert.equal(bash('harness status').verdict, 'ASK');
});

test('an EGO_HOME under the home directory is still protected against symlinked spellings', () => {
  const c = ctx({ egoHome: join(homedir(), '.ego') });
  assert.equal(
    evaluate(table, c, { tool: 'Edit', input: { file_path: join(homedir(), '.ego', 'index', 'x.json') } })
      .decisive?.capability,
    'harness.trust.tamper',
  );
});

test('round-2 residuals: carriers, substitutions, wrappers, env injection, aliases and forge flag positions', () => {
  for (const cmd of [
    'find . -name "*.ts" -exec git push origin main \\;',
    'find . -type f -execdir kubectl delete pod x -n production \\;',
    'find / -name x -exec rm -rf / \\;',
    'fd -e ts -x git push',
    'diff <(git push origin main) <(echo)',
    'cat >(git push)',
    'setsid git push origin main',
    'watch -n 5 git push',
    'ionice -c 3 nice -n 5 git push',
    'flock /tmp/l -c "git push"',
    'git --attr-source=HEAD push origin main',
    'git --attr-source HEAD push origin main',
    'git -c alias.p=push p origin main',
    'git -c alias.p="push --force" p origin main',
    'gh pr -R owner/repo create --fill',
    'gh pr -R owner/repo merge 3 --squash',
    'gh --title t pr create',
    'gh -t t -b b pr create',
    'gh --body b pr merge 3 --squash',
    'glab mr -R owner/repo merge 3',
    'gh pr create -R owner/repo --title "x"',
  ]) {
    const r = bash(cmd);
    assert.equal(r.verdict, 'DENY', cmd);
    assert.notEqual(r.decisive?.capability, 'command.unknown', cmd);
  }
  // a config-env alias body is invisible: refused as an alias override, never trusted
  assert.equal(bash('EGO_ALIAS=push git --config-env=alias.p=EGO_ALIAS p origin main').verdict, 'DENY');
  assert.equal(bash('git -c alias.sh="!sh -c \'git push\'" sh').verdict, 'DENY');
  // environment injection
  assert.equal(bash('LD_PRELOAD=/tmp/evil.so ls').decisive?.capability, 'command.env-inject');
  assert.equal(
    bash('GIT_CONFIG_PARAMETERS="\'core.hooksPath=/dev/null\'" git commit -m x').decisive?.capability,
    'command.env-inject',
  );
  assert.equal(bash('GIT_DIR=/tmp/other/.git git commit -m x').decisive?.capability, 'command.env-inject');
  assert.equal(bash('NODE_OPTIONS=--require=/tmp/x.js npm test').decisive?.capability, 'command.env-inject');
  assert.equal(bash('PATH=/tmp/bin:$PATH ls').decisive?.capability, 'command.env-override');
  assert.equal(bash('FOO=1 BAR=2 ls').verdict, 'ALLOW', 'ordinary variables are transparent');
  // a variable or substitution as the command head is opaque, not silently unknown
  assert.equal(bash('$(which harness) status').decisive?.capability, 'command.script-opaque');
  assert.equal(bash('H=harness; $H hook claude-code UserPromptSubmit').verdict, 'DENY');
  // ordinary work stays allowed
  assert.equal(bash('find . -name "*.ts" -exec grep -l foo {} +').verdict, 'ALLOW');
  assert.equal(bash('find src -type f | xargs wc -l').verdict, 'ALLOW');
  assert.equal(bash('diff <(sort a.txt) <(sort b.txt)').verdict, 'ALLOW');
  assert.equal(bash('gh pr view 3 --json title').verdict, 'ALLOW');
  assert.equal(bash('gh pr list --search "merge"').verdict, 'ALLOW');
  assert.equal(bash('git -C . status').verdict, 'ALLOW');
});

test('round-2 residuals: credential paths in any spelling, cd tracking, recursive reads of HOME', () => {
  const home = homedir();
  for (const cmd of [
    'cat ~/./.ssh/id_rsa',
    'cat $HOME/./.ssh/id_rsa',
    'cat ~//.ssh/id_rsa',
    'cat ~/Documents/../.ssh/id_rsa',
    `cat ${home}/.ssh/id_rsa`,
    'cat ~/.s*/id_*',
    'cat ~/.?sh/id_rsa',
    'cat ~/.{ssh,aws}/*',
    'grep -r "PRIVATE KEY" ~',
    'grep -R BEGIN $HOME',
    'tar czf /tmp/h.tgz ~',
    'find ~ -name id_rsa',
    'rg -uu AKIA /',
    'cd ~ && cat .netrc',
    'cd ~/.config && cat gh/hosts.yml',
    'cd ~ && cat ./.ssh/id_rsa',
    'cd /tmp && cd ~ && cat .npmrc',
    'sort ~/.ssh/id_ed25519',
  ]) {
    const r = bash(cmd);
    assert.equal(r.verdict, 'DENY', cmd);
    assert.ok(
      r.decisive?.capability.startsWith('fs.credential-store.') ||
        r.decisive?.capability === 'fs.env-file.read',
      `${cmd} -> ${r.decisive?.capability}`,
    );
  }
  // another user's home is opaque (ASK), never allowed
  assert.equal(bash('cat ~root/.ssh/id_rsa').verdict, 'ASK');
  // ordinary reads stay governed by the command class (reads outside the workspace are not path-classified for shells)
  assert.equal(bash('cat ~/.config/myapp/settings.json').verdict, 'ALLOW');
  assert.equal(bash('ls ~/Documents').verdict, 'ALLOW');
  assert.equal(bash('cat /etc/hosts').verdict, 'ALLOW');
  assert.equal(bash('grep -r foo src').verdict, 'ALLOW');
  assert.equal(bash('cat package.json').verdict, 'ALLOW');
  assert.equal(bash('cd src && cat index.ts').verdict, 'ALLOW');
});

test('round-2 residuals: copies, archives and globs into protected paths resolve their destination', () => {
  const c = ctx();
  for (const cmd of [
    'cp -r /tmp/generated .harness/',
    'cp -r /tmp/.harness .',
    'tar -xf p.tar -C .harness/generated',
    'unzip -o p.zip -d .harness/generated',
    'cp p.json .harness/./generated/policy.json',
    `cp p.json ${repo}/.harness/runtime/sessions/s1.json`,
    'rsync -a /tmp/x/ .harness/runtime/',
    'dd if=/tmp/p.json of=.harness/generated/policy.json',
    'find .harness/runtime/sessions -name s1.json -exec cp /tmp/forged.json {} \\;',
    'find .harness/runtime/sessions -name s1.json -delete',
    'cp -r /tmp/hooks/ .git/hooks/',
    'tar -xf h.tar -C .git',
    'cp x .husky/pre-commit',
  ]) {
    const r = bash(cmd, c);
    assert.equal(r.verdict, 'DENY', cmd);
    assert.ok(
      [
        'harness.runtime.tamper',
        'harness.gate.bypass',
        'fs.hook-config.write',
        'fs.git-internals.write',
        'command.destructive',
      ].includes(r.decisive?.capability ?? ''),
      `${cmd} -> ${r.decisive?.capability}`,
    );
  }
  assert.equal(
    bash('cp p.json .harness/gen*/policy.json', c).verdict,
    'ASK',
    'a glob destination is unknown',
  );
  // a write through a symlink resolves to the real protected path
  const link = join(mkdtempSync(join(tmpdir(), 'ego-hl-')), 'hl');
  mkdirSync(join(repo, '.harness', 'generated'), { recursive: true });
  symlinkSync(join(repo, '.harness'), link);
  assert.equal(
    bash(`cp p.json ${link}/generated/policy.json`, c).decisive?.capability,
    'harness.runtime.tamper',
  );
  assert.equal(bash('cp a.ts src/b.ts', c).verdict, 'ALLOW');
  assert.equal(bash('tar -xf vendor.tar -C vendor', c).verdict, 'ALLOW');
  // extracting into the repository root (which contains .harness and .git) is opaque; scratch space is free
  assert.equal(bash('tar -xf vendor.tar', c).decisive?.capability, 'command.archive-extract');
  assert.equal(bash('unzip -o p.zip', c).verdict, 'ASK');
  assert.equal(bash('tar -xf vendor.tar -C /tmp/x', c).verdict, 'ALLOW');
  assert.equal(bash('echo x > /tmp/out.txt', c).verdict, 'ALLOW');
  assert.equal(bash('cp a.ts /tmp/b.ts', c).verdict, 'ALLOW');
});

test('round-3 residuals: forge API writes, argument-position locked verbs, env wrapper, replace strings, quoted substitutions', () => {
  for (const cmd of [
    'gh api -X PUT repos/o/r/pulls/3/merge',
    'gh api --method POST repos/o/r/pulls -f title=x -f head=b -f base=main',
    'gh api repos/o/r/pulls -f title=x -f head=b -f base=main',
    'glab api -X PUT projects/1/merge_requests/3/merge',
    'gh api graphql -f query="mutation{mergePullRequest(input:{pullRequestId:\\"x\\"}){clientMutationId}}"',
    'echo main | xargs -I % git push origin %',
    'echo x | xargs -J % git push origin %',
    'env LD_PRELOAD=/tmp/evil.so ls',
    'env GIT_CONFIG_PARAMETERS="\'core.hooksPath=scripts\'" git commit -m x',
    'nice env LD_PRELOAD=/tmp/e.so ls',
    'env -- LD_PRELOAD=/tmp/e.so ls',
    'x=$(printf ")"; git push origin main)',
    'diff <(echo "a)"; git push) <(echo)',
    'chrt -f 10 git push',
    'chrt 10 kubectl delete pod x -n production',
    'flock -w 3 /tmp/l git push',
    'timeout -s KILL 5 git push',
    'time -p git push',
    'caffeinate -i git push',
    'env -u X git push',
    'cpulimit -l 50 -- git push origin main',
    'cpx git push origin main',
    'mkdirp git push',
    'some-launcher --flag git push origin main',
    'git --git-dir=sub/.git --work-tree=. commit -m x',
    'git checkout HEAD -- .git/hooks',
  ]) {
    const r = bash(cmd);
    assert.equal(r.verdict, 'DENY', `${cmd} -> ${r.decisive?.capability}`);
  }
  // reads through the API and ordinary commands stay allowed or ask
  assert.equal(bash('gh api repos/o/r/pulls').verdict, 'ALLOW');
  assert.equal(bash('gh api -X GET repos/o/r/pulls/3').verdict, 'ALLOW');
  assert.equal(bash('gh api graphql -f query="{viewer{login}}"').verdict, 'ALLOW');
  assert.notEqual(bash('mvn deploy').verdict, 'ALLOW', 'not a local mutation by prefix');
  assert.equal(bash('echo "remember to git push later"').verdict, 'ALLOW', 'a quoted string is data');
  assert.equal(bash('find . -name "*.log" -delete').decisive?.capability, 'command.destructive');
  assert.equal(bash('find .harness -delete').verdict, 'DENY');
});

test('round-3 residuals: search tools, escapes, ancestor globs, cd into protected trees, links, cpio, case and nested .git', () => {
  const c = ctx();
  const tool = (name: string, input: Record<string, unknown>) => evaluate(table, c, { tool: name, input });
  assert.equal(
    tool('Grep', { pattern: 'KEY', path: join(homedir(), '.ssh'), output_mode: 'content' }).verdict,
    'DENY',
  );
  assert.equal(tool('Grep', { pattern: 'KEY', path: '~/.aws/credentials' }).verdict, 'DENY');
  assert.equal(tool('Glob', { pattern: '.ssh/*', path: homedir() }).verdict, 'DENY');
  assert.equal(tool('Grep', { pattern: 'TODO', path: repo }).verdict, 'ALLOW');
  assert.equal(tool('Glob', { pattern: 'src/**/*.ts' }).verdict, 'ALLOW');
  const homeTop = homedir().split('/').filter(Boolean)[0]!; // the top-level directory that contains HOME (Users / home)
  for (const cmd of [
    'cat ~/.ss\\h/id_rsa',
    `cat /${homeTop[0]}*/${homedir().split('/').pop()}/.ssh/id_rsa`,
    `cd / && grep -r KEY ${homeTop}`,
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', cmd);
  }
  mkdirSync(join(repo, '.harness', 'runtime', 'sessions'), { recursive: true });
  mkdirSync(join(repo, '.harness', 'generated'), { recursive: true });
  for (const cmd of [
    'cd .harness/generated && cp /tmp/p.json policy.json',
    'cd .harness/runtime/sessions && cp ../../../forged.json s1.json',
    'cd .git/hooks && cp /tmp/x pre-commit',
    'cp forged.json .harness/r\\untime/sessions/s1.json',
    'cpio -pdm .harness/generated < list',
    'cpio -pdmu .git/hooks < list',
    `ln -s ${repo}/.harness /tmp/ego-x-link && cp /tmp/forged.json /tmp/ego-x-link/generated/policy.json`,
    'tar -xf h.tar -C .git',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', `${cmd} -> ${bash(cmd, c).decisive?.capability}`);
  }
  const write = (p: string) => evaluate(table, c, { tool: 'Write', input: { file_path: join(repo, p) } });
  assert.equal(write('.GIT/hooks/pre-commit').verdict, 'DENY');
  assert.equal(write('.Husky/pre-commit').verdict, 'DENY');
  assert.equal(write('sub/.git/hooks/pre-commit').verdict, 'DENY');
  assert.equal(write('policies/organization/permissions.md').verdict, 'DENY');
  assert.equal(write('.harness/mcp-trust.md').verdict, 'ASK');
  assert.equal(write('.gitignore').verdict, 'ALLOW');
  assert.equal(write('.github/workflows/ci.yml').verdict, 'ALLOW');
  assert.equal(bash('cd src && cp a.ts b.ts', c).verdict, 'ALLOW');
});

test('round-4 residuals: env -S command carrier, pax destination, carried sh -c, glued and file-loaded forge fields', () => {
  const c = ctx();
  mkdirSync(join(repo, '.harness', 'generated'), { recursive: true });
  // env -S / --split-string re-splits its value into a command line: the wrapped verb must still be classified
  for (const cmd of [
    'env -S "git push origin main"',
    'env --split-string="git push origin main"',
    'env -S"git push origin main"',
    'nice env -S "git push origin main"',
    'env -S "gh pr merge 3"',
    'env -S "kubectl delete pod x -n production"',
    'env -S "cat ~/.ssh/id_rsa"',
    'env -S "harness hook claude-code UserPromptSubmit"',
    'env -S "cp forged.json .harness/generated/policy.json"',
  ]) {
    const r = bash(cmd, c);
    assert.equal(r.verdict, 'DENY', `${cmd} -> ${r.verdict} ${r.decisive?.capability}`);
    assert.notEqual(r.decisive?.capability, 'command.unknown', cmd);
  }
  // pax copy mode writes to its LAST operand (the destination directory), like cp/mv — not the first
  assert.equal(bash('pax -rw src .harness/generated', c).verdict, 'DENY');
  assert.equal(bash('pax -r -w a b .git/hooks', c).verdict, 'DENY');
  // a carried sh -c body must survive re-tokenization when it is reconstructed from replace-string payloads
  for (const cmd of [
    'echo x | xargs -I % sh -c "git push origin %"',
    'echo main | xargs -I{} sh -c "git push origin {}"',
    'find . -maxdepth 0 -exec sh -c "git push origin main" \\;',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', cmd);
  }
  // forge.api.mutate: glued short field flags (-ftitle=x) and file-loaded graphql bodies (query=@file) are mutations
  for (const cmd of [
    'gh api repos/o/r/pulls -ftitle=x -fhead=b -fbase=main',
    'gh api -Ftitle=x repos/o/r/pulls',
    'glab api -fbody=x projects/1/issues',
    'gh api graphql -F query=@mutation.graphql -f owner=x',
    'gh api graphql -f query=@m.graphql',
  ]) {
    assert.equal(bash(cmd, c).decisive?.capability, 'forge.api.mutate', cmd);
  }
  // false positives that must NOT be denied
  assert.equal(bash('git merge -n feature', c).verdict, 'ALLOW'); // merge -n is --no-stat, not --no-verify
  assert.equal(bash('git merge --no-stat feature', c).verdict, 'ALLOW');
  assert.equal(bash('git commit -n -m x', c).decisive?.capability, 'git.hooks.bypass'); // commit -n IS --no-verify
  assert.equal(bash('gh api repos/o/r/pulls', c).verdict, 'ALLOW'); // a read stays a read
  assert.equal(bash('gh api graphql -f query="{viewer{login}}"', c).verdict, 'ALLOW'); // inline read query
});

test('round-5 residuals: env -S options, archive-create writes, mv source, glued redirects, cd options, trust dir node, forge/k8s/cloud/interpreter', () => {
  const c = ctx();
  mkdirSync(join(repo, '.harness', 'generated'), { recursive: true });
  mkdirSync(join(repo, '.harness', 'runtime'), { recursive: true });
  // [0] env -S whose split value begins with an env option (-u/-C/-i) still classifies the carried command
  for (const cmd of [
    'env -S "-u X git push origin main"',
    'env -S "-C /tmp kubectl delete pod y -n production"',
    'env -S "-i git push origin main"',
    'env --split-string="-u X git push origin main"',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', cmd);
  }
  // [1][2] archive-create modes write the archive/-f operand into a protected tree
  for (const cmd of [
    'pax -w -f .harness/generated/policy.json a.txt',
    'pax -wf .harness/generated/x.tar a.txt',
    'tar -cf .harness/generated/policy.json a.txt',
    'tar --create --file .harness/generated/policy.json a.txt',
    'tar -czf .git/hooks/pre-commit a',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', cmd);
  }
  // [14] mv relocates a protected directory (its SOURCE is removed): a write to that tree
  assert.equal(bash('mv .harness /tmp/h', c).decisive?.capability, 'harness.gate.bypass');
  assert.equal(bash('mv .harness/generated/policy.json /tmp/x', c).verdict, 'DENY');
  // [7] a redirection glued to the preceding word is still a write
  for (const cmd of [
    'echo x>.harness/generated/policy.json',
    'printf yes>>.harness/runtime/ledger.json',
    'echo approved>.harness/runtime/decisions/d1.json',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', cmd);
  }
  // [8] cd with options / -- still tracks the working directory
  assert.equal(bash('cd -- .harness/generated && cp /tmp/evil policy.json', c).verdict, 'DENY');
  assert.equal(bash('cd -P .harness/generated && cp /tmp/evil policy.json', c).verdict, 'DENY');
  // [10][11][13] the EGO_HOME trust store: the directory node itself, not only strict descendants
  const ego = c.egoHome!;
  for (const cmd of [
    `mv ${ego}/trust /tmp/stolen`,
    `cp -r ${ego}/trust /tmp/copy`,
    `rm -rf ${ego}/runtimes`,
    `mv ${ego}/releases /tmp/r`,
    `tee ${ego}/trust/keys.json`,
  ]) {
    assert.equal(bash(cmd, c).decisive?.capability, 'harness.trust.tamper', cmd);
  }
  // [3] forge graphql with a file/stdin body (--input / -i) is a mutation; [4] combined commit -nm bypasses hooks
  assert.equal(bash('gh api graphql --input payload.json', c).decisive?.capability, 'forge.api.mutate');
  assert.equal(bash('gh api graphql -i -', c).decisive?.capability, 'forge.api.mutate');
  assert.equal(bash('git commit -nm msg', c).decisive?.capability, 'git.hooks.bypass');
  assert.equal(bash('git commit -nam msg', c).decisive?.capability, 'git.hooks.bypass');
  // [9] production kubectl verbs debug/certificate; [12] cloud aws lifecycle verbs
  assert.equal(bash('kubectl --context prod debug node/n1 --image busybox', c).decisive?.capability, 'production.k8s.mutate');
  assert.equal(bash('kubectl -n prod certificate approve csr-1', c).decisive?.capability, 'production.k8s.mutate');
  assert.equal(bash('aws ec2 run-instances --image-id ami', c).decisive?.capability, 'production.cloud.mutate');
  assert.equal(bash('aws ec2 stop-instances --instance-ids i-1', c).decisive?.capability, 'production.cloud.mutate');
  // [15][16][17] an inline interpreter whose body names a protected store fails closed to the matching deny
  assert.equal(
    bash(`node -e "require('fs').writeFileSync(require('os').homedir()+'/.ssh/id_rsa','k')"`, c).decisive?.capability,
    'fs.credential-store.write',
  );
  assert.equal(
    bash(`python3 -c "open(__import__('os').path.expanduser('~/.ego/trust/k'),'w')"`, c).decisive?.capability,
    'harness.trust.tamper',
  );
  assert.equal(
    bash(`node -e "require('fs').writeFileSync('.git/hooks/pre-commit','x')"`, c).decisive?.capability,
    'fs.hook-config.write',
  );
  // controls that must NOT be denied
  assert.equal(bash('tar -cf out.tar a.txt b.txt', c).verdict, 'ALLOW'); // archive into a scratch path
  assert.equal(bash('git merge -n feature', c).verdict, 'ALLOW');
  assert.equal(bash('gh api graphql -f query="{viewer{login}}"', c).verdict, 'ALLOW');
  assert.equal(bash('cd src && cp a.ts b.ts', c).verdict, 'ALLOW');
  assert.equal(bash(`node -e "process.stdout.write(String(1+1))"`, c).verdict, 'ASK'); // benign inline interpreter, nothing protected named
})

test('round-6 residuals: archivers, trust globs/parent, glued redirects, ANSI-C, graphql substitution, aws s3, interpreter newline', () => {
  const c = ctx();
  mkdirSync(join(repo, '.harness', 'generated'), { recursive: true });
  mkdirSync(join(repo, '.harness', 'runtime'), { recursive: true });
  mkdirSync(join(repo, '.harness', 'hooks'), { recursive: true });
  const NL = '\n';
  // [1][13] sideways archivers write their output/-C archive into a protected tree
  for (const cmd of [
    'zip -r .harness/generated/evil.zip a',
    'zip .harness/runtime/x.zip a',
    'tar -xf a.tar --directory=.harness/generated',
    'tar -xf a.tar --directory .harness/generated',
    'bsdtar -xf /tmp/e.tar -C .harness/generated/',
    'gtar -xf /tmp/e.tar -C .harness/generated/',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', cmd);
  }
  // [3][4] the EGO_HOME trust store reached by a glob or a recursive parent op
  const ego = c.egoHome!;
  for (const cmd of [
    `rm -rf ${ego}/*`,
    `rm -rf ${ego}/trust*`,
    `rm -rf ${ego}/trus[t]`,
    `mv ${ego}/trus[t] /tmp/x`,
    `cp -r ${ego} /tmp/x`,
  ]) {
    assert.equal(bash(cmd, c).decisive?.capability, 'harness.trust.tamper', cmd);
  }
  // [5] a redirection glued to a word ending in a digit is still a write
  for (const cmd of [
    'echo x2>.harness/generated/policy.json',
    'printf zzz9>>.harness/hooks/pre-commit',
    'echo boom5>.harness/runtime/ledger.json',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', cmd);
  }
  // [11] ANSI-C $'...' quoting unwraps a locked verb
  assert.equal(bash("kubectl --context prod $'delete' pod x", c).decisive?.capability, 'production.k8s.mutate');
  assert.equal(bash("git $'push' origin main", c).verdict, 'DENY');
  // [6] a graphql body from a shell variable/substitution cannot be inspected -> mutate
  for (const cmd of [
    'gh api graphql -f query="$MUT"',
    'gh api graphql -f query=$MUT',
    'gh api graphql -f query="$(cat m.gql)"',
  ]) {
    assert.equal(bash(cmd, c).decisive?.capability, 'forge.api.mutate', cmd);
  }
  // [7] AWS S3 high-level state-change verbs
  for (const cmd of ['aws s3 rb s3://prod-bucket --force', 'aws s3 rm s3://prod/x', 'aws s3 sync ./d s3://prod/']) {
    assert.equal(bash(cmd, c).decisive?.capability, 'production.cloud.mutate', cmd);
  }
  // [0] a newline in an interpreter body before the protected path no longer defeats the matcher
  assert.equal(
    bash(`node -e "let a=1;${NL}require('fs').writeFileSync(process.env.HOME+'/.ssh/id_rsa','x')"`, c).decisive
      ?.capability,
    'fs.credential-store.write',
  );
  assert.equal(
    bash(`python3 -c "a=1;${NL}open('.git/hooks/pre-commit','w')"`, c).decisive?.capability,
    'fs.hook-config.write',
  );
  // [8] git commit hook-bypass is precise: real bypass flags DENY, a -n inside the message does NOT
  assert.equal(bash('git commit -nm msg', c).decisive?.capability, 'git.hooks.bypass');
  assert.equal(bash('git -C . commit -vnm msg', c).decisive?.capability, 'git.hooks.bypass');
  assert.equal(bash('git commit -m "add support for -n flag"', c).verdict, 'ALLOW');
  // [14] the enforcement shims under .harness/hooks are an absolute write, on the file tool too
  const w = (f: string) => evaluate(table, c, { tool: 'Write', input: { file_path: join(repo, f) } });
  assert.equal(w('.harness/hooks/git-hook.sh').decisive?.capability, 'harness.runtime.tamper');
  assert.ok(w('.harness/hooks/ego-hook.sh').decisive?.absolute);
  // controls that must NOT be denied
  assert.equal(bash('zip -r out.zip src', c).verdict, 'ALLOW');
  assert.equal(bash('tar -xf a.tar -C build', c).verdict, 'ALLOW');
  assert.equal(bash('gh api graphql -f query="{viewer{login}}"', c).verdict, 'ALLOW');
  assert.equal(bash('git commit -am "message"', c).verdict, 'ALLOW');
})

test('round-7 residuals: dash-less tar, mv of the EGO_HOME parent, git commit bypass carried through env -S / -c', () => {
  const c = ctx();
  mkdirSync(join(repo, '.harness', 'generated'), { recursive: true });
  const ego = c.egoHome!;
  // [R7-2] traditional dash-less tar syntax (tar xf / cf / czf) resolves the archive/extract destination
  for (const cmd of [
    'tar xf a.tar -C .harness/generated',
    'tar cf .harness/generated/x.tar a',
    'tar czf .harness/generated/x.tgz a',
    'tar xzf a.tgz --directory=.harness/generated',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', cmd);
  }
  // [R7-1] mv/rename relocate a whole tree without a recursive flag: moving EGO_HOME away is trust tamper
  assert.equal(bash(`mv ${ego} /tmp/stolen`, c).decisive?.capability, 'harness.trust.tamper');
  assert.equal(bash(`rename ${ego} /tmp/x`, c).decisive?.capability, 'harness.trust.tamper');
  assert.equal(bash(`mv ${ego}/trust /tmp/x`, c).decisive?.capability, 'harness.trust.tamper');
  // [R7-3] a git commit hook bypass carried in a quoted env -S / --split-string / bash -c value is still caught
  for (const cmd of [
    `env -S 'git commit -nm x'`,
    `env --split-string='git commit -nm x'`,
    `bash -c 'git commit -nm x'`,
    `sh -c 'git commit --no-verify -m x'`,
  ]) {
    assert.equal(bash(cmd, c).decisive?.capability, 'git.hooks.bypass', cmd);
  }
  // controls: a -n inside the carried message is NOT a bypass; a dash-less tar to a scratch path is fine
  assert.equal(bash(`env -S 'git commit -m "fix -n bug"'`, c).verdict, 'ALLOW');
  assert.equal(bash('tar xf a.tar -C build', c).verdict, 'ALLOW');
  assert.equal(bash('tar tf a.tar', c).verdict, 'ALLOW'); // list mode is read-only
})

test('round-8 residuals: tar write modes, quoted commit flags, multi-digit redirects, control-plane writes', () => {
  const c = ctx();
  mkdirSync(join(repo, '.harness', 'generated'), { recursive: true });
  mkdirSync(join(repo, 'control-plane', 'permissions'), { recursive: true });
  // [0] every archive-WRITING tar mode (create/append/update/catenate), incl. dash-less and blocking-factor spellings
  for (const cmd of [
    'tar rf .harness/generated/x.tar a',
    'tar uf .harness/generated/x.tar a',
    'tar --append --file .harness/generated/x.tar a',
    'tar rf .git/hooks/pre-commit payload',
    'tar cbf 20 .harness/generated/x.tar a',
    'tar -rf .harness/generated/x.tar a',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', cmd);
  }
  // [1] a hook-bypass short flag survives being shell-quoted (the shell strips the quotes before git sees it)
  for (const cmd of ['git commit "-n" -m x', 'git commit -n"m" x', 'git commit -"n" -m x', 'git commit -vn"m" x']) {
    assert.equal(bash(cmd, c).decisive?.capability, 'git.hooks.bypass', cmd);
  }
  // commit flag-cluster precision: -mn / -mfoon are a `-m` message, not a bypass; -m "-n" message is not a flag
  assert.equal(bash('git commit -mn', c).verdict, 'ALLOW');
  assert.equal(bash('git commit -mfoon', c).verdict, 'ALLOW');
  assert.equal(bash('git commit -m "-n"', c).verdict, 'ALLOW');
  // [2] a redirection glued to a word ending in TWO OR MORE digits is still a write
  for (const cmd of [
    'echo x123>.harness/generated/authority.json',
    'echo pwned12>.git/config',
    'echo v2024>.git/hooks/pre-commit',
    'printf y99>>.harness/runtime/ledger.json',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', cmd);
  }
  // [5] the EGO control-plane / policy baselines are harness.control-plane.edit on the file tool (and shell writes)
  const w = (f: string) => evaluate(table, c, { tool: 'Write', input: { file_path: join(repo, f) } });
  assert.equal(w('control-plane/permissions/absolute-denies.md').decisive?.capability, 'harness.control-plane.edit');
  assert.equal(w('control-plane/permissions/matchers.md').decisive?.capability, 'harness.control-plane.edit');
  assert.equal(w('policies/baselines/x.md').decisive?.capability, 'harness.control-plane.edit');
  // controls
  assert.equal(bash('tar cf out.tar a b', c).verdict, 'ALLOW'); // archive to a scratch path
  assert.equal(bash('git commit -am "message with -n inside"', c).verdict, 'ALLOW');
})

test('round-9 residuals: >| noclobber redirect, commit $IFS/$"" splice, .git gitlink file, nested hook config', () => {
  const c = ctx();
  mkdirSync(join(repo, '.harness', 'generated'), { recursive: true });
  mkdirSync(join(repo, 'packages', 'api'), { recursive: true });
  // [0] the `>|` noclobber-override redirect is a write, not a pipe split
  for (const cmd of [
    'echo x>|.harness/generated/policy.json',
    'echo x12>|.git/hooks/evil',
    'printf y>|.harness/runtime/ledger.json',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'DENY', cmd);
  }
  // [1] a commit hook-bypass flag reconstructed via $IFS field-split / $"" empty-expansion is still caught
  for (const cmd of ['git commit -n$IFS -m x', 'git commit -n${IFS}-m x', 'git commit -n$"" -m x', 'git commit "-n"$IFS-m x']) {
    assert.equal(bash(cmd, c).decisive?.capability, 'git.hooks.bypass', cmd);
  }
  // [8] the `.git` gitlink pointer FILE (worktree/submodule) is protected, not only `.git/` contents
  assert.equal(evaluate(table, c, { tool: 'Write', input: { file_path: join(repo, '.git') } }).decisive?.capability, 'fs.git-internals.write');
  assert.equal(bash('echo "gitdir: /tmp/evil" > .git', c).verdict, 'DENY');
  // [9] nested host hook/permission config (not only at the repo root) is protected
  const w = (f: string) => evaluate(table, c, { tool: 'Write', input: { file_path: join(repo, f) } });
  assert.equal(w('packages/api/.claude/settings.json').decisive?.capability, 'fs.hook-config.write');
  assert.equal(w('packages/api/.claude/settings.local.json').decisive?.capability, 'fs.hook-config.write');
  assert.equal(w('packages/api/.codex/config.toml').decisive?.capability, 'fs.hook-config.write');
  // controls: -am/-qm messages and a message containing $ are not bypasses; a plain pipe still splits
  assert.equal(bash('git commit -am "message with -n inside"', c).verdict, 'ALLOW');
  assert.equal(bash('git commit -m "cost $5"', c).verdict, 'ALLOW');
  assert.equal(bash('cat a | grep b', c).verdict, 'ALLOW');
})

test('round-10 residuals: commit ${IFS%?} splice, >>| redirect, symlinked .git, npm install lifecycle', () => {
  const c = ctx();
  mkdirSync(join(repo, '.harness', 'generated'), { recursive: true });
  // [0] any $-expansion that field-splits/empties reconstructs a bare -n commit hook bypass
  for (const cmd of [
    'git commit -n${IFS%?}-m x',
    'git commit -n${IFS#?}-m x',
    'git commit -n${x:- }-m x',
    'git commit -n${#}-m x',
  ]) {
    assert.equal(bash(cmd, c).decisive?.capability, 'git.hooks.bypass', cmd);
  }
  // [1] the >>| (append + noclobber-override) redirect is a write
  assert.equal(bash('echo x >>| .harness/generated/policy.json', c).verdict, 'DENY');
  assert.equal(bash('echo x>>|.git/hooks/pre-commit', c).verdict, 'DENY');
  // [2] a symlinked .git node is still protected on the Write/Edit tool (realpath drops the name; lexical path catches it)
  const sg = mkdtempSync(join(tmpdir(), 'ego-symgit-'));
  mkdirSync(join(sg, 'realgit', 'hooks'), { recursive: true });
  writeFileSync(join(sg, 'realgit', 'config'), '');
  writeFileSync(join(sg, 'realgit', 'hooks', 'pre-commit'), '');
  symlinkSync(join(sg, 'realgit'), join(sg, '.git'));
  writeFileSync(join(sg, 'package.json'), '{}');
  const sgCtx = ctx({ repoRoots: [sg], cwd: sg });
  assert.equal(evaluate(table, sgCtx, { tool: 'Write', input: { file_path: join(sg, '.git', 'config') } }).decisive?.capability, 'fs.git-internals.write');
  assert.equal(evaluate(table, sgCtx, { tool: 'Edit', input: { file_path: join(sg, '.git', 'hooks', 'pre-commit') } }).decisive?.capability, 'fs.hook-config.write');
  // [10] npm/pnpm install runs the install lifecycle scripts, which are effect-analysed
  const inst = mkdtempSync(join(tmpdir(), 'ego-inst-'));
  mkdirSync(join(inst, '.git'), { recursive: true });
  writeFileSync(join(inst, 'package.json'), JSON.stringify({ scripts: { postinstall: 'git push origin main' } }));
  const iCtx = ctx({ repoRoots: [inst], cwd: inst });
  for (const cmd of ['npm install', 'npm ci', 'npm install lodash', 'pnpm add x']) {
    assert.equal(evaluate(table, iCtx, { tool: 'Bash', input: { command: cmd } }).verdict, 'DENY', cmd);
  }
  // control: an install with no lifecycle scripts is an ordinary local mutation
  const ok = mkdtempSync(join(tmpdir(), 'ego-ok-'));
  writeFileSync(join(ok, 'package.json'), JSON.stringify({ scripts: { build: 'tsc' } }));
  assert.notEqual(evaluate(table, ctx({ repoRoots: [ok], cwd: ok }), { tool: 'Bash', input: { command: 'npm install' } }).verdict, 'DENY');
})

test('round-11 residuals: commit default-value expansion, sh -euc cluster, cloud global options, tilde paths, make -C, install prepublish', () => {
  const c = ctx();
  mkdirSync(join(repo, '.harness', 'generated'), { recursive: true });
  // [0] a hook-bypass flag supplied as a parameter-expansion default value is caught
  for (const cmd of [
    'git commit ${x:---no-verify} -m y',
    'git commit -${x:-n} -m y',
    'git commit -${x:=n} -m y',
    'git commit -${x-n} -m y',
    'git commit -${x:-nm} y',
  ]) {
    assert.equal(bash(cmd, c).decisive?.capability, 'git.hooks.bypass', cmd);
  }
  // [4] a combined short-flag cluster ending in c (sh -euc / bash -lc) still exposes the -c payload
  assert.equal(bash('sh -euc "git push origin main"', c).decisive?.capability, 'git.remote.push');
  assert.equal(bash('bash -lc "gh pr merge 3"', c).decisive?.capability, 'forge.pr.merge');
  assert.equal(bash('sh -ec "kubectl --context prod delete pod x"', c).decisive?.capability, 'production.k8s.mutate');
  // [5] a global option before the aws service / terraform flag no longer defeats the production matchers
  for (const cmd of [
    'aws --profile prod iam delete-user --user-name x',
    'aws --region us-east-1 iam create-user --user-name x',
    'aws --output json secretsmanager delete-secret --secret-id x',
    'terraform -chdir=infra/prod apply -auto-approve',
  ]) {
    assert.equal(bash(cmd, c).decisive?.capability, 'production.cloud.mutate', cmd);
  }
  // [6] a literal ~/ file-tool path is home-expanded, so a credential/trust path is not treated as in-repo
  assert.equal(evaluate(table, c, { tool: 'Write', input: { file_path: '~/.ssh/id_rsa' } }).decisive?.capability, 'fs.credential-store.write');
  assert.equal(evaluate(table, c, { tool: 'Read', input: { file_path: '~/.aws/credentials' } }).verdict, 'DENY');
  // [7] make -C DIR does not mis-parse the directory as a target
  const mk = ctx({ repoRoots: [repo], cwd: repo });
  writeFileSync(join(repo, 'Makefile'), 'deploy:\n\tgit push origin main\n');
  assert.equal(bash('make -C . deploy', mk).decisive?.capability, 'git.remote.push');
  assert.equal(bash('make --directory=. deploy', mk).decisive?.capability, 'git.remote.push');
  // [1] install runs prepublish/preprepare/postprepare/dependencies too
  const inst = mkdtempSync(join(tmpdir(), 'ego-inst2-'));
  mkdirSync(join(inst, '.git'), { recursive: true });
  writeFileSync(join(inst, 'package.json'), JSON.stringify({ scripts: { prepublish: 'git push --force origin main' } }));
  assert.equal(evaluate(table, ctx({ repoRoots: [inst], cwd: inst }), { tool: 'Bash', input: { command: 'npm install' } }).verdict, 'DENY');
})

test('round-12 residuals: commit embedded empty expansion, make -f altmakefile, sort/uniq/yq writes, rm -rf EGO_HOME root', () => {
  const c = ctx();
  mkdirSync(join(repo, '.harness', 'generated'), { recursive: true });
  // [0] an empty ${x} that VANISHES and glues the fragments into a bypass flag is caught (both split and empty models)
  for (const cmd of [
    'git commit -${x}-no-verify -m x',
    'git commit --${x}no-verify -m x',
    'git commit -${x}n -m x',
    'git commit -v${x}n -m x',
    'git commit -${x#pat}n -m x',
  ]) {
    assert.equal(bash(cmd, c).decisive?.capability, 'git.hooks.bypass', cmd);
  }
  // [1] make -f/--file/--makefile reads the alternate makefile, so its recipe is analysed
  writeFileSync(join(repo, 'ci.mk'), 'release:\n\taws iam delete-user --user-name admin\n');
  for (const cmd of ['make -f ci.mk release', 'make --file ci.mk release', 'make --file=ci.mk release', 'make -fci.mk release']) {
    assert.equal(bash(cmd, c).decisive?.capability, 'production.cloud.mutate', cmd);
  }
  // [2] "read-only" utilities that write via -o/output-operand/-i are writes
  assert.equal(bash('sort -o .git/hooks/pre-commit in', c).decisive?.capability, 'fs.hook-config.write');
  assert.equal(bash('sort --output=.harness/generated/x.json a', c).decisive?.capability, 'harness.runtime.tamper');
  assert.equal(bash('uniq in .git/config', c).decisive?.capability, 'fs.git-internals.write');
  assert.equal(bash('yq -i .harness/generated/policy.json', c).decisive?.capability, 'harness.runtime.tamper');
  // [4] rm -rf of the EGO_HOME root is a whole-tree destroy of the trust store
  assert.equal(bash(`rm -rf ${c.egoHome}`, c).decisive?.capability, 'harness.trust.tamper');
  // controls
  assert.equal(bash('sort a b', c).verdict, 'ALLOW'); // no -o: a read
  assert.equal(bash('git commit -am "message with -n"', c).verdict, 'ALLOW');
})

test('round-13 residuals: interpreter carve-out, wrappers, write destinations, git ref and recovery mutations', () => {
  const c = ctx();
  // [1] command.read-only carried an unbounded console.log(…)/print(…) carve-out that won first match over every
  // inline-interpreter deny: any code rode along inside it and reached ALLOW
  for (const cmd of [
    'node -e \'console.log(require("child_process").execSync("git push origin main").toString())\'',
    'python3 -c \'print(__import__("os").system("git push origin main"))\'',
    'awk \'BEGIN{system("git push origin main")}\'',
    'python3 -u -c \'import os; os.system("git push origin main --force")\'',
  ]) {
    assert.notEqual(bash(cmd, c).verdict, 'ALLOW', cmd);
  }
  // the same wrapper must not launder a protected-store read or a hook write either
  assert.equal(
    bash('node -e \'console.log(require("fs").readFileSync(process.env.HOME+"/.ssh/id_rsa","utf8"))\'', c)
      .decisive?.capability,
    'fs.credential-store.write',
  );
  for (const cmd of [
    'node -e \'console.log(require("fs").writeFileSync(".git/hooks/pre-commit","#!/bin/sh"))\'',
    'tsx -e \'require("fs").writeFileSync(".git/hooks/pre-commit","#!/bin/sh")\'',
  ]) {
    assert.equal(bash(cmd, c).decisive?.capability, 'fs.hook-config.write', cmd);
  }
  // a genuinely literal body stays allowed: the carve-out is bounded, not removed
  assert.equal(bash("node -e 'console.log(1)'", c).verdict, 'ALLOW');
  assert.equal(bash('ls -la', c).verdict, 'ALLOW');
  assert.equal(bash('awk {print $1}', c).verdict, 'ALLOW');

  // [2] privilege and wrapper tools must not swallow the command they run
  assert.equal(bash('su --command="rm -rf /" root', c).decisive?.capability, 'fs.destructive-root');
  assert.equal(bash('su --session-command="rm -rf /" root', c).decisive?.capability, 'fs.destructive-root');
  assert.equal(
    bash('runuser -u root -- cp /tmp/evil .git/hooks/pre-commit', c).decisive?.capability,
    'fs.hook-config.write',
  );
  assert.equal(
    bash('watch -d cp /tmp/evil .git/hooks/pre-commit', c).decisive?.capability,
    'fs.hook-config.write',
  );
  assert.equal(bash('doas cp /etc/shadow /tmp/x', c).decisive?.capability, 'command.privileged');
  assert.equal(bash('doas -u root rm -rf /', c).decisive?.capability, 'fs.destructive-root');
  assert.equal(bash('sh -cx "git push origin main"', c).decisive?.capability, 'git.remote.push');
  assert.equal(bash('bash -c -- "git push origin main"', c).decisive?.capability, 'git.remote.push');
  assert.equal(bash('fd -x rm -rf {}', c).decisive?.capability, 'fs.destructive-root');

  // [3] write destinations hidden in glued option values, target-directory flags and displaced operands
  assert.equal(bash('sort -o.git/hooks/pre-commit payload', c).decisive?.capability, 'fs.hook-config.write');
  assert.equal(bash('patch -o.git/hooks/pre-commit payload.diff', c).decisive?.capability, 'fs.hook-config.write');
  assert.equal(bash('find . -fprint .git/hooks/pre-commit', c).decisive?.capability, 'fs.hook-config.write');
  assert.equal(bash('tar -xf a.tar -C.git/hooks', c).decisive?.capability, 'fs.git-internals.write');
  assert.equal(bash('tar -xf a.tar --one-top-level=.git/hooks', c).decisive?.capability, 'fs.git-internals.write');
  assert.equal(bash('unzip -d.git/hooks a.zip', c).decisive?.capability, 'fs.git-internals.write');
  assert.equal(bash('cp -t /etc payload', c).decisive?.capability, 'fs.outside-workspace.write');
  assert.equal(bash('cp --target-directory=/etc payload', c).decisive?.capability, 'fs.outside-workspace.write');
  // a trailing value option must not displace the destination
  assert.equal(bash('cp -r payload /etc --sparse always', c).decisive?.capability, 'fs.outside-workspace.write');
  // a glued -C value must not be read as tar's `c` (create) function letter
  assert.equal(bash('tar -xf a.tar -C /tmp/ok', c).verdict, 'ALLOW');
  assert.equal(bash('tar czf /tmp/a.tgz src', c).verdict, 'ALLOW');

  // [4] redirection targets are unquoted, unescaped and `..`-resolved before classification
  assert.equal(bash('echo x > "control-plane"/permissions/matchers.md', c).verdict, 'DENY');
  assert.equal(bash('echo x > control-plan\\e/permissions/matchers.md', c).verdict, 'DENY');
  assert.equal(bash('echo x > /dev/../etc/cron.d/x', c).decisive?.capability, 'fs.outside-workspace.write');
  assert.equal(bash('echo x > /dev/null', c).verdict, 'ALLOW'); // a real device sink is still not a write
  assert.equal(bash('echo x > /dev/stderr', c).verdict, 'ALLOW');

  // [5] git: abbreviated long options, substitutions in flag position, post-verb hooksPath, transport programs
  assert.equal(bash('git commit --no-verif -m x', c).decisive?.capability, 'git.hooks.bypass');
  assert.equal(bash('git commit -$(echo n) -m x', c).decisive?.capability, 'git.hooks.bypass');
  assert.equal(bash('git commit -`echo n` -m x', c).decisive?.capability, 'git.hooks.bypass');
  assert.equal(bash('git clone -c core.hooksPath=/tmp/h ./src ./dest', c).decisive?.capability, 'git.hooks.bypass');
  assert.equal(
    bash('git clone --upload-pack="sh /tmp/evil.sh" ./src ./dest', c).decisive?.capability,
    'git.alias.inline',
  );
  // a substitution used as a MESSAGE is data, not a flag
  assert.equal(bash('git commit -m "msg $(date)"', c).verdict, 'ALLOW');

  // [6] ref and recovery mutations were all swallowed by the read-only `git status` matcher
  assert.equal(bash('git branch -f main HEAD~5', c).decisive?.capability, 'git.local.reset');
  assert.equal(bash('git branch -D feature', c).decisive?.capability, 'git.local.branch.delete');
  assert.equal(bash('git reflog expire --expire=now --all', c).decisive?.capability, 'git.local.recovery.destroy');
  assert.equal(bash('git gc --prune=now', c).decisive?.capability, 'git.local.recovery.destroy');
  assert.equal(bash('git stash clear', c).decisive?.capability, 'git.local.recovery.destroy');
  assert.equal(
    bash('git remote set-url origin https://attacker.example/x.git', c).decisive?.capability,
    'git.remote.configure',
  );
  assert.equal(bash('git checkout -f main', c).decisive?.capability, 'git.local.restore');
  assert.equal(bash('git checkout HEAD -- src/main', c).decisive?.capability, 'git.local.restore');
  // listings stay allowed
  for (const cmd of ['git branch', 'git branch -a', 'git reflog', 'git remote -v', 'git stash list', 'git status'])
    assert.equal(bash(cmd, c).verdict, 'ALLOW', cmd);

  // [7] forge and production spellings
  assert.equal(bash('gh api graphql -f "query=`cat mut.graphql`"', c).decisive?.capability, 'forge.api.mutate');
  // no --context given: Q98 target resolution refuses to guess "local" for a namespace deletion
  assert.equal(
    bash('kubectl --namespace=default delete namespace payments', c).decisive?.capability,
    'k8s.target.unclassified',
  );
  assert.equal(bash('kubectl --context kind-dev delete ns test', c).decisive?.capability, 'k8s.local.delete');
  assert.equal(
    bash('kubectl --server=https://prod-api.k8s.acme.com:6443 delete deployment api', c).decisive?.capability,
    'production.k8s.mutate',
  );
  assert.equal(
    bash('psql "postgresql://app:pw@prod-db.acme.com:5432/appdb" -c "DROP TABLE orders"', c).decisive?.capability,
    'production.database.mutate',
  );
  assert.equal(bash('redis-cli -h cache.prod.acme.com flushall', c).decisive?.capability, 'production.database.mutate');
  assert.equal(bash('tofu apply -auto-approve', c).decisive?.capability, 'production.cloud.mutate');
  assert.equal(bash('gcloud run deploy api --image gcr.io/p/api:bad', c).decisive?.capability, 'production.cloud.mutate');
  assert.equal(bash('gcloud storage rm -r gs://prod-bucket', c).decisive?.capability, 'production.cloud.mutate');
  assert.equal(bash('docker push registry.acme.com/prod/api:latest', c).decisive?.capability, 'container.registry.push');
  // ordinary local development is untouched
  for (const cmd of ['docker compose up -d', 'kubectl get pods', 'psql -c "select 1"'])
    assert.equal(bash(cmd, c).verdict, 'ALLOW', cmd);
})

test('round-13 residuals: the EGO_HOME trust store is recognised whatever the path casing', () => {
  // macOS and Windows resolve ~/.ego/RUNTIMES/... to the real `runtimes` directory, so a case variant reached the
  // trust store under a weaker capability than harness.trust.tamper
  const c = ctx();
  for (const cmd of [
    `echo x > ${c.egoHome}/RUNTIMES/a1b2/dist/ego.js`,
    `echo x > ${c.egoHome}/Runtimes/a1b2/dist/ego.js`,
    `cp evil ${c.egoHome}/Trust/keys`,
    `cp evil ${c.egoHome}/INDEX/x`,
  ]) {
    assert.equal(bash(cmd, c).decisive?.capability, 'harness.trust.tamper', cmd);
  }
  // the lowercase spellings keep working exactly as before
  assert.equal(bash(`echo x > ${c.egoHome}/runtimes/a1b2/dist/ego.js`, c).decisive?.capability, 'harness.trust.tamper');
})

test('Q98 target/effect classification: a Kubernetes or database command is judged by WHERE it points', () => {
  const c = ctx();
  // LOCAL — declared local development targets are the agent's working material: no human approval
  for (const cmd of [
    'kubectl --context kind-dev apply -f k8s/dev.yaml',
    'kubectl --context=k3d-test delete pod x',
    'kubectl --context docker-desktop apply -f a.yaml',
    'helm upgrade --install app ./chart --kube-context kind-dev',
    'psql postgres://localhost:5432/app_dev -c "drop table x"',
    'psql -h 127.0.0.1 -c "select 1"',
    'psql -c "select 1"', // no host at all: the local socket
    'mongosh --eval "db.x.find()"',
    'sqlite3 ./dev.db "delete from t"',
    'docker compose up -d',
  ]) {
    assert.equal(bash(cmd, c).verdict, 'ALLOW', cmd);
  }

  // deleting a LOCAL cluster is still a declared human gate: local does not mean unguarded
  assert.equal(bash('minikube delete', c).decisive?.capability, 'k8s.local.delete');

  // EXTERNAL — a resolved target that is not declared local is a shared system, whatever the tool is called
  assert.equal(
    bash('kubectl --context acme-eks-blue delete ns payments', c).decisive?.capability,
    'k8s.nonlocal.mutate',
  );
  assert.equal(
    bash('psql postgres://admin:pw@db.acme.internal:5432/app -c "delete from users"', c).decisive?.capability,
    'db.nonlocal.mutate',
  );
  assert.equal(
    bash('mongosh mongodb+srv://cluster0.acme.mongodb.net/app --eval "db.users.drop()"', c).decisive?.capability,
    'db.nonlocal.mutate',
  );
  assert.equal(
    bash('mysql --host=analytics.acme.com -e "drop database x"', c).decisive?.capability,
    'db.nonlocal.mutate',
  );

  // PRODUCTION — a production marker in the context, namespace or host reaches the absolute denies
  assert.equal(
    bash('kubectl --context acme-prod-eks apply -f a.yaml', c).decisive?.capability,
    'production.k8s.mutate',
  );
  assert.equal(
    bash('kubectl --context kind-dev -n production delete deploy api', c).decisive?.capability,
    'production.k8s.mutate',
  );

  // TARGET_UNCLASSIFIED — never guessed local; it asks a human and the reason says why
  for (const cmd of [
    'kubectl delete deployment api',
    'kubectl apply -f k8s/dev.yaml',
    'helm uninstall billing',
    'kubectl --context "$CTX" delete ns x',
    'psql $DATABASE_URL -c "delete from users"',
  ]) {
    const r = bash(cmd, c);
    assert.equal(r.verdict, 'ASK', cmd);
    assert.match(r.decisive?.capability ?? '', /target\.unclassified$/, cmd);
    assert.match(r.reason, /TARGET_UNCLASSIFIED/, cmd);
  }

  // reads are not re-targeted: only operations that actually mutate the target are judged against it
  assert.equal(bash('kubectl get pods', c).verdict, 'ALLOW');
  assert.equal(bash('kubectl --context acme-eks-blue get pods', c).verdict, 'ALLOW');
})
