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
