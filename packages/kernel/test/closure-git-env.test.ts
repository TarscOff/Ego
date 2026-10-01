// CLOSURE OF THE GIT, ENVIRONMENT, OVERLAY AND TIME FINDINGS (closure audit 2026-10-01, wave 3, branch "git-env-time").
// Each test names the CAUSE, not the spelling: the spellings are the reviews', the statement is what must stay true.
//
//   TIME   a decision ends, with a verdict, inside the hook's budget on ANY input (r11-243)
//   GIT    ONE reader of a git command line: options by their canonical names, config keys that name a program or an identity,
//          what a transport verb reads (r11-103, 105, 150, 202, 157, 201, 203, 239)
//   ENV    ONE recorder of what the next command runs in, whichever builtin assigned it, and the options that select a program
//          (r11-107, 108, 109, 205, sa10-86, sa10-96)
//   OVL    an overlay may only narrow, and a narrowing must reach the rule that decides (r11-117, 118, 120)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { evaluate, type Evaluation } from '../src/authority/evaluate.ts';
import { WORK_LIMIT, overrideWorkLimit, workSpent } from '../src/authority/work-bound.ts';
import {
  GIT_HYPHENATED_WITH_RULES,
  PROGRAM_KEYS,
  gitOption,
  isIdentityConfigKey,
  isKnownGitVerb,
  programKeyKind,
  readGitInvocation,
} from '../src/authority/git-invocation.ts';
import { GIT_CONFIG_KEYS } from '../src/authority/git-verb-options.ts';
import { ORDINARY, RANK, SEMANTIC_CLASSES, ctx, table, workspace } from './support/corpus.ts';

const run = (command: string, dir: string): Evaluation => evaluate(table, ctx(dir), { tool: 'Bash', input: { command } });
const verdictOf = (command: string, dir: string): string => run(command, dir).verdict;
/** a real git invocation in a fixture directory, with the operator's own configuration kept out of it */
const gitIn = (dir: string, ...args: string[]): string =>
  execFileSync('git', args, { cwd: dir, env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' }, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
const caps = (e: Evaluation): string => e.hits.map((h) => `${h.verdict}:${h.capability}`).join(',');
const timed = <T>(f: () => T): { value: T; ms: number } => {
  const t0 = performance.now();
  const value = f();
  return { value, ms: performance.now() - t0 };
};

/* ------------------------------------------------------------------------------------------------------------- *
 * TIME
 *
 * The host gives a PreToolUse hook thirty seconds, and a hook that has not answered by then has not refused: the call runs.
 * A sed script of seven hundred spaces followed by `git push origin main` is an absolute deny, and the scan that was reading
 * the script backtracked for 66-105 seconds before it got as far as saying so (exit review 11, r11-243). Three things keep
 * that from coming back: the scanners are linear, a command too large for a pattern to be trusted with is not handed to one,
 * and a decision that spends more than a fixed number of work units ends with an ASK instead of a clock.
 * ------------------------------------------------------------------------------------------------------------- */

/** The wall-clock allowance a test gives a decision. The hook's is 30 s; the tests ask for a tenth of that so that a machine
 *  three times slower than the one these numbers were measured on still has a margin, and a regression is a failure rather
 *  than a flake. */
const FAST_MS = 3000;
const PUSH = 'git' + ' push origin main';

test('r11-243: a sed script of whitespace in front of a push is still the DENY it is, and quickly', () => {
  const dir = workspace({ 'README.md': 'x\n' });
  for (const n of [700, 5000, 30000]) {
    const { value, ms } = timed(() => run(`sed -n '${' '.repeat(n)}p' README.md; ${PUSH}`, dir));
    assert.equal(value.verdict, 'DENY', `${n} spaces: ${caps(value)}`);
    assert.ok(ms < FAST_MS, `${n} spaces took ${Math.round(ms)} ms`);
  }
});

test('the sed scanners are linear on every shape that made one backtrack: blanks, backslashes, delimiters, addresses', () => {
  const dir = workspace({ 'README.md': 'x\n' });
  const N = 20000;
  const shapes: Record<string, string> = {
    'a run of blanks before the command': `sed -n '${' '.repeat(N)}p' README.md`,
    'blanks after an address': `sed -n '1${' '.repeat(N)}p' README.md`,
    'blanks after a brace': `sed -n '{${' '.repeat(N)}p}' README.md`,
    'blanks before an e command': `sed -n '1${' '.repeat(N)}e id' README.md`,
    'a run of backslashes in an address': `sed -n '/${'\\'.repeat(N)}x' README.md`,
    'a run of escaped pairs': `sed -n '${'\\\\'.repeat(N / 2)}' README.md`,
    'a long run of one delimiter': `sed -n '${'s'.repeat(N)}' README.md`,
    'many substitutions with a flag': `sed -n '${'s/a/b/;'.repeat(N / 8)}' README.md`,
    'many write commands': `sed -n '${'1w x;'.repeat(N / 40)}' README.md`,
    'an awk program of blanks': `awk '${' '.repeat(N)}' README.md`,
  };
  for (const [what, command] of Object.entries(shapes)) {
    const { ms } = timed(() => run(`${command}; ${PUSH}`, dir));
    assert.ok(ms < FAST_MS, `${what} took ${Math.round(ms)} ms`);
  }
});

test('a hundred kilobytes of command, whatever it is made of, is answered in under a second', () => {
  const dir = workspace({ 'README.md': 'x\n' });
  const KB100 = 100 * 1024;
  const rep = (s: string): string => s.repeat(Math.ceil(KB100 / s.length)).slice(0, KB100);
  const shapes: Record<string, string> = {
    'one long word': `echo ${rep('a')}`,
    'blanks': `echo${rep(' ')}x`,
    'a long list': rep('echo a; '),
    'a long pipeline': rep('echo a | ') + 'cat',
    'a long chain': rep('true && ') + 'true',
    'many words': `echo ${rep('a ')}`,
    'many substitutions': `echo ${rep('$(a) ')}`,
    'many quotes': `echo ${rep("'a' ")}`,
    'many comments inside a word': `echo ${rep('a#')}`,
    'moves into a directory that is not there': rep('cd a; ') + 'ls',
    'nested carriers': `bash -c '${rep('echo a; ')}'`,
    'a sed script of blanks': `sed -n '${' '.repeat(KB100)}p' README.md`,
    'a heredoc': `cat > f <<'EOF'\n${rep('a line of text\n')}EOF\n`,
  };
  for (const [what, command] of Object.entries(shapes)) {
    const { value, ms } = timed(() => run(command, dir));
    assert.ok(ms < 1000, `${what} took ${Math.round(ms)} ms`);
    assert.ok(value.verdict === 'ASK' || value.verdict === 'ALLOW', `${what}: ${value.verdict}`);
  }
});

test('a command that is too large to classify ASKS, with that reason, and is never an ALLOW', () => {
  const dir = workspace({ 'README.md': 'x\n' });
  // (a) one command larger than any command is: the stage asks, and says why
  const huge = run(`echo ${'a'.repeat(100 * 1024)}`, dir);
  assert.equal(huge.verdict, 'ASK');
  assert.match(huge.reason, /too large to classify within the bound/);
  // (b) a decision that spends more than its limit: the same words, from the counter
  overrideWorkLimit(2_000);
  try {
    const e = run('echo a; echo b; echo c; echo d; echo e; echo f; echo g; echo h', dir);
    assert.equal(e.verdict, 'ASK', caps(e));
    assert.match(e.reason, /too large to classify within the bound/);
  } finally {
    overrideWorkLimit(null);
  }
});

test('...and the neighbours of an oversize command are still read: a push behind it is the DENY it is', () => {
  const dir = workspace({ 'README.md': 'x\n' });
  const padded = `echo ${'a'.repeat(100 * 1024)}; ${PUSH}`;
  const { value, ms } = timed(() => run(padded, dir));
  assert.equal(value.verdict, 'DENY', caps(value));
  assert.ok(ms < 1000, `${Math.round(ms)} ms`);
  // the same push in FRONT of a decision that runs out of budget keeps its DENY: what was found is never given back
  overrideWorkLimit(400_000);
  try {
    const e = run(`${PUSH}; ${'echo a; '.repeat(2000)}`, dir);
    assert.equal(e.verdict, 'DENY', caps(e));
    assert.ok(e.hits.some((h) => h.capability === 'command.unknown' && /too large to classify/.test(h.via ?? '')), caps(e));
  } finally {
    overrideWorkLimit(null);
  }
});

test('a command nested deeper than the stack is an ASK, not an exception', () => {
  const dir = workspace();
  const e = run(`${'sudo '.repeat(1800)}ls`, dir);
  assert.equal(e.verdict, 'ASK', caps(e));
  assert.match(e.reason, /too (large|deeply nested) to classify within the bound/);
});

test('the bound is far above any ordinary decision: the largest in the corpus spends under a twentieth of it', () => {
  const dir = workspace();
  let most = 0;
  const measure = (c: string): void => {
    run(c, dir);
    most = Math.max(most, workSpent());
  };
  for (const cmds of Object.values(ORDINARY)) for (const c of cmds) measure(c);
  // every attack spelling of two of the heaviest families (carriers and nested shells), where a decision costs the most
  for (const cls of SEMANTIC_CLASSES.filter((k) => k.family === 'command').slice(0, 40)) for (const c of cls.cases) measure(c);
  assert.ok(most > 0, 'nothing was measured');
  assert.ok(most * 20 < WORK_LIMIT, `the largest decision measured spends ${most} units; the limit is ${WORK_LIMIT}`);
});

test('the reproduction in the review (700 spaces, a sed script, a push) does not depend on the clock: the same units every time', () => {
  const dir = workspace({ 'README.md': 'x\n' });
  const command = `sed -n '${' '.repeat(700)}p' README.md; ${PUSH}`;
  run(command, dir);
  const first = workSpent();
  run(command, dir);
  assert.equal(workSpent(), first);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * GIT
 *
 * A git command line says four things the policy cares about: WHICH ACT it is, WHAT PROGRAM it makes git run, WHO it speaks as, and
 * WHAT IT READS. Each was read by its own code with its own list, and each list was right about the spellings its author had in
 * mind. `authority/git-invocation.ts` reads the line once, and these tests state what has to stay true of it.
 * ------------------------------------------------------------------------------------------------------------- */

/** every spelling must be at least this; a stricter verdict (an absolute deny that was already there) is not a regression */
const atLeast = (floor: 'ASK' | 'DENY', command: string, dir: string, why = ''): void => {
  const got = verdictOf(command, dir);
  assert.ok(RANK[got]! >= RANK[floor]!, `${command}${why ? ` (${why})` : ''}: ${got}, expected at least ${floor}`);
};

test('r11-202: a branch reset is decided by the OPTION, whatever it is spelled: the long name, a prefix of it, a cluster, a global option in front', () => {
  const dir = workspace();
  for (const c of [
    'git switch -C main HEAD~3',
    'git switch --force-create main HEAD~3',
    'git switch --force-c main HEAD~3',
    'git switch --force-cre main',
    'git switch -fC main HEAD~3',
    'git switch -qC main HEAD~3',
    'git switch -C main',
    // a global option in front of the verb, one that takes a value included
    'git --attr-source HEAD branch -M topic3 topic2',
    'git --attr-source=HEAD branch -M topic3 topic2',
    'git --super-prefix=x/ checkout -B main',
    'git --no-pager --attr-source HEAD switch --force-create main',
    'git -c core.autocrlf=false switch --force-create main',
    'git -C . switch --force-create main',
    'git --git-dir=.git --work-tree=. switch --force-create main',
    // the other two verbs that move a branch that exists
    'git checkout -B main HEAD~3',
    'git checkout -fB main',
    'git branch -M a b',
    'git branch -C a b',
    'git branch --move --force a b',
    'git branch -fm a b',
    'git worktree add -B main ../w',
  ])
    atLeast('ASK', c, dir);
  // ...and the spellings that CREATE a branch, or switch to one, are the ordinary act they were
  for (const c of ['git switch -c topic', 'git switch --create topic', 'git switch main', 'git checkout -b topic', 'git branch -m a b', 'git branch topic'])
    assert.equal(verdictOf(c, dir), 'ALLOW', c);
});

test('r11-150: a configuration key that names a program is gated on every key git documents, however the value is handed over', () => {
  const dir = workspace();
  for (const c of [
    'git -c man.man.path=/tmp/evilman log --help',
    'git -c man.viewer=evil -c man.evil.cmd=/tmp/evil help log',
    'git -c help.format=web -c browser.chrome.path=/tmp/evil -c web.browser=chrome push --help',
    'git -c browser.x.cmd=/tmp/evil help -w log',
    'git -c web.browser=/tmp/evil help -w log',
    'git -c core.pager=/tmp/evil log',
    'git -c core.editor=/tmp/evil commit',
    'git -c sequence.editor=/tmp/evil rebase -i HEAD~2',
    'git -c core.sshCommand=/tmp/evil fetch origin',
    'git -c core.fsmonitor=/tmp/evil status',
    'git -c core.alternateRefsCommand=/tmp/evil fetch origin',
    'git -c core.askPass=/tmp/evil fetch origin',
    'git -c credential.helper=/tmp/evil fetch origin',
    'git -c credential.https://example.com.helper=/tmp/evil fetch origin',
    'git -c diff.external=/tmp/evil diff',
    'git -c diff.x.textconv=/tmp/evil diff',
    'git -c difftool.x.cmd=/tmp/evil difftool',
    'git -c mergetool.x.path=/tmp/evil mergetool',
    'git -c merge.x.driver=/tmp/evil merge topic',
    'git -c filter.x.clean=/tmp/evil add .',
    'git -c gpg.program=/tmp/evil commit -S -m x',
    'git -c gpg.ssh.defaultKeyCommand=/tmp/evil commit -m x',
    'git -c gc.recentObjectsHook=/tmp/evil gc',
    'git -c uploadpack.packObjectsHook=/tmp/evil fetch origin',
    'git -c instaweb.httpd=/tmp/evil instaweb',
    'git -c sendemail.smtpServer=/tmp/evil send-email a.patch',
    'git -c sendemail.toCmd=/tmp/evil send-email a.patch',
    'git -c imap.tunnel=/tmp/evil imap-send',
    'git -c interactive.diffFilter=/tmp/evil add -p',
    'git -c submodule.x.update=!/tmp/evil submodule update',
    'git -c include.path=/tmp/evil.cfg status',
    'git -c remote.origin.uploadpack=/tmp/evil fetch origin',
    // the value handed over by the environment, and the key set on a clone
    'git --config-env=man.man.path=EVIL log --help',
    'git --config-env core.pager=EVIL log',
    'git clone --config man.man.path=/tmp/evil https://example.com/x.git',
    'git clone -c core.pager=/tmp/evil https://example.com/x.git',
    // a key in capitals is the same key
    'git -c MAN.MAN.PATH=/tmp/evil log --help',
    'git -c Core.Pager=/tmp/evil log',
  ])
    atLeast('ASK', c, dir);
  // an ordinary key is data
  for (const c of ['git -c color.ui=always diff', 'git -c core.autocrlf=false status', 'git -c advice.detachedHead=false checkout main', 'git -c diff.renames=true diff'])
    assert.equal(verdictOf(c, dir), 'ALLOW', c);
});

test('the table of program keys agrees with git: every key on it is one git documents, and the classes it names are the right ones', () => {
  // the keys the kernel calls a program are named in `git help -c` (spelled with <placeholders>); a typo in the table would be a
  // key nobody can set, and a key git adds that this table lacks is caught by the shape rule and the families, not by luck
  const documented = new Set(GIT_CONFIG_KEYS.map((k) => k.replace(/<[^>]*>/g, '*').toLowerCase()));
  // (two are documented elsewhere: credential.<url>.* in gitcredentials(7), filter.<driver>.process in gitattributes(5))
  const elsewhere = new Set(['credential.*.helper', 'filter.*.process']);
  for (const [pattern] of PROGRAM_KEYS) assert.ok(documented.has(pattern.toLowerCase()) || elsewhere.has(pattern), `${pattern} is not a key git documents`);
  assert.ok(GIT_CONFIG_KEYS.length > 500, 'the documented keys were not generated');
  assert.equal(programKeyKind('man.man.path'), 'path');
  assert.equal(programKeyKind('core.pager'), 'command');
  assert.equal(programKeyKind('man.viewer'), 'name');
  assert.equal(programKeyKind('color.ui'), null);
  assert.equal(programKeyKind('branch.main.remote'), null);
  assert.ok(isIdentityConfigKey('Author.Name') && isIdentityConfigKey('committer.email') && isIdentityConfigKey('user.signingKey'));
  assert.ok(!isIdentityConfigKey('user.useConfigOnly') && !isIdentityConfigKey('core.pager'));
});

test('r11-157, r11-201: authorship is set by author.*, committer.* and user.* alike, on the line, from the environment, or on a clone', () => {
  const dir = workspace();
  for (const c of [
    'git -c user.name=Bob commit -m x',
    'git -c author.name=Mallory -c author.email=m@evil.test commit -m x',
    'git -c committer.name=Carol -c committer.email=c@evil.test commit -m x',
    'git -c author.name=Foo -c author.email=f@b -c committer.name=Bar -c committer.email=b@b commit -m x',
    'FOO=Baz git --config-env=user.name=FOO commit -m x',
    'FAKE=Mallory FAKEM=m@evil.test git --config-env=user.name=FAKE --config-env=user.email=FAKEM commit -m x',
    'git --config-env author.email=FAKEM commit -m x',
    'git -c Author.Name=Mallory commit -m x',
    'git -c user.signingkey=ABCDEF commit -S -m x',
    'git -c author.name=Mallory merge topic',
    'git -c committer.name=Carol rebase main',
    'git -c author.name=Mallory cherry-pick abc',
    'git -c author.name=Mallory tag -a v1 -m x',
    // the identity planted in a clone is the one every later commit in it is made as
    'git clone --config user.name=Mallory https://example.com/x.git',
    'git clone --config author.email=m@evil.test https://example.com/x.git',
    'git clone -c committer.name=Carol https://example.com/x.git',
  ])
    atLeast('ASK', c, dir);
  // the spellings that were already gated stay so, and a commit with no override is ordinary
  assert.equal(verdictOf('git commit -m x', dir), 'ALLOW');
  assert.equal(verdictOf('git commit --amend --no-edit', dir), 'ASK');
  for (const c of ['git commit --author="A <a@b>" -m x', 'GIT_AUTHOR_NAME=X git commit -m x']) atLeast('ASK', c, dir);
});

test('r11-203: a pathspec after a tree-ish overwrites the tree: whole-tree spellings are the destruction `checkout .` is, every other path is a restore', () => {
  const dir = workspace({ 'src/a.ts': 'x\n' });
  for (const c of [
    'git checkout HEAD -- .',
    'git checkout HEAD~3 -- .',
    'git checkout main -- .',
    'git checkout HEAD .',
    'git checkout HEAD -- *',
    'git checkout HEAD -- :/',
    'git checkout HEAD -- ./',
    'git checkout HEAD -- ./.',
    'git checkout HEAD -- :(top)',
    'git checkout HEAD -- :(top).',
    'git checkout stash@{0} -- .',
    'git checkout -f HEAD -- .',
    'git checkout HEAD -- src/ .',
    'git restore --source=HEAD~3 .',
    'git restore -s HEAD .',
    'git restore --source HEAD --worktree .',
    'git restore -W :/',
    'git restore --staged --worktree .',
    'git checkout -- .',
    'git checkout .',
  ]) {
    const e = run(c, dir);
    assert.ok(RANK[e.verdict]! >= RANK.ASK!, c);
    assert.ok(e.hits.some((h) => h.capability === 'command.destructive'), `${c}: ${caps(e)}`);
  }
  // a path that is not the whole tree is a restore, whatever character it ends in
  for (const c of ['git checkout HEAD -- src', 'git checkout HEAD -- src/', 'git checkout HEAD -- src/*', 'git checkout HEAD -- src/a.ts', 'git checkout HEAD src/a.ts', 'git restore src/']) {
    const e = run(c, dir);
    assert.equal(e.verdict, 'ASK', `${c}: ${caps(e)}`);
    assert.ok(e.hits.some((h) => h.capability === 'git.local.restore'), `${c}: ${caps(e)}`);
  }
  // reading, branching and unstaging are not restores
  for (const c of ['git checkout main', 'git checkout -b topic', 'git checkout -b topic HEAD', 'git restore --staged .', 'git restore -S src/a.ts'])
    assert.notEqual(verdictOf(c, dir), 'DENY', c);
  for (const c of ['git checkout main', 'git checkout -b topic HEAD']) assert.equal(verdictOf(c, dir), 'ALLOW', c);
});

test('r11-103: a repository a transport verb is pointed at is a path it reads, spelled as a path, as a file:// URL, or behind --reference', () => {
  const dir = workspace();
  const OUTSIDE = '/usr/share/zoneinfo';
  for (const c of [
    `git clone ${OUTSIDE} /tmp/x`,
    `git clone file://${OUTSIDE} /tmp/x`,
    `git clone file://localhost${OUTSIDE} /tmp/x`,
    `git clone file://anyhost${OUTSIDE} /tmp/x`,
    'git clone file:///usr/share/%7Ezone/info /tmp/x',
    `git clone --shared file://${OUTSIDE}`,
    `git clone --local file://${OUTSIDE} /tmp/x`,
    `git clone -l --no-checkout file://${OUTSIDE} /tmp/x`,
    `git fetch file://${OUTSIDE}`,
    `git fetch file://${OUTSIDE} main`,
    `git pull file://${OUTSIDE} main`,
    `git ls-remote file://${OUTSIDE}`,
    `git clone --reference ${OUTSIDE} https://example.com/x.git`,
    `git clone --reference-if-able ${OUTSIDE} https://example.com/x.git`,
    `git clone -c core.autocrlf=false file://${OUTSIDE} /tmp/x`,
    `git -C . clone file://${OUTSIDE} /tmp/x`,
  ])
    atLeast('ASK', c, dir);
  // a credential store is not made readable by a URL
  for (const c of ['git clone file://$HOME/.ssh /tmp/x', `git clone file://${homedir()}/.ssh /tmp/x`, `git fetch file://${homedir()}/.aws`])
    atLeast('DENY', c, dir);
  // the ordinary clones: a remote, a path in the workspace or in scratch space, a remote name
  for (const c of [
    'git clone https://example.com/x.git /tmp/x',
    'git clone git@example.com:o/r.git',
    'git clone file:///tmp/x /tmp/y',
    'git clone ./sibling /tmp/y',
    'git fetch origin',
    'git fetch origin main',
    'git pull',
    'git pull origin main',
    'git ls-remote origin',
  ])
    assert.equal(verdictOf(c, dir), 'ALLOW', c);
});

test('r11-105: a git command is not the verb it begins with: remote-ext runs a command, checkout-index overwrites the tree, status-x is another program', () => {
  const dir = workspace();
  for (const c of [
    "git remote-ext x 'git push --force origin main'",
    "printf 'connect git-upload-pack\\n' | git remote-ext x 'git push --force origin main'",
    "git remote-ext x 'touch /tmp/ran'",
  ])
    assert.equal(verdictOf(c, dir), 'DENY', c);
  // a hyphenated command that no rule names is not read as the shorter verb a pattern ends in `\b` in front of
  for (const c of ['git checkout-index -f -a', 'git status-x', 'git log-x', 'git clone-x https://example.com/x.git', 'git commit-graph write', 'git fetch-pack /tmp/x', 'git remote-fd 1 2', 'git remote-https origin https://example.com/x', 'git push-x origin main'])
    assert.equal(verdictOf(c, dir), 'ASK', c);
  // the hyphenated commands that DO have rules are untouched
  for (const c of ['git merge-base HEAD main', 'git rev-parse HEAD', 'git cat-file -p HEAD', 'git ls-files', 'git ls-remote origin', 'git for-each-ref', 'git cherry-pick --abort'])
    assert.notEqual(verdictOf(c, dir), 'DENY', c);
  for (const c of ['git merge-base HEAD main', 'git rev-parse HEAD', 'git ls-files', 'git for-each-ref']) assert.equal(verdictOf(c, dir), 'ALLOW', c);
  // every hyphenated command a matcher names is on the list that exempts it from the rename (the two are kept in step)
  const named = new Set<string>();
  for (const m of table.matchers) for (const v of (m.command ?? '').match(/\b[a-z]+(?:-[a-z]+)+\b/g) ?? []) if (isKnownGitVerb(v) && /git/.test(m.command ?? '')) named.add(v);
  for (const v of named) if (v.includes('-')) assert.ok(GIT_HYPHENATED_WITH_RULES.has(v), `${v} is named by a matcher and would be renamed`);
});

test('options are read by their canonical names: a prefix of a long option, a cluster of short ones, a value that looks like an option', () => {
  const read = (s: string) => readGitInvocation(s.split(' '));
  // an unambiguous prefix is the option
  assert.deepEqual(gitOption(read('git switch --force-c main'), '--force-create')?.names, ['-C', '--force-create']);
  assert.ok(gitOption(read('git push --no-verif origin main'), '--no-verify'));
  assert.ok(gitOption(read('git stash push --include-untr'), '--include-untracked'));
  assert.ok(gitOption(read('git stash -u'), '--include-untracked'), 'the default subcommand of stash is push');
  assert.ok(gitOption(read('git worktree add --force x'), '--force'));
  // a cluster is each letter, and the first that takes a value takes the rest
  assert.ok(gitOption(read('git switch -fC main'), '-f'));
  assert.ok(gitOption(read('git switch -fC main'), '-C'));
  assert.equal(gitOption(read('git commit -nm msg'), '--message')?.value, 'msg');
  assert.ok(gitOption(read('git commit -nm msg'), '-n'));
  // the value of an option is not an option: `-m --force` is a message
  assert.equal(gitOption(read('git commit -m --force'), '--force'), undefined);
  assert.equal(gitOption(read('git commit -m --force'), '-m')?.value, '--force');
  // nothing after `--` is an option
  assert.equal(gitOption(read('git checkout HEAD -- --force'), '--force'), undefined);
  // an ambiguous prefix is read as the governed option it could be, because git refuses it and "refused" is not "harmless"
  assert.ok(gitOption(read('git merge main --no-verif'), '--no-verify'));
  assert.ok(gitOption(read('git cherry-pick abc --no-verif'), '--no-verify'));
  // the negation is another option
  assert.equal(gitOption(read('git switch --no-force-create main'), '-C'), undefined);
});

test('r11-239: the repository\'s own configuration is whatever git says is local, however many files it includes', () => {
  // a chain of includes whose last file sets a program git runs on every commit. The kernel followed four, and git follows ten.
  for (const depth of [1, 4, 5, 6, 10]) {
    const dir = workspace();
    gitIn(dir, 'init', '-q');
    const out = mkdtempSync(join(tmpdir(), 'ego-chain-'));
    writeFileSync(join(out, `f${depth}`), '[core]\n\tfsmonitor = /tmp/evil.sh\n');
    for (let i = depth - 1; i >= 1; i--) writeFileSync(join(out, `f${i}`), `[include]\n\tpath = ${out}/f${i + 1}\n`);
    appendFileSync(join(dir, '.git', 'config'), `[include]\n\tpath = ${out}/f1\n`);
    const e = run('git commit -m x --allow-empty', dir);
    assert.notEqual(e.verdict, 'ALLOW', `depth ${depth}: ${caps(e)}`);
  }
  // past the depth git follows, git itself refuses the configuration: the question is then unanswered, and unanswered asks
  const dir = workspace();
  gitIn(dir, 'init', '-q');
  const out = mkdtempSync(join(tmpdir(), 'ego-chain-'));
  writeFileSync(join(out, 'f12'), '[core]\n\tfsmonitor = /tmp/evil.sh\n');
  for (let i = 11; i >= 1; i--) writeFileSync(join(out, `f${i}`), `[include]\n\tpath = ${out}/f${i + 1}\n`);
  appendFileSync(join(dir, '.git', 'config'), `[include]\n\tpath = ${out}/f1\n`);
  assert.notEqual(run('git commit -m x --allow-empty', dir).verdict, 'ALLOW');
  // an operator's own global configuration is not the repository's: a program there is the operator's business
  const clean = workspace();
  gitIn(clean, 'init', '-q');
  assert.equal(run('git commit -m x --allow-empty', clean).verdict, 'ALLOW');
});
