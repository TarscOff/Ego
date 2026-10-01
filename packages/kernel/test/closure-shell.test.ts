// CLOSURE OF THE SHELL-STRUCTURE FINDINGS (independent audit of 2026-10-01, re-running the Phase-1 gate on 05083c9).
// Each test names the CAUSE, not the spelling: the spellings are the audit's, the statement is what must stay true.
// Four causes, each of which an earlier fix had closed at ONE spelling and left its neighbours open:
//   1. a dry-run flag is judged by the LAST such flag the tool sees, not by whether one is present;
//   2. a function shadows a real program only while a definition that ran in the parent shell stands;
//   3. nothing after `--` is an option, so no option exception applies there;
//   4. `find -exec` of a writer is a write to every path the search can reach.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { workspace, verdict } from './support/corpus.ts';
import { cwdTimeline, functionBindingTimeline, splitShellPipeline } from '../src/authority/evaluate.ts';

const PROD = 'kubectl --context production';

test('the LAST dry-run flag decides: a bare flag followed by a flag that says "really do it" is not a dry run', () => {
  const dir = workspace({ 'x.yaml': 'kind: Deployment\n' });
  // the audit's reproductions: kubectl and helm treat a bare --dry-run as a flag with NO value, so the next word is a
  // new word (here another flag) and the second flag is the one that decides
  for (const c of [
    `${PROD} apply -f x.yaml --dry-run --dry-run=none`,
    `${PROD} delete pod x --dry-run --dry-run=none`,
    'helm --kube-context production upgrade r ./chart --dry-run --dry-run=none',
    // ...whatever "really do it" is spelled
    `${PROD} apply -f x.yaml --dry-run --dry-run=false`,
    `${PROD} apply -f x.yaml --dry-run=client --dry-run=false`,
    `${PROD} apply -f x.yaml --dry-run=server --dry-run=none`,
    'helm --kube-context production upgrade r ./chart --dry-run --dry-run=false',
    'helm --kube-context production upgrade r ./chart --dry-run=server --dry-run=none',
    // ...and however it is quoted: the shell removes the quotes before the tool sees the word
    `${PROD} apply -f x.yaml --dry-run=client "--dry-run=none"`,
    `${PROD} apply -f x.yaml --dry-run=client '--dry-run=none'`,
    `${PROD} apply -f x.yaml --dry-run=client --dry-run='none'`,
    // ...and however many dry flags stand in front of it
    `${PROD} apply -f x.yaml --dry-run --dry-run=client --dry-run=none`,
    `${PROD} apply --dry-run -f x.yaml -R --dry-run=none`,
    `oc --context production delete pod x --dry-run --dry-run=none`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
});

test('...and the same flags in the other order, or all of them dry, still LOOK', () => {
  const dir = workspace({ 'x.yaml': 'kind: Deployment\n' });
  for (const c of [
    `${PROD} apply -f x.yaml --dry-run=none --dry-run`,
    `${PROD} apply -f x.yaml --dry-run=none --dry-run=client`,
    `${PROD} apply -f x.yaml --dry-run=none --dry-run=server`,
    `${PROD} apply -f x.yaml --dry-run --dry-run=server`,
    `${PROD} apply -f x.yaml --dry-run --dry-run`,
    `${PROD} apply -f x.yaml --dry-run=false --dry-run=client`,
    `${PROD} apply -f x.yaml --dry-run=client -f "$MORE"`,
    `${PROD} delete pod x --dry-run=client`,
    // a bare flag's next word is a positional, not its value
    `${PROD} apply -f x.yaml --dry-run none`,
    'helm --kube-context production upgrade r ./chart --dry-run',
    'helm --kube-context production upgrade r ./chart --dry-run=none --dry-run',
    'helm --kube-context production upgrade r ./chart --dry-run=false --dry-run=server',
  ])
    assert.equal(verdict(c, dir), 'ALLOW', c);
  // a flag that is the VALUE of the option before it is not a flag: `--field-manager --dry-run=client` names a manager
  for (const c of [
    `${PROD} apply -f x.yaml --field-manager --dry-run=client`,
    `${PROD} apply -f x.yaml --field-manager --dry-run`,
    `helm --kube-context production uninstall app --description --dry-run`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
});

test('nothing after `--` is an option: a dry-run flag there is a PATH, and the governed file beside it is still removed', () => {
  const dir = workspace({ 'control-plane/permissions/absolute-denies.md': 'x\n', 'policies/p.md': 'x\n' });
  const governed = 'control-plane/permissions/absolute-denies.md';
  // the audit's reproduction: `-n` after `--` names a file called -n; the removal of the governed file is the act
  for (const c of [
    `git rm -f --ignore-unmatch -- -n ${governed}`,
    'git rm -rf -- -n control-plane',
    `git rm -f -- -n -- ${governed}`,
    `git rm --ignore-unmatch -- --dry-run ${governed}`,
    `git rm -- -n ${governed}`,
    `git mv -- -n ${governed} elsewhere.md`,
    `git mv -f -- --dry-run ${governed} elsewhere.md`,
    // the flag that was a dry run and was UNDONE by a later one is not one
    `git rm -n --no-dry-run ${governed}`,
    `git rm --dry-run --no-dry-run ${governed}`,
    // the same reader serves the operands of `git merge-file`, whose options take values: a label is not the file written
    `git merge-file -L a -L b -L c ${governed} base.md other.md`,
    `git merge-file --marker-size 9 ${governed} base.md other.md`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // ...while the flag BEFORE `--` still means what it meant
  for (const c of [
    `git rm -n -- ${governed}`,
    `git rm -n ${governed}`,
    `git rm --dry-run -f -- ${governed}`,
    `git rm -rn policies`,
    `git rm -nr policies`,
    `git rm --no-dry-run -n ${governed}`,
    `git mv -n -- ${governed} elsewhere.md`,
    `git mv --dry-run ${governed} elsewhere.md`,
  ])
    assert.notEqual(verdict(c, dir), 'DENY', c);
});

test('the same reader serves rsync and patch: the last flag decides, and `--` ends the flags', () => {
  const dir = workspace({ 'src/a.txt': 'x\n', 'control-plane/permissions/matchers.md': 'x\n' });
  // rsync: a dry run lists what WOULD be transferred; `--no-dry-run`, a flag after `--` and the value of `-e` are not that
  for (const c of [
    'rsync -a --dry-run --no-dry-run src/ .harness/generated/',
    'rsync -an --no-dry-run src/ .harness/generated/',
    'rsync -a -- -n src/ .harness/generated/',
    'rsync -a -e -n src/ .harness/generated/',
    'rsync -ae -n src/ .harness/generated/',
    'rsync -en src/ .harness/generated/',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  for (const c of [
    'rsync -avn src/ .harness/generated/',
    'rsync -a -n src/ .harness/generated/',
    'rsync --dry-run -a src/ .harness/generated/',
    'rsync -a --no-dry-run --dry-run src/ .harness/generated/',
  ])
    assert.notEqual(verdict(c, dir), 'DENY', c);
  // patch: `--dry-run` and `--check` change nothing; after `--` they are file names
  assert.notEqual(verdict('patch --dry-run control-plane/permissions/matchers.md', dir), 'DENY');
  assert.notEqual(verdict('patch --check control-plane/permissions/matchers.md', dir), 'DENY');
  assert.equal(verdict('patch -- --dry-run control-plane/permissions/matchers.md', dir), 'DENY');
  assert.equal(verdict('patch -p1 -- --check control-plane/permissions/matchers.md', dir), 'DENY');
});

test('the matchers that look for a dry-run flag read the same fact the code does: push, send-pack, the cloud CLIs, argocd', () => {
  const dir = workspace();
  // a regex can only ask whether a flag is PRESENT; the text it is handed says which one DECIDES
  for (const c of [
    'git push -n --no-dry-run origin main',
    'git push --dry-run --no-dry-run origin main',
    'git push --force -n --no-dry-run origin main',
    'git push --dry-run=false origin main',
    'git send-pack -n --no-dry-run origin main',
    // ...a `-n` that is a push option's value, or a remote's name, is not the flag
    'git push -o -n origin main',
    'git push --push-option -n origin main',
    'git push --push-option=-n origin main',
    'git push -- -n main',
    'git push origin main -- -n',
    'argocd app sync prod --dry-run=false',
    'argocd app sync prod --dry-run --dry-run=false',
    'aws ec2 terminate-instances --instance-ids i-1 --profile production --dry-run --no-dry-run',
    'aws ec2 terminate-instances --instance-ids i-1 --dry-run --no-dry-run',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // ...and the same flags in the other order still LOOK
  for (const c of [
    'git push -n origin main',
    'git push --dry-run origin main',
    'git push origin main -n',
    'git push --no-dry-run --dry-run origin main',
    'git push -n -n origin main',
    'git send-pack --dry-run origin main',
    'argocd app sync prod --dry-run',
    'argocd app sync prod --dry-run=false --dry-run',
    'aws ec2 terminate-instances --instance-ids i-1 --dry-run',
    'aws ec2 terminate-instances --instance-ids i-1 --no-dry-run --dry-run',
    'aws s3 rm s3://prod-bucket/x --dryrun',
  ])
    assert.notEqual(verdict(c, dir), 'DENY', c);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * FUNCTION BINDINGS. A function shadows the real program ONLY while a definition that ran in the PARENT shell
 * stands. Every case below ends in a real `git push origin main` (an organization lock) or `kubectl --context
 * production delete pod x` (an absolute deny), in real bash and zsh - the differential test further down checks that
 * claim against the shells themselves rather than trusting the list.
 * ------------------------------------------------------------------------------------------------------------- */

const PUSH = 'git push origin main';
const KILL = 'kubectl --context production delete pod x';

test('a definition that ran in a pipeline stage, a group or a subshell binds nothing in the parent', () => {
  const dir = workspace();
  for (const c of [
    // the review-8 CRITICAL, still ALLOW: the pipe is attached to the stage after the BODY
    `git() { echo hi; } | cat\n${PUSH}`,
    `git() { echo hi; } | cat; ${PUSH}`,
    `kubectl() { :; } | cat; ${KILL}`,
    `kubectl() { :; } | cat\n${KILL}`,
    // review-11 #199: the stage to the right of a pipe runs in a subshell as well (bash; zsh keeps it, the safe reading is not to)
    `echo x | git() { true; }; ${PUSH}`,
    `echo x | git() { true; }\n${PUSH}`,
    // a group is the stage of a pipeline when the pipe follows its closing brace, and a pipe feeds one too
    `{ git() { true; }; } | cat; ${PUSH}`,
    `echo x | { git() { true; }; }; ${PUSH}`,
    `{ echo a; git() { true; }; } | cat; ${PUSH}`,
    // a background job is a subshell, and so is everything in a group that is backgrounded
    `{ git() { true; }; } & ${PUSH}`,
    `{ echo a; git() { true; }; } & ${PUSH}`,
    `git() { true; } & ${PUSH}`,
    // the right of && and || runs only sometimes, and a whole group there runs only sometimes
    `false && { echo a; git() { true; }; }; ${PUSH}`,
    `true || { echo a; git() { true; }; }; ${PUSH}`,
    `false && echo a && git() { true; }; ${PUSH}`,
    // substitutions and backticks run in a subshell
    `echo $(git() { true; }); ${PUSH}`,
    `echo \`git() { true; }\`; ${PUSH}`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // ...and the cases that really DO bind, which keep their meaning (the function runs, not the program)
  for (const c of [
    `git() { true; }; ${PUSH}`,
    `git() { true; }\n${PUSH}`,
    `{ git() { true; }; }; ${PUSH}`,
    `git() { true; } && ${PUSH}`,
    `function git { true; }; ${PUSH}`,
    `git () { true; }; ${PUSH}`,
    `git() ( true ); ${PUSH}`,
    `log() { echo hi; }; log start`,
  ])
    assert.equal(verdict(c, dir), 'ALLOW', c);
});

test('a binding is lost by anything that can unset it: a callee, a sourced file, eval, trap, an alias of the callee', () => {
  const dir = workspace({ 'u.sh': 'unset -f git\n', 'noop.sh': 'true\n', 'chain.sh': 'source ./u.sh\n', 'k.sh': 'unset -f kubectl\n' });
  for (const c of [
    // review-11 #198: a function that is CALLED and unsets the name
    `f() { unset -f git; }; git() { true; }; f; ${PUSH}`,
    `git() { true; }; f() { unset -f git; }; f; ${PUSH}`,
    `f() { g; }; g() { unset -f git; }; git() { true; }; f; ${PUSH}`,
    `git() { true; }; f() { g; }; g() { unset -f git; }; f; ${PUSH}`,
    `git() { true; }; f() { builtin unset -f git; }; f; ${PUSH}`,
    `git() { true; }; f() { command unset -f git; }; f; ${PUSH}`,
    `git() { true; }; f() { unset -f git 2>/dev/null; }; if true; then f; fi; ${PUSH}`,
    `git() { true; }; f() { unset -f git; }; f | cat; ${PUSH}`,
    `git() { true; }; f() { unset -f git; }; time f; ${PUSH}`,
    `git() { true; }; f() { unset -f git; }; ! f; ${PUSH}`,
    `git() { true; }; f() { unset -f git; }; FOO=1 f; ${PUSH}`,
    `git() { true; }; f() { unset -f git; }; "f"; ${PUSH}`,
    `git() { true; }; f() { unset -f git; }; alias h=f; h; ${PUSH}`,
    `kubectl() { :; }; f() { unset -f kubectl; }; f; ${KILL}`,
    // a sourced file runs in the parent shell, and one that cannot be read leaves the binding unproved
    `git() { true; }; source ./u.sh; ${PUSH}`,
    `git() { true; }; . ./u.sh; ${PUSH}`,
    `git() { true; }; source u.sh; ${PUSH}`,
    `git() { true; }; source ./chain.sh; ${PUSH}`,
    `git() { true; }; source ./missing.sh; ${PUSH}`,
    `git() { true; }; source "$LIB"; ${PUSH}`,
    `git() { true; }; f() { source ./u.sh; }; f; ${PUSH}`,
    `kubectl() { :; }; source ./k.sh; ${KILL}`,
    // eval and trap run code the line does not show
    `git() { true; }; eval 'unset -f git'; ${PUSH}`,
    `git() { true; }; eval "$CLEANUP"; ${PUSH}`,
    `git() { true; }; f() { eval 'unset -f git'; }; f; ${PUSH}`,
    `git() { true; }; trap 'unset -f git' DEBUG; ${PUSH}`,
    `git() { true; }; trap 'unset -f git' ERR; ${PUSH}`,
    `git() { true; }; trap "$H" DEBUG; ${PUSH}`,
    `trap 'unset -f git' DEBUG; git() { true; }; ${PUSH}`,
    // an alias is looked up before a function of the same name, by every shell that expands aliases - and calling one runs
    // its value, in this shell
    `git() { true; }; alias git='command git'; ${PUSH}`,
    `git() { true; }; alias h='unset -f git'\nh\n${PUSH}`,
    `git() { true; }; alias h='source ./u.sh'\nh\n${PUSH}`,
    `git() { true; }; f() { unset -f git; }; alias h='f --x'\nh\n${PUSH}`,
    // a function whose BODY is a subshell ends where the subshell does: what follows it is the caller's again
    `git() ( true ); unset -f git; ${PUSH}`,
    `git() ( true ); source ./u.sh; ${PUSH}`,
    `git() ( true ); eval 'unset -f git'; ${PUSH}`,
    `cd() ( true ); unset -f cd; cd control-plane; tee permissions/matchers.md`,
    // zsh's own spellings of the same removal
    `git() { true; }; unfunction git; ${PUSH}`,
    `git() { true; }; unhash -f git; ${PUSH}`,
    `git() { true; }; disable -f git; ${PUSH}`,
    // a name built at run time may be this one
    `git() { true; }; unset -f $NAME; ${PUSH}`,
    `git() { true; }; unset -f "$NAME"; ${PUSH}`,
    `git() { true; }; unset -f g*; ${PUSH}`,
    // the zsh hook functions run by themselves, before the next command
    `TRAPDEBUG() { unset -f git; }; git() { true; }; ${PUSH}`,
    `git() { true; }; TRAPDEBUG() { unset -f git; }; ${PUSH}`,
    `chpwd() { unset -f git; }; git() { true; }; cd /; ${PUSH}`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // ...and what does NOT lose it: the function was never called, the file only reads, the unset is of a variable
  for (const c of [
    `git() { true; }; f() { unset -f git; }; ${PUSH}`,
    `git() { true; }; f() { echo hi; }; f; ${PUSH}`,
    `git() { true; }; g() { true; }; f() { g; }; f; ${PUSH}`,
    `git() { true; }; source ./noop.sh; ${PUSH}`,
    `git() { true; }; unset -v git; ${PUSH}`,
    `git() { true; }; unset -f other; ${PUSH}`,
    `git() { true; }; command git --version; echo done`,
  ])
    assert.equal(verdict(c, dir), 'ALLOW', c);
  // a trap that runs nothing before the next command (EXIT only, or just listing them) is not what un-binds it: `trap`
  // is an unmodelled builtin and asks on its own, and the push after it is still read as the call to the function
  for (const c of [`git() { true; }; trap 'echo bye' EXIT; ${PUSH}`, `git() { true; }; trap -p; ${PUSH}`])
    assert.equal(verdict(c, dir), 'ASK', c);
});

test('a program is the real one when the line says so: command, builtin, env, exec, a path, nohup', () => {
  const dir = workspace();
  for (const c of [
    `git() { true; }; command ${PUSH}`,
    `git() { true; }; env ${PUSH}`,
    `git() { true; }; /usr/bin/git push origin main`,
    `git() { true; }; exec ${PUSH}`,
    `git() { true; }; nohup ${PUSH}`,
    `git() { true; }; xargs ${PUSH} < /dev/null`,
    `git() { true; }; find . -maxdepth 0 -exec ${PUSH} \\;`,
    `git() { true; }; bash -c '${PUSH}'`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
});

test('the working directory has the same view of a definition: a cd that is really the builtin moves the shell', () => {
  const dir = workspace({ 'control-plane/permissions/matchers.md': 'x\n' });
  const tee = 'tee permissions/matchers.md';
  for (const c of [
    `cd() { true; } | cat\ncd control-plane\n${tee}`,
    `echo x | cd() { true; }\ncd control-plane\n${tee}`,
    `{ cd() { true; }; } | cat\ncd control-plane\n${tee}`,
    `f() { unset -f cd; }; cd() { true; }; f; cd control-plane; ${tee}`,
    `cd() { true; }; source ./missing.sh; cd control-plane; ${tee}`,
    `cd() { true; }; eval 'unset -f cd'; cd control-plane; ${tee}`,
    // a definition that may or may not have run: the move may or may not happen, and either may be where the write lands
    `false && cd() { true; }; cd control-plane; ${tee}`,
    `if [ -n "$X" ]; then cd() { true; }; fi; cd control-plane; ${tee}`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // a function that really shadows it: nothing moves (its body is judged where it stands)
  assert.equal(verdict(`cd() { true; }; cd control-plane; tee x.md`, dir), 'ALLOW');
  // a group in a pipeline is a subshell: its cd does not reach the caller, so the write lands where the shell is
  assert.equal(verdict(`{ cd control-plane; true; } | cat\ntee x.md`, dir), 'ALLOW');
  assert.equal(verdict(`{ cd control-plane; true; } & tee x.md`, dir), 'ALLOW');
  // ...but its own later stages are in the directory it moved to: a pipeline element and a background list are a
  // subshell, and a subshell sees its own cd
  for (const c of [
    `{ cd control-plane; ${tee}; } | cat`,
    `{ cd control-plane; ${tee}; } &`,
    `cd control-plane && ${tee} &`,
    `true; cd control-plane && ${tee} &`,
    `echo x | { cd control-plane; ${tee}; }`,
    `(cd control-plane && ${tee}) | cat`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
});

test('`find -exec` of anything that writes its operands is a write to every path the search can reach', () => {
  const dir = workspace({ 'src/a.ts': 'x\n', 'control-plane/permissions/matchers.md': 'x\n' });
  // the audit's reproductions (review-11 #88): a predicate that names the hooks directory selects files IN it
  for (const c of [
    'find . -path "*/.git/hooks/*" -exec chmod +x {} \\;',
    'find . -path "*/.git/hooks/*" -exec chmod 777 {} \\;',
    'find . -path "*/.git/hooks/*" -exec chmod +x {} +',
    'find . -path "*/.git/hooks/*" -execdir chmod +x {} \\;',
    'find . -path "*/.git/hooks/*" -ok chmod +x {} \\;',
    'find . -ipath "*/.git/hooks/*" -exec chmod +x {} \\;',
    'find . -path "*/.git/hooks/*" -exec touch {} \\;',
    'find . -path "*/.git/hooks/*" -exec chown root {} \\;',
    'find . -path "*/.git/hooks/*" -exec chgrp staff {} \\;',
    'find . -path "*/.git/hooks/*" -exec mv {} /tmp/saved \\;',
    'find . -path "*/.git/hooks/*" -exec cp /tmp/evil {} \\;',
    'find . -path "*/.git/hooks/*" -delete',
    // a governed tree named by the predicate, whichever way it is spelled
    'find . -path "./control-plane/*" -exec chmod 644 {} \\;',
    'find . -path "*control-plane*" -exec chmod 644 {} \\;',
    'find . -wholename "*/.harness/*" -exec chmod 644 {} +',
    'find . -path "*/.harness/*" -delete',
    // a SECOND starting point is a starting point: the search reaches everything under it
    'find . .git/hooks -name x -exec chmod +x {} \\;',
    'find src .git/hooks -type f -exec touch {} \\;',
    'find -L . .harness/generated -exec chmod 600 {} \\;',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // a predicate that does not NAME the place cannot be shown to avoid it: asking is the verdict, as it is for cp
  for (const c of [
    'find . -name pre-commit -exec chmod +x {} \\;',
    'find . -name pre-commit -exec chmod +x {} +',
    'find . -name "*.sh" -exec chmod +x {} \\;',
    'find . -type f -exec chmod 644 {} \\;',
    'find . -exec chmod +x {} \\;',
    'find . -execdir chmod +x {} \\;',
    'find . -ok chmod +x {} \\;',
    'find . -name pre-commit -exec touch {} \\;',
    'find . -name pre-commit -exec cp src/a.ts {} \\;',
    'find . -name pre-commit -exec mv {} /tmp/x \\;',
    'find src -name "*.sh" -exec chmod +x {} \\;',
    // a pattern that is on the EXCLUDING side of the test (`-prune`, `!`) names nothing that is selected
    'find . -path "*/.git/*" -prune -o -type f -exec chmod +x {} \\;',
    'find . -type f ! -path "*/.git/*" -exec chmod +x {} \\;',
    'find . -name node_modules -prune -o -name "*.sh" -exec chmod +x {} \\;',
    // fd is find under another name: its match is appended when no placeholder says where it goes
    'fd pre-commit -x chmod +x',
    'fd -H pre-commit -x chmod +x {}',
    "fd -H -p 'git/hooks' -x chmod +x {}",
  ])
    assert.equal(verdict(c, dir), 'ASK', c);
  // ...and the reads, and the ordinary work, are untouched
  for (const c of [
    'find . -name "*.ts"',
    'find src -name "*.ts" -exec cat {} \\;',
    'find . -name "*.ts" -exec grep -l foo {} +',
    'find . -type f -exec wc -l {} +',
    'find . -exec echo {} \\;',
    'find . -path "*/.git/hooks/*" -exec cat {} \\;',
    'find . -path "*/.git/hooks/*" -exec grep -l exit {} +',
  ])
    assert.equal(verdict(c, dir), 'ALLOW', c);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * THE MODEL AGAINST THE SHELLS. A list of spellings proves the spellings. The property is SOUNDNESS: whatever bash and
 * zsh really do, the model never claims a name is a function when either of them runs the program. (Bound in zsh and
 * not in bash is the safe disagreement; the reverse is the defect.)
 * ------------------------------------------------------------------------------------------------------------- */

const SHELLS = ['bash', 'zsh'].filter((sh) => {
  const r = spawnSync(sh, ['-c', ':']);
  return !r.error && r.status === 0;
});

function sandbox() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'ego-closure-')));
  const bin = join(root, 'bin');
  mkdirSync(bin);
  for (const name of ['git', 'kubectl']) {
    writeFileSync(join(bin, name), `#!/bin/sh\necho REAL:${name}\n`);
    chmodSync(join(bin, name), 0o755);
  }
  for (const [name, text] of Object.entries({
    'u.sh': 'unset -f git\n',
    'noop.sh': 'true\n',
    'chain.sh': 'source ./u.sh\n',
    'redef.sh': 'git() { echo SOURCED; }\n',
    'k.sh': 'unset -f kubectl\n',
    'go.sh': 'cd b\n',
  }))
    writeFileSync(join(root, name), text);
  for (const d of ['a/x', 'b', 'home', 'control-plane']) mkdirSync(join(root, d), { recursive: true });
  const env = { PATH: `${bin}:/usr/bin:/bin`, HOME: join(root, 'home'), ZDOTDIR: join(root, 'home') };
  const read = (file: string, moved: boolean): string | null => {
    if (moved && !isAbsolute(file)) return null;
    try {
      return readFileSync(isAbsolute(file) ? file : resolve(root, file), 'utf8');
    } catch {
      return null;
    }
  };
  return { root, env, read };
}

/** scripts that define git and then do something to the definition; each is run followed by `git push origin main` */
const BINDING_SCRIPTS = [
  'git() { echo FN; } | cat',
  'echo x | git() { echo FN; }',
  'echo x | { git() { echo FN; }; }',
  '{ git() { echo FN; }; } | cat',
  '{ echo a; git() { echo FN; }; } | cat',
  '{ git() { echo FN; }; } &',
  '{ echo a; git() { echo FN; }; } & wait',
  'git() { echo FN; } & wait',
  '( git() { echo FN; } )',
  'echo $(git() { echo FN; })',
  'echo `git() { echo FN; }`',
  'false && git() { echo FN; }',
  'false && { echo a; git() { echo FN; }; }',
  'true || git() { echo FN; }',
  'if false; then git() { echo FN; }; fi',
  'f() { git() { echo FN; }; }',
  'f() { unset -f git; }; git() { echo FN; }; f',
  'git() { echo FN; }; f() { unset -f git; }; f',
  'f() { g; }; g() { unset -f git; }; git() { echo FN; }; f',
  'f() { builtin unset -f git; }; git() { echo FN; }; f',
  'f() { source ./u.sh; }; git() { echo FN; }; f',
  'f() { eval "unset -f git"; }; git() { echo FN; }; f',
  'git() { echo FN; }; source ./u.sh',
  'git() { echo FN; }; . ./u.sh',
  'git() { echo FN; }; source ./chain.sh',
  'git() { echo FN; }; source ./k.sh; unset -f git',
  'git() { echo FN; }; eval "unset -f git"',
  "git() { echo FN; }; eval 'unset -f git'",
  "git() { echo FN; }; trap 'unset -f git' DEBUG",
  "git() { echo FN; }; trap 'unset -f git' ERR; false",
  "trap 'unset -f git' DEBUG; git() { echo FN; }",
  'TRAPDEBUG() { unset -f git; }; git() { echo FN; }',
  'git() { echo FN; }; TRAPDEBUG() { unset -f git; }',
  'chpwd() { unset -f git; }; git() { echo FN; }; cd /',
  'TRAPZERR() { unset -f git; }; git() { echo FN; }; false',
  'git() { echo FN; }; unset git',
  'git() { echo FN; }; unset -f git',
  "shopt -s expand_aliases\ngit() { echo FN; }\nalias git='command git'",
  "shopt -s expand_aliases\ngit() { echo FN; }\nalias h='unset -f git'\nh",
  'git() ( echo FN ); unset -f git',
  'git() ( echo FN ); source ./u.sh',
  'git() ( echo FN ); f() { unset -f git; }; f',
  'git() { echo FN; }; builtin unset -f git',
  'git() { echo FN; }; command unset -f git',
  'git() { echo FN; }; FOO=1 unset -f git',
  'git() { echo FN; }; unset -f nope git',
  'git() { echo FN; }; unset -f {git,x}',
  'git() { echo FN; }; x=git; unset -f $x',
  'git() { echo FN; }; true && unset -f git',
  'git() { echo FN; }; unfunction git',
  'git() { echo FN; }; unhash -f git',
  'git() { echo FN; }; disable -f git',
  'git() { echo FN; }; f() { unset -f git; }; alias h=f; h',
  'git() { echo FN; }; f() { unset -f git; }; time f',
  'git() { echo FN; }; f() { unset -f git; }; ! f',
  'git() { echo FN; }; f() { unset -f git; }; "f"',
  'git() { echo FN; }; f() { unset -f git; }; if f; then :; fi',
  'git() { echo FN; }; env git --version > /dev/null; unset -f git',
];

/** scripts after which git is STILL the function in both shells: the model must keep saying so, or it gates ordinary work */
const STAYS_BOUND = [
  'git() { echo FN; }',
  'function git { echo FN; }',
  'git () { echo FN; }',
  'git() ( echo FN )',
  '{ git() { echo FN; }; }',
  'git() { echo FN; } && true',
  'git() { echo FN; }; git() { echo FN2; }',
  // a redefinition that did not happen in this shell leaves the first definition standing; one that did replaces its body
  'git() { echo FN; }; echo x | git() { echo FN2; }',
  'git() { echo FN; }; ( git() { echo FN2; } )',
  'git() { echo FN; }; git() { echo FN2; } &',
  'git() { echo FN; }; f() { git() { echo FN2; }; }; f',
  'git() { echo FN; }; f() { unset -f git; }',
  'git() { echo FN; }; f() { echo hi; }; f',
  'git() { echo FN; }; g() { :; }; f() { g; }; f',
  'git() { echo FN; }; source ./noop.sh',
  'git() { echo FN; }; source ./redef.sh',
  'git() { echo FN; }; unset -v git',
  'git() { echo FN; }; unset -f other',
  "git() { echo FN; }; trap 'echo bye' EXIT",
  'git() { echo FN; }; trap - EXIT',
  'git() { echo FN; }; trap -p',
  'git() { echo FN; }; typeset -f > /dev/null',
  'git() { echo FN; }; command git --version > /dev/null',
  'git() { echo FN; }; env git --version > /dev/null',
  'git() { echo FN; }; \\git --version > /dev/null',
  'git() { echo FN; }; PATH=/nonexistent',
  'git() { echo FN; }; hash -r',
  'git() { echo FN; }; alias g=git',
];

const ranTheProgram = (out: string): boolean => /REAL:git/.test(out);

test('SOUNDNESS: the model never says "git is a function" where bash or zsh run the real program', () => {
  const { root, env, read } = sandbox();
  const failures: string[] = [];
  let bound = 0;
  for (const script of BINDING_SCRIPTS) {
    const full = `${script}\ngit push origin main`;
    const stages = splitShellPipeline(full);
    const last = functionBindingTimeline(stages, read)[stages.length - 1]!;
    const real = SHELLS.filter((sh) => {
      const r = spawnSync(sh, ['-c', full], { cwd: root, env, encoding: 'utf8', timeout: 10000 });
      return ranTheProgram(r.stdout ?? '');
    });
    if (last.must.has('git') && real.length > 0) failures.push(`${JSON.stringify(script)}: modelled as bound; ${real.join(' and ')} ran the program`);
    if (last.must.has('git')) bound++;
  }
  assert.deepEqual(failures, []);
  // the list is of scripts that undo or never make the binding; a model that says "bound" for none of them is not
  // being cautious, it is being right, and one that says it for many of them is wrong in the other direction
  assert.ok(bound <= BINDING_SCRIPTS.length * 0.25, `${bound} of ${BINDING_SCRIPTS.length} scripts still modelled as bound`);
});

test('PRECISION: what really stays a function stays one, because a model that always says "unknown" gates ordinary work', () => {
  const { root, env, read } = sandbox();
  const failures: string[] = [];
  for (const script of STAYS_BOUND) {
    const full = `${script}\ngit push origin main`;
    const stages = splitShellPipeline(full);
    const last = functionBindingTimeline(stages, read)[stages.length - 1]!;
    for (const sh of SHELLS) {
      const r = spawnSync(sh, ['-c', full], { cwd: root, env, encoding: 'utf8', timeout: 10000 });
      if (ranTheProgram(r.stdout ?? '')) failures.push(`${sh}: ${JSON.stringify(script)} is not a "stays bound" case after all`);
    }
    if (!last.must.has('git')) failures.push(`${JSON.stringify(script)}: git is still the function, and the model lost it`);
  }
  assert.deepEqual(failures, []);
});

const CWD_SCRIPTS = [
  'cd() { :; } | cat; cd a',
  'echo x | cd() { :; }; cd a',
  '{ cd() { :; }; } | cat; cd a',
  '{ cd() { :; }; } & wait; cd a',
  'cd() { :; } & wait; cd a',
  'false && cd() { :; }; cd a',
  'false && { echo a; cd() { :; }; }; cd a',
  'true && cd() { :; }; cd a',
  'if false; then cd() { :; }; fi; cd a',
  'f() { unset -f cd; }; cd() { :; }; f; cd a',
  'cd() { :; }; unset -f cd; cd a',
  "cd() { :; }; eval 'unset -f cd'; cd a",
  'cd() { :; }; source ./go.sh',
  'cd() { :; }; cd a',
  'cd() { :; }; cd a; cd x',
  'cd() { builtin cd b; }; cd a',
  'pushd() { :; }; pushd a >/dev/null; pwd',
  '{ cd a; cd x; } | cat',
  '{ cd a; cd x; } | cat; cd b',
  '{ cd a; true; } & wait',
  '{ cd a; cd x; } & wait; pwd',
  'echo x | { cd a; cd x; }',
  'echo x | { cd a; }; cd b',
  'cd a && { cd x; cd ..; } | cat',
  'true && { cd a; cd x; } & wait',
  '( cd a; cd x ) | cat; cd b',
];

for (const shell of SHELLS) {
  test(`the modelled working directory contains the one ${shell} ends in, with functions, groups and pipelines`, () => {
    const { root, env, read } = sandbox();
    const failures: string[] = [];
    for (const script of CWD_SCRIPTS) {
      const real = spawnSync(shell, ['-c', `${script}\npwd -P`], { cwd: root, env, encoding: 'utf8', timeout: 10000 });
      const lines = (real.stdout ?? '').trim().split('\n');
      const actual = lines[lines.length - 1]!;
      const points = cwdTimeline(splitShellPipeline(`${script}\ntrue`), root, true, (abs) => read(abs, false));
      const last = points[points.length - 1]!;
      if (!last.unknown && !last.dirs.includes(actual))
        failures.push(`${shell}: ${JSON.stringify(script)} ended in ${actual.replace(root, '<root>')}; modelled ${last.dirs.map((d) => d.replace(root, '<root>')).join(' | ')}`);
    }
    assert.deepEqual(failures, []);
  });
}
