// CLOSURE OF THE SHELL-STRUCTURE FINDINGS (independent audit of 2026-10-01, re-running the Phase-1 gate on 05083c9).
// Each test names the CAUSE, not the spelling: the spellings are the audit's, the statement is what must stay true.
// Four causes, each of which an earlier fix had closed at ONE spelling and left its neighbours open:
//   1. a dry-run flag is judged by the LAST such flag the tool sees, not by whether one is present;
//   2. a function shadows a real program only while a definition that ran in the parent shell stands;
//   3. nothing after `--` is an option, so no option exception applies there;
//   4. `find -exec` of a writer is a write to every path the search can reach.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { workspace, verdict } from './support/corpus.ts';

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

