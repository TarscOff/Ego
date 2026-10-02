// ONE PATH RESOLVER FOR THE SHELL LAYER (closure audit 2026-10-01, wave 2, "paths").
//
// The structured tools judge a path by what it RESOLVES to: `Write d/../settings.json` with `d -> .claude/sub` is the
// parent of the link's TARGET, `.claude/settings.json`, and is refused. The Bash layer used to turn a shell word into a
// path at about twenty places, each of them calling `resolve(cwd, word)` — which applies `..` to the TEXT — before the
// classifier saw it. So `echo x > d/../settings.json` was ALLOW while `cd d && echo x > ../settings.json` was DENY: the
// same file, written by the same shell, judged two ways. One function (pathCandidates, authority/paths.ts) now answers
// "what may this word denote?" for every site: the lexical reading AND the physical one, as written AND trimmed, in
// EVERY directory the shell may be in, and the verdict is the worst of them.
//
//   A  `..` after a link, through every kind of shell site      B  the reading must not make ordinary work gated
//   C  the directory is a SET: a conditional `cd`, `cd d/..`    D  spellings of one path: padding, tilde, $HOME, runs
//   E  /proc and descriptor aliases                              F  one reader for "is this a discard device"
//   G  the resolver is bounded                                   H  no site resolves a shell word on its own
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { evaluate, type Evaluation } from '../src/authority/evaluate.ts';
import { chdirPath, directoryCandidates, isDiscardDevice, openedPath, pathCandidates } from '../src/authority/paths.ts';
import { RANK, ctx, link, table, workspace } from './support/corpus.ts';

const HOME = homedir();

/** `d` is a link to `.claude/sub`, so `d/..` is `.claude` — the directory the agent's own configuration lives in.
 *  `e` is a link to `src/deep`, so `e/..` is `src` — ordinary. `chain` is a link to a link; `rel/up` is a RELATIVE
 *  link that itself climbs out of its own directory. */
const FILES: Record<string, string> = {
  '.claude/sub/keep': '',
  d: link('.claude/sub'),
  'src/deep/keep': '',
  e: link('src/deep'),
  chain: link('d'),
  'rel/x/keep': '',
  'rel/up': link('../.claude/sub'),
  // `hk/..` is `.git/hooks`: a directory an archive may not be extracted into, and the only kind of extraction target that is
  // refused outright rather than asked about (an archive's contents cannot be seen)
  '.git/hooks/sub/keep': '',
  hk: link('.git/hooks/sub'),
  // a link and a plain directory whose NAMES hold a space: the word that names them keeps its quoting only in the segment
  // as written, and the operand readers see a normalised one
  'd dir': link('.claude/sub'),
  'sp l': link('.claude'),
  'my docs/keep': '',
  'a.tar': 'x',
  'a.zip': 'x',
  'urls.txt': 'https://example.com\n',
  '.env': 'SECRET=1\n',
};

const dirOf = workspace(FILES);
const run = (command: string, dir = dirOf): Evaluation => evaluate(table, ctx(dir), { tool: 'Bash', input: { command } });
const verdictOf = (command: string, dir = dirOf): string => run(command, dir).verdict;
const caps = (e: Evaluation): string => e.hits.map((h) => `${h.verdict}:${h.capability}`).join(',');

/** Acts the policy ASKS about when they name `.claude` (an archive's contents, a deletion by search): through a link and `..`
 *  they must ask exactly as the plain spelling does — never fall to ALLOW. */
const ASKED_DOTDOT: readonly string[] = [
  'tar -xf a.tar -C d/..',
  'tar xf a.tar --directory=d/..',
  'unzip -d d/.. a.zip',
  'find d/.. -name settings.json -delete',
  'find d/.. -name x -exec rm {} \\;',
];

const REFUSED_DOTDOT: readonly string[] = [
  // a redirection, in every form the shell has
  'echo x > d/../settings.json',
  'echo x >> d/../settings.json',
  ': > d/../settings.json',
  'printf x 1> d/../settings.json',
  'echo x &> d/../settings.json',
  'echo x >| d/../settings.json',
  'echo x > "d/../settings.json"',
  "echo x > 'd'/'..'/settings.json",
  'echo x > ./d/../settings.json',
  'echo x > d/./../settings.json',
  'echo x > d//../settings.json',
  'echo x > d/../../.claude/settings.json',
  'echo x > chain/../settings.json',
  'echo x > rel/up/../settings.json',
  '(echo x) > d/../settings.json',
  '{ echo x; } > d/../settings.json',
  'cat > d/../settings.json <<EOF\nx\nEOF',
  'cat <<EOF > d/../settings.json\nx\nEOF',
  'cat <<< x > d/../settings.json',
  'sh -c "echo x > d/../settings.json"',
  'bash -c \'echo x > d/../settings.json\'',
  // a writer's operand
  'touch d/../settings.json',
  'cp package.json d/../settings.json',
  'cp -t d/.. package.json',
  'cp --target-directory=d/.. package.json',
  'cp package.json d/..',
  'mv package.json d/../settings.json',
  'echo x | tee d/../settings.json',
  'echo x | tee -a d/../settings.json',
  'dd if=/dev/zero of=d/../settings.json count=1',
  'install package.json d/../settings.json',
  'ln -s package.json d/../settings.json',
  'rm d/../settings.json',
  'rm -f d/../settings.json',
  'chmod 600 d/../settings.json',
  'truncate -s 0 d/../settings.json',
  'sed -i s/a/b/ d/../settings.json',
  'sed -n "1w d/../settings.json" package.json',
  'perl -pi -e s/a/b/ d/../settings.json',
  'rsync package.json d/../settings.json',
  'sort -o d/../settings.json package.json',
  'git rm d/../settings.json',
  'git checkout HEAD -- d/../settings.json',
  'git restore d/../settings.json',
  // an archive extraction into a directory that IS protected, and an archive written
  'tar -xf a.tar -C hk/..',
  'tar xf a.tar -C hk/..',
  'tar -xf a.tar --directory=hk/..',
  'tar -xf a.tar -Chk/..',
  'unzip -d hk/.. a.zip',
  'tar -cf d/../settings.json src',
  'zip d/../settings.json src',
  // a payload another command runs
  'find . -name x -exec cp package.json d/../settings.json \\;',
  'find . -name x -execdir tee d/../settings.json \\;',
  'find . -name x | xargs cp -t d/..',
  'xargs -I{} cp {} d/../settings.json < urls.txt',
  // a path-valued option
  'curl -o d/../settings.json https://example.com',
  'curl --output d/../settings.json https://example.com',
  'wget -O d/../settings.json https://example.com',
  'esbuild src/a.ts --outfile=d/../settings.json',
  'tsc --tsBuildInfoFile d/../settings.json',
  'cmd --output d/../settings.json',
  // a name with a space in it: one word to the shell, several to the readers of a normalised segment
  'echo x > "d dir/../settings.json"',
  'cp package.json "d dir/../settings.json"',
  'cp package.json d\\ dir/../settings.json',
  "cp package.json 'd dir'/../settings.json",
  'cp -t "d dir/.." package.json',
  'touch "d dir/../settings.json"',
  'mv package.json "d dir/../settings.json"',
  'echo x | tee "d dir/../settings.json"',
  'sed -i s/a/b/ "d dir/../settings.json"',
  'rm "d dir/../settings.json"',
  'dd if=package.json of="d dir/../settings.json"',
  'curl -o "d dir/../settings.json" https://example.com',
  'sudo cp package.json "d dir/../settings.json"',
  'env X=1 cp package.json "d dir/../settings.json"',
  // ...and a link whose name holds a space needs no `..` at all: `sp l` is `.claude`
  'cp package.json "sp l/settings.json"',
  'cp package.json sp\\ l/settings.json',
  'touch "sp l/settings.json"',
  'echo x | tee "sp l/settings.json"',
  'mv package.json "sp l/settings.json"',
  'rm "sp l/settings.json"',
  'cp -t "sp l" package.json',
  'cp package.json "sp l"',
  'sed -i s/a/b/ "sp l/settings.json"',
  'curl -o "sp l/settings.json" https://example.com',
];

test('A. `..` after a link names the parent of the link TARGET, at every site that turns a shell word into a path', () => {
  const failures: string[] = [];
  for (const command of REFUSED_DOTDOT) {
    const e = run(command);
    if (e.verdict !== 'DENY') failures.push(`${e.verdict} [${caps(e)}]  ${command.replace(/\n/g, '\\n')}`);
  }
  assert.deepEqual(failures, [], `a path reached through a link and \`..\` was not judged as what it names:\n  ${failures.join('\n  ')}`);
});

test('A. what the plain spelling asks about, the linked spelling asks about too', () => {
  for (const command of ASKED_DOTDOT) {
    const plain = command.replace(/d\/\.\./g, '.claude');
    assert.notEqual(verdictOf(plain), 'ALLOW', `${plain} (the control: the plain spelling must itself ask)`);
    assert.notEqual(verdictOf(command), 'ALLOW', command);
  }
});

test('A. the physical spelling and the linked spelling of one file are judged alike, in both directions', () => {
  // the differential: replace `d/..` by the directory it IS and the verdict must not get weaker
  for (const command of REFUSED_DOTDOT) {
    if (!command.includes('d/..')) continue;
    const resolved = command.replace(/d\/\.\.\/\.\.\/\.claude/g, '.claude').replace(/d\/\.\./g, '.claude');
    const linked = verdictOf(command);
    const plain = verdictOf(resolved);
    assert.ok(RANK[linked]! >= RANK[plain]!, `${command}: ${linked}, but the same act spelled ${resolved} is ${plain}`);
  }
  // a path through a link whose parent is ordinary is ordinary work (the half that keeps the resolver usable): the verdict
  // is exactly the one the physical spelling earns, never stricter for the link alone
  for (const command of [
    'echo x > e/../out.txt',
    'cp package.json e/../copy.json',
    'touch e/../x.ts',
    'mv package.json e/../moved.json',
    'sed -i s/a/b/ e/../x.ts',
    'tar -cf e/../out.tar docs',
    'curl -o e/../page.html https://example.com',
    'wget -O e/../page.html https://example.com',
    'find . -name x -exec cp package.json e/../copy.json \\;',
  ])
    assert.equal(verdictOf(command), verdictOf(command.replace('e/..', 'src')), command);
  assert.equal(verdictOf('echo x > e/../out.txt'), 'ALLOW');
  assert.equal(verdictOf('cp package.json e/../copy.json'), 'ALLOW');
  assert.equal(verdictOf('touch e/../x.ts'), 'ALLOW');
  // ...and a plain directory with a space in its name is ordinary work, with or without a `..`
  for (const command of ['cp package.json "my docs/../copy.json"', 'echo x > "my docs/../out.txt"', 'touch "my docs/../x.ts"', 'cp package.json "my docs/copy.json"', 'cat "my docs/../package.json"'])
    assert.equal(verdictOf(command), 'ALLOW', command);
  // a word that is only READ through a link with a space in its name is read, as it is through any other spelling
  assert.equal(verdictOf('cp "sp l/settings.json" /tmp/x'), verdictOf('cp .claude/settings.json /tmp/x'));
  assert.equal(verdictOf('cat "sp l/settings.json"'), verdictOf('cat .claude/settings.json'));
  assert.equal(verdictOf('git commit -m "update docs/a b.md"'), verdictOf('git commit -m "update docs"'));
  assert.equal(verdictOf('sqlite3 app.db "select * from t where a = 1"'), verdictOf('sqlite3 app.db "select 1"'));
});

test('A. reading through a link and `..` is judged like the file it reaches', () => {
  // `d/../../.env` is, physically, `.env` in the workspace root (the link's target is two levels down)
  assert.equal(verdictOf('cat d/../../.env'), verdictOf('cat .env'));
  assert.notEqual(verdictOf('cat d/../../.env'), 'ALLOW');
  assert.equal(verdictOf('cat chain/../../.env'), verdictOf('cat .env'));
  assert.equal(verdictOf('cat e/../../.env'), verdictOf('cat .env'));
});

test('A. a credential store reached through a link and `..` is a credential store, for a read and for a write', () => {
  // the link lives in the workspace and names a directory INSIDE ~/.ssh (that need not exist), so `cred/..` is ~/.ssh itself
  const dir = workspace({ cred: link(`${HOME}/.ssh/zz-paths-${process.pid}`), 'rel/c2': link(`../cred`) });
  for (const command of [
    'cat cred/../id_rsa',
    'cat cred/../id_ed25519',
    'cat < cred/../id_rsa',
    'cp cred/../id_rsa /tmp/leak',
    'head -c 8 rel/c2/../id_rsa',
    `cat ${join(dir, 'cred')}/../id_rsa`,
  ])
    assert.equal(verdictOf(command, dir), verdictOf(command.replace(/(?:\S*cred|rel\/c2)\/\.\./, '~/.ssh'), dir), command);
  assert.notEqual(verdictOf('cat cred/../id_rsa', dir), 'ALLOW');
  // the DIRECTORY itself is not a file a path matcher names, so a recursive read of it asks (as it does through any link);
  // what must not happen is ALLOW
  for (const command of ['grep -r KEY cred/..', 'ls cred/..', 'find cred/.. -name id_rsa', 'tar -cf /tmp/x.tar cred/..'])
    assert.notEqual(verdictOf(command, dir), 'ALLOW', command);
  for (const command of ['echo x > cred/../authorized_keys', 'cp package.json cred/../authorized_keys', 'tee cred/../config < package.json'])
    assert.equal(verdictOf(command, dir), 'DENY', command);
  // the tools surface agrees
  assert.notEqual(evaluate(table, ctx(dir), { tool: 'Read', input: { file_path: 'cred/../id_rsa' } }).verdict, 'ALLOW');
  assert.notEqual(evaluate(table, ctx(dir), { tool: 'Grep', input: { path: 'cred/..', pattern: 'KEY' } }).verdict, 'ALLOW');
});

test('A. the file a reader opens is the physical one: a script, a makefile, an awk program or a Dockerfile behind `link/..` is READ', () => {
  const PUSH = 'git push origin main\n';
  const dir = workspace({
    '.claude/sub/keep': '',
    d: link('.claude/sub'),
    '.claude/run.sh': `#!/bin/sh\n${PUSH}`,
    '.claude/env.sh': PUSH,
    '.claude/plan.mk': `build:\n\t${PUSH}`,
    '.claude/Makefile': `build:\n\t${PUSH}`,
    '.claude/prog.awk': 'BEGIN{system("git push origin main")}\n',
    '.claude/p.sed': '1e git push origin main\n',
    '.claude/Dockerfile': `FROM alpine\nRUN ${PUSH}`,
    // the file the TEXT names: beside the link, harmless
    'run.sh': '#!/bin/sh\necho ok\n',
    'Makefile': 'build:\n\ttsc -p .\n',
  });
  for (const command of [
    'sh d/../run.sh',
    'bash d/../run.sh',
    './d/../run.sh',
    'sh ./d//../run.sh',
    'source d/../env.sh',
    '. d/../env.sh',
    'make -f d/../plan.mk build',
    'make -C d/.. build',
    'make -C d/.. -f plan.mk build',
    'awk -f d/../prog.awk',
    'sed -f d/../p.sed package.json',
    'docker build -f d/../Dockerfile .',
    'cd d && sh ../run.sh',
    'cd d && make -C .. build',
  ])
    assert.equal(verdictOf(command, dir), 'DENY', command);
  // the same words with no link in the way read the file beside them, as before
  assert.equal(verdictOf('sh run.sh', dir), verdictOf('sh src/../run.sh', dir));
  assert.equal(verdictOf('make build', dir), verdictOf('make -C src/.. build', dir));
});

test('B. a link whose target does not exist yet is followed: `..` after it is still the parent of the target', () => {
  // the link names a directory that nobody has created; the shell cannot open through it, but a mkdir earlier in the
  // same command line can make it real, so the target's parent is what is judged
  const dir = workspace({ ghost: link('.claude/zz-new') });
  for (const command of ['echo x > ghost/../settings.json', 'cp package.json ghost/../settings.json', 'touch ghost/../settings.json'])
    assert.equal(verdictOf(command, dir), 'DENY', command);
});

test('C. the directory is a SET: a conditional or lexical-versus-physical `cd` keeps every possibility', () => {
  for (const command of [
    'cd d/.. && echo x > settings.json', // logical: the workspace root; physical: .claude — both are possible
    'cd d/.. && cp package.json settings.json',
    'pushd d/.. >/dev/null; echo x > settings.json',
    'cd d; echo x > ../settings.json',
    'cd chain && echo x > ../settings.json',
    'test -d nope || cd d; echo x > ../settings.json',
    'if [ -d d ]; then cd d; fi; echo x > ../settings.json',
    'cd src; cd ../d/..; echo x > settings.json',
    'cd d && cd .. && touch settings.json',
    'cd -P d/.. && echo x > settings.json',
    '(cd d/.. && echo x > settings.json)',
    'cd e && echo x > ../../d/../settings.json',
  ])
    assert.equal(verdictOf(command), 'DENY', command);
  // ...and the same shapes toward an ordinary directory stay ordinary
  for (const command of ['cd e && echo x > ../out.txt', 'cd src && echo x > ../out.txt', 'cd e && cd .. && echo x > out.txt'])
    assert.equal(verdictOf(command), 'ALLOW', command);
  // (`cd e/..` itself is two directories — the logical one and the physical one — and nothing positive rests on that:
  // it asks, as it did before the resolver was shared)
  assert.notEqual(verdictOf('cd e/.. && echo x > out.txt'), 'DENY');
});

test('C. the shell may itself be standing in a link: `..` is the parent of the directory it is really in', () => {
  const inside = (cwd: string, command: string): string => evaluate(table, { ...ctx(dirOf), cwd }, { tool: 'Bash', input: { command } }).verdict;
  for (const command of ['echo x > ../settings.json', 'cp package.json ../settings.json', 'touch ../settings.json', 'tee ../settings.json < package.json'])
    assert.equal(inside(join(dirOf, 'd'), command), 'DENY', `in a link to .claude/sub: ${command}`);
  for (const command of ['echo x > ../out.txt', 'cp package.json ../copy.json', 'touch ../x.ts'])
    assert.equal(inside(join(dirOf, 'e'), command), 'ALLOW', `in a link to src/deep: ${command}`);
  assert.equal(inside(join(dirOf, 'src'), 'echo x > ../out.txt'), 'ALLOW');
});

test('the lexical reading stays beside the physical one: a protected NAME that is itself a link is still protected', () => {
  // `.claude` here is a link, so its realpath (`store/…`) no longer says `.claude`: only the typed name protects the file.
  // A resolver that kept only the physical reading would have judged `store/settings.json` and let all of these through.
  const root = mkdtempSync(join(tmpdir(), 'ego-namelink-'));
  mkdirSync(join(root, '.git', 'hooks'), { recursive: true });
  mkdirSync(join(root, 'store'));
  mkdirSync(join(root, 'src'));
  symlinkSync('store', join(root, '.claude'));
  writeFileSync(join(root, 'package.json'), '{}');
  for (const command of [
    'echo x > .claude/settings.json',
    'cp package.json .claude/settings.json',
    'touch .claude/settings.json',
    'tee .claude/settings.json < package.json',
    'mv package.json .claude/settings.json',
    'sed -i s/a/b/ .claude/settings.json',
    'cp package.json src/../.claude/settings.json',
    'cd src && cp ../package.json ../.claude/settings.json',
    'find . -name x -exec cp package.json .claude/settings.json \\;',
  ])
    assert.equal(verdictOf(command, root), 'DENY', command);
  assert.equal(verdictOf('echo x > src/ok.txt', root), 'ALLOW');
});

test('D. one path spelled many ways is one path', () => {
  const root = 'echo x >';
  for (const spelling of [
    '.claude//settings.json',
    '.claude/./settings.json',
    './.claude///./settings.json',
    '.claude/settings.json/',
    '.claude/settings.json/.',
    'src//..//.claude/settings.json',
    '"$PWD/.claude/settings.json"',
    '${PWD}/.claude/settings.json',
    '~+/.claude/settings.json',
    '$PWD/src/../.claude/settings.json',
  ])
    assert.equal(verdictOf(`${root} ${spelling}`), 'DENY', spelling);
  for (const spelling of [
    '$HOME/.ssh/authorized_keys',
    '${HOME}/.ssh/authorized_keys',
    '"$HOME/.ssh/authorized_keys"',
    '"$HOME"/.ssh/authorized_keys',
    '~/.ssh/authorized_keys',
    '~//.ssh//authorized_keys',
    '~/./.ssh/authorized_keys',
    '~/.ssh/../.ssh/authorized_keys',
    `${HOME}//.ssh/./authorized_keys`,
    '${HOME}x/.ssh/authorized_keys', // a brace ends the name: the home directory followed by an `x`
  ])
    assert.equal(verdictOf(`${root} ${spelling}`), 'DENY', spelling);
  // `$HOMEDIR` is a different variable, not `$HOME` followed by letters: nothing can be said, so it asks
  assert.equal(verdictOf('echo x > $HOMEDIR/.ssh/authorized_keys'), 'ASK');
  // a name the line itself gave a value this kernel cannot read is no longer the directory the reader would expand it to
  for (const command of [
    'PWD=$(echo /etc); echo x > $PWD/cron.d/x',
    'HOME=$(echo /etc); echo x > $HOME/cron.d/x',
    'export HOME=$(echo /etc) && echo x > ${HOME}/cron.d/x',
    'OLDPWD=$(echo /etc); cd src; echo x > $OLDPWD/cron.d/x',
  ])
    assert.notEqual(verdictOf(command), 'ALLOW', command);
  assert.equal(verdictOf('PWD=/etc; echo x > $PWD/cron.d/x'), 'DENY', 'a literal assignment is read, as every other variable is');
  assert.equal(verdictOf('echo x > $PWD/out.txt'), 'ALLOW');
  // the previous directory, where the command line has one
  assert.equal(verdictOf('cd src; echo x > ~-/.claude/settings.json'), 'DENY');
  assert.equal(verdictOf('cd src; cp package.json ~-/.claude/settings.json'), 'DENY');
  assert.equal(verdictOf('cd src; echo x > $OLDPWD/.claude/settings.json'), 'DENY');
  assert.equal(verdictOf('cd src; echo x > ~-/ordinary.txt'), 'ALLOW');
  // ...and where it has none, the word is dynamic and asks
  assert.equal(verdictOf('echo x > ~-/ordinary.txt'), 'ASK');
  // another user's home: nothing here can say where it is, but a write outside the workspace is refused wherever it is
  assert.equal(verdictOf('echo x > ~root/.ssh/authorized_keys'), 'DENY');
  assert.equal(verdictOf('echo x > ~nobody-such-user/.ssh/authorized_keys'), 'DENY');
  assert.notEqual(verdictOf('cat ~nobody-such-user/notes.txt'), 'ALLOW');
});

test('D. a leading tilde is $HOME: a HOME the line assigns is the home the tilde means', () => {
  // the process's own home is INSIDE the workspace here, so a tilde that kept meaning it would be an ordinary repository
  // path - and `export HOME=/etc; echo x > ~/passwd` would write /etc/passwd at ALLOW
  const dir = workspace({ 'home/keep': '' });
  const saved = process.env.HOME;
  process.env.HOME = join(dir, 'home');
  try {
    assert.equal(verdictOf('echo x > ~/note.txt', dir), 'ALLOW', 'the control: the process home is an ordinary place here');
    for (const command of [
      'export HOME=/etc; echo x > ~/passwd',
      'HOME=/etc; cp package.json ~/passwd',
      'export HOME=/etc && tee ~/cron.d/x < package.json',
      'HOME=/etc; touch ~/passwd',
      'HOME=/etc; echo x >~/passwd',
    ])
      assert.equal(verdictOf(command, dir), 'DENY', command);
    for (const command of ['HOME=$(echo /etc); echo x > ~/passwd', 'export HOME=$X; cp package.json ~/passwd'])
      assert.notEqual(verdictOf(command, dir), 'ALLOW', command);
    // a tilde that is not the start of a word is not expanded by the shell (an assignment to HOME asks on its own, so the
    // comparison is with the same line writing an ordinary name)
    assert.equal(verdictOf("HOME=/etc; echo x > 'a~/passwd'", dir), verdictOf('HOME=/etc; echo x > a.txt', dir));
  } finally {
    if (saved === undefined) delete process.env.HOME;
    else process.env.HOME = saved;
  }
});

test('D. padding that survived quoting: the path as written AND the trimmed one are judged', () => {
  for (const command of [
    'echo x > " /etc/cron.d/x"',
    'echo x > "/etc/cron.d/x "',
    'echo x > "\t/etc/cron.d/x"',
    'echo x > " /etc/cron.d/x"',
    'echo x > "\u0085/etc/cron.d/x"',
    "echo x > ' /etc/cron.d/x'",
    'tee " /etc/cron.d/x" < /dev/null',
    'cp package.json " /etc/cron.d/x"',
    'mv package.json " /etc/cron.d/x"',
    'touch " /etc/cron.d/x"',
    'echo x > " ~/.ssh/authorized_keys"',
    'echo x > " $HOME/.ssh/authorized_keys"',
    'echo x > " .claude/settings.json"',
    'echo x > ".claude/settings.json "',
    'curl -o " /etc/cron.d/x" https://example.com',
    'tar -xf a.tar -C " /etc"',
    'find . -name x -exec cp package.json " /etc/cron.d/x" \\;',
    'sed -i s/a/b/ " /etc/cron.d/x"',
  ])
    assert.equal(verdictOf(command), 'DENY', command);
  // padding on an ordinary path is not a reason to refuse it
  assert.equal(verdictOf('echo x > " out.txt"'), 'ALLOW');
  assert.equal(verdictOf('echo x > "out.txt "'), 'ALLOW');
});

test('E. a path through /proc or a descriptor alias is an alias for something else, and asks', () => {
  for (const command of [
    'echo x > /proc/self/cwd/src/a.ts',
    'echo x > /proc/self/root/tmp/x',
    'echo x > /proc/thread-self/cwd/src/a.ts',
    'echo x > /proc/1234/cwd/src/a.ts',
    'echo x > /proc/self/fd/3',
    'echo x > /dev/fd/3',
    'echo x > /dev/fd/10',
    'cat /proc/self/cwd/package.json',
    'cat /dev/fd/3',
    'cp package.json /proc/self/cwd/copy.json',
    'tee /dev/fd/3 < package.json',
    'curl -o /dev/fd/3 https://example.com',
  ])
    assert.notEqual(verdictOf(command), 'ALLOW', command);
  // ...and the alias is followed as far as it can be: the working directory is where it points
  assert.equal(verdictOf('echo x > /proc/self/cwd/.claude/settings.json'), 'DENY');
  assert.equal(verdictOf('echo x > /proc/self/root/etc/cron.d/x'), 'DENY');
  assert.equal(verdictOf('cd .claude && echo x > /proc/self/cwd/settings.json'), 'DENY');
  // descriptors 0, 1 and 2 ARE the command's own standard streams: a destination that was judged where it was opened
  for (const command of ['echo x > /dev/stdout', 'echo x > /dev/stderr', 'echo x 2>/dev/stderr', 'echo x > /dev/fd/1', 'echo x > /dev/fd/2', 'cat < /dev/stdin'])
    assert.equal(verdictOf(command), 'ALLOW', command);
});

test('F. one reader decides whether a destination is a discard device, and the redirection and the option agree', () => {
  const PLAIN = verdictOf('curl https://example.com');
  assert.notEqual(PLAIN, 'DENY');
  for (const command of [
    'curl -o /dev/null https://example.com',
    'curl --output /dev/null https://example.com',
    'curl --output=/dev/null https://example.com',
    'curl -o/dev/null https://example.com',
    'curl -s -o /dev/null -w "%{http_code}" https://example.com',
    'curl -sSL -o /dev/null https://example.com',
    'wget -O /dev/null https://example.com',
    'wget -qO /dev/null https://example.com',
    'wget --output-document=/dev/null https://example.com',
    'wget -O- https://example.com',
    'cmd --output /dev/null',
    'esbuild src/a.ts --outfile=/dev/null',
    'tsc --tsBuildInfoFile /dev/null',
    'curl -o /dev/stdout https://example.com',
    'curl -o /dev/stderr https://example.com',
    'curl -o /dev/zero https://example.com',
    'curl -D /dev/null https://example.com',
    'curl -D /dev/stdout https://example.com',
    'curl -c /dev/null https://example.com',
    'curl --dump-header /dev/null https://example.com',
    'curl --stderr /dev/null https://example.com',
    'wget -O /dev/stdout https://example.com',
    'wget -a /dev/null https://example.com',
    'gcc -o /dev/null foo.c',
    'git diff --output=/dev/null',
    'tar -cf /dev/null src',
  ])
    assert.notEqual(verdictOf(command), 'DENY', `${command}: an option-valued discard device is not a write to a path`);
  // ...and the same options name a file when it is one
  for (const command of [
    'curl -D .claude/settings.json https://example.com',
    'curl -c .git/hooks/pre-commit https://example.com',
    'curl --cookie-jar .claude/settings.json https://example.com',
    'curl --dump-header=.claude/settings.json https://example.com',
    'wget -O .claude/settings.json https://example.com',
    'wget -O.claude/settings.json https://example.com',
    'wget -qO.claude/settings.json https://example.com',
    'wget -a .claude/settings.json https://example.com',
    'git diff --output=.claude/settings.json',
  ])
    assert.equal(verdictOf(command), 'DENY', command);
  assert.equal(verdictOf('curl -o /dev/null https://example.com'), PLAIN);
  assert.equal(verdictOf('cmd --output /dev/null'), verdictOf('cmd'));
  // the device itself is judged the way a redirection judges it, whichever way it is spelled
  for (const sink of ['/dev/null', '/dev/zero', '/dev/full', '/dev/stdout', '/dev/stderr', '/dev/stdin', '/dev/random', '/dev/urandom', '/dev/tty', '/dev/fd/0', '/dev/fd/1', '/dev/fd/2'])
    assert.equal(isDiscardDevice(sink), true, sink);
  for (const notSink of [
    '/dev/disk0', '/dev/rdisk1', '/dev/sda1', '/dev/nvme0n1', '/dev/mem', '/dev/kmem', '/dev/pts/3', '/dev/console', '/dev/ptmx',
    '/dev/fd/3', '/dev/fd/12', '/dev/null/x', '/dev/../etc/passwd', '/dev/tcp/example.com/80', '/dev/udp/example.com/53', '/dev', '/dev/', '/devnull', '/etc/passwd', 'dev/null',
  ])
    assert.equal(isDiscardDevice(notSink), false, notSink);
  // a raw block device is a destination in EVERY form: the redirection used to drop it with the other devices
  for (const command of [
    'echo x > /dev/disk0',
    'echo x > /dev/sda',
    'echo x >> /dev/rdisk2',
    'cp package.json /dev/disk0',
    'curl -o /dev/disk0 https://example.com',
    'dd if=/dev/zero of=/dev/disk0 count=1',
    'tee /dev/disk0 < package.json',
    'cat package.json > /dev/mem',
    'cat package.json > /dev/pts/3',
    'curl -o /dev/../etc/cron.d/x https://example.com',
    'echo x > /dev/../etc/cron.d/x',
  ])
    assert.equal(verdictOf(command), 'DENY', command);
  // ...and the discard devices stay what they were
  for (const command of ['echo x > /dev/null', 'cat /dev/null', 'ls | tee /dev/null', 'cp package.json /dev/null', 'sort -o /dev/null package.json', 'echo x > /dev/tty'])
    assert.equal(verdictOf(command), 'ALLOW', command);
  assert.equal(verdictOf('echo x > /dev/tcp/localhost/80'), 'ASK', 'a socket is judged by the network, not as a file');
  // ...and the one place under /dev where a file is ordinary stays ordinary now that the rest of /dev is not dropped
  for (const command of ['echo x > /dev/shm/x', 'cp package.json /dev/shm/x', 'mkdir -p /dev/shm/build'])
    assert.equal(verdictOf(command), 'ALLOW', command);
});

test('G. the resolver returns the lexical reading AND the physical one, bounded and without throwing', () => {
  const dir = workspace(FILES);
  const real = (p: string): string => join(dir, p);
  const c = pathCandidates(dir, 'd/../settings.json');
  assert.equal(c.dynamic, false);
  assert.ok(c.paths.some((p) => p === real('settings.json')), `the lexical reading is kept for the protected-NAME check: ${c.paths.join(' ')}`);
  assert.ok(c.paths.some((p) => p.endsWith('/.claude/settings.json')), `the physical reading is the parent of the link target: ${c.paths.join(' ')}`);
  // with no `..` the two readings are one
  assert.equal(pathCandidates(dir, 'src/a.ts').paths.length, 1);
  // the cwd is a set
  const two = pathCandidates([dir, join(dir, 'src')], 'x.ts').paths;
  assert.ok(two.includes(real('x.ts')) && two.includes(real('src/x.ts')));
  // every dynamic word says so, and has no path
  for (const w of ['$X/a', '`cmd`/a', '$(cmd)', '~-3/a', '~+2/a']) {
    const d = pathCandidates(dir, w);
    assert.equal(d.dynamic, true, w);
    assert.deepEqual(d.paths, [], w);
  }
  // a glob is read by its literal prefix
  assert.equal(pathCandidates(dir, 'src/*.ts').glob, true);
  // padding adds the trimmed reading, and nothing else
  assert.deepEqual(new Set(pathCandidates(dir, ' src/a.ts').paths), new Set([real(' src/a.ts'), real('src/a.ts')]));
  // a link loop and a long chain terminate, and the answer is a path
  const loops = workspace({ l1: link('l2'), l2: link('l1'), 'x/y': 'z' });
  assert.ok(pathCandidates(loops, 'l1/../x').paths.length >= 1);
  const farm: Record<string, string> = {};
  for (let i = 0; i < 60; i++) farm[`m${i}`] = link(`m${i + 1}`);
  const started = Date.now();
  assert.ok(pathCandidates(workspace(farm), 'm0/../x').paths.length >= 1);
  assert.ok(Date.now() - started < 3000, 'a chain of sixty links is bounded by the shared link budget');
  // a very deep `..` chain does not climb above the root
  assert.deepEqual(pathCandidates('/', '../../../../etc/x').paths, ['/etc/x']);
  // a path longer than the kernel opens (ENAMETOOLONG) is not walked: no stack overflow, no seconds spent asking the disk
  const longStarted = Date.now();
  const long = pathCandidates(dir, `${'a/'.repeat(30000)}z`);
  assert.ok(long.paths.length >= 1 && Date.now() - longStarted < 2000, `thirty thousand components took ${Date.now() - longStarted} ms`);
  const longVerdictStarted = Date.now();
  // (a path longer than the kernel opens writes nothing; it is refused, not allowed, and it is refused in bounded time)
  assert.equal(verdictOf(`echo x > ${'a/'.repeat(8000)}z`), 'DENY');
  assert.ok(Date.now() - longVerdictStarted < 15000, 'a redirection to a path of eight thousand components is decided in bounded time');
  assert.equal(pathCandidates(dir, '/proc/self/cwd/a').uncertain !== null, true);
  assert.equal(pathCandidates(dir, '/dev/fd/3').uncertain !== null, true);
  assert.equal(pathCandidates(dir, '/dev/fd/1').uncertain, null);
  assert.equal(pathCandidates(dir, '~nobody-such-user/a').uncertain !== null, true);
  // $HOME is the user's home, on both spellings, and only when it is the whole variable name
  // (the word AS TYPED is one more reading of it - a quoted `$HOME` is a directory of that name - and is not part of what the variable expands to)
  const expanded = (word: string): string[] => {
    const c = pathCandidates(dir, word);
    return c.paths.filter((p) => !c.typed.has(p));
  };
  const home = expanded('$HOME/a');
  assert.ok(home.includes(join(HOME, 'a')), home.join(' '));
  assert.deepEqual(expanded('${HOME}/a'), home);
  assert.equal(pathCandidates(dir, '$HOMEDIR/a').dynamic, true);
  // ...whereas a BRACE ends the name, so `${HOME}x` is the home directory followed by an `x`
  assert.deepEqual(expanded('${HOME}x/a'), [`${HOME}x/a`]);
  // an alias is recognised before a `..` is applied to it: `/proc/self/cwd/../x` is beside the working directory
  const beside = pathCandidates(dir, '/proc/self/cwd/../x');
  assert.notEqual(beside.uncertain, null);
  assert.ok(beside.paths.includes(join(dirname(dir), 'x')), beside.paths.join(' '));
  assert.ok(pathCandidates(dir, '/proc/self/root/../x').paths.includes('/x'));
});

test('G. whatever the word, the resolver returns absolute paths, in bounded time, and does not throw', () => {
  const dir = workspace(FILES);
  // a small deterministic generator (a linear congruential sequence), so a failure names a word that can be replayed
  let seed = 20261001;
  const next = (n: number): number => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed % n;
  };
  const pieces = ['d', 'e', 'chain', 'src', '..', '.', '', '~', '~-', '~+', '$HOME', '${HOME}', '$X', '`c`', '*', '?', '[a]', '{a,b}', ' ', '\t', '/', '//', 'proc', 'self', 'cwd', 'fd', '3', '/dev/null', 'a b', ' '];
  const started = Date.now();
  for (let i = 0; i < 3000; i++) {
    const parts: string[] = [];
    for (let k = 1 + next(7); k > 0; k--) parts.push(pieces[next(pieces.length)]!);
    const word = parts.join(next(3) === 0 ? '' : '/');
    const c = pathCandidates(next(2) === 0 ? dir : [dir, join(dir, 'src'), join(dir, 'd')], word, next(2) === 0 ? [dir] : undefined);
    for (const p of c.paths) assert.ok(p.startsWith('/'), `${JSON.stringify(word)} produced the relative path ${p}`);
    if (c.dynamic) assert.deepEqual(c.paths, [], JSON.stringify(word));
  }
  assert.ok(Date.now() - started < 20000, 'three thousand words are read in bounded time');
});

test('G. the physical reading is the file the kernel opens: a differential against open(2) over random paths through links and `..`', () => {
  // every directory holds a marker that says which directory it is, so the content read through a path names the place the
  // kernel resolved it to. The reading is checked against the kernel itself, not against what the author expects `..` to do.
  const dir = workspace({
    ...FILES,
    MARK: 'root',
    '.claude/MARK': 'claude',
    '.claude/sub/MARK': 'sub',
    'src/MARK': 'src',
    'src/deep/MARK': 'deep',
    'rel/MARK': 'rel',
  });
  let seed = 7;
  const next = (n: number): number => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed % n;
  };
  const parts = ['d', 'd', 'e', 'e', 'chain', 'rel', 'rel/up', 'src', 'deep', '..', '..', '..', '..', '.', '.claude', 'sub'];
  let compared = 0;
  let throughLinks = 0;
  for (let i = 0; i < 4000; i++) {
    const word = [...Array.from({ length: 1 + next(6) }, () => parts[next(parts.length)]!), 'MARK'].join('/');
    let truth: string;
    try {
      // string concatenation, not `join`: `join` would collapse the `..` before the kernel ever saw it
      truth = readFileSync(`${dir}/${word}`, 'utf8');
    } catch {
      continue; // the kernel cannot open it either (a missing component, a file where a directory should be)
    }
    compared++;
    const c = pathCandidates(dir, word);
    const reads = c.paths.map((p) => {
      try {
        return readFileSync(p, 'utf8');
      } catch {
        return null;
      }
    });
    assert.ok(reads.includes(truth), `${word}: the kernel opens the '${truth}' marker, the readings are ${c.paths.join(' | ')} -> ${JSON.stringify(reads)}`);
    if (/(^|\/)(d|e|chain|rel\/up)\/\.\./.test(word)) throughLinks++;
  }
  assert.ok(compared > 300 && throughLinks > 30, `the sample reached ${compared} openable paths, ${throughLinks} of them through a link and \`..\``);
});

test('G. the readers that are not judges: the file a command opens, the directory a -C leaves it in, the directories a cd may reach', () => {
  const dir = workspace(FILES);
  const real = realpathSync(dir);
  // the file whose bytes run: the PHYSICAL one, canonical
  assert.equal(openedPath(dir, 'd/../Makefile'), join(real, '.claude', 'Makefile'));
  assert.equal(openedPath(dir, 'src/../Makefile'), join(real, 'Makefile'));
  assert.equal(openedPath(dir, './src//a.ts'), join(real, 'src', 'a.ts'));
  assert.equal(openedPath(dir, '$X/Makefile'), null);
  assert.equal(openedPath(dir, '*.mk'), null);
  // a chdir(2): physical where a `..` follows a link, the text the caller compares otherwise
  assert.equal(chdirPath(dir, 'd/..'), join(real, '.claude'));
  assert.equal(chdirPath(dir, 'src'), join(dir, 'src'));
  assert.equal(chdirPath(dir, '..'), dirname(dir));
  assert.equal(chdirPath(dir, '$X'), null);
  // `cd d/..` goes two places unless it says -P: the logical one (the text) and the physical one (the link followed)
  assert.deepEqual(directoryCandidates(dir, 'd/..'), [real, join(real, '.claude')]);
  assert.deepEqual(directoryCandidates(dir, 'd/..', true), [join(real, '.claude')]);
  assert.deepEqual(directoryCandidates(dir, 'src'), [join(real, 'src')]);
  assert.equal(directoryCandidates(dir, 'nope*'), null);
  assert.equal(directoryCandidates(dir, '$X'), null);
  assert.equal(directoryCandidates(dir, '~-3'), null);
});

test('G. a physical walk costs filesystem calls, and ordinary work pays for none it does not need', () => {
  const dir = workspace(FILES);
  // sixty evaluations of a command that has no `..` and no link in it, and sixty of one that has both
  const started = Date.now();
  for (let i = 0; i < 60; i++) verdictOf('echo x > out.txt', dir);
  const plain = Date.now() - started;
  const startedDots = Date.now();
  for (let i = 0; i < 60; i++) verdictOf('echo x > e/../out.txt', dir);
  const dots = Date.now() - startedDots;
  // (a loose bound on purpose: it exists to catch a walk that repeats itself per site, not to time the machine)
  assert.ok(dots < Math.max(plain * 5, 10000), `a \`..\` word through a link costs ${dots} ms against ${plain} ms for a plain one`);
});

test('H. no site resolves a shell word on its own: the evaluator does not import `resolve`, and every candidate goes through authority/paths.ts', () => {
  const src = readFileSync(new URL('../src/authority/evaluate.ts', import.meta.url), 'utf8');
  const pathImport = /import \{([^}]*)\} from 'node:path';/.exec(src);
  assert.ok(pathImport, 'evaluate.ts imports from node:path');
  assert.ok(!/\bresolve\b/.test(pathImport![1]!), 'evaluate.ts must not import `resolve`: a lexical join of a cwd and a shell word is the defect this file closes');
  // ...and the lexical spellings of the same defect that do not need `resolve`. Where a line sits is decided by the function
  // it is in: these two read a path out of GIT'S OWN CONFIGURATION (a hooks directory, the file a value came from), which
  // is a value and not a word the shell expands
  const lines = src.split('\n');
  const enclosing = (i: number): string => {
    for (let k = i; k >= 0; k--) {
      const m = /^(?:export )?function (\w+)/.exec(lines[k]!);
      if (m) return m[1]!;
    }
    return '';
  };
  const CONFIGURATION_VALUES = new Set(['configuredHooksDirs', 'gitLocalProgramValues']);
  const offenders: string[] = [];
  lines.forEach((line, i) => {
    const code = line.replace(/\/\/.*$/, '');
    const hit =
      /\bpath\.resolve\(|\bresolvePath\(/.test(code) ||
      // join(<a directory the shell is in>, <a word>) is `resolve` by another name
      /\bjoin\((?:cwd|effectiveCwd|baseDir|dir|base|start|env\.cwd|state\.env\.cwd|ctx\.cwd)\s*,\s*(?:t|tok|word|raw|operand|target|file|f|w|v|value|arg)\b/.test(code) ||
      // the ternary every site used to carry
      /isAbsolute\((\w+)\)\s*\?\s*\1\s*:\s*(?:resolve|join)\(/.test(code);
    if (hit && !CONFIGURATION_VALUES.has(enclosing(i))) offenders.push(`${i + 1}: ${line.trim()}`);
  });
  assert.deepEqual(offenders, [], `a shell word is joined to a directory without the resolver:\n  ${offenders.join('\n  ')}`);
  // the resolver module is the one place that applies `..`
  const paths = readFileSync(new URL('../src/authority/paths.ts', import.meta.url), 'utf8');
  assert.match(paths, /export function pathCandidates\(/);
  assert.match(paths, /export function isDiscardDevice\(/);
});

test('H. canonicalPath, physicalPath and the tools surface use the same resolver as the shell', () => {
  const dir = workspace(FILES);
  // Write, Edit and the Bash redirection agree on `d/../settings.json`
  const tool = evaluate(table, ctx(dir), { tool: 'Write', input: { file_path: 'd/../settings.json', content: 'x' } });
  const bash = run('echo x > d/../settings.json', dir);
  assert.equal(tool.verdict, bash.verdict);
  assert.equal(tool.decisive?.capability, bash.decisive?.capability);
  // a trailing-space path through the tool and through the shell: refused by the same capability
  const t2 = evaluate(table, ctx(dir), { tool: 'Write', input: { file_path: ' /etc/cron.d/x', content: 'x' } });
  const b2 = run('echo x > " /etc/cron.d/x"', dir);
  assert.equal(t2.verdict, 'DENY');
  assert.equal(b2.verdict, 'DENY');
});

test('the workspace made by this file is unaffected by an earlier test (a fixture that is cached would hide a stale read)', () => {
  const root = mkdtempSync(join(tmpdir(), 'ego-paths-'));
  mkdirSync(join(root, '.git', 'hooks'), { recursive: true });
  writeFileSync(join(root, 'package.json'), '{}');
  mkdirSync(join(root, 'real'));
  const c = ctx(root);
  const first = evaluate(table, c, { tool: 'Bash', input: { command: 'echo x > lnk/../settings.json' } }).verdict;
  assert.equal(first, 'ALLOW');
  // the link appears BETWEEN two evaluations: the second must see it (the cache lives for one evaluation only)
  mkdirSync(join(root, '.claude', 'sub'), { recursive: true });
  symlinkSync('.claude/sub', join(root, 'lnk'));
  const second = evaluate(table, c, { tool: 'Bash', input: { command: 'echo x > lnk/../settings.json' } }).verdict;
  assert.equal(second, 'DENY');
});
