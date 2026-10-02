// CLOSURE AUDIT 2026-10-02, INTEGRATION - THE THREE REGRESSIONS THE FULL SUITE FOUND AFTER THE FOUR WAVES WERE MERGED.
//
// Each wave was green on its own branch. The corpus crosses every semantic class with every PRODUCER (a git hook, a lint-staged
// configuration, a make command-line override), and three of those pairs fell under the floor of the class they carry once the
// waves met. In a plain command line the same bodies were right; what differed was the ROUTE a body takes to the readers.
//
//   A. a producer's body that runs, again, the very command that fired the producer (`git commit` -> pre-commit hook -> `env
//      EDITOR=… git commit`) was never judged for the environment it hands the command. The cycle guard identifies an invocation by
//      the producer it resolves to - for a hook, `hooks directory + verb` - so the nested command was "the same execution" as the
//      one running its body and was cut off before the environment was consulted; `env 'EDITOR=/tmp/x' git commit` was ASK on the
//      command line and ALLOW in the hook, in lint-staged, and in anything else that re-enters its own producer. The environment
//      a pass runs in is part of what it IS (make's key has always carried it); it is now part of every producer's - every process
//      input the pass inherits, because what the rest of the body reads is not only the names that select a program (a hook that
//      runs `make run` and then `CMD='git push origin main' git commit` fires itself again with a CMD its recipe expands).
//
//   B. the command a make override carries is read as the words it holds, not as make's own option parser would read them: the
//      guard against `-E`/`--eval` scanned the NORMALISED words, in which `V="gawk -Eevil.awk d.txt"` is five words and one of them
//      is spelled like make's `-E`. The command line was called "supplied on stdin or on the command line", the makefile
//      "unreadable", and the override - which holds the command that reads `evil.awk` - never reached the readers of the command it
//      holds. There is ONE reader of make's command line (parseMakeCommandLine); it reads the words make is handed.
//
// The verdicts below are what a reader must give. `ASK` is "something selects a program that nobody read"; `DENY` is "the act was
// READ and refused"; `ALLOW` is a control that must stay as it was.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PRODUCERS, RANK, SEMANTIC_CLASSES, verdict, workspace } from './support/corpus.ts';

const v = (command: string, files: Record<string, string> = {}): string => verdict(command, workspace(files));
/** the verdict is at least `floor`: a stricter layer may refuse what a lower one only asks about */
const atLeast = (got: string, floor: 'ASK' | 'DENY'): boolean => RANK[got]! >= RANK[floor]!;

/* ------------------------------------------------------------------------------------------------------------- *
 * A. A PRODUCER'S BODY THAT RUNS ITS OWN PRODUCER AGAIN IS A SECOND PASS IN ANOTHER ENVIRONMENT, NOT A REPEAT
 * ------------------------------------------------------------------------------------------------------------- */

/** a hook that fires on `invocation`, and the nested command (the verb and operands the hook runs again) that re-enters it */
const HOOKS: Array<{ hook: string; invocation: string; nested: string }> = [
  { hook: 'pre-commit', invocation: 'git commit -m x', nested: 'git commit --allow-empty' },
  { hook: 'post-commit', invocation: 'git commit -m x', nested: 'git commit --allow-empty' },
  { hook: 'commit-msg', invocation: 'git commit -m x', nested: 'git commit --allow-empty' },
  { hook: 'post-checkout', invocation: 'git checkout main', nested: 'git checkout main' },
  { hook: 'post-merge', invocation: 'git merge main', nested: 'git merge main' },
  { hook: 'post-index-change', invocation: 'git status', nested: 'git status' },
];

/** how a body hands a program-selecting variable to the git command it runs: the quoting, the carrier, the position */
const INJECTING: Array<(nested: string) => string> = [
  (n) => `env 'EDITOR=/tmp/x' ${n}`,
  (n) => `env "VISUAL=/tmp/x" ${n}`,
  (n) => `env EDITOR=/tmp/x ${n}`,
  (n) => `EDITOR=/tmp/x ${n}`,
  (n) => `env -i 'PAGER=/tmp/x' ${n}`,
  (n) => `export 'EDITOR=/tmp/x'; ${n}`,
  (n) => `timeout 60 env EDITOR=/tmp/x ${n}`,
  (n) => `find . -exec env EDITOR=/tmp/x ${n} \\;`,
];

/** the same nested command with an environment that selects NO program (or one the rules accept): it must stay what it was */
const INERT: Array<(nested: string) => string> = [
  (n) => n,
  (n) => `env FOO=bar ${n}`,
  (n) => `env 'FOO=bar' ${n}`,
  (n) => `GIT_EDITOR=true ${n}`,
  (n) => `env --unset=CI ${n}`,
  (n) => `GIT_PAGER=cat ${n}`,
];

const hookFiles = (hook: string, body: string): Record<string, string> => ({ [`.git/hooks/${hook}`]: `#!/bin/sh\n${body}\n` });

test('A: a command on the command line that gives git a program to run is ASK, in every spelling the corpus knows', () => {
  const wrong: string[] = [];
  for (const { nested } of HOOKS)
    for (const spell of INJECTING) {
      const c = spell(nested);
      const got = v(c);
      if (!atLeast(got, 'ASK')) wrong.push(`${c} -> ${got}`);
    }
  assert.deepEqual(wrong, []);
});

test('A: the same command as the body of a git hook that fires on it is judged for the environment it gives the command', () => {
  const wrong: string[] = [];
  for (const { hook, invocation, nested } of HOOKS)
    for (const spell of INJECTING) {
      const body = spell(nested);
      const got = v(invocation, hookFiles(hook, body));
      if (!atLeast(got, 'ASK')) wrong.push(`${hook}: ${body} -> ${got}`);
    }
  assert.deepEqual(wrong, []);
});

test('A: the same command as a lint-staged task, run by the pre-commit hook of the commit it is part of', () => {
  const hook = '#!/bin/sh\nnpx lint-staged\n';
  const configs: Array<[label: string, task: string, files: (task: string) => Record<string, string>]> = [
    ['package.json, a list', 'task', (t) => ({ 'package.json': JSON.stringify({ 'lint-staged': { '*.ts': [t] } }) })],
    ['package.json, a string', 'task', (t) => ({ 'package.json': JSON.stringify({ 'lint-staged': { '*.ts': t } }) })],
    ['.lintstagedrc.json', 'task', (t) => ({ '.lintstagedrc.json': JSON.stringify({ '*.ts': [t] }) })],
    ['.lintstagedrc.json, a task after a safe one', 'task', (t) => ({ '.lintstagedrc.json': JSON.stringify({ '*.ts': ['prettier --check', t] }) })],
  ];
  const wrong: string[] = [];
  for (const [label, , files] of configs)
    for (const spell of INJECTING) {
      const body = spell('git commit --allow-empty');
      const got = v('git commit -m x', { ...files(body), '.git/hooks/pre-commit': hook });
      if (!atLeast(got, 'ASK')) wrong.push(`${label}: ${body} -> ${got}`);
    }
  assert.deepEqual(wrong, []);
});

test('A: the producers the corpus builds carry the class of an assignment in quotes handed to env or export', () => {
  const cls = SEMANTIC_CLASSES.find((c) => c.id === 'an assignment word in quotes handed to env or export')!;
  assert.ok(cls, 'the class is in the corpus');
  const wrong: string[] = [];
  for (const spelling of cls.cases)
    for (const name of ['git pre-commit hook', 'lint-staged config', 'git post-checkout hook', 'lint-staged config below the working directory']) {
      const p = PRODUCERS.find((x) => x.name === name)!;
      assert.ok(p, `the producer "${name}" is in the corpus`);
      if (p.safe && !p.safe(spelling)) continue;
      const [files, invoke] = p.build(spelling);
      // (the post-checkout hook fires on a checkout and the class's spellings run `git commit`: a different verb, so that producer reaches
      // the body by the ordinary route and must meet the floor as well - it is the control that the other three are not special)
      const got = verdict(invoke, workspace({ ...cls.files, ...files }));
      if (!atLeast(got, cls.floor as 'ASK')) wrong.push(`${name}: ${spelling} -> ${got}`);
    }
  assert.deepEqual(wrong, []);
});

test('A: a program-selecting variable is judged for what it selects, in the hook as on the command line', () => {
  // the variable that selects the program is not only an editor: a path, a git configuration, an ssh command
  const wrong: string[] = [];
  for (const assignment of ['PATH=/tmp/bin', 'GIT_SSH_COMMAND=/tmp/x', 'GIT_CONFIG_COUNT=1', 'GIT_EXTERNAL_DIFF=/tmp/x', 'LD_PRELOAD=/tmp/x.so']) {
    const body = `env ${assignment} git commit --allow-empty`;
    const plain = v(body);
    const inHook = v('git commit -m x', hookFiles('pre-commit', body));
    if (!atLeast(plain, 'ASK')) wrong.push(`plain: ${body} -> ${plain}`);
    if (!atLeast(inHook, 'ASK')) wrong.push(`pre-commit: ${body} -> ${inHook}`);
  }
  assert.deepEqual(wrong, []);
});

test('A: the environment a hook hands the command that fires it again is read by the rest of the hook, not only by the names that select a program', () => {
  // the hook runs `make run` and then runs the commit again with a CMD its recipe expands: the second pass of the hook is a different hook
  // from the first, although nothing in the environment names a program. On the command line the same CMD is DENY (the recipe is read).
  const makefile = 'CMD ?= echo ok\nrun:\n\t$(CMD)\n';
  const ACT = 'git push origin main';
  const spellings = [
    (c: string) => `CMD='${c}' git commit --allow-empty`,
    (c: string) => `env CMD='${c}' git commit --allow-empty`,
    (c: string) => `env 'CMD=${c}' git commit --allow-empty`,
    (c: string) => `env "CMD=${c}" git commit --allow-empty`,
    (c: string) => `env -i 'CMD=${c}' git commit --allow-empty`,
    (c: string) => `timeout 60 env CMD='${c}' git commit --allow-empty`,
  ];
  const wrong: string[] = [];
  for (const spell of spellings) {
    const body = spell(ACT);
    const orders = [`make run\n${body}`, `${body}\nmake run`];
    for (const hook of orders) {
      const files = { Makefile: makefile, '.git/hooks/pre-commit': `#!/bin/sh\n${hook}\n` };
      const got = v('git commit -m x', files);
      if (got !== 'DENY') wrong.push(`${hook.replace(/\n/g, ' ; ')} -> ${got}`);
    }
    // the same variable on the command that fires the hook, with a hook that only runs make: the pass the nested form re-enters
    const onTheLine = v(spell(ACT).replace('--allow-empty', '-m x'), { Makefile: makefile, '.git/hooks/pre-commit': '#!/bin/sh\nmake run\n' });
    if (onTheLine !== 'DENY') wrong.push(`on the command line: ${spell(ACT)} -> ${onTheLine}`);
  }
  // controls: a CMD that runs nothing gated, and no re-entry at all
  for (const spell of spellings) {
    const body = spell('echo hi');
    const got = v('git commit -m x', { Makefile: makefile, '.git/hooks/pre-commit': `#!/bin/sh\nmake run\n${body}\n` });
    if (got !== 'ALLOW') wrong.push(`control: ${body} -> ${got}`);
  }
  assert.equal(v('git commit -m x', { Makefile: makefile, '.git/hooks/pre-commit': '#!/bin/sh\nmake run\n' }), 'ALLOW');
  assert.deepEqual(wrong, []);
});

test('A, control: a nested command whose environment selects no program is what it was, in a hook and in lint-staged', () => {
  const wrong: string[] = [];
  for (const { hook, invocation, nested } of HOOKS)
    for (const spell of INERT) {
      const body = spell(nested);
      // the hook that runs the command with no environment at all is ALLOW, and an environment that selects no program adds nothing to it
      const got = v(invocation, hookFiles(hook, body));
      if (got !== 'ALLOW') wrong.push(`${hook}: ${body} -> ${got}`);
    }
  // (lint-staged is two producers deep - the hook, then its configuration - so a task that gives the commit ANY assignment is a second
  // pass whose chain is longer than the analysis goes, and it asks; the tasks without an assignment are the control that nothing else changed)
  for (const spell of INERT.filter((s) => !/=/.test(s('x')))) {
    const body = spell('git commit --allow-empty');
    const got = v('git commit -m x', {
      'package.json': JSON.stringify({ 'lint-staged': { '*.ts': [body] } }),
      '.git/hooks/pre-commit': '#!/bin/sh\nnpx lint-staged\n',
    });
    if (got !== 'ALLOW') wrong.push(`lint-staged: ${body} -> ${got}`);
  }
  assert.deepEqual(wrong, []);
});

test('A, control: the nested command with no environment at all is ALLOW, and a different verb is not the same execution', () => {
  assert.equal(v('git commit -m x', hookFiles('pre-commit', 'git commit --allow-empty')), 'ALLOW');
  assert.equal(v('git commit -m x', hookFiles('pre-commit', 'git status')), 'ALLOW');
  // a hook that sets the variable for a DIFFERENT verb was always judged (its key is its own); that must not have changed
  assert.ok(atLeast(v('git commit -m x', hookFiles('pre-commit', 'env EDITOR=/tmp/x git log')), 'ASK'));
  assert.ok(atLeast(v('git commit -m x', hookFiles('pre-commit', 'env EDITOR=/tmp/x git merge main')), 'ASK'));
});

test('A: the recursion still ends - a hook that runs itself again in the same environment is read once, quickly', () => {
  const t0 = performance.now();
  const got = v('git commit -m x', hookFiles('pre-commit', "env 'EDITOR=/tmp/x' git commit --allow-empty\nenv 'EDITOR=/tmp/x' git commit --allow-empty\nEDITOR=/tmp/x git commit --allow-empty"));
  assert.ok(atLeast(got, 'ASK'));
  assert.ok(performance.now() - t0 < 5000, 'a repeated nested command was analysed again and again');
});

test('A: a hook that re-enters itself in many different environments is answered at the bound, with a question and in time', () => {
  // each distinct environment is another pass, and the passes of one path multiply: the work bound (work-bound.ts) is what ends them. The
  // answer is an ASK - never ALLOW, because a bound that was reached is not an absence of risk - and it arrives in a fraction of the host's 30 s
  const names = ['EDITOR', 'VISUAL', 'PAGER', 'DIFFPROG', 'MERGE', 'BROWSER', 'TERMINAL', 'MANPAGER'];
  for (const n of [3, 6, 8]) {
    const body = names
      .slice(0, n)
      .map((k) => `env ${k}=/tmp/x git commit --allow-empty`)
      .join('\n');
    const t0 = performance.now();
    const got = v('git commit -m x', hookFiles('pre-commit', body));
    const ms = performance.now() - t0;
    assert.ok(atLeast(got, 'ASK'), `${n} environments: ${got}`);
    assert.ok(ms < 10_000, `${n} environments took ${Math.round(ms)} ms`);
  }
});

/* ------------------------------------------------------------------------------------------------------------- *
 * B. A MAKE OVERRIDE'S VALUE IS THE COMMAND IT HOLDS, NOT AN OPTION OF MAKE
 * ------------------------------------------------------------------------------------------------------------- */

/** awk reads a program FILE from every one of these (getopt's: the value is the rest of the word, or the next word); the file runs a gated command */
const AWK_FILE_SPELLINGS = [
  'gawk -Eevil.awk d.txt',
  'gawk -E evil.awk d.txt',
  'gawk -nEevil.awk d.txt',
  'gawk -ievil.awk d.txt',
  'gawk -i evil.awk d.txt',
  'gawk --exec=evil.awk d.txt',
  'gawk --exec evil.awk d.txt',
  'gawk --include=evil.awk d.txt',
  'gawk -fevil.awk d.txt',
  'gawk -nfevil.awk d.txt',
  'awk -fevil.awk d.txt',
];
const AWK_FILES: Record<string, string> = { 'evil.awk': 'BEGIN{system("git push origin main")}', 'd.txt': 'x\n' };
const MAKEFILE = 'V := echo ok\nrun:\n\t$(V)\n';

test('B: the awk program file is read from every spelling of its option on a plain command line', () => {
  const wrong: string[] = [];
  for (const c of AWK_FILE_SPELLINGS) {
    const got = v(c, AWK_FILES);
    if (got !== 'DENY') wrong.push(`${c} -> ${got}`);
  }
  assert.deepEqual(wrong, []);
});

test('B: the same command as the value of a make override on the command line is read the same way', () => {
  const wrong: string[] = [];
  const files = { ...AWK_FILES, Makefile: MAKEFILE };
  for (const c of AWK_FILE_SPELLINGS) {
    for (const make of [
      `make V="${c}" run`,
      `make V='${c}' run`,
      `make "V=${c}" run`,
      `make run V="${c}"`,
      `make -s V="${c}" run`,
      `make -k V="${c}" run`,
      `make -j1 V="${c}" run`,
      `CC=cc make V="${c}" run`,
    ]) {
      const got = v(make, files);
      if (got !== 'DENY') wrong.push(`${make} -> ${got}`);
    }
  }
  assert.deepEqual(wrong, []);
});

test('B: the corpus producer "make command-line override" carries every spelling of the awk class', () => {
  const cls = SEMANTIC_CLASSES.find((c) => c.id === 'an awk program, include or library handed over by a glued or clustered option')!;
  assert.ok(cls, 'the class is in the corpus');
  const p = PRODUCERS.find((x) => x.name === 'make command-line override')!;
  const wrong: string[] = [];
  for (const spelling of cls.cases) {
    if (p.safe && !p.safe(spelling)) continue;
    const [files, invoke] = p.build(spelling);
    const got = verdict(invoke, workspace({ ...cls.files, ...files }));
    if (got !== 'DENY') wrong.push(`${spelling} -> ${got} (${invoke})`);
  }
  assert.deepEqual(wrong, []);
});

test('B: a word in an override value that is spelled like an option of MAKE is still only a word of the command it holds', () => {
  // the values are ordinary commands whose options happen to be make's letters: -E, -f, -C, -n, -e, -I, -o, -W
  const files = { Makefile: MAKEFILE, 'd.txt': 'x\n', 'a.mk': 'x:\n\techo ok\n' };
  const ordinary = ['grep -E foo d.txt', 'sed -E s/a/b/ d.txt', 'grep -Efoo d.txt', 'cat -n d.txt', 'ls -C', 'sort -o out.txt d.txt', 'diff -I x d.txt d.txt'];
  const wrong: string[] = [];
  for (const c of ordinary) {
    // the override is what it holds: an ordinary command is as ordinary there as it is alone, and none of them is gated by a word's
    // resemblance to an option of make
    const alone = v(c, files);
    const carried = v(`make V="${c}" run`, files);
    if (alone !== 'ALLOW') wrong.push(`${c} alone -> ${alone}: the control is not ordinary`);
    if (carried !== 'ALLOW') wrong.push(`make V="${c}" run -> ${carried}`);
  }
  assert.deepEqual(wrong, []);
});

test('B, control: make\'s own -E / --eval still hands the makefile over on the command line, in every spelling make reads', () => {
  const files = { Makefile: MAKEFILE };
  const injected = [
    "make -E 'run: ; git push origin main' run",
    "make -Erun: run",
    "make -kE 'run:' run",
    "make --eval='run: ; git push origin main' run",
    "make --eval 'run:' run",
    "make --ev='run:' run",
    "make -E 'x:' V=\"grep -E foo d.txt\" run",
    "make V=\"gawk -Eevil.awk d.txt\" -E 'x:' run",
    "make V=\"gawk -Eevil.awk d.txt\" --eval='x:' run",
    // ...behind the carriers, where the words make is handed are read from the command the carrier holds
    "bash -c \"make -E 'x:' run\"",
    "sudo make -E 'x:' run",
    'env -S "make -E x: run"',
    'nice make -Ex: run',
    'timeout 5 make -kE x: run',
    "find . -exec make -E 'x:' \\;",
  ];
  const wrong: string[] = [];
  for (const c of injected) {
    const got = v(c, { ...files, ...AWK_FILES });
    if (!atLeast(got, 'ASK')) wrong.push(`${c} -> ${got}`);
  }
  assert.deepEqual(wrong, []);
});

test('B, control: after the goals nothing is an option - `make run -- -Efoo` names a target', () => {
  // `--` ends make's options; what follows is a goal, however it is spelled. It is not injected text, and the goal has no rule
  const got = v('make run -- -Efoo', { Makefile: MAKEFILE });
  assert.notEqual(got, 'DENY');
});
