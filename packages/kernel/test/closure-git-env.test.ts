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
import { evaluate, type Evaluation } from '../src/authority/evaluate.ts';
import { WORK_LIMIT, overrideWorkLimit, workSpent } from '../src/authority/work-bound.ts';
import { ORDINARY, SEMANTIC_CLASSES, ctx, table, workspace } from './support/corpus.ts';

const run = (command: string, dir: string): Evaluation => evaluate(table, ctx(dir), { tool: 'Bash', input: { command } });
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
