// CLOSURE EVIDENCE (independent audit of 2026-10-01, receipt findings 17 and 18).
//
// The Phase-1 closure gate re-ran every pin against the current tree and found two classes whose protection was
// real but whose EVIDENCE was not: a fix could be reverted with the suite still green. This file is the evidence.
//   - finding 18: the secret detectors. 27 of the 91 block-severity detectors were never the reporting detector in
//     any test, so a deleted or shadowed one cost nothing. The catalogue is now loaded, and every detector must
//     report its own fixture (support/secret-fixtures.ts).
//   - finding 17: the backslash-newline class. It was pinned by one assertion that a SECOND erasure also satisfied.
//     The splitter and the redirection scanner each get a direct test, and the readers of script text - which had
//     replaced the pair with a space instead of deleting it - are held to the shell's own rule.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadControlPlane } from '../src/control-plane/load.ts';
import { redact, allDetectors } from '../src/redaction/redact.ts';
import { redactCurl } from '../src/redaction/curl.ts';
import { evaluate, redirectionTargets, splitShellPipeline } from '../src/authority/evaluate.ts';
import { FIXTURES } from './support/secret-fixtures.ts';
import { ctx, table, workspace } from './support/corpus.ts';

const ROOT = new URL('../../../control-plane/', import.meta.url).pathname;
const detectors = allDetectors(loadControlPlane(ROOT).secrets);

/* ------------------------------------------------------------------------------------------------------------- *
 * FINDING 18: THE SECRET CATALOGUE
 * ------------------------------------------------------------------------------------------------------------- */

test('secret catalogue: every detector has a fixture, every fixture has a detector, and the count is exact', () => {
  const ids = detectors.map((d) => d.id);
  assert.equal(new Set(ids).size, ids.length, 'detector ids must be unique');
  assert.deepEqual(
    ids.filter((id) => !(id in FIXTURES)),
    [],
    'these detectors have no fixture in support/secret-fixtures.ts: a detector nothing exercises can be emptied or deleted unnoticed',
  );
  assert.deepEqual(
    Object.keys(FIXTURES).filter((id) => !ids.includes(id)),
    [],
    'these fixtures name a detector that is no longer in control-plane/secrets: a deleted detector must take its fixture with it, deliberately',
  );
  // The exact numbers, not a floor: a floor of 90 let one block detector vanish. Changing either number is a decision
  // that belongs in the same commit as the detector it counts.
  assert.equal(detectors.filter((d) => d.severity === 'block').length, 91, 'block-severity detectors');
  assert.equal(detectors.filter((d) => d.severity === 'warn').length, 6, 'warn-severity detectors');
});

test('secret catalogue: every detector is THE detector that reports its own fixture, and the secret is gone', () => {
  const problems: string[] = [];
  for (const d of detectors) {
    const f = FIXTURES[d.id];
    if (!f) continue; // reported by the test above
    const opts = { isFile: f.isFile ?? false };
    // in the full, ordered set: the way every real caller runs it. A detector an earlier one always pre-empts cannot
    // be the reporter here, which is the defect (ai.anthropic, forge.github.app-token and
    // forge.github.fine-grained-pat were each swallowed by a broader detector that ran first).
    const full = redact(f.input, detectors, opts);
    const own = full.findings.find((x) => x.detector === d.id);
    if (!own) problems.push(`${d.id}: not the reporting detector for its fixture (reported: ${full.findings.map((x) => x.detector).join(', ') || 'nothing'})`);
    else if (own.severity !== d.severity) problems.push(`${d.id}: reported at ${own.severity}, catalogued at ${d.severity}`);
    if (d.severity === 'block' && !full.blocked) problems.push(`${d.id}: its fixture was not blocked`);
    if (full.text.includes(f.secret)) problems.push(`${d.id}: the secret survives in the redacted text`);
    if (JSON.stringify(full.findings).includes(f.secret)) problems.push(`${d.id}: the secret appears in a finding`);
    // and by ITSELF: the detector's own pattern must find and remove the secret, not lean on a neighbour
    const alone = redact(f.input, [d], opts);
    if (!alone.findings.some((x) => x.detector === d.id)) problems.push(`${d.id}: does not match its own fixture`);
    if (alone.text.includes(f.secret)) problems.push(`${d.id}: on its own it leaves the secret in the text`);
  }
  assert.deepEqual(problems, []);
});

test('secret catalogue: a block-severity token is blocked in an assignment, not demoted by the generic warn rules', () => {
  // The generic `NAME_TOKEN=value` and `.env` line rules are warn-level and ran FIRST, so they redacted the value out
  // from under the specific detector: `export GITHUB_TOKEN=ghp_…` and `STRIPE_SECRET_KEY=sk_live_…` in a file were
  // only a warning, and the pre-commit and pre-push scans (which refuse on `blocked`) let the commit through. The
  // class is "which detector reports a span is decided by file order", so it is held for EVERY distinctive-prefix
  // detector at once, not for the two spellings that were noticed.
  const problems: string[] = [];
  let checked = 0;
  for (const d of detectors) {
    const f = FIXTURES[d.id];
    if (!f || d.severity !== 'block' || f.input !== f.secret || /\s/.test(f.input)) continue;
    const bad: string[] = [];
    for (const [shape, isFile] of [
      ['export DEPLOY_TOKEN=<secret>', false],
      ['PAYMENTS_API_KEY="<secret>"', false],
      ['FOO=<secret>', true],
      ["    SERVICE_SECRET = '<secret>'", true],
    ] as const) {
      checked++;
      const r = redact(shape.replace('<secret>', f.input) + '\n', detectors, { isFile });
      if (!r.findings.some((x) => x.detector === d.id) || !r.blocked || r.text.includes(f.secret)) bad.push(shape);
    }
    if (bad.length) problems.push(`${d.id}: not blocked, or leaking, in ${bad.length} of 4 assignment shapes, e.g. ${bad[0]}`);
  }
  assert.ok(checked > 200, `the class check must run over the catalogue, ran ${checked}`);
  assert.deepEqual(problems, []);
});

test('secret catalogue: a redaction label is not a secret, so the specific label survives a generic rule', () => {
  const token = FIXTURES['forge.github.pat']!.input;
  const r = redact(`export GITHUB_TOKEN=${token}`, detectors);
  assert.equal(r.text, 'export GITHUB_TOKEN=[REDACTED:github-token]');
  assert.deepEqual(r.findings.map((f) => f.detector), ['forge.github.pat'], 'one span, one report');
  // a value that merely LOOKS like a label is still redacted when it is more than the label
  const mixed = redact('DEPLOY_TOKEN=[REDACTED:x]-and-more-of-a-real-secret', detectors);
  assert.ok(!mixed.text.includes('and-more-of-a-real-secret'));
});

test('secret catalogue: the fixtures and this file carry no literal that the repository scans would refuse', () => {
  // The repository's own pre-commit and pre-push scans run these detectors over the files committed here. Fixtures
  // are assembled from pieces precisely so that a committed fixture is not itself a refusal.
  for (const file of ['support/secret-fixtures.ts', 'closure-evidence.test.ts']) {
    const text = readFileSync(new URL(file, import.meta.url), 'utf8');
    const r = redact(text, detectors, { isFile: true });
    assert.deepEqual(
      r.findings.filter((f) => f.severity === 'block').map((f) => f.detector),
      [],
      `${file} contains a literal that matches a block-severity detector`,
    );
  }
});

/* ------------------------------------------------------------------------------------------------------------- *
 * FINDING 17: THE BACKSLASH-NEWLINE CLASS
 *
 * The shell deletes `\<newline>` before it parses anything, in the middle of a word as well as between two. Every
 * reader that classifies shell text has to delete it the same way. Each of the three tests below fails on the
 * revert of ONE reader and passes on the revert of the others, which is what makes a revert visible.
 * ------------------------------------------------------------------------------------------------------------- */

const stageTexts = (command: string): string[] => splitShellPipeline(command).map((s) => s.text);

test('backslash-newline, the splitter by itself: the pair is deleted before tokenization, mid-word, never replaced by a space', () => {
  // between two words
  assert.deepEqual(stageTexts('echo x > \\\n/etc/cron.d/evil'), ['echo x > /etc/cron.d/evil']);
  // INSIDE a word: a space here would turn `.gi t/hooks/pre-commit` into the target `.gi`
  assert.deepEqual(stageTexts('echo x > .gi\\\nt/hooks/pre-commit'), ['echo x > .git/hooks/pre-commit']);
  assert.deepEqual(stageTexts('echo x > .g\\\n\\\nit/hooks/pre-commit'), ['echo x > .git/hooks/pre-commit']);
  // in the HEAD of a command: `do` is a shell keyword, `docker` is not
  assert.deepEqual(stageTexts('do\\\ncker run alpine'), ['docker run alpine']);
  assert.deepEqual(stageTexts('git pu\\\nsh origin main'), ['git push origin main']);
  // an operator can be split in two: `>\<nl>>` is `>>`
  assert.deepEqual(stageTexts('echo x >\\\n> f'), ['echo x >> f']);
  // the pair does not start a new stage
  assert.equal(splitShellPipeline('echo a \\\n  && echo b').length, 2);
  // double quotes do not stop the deletion; single quotes keep the pair literal
  assert.deepEqual(stageTexts('echo "a\\\nb"'), ['echo "ab"']);
  assert.deepEqual(stageTexts("echo 'a\\\nb'"), ["echo 'a\\\nb'"]);
  // an EVEN number of backslashes is an escaped backslash and then a plain newline: that is NOT a continuation
  assert.deepEqual(stageTexts('echo a \\\\\ngit push origin main'), ['echo a \\\\', 'git push origin main']);
  // a COMMENT is ended by the newline whatever it ends with
  assert.deepEqual(stageTexts('echo hi # note \\\ngit push origin main'), ['echo hi', 'git push origin main']);
});

test('backslash-newline, the redirection scanner by itself: a target split by a continuation is the file the shell opens', () => {
  // called WITHOUT the splitter, so a revert of this reader alone is visible even though the splitter still deletes
  assert.deepEqual(redirectionTargets('echo x > \\\n/etc/cron.d/evil'), ['/etc/cron.d/evil']);
  // mid-word is what tells a deletion from a replacement by a space (`.gi`)
  assert.deepEqual(redirectionTargets('echo x > .gi\\\nt/hooks/pre-commit'), ['.git/hooks/pre-commit']);
  assert.deepEqual(redirectionTargets('echo x >> .harn\\\ness/runtime/pin.json'), ['.harness/runtime/pin.json']);
  assert.deepEqual(redirectionTargets('echo x &> control-pla\\\nne/permissions/x.md'), ['control-plane/permissions/x.md']);
  assert.deepEqual(redirectionTargets('echo x 3>| .g\\\n\\\nit/hooks/pre-commit'), ['.git/hooks/pre-commit']);
  // the operator itself may be split
  assert.deepEqual(redirectionTargets('echo x >\\\n> .git/hooks/pre-commit'), ['.git/hooks/pre-commit']);
  // the scanner stays quote-aware: a continuation inside a quoted argument writes nothing
  assert.deepEqual(redirectionTargets('echo "why > .git/hooks\\\n/x"'), []);
  assert.deepEqual(redirectionTargets('echo hello \\\n world'), []);
});

test('backslash-newline, end to end: the verdict is the one the joined line gets, whichever reader sees the pair', () => {
  const dir = workspace();
  const at = (command: string) => evaluate(table, ctx(dir), { tool: 'Bash', input: { command } });
  assert.equal(at('echo x > \\\n/etc/cron.d/evil').decisive?.capability, 'fs.outside-workspace.write');
  assert.equal(at('echo x > .gi\\\nt/hooks/pre-commit').decisive?.capability, 'fs.hook-config.write');
  assert.equal(at('echo x > .harn\\\ness/runtime/pin.json').verdict, 'DENY');
  assert.equal(at('echo x > control-pla\\\nne/permissions/x.md').verdict, 'DENY');
});

/** a script and a line typed directly are the same text to the shell, so they must get the same verdict */
const scriptVerdict = (line: string, how: string) => {
  const dir = workspace({ 'run.sh': `#!/bin/sh\n${line}\n` });
  return evaluate(table, ctx(dir), { tool: 'Bash', input: { command: how } });
};
const directVerdict = (line: string) => {
  const dir = workspace();
  return evaluate(table, ctx(dir), { tool: 'Bash', input: { command: line } });
};

test('backslash-newline in a SCRIPT FILE is deleted as the shell deletes it: a continued write target is the protected path', () => {
  // [continued line as written in the file, the same line as the shell reads it]
  const CONTINUED: Array<[string, string]> = [
    ['echo x > .gi\\\nt/hooks/pre-commit', 'echo x > .git/hooks/pre-commit'],
    ['echo x > .harn\\\ness/runtime/pin.json', 'echo x > .harness/runtime/pin.json'],
    ['echo x > control-pla\\\nne/permissions/x.md', 'echo x > control-plane/permissions/x.md'],
    ['echo x | tee .gi\\\nt/hooks/pre-commit', 'echo x | tee .git/hooks/pre-commit'],
    ['echo x > /etc/cr\\\non.d/evil', 'echo x > /etc/cron.d/evil'],
    ['git pu\\\nsh origin main', 'git push origin main'],
    ['echo x > .g\\\n\\\nit/hooks/pre-commit', 'echo x > .git/hooks/pre-commit'],
  ];
  for (const [continued, joined] of CONTINUED) {
    const direct = directVerdict(joined);
    assert.equal(direct.verdict, 'DENY', `the joined line is an absolute refusal: ${joined}`);
    for (const how of ['./run.sh', 'sh run.sh', 'bash run.sh']) {
      const r = scriptVerdict(continued, how);
      assert.equal(r.verdict, direct.verdict, `${how} with ${JSON.stringify(continued)}`);
      assert.equal(r.decisive?.capability, direct.decisive?.capability, `${how} with ${JSON.stringify(continued)}`);
    }
  }
});

test('a script file reads a continuation exactly where the shell does: not after an even run of backslashes, a comment or a CR', () => {
  // All four shells on this machine (sh, bash, dash, zsh) run the SECOND line in each of these; a reader that joins it
  // to the first hides a `git push` at ALLOW.
  for (const line of [
    'echo hi \\\\\ngit push origin main', // `\\` is an escaped backslash, then the newline ends the command
    'echo hi # note \\\ngit push origin main', // a comment ends at the newline, a backslash in it joins nothing
    'echo hi \\\r\ngit push origin main', // `\` + CR escapes the CR; the LF that follows is an ordinary newline
  ]) {
    const direct = directVerdict(line);
    assert.equal(direct.decisive?.capability, 'git.remote.push', JSON.stringify(line));
    for (const how of ['./run.sh', 'sh run.sh']) {
      const r = scriptVerdict(line, how);
      assert.equal(r.verdict, 'DENY', `${how} with ${JSON.stringify(line)}`);
      assert.equal(r.decisive?.capability, 'git.remote.push', `${how} with ${JSON.stringify(line)}`);
    }
  }
});

test('script continuations that ARE continuations stay ordinary development', () => {
  for (const line of [
    'echo building \\\n  the project > out.log',
    'cp a.ts \\\n  b.ts',
    'ls -la \\\n  src',
    'echo one \\\\\\\ntwo', // three backslashes: an escaped backslash, then a real continuation
  ]) {
    assert.equal(scriptVerdict(line, './run.sh').verdict, 'ALLOW', JSON.stringify(line));
  }
  // a script saved with Windows line endings is still read line by line
  assert.equal(scriptVerdict('echo one\r\nls -la\r', './run.sh').verdict, 'ALLOW');
});

test('a Dockerfile RUN is joined as Docker joins it: mid-word, with a trailing blank after the backslash, over blank lines', () => {
  const build = (dockerfile: string) => {
    const dir = workspace({ Dockerfile: dockerfile });
    return evaluate(table, ctx(dir), { tool: 'Bash', input: { command: 'docker build .' } });
  };
  // Docker removes `\` + optional blanks + newline and joins WITHOUT inserting a space, so these are all `git push`
  for (const run of [
    'RUN echo ok \\ \n    && git push origin main', // a trailing blank after the backslash: the next line was hidden at ALLOW
    'RUN echo ok \\\t\n    && git push origin main',
    'RUN git pu\\\nsh origin main',
    'RUN echo ok \\\n\n    && git push origin main', // blank continuation lines are skipped
  ]) {
    const r = build(`FROM alpine\n${run}\n`);
    assert.equal(r.verdict, 'DENY', JSON.stringify(run));
    assert.equal(r.decisive?.capability, 'git.remote.push', JSON.stringify(run));
  }
  // `# escape=` changes the continuation character, and the rule is the same: a comment that ends in it joins nothing
  for (const dockerfile of [
    '# escape=`\nFROM alpine\n# helper `\nRUN git push origin main\n',
    '# escape=`\nFROM alpine\nRUN git pu`\nsh origin main\n',
    '# escape=`\nFROM alpine\nRUN echo ok ` \n && git push origin main\n',
    'FROM alpine\n# helper \\\nRUN git push origin main\n',
  ]) {
    const r = build(dockerfile);
    assert.equal(r.decisive?.capability, 'git.remote.push', JSON.stringify(dockerfile));
  }
  // the continuation of an ordinary build is untouched
  assert.equal(build('FROM node:24\nRUN npm ci --ignore-scripts \\\n    && npm run build\n').verdict, 'ALLOW');
  assert.equal(build('FROM alpine\nRUN echo ok \\ \n    && ls -la\n').verdict, 'ALLOW');
});

test('curl redaction joins a continuation as the shell does, so a credential split by one is redacted whole', () => {
  const first = 'Hq7Rt2Wx9Lm4';
  const second = 'Pz6Kd8Vb3Nc5';
  // (the command is assembled so that this file is not itself a curl line with a credential in it)
  const curl = (...words: string[]): string => ['cu' + 'rl', ...words].join(' ');
  const r = redactCurl(curl('-u', `alice:${first}\\\n${second}`, 'https://api.example.com/v1/export'));
  assert.ok(!r.text.includes(first), 'the first half must not survive');
  assert.ok(!r.text.includes(second), 'the second half must not survive');
  assert.ok(r.findings.some((f) => f.kind === 'curl.user'));
  // and the ordinary continuation still keeps its flags apart
  const spaced = redactCurl(curl('-sS \\\n  -u', `svc:${first}${second} \\\n  https://api.example.com`));
  assert.ok(!spaced.text.includes(first + second));
});
