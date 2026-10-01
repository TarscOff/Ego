// CLOSURE EVIDENCE (independent audit of 2026-10-01, receipt finding 18).
//
// The Phase-1 closure gate re-ran every pin against the current tree and found a class whose protection was real
// but whose EVIDENCE was not: a fix could be reverted with the suite still green. This file is the evidence.
//   - finding 18: the secret detectors. 27 of the 91 block-severity detectors were never the reporting detector in
//     any test, so a deleted or shadowed one cost nothing. The catalogue is now loaded, and every detector must
//     report its own fixture (support/secret-fixtures.ts).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadControlPlane } from '../src/control-plane/load.ts';
import { redact, allDetectors } from '../src/redaction/redact.ts';
import { FIXTURES } from './support/secret-fixtures.ts';

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
