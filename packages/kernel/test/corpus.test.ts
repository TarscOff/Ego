// The regression corpus, run by ROOT SEMANTIC CLASS rather than by the order the defects arrived.
// The corpus itself — classes, transformations, producers, ordinary commands — lives in `support/corpus.ts`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  RANK,
  SEMANTIC_CLASSES,
  TRANSFORMS,
  PRODUCERS,
  ORDINARY,
  EXPECTED_GATES,
  workspace,
  verdict,
} from './support/corpus.ts';

test('every canonical spelling of a semantic class meets its floor', () => {
  const dir = workspace();
  const failures: string[] = [];
  for (const cls of SEMANTIC_CLASSES)
    for (const c of cls.cases) {
      const got = verdict(c, dir);
      if (RANK[got]! < RANK[cls.floor]!) failures.push(`[${cls.family}] ${cls.id}: "${c}" ${cls.floor} -> ${got}`);
    }
  assert.deepEqual(failures, [], `a canonical spelling fell under its floor:\n  ${failures.join('\n  ')}`);
});

test('every generated shell variant meets the floor of the class it carries', () => {
  const dir = workspace();
  const failures: string[] = [];
  let checked = 0;
  for (const cls of SEMANTIC_CLASSES)
    for (const c of cls.cases)
      for (const t of TRANSFORMS) {
        if (t.safe && !t.safe(c)) continue; // not a variant: the pair cannot be spelled
        checked++;
        const got = verdict(t.apply(c), dir);
        if (RANK[got]! < RANK[cls.floor]!) failures.push(`[${cls.family}] ${t.name}: "${c}" ${cls.floor} -> ${got}`);
      }
  assert.ok(checked > 1000, `the cross-product collapsed: only ${checked} variants`);
  assert.deepEqual(failures, [], `a shell transformation reduced authority:\n  ${failures.join('\n  ')}`);
});

test('every producer-carried variant meets the floor of the body it resolves', () => {
  const failures: string[] = [];
  let checked = 0;
  for (const cls of SEMANTIC_CLASSES) {
    // one representative spelling per class: the producers vary the RESOLUTION path, not the spelling, and each
    // case here costs a temporary repository on disk
    const c = cls.cases[0]!;
    for (const p of PRODUCERS) {
      if (p.safe && !p.safe(c)) continue;
      checked++;
      const [files, invoke] = p.build(c);
      const got = verdict(invoke, workspace(files));
      if (RANK[got]! < RANK[cls.floor]!) failures.push(`[${cls.family}] ${p.name}: "${c}" ${cls.floor} -> ${got}`);
    }
  }
  assert.ok(checked > 200, `the cross-product collapsed: only ${checked} variants`);
  assert.deepEqual(failures, [], `a producer reduced the authority of its body:\n  ${failures.join('\n  ')}`);
});

test('ordinary development is gated in exactly the places that are accounted for', () => {
  const dir = workspace();
  const unexpected: string[] = [];
  const stale: string[] = [];
  let total = 0;
  for (const [ecosystem, commands] of Object.entries(ORDINARY))
    for (const c of commands) {
      total++;
      const got = verdict(c, dir);
      const accounted = Object.hasOwn(EXPECTED_GATES, c);
      if (got !== 'ALLOW' && !accounted) unexpected.push(`[${ecosystem}] ${got} ${c}`);
      if (got === 'ALLOW' && accounted) stale.push(`[${ecosystem}] ${c} is now ALLOW — remove it from EXPECTED_GATES`);
    }
  assert.equal(total, 98, 'the ordinary corpus changed size; update the count deliberately');
  assert.deepEqual(unexpected, [], `ordinary development gated without a reason:\n  ${unexpected.join('\n  ')}`);
  assert.deepEqual(stale, [], `EXPECTED_GATES is out of date:\n  ${stale.join('\n  ')}`);
});
