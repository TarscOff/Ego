import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseMarkdown, findSection, ControlPlaneSyntaxError } from '../src/util/markdown.ts';

const SAMPLE = `---
schema: ego.capabilities/1
id: sample
family: sample
---
# Sample

Intro paragraph.

## Allowed

- [x] \`a.read\` — read things
- [ ] \`a.inactive\` — documented but inactive

## Requires human approval

- [x] \`a.ask\` — ask first

## Denied

- [x] \`a.deny\` — never
- plain bullet

\`\`\`
- [x] \`inside.fence\` — must be ignored
\`\`\`
`;

test('parses frontmatter, sections, checklist items and ignores fenced content', () => {
  const doc = parseMarkdown('sample.md', SAMPLE);
  assert.equal(doc.frontmatter['id'], 'sample');
  assert.equal(doc.title, 'Sample');
  const allowed = findSection(doc, 'Allowed')!;
  assert.deepEqual(
    allowed.items.map((i) => [i.id, i.checked, i.text]),
    [
      ['a.read', true, 'read things'],
      ['a.inactive', false, 'documented but inactive'],
    ],
  );
  assert.equal(findSection(doc, 'requires human approval')!.items[0]!.id, 'a.ask');
  const denied = findSection(doc, 'Denied')!;
  assert.equal(denied.items.length, 1);
  assert.deepEqual(denied.bullets, ['plain bullet']);
  assert.ok(!doc.allSections.some((s) => s.items.some((i) => i.id === 'inside.fence')));
});

test('unterminated frontmatter fails closed', () => {
  assert.throws(() => parseMarkdown('x.md', '---\nid: x\n# no end'), ControlPlaneSyntaxError);
});
