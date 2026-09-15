import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseYaml, stringifyYaml, YamlSyntaxError } from '../src/util/yaml.ts';

test('parses nested maps, lists, scalars and flow collections', () => {
  const v = parseYaml(`
schema: ego.capabilities/1
id: git
absolute: false
count: 3
ratio: 1.5
nothing: ~
list:
  - a
  - "b c"
  - 'it''s'
maps:
  - capability: git.local.commit
    verdict: ASK
  - capability: git.local.reset
    verdict: DENY
flow: [x, y, 2]
fmap: {a: 1, b: true}
text: >
  folded
  text
block: |
  line1
  line2
`);
  assert.deepEqual(v, {
    schema: 'ego.capabilities/1',
    id: 'git',
    absolute: false,
    count: 3,
    ratio: 1.5,
    nothing: null,
    list: ['a', 'b c', "it's"],
    maps: [
      { capability: 'git.local.commit', verdict: 'ASK' },
      { capability: 'git.local.reset', verdict: 'DENY' },
    ],
    flow: ['x', 'y', 2],
    fmap: { a: 1, b: true },
    text: 'folded text',
    block: 'line1\nline2\n',
  });
});

test('list at the same indentation as its key', () => {
  const v = parseYaml('keys:\n- id: a\n  status: active\n- id: b\n  status: standby\n');
  assert.deepEqual(v, {
    keys: [
      { id: 'a', status: 'active' },
      { id: 'b', status: 'standby' },
    ],
  });
});

test('preserves regex backslashes in single quotes', () => {
  const v = parseYaml(`pattern: '^git\\s+push\\b'`) as { pattern: string };
  assert.equal(v.pattern, '^git\\s+push\\b');
});

test('rejects duplicate keys, tabs and unsupported constructs', () => {
  assert.throws(() => parseYaml('a: 1\na: 2'), YamlSyntaxError);
  assert.throws(() => parseYaml('a:\n\t- x'), YamlSyntaxError);
  assert.throws(() => parseYaml('a: &anchor x'), YamlSyntaxError);
  assert.throws(() => parseYaml('a: [1, 2'), YamlSyntaxError);
});

test('stringify is deterministic and round-trips', () => {
  const v = { b: [1, 'two', { c: 'x: y' }], a: { z: true, y: null } };
  const s = stringifyYaml(v);
  assert.equal(s, stringifyYaml(v));
  assert.deepEqual(parseYaml(s), { a: { y: null, z: true }, b: [1, 'two', { c: 'x: y' }] });
});
