// THE WORKING-DIRECTORY MODEL, CHECKED AGAINST REAL SHELLS. `cwdTimeline` says where each stage of a command may run;
// the property is SOUNDNESS: whatever directory bash and zsh actually end up in is one the model allows (or the model
// says it does not know). A hand-written expectation would only encode the author's idea of `cd`, which is what was
// wrong eleven times in exit review 10.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { cwdTimeline, splitShellPipeline } from '../src/authority/evaluate.ts';

const root = realpathSync(mkdtempSync(join(tmpdir(), 'ego-cwd-')));
for (const d of ['a/x', 'b', 'home', 'control-plane']) mkdirSync(join(root, d), { recursive: true });
symlinkSync(join(root, 'a', 'x'), join(root, 'link'));
writeFileSync(join(root, 'go.sh'), 'cd b\n');

const SCRIPTS = [
  'cd a; cd x',
  'cd a && cd x',
  'cd a && cd nonexist',
  'cd nonexist',
  'cd nonexist || cd b',
  'cd nonexist || cd b; cd x',
  'true || cd a',
  'false || cd a',
  'false && cd a',
  'true && cd a',
  '[ -d nope ] && cd a',
  '[ -d a ] && cd a',
  'test -d nope && cd a; true',
  'if true; then cd a; fi',
  'if false; then cd a; fi',
  'for i in 1 2; do cd a; done',
  'while false; do cd a; done',
  'case x in x) cd a ;; esac',
  'case x in y) cd a ;; esac',
  'f() { cd a; }; f',
  'f() { cd a; }; true',
  'f() { cd a; }; f; cd b',
  'cd() { true; }; cd a',
  'cd() { builtin cd b; }; cd a',
  '(cd a)',
  '(cd a; cd x)',
  'cd a | cat',
  'cat /dev/null | cd a',
  'cd a & wait',
  'echo $(cd a)',
  'cd a; cd -',
  'cd a; cd b; cd -',
  'pushd a >/dev/null; pushd b >/dev/null; popd >/dev/null',
  'pushd a >/dev/null; popd >/dev/null',
  'cd a >/dev/null 2>&1',
  'cd',
  'cd ~',
  'cd link',
  'cd link/..',
  'cd -P link/..',
  '! cd a',
  'FOO=1 cd a',
  'builtin cd a',
  'command cd a',
  "'cd' a",
  'c\\d a',
  'if cd a; then true; fi',
  'while cd a; do break; done',
  'cd a; cd ..; cd b',
  'cd a && cd .. && cd b',
  '{ cd a; }',
  '{ cd a; } ; cd x',
  'true; cd a && true || cd b',
  'cd a || cd b',
  'source ./go.sh',
  '. ./go.sh',
  'cd a; source ../go.sh',
  'cd a\ncd x\ncd ..',
  'cd a;\n\n cd x',
  '(cd a; true); cd b',
  'echo $(cd a; cd x); true',
  '( (cd a); cd b )',
  '(cd a) && cd b',
  'v=$(cd a; pwd); cd b',
  'echo `cd a`; cd b',
  '(cd a; (cd x; true); true); cd b',
  'cd a; (cd ..; true)',
  'cd a; echo $(cd ..)',
  '{ cd a; } & wait',
  'cd a || cd b; cd x',
  'cd a && cd b || cd x',
];

for (const shell of ['bash', 'zsh']) {
  test(`the modelled working directory contains the one ${shell} ends in`, () => {
    const prev = process.env['HOME'];
    process.env['HOME'] = join(root, 'home');
    try {
      const failures: string[] = [];
      let precise = 0;
      for (const script of SCRIPTS) {
        // `cd a\ncd x` style scripts run from `root`; the model is asked about a trailing no-op so that the LAST stage's
        // starting directory is the directory the script ends in
        const real = spawnSync(shell, ['-c', `${script}\npwd -P`], {
          cwd: root,
          env: { ...process.env, HOME: join(root, 'home') },
          encoding: 'utf8',
        });
        if (real.error) continue;
        const lines = (real.stdout ?? '').trim().split('\n');
        const actual = lines[lines.length - 1]!;
        const points = cwdTimeline(splitShellPipeline(`${script}\ntrue`), root, true, (abs) => {
          try {
            return abs.startsWith(root) ? spawnSync('cat', [abs], { encoding: 'utf8' }).stdout : null;
          } catch {
            return null;
          }
        });
        const last = points[points.length - 1]!;
        if (!last.unknown && !last.dirs.includes(actual))
          failures.push(`${shell}: ${JSON.stringify(script)} ended in ${actual.replace(root, '<root>')}; modelled ${last.dirs.map((d) => d.replace(root, '<root>')).join(' | ')}`);
        if (!last.unknown && last.dirs.length === 1) precise++;
      }
      assert.deepEqual(failures, []);
      assert.ok(precise >= SCRIPTS.length * 0.4, `the model collapsed to "unknown" too often: ${precise}/${SCRIPTS.length} precise`);
    } finally {
      if (prev === undefined) delete process.env['HOME'];
      else process.env['HOME'] = prev;
    }
  });
}

test('the simple cases stay exact, because a model that always says "maybe" gates ordinary work', () => {
  const at = (script: string) => {
    const pts = cwdTimeline(splitShellPipeline(`${script}\ntrue`), root, true);
    const last = pts[pts.length - 1]!;
    return { dirs: last.dirs.map((d) => d.replace(root, '<root>')), unknown: last.unknown };
  };
  assert.deepEqual(at('cd a && cd x'), { dirs: ['<root>/a/x'], unknown: false });
  assert.deepEqual(at('cd a; cd ..; cd b'), { dirs: ['<root>/b'], unknown: false });
  assert.deepEqual(at('(cd a; cd x)'), { dirs: ['<root>'], unknown: false });
  assert.deepEqual(at('cd a | cat'), { dirs: ['<root>'], unknown: false });
  assert.deepEqual(at('pushd a >/dev/null; popd >/dev/null'), { dirs: ['<root>'], unknown: false });
  assert.deepEqual(at('cd a; cd -'), { dirs: ['<root>'], unknown: false });
  assert.deepEqual(at('cd a\ncd x\ncd ..'), { dirs: ['<root>/a'], unknown: false });
});
