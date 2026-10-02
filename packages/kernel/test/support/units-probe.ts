// A child process for closure-authority2.test.ts (RB-7): decide a fixed list of commands in a workspace made at the path given on
// the command line and print, one line each, the verdict, the deciding capability and the WORK UNITS spent. The test runs it twice -
// under a different HOME, a different TMPDIR, a checkout at a different depth, and (with `--twice`) in a process that has already
// decided every command once - and compares the lines: the units a decision spends depend on the command and the declared
// configuration, never on where the machine keeps its files or on what the process has already seen.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { table, ORDINARY, SEMANTIC_CLASSES } from './corpus.ts';
import { evaluate } from '../../src/authority/evaluate.ts';
import { workSpent } from '../../src/authority/work-bound.ts';

const [, , dir, ...flags] = process.argv;
mkdirSync(join(dir!, '.git', 'hooks'), { recursive: true });
writeFileSync(join(dir!, 'package.json'), JSON.stringify({ scripts: { test: 'tsc -p .' } }));
writeFileSync(join(dir!, 'Makefile'), 'build:\n\ttsc -p .\n');
writeFileSync(join(dir!, 'x'), 'echo hi\n');

/** commands that NAME the places the machine keeps things, so the machine's choice of them is in the path the decision reads */
const NAMED: string[] = [
  'cat ~/.ssh/id_rsa',
  'ls ~',
  'ls $HOME',
  'ls ${HOME}/projects',
  'echo x > ~/y',
  'echo x > $HOME/y',
  'cp x ~/b',
  'rm -rf ~/scratch',
  'cd ~ && rm x',
  'cd ~/proj/sub && cat a',
  'cat $TMPDIR/x',
  'echo x > $TMPDIR/out',
  'cat /tmp/x',
  'echo x > /tmp/ego-units/out',
  'cd /tmp && ls',
  'cd $TMPDIR && rm -rf build',
  'touch ./a/b/c/d/e',
  'cat ../x',
  'rm -rf ./x ./y ./z',
  'git status',
  'git -C . log --oneline',
  'git -C ~ status',
  'git -C /tmp status',
  'make build',
  'ls ~/a ~/b ~/c ~/d',
  'tee ~/.bashrc < x',
];
const commands = [
  ...NAMED,
  ...Object.values(ORDINARY).flat(),
  ...SEMANTIC_CLASSES.flatMap((c) => c.cases.slice(0, 2)),
];
const files = Object.fromEntries(
  SEMANTIC_CLASSES.flatMap((c) => Object.entries(c.files ?? {})).filter(([k]) => !k.includes('..')),
);
for (const [name, content] of Object.entries(files)) {
  try {
    const p = join(dir!, name);
    mkdirSync(join(p, '..'), { recursive: true });
    if (typeof content === 'string' && !content.startsWith('\0')) writeFileSync(p, content);
  } catch {
    /* a fixture the class needs that this probe cannot make is not one of the commands compared */
  }
}

const ctx = { profile: 'STANDARD', mode: 'NORMAL_DELIVERY', repoRoots: [dir!], cwd: dir! };
const decide = (command: string): string => {
  try {
    const r = evaluate(table, ctx, { tool: 'Bash', input: { command } });
    return `${r.verdict} ${r.decisive?.capability ?? '-'} ${workSpent()}`;
  } catch (e) {
    return `THROW ${(e as Error).name}`;
  }
};
const first = commands.map(decide);
const second = flags.includes('--twice') ? commands.map(decide) : first;
console.log(JSON.stringify({ commands, first, second }));
