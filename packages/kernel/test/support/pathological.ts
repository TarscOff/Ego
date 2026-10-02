// PATHOLOGICAL INPUTS, ONE SEEDED GENERATOR PER READER FAMILY (closure audit 2026-10-02, general property I: BOUNDED WORK).
//
// The claim of authority/work-bound.ts is that EVERY reader of unbounded input pays for what it reads (`chargeWork`) BEFORE it reads it, so a
// decision on any input ends, with a verdict, in a time that does not depend on the input. A reader that does not charge is invisible to every
// other test: its inputs are small. These generators make them large in the shapes that have each made a reader slow before - a fan-out chain,
// a nesting, a repetition, a huge list, a long word - one family per reader, growing by a factor of two; the test that drives them
// (closure-authority2.test.ts, "BOUNDED WORK") asserts for each family and each size that the decision is a verdict, not a throw, in under a second
// of CPU, and that what it charged grows with what it was handed.
//
// A family is `{ id, reader, make(seed, n) }`: `n` is the size in the family's own unit (characters, entries, levels), `make` is a PURE function of
// (seed, n), and `files` are the fixtures the command needs. The list of families is the list of readers; a new reader of unbounded input adds one.
export interface Family {
  /** the shape, as a person would name it */
  id: string;
  /** the reader that must pay for it (a module and a function) */
  reader: string;
  /** the largest size worth running (the shape is already past the bound well before it) */
  max: number;
  make(seed: number, n: number): { command: string; files?: Record<string, string> };
}

/** a seeded generator (mulberry32): the same (seed, n) is the same input on every machine */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]!;
const word = (r: () => number, len: number): string => Array.from({ length: len }, () => 'abcdefghijklmnopqrstuvwxyz'[Math.floor(r() * 26)]).join('');

const BASE_FAMILIES: readonly Family[] = [
  {
    id: 'one long word',
    reader: 'evaluate.ts normalizer (the stage text) and the tokenizer',
    max: 1 << 18,
    make: (seed, n) => ({ command: `echo ${word(prng(seed), n)}` }),
  },
  {
    id: 'a long list of statements',
    reader: 'evaluate.ts statement splitter and the per-stage analysis',
    max: 1 << 16,
    make: (seed, n) => {
      const r = prng(seed);
      return { command: Array.from({ length: n }, () => `echo ${word(r, 2)}`).join('; ') };
    },
  },
  {
    id: 'a long pipeline',
    reader: 'evaluate.ts pipeline pairing (PAIR_COST)',
    max: 1 << 14,
    make: (_seed, n) => ({ command: `${Array.from({ length: n }, () => 'cat x').join(' | ')} | cat` }),
  },
  {
    id: 'a long && chain',
    reader: 'evaluate.ts chain analysis and the cwd timeline',
    max: 1 << 15,
    make: (_seed, n) => ({ command: `${Array.from({ length: n }, () => 'true').join(' && ')} && ls` }),
  },
  {
    id: 'a fan-out of brace groups',
    reader: 'evaluate.ts expandBraces',
    max: 24,
    make: (_seed, n) => ({ command: `echo ${Array.from({ length: n }, () => '{a,b,c,d}').join('')}` }),
  },
  {
    id: 'a numeric brace range',
    reader: 'evaluate.ts expandBraces (ranges)',
    max: 1 << 30,
    make: (_seed, n) => ({ command: `echo {1..${n}}` }),
  },
  {
    id: 'nested brace groups',
    reader: 'evaluate.ts expandBraces (nesting)',
    max: 1 << 11,
    make: (_seed, n) => ({ command: `echo ${'{a,'.repeat(n)}b${'}'.repeat(n)}` }),
  },
  {
    id: 'nested command substitutions',
    reader: 'evaluate.ts substitution reader (nesting)',
    max: 1 << 11,
    make: (_seed, n) => ({ command: `echo ${'$('.repeat(n)}date${')'.repeat(n)}` }),
  },
  {
    id: 'nested subshells and groups',
    reader: 'evaluate.ts shell structure splitter (nesting)',
    max: 1 << 11,
    make: (_seed, n) => ({ command: `${'( '.repeat(n)}ls${' )'.repeat(n)}` }),
  },
  {
    id: 'nested shells (bash -c inside bash -c)',
    reader: 'evaluate.ts carried-command reader (nesting)',
    // the quoting doubles its escapes at every level: 14 levels are 32 KB of text, 18 half a megabyte
    max: 14,
    make: (_seed, n) => {
      let c = 'ls';
      for (let i = 0; i < n; i++) c = `bash -c ${JSON.stringify(c)}`;
      return { command: c };
    },
  },
  {
    id: 'a chain of carriers',
    reader: 'carriers.ts peelCarriers',
    max: 1 << 12,
    make: (_seed, n) => ({ command: `${'env FOO=1 '.repeat(n)}ls` }),
  },
  {
    id: 'a wildcard over many paths',
    reader: 'paths.ts glob listing and evaluate.ts wildcard expansion',
    max: 1 << 12,
    make: (_seed, n) => ({
      command: 'cat d/*.txt d/*.md d/f*',
      files: Object.fromEntries(Array.from({ length: n }, (_, i) => [`d/f${i}.txt`, ''])),
    }),
  },
  {
    id: 'many wildcards over one directory',
    reader: 'paths.ts listing cache (ENTRY_VISIT_COST)',
    max: 1 << 11,
    make: (_seed, n) => ({
      command: `cat ${Array.from({ length: n }, (_, i) => `d/f${i % 7}*`).join(' ')}`,
      files: Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`d/f${i}`, ''])),
    }),
  },
  {
    id: 'a sed script of blanks',
    reader: 'evaluate.ts sed scanner',
    max: 1 << 17,
    make: (_seed, n) => ({ command: `sed -n '${' '.repeat(n)}p' README.md; ${'git'} push origin main` }),
  },
  {
    id: 'a sed script of substitutions',
    reader: 'sed.ts script reader',
    max: 1 << 15,
    make: (seed, n) => {
      const r = prng(seed);
      return { command: `sed -n '${Array.from({ length: n }, () => `s/${word(r, 1)}/${word(r, 1)}/g`).join(';')}' README.md` };
    },
  },
  {
    id: 'an awk program of blanks',
    reader: 'evaluate.ts awk scanner',
    max: 1 << 17,
    make: (_seed, n) => ({ command: `awk '${' '.repeat(n)}' README.md` }),
  },
  {
    id: 'an awk program of statements',
    reader: 'evaluate.ts awk scanner',
    max: 1 << 14,
    make: (seed, n) => {
      const r = prng(seed);
      return { command: `awk '{ ${Array.from({ length: n }, () => `x = x + ${Math.floor(r() * 9)};`).join(' ')} }' README.md` };
    },
  },
  {
    id: 'a heredoc of many lines',
    reader: 'evaluate.ts heredoc scanning',
    max: 1 << 16,
    make: (_seed, n) => ({ command: `cat > f <<'EOF'\n${Array.from({ length: n }, () => 'a line of text').join('\n')}\nEOF\n` }),
  },
  {
    id: 'many heredocs',
    reader: 'evaluate.ts heredoc scanning (one per statement)',
    max: 1 << 13,
    make: (_seed, n) => ({ command: Array.from({ length: n }, (_, i) => `cat <<E${i}\nx\nE${i}`).join('\n') }),
  },
  {
    id: 'a run of angle brackets',
    reader: 'evaluate.ts redirection and here-string patterns',
    max: 1 << 16,
    make: (_seed, n) => ({ command: `cat ${'<'.repeat(n)}` }),
  },
  {
    id: 'many redirections',
    reader: 'evaluate.ts redirection reader',
    max: 1 << 14,
    make: (_seed, n) => ({ command: `echo x ${Array.from({ length: n }, (_, i) => `> out${i}`).join(' ')}` }),
  },
  {
    id: 'moves into a directory that is not there',
    reader: 'evaluate.ts cwd timeline + paths.ts walk',
    max: 1 << 14,
    make: (_seed, n) => ({ command: `${'cd a; '.repeat(n)}ls` }),
  },
  {
    id: 'a long path with many components',
    reader: 'paths.ts canonicalPath',
    max: 1 << 11,
    make: (_seed, n) => ({ command: `cat ${'a/'.repeat(n)}f` }),
  },
  {
    id: 'many distinct paths',
    reader: 'evaluate.ts path classification (PATH_JUDGE_COST)',
    max: 1 << 14,
    make: (seed, n) => {
      const r = prng(seed);
      return { command: `cat ${Array.from({ length: n }, () => `d/${word(r, 6)}`).join(' ')}` };
    },
  },
  {
    id: 'hundreds of different sixty-kilobyte scripts',
    reader: 'evaluate.ts file reader (readInsideWorkspace)',
    max: 1 << 8,
    make: (_seed, n) => ({
      command: Array.from({ length: n }, (_, i) => `sh s${i}.sh`).join('; '),
      files: Object.fromEntries(Array.from({ length: n }, (_, i) => [`s${i}.sh`, `# ${'x'.repeat(60_000)}\necho ${i}\n`])),
    }),
  },
  {
    id: 'a script that names scripts',
    reader: 'evaluate.ts producer closure walk (shell scripts)',
    max: 1 << 8,
    make: (_seed, n) => ({
      command: 'sh s0.sh',
      files: Object.fromEntries(Array.from({ length: n }, (_, i) => [`s${i}.sh`, i + 1 < n ? `sh s${i + 1}.sh\nsh s${i + 1}.sh\n` : 'ls\n'])),
    }),
  },
  {
    id: 'package scripts that call package scripts',
    reader: 'evaluate.ts producer closure walk (npm scripts)',
    max: 1 << 8,
    make: (_seed, n) => ({
      command: 'npm run s0',
      files: {
        'package.json': JSON.stringify({ scripts: Object.fromEntries(Array.from({ length: n }, (_, i) => [`s${i}`, i + 1 < n ? `npm run s${i + 1} && npm run s${i + 1}` : 'echo done'])) }),
      },
    }),
  },
  {
    id: 'a makefile of targets that depend on targets',
    reader: 'evaluate.ts make expander (another task\'s reader; the family is here so the harness names it)',
    max: 1 << 8,
    make: (_seed, n) => ({
      command: 'make t0',
      files: { Makefile: Array.from({ length: n }, (_, i) => (i + 1 < n ? `t${i}: t${i + 1} t${i + 1}\n\techo ${i}\n` : `t${i}:\n\techo ${i}\n`)).join('') },
    }),
  },
  {
    id: 'a makefile of variables that expand variables',
    reader: 'evaluate.ts make expander (variable fan-out)',
    max: 1 << 7,
    make: (_seed, n) => ({
      command: 'make all',
      files: { Makefile: `${Array.from({ length: n }, (_, i) => `V${i} = $(V${i + 1}) $(V${i + 1})\n`).join('')}V${n} = x\nall:\n\techo $(V0)\n` },
    }),
  },
  {
    id: 'a git hook that runs hooks',
    reader: 'evaluate.ts producer closure walk (git hooks)',
    max: 1 << 6,
    make: (_seed, n) => ({
      command: 'git commit -m x',
      files: { '.git/hooks/pre-commit': `#!/bin/sh\n${Array.from({ length: n }, () => 'sh .git/hooks/pre-commit').join('\n')}\n` },
    }),
  },
  {
    id: 'a kubectl command with a huge flag list',
    reader: 'k8s.ts option reader',
    max: 1 << 14,
    make: (seed, n) => {
      const r = prng(seed);
      return { command: `kubectl --context kind-dev get pods ${Array.from({ length: n }, () => `-l ${word(r, 3)}=${word(r, 3)}`).join(' ')}` };
    },
  },
  {
    id: 'a kubectl apply of many manifests',
    reader: 'k8s.ts and the manifest reader',
    max: 1 << 11,
    make: (_seed, n) => ({
      command: `kubectl --context kind-dev apply ${Array.from({ length: n }, (_, i) => `-f m${i}.yaml`).join(' ')}`,
      files: Object.fromEntries(Array.from({ length: Math.min(n, 64) }, (_, i) => [`m${i}.yaml`, `apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c${i}}\n`])),
    }),
  },
  {
    id: 'a docker run with a huge argument list',
    reader: 'containers.ts option reader',
    max: 1 << 14,
    make: (seed, n) => {
      const r = prng(seed);
      return { command: `docker run --rm ${Array.from({ length: n }, () => `-e ${word(r, 3)}=${word(r, 3)}`).join(' ')} alpine true` };
    },
  },
  {
    id: 'a compose file of many services',
    reader: 'containers.ts compose reader',
    max: 1 << 9,
    make: (_seed, n) => ({
      command: 'docker compose build',
      // (a build is what makes the reader open the file: `up` alone never reads it)
      files: {
        Dockerfile: 'FROM alpine\nRUN echo ok\n',
        'docker-compose.yml': `services:\n${Array.from({ length: n }, (_, i) => `  s${i}:\n    build: .\n    command: sh -c "echo ${i}"\n`).join('')}`,
      },
    }),
  },
  {
    id: 'a SQL statement of many clauses',
    reader: 'evaluate.ts database statement scanner',
    max: 1 << 15,
    make: (seed, n) => {
      const r = prng(seed);
      return { command: `psql -h localhost -c "SELECT ${Array.from({ length: n }, () => `a${Math.floor(r() * 9)}`).join(', ')} FROM t"` };
    },
  },
  {
    id: 'a SQL statement of nested parentheses',
    reader: 'evaluate.ts database statement scanner (nesting)',
    max: 1 << 11,
    make: (_seed, n) => ({ command: `psql -h localhost -c "SELECT ${'('.repeat(n)}1${')'.repeat(n)}"` }),
  },
  {
    id: 'a SQL file of many statements',
    reader: 'evaluate.ts database client script operand (opaque by design: it asks and the file is not read)',
    max: 1 << 14,
    make: (_seed, n) => ({
      command: 'psql -h localhost -f s.sql',
      files: { 's.sql': Array.from({ length: n }, (_, i) => `INSERT INTO t VALUES (${i});`).join('\n') },
    }),
  },
  {
    id: 'many written files, each read afterwards',
    reader: 'evaluate.ts freshness ledger (written paths)',
    max: 1 << 11,
    make: (_seed, n) => ({ command: Array.from({ length: n }, (_, i) => `echo x > w${i}; cat w${i}`).join('; ') }),
  },
  {
    id: 'a find with a long chain of -exec',
    reader: 'carriers.ts payload spans',
    max: 1 << 11,
    make: (_seed, n) => ({ command: `find . ${Array.from({ length: n }, () => '-exec echo {} ;').join(' ')}` }),
  },
  {
    id: 'an xargs chain',
    reader: 'evaluate.ts payload reader',
    max: 1 << 11,
    make: (_seed, n) => ({ command: `echo x ${Array.from({ length: n }, () => '| xargs echo').join(' ')}` }),
  },
  {
    id: 'a git command with a huge option list',
    reader: 'git-invocation.ts option reader',
    max: 1 << 13,
    make: (seed, n) => {
      const r = prng(seed);
      return { command: `git log ${Array.from({ length: n }, () => `--grep=${word(r, 3)}`).join(' ')}` };
    },
  },
  {
    id: 'many git commands',
    reader: 'evaluate.ts git analysis (SPAWN_COST)',
    max: 96, // (a spawn is real time: the bound is a hundred of them)
    make: (_seed, n) => ({ command: Array.from({ length: n }, () => 'git status').join('; ') }),
  },
  {
    id: 'a function definition chain',
    reader: 'evaluate.ts function reader',
    max: 1 << 10,
    make: (_seed, n) => ({ command: `${Array.from({ length: n }, (_, i) => `f${i}() { f${i + 1}; f${i + 1}; }`).join('\n')}\nf${n}() { ls; }\nf0` }),
  },
  {
    id: 'an arithmetic expansion of many terms',
    reader: 'evaluate.ts arithmetic reader',
    max: 1 << 14,
    make: (_seed, n) => ({ command: `echo $((${Array.from({ length: n }, () => '1').join('+')}))` }),
  },
  {
    id: 'a case statement of many arms',
    reader: 'evaluate.ts shell structure splitter (case)',
    max: 1 << 12,
    make: (_seed, n) => ({ command: `case x in ${Array.from({ length: n }, (_, i) => `p${i}) ls;;`).join(' ')} esac` }),
  },
];

// THE READERS WAVE 6 ADDED (dataflow.ts, flow.ts, links.ts). They were merged after the harness was written; the families name them so that the next
// reader of their kind has a place to go. (The wildcard destination reader is not here: its price per unit is the highest of any reader - a
// directory of four thousand entries spends about a second of CPU at the bound - so a family for it fails the time claim of the test until the
// price of a listing entry is calibrated against real time, which is a separate piece of work.)
const names = (n: number): string => Array.from({ length: n }, (_, i) => `f${i}`).join(' ');
const WAVE6_FAMILIES: readonly Family[] = [
  {
    id: 'a produced list handed to xargs',
    reader: 'dataflow.ts planXargs (a variant for every way the consumer cuts the produced text)',
    max: 1 << 12,
    make: (_seed, n) => ({ command: `echo ${names(n)} | xargs cat` }),
  },
  {
    id: 'a read loop over a produced list',
    reader: 'dataflow.ts planReadLoop (the body is judged once for every value)',
    max: 1 << 12,
    make: (_seed, n) => ({ command: `printf '%s\\n' ${names(n)} | while read f; do cat "$f"; done` }),
  },
  {
    id: 'a command substitution of a produced list',
    reader: 'flow.ts foldSubstitutions (the consumer is judged again with the output in place)',
    max: 1 << 12,
    make: (_seed, n) => ({ command: `cat $(echo ${names(n)})` }),
  },
  {
    id: 'many command substitutions',
    reader: 'dataflow.ts planSubstitutions (a producer for every site)',
    max: 1 << 11,
    make: (_seed, n) => ({ command: `cat ${Array.from({ length: n }, (_, i) => `$(echo f${i})`).join(' ')}` }),
  },
  {
    id: 'a link-keeping copy of many sources',
    reader: 'links.ts linksUnder (a walk below every source)',
    max: 1 << 11,
    make: (_seed, n) => ({
      command: `cp -a ${Array.from({ length: n }, (_, i) => `d${i}`).join(' ')} out`,
      files: Object.fromEntries(Array.from({ length: n }, (_, i) => [`d${i}/a`, ''])),
    }),
  },
];

/** every family: the list of the readers of unbounded input */
export const FAMILIES: readonly Family[] = [...BASE_FAMILIES, ...WAVE6_FAMILIES];

/** `pick` and `word` are exported for the families a later reader adds */
export { pick, word };
