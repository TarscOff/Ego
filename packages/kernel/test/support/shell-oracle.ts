// A REAL SHELL AS THE ORACLE (closure audit 2026-10-02). A hand-written expectation encodes its author's idea of what a shell runs, and the
// idea was wrong every time a syntax was found that runs a command nobody expected (`$[ ]`, a quoted subscript, a self-unsetting function).
// So the oracle is the shell: fake executables that LOG what they were called with, placed first in PATH, run under every shell the machine
// has, and whatever really ran is what the evaluator must have refused. Nothing here touches the network or a path outside a scratch tree:
// the only programs a script can reach by name are the fakes, which append a line to a log and exit.
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

/** the programs the scripts name; each is a fake */
export const FAKE_PROGRAMS = ['git', 'kubectl', 'psql', 'rm', 'curl', 'docker'] as const;

export interface Ran {
  name: string;
  /** the directory the program was started in (physical) */
  cwd: string;
  args: string[];
}

/** the first shell of this name the machine has, or null: the tests that need one SKIP without it */
export function findShell(name: 'bash' | 'zsh' | 'dash'): string | null {
  for (const dir of ['/bin', '/usr/bin', '/usr/local/bin', '/opt/homebrew/bin']) {
    const p = join(dir, name);
    if (existsSync(p)) return p;
  }
  return null;
}

export interface ShellSandbox {
  /** a scratch directory */
  readonly dir: string;
  /** the directory every script starts in: the workspace the evaluator is told about */
  readonly work: string;
  /** runs `script` under the shell at `shellPath`; what the fakes were called with, in order */
  run(shellPath: string, script: string): Ran[];
  dispose(): void;
}

export function shellSandbox(): ShellSandbox {
  const dir = mkdtempSync(join(tmpdir(), 'ego-shell-oracle-'));
  const bin = join(dir, 'bin');
  const work = join(dir, 'work');
  const home = join(dir, 'home');
  for (const d of [bin, work, home]) mkdirSync(d, { recursive: true });
  const log = join(dir, 'oracle.log');
  for (const name of FAKE_PROGRAMS) {
    writeFileSync(join(bin, name), `#!/bin/sh\n{ printf 'RAN\\t%s\\t%s' "\${0##*/}" "$(pwd -P)"; for a in "$@"; do printf '\\t%s' "$a"; done; printf '\\n'; } >> "${log}"\nexit 0\n`);
    chmodSync(join(bin, name), 0o755);
  }
  // the directories the scripts may name exist, so a `cd` is not the end of one
  for (const d of ['a', 'b', 'sub', 'control-plane']) mkdirSync(join(work, d), { recursive: true });
  return {
    dir,
    work: realpathSync(work),
    run(shellPath, script) {
      rmSync(log, { force: true });
      spawnSync(shellPath, ['-c', script], {
        cwd: work,
        env: { PATH: `${bin}:/usr/bin:/bin`, HOME: home, TMPDIR: dir, LANG: 'C', ZDOTDIR: home, ORACLE_LOG: log },
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 5000,
        killSignal: 'SIGKILL',
      });
      if (!existsSync(log)) return [];
      return readFileSync(log, 'utf8')
        .split('\n')
        .filter((l) => l.startsWith('RAN\t'))
        .map((l) => {
          const f = l.split('\t');
          return { name: f[1]!, cwd: f[2]!, args: f.slice(3) };
        });
    },
    dispose() {
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** whether a run of a fake is an act the evaluator must refuse (DENY) whatever the script around it looked like */
export function isForbiddenRun(r: Ran, work: string): boolean {
  const a = r.args;
  switch (r.name) {
    case 'git':
      return a[0] === 'push' && !a.includes('--dry-run') && !a.includes('-n');
    case 'kubectl':
      return a.includes('delete') && a.includes('production') && !a.some((x) => /^--dry-run(=(client|server|true))?$/.test(x));
    case 'rm':
      // (the file the path names from where the program was started: `rm control-plane` in a sub directory removes another one)
      return a.some((x) => !x.startsWith('-') && (isAbsolute(x) ? x : resolve(r.cwd, x)).replace(/\/+$/, '').startsWith(join(work, 'control-plane')));
    case 'psql':
      return a.some((x) => /prod-db\.acme\.com/.test(x)) && a.some((x) => /drop/i.test(x));
    default:
      return false;
  }
}

/** the builtins and keywords a shell lists, for the sweep that checks which of them evaluate a word as code */
export function listBuiltins(shellPath: string, kind: 'bash' | 'zsh'): string[] {
  const cmd = kind === 'bash' ? 'compgen -b; compgen -k' : 'print -l ${(k)builtins} ${(k)reswords}';
  const r = spawnSync(shellPath, ['-c', cmd], { encoding: 'utf8', timeout: 5000 });
  return [...new Set((r.stdout ?? '').split(/\s+/).filter((x) => /^[A-Za-z_.:[\]!{}-]+$/.test(x)))];
}

/** a seeded generator (mulberry32): the same seed is the same scripts on every machine */
export function seeded(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
