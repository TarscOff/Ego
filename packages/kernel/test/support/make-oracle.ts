// THE REAL MAKE AS AN ORACLE, AND A SEEDED GENERATOR OF MAKEFILES THAT TRY TO HIDE A COMMAND FROM THE READER (closure audit 2026-10-02, wave 6, TG-01).
//
// The make closure tests of the earlier waves were built from the reviewers' reproductions, so they shared the reviewers' blind spots: eight of the
// ten findings of wave 5 were found by a reviewer who ran the REAL make with a logging `git` on the PATH and compared what ran with the kernel's
// verdict. That comparison is the test, and it is kept here: a case is a set of files and a command line; the command is run for real, in a
// repository of its own, with a `git` that appends its arguments to a log; the kernel is asked about the same command on a copy of the same files.
// Whatever the logging `git` was run with is something the kernel was wrong to ALLOW.
//
// The generator composes a makefile from three things - how the variable CMD comes to hold the act (a SETTER), how the recipe reads it (a USER),
// and a line of noise between them - so the cases are the cross-product of constructs, not a list of spellings somebody thought of; it is seeded
// and bounded, so the run is the same everywhere. The oracle is skipped (not failed) where `make` is not GNU make.
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

const T = '\t';

export interface OracleCase {
  readonly name: string;
  readonly files: Readonly<Record<string, string>>;
  readonly cmd: string;
  /** the tag that identifies this case's act in the log of the logging `git` */
  readonly tag: string;
}

/** true when `make` on this host is GNU make: the oracle means nothing otherwise */
export function realMakeAvailable(): boolean {
  const r = spawnSync('make', ['--version'], { encoding: 'utf8' });
  return r.status === 0 && /GNU Make/i.test(r.stdout);
}

/** Runs the command for real. Returns the arguments the logging `git` was called with. */
export function runReal(root: string, c: OracleCase): string[] {
  const dir = mkdtempSync(join(root, 'real-'));
  mkdirSync(join(dir, '.git'), { recursive: true });
  for (const [name, content] of Object.entries(c.files)) {
    const p = join(dir, name);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content);
    if (/\.sh$/.test(name)) chmodSync(p, 0o755);
  }
  const bin = join(root, 'bin');
  const log = join(dir, '..', `log-${c.tag}`);
  const r = spawnSync('/bin/sh', ['-c', c.cmd], {
    cwd: dir,
    env: { ...process.env, PATH: `${bin}:${process.env['PATH'] ?? ''}`, LOGF: log, MAKEFLAGS: '', MAKELEVEL: '' },
    timeout: 20000,
    encoding: 'utf8',
  });
  void r;
  const ran = existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter(Boolean) : [];
  rmSync(dir, { recursive: true, force: true });
  return ran;
}

/** A directory with the logging `git` in it. */
export function oracleRoot(): string {
  const root = mkdtempSync(join(tmpdir(), 'make-oracle-'));
  mkdirSync(join(root, 'bin'));
  writeFileSync(join(root, 'bin', 'git'), '#!/bin/sh\necho "$*" >> "$LOGF"\n');
  chmodSync(join(root, 'bin', 'git'), 0o755);
  return root;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * THE GENERATOR
 * ------------------------------------------------------------------------------------------------------------- */

function random(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface Part {
  /** makefile lines before the rule that uses the variable */
  head?: string[];
  files?: Record<string, string>;
  /** command-line words after the goal / before it, and the environment prefix */
  args?: string[];
  env?: string;
  /** the goal; `run` unless a setter needs another */
  goal?: string;
}

const noise = (r: () => number): string[] =>
  [
    [],
    ['# a comment'],
    [''],
    ['.PHONY: run'],
    ['-include nosuch.mk'],
    ['X = a \\', 'b'],
    ['X = a\\\\', 'Y = b'],
    ['%.o: %.c', `${T}@echo compile`],
    ['OTHER = $(shell echo hi)'],
    ['ifdef NOSUCH', 'X = 1', 'endif'],
  ][Math.floor(r() * 10)]!;

/** how CMD comes to hold the act P - each one a way the kernel's reader once did not see the assignment, or saw the wrong one */
function setters(P: string): Array<{ name: string; make: (decoy: boolean) => Part }> {
  const dec = (decoy: boolean): string[] => (decoy ? ['CMD = echo safe'] : []);
  return [
    { name: 'plain =', make: (d) => ({ head: [...dec(d), `CMD = ${P}`] }) },
    { name: ':=', make: (d) => ({ head: [...dec(d), `CMD := ${P}`] }) },
    { name: '?= (undefined)', make: () => ({ head: [`CMD ?= ${P}`] }) },
    { name: '+=', make: (d) => ({ head: [d ? 'CMD = echo safe' : 'CMD =', `CMD += ; ${P}`] }) },
    { name: 'override', make: (d) => ({ head: [...dec(d), `override CMD = ${P}`] }) },
    { name: 'export', make: (d) => ({ head: [...dec(d), `export CMD = ${P}`] }) },
    { name: 'tab-indented', make: (d) => ({ head: [...dec(d), `${T}CMD = ${P}`] }) },
    { name: 'tab-indented in a conditional', make: (d) => ({ head: [...dec(d), `${T}ifndef NOSUCH`, `CMD = ${P}`, `${T}endif`] }) },
    { name: 'computed name', make: (d) => ({ head: [...dec(d), 'N = CMD', `$(N) = ${P}`] }) },
    { name: 'computed name, simply expanded', make: (d) => ({ head: [...dec(d), 'N = CM', `$(N)D := ${P}`] }) },
    { name: 'define', make: (d) => ({ head: [...dec(d), 'define CMD', P, 'endef'] }) },
    { name: 'include', make: (d) => ({ head: [...dec(d), 'include inc.mk'], files: { 'inc.mk': `CMD = ${P}\n` } }) },
    { name: 'include declined by ?=', make: () => ({ head: [`CMD = ${P}`, 'include inc.mk'], files: { 'inc.mk': 'CMD ?= echo safe\n' } }) },
    { name: 'include declined by ifndef', make: () => ({ head: [`CMD = ${P}`, 'include inc.mk'], files: { 'inc.mk': 'ifndef CMD\nCMD = echo safe\nendif\n' } }) },
    { name: 'conditional', make: (d) => ({ head: [...dec(d), 'ifndef NOSUCH', `CMD = ${P}`, 'else', 'CMD = echo safe', 'endif'] }) },
    { name: 'conditional else', make: (d) => ({ head: [...dec(d), 'ifdef NOSUCH', 'CMD = echo safe', 'else', `CMD = ${P}`, 'endif'] }) },
    { name: 'line after an even run of backslashes', make: (d) => ({ head: [...dec(d), 'Z = z\\\\', `CMD = ${P}`] }) },
    { name: 'command line =', make: () => ({ head: ['CMD = echo safe'], args: [`'CMD=${P}'`] }) },
    { name: 'command line :=', make: () => ({ head: ['CMD = echo safe'], args: [`'CMD:=${P}'`] }) },
    { name: 'command line ?=', make: () => ({ head: ['CMD = echo safe'], args: [`'CMD?=${P}'`] }) },
    { name: 'command line, spelled out', make: () => ({ head: ['CMD = echo safe'], args: [`'CMD = ${P}'`] }) },
    { name: 'command line, twice', make: () => ({ head: ['CMD = echo safe'], args: ['CMD=true', `'CMD=${P}'`] }) },
    { name: 'environment', make: () => ({ head: ['CMD ?= echo safe'], env: `CMD='${P}' ` }) },
    { name: 'environment with -e', make: () => ({ head: ['CMD = echo safe'], env: `CMD='${P}' `, args: ['-e'] }) },
    { name: 'shell at parse time', make: (d) => ({ head: [...dec(d), `CMD := $(shell ${P})`] }) },
    { name: 'shell at parse time in a define', make: (d) => ({ head: [...dec(d), 'define RUN', `$(shell ${P})`, 'endef', 'CMD := $(call RUN)'] }) },
    { name: 'shell at parse time, name computed', make: (d) => ({ head: [...dec(d), 'define RUN', `$(shell ${P})`, 'endef', 'N = RUN', 'CMD := $($(N))'] }) },
    { name: 'eval', make: (d) => ({ head: [...dec(d), `$(eval CMD = ${P})`] }) },
    { name: 'target-specific', make: (d) => ({ head: [...dec(d), `run: CMD = ${P}`] }) },
    { name: 'a second makefile', make: (d) => ({ head: [...dec(d), 'include a.mk'], files: { 'a.mk': 'include b.mk\n', 'b.mk': `CMD = ${P}\n` } }) },
    { name: 'a variable that says which file to include', make: (d) => ({ head: [...dec(d), 'F = inc.mk', 'include $(F)'], files: { 'inc.mk': `CMD = ${P}\n` } }) },
  ];
}

/** how the recipe reads CMD */
const users: Array<{ name: string; line: string; head?: string[] }> = [
  { name: '$(CMD)', line: '$(CMD)' },
  { name: '${CMD}', line: '${CMD}' },
  { name: '@$(CMD)', line: '@$(CMD)' },
  { name: '-$(CMD)', line: '-$(CMD)' },
  { name: 'strip', line: '$(strip $(CMD))' },
  { name: 'if', line: '$(if 1,$(CMD),no)' },
  { name: 'foreach', line: '$(foreach i,1,$(CMD))' },
  { name: 'subst', line: '$(subst x,y,$(CMD))' },
  { name: 'patsubst', line: '$(patsubst %.nosuch,%.o,$(CMD))' },
  { name: 'substitution reference', line: '$(CMD:.nosuch=.o)' },
  { name: 'through a recursive variable', line: '$(RUN)', head: ['RUN = $(CMD)'] },
  { name: 'through a simple variable', line: '$(RUN)', head: ['RUN := $(CMD)'] },
  { name: 'through call', line: '$(call exec)', head: ['exec = $(CMD)'] },
  { name: 'through call with an argument', line: '$(call exec,1)', head: ['exec = $(CMD) $(1)'] },
  { name: 'through value', line: '$(value CMD)' },
  { name: 'in a canned recipe', line: '$(CANNED)', head: ['define CANNED', '@echo a', '$(CMD)', 'endef'] },
  { name: 'after a semicolon', line: 'true; $(CMD)' },
  { name: 'inside a loop', line: 'for i in 1; do $(CMD); done' },
  { name: 'with a continuation', line: 'true && \\\n\t$(CMD)' },
  { name: 'through a computed name', line: '$($(NAME))', head: ['NAME = CMD'] },
];

export function generateCases(seed: number, count: number): OracleCase[] {
  const r = random(seed);
  const out: OracleCase[] = [];
  for (let n = 0; n < count; n++) {
    const tag = `s${seed}n${n}`;
    const P = `git push origin ${tag}`;
    const all = setters(P);
    const setter = all[Math.floor(r() * all.length)]!;
    const user = users[Math.floor(r() * users.length)]!;
    const part = setter.make(r() < 0.7);
    const lines = [...(part.head ?? []), ...noise(r), ...(user.head ?? []), 'run:', `${T}${user.line}`];
    const args = [...(part.args ?? [])];
    const flags = args.filter((a) => a.startsWith('-'));
    const defs = args.filter((a) => !a.startsWith('-'));
    const cmd = `${part.env ?? ''}make ${[...flags, ...defs, 'run'].join(' ')}`;
    out.push({ name: `${setter.name} / ${user.name}`, files: { Makefile: lines.join('\n') + '\n', ...(part.files ?? {}) }, cmd, tag });
  }
  return out;
}

/** The cases that put the act where make's OWN rules run it: a built-in rule whose program a variable names, a recipe-less rule, a default
 *  goal behind a pattern rule, a `.DEFAULT`. */
export function implicitCases(): OracleCase[] {
  const mk = (name: string, tag: string, files: Record<string, string>, cmd: string): OracleCase => ({ name, files, cmd, tag });
  const P = (t: string): string => `git push origin ${t}`;
  return [
    mk('CC with a comment', 'i1', { Makefile: `CC = ${P('i1')} #\n`, 'foo.c': 'x' }, 'make foo'),
    mk('COMPILE.c', 'i2', { Makefile: `COMPILE.c = ${P('i2')} ;\n`, 'foo.c': 'x' }, 'make foo.o'),
    mk('LINK.c', 'i3', { Makefile: `LINK.c = ${P('i3')} ;\n`, 'foo.c': 'x' }, 'make foo'),
    mk('a prerequisite', 'i4', { Makefile: `CC = ${P('i4')} ;\nall: foo.o\n`, 'foo.c': 'x' }, 'make all'),
    mk('a recipe-less rule', 'i5', { Makefile: `CC = ${P('i5')} ;\nall: foo.o\nfoo.o: foo.h\n`, 'foo.c': 'x', 'foo.h': 'x' }, 'make all'),
    mk('no makefile, command line CC', 'i6', { 'foo.c': 'x' }, `make 'CC=${P('i6')} #' foo`),
    mk('no makefile, command line CC as a script', 'i7', { 'foo.c': 'x', 'tool.sh': `#!/bin/sh\n${P('i7')}\n` }, 'make CC=./tool.sh foo'),
    mk('LEX', 'i8', { Makefile: `LEX = ${P('i8')} ;\n`, 'foo.l': '%%\n' }, 'make foo.c'),
    mk('CFLAGS', 'i9', { Makefile: `CFLAGS = ; ${P('i9')}\n`, 'foo.c': 'x' }, 'make foo'),
    mk('a default goal behind a pattern rule', 'i10', { Makefile: `%.o: %.c\n${T}@echo c\nall:\n${T}${P('i10')}\n` }, 'make'),
    mk('.DEFAULT', 'i11', { Makefile: `.DEFAULT:\n${T}${P('i11')}\n` }, 'make anything'),
    mk('a suffix rule', 'i12', { Makefile: `.c.o:\n${T}${P('i12')}\n`, 'foo.c': 'x' }, 'make foo.o'),
    mk('a static pattern rule', 'i13', { Makefile: `OBJ = foo.o\nall: $(OBJ)\n$(OBJ): %.o: %.c\n${T}${P('i13')}\n`, 'foo.c': 'x' }, 'make all'),
    mk('a pattern rule with a stem in the command', 'i14', { Makefile: `all: foo.run\n%.run:\n${T}${P('i14')} $*\n` }, 'make all'),
    mk('the second of two pattern rules', 'i15', { Makefile: `all: x.o\n%.o: %.c\n${T}@echo c\n%.o: %.cc\n${T}${P('i15')}\n`, 'x.cc': 'x' }, 'make all'),
    mk('$(MAKE) with a variable', 'i16', { Makefile: `run:\n${T}$(MAKE) inner CMD='${P('i16')}'\ninner:\n${T}$(CMD)\n` }, 'make run'),
    mk('$(MAKE) -C', 'i17', { Makefile: `run:\n${T}$(MAKE) -C sub\n`, 'sub/Makefile': `all:\n${T}${P('i17')}\n` }, 'make run'),
    mk('a conditional value read at parse time', 'i18', { Makefile: `ifndef NOSUCH\nCMD = ${P('i18')}\nelse\nCMD = echo safe\nendif\nX := $(shell $(CMD))\nall: ; @echo\n` }, 'make all'),
    mk('a conditional value read at parse time, the act in the else', 'i19', { Makefile: `ifdef NOSUCH\nCMD = echo safe\nelse\nCMD = ${P('i19')}\nendif\nX := $(shell $(CMD))\nall: ; @echo\n` }, 'make all'),
    mk('a command whose text comes from the environment', 'i20', { Makefile: 'X := $(shell $(NOPE))\nall: ; @echo\n' }, `NOPE='${P('i20')}' make all`),
    mk('the default goal named on the command line', 'i21', { Makefile: `safe: ; @echo\ndeploy:\n${T}${P('i21')}\n` }, 'make .DEFAULT_GOAL=deploy'),
    mk('a definition that is not a goal', 'i22', { Makefile: `all:\n${T}${P('i22')}\n` }, "make 'A B=c'"),
  ];
}
