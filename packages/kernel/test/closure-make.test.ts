// CLOSURE AUDIT 2026-10-01, WAVE 2 - ROOT CAUSE "MAKE": WHAT MAKEFILE TEXT WILL MAKE EXECUTE, AND WAS ANY OF IT WRITTEN OR CAN ANY
// OF IT BE REWRITTEN BEFORE OR WHILE IT RUNS?
//
// Eight reviewed findings (r11-34 35 36 37 44 45 53 132) were one question asked in eight places. The freshness ledger answers
// "is this path stale" for a makefile read after a write on the same line; each finding is a way the answer was never asked or
// was asked of the wrong file:
//
//   A. a recursion re-enters an invocation it is inside of: the cycle guard took the second pass for a repeat of the first, so a
//      makefile rewritten in between (r11-35), a sub-makefile replaced and read again (r11-36) and a command line that a
//      conditional changed (r11-34) were never read. The guard now asks the ledger, and the key carries the environment.
//   B. a makefile that is REMADE: `-include gen.mk` with `%.mk: %.in` is a rule that builds the include, not a rule with its name
//      (r11-37). One reader (remadeBy) answers "can a rule of this makefile build this file" for the first makefile and for every
//      include.
//   C. a shell function runs when it is called, not where it is defined: the body was analysed against the files and the
//      directory of the definition (r11-44).
//   D. a writer's destination is read in the directory the writer runs in - `env -C sub cp ../evil.mk Makefile` (r11-45).
//   E. `make -f ev*.mk`: the shell expands the glob, make opens the match; a word that names no file is unresolved, never absent
//      (r11-53).
//   F. an `=` in a sed script is not a reason to drop the script from the writer's operands, and the file with it (r11-132).
//
// ...and three neighbours of the same question that the eight findings did not name but that follow from it:
//
//   G. `make -j` runs recipes at the same time, so a read may come after a write that is later in the text.
//   H. `-I DIR` is part of where an `include` is looked for.
//   I. a pipeline and a background job run while the stages after them do.
//   J. the words of a redirection are not make goals - `make 2>&1` ran under a proof that its "goal" `2>&1` had no rule.
//   K. a command the makefile runs while it is read (`$(shell cp gen.in gen.mk)` above an include) may write what it reads next.
//   L. a deletion is a write: `rm GNUmakefile && make` makes the next makefile in make's order the one that runs.
//
// The verdicts below are what a reader must give. `DENY` means the act is READ (the makefile is on the disk and nothing can have
// changed it); `ASK` means something runs that could not be read; `ALLOW` is the control that must stay as it was.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { workspace, verdict } from './support/corpus.ts';

/** an absolute-class act: "read" (DENY), "hidden" (ALLOW) and "gated unread" (ASK) are three different answers */
const ACT = 'git push origin main';
const EVIL = `all:\n\t${ACT}\n`;
const OK = 'all:\n\techo ok\n';

/** `GATED` is "not ALLOW": the act is not readable here, or is read and refused - the test is about the gate, not which side of it */
type Want = 'ALLOW' | 'ASK' | 'DENY' | 'GATED';
type Row = [label: string, command: string, files: Record<string, string>, want: Want];

function check(rows: readonly Row[]): void {
  const wrong: string[] = [];
  for (const [label, command, files, want] of rows) {
    const got = verdict(command, workspace(files));
    if (want === 'GATED' ? got === 'ALLOW' : got !== want) wrong.push(`${label}: ${command.replace(/\n/g, '\\n')} -> ${got}, wanted ${want}`);
  }
  assert.deepEqual(wrong, []);
}

/* ------------------------------------------------------------------------------------------------------------- *
 * A. A RECURSION IS A SECOND PASS, NOT A REPEAT
 * ------------------------------------------------------------------------------------------------------------- */

// r11-34: the nested make is started with a variable the makefile's `?=` leaves alone, so its `$(CMD)` is another command
const CONDITIONAL_NEXT = `CMD ?= echo hi\nifeq ($(CMD),echo hi)\nNEXT = CMD="${ACT}" make run\nelse\nNEXT = true\nendif\nrun:\n\t$(CMD)\n\t$(NEXT)\n`;

test('A. a recursive make started with a variable the makefile reads is a different invocation (r11-34)', () => {
  check([
    ['the reported conditional', 'make run', { Makefile: CONDITIONAL_NEXT }, 'DENY'],
    ['the unbounded spelling', 'make run', { Makefile: `CMD ?= echo hi\nrun:\n\t$(CMD)\n\tCMD="${ACT}" make run\n` }, 'DENY'],
    ['through env', 'make run', { Makefile: `CMD ?= echo hi\nrun:\n\t$(CMD)\n\tenv CMD="${ACT}" make run\n` }, 'DENY'],
    // ($(MAKE) is a variable this resolver does not read, so a recipe line that spells it asks - it never allows)
    ['through $(MAKE)', 'make run', { Makefile: `CMD ?= echo hi\nrun:\n\t$(CMD)\n\tCMD="${ACT}" $(MAKE) run\n` }, 'GATED'],
    ['through an export', 'make run', { Makefile: `CMD ?= echo hi\nrun:\n\t$(CMD)\n\texport CMD="${ACT}"; make run\n` }, 'GATED'],
    ['the command-line spelling', 'make run', { Makefile: `CMD ?= echo hi\nrun:\n\t$(CMD)\n\tmake run CMD="${ACT}"\n` }, 'DENY'],
    ['the command-line spelling through $(MAKE)', 'make run', { Makefile: `CMD ?= echo hi\nrun:\n\t$(CMD)\n\t$(MAKE) run CMD="${ACT}"\n` }, 'GATED'],
    // a one-word value is the spelling every shape of the environment carries alike: `sh a` runs the file a
    ['a one-word value, inline', 'make run', { Makefile: 'CMD ?= echo hi\nrun:\n\t$(CMD) a\n\tCMD=sh make run\n', a: `${ACT}\n` }, 'DENY'],
    ['a one-word value, through env', 'make run', { Makefile: 'CMD ?= echo hi\nrun:\n\t$(CMD) a\n\tenv CMD=sh make run\n', a: `${ACT}\n` }, 'DENY'],
    ['a one-word value, through export', 'make run', { Makefile: 'CMD ?= echo hi\nrun:\n\t$(CMD) a\n\texport CMD=sh; make run\n', a: `${ACT}\n` }, 'DENY'],
    ['a one-word value, through export and &&', 'make run', { Makefile: 'CMD ?= echo hi\nrun:\n\t$(CMD) a\n\texport CMD=sh && make run\n', a: `${ACT}\n` }, 'DENY'],
    ['under -e the environment beats the makefile\'s own =', 'make run', { Makefile: `CMD = echo hi\nrun:\n\t$(CMD)\n\tCMD="${ACT}" make -e run\n` }, 'DENY'],
    [
      'the branch a variable picks is a different makefile',
      'make run',
      { Makefile: 'ifdef PICK\nNEXT = make -f other.mk run\nelse\nNEXT = true\nendif\nrun:\n\t$(NEXT)\n', 'other.mk': `run:\n\t${ACT}\n` },
      'DENY',
    ],
    [
      'the branch a variable picks is another directory',
      'make run',
      { Makefile: 'ifdef PICK\nNEXT = make -C sub run\nelse\nNEXT = true\nendif\nrun:\n\t$(NEXT)\n', 'sub/Makefile': `run:\n\t${ACT}\n` },
      'DENY',
    ],
    [
      'two levels down, still the environment',
      'make run',
      { Makefile: `CMD ?= echo hi\nrun:\n\t$(CMD)\n\tmake -C sub run\n`, 'sub/Makefile': `CMD ?= echo hi\nrun:\n\t$(CMD)\n\tCMD="${ACT}" make run\n` },
      'DENY',
    ],
  ]);
});

// r11-35: the recipe rewrites the makefile and then runs make again, which reads the new one
test('A. a recipe that rewrites the makefile and runs make again reads the new makefile (r11-35)', () => {
  const again = ['make run', '$(MAKE) run', 'make -f Makefile run', 'make --no-print-directory run', '+make run', '-make run', '@make run', 'make -s run'];
  const rewrite = [
    'cp evil.mk Makefile',
    'mv evil.mk Makefile',
    "sed -i 's/true/false/' Makefile",
    "printf 'run:\\n\\t" + ACT + "\\n' > Makefile",
    'cat evil.mk > Makefile',
    'install evil.mk Makefile',
    'tee Makefile < evil.mk',
    'cp evil.mk GNUmakefile',
    'ln -sf evil.mk Makefile',
    'dd if=evil.mk of=Makefile',
  ];
  const rows: Row[] = [];
  for (const w of rewrite) rows.push([`rewritten by ${w}`, 'make run', { Makefile: `run:\n\t${w}\n\tmake run\n`, 'evil.mk': `run:\n\t${ACT}\n` }, 'ASK']);
  for (const a of again) rows.push([`re-entered as ${a}`, 'make run', { Makefile: `run:\n\tcp evil.mk Makefile\n\t${a}\n`, 'evil.mk': `run:\n\t${ACT}\n` }, 'ASK']);
  rows.push(['the rewrite on the same line as the re-entry', 'make run', { Makefile: `run:\n\tcp evil.mk Makefile && make run\n`, 'evil.mk': `run:\n\t${ACT}\n` }, 'ASK']);
  rows.push(['a rewrite and a re-entry in two targets', 'make run', { Makefile: `run: prep\n\tmake run2\nprep:\n\tcp evil.mk Makefile\nrun2:\n\tmake run\n`, 'evil.mk': `run:\n\t${ACT}\n` }, 'ASK']);
  check(rows);
});

// r11-36: the sub-makefile is replaced and the whole invocation runs a second time
test('A. a second pass of a recipe runs the makefile the first pass replaced (r11-36)', () => {
  const sub = { 'sub/Makefile': OK, 'evil.mk': EVIL };
  check([
    ['the reported stamp file', 'make run', { Makefile: 'run:\n\tmake -C sub all\n\tcp evil.mk sub/Makefile\n\t[ -e stamp ] || { touch stamp; make run; }\n', ...sub }, 'ASK'],
    ['test -e', 'make run', { Makefile: 'run:\n\tmake -C sub all\n\tcp evil.mk sub/Makefile\n\ttest -e stamp || { touch stamp; make run; }\n', ...sub }, 'ASK'],
    ['an if', 'make run', { Makefile: 'run:\n\tmake -C sub all\n\tcp evil.mk sub/Makefile\n\tif [ ! -f stamp ]; then touch stamp; make run; fi\n', ...sub }, 'ASK'],
    ['mv instead of cp', 'make run', { Makefile: 'run:\n\tmake -C sub all\n\tmv evil.mk sub/Makefile\n\t[ -e stamp ] || { touch stamp; make run; }\n', ...sub }, 'ASK'],
    ['sed -i instead of cp', 'make run', { Makefile: "run:\n\tmake -C sub all\n\tsed -i 's/ok/ok; git push origin main/' sub/Makefile\n\t[ -e stamp ] || { touch stamp; make run; }\n", ...sub }, 'ASK'],
    ['a redirection instead of cp', 'make run', { Makefile: 'run:\n\tmake -C sub all\n\tcat evil.mk > sub/Makefile\n\t[ -e stamp ] || { touch stamp; make run; }\n', ...sub }, 'ASK'],
    ['$(MAKE) for the re-entry', 'make run', { Makefile: 'run:\n\tmake -C sub all\n\tcp evil.mk sub/Makefile\n\t[ -e stamp ] || { touch stamp; $(MAKE) run; }\n', ...sub }, 'ASK'],
    [
      'through an npm script (the same guard)',
      'npm run build',
      { 'package.json': JSON.stringify({ scripts: { build: 'make -C sub all && cp evil.mk sub/Makefile && ([ -e stamp ] || (touch stamp && npm run build))' } }), ...sub },
      'ASK',
    ],
    [
      'through a shell script',
      './go.sh',
      { 'go.sh': '#!/bin/sh\nmake -C sub all\ncp evil.mk sub/Makefile\n[ -e stamp ] || { touch stamp; ./go.sh; }\n', ...sub },
      'ASK',
    ],
  ]);
});

test('A. a recursion that writes nothing, or enters another directory, is not gated', () => {
  check([
    ['a sub-make in another directory', 'make all', { Makefile: 'all:\n\tmake -C sub all\n', 'sub/Makefile': OK }, 'ALLOW'],
    ['a recursion on another goal', 'make all', { Makefile: 'all:\n\tmake other\nother:\n\techo ok\n' }, 'ALLOW'],
    ['clean then build', 'make all', { Makefile: 'all: clean\n\tmake build\nclean:\n\trm -rf build\nbuild:\n\techo ok\n' }, 'ALLOW'],
    ['a recipe that writes a build output and runs another goal', 'make all', { Makefile: 'all:\n\techo x > out.txt\n\tmake other\nother:\n\techo ok\n' }, 'ALLOW'],
    ['a sub-make that reads a parent makefile and writes only its output', 'make all', { Makefile: 'all:\n\tmake -C sub all\n', 'sub/Makefile': 'all:\n\techo ok > out.txt\n' }, 'ALLOW'],
  ]);
});

test('A. a recursion that varies its command line without end stops at the bound and asks', () => {
  // each level is a different invocation (the variable grows), so the cycle guard never closes it; the depth bound does
  const rows: Row[] = [
    ['a growing variable', 'make run', { Makefile: 'V ?= a\nrun:\n\techo $(V)\n\tmake run V=$(V)a\n' }, 'ASK'],
    ['a growing variable through the environment', 'make run', { Makefile: 'V ?= a\nrun:\n\techo $(V)\n\tV=$(V)a make run\n' }, 'ASK'],
    ['a growing directory', 'make run', { Makefile: 'run:\n\tmake -C sub run\n', 'sub/Makefile': 'run:\n\tmake -C sub run\n', 'sub/sub/Makefile': 'run:\n\tmake -C sub run\n', 'sub/sub/sub/Makefile': 'run:\n\tmake -C sub run\n', 'sub/sub/sub/sub/Makefile': 'run:\n\tmake -C sub run\n', 'sub/sub/sub/sub/sub/Makefile': 'run:\n\techo end\n' }, 'ASK'],
  ];
  check(rows);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * B. A MAKEFILE THAT A RULE OF THE MAKEFILE REMAKES
 * ------------------------------------------------------------------------------------------------------------- */

test('B. an include built by a rule of the makefile is a pre-image of what runs (r11-37)', () => {
  const gen = { 'gen.in': EVIL.replace('all:', 'all::') };
  const top = (include: string, rule: string): string => `${include}\nall::\n\techo ok\n${rule}`;
  check([
    ['the reported pattern rule', 'make all', { Makefile: top('-include gen.mk', '%.mk: %.in\n\tcp $< $@\n'), ...gen }, 'ASK'],
    ['a plain include', 'make all', { Makefile: top('include gen.mk', '%.mk: %.in\n\tcp $< $@\n'), ...gen }, 'ASK'],
    ['sinclude', 'make all', { Makefile: top('sinclude gen.mk', '%.mk: %.in\n\tcp $< $@\n'), ...gen }, 'ASK'],
    ['the file already there and older than its source', 'make all', { Makefile: top('-include gen.mk', '%.mk: %.in\n\tcp $< $@\n'), ...gen, 'gen.mk': 'all::\n\techo old\n' }, 'ASK'],
    ['a suffix rule', 'make all', { Makefile: `.SUFFIXES: .in .mk\n${top('-include gen.mk', '.in.mk:\n\tcp $< $@\n')}`, ...gen }, 'ASK'],
    ['a literal rule', 'make all', { Makefile: top('-include gen.mk', 'gen.mk: gen.in\n\tcp gen.in gen.mk\n'), ...gen }, 'ASK'],
    ['a double-colon rule', 'make all', { Makefile: top('-include gen.mk', 'gen.mk:: gen.in\n\tcp gen.in gen.mk\n'), ...gen }, 'ASK'],
    ['a wildcard target', 'make all', { Makefile: top('-include gen.mk', 'gen*.mk: gen.in\n\tcp gen.in gen.mk\n'), ...gen }, 'ASK'],
    ['a target named by a variable', 'make all', { Makefile: `GEN := gen.mk\n${top('-include gen.mk', '$(GEN): gen.in\n\tcp gen.in gen.mk\n')}`, ...gen }, 'ASK'],
    ['a .DEFAULT rule', 'make all', { Makefile: top('-include gen.mk', '.DEFAULT:\n\tcp gen.in $@\n'), ...gen }, 'ASK'],
    ['the include in a directory', 'make all', { Makefile: top('-include sub/gen.mk', 'sub/%.mk: sub/%.in\n\tcp $< $@\n'), 'sub/gen.in': 'all::\n\techo x\n' }, 'ASK'],
    ['an include of an include', 'make all', { Makefile: top('include more.mk', ''), 'more.mk': '-include gen.mk\n%.mk: %.in\n\tcp $< $@\n', ...gen }, 'ASK'],
    ['a glob include whose match the rule can rebuild', 'make all', { Makefile: top('-include gen*.mk', '%.mk: %.in\n\tcp $< $@\n'), 'gen1.mk': 'all::\n\techo one\n', 'gen1.in': 'all::\n\techo two\n' }, 'ASK'],
    // (the glob is expanded before make remakes anything: a match the rule has no source for is read as it is)
    ['a glob include whose match the rule cannot rebuild', 'make all', { Makefile: top('-include gen*.mk', '%.mk: %.in\n\tcp $< $@\n'), 'gen1.mk': 'all::\n\techo one\n', ...gen }, 'ALLOW'],
    [
      'the recipe that remakes it is read, and it pushes',
      'make all',
      { Makefile: top('-include gen.mk', `%.mk: %.in\n\t${ACT}\n\tcp $< $@\n`), ...gen },
      'DENY',
    ],
    ['a dry run still remakes the makefile', 'make -n all', { Makefile: top('-include gen.mk', `%.mk: %.in\n\t${ACT}\n\tcp $< $@\n`), ...gen }, 'DENY'],
    ['the first makefile remade by a match-anything rule', 'make all', { Makefile: 'all:\n\techo ok\n%: %.in\n\tcp $< $@\n', 'Makefile.in': EVIL }, 'ASK'],
  ]);
});

test('B. an include no rule can build is read as it is, and nothing is gated', () => {
  check([
    ['a plain include', 'make all', { Makefile: 'include config.mk\nall:\n\techo $(X)\n', 'config.mk': 'X = ok\n' }, 'ALLOW'],
    ['a dependency include with an unrelated pattern rule', 'make all', { Makefile: '-include deps.d\nall:\n\techo ok\n%.o: %.c\n\tcc -c $<\n', 'a.c': 'int a;' }, 'ALLOW'],
    ['an optional include that is not there', 'make all', { Makefile: '-include local.mk\nall:\n\techo ok\n' }, 'ALLOW'],
    ['an include with a suffix rule for other files', 'make all', { Makefile: 'include config.mk\n.c.o:\n\tcc -c $<\nall:\n\techo ok\n', 'config.mk': 'X = 1\n' }, 'ALLOW'],
    // an implicit rule builds a file only when its prerequisites are there or can be made: a rule that cannot apply is not a remake
    ['a match-anything rule with no source for the makefile', 'make all', { Makefile: 'all:\n\techo ok\n%: %.sh\n\tsh $<\n' }, 'ALLOW'],
    ['a single-suffix rule with no source for the makefile', 'make all', { Makefile: 'all:\n\techo ok\n.c:\n\tcc -o $@ $<\n' }, 'ALLOW'],
    ['a pattern rule whose source is not there', 'make all', { Makefile: '-include gen.mk\nall::\n\techo ok\n%.mk: %.in\n\tcp $< $@\n' }, 'ALLOW'],
    ['...but one the same command line writes', 'cp base.in gen.in && make all', { Makefile: '-include gen.mk\nall::\n\techo ok\n%.mk: %.in\n\tcp $< $@\n', 'base.in': 'all::\n\techo x\n' }, 'ASK'],
    ['...or one that a rule of the makefile makes', 'make all', { Makefile: '-include gen.mk\nall::\n\techo ok\n%.mk: %.in\n\tcp $< $@\ngen.in:\n\tprintf "all::\\\\n\\\\techo x\\\\n" > $@\n' }, 'ASK'],
    ['a suffix rule whose source is not there', 'make all', { Makefile: '.SUFFIXES: .in .mk\n-include gen.mk\nall::\n\techo ok\n.in.mk:\n\tcp $< $@\n' }, 'ALLOW'],
    ['an optional include that holds the act, with no rule to remake it', 'make all', { Makefile: '-include gen.mk\nall::\n\techo ok\n', 'gen.mk': EVIL.replace('all:', 'all::') }, 'DENY'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * C. A FUNCTION RUNS WHERE IT IS CALLED
 * ------------------------------------------------------------------------------------------------------------- */

test('C. a function is read again at its call when a file or the directory moved since the definition (r11-44)', () => {
  const sub = { 'sub/Makefile': OK, 'evil.mk': EVIL };
  const root = { Makefile: OK, 'evil.mk': EVIL };
  check([
    ['the reported copy between the definition and the call', 'f() { make -C sub all; }; cp evil.mk sub/Makefile; f', sub, 'ASK'],
    ['mv', 'f() { make -C sub all; }; mv evil.mk sub/Makefile; f', sub, 'ASK'],
    ['sed -i', "f() { make -C sub all; }; sed -i 's/ok/ok; git push origin main/' sub/Makefile; f", sub, 'ASK'],
    ['a redirection', 'f() { make -C sub all; }; cat evil.mk > sub/Makefile; f', sub, 'ASK'],
    ['the function keyword', 'function f { make -C sub all; }; cp evil.mk sub/Makefile; f', sub, 'ASK'],
    ['a subshell body', 'f() ( make -C sub all ); cp evil.mk sub/Makefile; f', sub, 'ASK'],
    ['a call after &&', 'f() { make -C sub all; }; cp evil.mk sub/Makefile && f', sub, 'ASK'],
    ['two functions', 'c() { make all; }; g() { c; }; cp evil.mk Makefile; g', root, 'ASK'],
    ['three functions', 'c() { make all; }; g() { c; }; h() { g; }; cp evil.mk Makefile; h', root, 'ASK'],
    ['called twice', 'f() { make all; }; f; cp evil.mk Makefile; f', root, 'ASK'],
    ['the last definition is the one that runs', 'f() { make all; }; f() { make -C sub all; }; cp evil.mk sub/Makefile; f', { ...sub, Makefile: OK }, 'ASK'],
    ['inside a command substitution', 'f() { make all; }; cp evil.mk Makefile; echo $(f)', root, 'ASK'],
    ['in a pipeline', 'f() { make all; }; cp evil.mk Makefile; f | cat', root, 'ASK'],
    ['in a group', 'f() { make all; }; cp evil.mk Makefile; { f; }', root, 'ASK'],
    ['in a subshell', 'f() { make all; }; cp evil.mk Makefile; (f)', root, 'ASK'],
    ['in a loop', 'f() { make all; }; cp evil.mk Makefile; for i in 1 2; do f; done', root, 'ASK'],
    ['with an argument', 'f() { make -C "$1" all; }; cp evil.mk sub/Makefile; f sub', { ...sub, Makefile: OK }, 'ASK'],
    ['a different directory at the call', 'f() { make all; }; cd sub; f', { Makefile: OK, 'sub/Makefile': EVIL }, 'DENY'],
    ['a different directory, behind a pushd', 'f() { make all; }; pushd sub; f', { Makefile: OK, 'sub/Makefile': EVIL }, 'DENY'],
    ['a different directory in a subshell', 'f() { make all; }; (cd sub && f)', { Makefile: OK, 'sub/Makefile': EVIL }, 'DENY'],
    ['a script that defines and calls', './go.sh', { 'go.sh': '#!/bin/sh\nf() { make -C sub all; }\ncp evil.mk sub/Makefile\nf\n', ...sub }, 'ASK'],
    ['a make recipe that defines and calls', 'make run', { Makefile: 'run:\n\tf() { make -C sub all; }; cp evil.mk sub/Makefile; f\n', ...sub }, 'ASK'],
  ]);
});

test('C. a function whose files did not move is not read twice, and nothing is gated', () => {
  const root = { Makefile: OK, 'evil.mk': EVIL };
  check([
    ['defined and called at once', 'f() { make all; }; f', root, 'ALLOW'],
    ['an unrelated write between definition and call', 'f() { make all; }; echo x > out.txt; f', root, 'ALLOW'],
    ['called from a function', 'c() { make all; }; g() { c; }; g', root, 'ALLOW'],
    ['the call is the act itself', 'f() { make all; }; f', { Makefile: EVIL }, 'DENY'],
    ['a function redefined after the write is the one that runs', 'f() { make all; }; cp evil.mk Makefile; f() { echo hi; }; f', root, 'ALLOW'],
    ['a recursive function', 'f() { make all; [ -e stop ] || f; }; f', root, 'ALLOW'],
    ['a function that writes and calls itself stops', 'f() { touch x; [ -e stop ] || f; }; f', root, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * D. A WRITER'S DESTINATION IS READ IN THE DIRECTORY THE WRITER RUNS IN
 * ------------------------------------------------------------------------------------------------------------- */

test('D. a writer behind env -C writes into the directory it names (r11-45)', () => {
  const files = { Makefile: OK, 'sub/Makefile': OK, 'evil.mk': EVIL, 'sub/evil.mk': EVIL };
  const make = 'make -C sub all';
  check([
    ['the reported env -C', `env -C sub cp ../evil.mk Makefile && ${make}`, files, 'ASK'],
    ['env --chdir', `env --chdir=sub cp ../evil.mk Makefile && ${make}`, files, 'ASK'],
    ['env --chdir with a separate word', `env --chdir sub cp ../evil.mk Makefile && ${make}`, files, 'ASK'],
    ['a glued -C', `env -Csub cp ../evil.mk Makefile && ${make}`, files, 'ASK'],
    ['mv', `env -C sub mv evil.mk Makefile && ${make}`, files, 'ASK'],
    ['sed -i', `env -C sub sed -i 's/ok/ok; git push origin main/' Makefile && ${make}`, files, 'ASK'],
    ['tee', `env -C sub tee Makefile < evil.mk && ${make}`, files, 'ASK'],
    ['install', `env -C sub install ../evil.mk Makefile && ${make}`, files, 'ASK'],
    ['behind nice', `nice -n 5 env -C sub cp ../evil.mk Makefile && ${make}`, files, 'ASK'],
    ['behind time', `time env -C sub cp ../evil.mk Makefile && ${make}`, files, 'ASK'],
    ['behind command', `command env -C sub cp ../evil.mk Makefile && ${make}`, files, 'ASK'],
    ['behind timeout', `timeout 5 env -C sub cp ../evil.mk Makefile && ${make}`, files, 'ASK'],
    ['git -C writes into its directory too', `git -C sub checkout -- Makefile && ${make}`, files, 'ASK'],
    ['a directory nobody can resolve', `env -C "$D" cp ../evil.mk Makefile && ${make}`, files, 'ASK'],
    ['in a loop', `for i in 1 2; do ${make}; env -C sub cp ../evil.mk Makefile; done`, files, 'ASK'],
    ['in a function', `w() { env -C sub cp ../evil.mk Makefile; }; w && ${make}`, files, 'ASK'],
    ['from a make recipe', 'make top', { ...files, 'top.mk': '', Makefile: `top:\n\tenv -C sub cp ../evil.mk Makefile\n\t${make}\n` }, 'ASK'],
  ]);
});

test('D. a writer behind env -C does not stale the directory it is not in', () => {
  const files = { Makefile: OK, 'sub/Makefile': OK, 'evil.mk': EVIL };
  check([
    ['the file the writer did not touch is still fresh', 'env -C sub cp ../evil.mk Other.mk && make all', files, 'ALLOW'],
    ['env -C that writes nothing', 'env -C sub ls && make -C sub all', files, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * E. `-f` TAKES WHATEVER THE SHELL EXPANDS IT TO
 * ------------------------------------------------------------------------------------------------------------- */

test('E. a glob in -f is expanded against the directory, as the shell does (r11-53)', () => {
  const files = { Makefile: OK, 'evil.mk': EVIL, 'sub/evil.mk': EVIL };
  check([
    ['the reported star', 'make -f ev*.mk', files, 'DENY'],
    // (only a WHOLE unquoted word is expanded: `'ev*.mk'`, `--file=ev*.mk` and `-fev*.mk` reach make as they are and name no file -
    //  checked against GNU make 3.81, which answers "No such file" to each of them)
    ['quoted: the shell does not expand it', "make -f 'ev*.mk'", files, 'ALLOW'],
    ['a question mark', 'make -f ev?l.mk', files, 'DENY'],
    ['a bracket class', 'make -f ev[a-z]l.mk', files, 'DENY'],
    ['a negated class', 'make -f ev[!x]l.mk', files, 'DENY'],
    ['a POSIX class', 'make -f ev[[:alpha:]]l.mk', files, 'DENY'],
    ['--file= is one word, and the shell expands no part of it', 'make --file=ev*.mk', files, 'GATED'],
    ['--makefile', 'make --makefile ev*.mk', files, 'DENY'],
    ['-f glued is one word as well', 'make -fev*.mk', files, 'ALLOW'],
    ['a cluster ending in f', 'make -kf ev*.mk', files, 'DENY'],
    ['a glob in a directory component', 'make -f s*/evil.mk', files, 'DENY'],
    ['a dot-slash prefix', 'make -f ./e*l.mk', files, 'DENY'],
    ['a second -f', 'make -f Makefile -f ev*.mk', files, 'DENY'],
    ['an abbreviated long option, glued', 'make --fil=ev*.mk', files, 'ALLOW'],
    ['an abbreviated long option, separate', 'make --fil ev*.mk', files, 'DENY'],
    ['--makefile separate', 'make --makefile ev?l.mk', files, 'DENY'],
    ['-C is a word too: the directory the glob names is entered', 'make -C su* all', { Makefile: OK, 'sub/Makefile': EVIL }, 'DENY'],
    ['-C with a question mark', 'make -C s?b all', { Makefile: OK, 'sub/Makefile': EVIL }, 'DENY'],
    ['-C and -f together', 'make -C su* -f x.mk', { 'sub/x.mk': EVIL }, 'DENY'],
    ['--directory= is one word', 'make --directory=su* all', { Makefile: OK, 'sub/Makefile': EVIL }, 'ALLOW'],
    ['-C quoted', "make -C 'su*' all", { Makefile: OK, 'sub/Makefile': EVIL }, 'ALLOW'],
    ['-C with a directory created on the way', 'mkdir sub && cp evil.mk sub/Makefile && make -C su* all', { Makefile: OK, 'evil.mk': EVIL }, 'ASK'],
    ['after -C the glob is the shell\'s (the directory it stands in), the match is opened in -C', 'make -C sub -f ev*.mk', { ...files, 'sub/Makefile': OK }, 'DENY'],
    // (a dry run prints the recipe and does not run it - the glob is read, the act is not performed)
    ['a dry run is a dry run', 'make -n -f ev*.mk', files, 'ALLOW'],
  ]);
});

test('E. the glob is the same one behind every wrapper, and reads what the shell would not hide', () => {
  const files = { Makefile: OK, 'evil.mk': EVIL };
  const gen = EVIL.replace('all:', 'all::');
  check([
    ['nice', 'nice make -f ev*.mk', files, 'DENY'],
    ['env', 'env make -f ev*.mk', files, 'DENY'],
    ['sudo', 'sudo make -f ev*.mk', files, 'DENY'],
    ['sh -c', "sh -c 'make -f ev*.mk'", files, 'DENY'],
    ['bash -c', 'bash -c "make -f ev*.mk"', files, 'DENY'],
    ['inside a function', 'f() { make -f ev*.mk; }; f', files, 'DENY'],
    ['from a recipe', 'make top', { ...files, Makefile: 'top:\n\tmake -f ev*.mk\n' }, 'DENY'],
    // (a hidden file matches too: the shell hides it only until `dotglob` is set, and a file nobody read is the worse mistake)
    ['a hidden match', 'make -f *.mk', { Makefile: OK, '.evil.mk': EVIL }, 'DENY'],
    ['a pattern that begins with the dot', 'make -f .ev*.mk', { Makefile: OK, '.evil.mk': EVIL }, 'DENY'],
    // (the shell compares names as written: `E*` does not match `evil`, on any filesystem)
    ['a pattern of the wrong case', "make -f 'E*.mk'", files, 'ALLOW'],
    ['outside the workspace', 'make -f /etc/ma*.mk', { Makefile: OK }, 'ASK'],
    // (the shell expands braces first and the result is a pattern like any other)
    ['a brace range in a glob word', 'make -f ev*.m{k..k}', files, 'DENY'],
    ['a brace range at the front of a glob word', 'make -f {e..e}v*.mk', files, 'DENY'],
    ['a brace range in a glob -C', 'make -C su{b..b}* all', { Makefile: OK, 'sub/Makefile': EVIL }, 'DENY'],
    ['a glob include: a question mark', 'make all', { Makefile: 'include ev?l.mk\nall::\n\techo ok\n', 'evil.mk': gen }, 'DENY'],
    ['a glob include: a bracket class', 'make all', { Makefile: '-include ev[a-z]l.mk\nall::\n\techo ok\n', 'evil.mk': gen }, 'DENY'],
    ['a glob include: a directory component', 'make all', { Makefile: 'include s*/x.mk\nall::\n\techo ok\n', 'sub/x.mk': gen }, 'DENY'],
    ['a glob include under a directory that is not there', 'make all', { Makefile: '-include nosuch/*.mk\nall:\n\techo ok\n' }, 'ALLOW'],
  ]);
});

test('E. a glob no file matches yet is stale if an earlier segment writes one', () => {
  const files = { Makefile: OK };
  check([
    ['printf into the matching name', `printf 'all:\\n\\t${ACT}\\n' > evil.mk && make -f ev*.mk`, files, 'ASK'],
    ['cp into the matching name', 'cp Makefile evil.mk && make -f ev*.mk', files, 'ASK'],
    ['a directory made on the way', "mkdir s && printf 'all:\\n\\tgit push origin main\\n' > s/evil.mk && make -f s*/evil.mk", files, 'ASK'],
    ['a glob in the home directory', 'make -f ~/ev*.mk', files, 'ASK'],
    ['a glob behind a variable', 'make -f "$X"*.mk', files, 'ASK'],
    ['a glob behind a command substitution', 'make -f $(echo ev)*.mk', files, 'ASK'],
  ]);
});

test('E. a pattern with more matches than this reader follows is a gap, not an empty set', () => {
  const many: Record<string, string> = { Makefile: OK };
  for (let i = 0; i < 600; i++) many[`gen/m${i}.mk`] = OK;
  check([
    ['-f', "make -f gen/m*.mk", many, 'ASK'],
    ['an include', 'make all', { ...many, Makefile: 'include gen/m*.mk\nall::\n\techo ok\n' }, 'ASK'],
    ['a few hundred are read, and read as what they are', 'make all', { ...Object.fromEntries(Object.entries(many).slice(0, 301)), Makefile: '-include gen/m*.mk\nall:\n\techo ok\n' }, 'ALLOW'],
  ]);
});

test('E. a glob GOAL is expanded by the shell too: make dep* runs the target of the directory it names', () => {
  const dflt = { Makefile: `.PHONY: deploy\ndeploy:\n\t${ACT}\n`, 'deploy/keep': '' };
  check([
    ['a star', 'make dep*', dflt, 'DENY'],
    ['a question mark', 'make dep?oy', dflt, 'DENY'],
    ['a bracket', 'make de[p]loy', dflt, 'DENY'],
    ['a dot-slash prefix', 'make ./dep*', dflt, 'DENY'],
    ['behind -n it is a dry run', 'make -n dep*', dflt, 'ALLOW'],
    ['among other goals', 'make clean dep*', { ...dflt, Makefile: `${dflt.Makefile}clean:\n\trm -rf out\n` }, 'DENY'],
    ['behind a wrapper', 'nice make dep*', dflt, 'DENY'],
    ['inside sh -c', "sh -c 'make dep*'", dflt, 'DENY'],
    ['a file the same command creates', 'touch deploy && make dep*', { Makefile: dflt.Makefile }, 'ASK'],
    // (the shell hands make the word as it is when nothing matches, and make has no target of that name)
    ['nothing matches', 'make dep*', { Makefile: dflt.Makefile }, 'ALLOW'],
    ['a harmless match', 'make bu*', { Makefile: 'build:\n\techo ok\n', 'build/keep': '' }, 'ALLOW'],
    ['every file in the directory', 'make *', { Makefile: dflt.Makefile }, 'ALLOW'],
  ]);
});

test('E. a glob that matches nothing, or something harmless, is read as that', () => {
  check([
    ['no match: make is told a file that is not there', 'make -f nomatch*.mk', { Makefile: EVIL }, 'ALLOW'],
    ['a harmless match', 'make -f ok*.mk', { Makefile: EVIL, 'ok1.mk': OK }, 'ALLOW'],
    ['the literal name still works', 'make -f evil.mk', { 'evil.mk': EVIL }, 'DENY'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * F. AN `=` IN A SCRIPT OR A FILE NAME DOES NOT HIDE THE WRITE
 * ------------------------------------------------------------------------------------------------------------- */

test('F. an in-place editor whose script holds an = still writes its file (r11-132)', () => {
  const files = { Makefile: 'CMD=true a\nbuild:\n\t$(CMD)\n', a: `${ACT}\n` };
  const edits = [
    "sed -i 's/^CMD=true/CMD=sh/' Makefile",
    "sed -i -e 's/^CMD=true/CMD=sh/' Makefile",
    "sed -i.bak 's/^CMD=true/CMD=sh/' Makefile",
    "sed --in-place=.bak 's/^CMD=true/CMD=sh/' Makefile",
    "sed --in-place 's/^CMD=true/CMD=sh/' Makefile",
    "sed -i '' 's/^CMD=true/CMD=sh/' Makefile",
    "sed -ni 's/^CMD=true/CMD=sh/p' Makefile",
    "sed -Ei 's/^CMD=true/CMD=sh/' Makefile",
    "sed -i 's/^CMD=true/CMD=sh/;s/a/a/' Makefile",
    "gsed -i 's/^CMD=true/CMD=sh/' Makefile",
    "perl -pi -e 's/^CMD=true/CMD=sh/' Makefile",
    "perl -i.bak -pe 's/^CMD=true/CMD=sh/' Makefile",
    "ruby -i -pe '$_.sub!(/CMD=true/, \"CMD=sh\")' Makefile",
  ];
  const rows: Row[] = edits.map((e) => [e, `${e} && make build`, files, 'ASK']);
  rows.push(['the spaced spelling, as before', "sed -i 's/^CMD = true/CMD = sh/' Makefile && make build", { Makefile: 'CMD = true a\nbuild:\n\t$(CMD)\n', a: `${ACT}\n` }, 'ASK']);
  rows.push(['through env -C', "env -C sub sed -i 's/^CMD=true/CMD=sh/' Makefile && make -C sub build", { 'sub/Makefile': 'CMD=true a\nbuild:\n\t$(CMD)\n', 'sub/a': `${ACT}\n` }, 'ASK']);
  check(rows);
});

test('F. a copy whose source name holds an = replaces its destination', () => {
  const files = { Makefile: OK, 'ev=il.mk': EVIL };
  check([
    ['cp', 'cp ev=il.mk Makefile && make all', files, 'ASK'],
    ['mv', 'mv ev=il.mk Makefile && make all', files, 'ASK'],
    ['install', 'install ev=il.mk Makefile && make all', files, 'ASK'],
    ['behind --', 'cp -- ev=il.mk Makefile && make all', files, 'ASK'],
    ['a destination with an =', 'cp Makefile m=k.mk && make -f m=k.mk all', { ...files, 'm=k.mk': OK }, 'ASK'],
    ['tee to a name with an =', 'tee m=k.mk < Makefile && make -f m=k.mk all', { ...files, 'm=k.mk': OK }, 'ASK'],
  ]);
});

test('F. an edit of another file leaves the makefile fresh', () => {
  check([
    ['sed -i on a source file', "sed -i 's/a=1/a=2/' main.c && make all", { Makefile: OK, 'main.c': 'int a=1;' }, 'ALLOW'],
    ['cp of a data file', 'cp ev=il.txt data.txt && make all', { Makefile: OK, 'ev=il.txt': 'x' }, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * G. RECIPES THAT RUN AT THE SAME TIME
 * ------------------------------------------------------------------------------------------------------------- */

test('G. under -j a recipe is read against the writes of every recipe, whatever order the text has them in', () => {
  const race = (extra = ''): Record<string, string> => ({
    Makefile: `${extra}all: build tamper\nbuild:\n\tsleep 1; make -C sub all\ntamper:\n\tcp evil.mk sub/Makefile\n`,
    'sub/Makefile': OK,
    'evil.mk': EVIL,
  });
  check([
    ['-j2', 'make -j2 all', race(), 'ASK'],
    ['-j with no number', 'make -j all', race(), 'ASK'],
    ['--jobs', 'make --jobs=4 all', race(), 'ASK'],
    ['--jobs with a separate number', 'make --jobs 4 all', race(), 'ASK'],
    ['a cluster ending in j', 'make -kj3 all', race(), 'ASK'],
    ['MAKEFLAGS in the makefile', 'make all', race('MAKEFLAGS += -j2\n'), 'ASK'],
    ['MAKEFLAGS with a long option', 'make all', race('MAKEFLAGS += --jobs=2\n'), 'ASK'],
    // (the recipe that replaces the makefile comes FIRST in the text, which the serial order already handles)
    ['the write is first in the text', 'make -j2 all', { ...race(), Makefile: 'all: tamper build\ntamper:\n\tcp evil.mk sub/Makefile\nbuild:\n\tmake -C sub all\n' }, 'ASK'],
  ]);
});

test('G. without -j, or with -j1, the recipes run one after the other and are read in that order', () => {
  const ordered = {
    Makefile: 'all: build tamper\nbuild:\n\tmake -C sub all\ntamper:\n\tcp evil.mk sub/Makefile\n',
    'sub/Makefile': OK,
    'evil.mk': EVIL,
  };
  check([
    ['serial', 'make all', ordered, 'ALLOW'],
    ['-j1', 'make -j1 all', ordered, 'ALLOW'],
    ['--jobs=1', 'make --jobs=1 all', ordered, 'ALLOW'],
    ['-j that writes nothing anyone reads', 'make -j4 all', { Makefile: 'all: a b\na:\n\techo x > a.out\nb:\n\techo y > b.out\n' }, 'ALLOW'],
    ['-j with a sub-make that nothing rewrites', 'make -j4 all', { Makefile: 'all: a b\na:\n\tmake -C sub all\nb:\n\techo y > b.out\n', 'sub/Makefile': OK }, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * H. WHERE `include` LOOKS
 * ------------------------------------------------------------------------------------------------------------- */

test('H. an include that is not in the make directory is looked for in the -I directories', () => {
  const gen = { 'evil/gen.mk': `all::\n\t${ACT}\n` };
  const optional = '-include gen.mk\nall::\n\techo ok\n';
  check([
    ['-I DIR, optional include', 'make -I evil all', { Makefile: optional, ...gen }, 'DENY'],
    ['-IDIR glued', 'make -Ievil all', { Makefile: optional, ...gen }, 'DENY'],
    ['--include-dir=DIR', 'make --include-dir=evil all', { Makefile: optional, ...gen }, 'DENY'],
    ['--include-dir DIR', 'make --include-dir evil all', { Makefile: optional, ...gen }, 'DENY'],
    ['a plain include', 'make -I evil all', { Makefile: 'include gen.mk\nall::\n\techo ok\n', ...gen }, 'DENY'],
    ['sinclude', 'make -I evil all', { Makefile: 'sinclude gen.mk\nall::\n\techo ok\n', ...gen }, 'DENY'],
    ['the first directory that has it wins', 'make -I none -I evil all', { Makefile: optional, ...gen }, 'DENY'],
    ['the make directory comes first', 'make -I evil all', { Makefile: optional, 'gen.mk': 'all::\n\techo here\n', ...gen }, 'ALLOW'],
    ['a file written into the directory by the same command', `printf 'all::\\n\\t${ACT}\\n' > evil/gen.mk && make -I evil all`, { Makefile: optional, 'evil/keep': '' }, 'ASK'],
    ['an include directory nobody can resolve', 'make -I "$D" all', { Makefile: optional }, 'ASK'],
    ['no -I: the optional include stays absent', 'make all', { Makefile: optional, ...gen }, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * I. A PIPELINE AND A BACKGROUND JOB RUN WHILE THE STAGES AROUND THEM DO
 * ------------------------------------------------------------------------------------------------------------- */

test('I. a read in a background job or a pipeline sees the writes of the stages that run beside it', () => {
  const sub = { 'sub/Makefile': OK, 'evil.mk': EVIL };
  check([
    ['a background job and a copy after it', '(sleep 1; make -C sub all) & cp evil.mk sub/Makefile', sub, 'ASK'],
    ['a background make', 'make -C sub all & cp evil.mk sub/Makefile', sub, 'ASK'],
    ['a backgrounded list', 'sleep 1 && make -C sub all & cp evil.mk sub/Makefile', sub, 'ASK'],
    ['a background job and a redirection after it', '(sleep 1; make -C sub all) & cat evil.mk > sub/Makefile', sub, 'ASK'],
    ['nohup', 'nohup make -C sub all & cp evil.mk sub/Makefile', sub, 'ASK'],
    ['a write in the other end of a pipe', '(sleep 1; make -C sub all) | cat | tee sub/Makefile', sub, 'ASK'],
    ['a copy in a pipeline with the read', 'make -C sub all | cp evil.mk sub/Makefile', sub, 'ASK'],
    ['trap on exit', "trap 'make -C sub all' EXIT; cp evil.mk sub/Makefile", sub, 'ASK'],
    // (the controls: nothing is rewritten, or the copy is of something nobody reads)
    ['a background job and an unrelated write', 'make -C sub all & echo done > out.txt', sub, 'ALLOW'],
    ['a pipeline that writes a log', 'make -C sub all 2>&1 | tee build.log', sub, 'ALLOW'],
    ['a background job alone', 'make -C sub all &', sub, 'ALLOW'],
    ['sequential: the read is first and the shell waits for it', 'make -C sub all; cp evil.mk sub/Makefile', sub, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * J. A REDIRECTION IS NOT A GOAL
 * ------------------------------------------------------------------------------------------------------------- */

test('J. the words of a redirection are not make goals: the default goal still runs (found by the merged-redirect transformation)', () => {
  const dflt = { Makefile: EVIL };
  check([
    ['stderr merged', 'make 2>&1', dflt, 'DENY'],
    ['stdout to a file', 'make > build.log', dflt, 'DENY'],
    ['stdin from a file', 'make < /dev/null', dflt, 'DENY'],
    ['both to a file', 'make &> build.log', dflt, 'DENY'],
    ['appended', 'make >> build.log 2>&1', dflt, 'DENY'],
    ['merged, piped', 'make 2>&1 | tail', dflt, 'DENY'],
    ['merged, tee', 'make -j4 2>&1 | tee build.log', dflt, 'DENY'],
    ['with -f', 'make -f evil.mk 2>&1', { 'evil.mk': EVIL }, 'DENY'],
    ['with a glob -f', 'make -f ev*.mk 2>&1', { 'evil.mk': EVIL }, 'DENY'],
    ['the redirection first', 'make 2>&1 all', dflt, 'DENY'],
    ['a goal and a redirection', 'make all 2>&1', dflt, 'DENY'],
    ['to the null device', 'make >/dev/null 2>&1', dflt, 'DENY'],
    ['behind nice', 'nice make 2>&1', dflt, 'DENY'],
    ['inside sh -c', "sh -c 'make 2>&1'", dflt, 'DENY'],
    ['a dry run is a dry run', 'make -n 2>&1', dflt, 'ALLOW'],
    ['a quoted > is a goal', "make '>'", { Makefile: OK }, 'ALLOW'],
    ['no makefile: nothing runs', 'make 2>&1', {}, 'ALLOW'],
    ['a harmless default goal', 'make 2>&1 | tail', { Makefile: OK }, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * K. A COMMAND THE MAKEFILE RUNS WHILE IT IS READ
 * ------------------------------------------------------------------------------------------------------------- */

test('K. a command run at parse time that may write is a command that may write the makefile read after it', () => {
  const gen = { 'gen.in': 'all::\n\techo x\n' };
  check([
    ['$(shell) above an optional include', 'make all', { Makefile: 'X := $(shell cp gen.in gen.mk)\n-include gen.mk\nall::\n\techo ok\n', ...gen }, 'ASK'],
    ['$(shell) above a plain include', 'make all', { Makefile: 'X := $(shell cp gen.in gen.mk)\ninclude gen.mk\nall::\n\techo ok\n', ...gen }, 'ASK'],
    ['!= above an include', 'make all', { Makefile: 'X != cp gen.in gen.mk\n-include gen.mk\nall::\n\techo ok\n', ...gen }, 'ASK'],
    ['a redirection', 'make all', { Makefile: "X := $(shell echo 'all::' > gen.mk)\n-include gen.mk\nall::\n\techo ok\n" }, 'ASK'],
    ['a script', 'make all', { Makefile: 'X := $(shell ./gen.sh)\n-include local.mk\nall:\n\techo ok\n', 'gen.sh': '#!/bin/sh\necho hi\n' }, 'ASK'],
    ['find -exec', 'make all', { Makefile: "X := $(shell find . -name '*.in' -exec cp {} gen.mk \\;)\n-include gen.mk\nall::\n\techo ok\n" }, 'ASK'],
    [
      'the second -f file',
      'make -f a.mk -f b.mk all',
      { 'a.mk': 'X := $(shell cp gen.in b.mk)\nall::\n\techo a\n', 'b.mk': 'all::\n\techo b\n', ...gen },
      'ASK',
    ],
    ['an include that is already there is rewritten before it is read', 'make all', { Makefile: 'X := $(shell cp gen.in gen.mk)\ninclude gen.mk\nall::\n\techo ok\n', ...gen, 'gen.mk': 'all::\n\techo old\n' }, 'ASK'],
    // (the controls: a pure read does not write, and a command with nothing read after it has nothing to make stale)
    ['a version lookup', 'make all', { Makefile: 'VERSION := $(shell git describe --tags)\n-include local.mk\nall:\n\techo ok\n' }, 'ALLOW'],
    ['the date', 'make all', { Makefile: 'NOW := $(shell date +%s)\ninclude config.mk\nall:\n\techo ok\n', 'config.mk': 'X = 1\n' }, 'ALLOW'],
    ['uname', 'make all', { Makefile: 'OS := $(shell uname -s)\n-include local.mk\nall:\n\techo ok\n' }, 'ALLOW'],
    ['!= pwd', 'make all', { Makefile: 'D != pwd\n-include local.mk\nall:\n\techo ok\n' }, 'ALLOW'],
    ['a script and nothing read after it', 'make all', { Makefile: 'X := $(shell ./gen.sh)\nall:\n\techo ok\n', 'gen.sh': '#!/bin/sh\necho hi\n' }, 'ALLOW'],
  ]);
});

test('K. the file function writes a file while the makefile is read (GNU make 4)', () => {
  check([
    ['above an optional include', 'make all', { Makefile: '$(file >gen.mk,all::)\n-include gen.mk\nall::\n\techo ok\n' }, 'ASK'],
    ['in an assignment', 'make all', { Makefile: 'X := $(file >gen.mk,all::)\n-include gen.mk\nall::\n\techo ok\n' }, 'ASK'],
    ['with braces', 'make all', { Makefile: 'X := ${file >gen.mk,all::}\n-include gen.mk\nall::\n\techo ok\n' }, 'ASK'],
    ['appending', 'make all', { Makefile: 'X := $(file >>gen.mk,all::)\n-include gen.mk\nall::\n\techo ok\n' }, 'ASK'],
    ['in a recipe', 'make all', { Makefile: 'all:\n\t$(file >sub/Makefile,all:)\n\tmake -C sub all\n', 'sub/Makefile': OK }, 'ASK'],
    ['reading a file is not writing one', 'make all', { Makefile: 'X := $(file <gen.in)\nall:\n\techo ok\n', 'gen.in': 'hello' }, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * L. A DELETION IS A WRITE
 * ------------------------------------------------------------------------------------------------------------- */

test('L. a makefile that is removed or moved away is not read, and the next one in make\'s order is', () => {
  // make reads GNUmakefile, then makefile, then Makefile: removing the first makes the last the one that runs
  const two = { GNUmakefile: OK, Makefile: EVIL };
  check([
    ['rm', 'rm GNUmakefile && make all', two, 'ASK'],
    ['rm -f', 'rm -f GNUmakefile && make all', two, 'ASK'],
    ['unlink', 'unlink GNUmakefile && make all', two, 'ASK'],
    ['mv away', 'mv GNUmakefile gnu.bak && make all', two, 'ASK'],
    ['mv into a directory', 'mkdir -p old && mv GNUmakefile old/ && make all', two, 'ASK'],
    ['mv -t', 'mkdir -p old && mv -t old GNUmakefile && make all', two, 'ASK'],
    ['git rm', 'git rm -f GNUmakefile && make all', two, 'ASK'],
    ['git mv', 'git mv GNUmakefile gnu.bak && make all', two, 'ASK'],
    ['rm with a glob', 'rm GNU* && make all', two, 'ASK'],
    ['rm with a bracket', 'rm GNU[m]akefile && make all', two, 'ASK'],
    ['find -delete', 'find . -name GNUmakefile -delete && make all', two, 'ASK'],
    ['behind env -C', 'env -C sub rm GNUmakefile && make -C sub all', { 'sub/GNUmakefile': OK, 'sub/Makefile': EVIL }, 'ASK'],
    ['behind nice', 'nice rm GNUmakefile && make all', two, 'ASK'],
    ['in a function that is called before the make', 'f() { rm GNUmakefile; }; f && make all', two, 'ASK'],
    ['a directory removed whole', 'rm -rf sub && make -C sub all', { 'sub/Makefile': OK }, 'ASK'],
    ['an included makefile removed', 'rm gen.mk && make all', { Makefile: '-include gen.mk\nall::\n\techo ok\n', 'gen.mk': 'all::\n\techo one\n' }, 'ASK'],
    ['a -f file removed', 'rm a.mk && make -f a.mk -f b.mk all', { 'a.mk': 'all::\n\techo a\n', 'b.mk': 'all::\n\techo b\n' }, 'ASK'],
    // (the controls: what is removed is not read. `rm` with a glob or a variable asks by itself, whatever follows it)
    ['an unrelated file', 'rm -f out.log && make all', { Makefile: OK, 'out.log': 'x' }, 'ALLOW'],
    ['a build directory', 'rm -rf dist && make all', { Makefile: OK, 'dist/a': 'x' }, 'ALLOW'],
    ['a moved data file', 'mv a.txt b.txt && make all', { Makefile: OK, 'a.txt': 'x' }, 'ALLOW'],
  ]);
});
