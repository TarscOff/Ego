// CLOSURE AUDIT 2026-10-02, WAVE 6 - THE MAKE PRODUCER'S VARIABLES: WHAT TEXT DOES MAKE HAND THE SHELL, AND WHAT DOES IT RUN ON THE WAY?
//
// Ten findings of the wave-5 review (MK-01..MK-10) and a test gap (TG-01) were one question asked in ten places, and each defect was two readers
// of the same makefile disagreeing about it. Since wave 6 there is ONE of each (authority/make.ts, make-reader.ts, make-builtins.ts):
//
//   - the command line: every word that holds `=` is a variable definition, never a goal (MK-01);
//   - the lines: a tab-indented line outside a rule is a makefile line (MK-02), a backslash continues a line only when it is the odd one out
//     (MK-03), a variable's value ends at its `#` (MK-05);
//   - the variables: ONE store with make's origins and precedence, read in make's order - an include inline (MK-06), a computed name (MK-07),
//     `override` (MK-08), a define expanded where it is USED (MK-04), the built-in rules and variables make has before it reads anything (MK-05);
//   - the expansion: bounded (MK-09) and complete, so the ordinary makefile is read and not guessed at (MK-10).
//
// Every row below was written against the unfixed tree first and fails there. `GATED` is "not ALLOW": the act is read and refused, or it is not
// readable here - the test is about the gate. Where GNU make is installed, the second half checks the READER against the real program: a
// logging `git` on the PATH, the makefile run for real, and the kernel's verdict compared with what ran (skipped when `make` is not GNU make).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { workspace, verdict, ORDINARY_MAKEFILES } from './support/corpus.ts';
import { generateCases, implicitCases, oracleRoot, realMakeAvailable, runReal, siteCases } from './support/make-oracle.ts';
import {
  MakeStore,
  continues,
  cutMakeComment,
  encodeMakeParts,
  flagDefinitions,
  makeLogicalLines,
  parseMakeCommandLine,
  readAssignment,
  readMakeNames,
} from '../src/authority/make.ts';
import { MakeReader, newMakeModel } from '../src/authority/make-reader.ts';
import { BUILTIN_RULES, BUILTIN_SUFFIXES, BUILTIN_VARIABLES, builtinRulesFor } from '../src/authority/make-builtins.ts';

const T = '\t';
const ACT = 'git push origin main';

/** a store whose variables are the makefile's, as recursive text */
function storeWith(vars: Record<string, string>): MakeStore {
  const s = new MakeStore();
  for (const [k, v] of Object.entries(vars)) s.set(k, [v], { origin: 'file', simple: false, conditional: false });
  return s;
}

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

/** a makefile whose only way to run the act is the variable CMD, which a decoy line sets to something harmless first */
const WITH_DECOY = (before: string, after = ''): string => `CMD = echo safe\n${before}\nrun:\n${T}$(CMD)\n${after}`;

/* ------------------------------------------------------------------------------------------------------------- *
 * MK-01. A WORD THAT HOLDS `=` IS A VARIABLE DEFINITION TO MAKE, NEVER A GOAL
 * ------------------------------------------------------------------------------------------------------------- */

test('MK-01. every spelling of a command-line variable overrides the makefile, and none of them is a goal', () => {
  const mk = { Makefile: WITH_DECOY('') };
  check([
    ['the plain spelling (control)', `make 'CMD=${ACT}' run`, mk, 'DENY'],
    ['simply expanded', `make 'CMD:=${ACT}' run`, mk, 'DENY'],
    ['POSIX simply expanded', `make 'CMD::=${ACT}' run`, mk, 'DENY'],
    ['conditional', `make 'CMD?=${ACT}' run`, mk, 'DENY'],
    ['appended (the name is not defined on the command line yet)', `make 'CMD+=; ${ACT}' run`, mk, 'DENY'],
    ['one word with blanks around the operator', `make 'CMD = ${ACT}' run`, mk, 'DENY'],
    ['one word with a blank before the operator', `make 'CMD :=${ACT}' run`, mk, 'DENY'],
    ['the operator written with an escaped blank', `make CMD\\ =\\ git\\ push\\ origin\\ main run`, mk, 'DENY'],
    ['a shell assignment runs while make starts (GNU make 4)', `make 'X!=${ACT}' run`, { Makefile: `run:\n${T}@echo hi\n` }, 'DENY'],
    ['the last of two definitions is the one make uses', `make CMD=true 'CMD=${ACT}' run`, mk, 'DENY'],
    ['the last of three', `make 'CMD=${ACT}' CMD=true 'CMD=${ACT}' run`, mk, 'DENY'],
    ['a harmless command line stays harmless (control)', 'make CMD=true run', mk, 'ALLOW'],
    ['a harmless one after a governed one (the last wins)', `make 'CMD=${ACT}' CMD=true run`, mk, 'ALLOW'],
  ]);
});

test('MK-01. a command-line definition selects the default goal and the goals of a dependency', () => {
  const goals = { Makefile: `safe: ; @echo\ndeploy:\n${T}${ACT}\n` };
  const dep = { Makefile: `T = safe\nrun: $(T)\nsafe: ; @echo\ndeploy:\n${T}${ACT}\n` };
  check([
    ['.DEFAULT_GOAL on the command line', 'make .DEFAULT_GOAL=deploy', goals, 'DENY'],
    ['.DEFAULT_GOAL:=', 'make .DEFAULT_GOAL:=deploy', goals, 'DENY'],
    ['.DEFAULT_GOAL after --', 'make -- .DEFAULT_GOAL=deploy', goals, 'DENY'],
    ['.DEFAULT_GOAL beats an assignment in the makefile', 'make .DEFAULT_GOAL=deploy', { Makefile: `.DEFAULT_GOAL := safe\n${goals.Makefile}` }, 'DENY'],
    ['a prerequisite list built from a variable the command line sets', 'make T:=deploy run', dep, 'DENY'],
    ['...and the spelling that was a goal', 'make T?=deploy run', dep, 'DENY'],
    ['...and the spelled-out one', 'make T\\ =\\ deploy run', dep, 'DENY'],
    ['the default goal still runs when the only word is a definition', 'make A\\ B=c', { Makefile: `all:\n${T}${ACT}\n` }, 'DENY'],
    ['a goal and a definition', 'make safe T:=deploy', dep, 'ALLOW'],
  ]);
});

test('MK-01. what holds `=` is read by one function, and it names what make names', () => {
  const read = (w: string): string => JSON.stringify(readAssignment(w));
  assert.equal(read('CMD=x'), '{"name":"CMD","op":"=","value":"x"}');
  assert.equal(read('CMD:=x'), '{"name":"CMD","op":":=","value":"x"}');
  assert.equal(read('CMD::=x'), '{"name":"CMD","op":"::=","value":"x"}');
  assert.equal(read('CMD?=x'), '{"name":"CMD","op":"?=","value":"x"}');
  assert.equal(read('CMD+=x'), '{"name":"CMD","op":"+=","value":"x"}');
  assert.equal(read('CMD!=x'), '{"name":"CMD","op":"!=","value":"x"}');
  assert.equal(read('CMD = x y'), '{"name":"CMD","op":"=","value":"x y"}');
  assert.equal(read('.DEFAULT_GOAL=deploy'), '{"name":".DEFAULT_GOAL","op":"=","value":"deploy"}');
  assert.equal(read('A-B.c=x'), '{"name":"A-B.c","op":"=","value":"x"}');
  assert.equal(read('$(N)=x'), '{"name":"$(N)","op":"=","value":"x"}');
  // a colon that does not start an operator makes it a rule; so does a blank followed by anything but an operator
  assert.equal(read('a:b=c'), 'null');
  assert.equal(read('all: V = 1'), 'null');
  assert.equal(read('foo bar = x'), 'null');
  assert.equal(read('=x'), 'null');
  // on a command line: every word with an `=` is a definition, but a colon in the name makes make read it as a goal
  const cl = parseMakeCommandLine(['make', 'a:b=c', 'x', 'NAME=v', 'n:=1', 'q?=2', '-k', 'R = s']);
  assert.deepEqual(cl.goals, ['a:b=c', 'x']);
  assert.deepEqual(cl.assignments.map((a) => `${a.name}${a.op}${a.value}`), ['NAME=v', 'n:=1', 'q?=2', 'R=s']);
  assert.equal(parseMakeCommandLine(['make', '=x']).unknown, '=x');
});

/* ------------------------------------------------------------------------------------------------------------- *
 * MK-02. A TAB-INDENTED LINE WITH NO RULE OPEN IS A MAKEFILE LINE
 * ------------------------------------------------------------------------------------------------------------- */

test('MK-02. a tab-indented assignment, conditional, include or goal is read, not skipped', () => {
  const evil = { 'evil.mk': `CMD = ${ACT}\n` };
  check([
    ['the reported tab-indented assignment', 'make run', { Makefile: WITH_DECOY(`${T}CMD = ${ACT}`) }, 'DENY'],
    ['...with spaces around a tab', 'make run', { Makefile: WITH_DECOY(`${T}  CMD = ${ACT}`) }, 'DENY'],
    ['a tab-indented conditional around the assignment', 'make run', { Makefile: `CMD = echo safe\n${T}ifndef FOO\nCMD = ${ACT}\n${T}else\nCMD = echo safe\n${T}endif\nrun:\n${T}$(CMD)\n` }, 'DENY'],
    ['a tab-indented include', 'make run', { Makefile: WITH_DECOY(`${T}include evil.mk`), ...evil }, 'DENY'],
    ['a tab-indented -include', 'make run', { Makefile: WITH_DECOY(`${T}-include evil.mk`), ...evil }, 'DENY'],
    ['a tab-indented .DEFAULT_GOAL', 'make', { Makefile: `safe: ; @echo\ndeploy:\n${T}${ACT}\n${T}.DEFAULT_GOAL := deploy\n`.replace('safe: ; @echo\n', `${T}.DEFAULT_GOAL := deploy\nsafe: ; @echo\n`) }, 'DENY'],
    ['a tab-indented export', 'make run', { Makefile: WITH_DECOY(`${T}export CMD = ${ACT}`) }, 'DENY'],
    ['a tab-indented override', 'make run', { Makefile: WITH_DECOY(`${T}override CMD = ${ACT}`) }, 'DENY'],
    ['a tab-indented define block', 'make run', { Makefile: WITH_DECOY(`${T}define CMD\n${ACT}\nendef`) }, 'DENY'],
    ['a tab-indented target-specific variable (a rule line: make stops, and the line is read as a recipe too)', 'make run', { Makefile: WITH_DECOY(`${T}run: CMD = ${ACT}`) }, 'GATED'],
    // the line a tab-indented rule would have been: make stops with "commands commence before first target"; read as both, never as nothing
    ['a tab-indented recipe line after an assignment', 'make run', { Makefile: `run:\n${T}@echo a\nX = 1\n${T}${ACT}\n` }, 'GATED'],
    ['a tab-indented recipe line after an include', 'make run', { Makefile: `run:\n${T}@echo a\ninclude x.mk\n${T}${ACT}\n`, 'x.mk': 'Y = 1\n' }, 'GATED'],
    ['a tab-indented recipe line after .PHONY', 'make run', { Makefile: `run:\n${T}@echo a\n.PHONY: run\n${T}${ACT}\n` }, 'GATED'],
    // controls: the same lines IN a rule are recipe lines, and a harmless tab-indented assignment is only an assignment
    ['a recipe line in the rule (control)', 'make run', { Makefile: `run:\n${T}${ACT}\n` }, 'DENY'],
    ['a harmless tab-indented assignment (control)', 'make run', { Makefile: WITH_DECOY(`${T}CMD = echo other`) }, 'ALLOW'],
    ['tab-indented conditionals inside a rule belong to the rule (control)', 'make run', { Makefile: `run:\n${T}@echo a\nifdef X\n${T}echo b\nendif\n` }, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * MK-03. A BACKSLASH CONTINUES A LINE ONLY WHEN IT IS THE ODD ONE OUT
 * ------------------------------------------------------------------------------------------------------------- */

test('MK-03. an even run of backslashes ends the line', () => {
  const deploy = `deploy:\n${T}${ACT}\n`;
  check([
    ['a variable line ending in two backslashes', 'make deploy', { Makefile: `X = a\\\\\n${deploy}` }, 'DENY'],
    ['a recipe line ending in two backslashes', 'make deploy', { Makefile: `deploy:\n${T}echo a\\\\\n${T}${ACT}\n` }, 'DENY'],
    ['...and four', 'make deploy', { Makefile: `deploy:\n${T}echo a\\\\\\\\\n${T}${ACT}\n` }, 'DENY'],
    ['a rule line ending in two backslashes', 'make deploy', { Makefile: `all: a\\\\\n${deploy}` }, 'DENY'],
    ['a comment ending in two backslashes', 'make deploy', { Makefile: `# note\\\\\n${deploy}` }, 'DENY'],
    ['an include line ending in two backslashes', 'make deploy', { Makefile: `-include nosuch.mk\\\\\n${deploy}` }, 'DENY'],
    ['a define body line ending in two backslashes', 'make deploy', { Makefile: `define D\nx\\\\\nendef\n${deploy}` }, 'DENY'],
    // the odd run is a continuation, and is still one: what it joins is not a rule (here the act is text inside a value, and nothing runs)
    ['one backslash joins the next line (control)', 'make deploy', { Makefile: `X = a\\\ndeploy: ; ${ACT}\n` }, 'ALLOW'],
    ['three backslashes join it too (control)', 'make deploy', { Makefile: `X = a\\\\\\\ndeploy: ; ${ACT}\n` }, 'ALLOW'],
    ['a comment that continues swallows the next line (control)', 'make deploy', { Makefile: `# note\\\ndeploy: ; ${ACT}\n` }, 'ALLOW'],
    // (make stops at the tab-indented line that is then left with no rule; it is read as an error AND as a recipe of the rule above)
    ['...and the recipe line it leaves behind is not read as nothing', 'make deploy', { Makefile: `X = a\\\n${deploy}` }, 'GATED'],
    // inside a recipe the shell reads the continuation: a command cut in the middle is one command, a comment is not continued
    ['a word cut by a continuation in a recipe', 'make deploy', { Makefile: `deploy:\n${T}git pu\\\nsh origin main\n` }, 'DENY'],
    ['...with the recipe prefix on the second line', 'make deploy', { Makefile: `deploy:\n${T}git pu\\\n${T}sh origin main\n` }, 'DENY'],
    ['a shell comment does not continue onto the next recipe line', 'make deploy', { Makefile: `deploy:\n${T}echo a # note \\\n${T}${ACT}\n` }, 'DENY'],
  ]);
});

test('MK-03. continuation, comment and hash are one function each', () => {
  assert.equal(continues('a\\'), true);
  assert.equal(continues('a\\\\'), false);
  assert.equal(continues('a\\\\\\'), true);
  assert.equal(continues('a'), false);
  assert.deepEqual(makeLogicalLines('a\\\nb\nc\\\\\nd'), ['a\\\nb', 'c\\\\', 'd']);
  assert.equal(cutMakeComment('a # b'), 'a ');
  assert.equal(cutMakeComment('a \\# b'), 'a \\# b');
  assert.equal(cutMakeComment('a \\\\# b'), 'a \\');
  assert.equal(cutMakeComment('a \\\\\\# b # c'), 'a \\\\\\# b ');
  assert.deepEqual(readMakeNames('$(OBJS:.c=.o): %.o: %.c', true), { names: ['$(OBJS:.c=.o)'], colon: 13, assignment: false });
});

/* ------------------------------------------------------------------------------------------------------------- *
 * MK-04. A COMMAND RUNS WHEN THE TEXT THAT HOLDS IT IS EXPANDED - A DEFINE, A CALL, A COMPUTED NAME
 * ------------------------------------------------------------------------------------------------------------- */

test('MK-04. a $(shell) in a define runs wherever the define is expanded while the makefile is read', () => {
  const run = `define RUN\n$(shell ${ACT})\nendef\n`;
  const all = `\nall: ; @echo hi\n`;
  check([
    ['$(call) in a simple assignment', 'make all', { Makefile: `${run}X := $(call RUN)${all}` }, 'DENY'],
    ['a computed variable name', 'make all', { Makefile: `${run}N := RUN\nX := $($(N))${all}` }, 'DENY'],
    ['in a conditional', 'make all', { Makefile: `${run}ifeq ($(call RUN),x)\nendif${all}` }, 'DENY'],
    ['in an include path', 'make all', { Makefile: `${run}-include $(call RUN)${all}` }, 'DENY'],
    ['through $(foreach)', 'make all', { Makefile: `${run}X := $(foreach a,1 2,$(call RUN))${all}` }, 'DENY'],
    ['through $(if)', 'make all', { Makefile: `${run}X := $(if 1,$(call RUN),no)${all}` }, 'DENY'],
    ['through $(or)', 'make all', { Makefile: `${run}X := $(or ,$(call RUN))${all}` }, 'DENY'],
    ['through another variable that is simply expanded', 'make all', { Makefile: `${run}A = $(RUN)\nX := $(A)${all}` }, 'DENY'],
    ['a define that is itself simply expanded (GNU make 4)', 'make all', { Makefile: `define X :=\n$(shell ${ACT})\nendef${all}` }, 'DENY'],
    ['in a recipe line', 'make all', { Makefile: `${run}\nall:\n${T}@echo $(call RUN)\n` }, 'DENY'],
    ['in a recipe, through a computed name', 'make all', { Makefile: `${run}N = RUN\nall:\n${T}@echo $($(N))\n` }, 'DENY'],
    ['as the whole recipe', 'make all', { Makefile: `define CANNED\n${ACT}\nendef\nall:\n${T}$(CANNED)\n` }, 'DENY'],
    ['a canned recipe of several commands', 'make all', { Makefile: `define CANNED\n@echo a\n${ACT}\nendef\nall:\n${T}$(CANNED)\n` }, 'DENY'],
    ['a canned recipe called with arguments', 'make all', { Makefile: `define CANNED\n@echo $(1)\n$(2)\nendef\nall:\n${T}$(call CANNED,a,${ACT})\n` }, 'DENY'],
    // the control: a define that is never expanded runs nothing, and a define with a harmless body is harmless
    ['a define nothing expands (control)', 'make all', { Makefile: `${run}${all.trimStart()}` }, 'ALLOW'],
    ['a define with a harmless body (control)', 'make all', { Makefile: `define H\n$(shell echo hi)\nendef\nX := $(call H)${all}` }, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * MK-05. THE RULES MAKE HAS BEFORE IT READS ANYTHING, AND THE TEXT AFTER A `#`
 * ------------------------------------------------------------------------------------------------------------- */

test('MK-05. a goal make can build with a built-in rule runs the variables that rule reads', () => {
  const c = { 'foo.c': 'int main(void){return 0;}\n' };
  const tool = { 'tool.sh': `#!/bin/sh\n${ACT}\n` };
  check([
    ['CC holds the act and a comment', 'make foo', { Makefile: `CC = ${ACT} #\n`, ...c }, 'DENY'],
    ['CC holds the act', 'make foo', { Makefile: `CC = ${ACT}\n`, ...c }, 'DENY'],
    ['CC is a script that holds the act', 'make foo', { Makefile: 'CC = ./tool.sh\n', ...c, ...tool }, 'DENY'],
    ['COMPILE.c', 'make foo.o', { Makefile: `COMPILE.c = ${ACT} ;\n`, ...c }, 'DENY'],
    ['LINK.c', 'make foo', { Makefile: `LINK.c = ${ACT} ;\n`, ...c }, 'DENY'],
    ['CFLAGS carries a second command', 'make foo', { Makefile: `CFLAGS = ; ${ACT}\n`, ...c }, 'DENY'],
    ['LEX', 'make foo.c', { Makefile: `LEX = ${ACT} ;\n`, 'foo.l': '%%\n' }, 'DENY'],
    ['YACC', 'make foo.c', { Makefile: `YACC = ${ACT} ;\n`, 'foo.y': '%%\n' }, 'DENY'],
    ['AS', 'make foo.o', { Makefile: `AS = ${ACT} ;\n`, 'foo.s': 'nop\n' }, 'DENY'],
    ['CXX', 'make foo', { Makefile: `CXX = ${ACT} ;\n`, 'foo.cc': 'int main(){}\n' }, 'DENY'],
    ['a prerequisite no rule gives a recipe', 'make all', { Makefile: `CC = ${ACT} ;\nall: foo\n`, ...c }, 'DENY'],
    ['an object prerequisite', 'make all', { Makefile: `CC = ${ACT} ;\nall: foo.o\n`, ...c }, 'DENY'],
    ['a rule with a dependency and no recipe takes its recipe from the built-in one', 'make all', { Makefile: `CC = ${ACT} ;\nall: foo.o\nfoo.o: foo.h\n`, ...c, 'foo.h': 'x' }, 'DENY'],
    ['in a subdirectory', 'make sub/foo', { Makefile: `CC = ${ACT} ;\n`, 'sub/foo.c': 'x' }, 'DENY'],
    ['on the command line, with no makefile at all', 'make CC=./tool.sh foo', { ...c, ...tool }, 'DENY'],
    ['on the command line with a compiler name that is the act', `make 'CC=${ACT} #' foo`, c, 'DENY'],
    ['the environment spelling asks (control)', 'CC=./tool.sh make foo', { ...c, ...tool }, 'GATED'],
    // controls: the built-in rule with its own program is a compile, and a name nothing builds is not a goal
    ['the built-in rule as it comes (control)', 'make foo', c, 'ALLOW'],
    ['a name nothing builds (control)', 'make nosuch', c, 'ALLOW'],
    ['no built-in rules with -r (control)', 'make -r foo', { Makefile: `CC = ${ACT} ;\n`, ...c }, 'ALLOW'],
    ['a rule the makefile gives (control)', 'make foo', { Makefile: `CC = ${ACT} ;\nfoo: ; @echo hi\n`, ...c }, 'ALLOW'],
  ]);
});

test('MK-05. a value ends at its #, and the text after it is not part of what a recipe runs', () => {
  check([
    ['a comment in a value does not hide what follows the reference', 'make run', { Makefile: `CMD = echo hi # note\nrun:\n${T}$(CMD) && ${ACT}\n` }, 'DENY'],
    ['...and the trailing blank is the value\'s', 'make run', { Makefile: `CMD = echo hi # note\nrun:\n${T}echo "[$(CMD)]" && ${ACT}\n` }, 'DENY'],
    // an escaped hash is a `#` in the value, and a `#` in the text the shell is handed starts a shell comment: the act is not run (checked: the
    // logging harness below runs these too)
    ['an escaped hash is part of the value, and the shell reads it as a comment', 'make run', { Makefile: `CMD = echo hi \\# note\nrun:\n${T}$(CMD) && ${ACT}\n` }, 'ALLOW'],
    ['two backslashes before the hash: a backslash and a comment', 'make run', { Makefile: `CMD = echo hi \\\\# note\nrun:\n${T}$(CMD) && ${ACT}\n` }, 'DENY'],
    ['a comment on a rule line before the semicolon', 'make run', { Makefile: `run: # note ; ${ACT}\n${T}echo hi\n` }, 'ALLOW'],
    ['an escaped hash on a rule line is a shell comment in the one-line recipe', 'make run', { Makefile: `run: ; echo a \\# b ; ${ACT}\n` }, 'ALLOW'],
    ['...and before it the act runs', 'make run', { Makefile: `run: ; ${ACT} \\# b\n` }, 'DENY'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * MK-06. AN INCLUDE IS READ INLINE, INTO THE SAME VARIABLES
 * ------------------------------------------------------------------------------------------------------------- */

test('MK-06. what an included file declines to assign is judged against what the includer set', () => {
  const run = `\nall:\n${T}$(CMD)\n`;
  check([
    ['a ?= default in the included file', 'make all', { Makefile: `CMD = ${ACT}\ninclude cfg.mk${run}`, 'cfg.mk': 'CMD ?= echo safe\n' }, 'DENY'],
    ['an ifndef guard in the included file', 'make all', { Makefile: `CMD = ${ACT}\ninclude cfg.mk${run}`, 'cfg.mk': 'ifndef CMD\nCMD = echo safe\nendif\n' }, 'DENY'],
    ['a -include of the same file', 'make all', { Makefile: `CMD = ${ACT}\n-include cfg.mk${run}`, 'cfg.mk': 'CMD ?= echo safe\n' }, 'DENY'],
    ['an included file two levels down', 'make all', { Makefile: `CMD = ${ACT}\ninclude a.mk${run}`, 'a.mk': 'include b.mk\n', 'b.mk': 'CMD ?= echo safe\n' }, 'DENY'],
    ['the second -f file', 'make -f a.mk -f b.mk all', { 'a.mk': `CMD = ${ACT}\n`, 'b.mk': `CMD ?= echo safe${run}` }, 'DENY'],
    ['an appended value in the included file', 'make all', { Makefile: `CMD = ${ACT}\ninclude cfg.mk${run}`, 'cfg.mk': 'CMD += ; echo safe\n' }, 'DENY'],
    ['a conditional include', 'make all', { Makefile: `CMD = ${ACT}\nifdef X\ninclude cfg.mk\nendif${run}`, 'cfg.mk': 'CMD = echo safe\n' }, 'DENY'],
    ['the includer assigns after the include (control: the includer wins)', 'make all', { Makefile: `include cfg.mk\nCMD = echo safe${run}`, 'cfg.mk': `CMD = ${ACT}\n` }, 'ALLOW'],
    ['the included file assigns the act (control)', 'make all', { Makefile: `CMD = echo safe\ninclude cfg.mk${run}`, 'cfg.mk': `CMD = ${ACT}\n` }, 'DENY'],
    ['a ?= default nobody overrides (control)', 'make all', { Makefile: `include cfg.mk${run}`, 'cfg.mk': 'CMD ?= echo safe\n' }, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * MK-07. A VARIABLE WHOSE NAME MAKE COMPUTES
 * ------------------------------------------------------------------------------------------------------------- */

test('MK-07. an assignment to a name make computes assigns that name', () => {
  const user = `\nrun:\n${T}$(CMD)\n`;
  check([
    ['a variable holds the name', 'make run', { Makefile: `CMD = echo safe\nN = CMD\n$(N) = ${ACT}${user}` }, 'DENY'],
    ['simply expanded', 'make run', { Makefile: `CMD = echo safe\nN = CMD\n$(N) := ${ACT}${user}` }, 'DENY'],
    ['exported', 'make run', { Makefile: `CMD = echo safe\nN = CMD\nexport $(N) = ${ACT}${user}` }, 'GATED'],
    ['overridden', 'make run', { Makefile: `CMD = echo safe\nN = CMD\noverride $(N) = ${ACT}${user}` }, 'DENY'],
    ['a name with an empty part', 'make run', { Makefile: `CMD = echo safe\nE =\nCMD$(E) = ${ACT}${user}` }, 'DENY'],
    ['a name with a function', 'make run', { Makefile: `CMD = echo safe\n$(subst X,,CXMDX) = ${ACT}${user}` }, 'DENY'],
    ['a define with a computed name', 'make run', { Makefile: `CMD = echo safe\nN = CMD\ndefine $(N)\n${ACT}\nendef${user}` }, 'DENY'],
    ['an appended value', 'make run', { Makefile: `CMD = echo safe\nN = CMD\n$(N) += ; ${ACT}${user}` }, 'DENY'],
    ['inside a conditional, with a name from the command line', 'make N=CMD run', { Makefile: `CMD = echo safe\nifdef N\n$(N) = ${ACT}\nendif${user}` }, 'DENY'],
    ['a name nobody can compute is a line this resolver does not read', 'make run', { Makefile: `CMD = echo safe\n$(shell echo CMD) = ${ACT}${user}` }, 'GATED'],
    ['a name from a variable nobody defined', 'make run', { Makefile: `CMD = echo safe\n$(NOSUCH) = ${ACT}${user}` }, 'GATED'],
    ['a computed ?= that is declined (control)', 'make run', { Makefile: `CMD = echo safe\nN = CMD\n$(N) ?= ${ACT}${user}` }, 'ALLOW'],
    ['a computed name that is not CMD (control)', 'make run', { Makefile: `CMD = echo safe\nN = OTHER\n$(N) = ${ACT}${user}` }, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * MK-08. `override` DOES NOT END A RULE
 * ------------------------------------------------------------------------------------------------------------- */

test('MK-08. a tab-indented line after an override line is a recipe line of the rule above it', () => {
  const after = (line: string): Record<string, string> => ({ Makefile: `all:\n${T}echo a\n${line}\n${T}${ACT}\n` });
  check([
    ['override =', 'make all', after('override Q = 1'), 'DENY'],
    ['override :=', 'make all', after('override Q := 1'), 'DENY'],
    ['override +=', 'make all', after('override Q += 1'), 'DENY'],
    ['override export', 'make all', after('override export Q = 1'), 'DENY'],
    ['bare override', 'make all', after('override Q'), 'DENY'],
    ['override define', 'make all', after('override define D\nx\nendef'), 'DENY'],
    ['a plain define (does not end the rule either)', 'make all', after('define D\nx\nendef'), 'DENY'],
    ['a conditional', 'make all', after('ifdef Z\nendif'), 'DENY'],
    ['a comment and a blank line', 'make all', after('# note\n'), 'DENY'],
    // the lines that DO end a rule: the tab-indented line after them is not a recipe of it (it is read as an error and as a recipe, never as nothing)
    ['a plain assignment ends the rule', 'make all', after('Q = 1'), 'GATED'],
    ['export ends it', 'make all', after('export Q'), 'GATED'],
    ['unexport ends it', 'make all', after('unexport Q'), 'GATED'],
    ['a rule line ends it: the recipe line is the new rule\'s', 'make all', after('other: ; @echo o'), 'ALLOW'],
    ['...and it runs when that rule does', 'make other', after('other: ; @echo o'), 'DENY'],
    // an override is an assignment: it beats the command line, and the rule above keeps its recipe lines
    ['override beats the command line', 'make CMD=true run', { Makefile: `override CMD = ${ACT}\nrun:\n${T}$(CMD)\n` }, 'DENY'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * MK-09. THE EXPANSION IS BOUNDED
 * ------------------------------------------------------------------------------------------------------------- */

/** a makefile of `levels` variables that each refer to the next one `fan` times, the last holding the act: `fan ** levels` copies when expanded naively */
const fanOut = (fan: number, levels: number, tail = ACT): string => {
  let mk = '';
  for (let i = 0; i < levels; i++) mk += `A${i} = ${Array(fan).fill(`$(A${i + 1})`).join(' ')}\n`;
  return `${mk}A${levels} = ${tail}\nall: ; $(A0)\n`;
};

/** the time one decision takes, and what it said */
function timed(command: string, files: Record<string, string>): { ms: number; got: string } {
  const dir = workspace(files);
  const t0 = performance.now();
  const got = verdict(command, dir);
  return { ms: performance.now() - t0, got };
}

test('MK-09. the reported fan-out - 654 bytes that took 42 seconds - is answered at once, and not with an ALLOW', () => {
  const mk = fanOut(12, 8);
  assert.equal(mk.length < 700, true);
  const { ms, got } = timed('make all', { Makefile: mk });
  assert.notEqual(got, 'ALLOW');
  assert.ok(ms < 1500, `took ${Math.round(ms)} ms`);
});

test('MK-09. PROPERTY: a makefile written to be slow gets a verdict in about a second, and the act it holds is never allowed', () => {
  // each generator is a way to make an expansion, a walk or a read grow faster than the text: references that fan out, that refer to
  // themselves, a call that calls twice, an include of thousands of names, thousands of rules, a prerequisite chain, a doubling value, a
  // foreach over a list that grows, a pattern with nothing to stop it
  const cases: Array<[name: string, command: string, files: Record<string, string>]> = [];
  for (const [fan, levels] of [[2, 30], [3, 20], [8, 8], [12, 8], [14, 10], [20, 6], [40, 4], [100, 3]] as const) cases.push([`fan-out ${fan}^${levels}`, 'make all', { Makefile: fanOut(fan, levels) }]);
  cases.push(['fan-out, benign tail', 'make all', { Makefile: fanOut(12, 8, 'echo hi') }]);
  cases.push(['self reference', 'make all', { Makefile: `A = $(A) $(A)\nall: ; $(A) ${ACT}\n` }]);
  cases.push(['a cycle of two', 'make all', { Makefile: `A = $(B) $(B)\nB = $(A) $(A)\nall: ; $(A) ${ACT}\n` }]);
  cases.push(['a cycle through call', 'make all', { Makefile: `f = $(call g,$(1)) $(call g,$(1))\ng = $(call f,$(1)) $(call f,$(1))\nall: ; $(call f,x) ${ACT}\n` }]);
  let deep = '';
  for (let i = 0; i < 60; i++) deep += `f${i} = $(call f${i + 1},$(1)) $(call f${i + 1},$(1))\n`;
  cases.push(['a call that calls twice, sixty deep', 'make all', { Makefile: `${deep}f60 = ${ACT}\nall: ; $(call f0,x)\n` }]);
  let dbl = 'X := a\n';
  for (let i = 0; i < 40; i++) dbl += 'X := $(X)$(X)\n';
  cases.push(['a value that doubles forty times', 'make all', { Makefile: `${dbl}all: ; echo $(X) && ${ACT}\n` }]);
  cases.push(['a recursive value that doubles', 'make all', { Makefile: `${dbl.replace(/:=/g, '=')}all: ; echo $(X) && ${ACT}\n` }]);
  cases.push(['a foreach over a growing list', 'make all', { Makefile: `L := a b c d e f g h\nL := $(foreach x,$(L),$(x)1 $(x)2 $(x)3 $(x)4)\nL := $(foreach x,$(L),$(x)1 $(x)2 $(x)3 $(x)4)\nL := $(foreach x,$(L),$(x)1 $(x)2 $(x)3 $(x)4)\nL := $(foreach x,$(L),$(x)1 $(x)2 $(x)3 $(x)4)\nL := $(foreach x,$(L),$(x)1 $(x)2 $(x)3 $(x)4)\nall: ; echo $(L) && ${ACT}\n` }]);
  cases.push(['two thousand optional includes', 'make all', { Makefile: `-include ${Array.from({ length: 2000 }, (_v, i) => `nosuch${i}.mk`).join(' ')}\nall: ; ${ACT}\n` }]);
  cases.push(['an include of a thousand real files', 'make all', { Makefile: `include ${Array.from({ length: 300 }, (_v, i) => `i${i}.mk`).join(' ')}\nall: ; ${ACT}\n`, ...Object.fromEntries(Array.from({ length: 300 }, (_v, i) => [`i${i}.mk`, `V${i} = ${i}\n`])) }]);
  cases.push(['five thousand rules', 'make all', { Makefile: `all: r0\n${Array.from({ length: 5000 }, (_v, i) => `r${i}: r${i + 1}\n${T}echo ${i}`).join('\n')}\nr5000: ; ${ACT}\n` }]);
  cases.push(['five thousand rules for one target', 'make all', { Makefile: `${Array.from({ length: 5000 }, (_v, i) => `all: p${i}\nall: ; echo ${i}`).join('\n')}\nall: ; ${ACT}\n` }]);
  cases.push(['a deep prerequisite chain', 'make all', { Makefile: `${Array.from({ length: 400 }, (_v, i) => `p${i}: p${i + 1}\n${T}echo ${i}`).join('\n')}\np400: ; ${ACT}\nall: p0\n` }]);
  cases.push(['five thousand variables', 'make all', { Makefile: `${Array.from({ length: 5000 }, (_v, i) => `V${i} = ${i} $(V${Math.max(0, i - 1)})`).join('\n').replace('V0 = 0 $(V0)', 'V0 = 0')}\nall: ; echo $(V4999) && ${ACT}\n` }]);
  cases.push(['a long line', 'make all', { Makefile: `X = ${'a '.repeat(200000)}\nall: ; echo $(X) && ${ACT}\n` }]);
  cases.push(['a conditional per line', 'make all', { Makefile: `${Array.from({ length: 800 }, (_v, i) => `ifdef F${i}\nC = ${i}\nendif`).join('\n')}\nall: ; $(C) ${ACT}\n` }]);
  cases.push(['alternatives that multiply', 'make all', { Makefile: `${Array.from({ length: 12 }, (_v, i) => `ifdef F${i}\nV${i} = a\nelse\nV${i} = b\nendif`).join('\n')}\nall: ; echo ${Array.from({ length: 12 }, (_v, i) => `$(V${i})`).join(' ')} && ${ACT}\n` }]);
  cases.push(['wildcards', 'make all', { Makefile: `F := $(wildcard *)\nG := $(foreach f,$(F),$(wildcard $(f)*))\nall: ; echo $(G) && ${ACT}\n`, ...Object.fromEntries(Array.from({ length: 200 }, (_v, i) => [`w${i}.c`, 'x'])) }]);
  cases.push(['implicit rules with every file there', 'make 5000', { Makefile: '', ...Object.fromEntries(Array.from({ length: 300 }, (_v, i) => [`f${i}.c`, 'x'])) }]);
  // the generated ones: sizes from a seeded stream, so a failure is a number somebody can run again
  let s = 20261002;
  const rnd = (): number => {
    s = (Math.imul(s, 1103515245) + 12345) >>> 0;
    return s / 4294967296;
  };
  for (let i = 0; i < 6; i++) cases.push([`generated fan-out ${i}`, 'make all', { Makefile: fanOut(2 + Math.floor(rnd() * 30), 2 + Math.floor(rnd() * 14)) }]);
  const slow: string[] = [];
  for (const [name, command, files] of cases) {
    const { ms, got } = timed(command, files);
    // a verdict, in about a second; and the act is in every makefile above (but the benign tail and the empty makefile), so ALLOW is wrong
    const holds = JSON.stringify(files).includes(ACT);
    if (ms > 1500) slow.push(`${name}: ${Math.round(ms)} ms`);
    if (holds && got === 'ALLOW') slow.push(`${name}: ALLOW over a makefile that holds the act`);
  }
  assert.deepEqual(slow, []);
});

test('MK-09. a reached bound is a gap, and the same makefile read by the unmetered expander says so too', () => {
  const store = new MakeStore();
  store.set('A0', ['$(A1) $(A1) $(A1) $(A1) $(A1) $(A1) $(A1) $(A1) $(A1) $(A1) $(A1) $(A1)'], { origin: 'file', simple: false, conditional: false });
  for (let i = 1; i < 10; i++) store.set(`A${i}`, [`$(A${i + 1}) $(A${i + 1}) $(A${i + 1}) $(A${i + 1}) $(A${i + 1}) $(A${i + 1}) $(A${i + 1}) $(A${i + 1}) $(A${i + 1}) $(A${i + 1}) $(A${i + 1}) $(A${i + 1})`], { origin: 'file', simple: false, conditional: false });
  store.set('A10', [`$(shell ${ACT})`], { origin: 'file', simple: false, conditional: false });
  const t0 = performance.now();
  const x = store.expand('$(A0)');
  assert.ok(performance.now() - t0 < 1000);
  assert.equal(x.capped, true);
  assert.deepEqual(x.alts.map((a) => a.text), [null]);
  // (what ran before the bound was reached is kept, once: a repeated command is not a longer list)
  assert.ok(x.ran.length <= 1);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * NEIGHBOURS OF THE FINDINGS: the same question asked of the readers the findings did not name
 * ------------------------------------------------------------------------------------------------------------- */

test('a value a conditional gives is read at every place make reads it, parse time included', () => {
  const tail = '\nall: ; @echo\n';
  check([
    ['the act in the branch the file reads first', 'make all', { Makefile: `ifndef NOSUCH\nCMD = ${ACT}\nelse\nCMD = echo safe\nendif\nX := $(shell $(CMD))${tail}` }, 'DENY'],
    ['the act in the branch the file reads last', 'make all', { Makefile: `ifdef NOSUCH\nCMD = echo safe\nelse\nCMD = ${ACT}\nendif\nX := $(shell $(CMD))${tail}` }, 'DENY'],
    ['through a second variable', 'make all', { Makefile: `ifdef NOSUCH\nCMD = echo safe\nelse\nCMD = ${ACT}\nendif\nWRAP = $(CMD)\nX := $(shell $(WRAP))${tail}` }, 'DENY'],
    ['in an include operand', 'make all', { Makefile: `ifdef NOSUCH\nF = a.mk\nelse\nF = b.mk\nendif\n-include $(F)${tail}`, 'b.mk': `X := $(shell ${ACT})\n` }, 'DENY'],
    ['two variables, each of which has a harmless value', 'make all', { Makefile: `ifdef A\nG = echo\nelse\nG = git\nendif\nifdef B\nAC = hi\nelse\nAC = push origin main\nendif\nall: ; $(G) $(AC)\n` }, 'DENY'],
  ]);
});

test('what the recipes are run with: export, .EXPORT_ALL_VARIABLES and the variables of the command line', () => {
  check([
    ['export with no names exports every variable the makefile sets', 'make all', { Makefile: 'export\nLD_PRELOAD := ./evil.so\nall: ; @ls\n', 'evil.so': 'x' }, 'GATED'],
    ['.EXPORT_ALL_VARIABLES', 'make all', { Makefile: '.EXPORT_ALL_VARIABLES:\nLD_PRELOAD := ./evil.so\nall: ; @ls\n', 'evil.so': 'x' }, 'GATED'],
    ['export of two names', 'make all', { Makefile: 'LD_PRELOAD := ./evil.so\nexport LD_PRELOAD OTHER\nall: ; @ls\n', 'evil.so': 'x' }, 'GATED'],
    ['export with the value', 'make all', { Makefile: 'export LD_PRELOAD := ./evil.so\nall: ; @ls\n', 'evil.so': 'x' }, 'GATED'],
    ['unexport takes it back (control)', 'make all', { Makefile: 'export\nunexport LD_PRELOAD\nLD_PRELOAD := ./evil.so\nall: ; @ls\n', 'evil.so': 'x' }, 'ALLOW'],
    ['a command-line variable reaches the recipes\' environment', 'make PGHOST=prod-db.acme.com all', { Makefile: "all: ; psql -c 'drop table users'\n" }, 'GATED'],
    ['...and a program-loading one', 'make LD_PRELOAD=./evil.so all', { Makefile: 'all: ; @ls\n', 'evil.so': 'x' }, 'GATED'],
    ['a harmless exported variable (control)', 'make all', { Makefile: 'export GREETING := hello\nall: ; @echo $$GREETING\n' }, 'ALLOW'],
  ]);
});

test('a variable a makefile puts in the flags is a variable of the make below it', () => {
  // the sub-makefile declines with ?= whatever the environment holds; the flags that reach it are the environment, or the command line
  const sub = { 'sub.mk': 'CMD ?= echo safe\nshow:\n\t$(CMD)\n' };
  const parent = (line: string): Record<string, string> => ({ Makefile: `${line}\nall:\n${T}$(MAKE) -f sub.mk show\n`, ...sub });
  const word = 'CMD=git\\ push\\ origin\\ main';
  check([
    ['MAKEFLAGS +=', 'make all', parent(`MAKEFLAGS += ${word}`), 'DENY'],
    ['MAKEFLAGS :=', 'make all', parent(`MAKEFLAGS := ${word}`), 'DENY'],
    ['export MAKEFLAGS :=', 'make all', parent(`export MAKEFLAGS := ${word}`), 'DENY'],
    ['after the -- that ends the options', 'make all', parent(`MAKEFLAGS += -- ${word}`), 'DENY'],
    ['GNUMAKEFLAGS (GNU make 4)', 'make all', parent(`GNUMAKEFLAGS += ${word}`), 'DENY'],
    ['MAKEOVERRIDES, which has the precedence of the command line', 'make all OTHER=1', parent(`MAKEOVERRIDES += ${word}`), 'DENY'],
    ['override MAKEOVERRIDES', 'make all OTHER=1', parent(`override MAKEOVERRIDES := ${word}`), 'DENY'],
    ['through $(MAKE) -C', 'make all', { Makefile: `MAKEFLAGS += ${word}\nall:\n${T}$(MAKE) -C d show\n`, 'd/Makefile': 'CMD ?= echo safe\nshow:\n\t$(CMD)\n' }, 'DENY'],
    ['text nobody can determine', 'make all', parent('MAKEFLAGS += $(shell echo hi)'), 'GATED'],
    ['an option is not a definition (control)', 'make all', parent('MAKEFLAGS += --no-print-directory'), 'ALLOW'],
    ['a harmless definition (control)', 'make all', parent('MAKEFLAGS += CMD=true'), 'ALLOW'],
  ]);
  // MAKEFLAGS as the command line made it
  assert.deepEqual(flagDefinitions(storeWith({ MAKEFLAGS: 'k -- A=1 B=a\\ b -j4 --eval=x' })).definitions, [['A', '1'], ['B', 'a b']]);
});

test('what an earlier unit of the same command exported is the environment make starts with', () => {
  const cc = { 'foo.c': 'int main(void) { return 0; }\n', 'Makefile': 'run:\n\t$(CC) -c foo.c\n' };
  check([
    ['an exported compiler that is the act', `export CC='${ACT} #'; make run`, cc, 'GATED'],
    // (a name the kernel does not track as an input is not seen by make's store: the export is judged where it is made, and asks)
    ['an exported variable the recipe reads', `export CMD='${ACT}'; make run`, { Makefile: 'CMD ?= echo safe\nrun:\n\t$(CMD)\n' }, 'GATED'],
    ['a flag of an implicit rule, exported', `export CFLAGS='; ${ACT}'; make foo`, { 'foo.c': 'int main(void) { return 0; }\n' }, 'GATED'],
    ['a harmless export (control)', 'export GREETING=hello; make run', { Makefile: 'run:\n\techo $(GREETING)\n' }, 'ALLOW'],
  ]);
});

test('the pieces of make that run something without a recipe saying so', () => {
  check([
    ['a default goal behind a pattern rule', 'make', { Makefile: `%.o: %.c\n${T}@echo c\nall:\n${T}${ACT}\n` }, 'DENY'],
    ['.DEFAULT is the recipe of a goal nothing builds', 'make anything', { Makefile: `.DEFAULT:\n${T}${ACT}\n` }, 'DENY'],
    ['a suffix rule', 'make foo.o', { Makefile: `.c.o:\n${T}${ACT}\n`, 'foo.c': 'x' }, 'DENY'],
    ['a single-suffix rule', 'make foo', { Makefile: `.c:\n${T}${ACT}\n`, 'foo.c': 'x' }, 'DENY'],
    ['a static pattern rule hands its recipe to each target', 'make all', { Makefile: `OBJ = foo.o\nall: $(OBJ)\n$(OBJ): %.o: %.c\n${T}${ACT}\n`, 'foo.c': 'x' }, 'DENY'],
    ['...built from a substitution reference', 'make all', { Makefile: `SRC = foo.c\nOBJ = $(SRC:.c=.o)\nall: $(OBJ)\n$(OBJ): %.o: %.c\n${T}${ACT}\n`, 'foo.c': 'x' }, 'DENY'],
    ['the second pattern rule, the one whose source is there', 'make all', { Makefile: `all: x.o\n%.o: %.c\n${T}@echo c\n%.o: %.cc\n${T}${ACT}\n`, 'x.cc': 'x' }, 'DENY'],
    ['a pattern rule reached through a rule with no recipe', 'make all', { Makefile: `all: foo.o\nfoo.o: foo.h\n%.o: %.c\n${T}${ACT}\n`, 'foo.c': 'x', 'foo.h': 'x' }, 'DENY'],
    ['$(MAKE) hands its command-line variable down', 'make run', { Makefile: `run:\n${T}$(MAKE) inner CMD='${ACT}'\ninner:\n${T}$(CMD)\n` }, 'DENY'],
    ['${MAKE}', 'make run', { Makefile: `run:\n${T}\${MAKE} inner CMD='${ACT}'\ninner:\n${T}$(CMD)\n` }, 'DENY'],
    ['$(MAKE) -C reads the makefile of the directory', 'make run', { Makefile: `run:\n${T}$(MAKE) -C sub\n`, 'sub/Makefile': `all:\n${T}${ACT}\n` }, 'DENY'],
    ['$(MAKE) in a dry run still runs', 'make -n run', { Makefile: `run:\n${T}$(MAKE) -C sub\n`, 'sub/Makefile': `all:\n${T}${ACT}\n` }, 'DENY'],
    ['a stem in the command', 'make all', { Makefile: `all: foo.run\n%.run:\n${T}${ACT} $*\n` }, 'DENY'],
    ['an automatic variable that is the command', 'make all', { Makefile: `all: x\nx:\n${T}$@ ; ${ACT}\n` }, 'DENY'],
  ]);
});

test('text functions form the command make runs, and the commands inside them run', () => {
  const run = (line: string, extra: Record<string, string> = {}): Record<string, string> => ({ Makefile: `X = foo\nL = echo git\nP = git\nall: ; ${line}\n`, ...extra });
  check([
    ['patsubst', 'make all', run('$(patsubst foo,git,$(X)) push origin main'), 'DENY'],
    ['a substitution reference', 'make all', run('$(X:foo=git) push origin main'), 'DENY'],
    ['subst', 'make all', run('$(subst X,g,Xit) push origin main'), 'DENY'],
    ['word', 'make all', run('$(word 2,$(L)) push origin main'), 'DENY'],
    ['filter', 'make all', run('$(filter git,git b c) push origin main'), 'DENY'],
    ['filter-out', 'make all', run('$(filter-out b c,git b c) push origin main'), 'DENY'],
    ['foreach', 'make all', run('$(foreach c,git,$(c)) push origin main'), 'DENY'],
    ['if', 'make all', run('$(if 1,git,echo) push origin main'), 'DENY'],
    ['or and and', 'make all', run('$(or ,$(and a,git)) push origin main'), 'DENY'],
    ['call', 'make all', { Makefile: `F = $(1) push origin $(2)\nall: ; $(call F,git,main)\n` }, 'DENY'],
    ['value', 'make all', run('$(value P) push origin main'), 'DENY'],
    ['strip', 'make all', run('$(strip   git  ) push origin main'), 'DENY'],
    ['addprefix', 'make all', run('$(addprefix g,it) push origin main'), 'DENY'],
    ['addsuffix', 'make all', run('$(addsuffix t,gi) push origin main'), 'DENY'],
    ['join', 'make all', run('$(join g,it) push origin main'), 'DENY'],
    ['firstword and lastword', 'make all', run('$(firstword git x)$(lastword x) push origin main'), 'GATED'],
    ['notdir', 'make all', run('$(notdir /usr/bin/git) push origin main'), 'DENY'],
    ['basename', 'make all', run('$(basename git.exe) push origin main'), 'DENY'],
    ['sort', 'make all', run('$(sort git git) push origin main'), 'DENY'],
    ['wordlist', 'make all', run('$(wordlist 2,2,x git) push origin main'), 'DENY'],
    ['findstring', 'make all', run('$(findstring git,git) push origin main'), 'DENY'],
    ['wildcard names the file that is there', 'make all', run('$(wildcard gi*) push origin main', { git: '#!/bin/sh\n' }), 'DENY'],
    ['wildcard over a name the shell would read as a command', 'make all', run('echo $(wildcard *.c)', { 'x;git push origin main.c': 'x' }), 'GATED'],
    ['a function inside the argument of another', 'make all', run('$(subst X,g,$(patsubst a,X,a)it) push origin main'), 'DENY'],
    ['a shell inside a function inside a recipe', 'make all', run(`echo $(strip $(shell ${ACT}))`), 'DENY'],
    ['a function that is not computed is unknown, not empty', 'make all', run('$(abspath git) push origin main'), 'GATED'],
    ['harmless functions (control)', 'make all', run('echo $(patsubst %.c,%.o,a.c b.c) $(sort b a) $(words a b)'), 'ALLOW'],
  ]);
});

test('a $(shell) whose command nobody can read is a command nobody can judge', () => {
  const mk = { Makefile: 'X := $(shell $(NOSUCH) hi)\nall: ; @echo\n' };
  check([
    ['a command taken from a variable nobody defined', 'make all', mk, 'GATED'],
    ['the environment of this command names the act', `NOSUCH='${ACT}' make all`, mk, 'DENY'],
    ['a command-line variable names the act', `make 'NOSUCH=${ACT}' all`, mk, 'DENY'],
    ['a harmless command-line value (control)', 'make NOSUCH=echo all', mk, 'ALLOW'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * THE STORE: ORIGIN AND PRECEDENCE, FLAVOUR, WHAT A CONDITIONAL GIVES
 * ------------------------------------------------------------------------------------------------------------- */

test('the store keeps make\'s precedence: default < environment < makefile < -e < command line < override', () => {
  const s = new MakeStore();
  const text = (name: string): string | null => s.expand(`$(${name})`).alts[0]?.text ?? null;
  assert.equal(text('CC'), 'cc');
  s.set('CC', ['env'], { origin: 'environment', simple: false, conditional: false });
  assert.equal(text('CC'), 'env');
  s.set('CC', ['file'], { origin: 'file', simple: false, conditional: false });
  assert.equal(text('CC'), 'file');
  s.set('V', ['envv'], { origin: 'environment-override', simple: false, conditional: false });
  assert.equal(s.set('V', ['file'], { origin: 'file', simple: false, conditional: false }), false);
  assert.equal(text('V'), 'envv');
  s.set('V', ['cli'], { origin: 'command-line', simple: false, conditional: false });
  assert.equal(s.set('V', ['file'], { origin: 'file', simple: false, conditional: false }), false);
  assert.equal(text('V'), 'cli');
  assert.equal(s.set('V', ['over'], { origin: 'override', simple: false, conditional: false }), true);
  assert.equal(text('V'), 'over');
  assert.equal(s.set('V', ['cli2'], { origin: 'command-line', simple: false, conditional: false }), false);
  // the same rank replaces: the last command-line definition is the one make uses
  s.set('W', ['one'], { origin: 'command-line', simple: false, conditional: false });
  s.set('W', ['two'], { origin: 'command-line', simple: false, conditional: false });
  assert.equal(text('W'), 'two');
});

test('the store expands a recursive value where it is used and a simple one where it is set', () => {
  const s = new MakeStore();
  const set = (n: string, v: string, simple = false): void => void s.set(n, [v], { origin: 'file', simple, conditional: false });
  const text = (src: string): string | null => s.expand(src).alts[0]?.text ?? null;
  set('A', '1');
  set('B', '$(A)'); // recursive: reads A when B is used
  s.set('C', [text('$(A)')!], { origin: 'file', simple: true, conditional: false }); // simple: A as it is NOW
  set('A', '2');
  assert.equal(text('$(B) $(C)'), '2 1');
  // a literal dollar in a simple value is written $$ and comes out once, not read again as a reference
  s.set('D', [encodeMakeParts(['$HOME'])], { origin: 'file', simple: true, conditional: false });
  assert.equal(text('[$(D)]'), '[$HOME]');
  // an undefined name is unknown, not empty - a bare HOME is the shell's, and a flag of an implicit rule is empty
  assert.equal(text('$(NOSUCH)'), null);
  assert.equal(text('[$(HOME)]'), '[$HOME]');
  assert.equal(text('[$(CFLAGS)]'), '[]');
  assert.equal(text('$(MAKEFLAGS)'), null);
  // a reference to itself is an error to make, and unknown here
  set('R', '$(R) x');
  assert.equal(text('$(R)'), null);
  // quoting is followed across the whole text: unknown inside double quotes is one word, outside it is an opacity
  assert.equal(text('echo "v $(NOSUCH)"'), 'echo "v $MAKEVAR"');
  assert.equal(text("echo '$(NOSUCH)'"), null);
});

test('the store keeps every value a conditional could have given, and the first is the current one', () => {
  const s = new MakeStore();
  s.set('CMD', ['a'], { origin: 'file', simple: false, conditional: false });
  s.set('CMD', ['b'], { origin: 'file', simple: false, conditional: true });
  assert.deepEqual(s.candidates('CMD'), ['b', 'a']);
  const x = s.expand('run $(CMD)');
  assert.deepEqual(x.alts.map((a) => a.text), ['run b', 'run a']);
  // an assignment outside a conditional replaces them all
  s.set('CMD', ['c'], { origin: 'file', simple: false, conditional: false });
  assert.deepEqual(s.candidates('CMD'), ['c']);
  // an environment value the makefile replaces stays a candidate: whether -e is in force is not always visible
  s.set('E', ['fromenv'], { origin: 'environment', simple: false, conditional: false });
  s.set('E', ['fromfile'], { origin: 'file', simple: false, conditional: false });
  assert.deepEqual(s.candidates('E'), ['fromfile', 'fromenv']);
});

test('the built-in table is the table of the make that is installed', { skip: !realMakeAvailable() }, () => {
  const db = spawnSync('make', ['-p', '-f', '/dev/null', '-q'], { encoding: 'utf8', env: { ...process.env, MAKEFLAGS: '' } }).stdout;
  const known = new Set(BUILTIN_VARIABLES.map(([n]) => n));
  const missing: string[] = [];
  const lines = db.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] === '# default') {
      const m = /^([^\s=:]+(?:,v)?)\s*:?=/.exec(lines[i + 1] ?? '');
      // (the entries that describe the host - where make is, its version, the features - are not a rule's business)
      if (m && !known.has(m[1]!) && !/^(MAKE|MAKEFILES|MAKEFILEPATH|SUFFIXES|\.FEATURES|\.VARIABLES|\.INCLUDE_DIRS|\.LIBPATTERNS)/.test(m[1]!)) missing.push(`variable ${m[1]}`);
    }
  }
  const have = new Set(BUILTIN_RULES.map((r) => `${r.target}: ${r.prereqs.join(' ')}`));
  const start = lines.indexOf('# Implicit Rules');
  for (let i = start + 1; i < lines.length && !/^# \d+ implicit rules/.test(lines[i]!); i++) {
    const m = /^(\S[^:]*):(:?)\s*(.*)$/.exec(lines[i]!);
    if (m && lines[i + 1]?.startsWith('#  commands to execute') && !have.has(`${m[1]}: ${m[3]!.trim()}`)) missing.push(`rule ${lines[i]}`);
  }
  const suffixes = / ([^\n]*)\n/.exec(`\n${(/^SUFFIXES\s*:?=\s*(.*)$/m.exec(db) ?? [])[1] ?? ''}\n`)?.[1]?.split(/\s+/).filter(Boolean) ?? [];
  for (const sfx of suffixes) if (!BUILTIN_SUFFIXES.includes(sfx)) missing.push(`suffix ${sfx}`);
  assert.deepEqual(missing, [], 'make knows something this table does not: add it');
  assert.ok(builtinRulesFor('foo', (f) => f === 'foo.c').length > 0);
});

/** the variables and the expressions the expander is held to the real make on: each expression is printed by `$(info)` and by `MakeStore.expand` */
const EXPR_DEFS = [
  'A = foo bar baz', 'B := $(A) qux', 'C = $(A:o=0)', 'D = a.c b.c dir/e.c', 'E = $(D:.c=.o)', 'F = %.c', 'G =', 'H = x y\tz', 'I = $(J)', 'J = jj',
  'K = a,b,c', 'L = ( paren', 'M = $$HOME', 'N := $$HOME', 'O = one two three four five', 'P = src/a.c src/b.c lib/c.c',
  'Q = foo.tar.gz bar.txt noext .hidden dir/file.ext dir.d/noext', 'f = [$(1)|$(2)|$(3)]', 'g = $(1)$(1)', 'define DEF\nline1\nline2\nendef',
];
const EXPRS = [
  '$(A)', '${A}', '$A', '$(B)', '$(C)', '$(E)', '$(G)', '[$(G)]', '$(H)', '$(I)', '$(K)', '$(L)', '$(M)', '$(N)',
  '$(subst o,0,$(A))', '$(subst ,X,abc)', '$(subst a,,banana)', '$(subst foo,$(J),$(A))',
  '$(patsubst %.c,%.o,$(D))', '$(patsubst %.c,%,$(D))', '$(patsubst a%,X%,$(A) apple)', '$(patsubst %,[%],$(A))', '$(patsubst b%,%b,$(A))', '$(patsubst foo,bar,$(A))', '$(patsubst %.c,%.o,.c a.c)',
  '$(strip   $(H)  )', '$(strip )', '$(findstring bar,$(A))', '$(findstring x,$(A))', '$(findstring ,$(A))',
  '$(filter %.c,$(D) x.h)', '$(filter-out %.c,$(D) x.h)', '$(filter foo baz,$(A))', '$(filter-out foo,$(A))', '$(filter %,$(A))', '$(filter a%b,ab acb a)',
  '$(sort $(O) one)', '$(sort z a m a)', '$(sort )',
  '$(word 1,$(O))', '$(word 5,$(O))', '$(word 6,$(O))', '$(wordlist 2,3,$(O))', '$(wordlist 4,9,$(O))', '$(wordlist 1,1,$(O))', '$(words $(O))', '$(words )', '$(words   a   b  )',
  '$(firstword $(O))', '$(lastword $(O))', '$(firstword )', '$(lastword )',
  '$(dir $(P))', '$(notdir $(P))', '$(dir a b/ /c)', '$(notdir a/ /b c//d)',
  '$(suffix $(Q))', '$(basename $(Q))', '$(basename a.b/c)', '$(suffix a.b/c)',
  '$(addprefix pre_,$(A))', '$(addsuffix .x,$(A))', '$(addprefix a b,c d)', '$(addsuffix 1 2,c d)', '$(addprefix x,)',
  '$(join a b c,1 2)', '$(join a,1 2 3)', '$(join ,)',
  '$(if $(G),yes,no)', '$(if $(A),yes,no)', '$(if $(A),yes)', '$(if  ,yes,no)', '$(if $(G),yes)x',
  '$(or $(G),$(G),c)', '$(or $(G),$(G))', '$(and a,b,c)', '$(and a,,c)',
  '$(foreach x,$(A),<$(x)>)', '$(foreach x,,<$(x)>)', '$(foreach x,a b,$(x)$(x))',
  '$(call f,1)', '$(call f,1,2,3)', '$(call f,,2)', '$(call f)', '$(call g,ab)', '$(call g,$(A))',
  '$(value A)', '$(value N)', '$(value M)', '$(flavor A)', '$(flavor B)', '$(origin A)',
  '$($(J))', '$(J$(J))', '$(subst j,J,$(J))', '$(patsubst %,$(J)%,x y)',
  '$(A:foo=1)', '$(A:o=0)', '$(A:%o=%0)', '$(A:a%=x%)', '$(D:%.c=%.o)',
  '$(strip $(subst a,b,$(filter %a%,$(A))))', '$(words $(sort $(A) $(A)))', '$(patsubst %.c,%.o,$(filter %.c,$(D)))',
  '$(if $(findstring bar,$(A)),FOUND,MISSING)', '$(foreach f,$(D),$(basename $(f)))',
  'x$(G)y', '$(G)$(G)', '$$', '$$$$', '$$(A)', '$(A)$$', 'a  b', '$(subst a,b, a )', '$(words a,b c)', '$(subst $(L),x,$(L) y)',
  '$(strip $(DEF))', '$(words $(DEF))', '$(word 2,$(DEF))',
];

test('REAL MAKE. the expander computes what make computes, function by function', { skip: !realMakeAvailable() }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'make-exprs-'));
  try {
    const defs = EXPR_DEFS.join('\n') + '\n';
    writeFileSync(join(dir, 'Makefile'), [defs, ...EXPRS.map((e, i) => `$(info @@${i}@@${e}@@/@@)`), 'all: ;', ''].join('\n'));
    const r = spawnSync('make', ['-f', 'Makefile', 'all'], { cwd: dir, encoding: 'utf8', env: { ...process.env, MAKEFLAGS: '' } });
    const real = new Map<number, string>();
    for (const m of r.stdout.matchAll(/@@(\d+)@@([\s\S]*?)@@\/@@/g)) real.set(Number(m[1]), m[2]!);
    assert.equal(real.size, EXPRS.length, `make printed ${real.size} of ${EXPRS.length}: ${r.stderr}`);
    const store = new MakeStore();
    const model = newMakeModel(store);
    new MakeReader(
      { read: (p) => (p.endsWith('Makefile') ? defs : null), opened: (d, n) => join(d, n), exists: () => false, glob: () => ({ names: [], incomplete: false }), ordinaryShell: () => true },
      model,
      [],
    ).readRoot(join(dir, 'Makefile'), dir);
    const wrong: string[] = [];
    let known = 0;
    EXPRS.forEach((e, i) => {
      const x = store.expand(e);
      const mine = x.alts[0]?.text;
      if (mine === null || mine === undefined) return;
      known++;
      if (x.alts.length === 1 && mine !== real.get(i)) wrong.push(`${e}: make says ${JSON.stringify(real.get(i))}, the expander ${JSON.stringify(mine)}`);
    });
    assert.deepEqual(wrong, []);
    assert.ok(known >= EXPRS.length - 2, `only ${known} of ${EXPRS.length} expressions were computed`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('REAL MAKE. the reader\'s rules and variables are the ones in make\'s own database (make -p)', { skip: !realMakeAvailable() }, () => {
  // makefiles whose syntax every GNU make reads alike; what is compared is what the recipe walk is built on - the targets, their prerequisites
  // and recipes, and the value of each variable the makefile sets
  const mks: Array<[string, string]> = [
    ['several targets, several prerequisites', `a b: c d\n${T}echo $@\nc d:\n${T}echo x\n`],
    ['order-only prerequisites', `all: a b | c d\n${T}echo all\na b c d:\n${T}echo $@\n`],
    ['targets and prerequisites from variables', `T = x y\nP = z\n$(T): $(P)\n${T}echo $@\nz:\n${T}echo z\n`],
    ['prerequisites on several lines', `all: a \\\n  b \\\n  c\n${T}echo all\na b c:\n${T}echo $@\n`],
    ['a recipe on the rule line, and more', `all: ; echo one\n${T}echo two\n`],
    ['an empty recipe', `all: a ;\na:\n${T}echo a\n`],
    ['a static pattern rule over a substitution reference', `SRC = a.c b.c\nOBJ = $(SRC:.c=.o)\nall: $(OBJ)\n$(OBJ): %.o: %.c\n${T}cc -c $< -o $@\n`],
    ['special targets', `.PHONY: all\n.SUFFIXES:\nall:\n${T}echo hi\n`],
    ['comments', `# c\nall: a # trailing\n${T}echo all # not a make comment\na:\n${T}echo a\n`],
    ['assignment kinds', `A = 1\nB := $(A)\nC ?= 3\nD += 4\nall: ;\n`],
    ['hashes in values', `A = x \\# y\nB = x # y\nC = x \\\\# y\nall: ;\n`],
    ['a define', `define D\nline1\nline2\nendef\nall:\n${T}$(D)\n`],
    ['override and export', `override A = 1\nexport B = 2\nexport C := 3\nall: ;\n`],
    ['an include', `include inc.mk\nI2 = $(I)\nall: ;\n`],
    ['a computed name', `N = CMD\n$(N) = foo\nall: ;\n`],
    ['a tab-indented assignment', `all: ;\n${T}A = 1\nB = 2\n`],
    ['dollars', `A = $$HOME $$$$\nall:\n${T}echo $$X $(A)\n`],
    ['a rule with only prerequisites, twice', `all: a\nall: b\na b: ;\n`],
    ['a rule indented with blanks', `  all: a\n${T}echo all\na: ;\n`],
    ['an appended value', `V = a\nV += b\nW :=\nW += c\nall: ;\n`],
    ['a value that continues', `V = a \\\n  b \\\n  c\nall: ;\n`],
  ];
  const root = mkdtempSync(join(tmpdir(), 'make-db-'));
  try {
    writeFileSync(join(root, 'inc.mk'), 'I = 1\n');
    const bad: string[] = [];
    for (const [name, text] of mks) {
      writeFileSync(join(root, 'Makefile'), text);
      const r = spawnSync('make', ['-p', '-q', '-f', 'Makefile'], { cwd: root, encoding: 'utf8', env: { ...process.env, MAKEFLAGS: '' } });
      const lines = r.stdout.split('\n');
      // the database: variables the makefile sets, and the targets whose commands or prerequisites it gives
      const vars = new Map<string, string>();
      const targets = new Map<string, { prereqs: string[]; orderOnly: string[]; recipe: string }>();
      let section = '';
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i]!;
        if (l === '# Variables') section = 'vars';
        else if (l === '# Files') section = 'files';
        else if (/^# (Implicit Rules|Pattern-specific|VPATH)/.test(l)) section = 'other';
        if (section === 'vars' && /^# makefile \(from/.test(l)) {
          const m = /^([^\s=:+?]+)\s*:?=\s?(.*)$/.exec(lines[i + 1] ?? '');
          if (m) vars.set(m[1]!, m[2]!);
        }
        if (section === 'files') {
          const m = /^([^#\s][^:]*):(?::)?\s*(.*)$/.exec(l);
          if (m && !/^\.(SUFFIXES|PHONY)/.test(m[1]!)) {
            let j = i + 1;
            let fromFile = false;
            const rec: string[] = [];
            for (; j < lines.length && (lines[j]!.startsWith('#') || lines[j]!.startsWith('\t')); j++) {
              if (/^#\s{2}commands to execute \(from/.test(lines[j]!)) fromFile = true;
              if (lines[j]!.startsWith('\t')) rec.push(lines[j]!.trim());
            }
            const [pre, ord] = (' ' + m[2]!).split(' | ');
            const ws = (s: string | undefined): string[] => (s ?? '').split(/\s+/).filter(Boolean);
            if (fromFile || ws(pre).length) targets.set(m[1]!, { prereqs: ws(pre), orderOnly: ws(ord), recipe: rec.join('').replace(/\s+/g, '') });
          }
        }
      }
      const store = new MakeStore({ builtinVariables: false });
      const model = newMakeModel(store);
      new MakeReader(
        { read: (p) => (p.endsWith('inc.mk') ? 'I = 1\n' : p.endsWith('Makefile') ? text : null), opened: (d, n) => join(d, n), exists: (p) => p.endsWith('inc.mk'), glob: () => ({ names: [], incomplete: false }), ordinaryShell: () => true },
        model,
        [],
      ).readRoot(join(root, 'Makefile'), root);
      const set = (a: string[]): string => [...new Set(a)].sort().join(' ');
      for (const [t, d] of targets) {
        const mine = model.rules.get(t);
        if (mine === undefined) bad.push(`${name}: make has the target ${t}, the reader does not`);
        else {
          if (set(d.prereqs) !== set(mine.prereqs)) bad.push(`${name}: prerequisites of ${t}: make [${d.prereqs}] reader [${mine.prereqs}]`);
          if (set(d.orderOnly) !== set(mine.orderOnly)) bad.push(`${name}: order-only prerequisites of ${t}: make [${d.orderOnly}] reader [${mine.orderOnly}]`);
          // (a continued recipe is printed by make with its backslash, and read here with the newline it is handed to the shell with)
          const norm = (x: string): string => x.replace(/\\/g, '').replace(/\s+/g, '');
          if (norm(d.recipe) !== norm(mine.recipes.join(''))) bad.push(`${name}: recipe of ${t}: make ${JSON.stringify(d.recipe)} reader ${JSON.stringify(mine.recipes)}`);
        }
      }
      for (const [v, val] of vars) {
        if (/^(MAKEFILE_LIST|MAKEFLAGS|MFLAGS|MAKEOVERRIDES|CURDIR|\.DEFAULT_GOAL)$/.test(v)) continue;
        const mine = store.has(v) ? (store.isSimple(v) ? store.expand(`$(${v})`).alts[0]?.text : store.text(v)) : undefined;
        if (mine === undefined) bad.push(`${name}: make sets ${v}, the reader does not`);
        else if (mine !== null && mine !== val) bad.push(`${name}: ${v} is ${JSON.stringify(val)} to make and ${JSON.stringify(mine)} to the reader`);
      }
    }
    assert.deepEqual(bad, []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

/* ------------------------------------------------------------------------------------------------------------- *
 * MK-10 / TG-01. THE ORDINARY MAKEFILE IS READ, NOT GUESSED AT
 * ------------------------------------------------------------------------------------------------------------- */

test('MK-10. makefiles as the world writes them are not gated, in every spelling of the command that runs them', () => {
  const gated: string[] = [];
  for (const { id, files, commands } of ORDINARY_MAKEFILES) {
    const dir = workspace({ ...files });
    for (const c of commands) {
      const got = verdict(c, dir);
      if (got !== 'ALLOW') gated.push(`${got} ${c}  (${id})`);
    }
  }
  assert.deepEqual(gated, []);
});

test('MK-10. the variables make sets itself are known, and the ones an environment sets are not guessed at', () => {
  const echo = (words: string): Record<string, string> => ({ Makefile: `build:\n${T}echo ${words}\n` });
  check([
    ['CURDIR, MAKEFILE_LIST, MAKECMDGOALS, MAKELEVEL, MAKE, MAKE_VERSION, SHELL, CC and RM', 'make build', echo('$(CURDIR) $(MAKEFILE_LIST) $(MAKECMDGOALS) $(MAKELEVEL) $(MAKE) $(MAKE_VERSION) $(SHELL) $(CC) $(RM)'), 'ALLOW'],
    ['the user\'s own HOME, USER and PWD', 'make build', echo('$(HOME) $(USER) $(PWD)'), 'ALLOW'],
    ['the flags of the implicit rules, nobody set', 'make build', echo('$(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)'), 'ALLOW'],
    ['a name nobody defined stays unknown', 'make build', echo('$(SOMETHING_ELSE)'), 'GATED'],
    ['...unless it is in double quotes, where it is one word', 'make build', { Makefile: `build:\n${T}echo "$(SOMETHING_ELSE)"\n` }, 'ALLOW'],
    ['CFLAGS from the command line is a value, read', `make 'CFLAGS=; ${ACT}' build`, { Makefile: `build:\n${T}cc $(CFLAGS) -c a.c\n`, 'a.c': 'x' }, 'DENY'],
    ['CURDIR is the directory of -C', 'make -C sub build', { 'sub/Makefile': `build:\n${T}echo $(CURDIR)\n` }, 'ALLOW'],
    ['MAKEFILE_LIST names the included files', 'make build', { Makefile: `include inc.mk\nbuild:\n${T}echo $(MAKEFILE_LIST)\n`, 'inc.mk': 'X = 1\n' }, 'ALLOW'],
    ['$^ is the list of the prerequisites', 'make app', { Makefile: `OBJS = a.o b.o\napp: $(OBJS)\n${T}cc -o $@ $^\n`, 'a.c': 'x', 'b.c': 'y' }, 'ALLOW'],
    ['$^ names what is built from a file the command line changes', `make 'OBJS=a.o; ${ACT}' app`, { Makefile: `OBJS = a.o\napp: $(OBJS)\n${T}cc -o $@ $^\n`, 'a.c': 'x' }, 'DENY'],
  ]);
});

/* ------------------------------------------------------------------------------------------------------------- *
 * THE READER AGAINST THE REAL MAKE (skipped where make is not GNU make)
 * ------------------------------------------------------------------------------------------------------------- */

test('REAL MAKE. nothing the logging git was run with was allowed - the cases the reviewers\' harness found, and the implicit ones', { skip: !realMakeAvailable() }, () => {
  const root = oracleRoot();
  try {
    const cases = implicitCases();
    const bad: string[] = [];
    let ran = 0;
    for (const c of cases) {
      const real = runReal(root, c).filter((l) => l.includes(c.tag));
      if (real.length > 0) ran++;
      const got = verdict(c.cmd, workspace({ ...c.files }));
      if (real.length > 0 && got === 'ALLOW') bad.push(`${c.name}: make ran "git ${real[0]}" and the verdict was ALLOW  [${c.cmd}]`);
    }
    assert.deepEqual(bad, []);
    assert.ok(ran >= 10, `the oracle has no teeth: only ${ran} of ${cases.length} cases ran the act under this make`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('REAL MAKE. every place make expands text while it reads the makefile runs a $(shell), and the verdict says so', { skip: !realMakeAvailable() }, () => {
  const root = oracleRoot();
  try {
    const cases = siteCases();
    const bad: string[] = [];
    let ran = 0;
    for (const c of cases) {
      const real = runReal(root, c).filter((l) => l.includes(c.tag));
      if (real.length > 0) ran++;
      const got = verdict(c.cmd, workspace({ ...c.files }));
      if (real.length > 0 && got === 'ALLOW') bad.push(`${c.name}: make ran "git ${real[0]}" and the verdict was ALLOW\n${c.files['Makefile']}`);
    }
    assert.deepEqual(bad, []);
    assert.ok(ran >= cases.length * 0.7, `the sites have no teeth: only ${ran} of ${cases.length} ran the act under this make`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('REAL MAKE. PROPERTY: for makefiles composed from the constructs of make, whatever the logging git was run with is never allowed (seeded)', { skip: !realMakeAvailable() }, () => {
  const root = oracleRoot();
  try {
    const cases = generateCases(20261002, 150);
    const bad: string[] = [];
    let ran = 0;
    for (const c of cases) {
      const real = runReal(root, c).filter((l) => l.includes(c.tag));
      if (real.length > 0) ran++;
      const got = verdict(c.cmd, workspace({ ...c.files }));
      if (real.length > 0 && got === 'ALLOW')
        bad.push(`${c.name}: make ran "git ${real[0]}" and the verdict was ALLOW\n    ${c.cmd}\n    ${JSON.stringify(c.files)}`);
    }
    assert.deepEqual(bad, []);
    assert.ok(ran >= cases.length * 0.3, `the generator has no teeth: only ${ran} of ${cases.length} cases ran the act under this make`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
