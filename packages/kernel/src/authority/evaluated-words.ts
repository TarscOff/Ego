// WHICH WORDS OF A COMMAND THE SHELL EVALUATES AS CODE (closure audit 2026-10-02, SH-4).
//
// The splitter reads a single-quoted word as inert text, and for an ordinary argument that is exactly right: `grep 'a[$(x)]' f`,
// `echo '$(date)'` and `git commit -m 'fix $(x)'` run nothing. But some builtins do not take their operand as data - they EVALUATE it.
// A subscript is an arithmetic expression, so `declare 'a[$(git push origin main)]=1'`, `read 'a[$(…)]'`, `unset 'a[$(…)]'`,
// `let 'a[$(…)]=1'` and `[[ 'a[$(…)]' -eq 1 ]]` run the command in the brackets, whatever quote the word wore, because the quote
// protects the word from splitting and globbing and the builtin evaluates what it receives. Checked against bash 3.2, GNU bash 5.2 and
// zsh 5.9 with a fake `git` that logs what really ran (the differential in closure-shell2.test.ts repeats it for every builtin the
// installed shells list), and not one of them was read by the evaluator: the only readers of "this text runs a command" were the
// splitter's scan for `$( )` outside single quotes and the heredoc body's.
//
// So the question is asked here, once, of the words of a command: WHICH OF THEM ARE EVALUATED. The commands inside them are found by
// the lexer's one reader (shell-lexer.ts: expressionCommands). This module knows builtins; it knows no tool, no capability, no verdict.

import { expressionCommands } from './shell-lexer.ts';

/** how a builtin reads its operands */
type Reading =
  /** `NAME` or `NAME[SUBSCRIPT]=VALUE`: the name part is read as a variable reference, so its subscript is evaluated; the value is data
   *  unless the variable is an INTEGER (or a nameref), whose value is evaluated on assignment and on use */
  | 'declaration'
  /** every operand is a name that may carry a subscript (`read 'a[EXPR]'`, `unset 'a[EXPR]'`) */
  | 'names'
  /** `printf -v NAME` and `print -v NAME` write into a name that may carry a subscript; `print -P TEXT` expands TEXT as a prompt */
  | 'print'
  /** every operand is an arithmetic expression (`let`, and zsh's `return`, `shift`, `break`, `continue`, `exit`) */
  | 'expressions'
  /** the operands of the arithmetic comparisons (`-eq` … `-ge`) and of `-v` / `-R` are expressions or names */
  | 'comparison';

/** DERIVED FROM THE SHELLS, not from a list of what is risky: every builtin of bash 3.2, GNU bash 5.2 and zsh 5.9 was run with a
 *  subscript holding a command in every operand position and option spelling, and these are the ones that ran it. The test file repeats
 *  the sweep for the shells it finds, so a builtin a newer shell evaluates and this table lacks fails there. */
const BUILTIN_READINGS: Readonly<Record<string, Reading>> = {
  declare: 'declaration',
  typeset: 'declaration',
  local: 'declaration',
  readonly: 'declaration',
  export: 'declaration',
  private: 'declaration',
  integer: 'declaration',
  float: 'declaration',
  read: 'names',
  unset: 'names',
  getln: 'names',
  getopts: 'names',
  zparseopts: 'names',
  zformat: 'names',
  mapfile: 'names',
  readarray: 'names',
  printf: 'print',
  print: 'print',
  let: 'expressions',
  return: 'expressions',
  shift: 'expressions',
  break: 'expressions',
  continue: 'expressions',
  exit: 'expressions',
  test: 'comparison',
  '[': 'comparison',
  '[[': 'comparison',
};

/** the builtins that RUN a command string given to `-C`: `mapfile -C CMD -c 1 ARRAY` calls it for every line read (GNU bash 5.2 ran it),
 *  `complete -C CMD` and `compgen -C CMD` call it to produce completions */
const CALLBACK_VERBS = new Set(['mapfile', 'readarray', 'complete', 'compgen']);

/** the options of `read` whose next word is a value (a prompt, a delimiter, a count, a timeout, a descriptor, initial text): data */
const READ_VALUED = /^-[A-Za-z]*[pdnNtui]$/;

/** where the NAME of a `NAME[SUBSCRIPT]=VALUE` word ends: its first `=` outside brackets */
function splitAssignment(word: string): { name: string; value: string | null } {
  let depth = 0;
  for (let i = 0; i < word.length; i++) {
    const c = word[i];
    if (c === '[') depth++;
    else if (c === ']') depth = Math.max(0, depth - 1);
    else if (c === '=' && depth === 0) return { name: word.slice(0, i).replace(/\+$/, ''), value: word.slice(i + 1) };
  }
  return { name: word, value: null };
}

/** the subscripts a compound assignment names: `([k]=v [$(cmd)]=w)` */
export function compoundSubscripts(value: string): string[] {
  const out: string[] = [];
  for (const m of value.matchAll(/\[([^\]]*)\]\+?=/g)) out.push(m[1]!);
  return out;
}

/**
 * The texts a builtin EVALUATES, and the command strings it RUNS, among its operands. `args` are the words with their quoting
 * removed (and a `$'…'` decoded), as the builtin receives them. The expressions are meant to be read by `expressionCommands`.
 */
export function evaluatedOperands(verb: string, args: readonly string[]): { expressions: string[]; commands: string[] } {
  const expressions: string[] = [];
  const commands: string[] = [];
  const base = verb.replace(/^.*\//, '');
  if (CALLBACK_VERBS.has(base))
    for (let i = 0; i < args.length; i++)
      if (/^-[A-Za-z]*C$/.test(args[i]!) && args[i + 1] !== undefined) {
        commands.push(args[i + 1]!);
        i++;
      }
  const reading = BUILTIN_READINGS[base];
  if (reading === undefined) return { expressions, commands };
  switch (reading) {
    case 'declaration': {
      // an option cluster says what the variable IS: `-i` (integer) and `-n` (nameref) evaluate the value too
      const evaluatesValue = args.some((a) => /^[-+][A-Za-z]*[in]/.test(a));
      for (const a of args) {
        if (/^[-+]/.test(a)) continue;
        const { name, value } = splitAssignment(a);
        expressions.push(name);
        if (value === null) continue;
        if (value.startsWith('(')) expressions.push(...compoundSubscripts(value));
        else if (evaluatesValue) expressions.push(value);
      }
      break;
    }
    case 'names': {
      for (let i = 0; i < args.length; i++) {
        const a = args[i]!;
        if (a === '--') continue;
        if (/^-[A-Za-z]/.test(a)) {
          // (a valued option's word is data; a cluster that ends in one takes the NEXT word)
          if (base === 'read' && READ_VALUED.test(a)) i++;
          continue;
        }
        expressions.push(a);
      }
      break;
    }
    case 'print': {
      for (let i = 0; i < args.length; i++) {
        const a = args[i]!;
        if (a === '--') break;
        if (a === '-v' && args[i + 1] !== undefined) {
          expressions.push(args[i + 1]!);
          i++;
        } else if (/^-v\S/.test(a)) expressions.push(a.slice(2));
        // zsh: `print -P TEXT` expands TEXT as a prompt, where a substitution runs when the shell has `promptsubst` on
        else if (base === 'print' && /^-[A-Za-z]*P/.test(a)) expressions.push(...args.slice(i + 1).filter((x) => x !== '--'));
        else if (!a.startsWith('-')) break;
      }
      break;
    }
    case 'expressions': {
      for (const a of args) if (a !== '--') expressions.push(a);
      break;
    }
    case 'comparison': {
      for (let i = 0; i < args.length; i++) {
        const a = args[i]!;
        if (/^-(eq|ne|lt|le|gt|ge)$/.test(a)) {
          if (i > 0) expressions.push(args[i - 1]!);
          if (args[i + 1] !== undefined) expressions.push(args[i + 1]!);
        } else if (/^-[vR]$/.test(a) && args[i + 1] !== undefined) expressions.push(args[i + 1]!);
      }
      break;
    }
  }
  return { expressions, commands };
}

/** The commands a simple command runs by EVALUATING its operands: the verb and operands after the shell has removed the quoting, and
 *  the words in front of the verb (an assignment's subscript). Empty for every command that takes its operands as data. */
export function evaluatedCommands(prefix: readonly string[], verb: string | undefined, args: readonly string[]): string[] {
  const expressions: string[] = [];
  const commands: string[] = [];
  // `a[EXPR]=v` and `a=([EXPR]=v)` in front of the command: the subscript of an assignment is evaluated
  // (an assignment WITH a subscript is not one to the splitter's list of leading assignments, so it arrives as the verb)
  for (const w of verb !== undefined ? [...prefix, verb] : prefix) {
    const { name, value } = splitAssignment(w);
    if (/^[A-Za-z_][A-Za-z0-9_]*\[/.test(name)) expressions.push(name);
    if (value !== null && value.startsWith('(')) expressions.push(...compoundSubscripts(value));
  }
  if (verb !== undefined) {
    const r = evaluatedOperands(verb, args);
    expressions.push(...r.expressions);
    commands.push(...r.commands);
    // a compound assignment spread over several words: `declare -a a=(x ['$(cmd)']=1)`
    const joined = args.join(' ');
    if (/=\(/.test(joined)) expressions.push(...compoundSubscripts(joined));
  }
  return [...commands, ...expressions.flatMap((e) => expressionCommands(e))];
}
