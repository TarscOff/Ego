// ONE RECORDER OF WHAT A SHELL LINE BINDS (closure audit 2026-10-01, wave 3, "environment").
//
// What the next command runs in is a fact about variables: PATH decides which `ls` runs, EDITOR which program `git commit`
// opens, BASH_ENV which file a shell reads first, NODE_OPTIONS which module node loads. A variable is bound by far more than
// `NAME=value`: `export` and its kin, `env` in front of a command, `printf -v NAME`, `read NAME`, `mapfile NAME`, `getopts
// SPEC NAME`, a `for NAME in` loop, `let`, and the `${NAME:=default}` expansion. The evaluator knew three of them, each at its
// own place and with its own regex, and every builtin that was not one of the three bound a name without the evaluator
// noticing: `printf -v PATH %s "$PWD/bin"; ls` ran a planted `ls` at ALLOW, and `read EDITOR <<< /tmp/x; git commit` opened a
// program of the caller's choosing (exit review 11, #108; self-attack 10, #86).
//
// So the question is asked here, once, of the words of a command: WHAT NAMES DOES THIS COMMAND BIND, and to what (a literal
// when one is written, otherwise null - "set at run time to something nobody can read"). The evaluator decides what a binding
// of a particular name costs; this module knows nothing of names that matter.
//
// A binding is PERSISTENT when it outlives the command that makes it (`export A=b`, `printf -v A`, a line that is only
// assignments) and TEMPORARY when it is the environment of one command (`A=b cmd`, `env A=b cmd`). Only the first changes what
// later commands run in; the second is read where the command it configures is read.

export interface Binding {
  name: string;
  /** the literal value when one is written; null when it is bound at run time to something this kernel cannot read */
  value: string | null;
  how: 'assignment' | 'declaration' | 'read' | 'printf' | 'mapfile' | 'getopts' | 'loop' | 'let' | 'default-expansion' | 'env';
}

/**
 * `NAME=value`, `NAME+=value` and `NAME[index]=value`: a word that, in a position where the shell reads assignments, binds.
 * The word is what the command receives - the shell removed its quotes - so `'EDITOR=/tmp/x'` handed to `env` or `export` is an
 * assignment exactly as the bare spelling is.
 */
export function assignmentWord(word: string): { name: string; value: string; append: boolean } | null {
  const m = /^([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?(\+?)=([\s\S]*)$/.exec(word);
  return m === null ? null : { name: m[1]!, value: m[3]!, append: m[2] === '+' };
}

const DECLARATIONS = new Set(['export', 'declare', 'typeset', 'readonly', 'local']);
/** `read` options that take the next word (or the rest of their own word) */
const READ_WITH_VALUE = /^-[A-Za-z]*[adinNptu]$/;
const MAPFILE_WITH_VALUE = /^-[A-Za-z]*[dnOsuCc]$/;

const isName = (w: string): boolean => /^[A-Za-z_][A-Za-z0-9_]*$/.test(w);

/**
 * What the command written as `words` binds. `words` are the shell's words with their quotes removed; the caller has already
 * taken the leading shell keywords (`if`, `then`, `do`, `!`, `time`) off the front. `raw` is the command as written, read for the
 * `${NAME:=default}` expansions, which bind wherever they stand.
 */
export function bindingsOf(words: readonly string[], raw: string): { persistent: Binding[]; temporary: Binding[] } {
  const temporary: Binding[] = [];
  const persistent: Binding[] = [];
  let i = 0;
  // the assignments in front of the command
  const leading: Binding[] = [];
  while (i < words.length) {
    const a = assignmentWord(words[i]!);
    if (a === null) break;
    leading.push({ name: a.name, value: a.append ? null : a.value, how: 'assignment' });
    i++;
  }
  // a line that is only assignments binds for the rest of the shell
  if (i >= words.length) persistent.push(...leading);
  else temporary.push(...leading);
  // `command` and `builtin` only choose how the name is looked up
  while (i < words.length && (words[i] === 'command' || words[i] === 'builtin')) i++;
  const head = (words[i] ?? '').replace(/^.*\//, '');
  const rest = words.slice(i + 1);
  if (DECLARATIONS.has(head)) {
    // `export -f NAME` and `declare -F` talk about functions, not variables
    const functionsOnly = rest.some((w) => /^-[A-Za-z]*[fF][A-Za-z]*$/.test(w));
    if (!functionsOnly)
      for (const w of rest) {
        if (/^[-+]/.test(w)) continue;
        const a = assignmentWord(w);
        if (a !== null) persistent.push({ name: a.name, value: a.append ? null : a.value, how: 'declaration' });
      }
  } else if (head === 'printf') {
    // `printf -v NAME FORMAT ARGS…` writes the formatted text into NAME
    for (let k = 0; k < rest.length; k++) {
      const w = rest[k]!;
      if (w === '-v' && rest[k + 1] !== undefined) {
        const n = rest[k + 1]!.replace(/\[[^\]]*\]$/, '');
        if (isName(n)) persistent.push({ name: n, value: null, how: 'printf' });
        break;
      }
      const glued = /^-v([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?$/.exec(w);
      if (glued) {
        persistent.push({ name: glued[1]!, value: null, how: 'printf' });
        break;
      }
      if (!w.startsWith('-')) break;
    }
  } else if (head === 'read') {
    const names: string[] = [];
    for (let k = 0; k < rest.length; k++) {
      const w = rest[k]!;
      if (w === '--') {
        names.push(...rest.slice(k + 1));
        break;
      }
      if (/^-[A-Za-z]/.test(w)) {
        // an option that takes a value takes the next word when it is the last letter of its cluster (`-p PROMPT`, `-a ARRAY`)
        if (READ_WITH_VALUE.test(w)) {
          if (w.endsWith('a') && rest[k + 1] !== undefined) names.push(rest[k + 1]!);
          k++;
        }
        continue;
      }
      names.push(w);
    }
    // (zsh: `read name?prompt`)
    const bound = names.map((n) => n.replace(/\?.*$/, '').replace(/\[[^\]]*\]$/, '')).filter(isName);
    if (bound.length === 0 && names.length === 0) bound.push('REPLY');
    for (const n of bound) persistent.push({ name: n, value: null, how: 'read' });
  } else if (head === 'mapfile' || head === 'readarray') {
    let name: string | null = null;
    for (let k = 0; k < rest.length; k++) {
      const w = rest[k]!;
      if (/^-[A-Za-z]/.test(w)) {
        if (MAPFILE_WITH_VALUE.test(w)) k++;
        continue;
      }
      name = w;
      break;
    }
    persistent.push({ name: name !== null && isName(name) ? name : 'MAPFILE', value: null, how: 'mapfile' });
  } else if (head === 'getopts') {
    // `getopts OPTSTRING NAME [ARGS]` writes the option letter into NAME, and OPTARG / OPTIND beside it
    const n = rest[1];
    if (n !== undefined && isName(n)) persistent.push({ name: n, value: null, how: 'getopts' });
  } else if (head === 'let') {
    for (const w of rest) {
      const a = assignmentWord(w);
      if (a !== null) persistent.push({ name: a.name, value: null, how: 'let' });
    }
  } else if (head === 'for' || head === 'select') {
    // `for NAME in WORDS…; do` binds NAME to each word in turn
    const n = rest[0];
    if (n !== undefined && isName(n)) persistent.push({ name: n, value: null, how: 'loop' });
  }
  // `${NAME:=default}` and `${NAME=default}` bind NAME when it is unset, wherever the expansion stands
  for (const m of raw.matchAll(/\$\{([A-Za-z_][A-Za-z0-9_]*):?=([^}]*)\}/g))
    persistent.push({ name: m[1]!, value: /[$`]/.test(m[2]!) ? null : m[2]!, how: 'default-expansion' });
  return { persistent, temporary };
}
