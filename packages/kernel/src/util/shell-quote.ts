// Turning an argument vector into the command line a POSIX shell would execute as that very vector.
//
// A host that hands the hook an argv array (Codex's `shell` tool sends `["bash","-lc","git push"]`) has not given a
// string, and the evaluator classifies strings. Joining the elements with spaces would be wrong in both directions: the
// element `git push` would read as two words, and a metacharacter in an element would run. Each element that is not made
// of characters no shell treats specially is therefore single-quoted, so the line classifies as exactly the command the
// host will execute.

const SAFE_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;

/** One argument as a single shell word. */
export function shellQuote(arg: string): string {
  if (arg === '') return "''";
  if (SAFE_WORD.test(arg)) return arg;
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

/** An argv as a command line, or null when it is not a non-empty array of strings (then it is not an argv). */
export function argvToCommandLine(argv: unknown): string | null {
  if (!Array.isArray(argv) || argv.length === 0) return null;
  if (!argv.every((a) => typeof a === 'string')) return null;
  // `FOO=bar` as the FIRST word is an environment assignment to a shell, but a program name to `execve`
  return (argv as string[]).map((a, i) => (i === 0 && a.includes('=') ? `'${a.replace(/'/g, `'\\''`)}'` : shellQuote(a))).join(' ');
}
