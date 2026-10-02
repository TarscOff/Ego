// THE ONE MODEL OF A GNU MAKE INVOCATION'S VARIABLES (closure audit 2026-10-02, wave 6, MK-01..MK-10).
//
// Ten findings were one question asked in ten places: WHAT TEXT DOES MAKE HAND TO THE SHELL, AND WHAT DOES IT RUN ON THE WAY? The previous
// waves answered it with three readers that each knew a different subset of GNU make - a command-line reader that took `CMD:=x` for a goal,
// a line reader that dropped a tab-indented assignment, a flat `Map<string, string>` of variables that was overwritten by every include, an
// expander that was exponential in the number of references. Each defect was a way two of them disagreed, so this module is ONE of each:
//
//   1. THE LINES (`makeLogicalLines`, `collapseContinuations`, `cutMakeComment`): a backslash continues a line only when it is the ODD one
//      out; a comment ends at an unescaped `#` and a variable's value ends there too.
//   2. THE COMMAND LINE (`parseMakeCommandLine`): every word that holds `=` is a variable definition to make, never a goal.
//   3. THE VARIABLES (`MakeStore`): origin and precedence (default < environment < makefile < -e < command line < override), flavour
//      (recursive or simple), the values a conditional can give, what is exported.
//   4. THE EXPANSION (`MakeStore.expand`): one evaluator for `$(NAME)`, `$(NAME:a=b)`, a computed name, and every text function, that
//      returns the text AND the commands make runs while getting there. It is BOUNDED: every step is charged to the decision's work
//      counter, a variable's expansion is memoised, and the size of any result is capped - a bound that is reached ends in an unknown
//      value and a flag, never a long computation (MK-09: 654 bytes of makefile took 42 s, and a hook that has not answered has not refused).
//   5. THE READER (`MakeReader`): classifies each line the way GNU make's own reader does - a tab-indented line outside a rule is a makefile
//      line; `override` does not end a rule; an include is read INLINE, into the same store, at the line of the directive.
//
// What an expansion cannot know is `null`, never the empty string: "a variable this resolver never saw defined is not provably empty".
import { chargeWork } from './work-bound.ts';
import { BUILTIN_VARIABLES, IMPLICIT_RULE_INPUTS, patternStem } from './make-builtins.ts';

/* ------------------------------------------------------------------------------------------------------------- *
 * 1. LINES AND NAMES
 * ------------------------------------------------------------------------------------------------------------- */

/** make's file-name wildcards: the names a pattern denotes are the directory's, not the makefile's */
export const MAKE_WILDCARD = /[*?[]/;
/** `$(file >NAME,TEXT)` and `$(file >>NAME,TEXT)`: the write forms of the `file` function (`<NAME` only reads) */
export const MAKE_FILE_WRITE = /\$[({]file\s*>/;

/** GNU make continues a line only when it ends in an ODD number of backslashes: an even count is literal backslashes and the next line
 *  stands alone (MK-03: `X = a\\` followed by a rule hid the rule). */
export function continues(line: string): boolean {
  let n = 0;
  for (let i = line.length - 1; i >= 0 && line[i] === '\\'; i--) n++;
  return n % 2 === 1;
}

/** The logical lines of a makefile: each physical line that continues is joined to the next with the backslash-newline KEPT, because
 *  what the join means depends on what the line turns out to be (a recipe hands it to the shell; anything else collapses it). */
export function makeLogicalLines(text: string): string[] {
  chargeWork(text.length);
  const raw = text.split(/\r?\n/);
  const out: string[] = [];
  for (let i = 0; i < raw.length; i++) {
    let line = raw[i]!;
    while (i + 1 < raw.length && continues(line)) line += '\n' + raw[++i]!;
    out.push(line);
  }
  return out;
}

/** Outside a recipe, a backslash-newline and the blanks around it are ONE space. */
export function collapseContinuations(line: string): string {
  return line.includes('\n') ? line.replace(/[ \t]*\\\n[ \t]*/g, ' ') : line;
}

/** A recipe line keeps its backslash-newlines (the shell reads them); the recipe prefix of a continuation line is dropped, as make does. */
export function recipeText(line: string, prefix: string): string {
  const body = line.slice(prefix.length);
  return body.includes('\n') ? body.replace(new RegExp(`\\n${prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'g'), '\n') : body;
}

/** The text before the first UNESCAPED `#`. An escape stays as written (`\#`): the readers of names and values unescape it themselves,
 *  and a run of backslashes halves - `a \\# b` is `a \` and a comment, `a \# b` is `a # b`. */
export function cutMakeComment(line: string): string {
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (c === '\\') {
      let n = 1;
      while (line[i + n] === '\\') n++;
      if (line[i + n] === '#') {
        if (n % 2 === 0) return line.slice(0, i + n);
        i += n;
        continue;
      }
      i += n - 1;
      continue;
    }
    if (c === '#') return line.slice(0, i);
  }
  return line;
}

/** `\#` is a `#` in a value; a run of backslashes before it halves. (The comment was cut first, so every run left is an odd one.) */
export function unescapeMakeHash(s: string): string {
  return s.replace(/(\\+)#/g, (_m, b: string) => '\\'.repeat(b.length >> 1) + '#');
}

/**
 * THE COMMANDS OF AN EXPANDED RECIPE LINE. make expands a recipe line first and only then cuts it into commands at its newlines (a newline
 * that a backslash continues stays in the command), and reads each command's own prefix characters - `@` `-` `+`, with blanks between them -
 * off its start. A canned recipe (`define BUILD` ... `endef`, used as `$(call BUILD,app)`) is several commands in one line, and the prefix of
 * the second one was left on it: `@echo building app` is a command that does not exist.
 */
export function recipeCommands(expanded: string): Array<{ command: string; plus: boolean }> {
  const out: Array<{ command: string; plus: boolean }> = [];
  for (const piece of makeLogicalLines(expanded)) {
    const plus = /^[@\s-]*\+/.test(piece);
    const command = piece.replace(/^[@+\s-]*[@+-]/, '').trimStart().replace(/^[@+-]+/, '').trim();
    if (command) out.push({ command, plus });
  }
  return out;
}

/** The index of the character that closes the `$(` or `${` that opens at `at`, counting only its own kind of bracket as make does; -1 when it never closes. */
export function closeOfReference(s: string, at: number): number {
  const open = s[at + 1];
  const close = open === '(' ? ')' : '}';
  let d = 0;
  for (let j = at + 1; j < s.length; j++) {
    if (s[j] === open) d++;
    else if (s[j] === close && --d === 0) return j;
  }
  return -1;
}

/**
 * A LIST OF FILE NAMES IN A MAKEFILE, READ THE WAY MAKE READS IT - THE ONE READER OF THE QUESTION "WHAT ARE THE NAMES HERE". A rule's
 * targets, its prerequisites, an `include` and a default goal all name files, and each was split on `\s+`: make's grammar is not the
 * shell's. Names are separated by unescaped blanks; a backslash in front of a blank, a colon or a hash is part of the name (`a\ b:` defines
 * ONE target, `a b`), and a RUN of backslashes in front of one halves (`q\\:` is the name `q\` followed by the colon, `k\\\ l` is the name
 * `k\ l`); a backslash in front of anything else stays as written. Checked against GNU make 3.81. A `$(...)` or `${...}` is part of a name
 * and is never cut (`$(OBJS:.c=.o): %.o: %.c` is a rule, and the `:` and the `=` inside the reference are not its colon and its assignment).
 *
 * Returns the names and, when `stopAtColon`, the index of the first colon that ends the list (-1 when none), so the caller reads a rule's
 * head and its tail from the SAME scan. `=` outside an escape is an assignment, not a rule head: the scan reports it as `assignment`.
 */
export function readMakeNames(text: string, stopAtColon: boolean): { names: string[]; colon: number; assignment: boolean } {
  const names: string[] = [];
  let cur = '';
  let open = false;
  let colon = -1;
  const flush = (): void => {
    if (open) names.push(cur);
    cur = '';
    open = false;
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '\\') {
      let n = 1;
      while (text[i + n] === '\\') n++;
      const next = text[i + n];
      open = true;
      if (next === ' ' || next === '\t' || next === ':' || next === '#') {
        // pairs collapse to one backslash; an odd one out escapes the blank, colon or hash, which is then part of the
        // name. After an EVEN run the character keeps its own meaning and is read on the next turn
        cur += '\\'.repeat(n >> 1);
        i += n - 1;
        if (n % 2 === 1) {
          cur += next;
          i++;
        }
      } else {
        cur += '\\'.repeat(n);
        i += n - 1;
      }
      continue;
    }
    if (c === '$' && (text[i + 1] === '(' || text[i + 1] === '{')) {
      const end = closeOfReference(text, i);
      const stop = end < 0 ? text.length - 1 : end;
      cur += text.slice(i, stop + 1);
      open = true;
      i = stop;
      continue;
    }
    if (c === ' ' || c === '\t') {
      flush();
      continue;
    }
    if (c === '#') break; // an unescaped hash starts a comment: nothing after it is a name
    if (stopAtColon && c === ':') {
      colon = i;
      break;
    }
    if (stopAtColon && c === '=') return { names, colon: -1, assignment: true };
    cur += c;
    open = true;
  }
  flush();
  return { names, colon, assignment: false };
}

/** The first `;` that is not inside a `$(...)` and not escaped: where a rule line's one-line recipe begins. */
export function findRecipeSemicolon(s: string): number {
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === '\\') {
      i++;
      continue;
    }
    if (c === '$' && (s[i + 1] === '(' || s[i + 1] === '{')) {
      const end = closeOfReference(s, i);
      if (end < 0) return -1;
      i = end;
      continue;
    }
    if (c === ';') return i;
  }
  return -1;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * 2. THE COMMAND LINE
 * ------------------------------------------------------------------------------------------------------------- */

export type AssignOp = '=' | ':=' | '::=' | ':::=' | '?=' | '+=' | '!=';

export interface MakeAssignment {
  name: string;
  op: AssignOp;
  value: string;
}

/**
 * ONE READER FOR "IS THIS TEXT A VARIABLE DEFINITION": the command-line words use it, and so does the makefile reader (which first cuts
 * the keywords). The name runs to a blank or to the first operator, a `$(...)` inside it belongs to it (a computed name), and the
 * operators are the ones GNU make 3.81 and 4.x have between them: `=` `:=` `::=` `:::=` `?=` `+=` `!=`. A `:` that is not the start of an
 * operator means the text is a RULE, and so is a blank followed by anything but an operator. The value is returned as it stands after
 * the operator, its leading blanks cut; its trailing ones belong to it.
 */
export function readAssignment(s: string): MakeAssignment | null {
  let i = 0;
  let nameEnd = -1;
  for (; i < s.length; i++) {
    const c = s[i]!;
    if (c === '$' && (s[i + 1] === '(' || s[i + 1] === '{')) {
      const end = closeOfReference(s, i);
      if (end < 0) return null;
      i = end;
      continue;
    }
    if (c === ' ' || c === '\t') {
      nameEnd = i;
      while (s[i] === ' ' || s[i] === '\t') i++;
      break;
    }
    if (c === '=' || c === ':' || ((c === '?' || c === '+' || c === '!') && s[i + 1] === '=')) break;
  }
  if (nameEnd < 0) nameEnd = i;
  let op: AssignOp | null = null;
  for (const candidate of [':::=', '::=', ':=', '?=', '+=', '!=', '='] as const)
    if (s.startsWith(candidate, i)) {
      op = candidate;
      break;
    }
  if (op === null || nameEnd === 0) return null;
  return { name: s.slice(0, nameEnd), op, value: s.slice(i + op.length).replace(/^[ \t]+/, '') };
}

/** A MAKE COMMAND LINE, READ THE WAY GNU MAKE'S OWN OPTION PARSER READS IT. Short options cluster and the last letter
 *  that takes a value takes the next word (`-kf other.mk`, `-sC sub`), long options may be abbreviated to any unique
 *  prefix (`--dir=sub`, `--fil x`), `-o`/`-W`/`-I` take a value that can look like a flag (`-o -n`), and `--` ends the
 *  options. The three scans this replaces (goals, `-C`/`-f`, and the dry-run/probe flags) each read a different
 *  subset of this and disagreed (exit review 10, self-attack: nine findings). */
export interface MakeCommandLine {
  dirs: string[];
  files: string[];
  goals: string[];
  /** EVERY word that holds `=`, in order: make takes each of them for a variable definition and none of them for a goal */
  assignments: MakeAssignment[];
  dryRun: boolean;
  question: boolean;
  probe: boolean;
  envOverrides: boolean;
  /** an option this parser does not know: the command line cannot be read with confidence */
  unknown: string | null;
  /** -E / --eval: makefile text supplied on the command line */
  injected: boolean;
  /** -I / --include-dir: where `include` looks when the file is not in the make directory */
  includeDirs: string[];
  /** -j / --jobs other than 1: recipes run at the same time */
  jobs: boolean;
  /** -r / --no-builtin-rules and -R / --no-builtin-variables */
  noBuiltinRules: boolean;
  noBuiltinVariables: boolean;
}
const MAKE_LONG_OPTIONS: Array<{ name: string; value: 'none' | 'required' | 'optional-number'; effect?: string }> = [
  { name: 'directory', value: 'required', effect: 'dir' },
  { name: 'file', value: 'required', effect: 'file' },
  { name: 'makefile', value: 'required', effect: 'file' },
  { name: 'include-dir', value: 'required', effect: 'incdir' },
  { name: 'old-file', value: 'required' },
  { name: 'assume-old', value: 'required' },
  { name: 'new-file', value: 'required' },
  { name: 'assume-new', value: 'required' },
  { name: 'what-if', value: 'required' },
  { name: 'jobs', value: 'optional-number', effect: 'jobs' },
  { name: 'load-average', value: 'optional-number' },
  { name: 'max-load', value: 'optional-number' },
  { name: 'just-print', value: 'none', effect: 'dry' },
  { name: 'dry-run', value: 'none', effect: 'dry' },
  { name: 'recon', value: 'none', effect: 'dry' },
  { name: 'question', value: 'none', effect: 'question' },
  { name: 'environment-overrides', value: 'none', effect: 'env' },
  { name: 'version', value: 'none', effect: 'probe' },
  { name: 'help', value: 'none', effect: 'probe' },
  { name: 'eval', value: 'required', effect: 'inject' },
  { name: 'always-make', value: 'none' },
  { name: 'debug', value: 'optional-number' },
  { name: 'ignore-errors', value: 'none' },
  { name: 'keep-going', value: 'none' },
  { name: 'print-data-base', value: 'none' },
  { name: 'no-builtin-rules', value: 'none', effect: 'norules' },
  { name: 'no-builtin-variables', value: 'none', effect: 'novars' },
  { name: 'silent', value: 'none' },
  { name: 'quiet', value: 'none' },
  { name: 'no-keep-going', value: 'none' },
  { name: 'stop', value: 'none' },
  { name: 'touch', value: 'none' },
  { name: 'print-directory', value: 'none' },
  { name: 'no-print-directory', value: 'none' },
  { name: 'warn-undefined-variables', value: 'none' },
  { name: 'check-symlink-times', value: 'none' },
  { name: 'no-silent', value: 'none' },
  { name: 'trace', value: 'none' },
  { name: 'output-sync', value: 'optional-number' },
  { name: 'shuffle', value: 'optional-number' },
];
export function parseMakeCommandLine(words: string[]): MakeCommandLine {
  const out: MakeCommandLine = {
    dirs: [], files: [], goals: [], assignments: [], dryRun: false, question: false, probe: false,
    envOverrides: false, unknown: null, injected: false, includeDirs: [], jobs: false,
    noBuiltinRules: false, noBuiltinVariables: false,
  };
  const SHORT_VALUE = new Set(['C', 'f', 'I', 'o', 'W', 'E']);
  const SHORT_OPTIONAL_NUMBER = new Set(['j', 'l']);
  const SHORT_FLAGS = new Set(['b', 'm', 'B', 'd', 'e', 'h', 'i', 'k', 'L', 'n', 'p', 'q', 'r', 'R', 's', 'S', 't', 'v', 'w', 'O']);
  let optionsEnded = false;
  for (let i = 1; i < words.length; i++) {
    const w = words[i]!;
    if (!optionsEnded && w === '--') {
      optionsEnded = true;
      continue;
    }
    if (!optionsEnded && w.startsWith('--')) {
      const eq = w.indexOf('=');
      const name = w.slice(2, eq < 0 ? undefined : eq);
      const hits = MAKE_LONG_OPTIONS.filter((o) => o.name === name);
      const cands = hits.length ? hits : MAKE_LONG_OPTIONS.filter((o) => o.name.startsWith(name));
      if (cands.length === 0 || (cands.length > 1 && new Set(cands.map((c) => `${c.value}:${c.effect ?? ''}`)).size > 1)) {
        out.unknown = w;
        continue;
      }
      const o = cands[0]!;
      let value: string | undefined = eq >= 0 ? w.slice(eq + 1) : undefined;
      if (o.value === 'required' && value === undefined) value = words[++i];
      else if (o.value === 'optional-number' && value === undefined && /^\d+(\.\d+)?$/.test(words[i + 1] ?? '')) value = words[++i];
      if (o.effect === 'dir' && value) out.dirs.push(value);
      else if (o.effect === 'file' && value) out.files.push(value);
      else if (o.effect === 'dry') out.dryRun = true;
      else if (o.effect === 'question') out.question = true;
      else if (o.effect === 'env') out.envOverrides = true;
      else if (o.effect === 'probe') out.probe = true;
      else if (o.effect === 'inject') out.injected = true;
      else if (o.effect === 'incdir' && value) out.includeDirs.push(value);
      else if (o.effect === 'norules') out.noBuiltinRules = true;
      else if (o.effect === 'novars') out.noBuiltinVariables = true;
      // `-j` with no number is as many jobs as there are recipes; `-j1` is the only serial one
      else if (o.effect === 'jobs') out.jobs ||= value === undefined || Number(value) !== 1;
      continue;
    }
    if (!optionsEnded && w.startsWith('-') && w.length > 1) {
      for (let k = 1; k < w.length; k++) {
        const c = w[k]!;
        if (SHORT_VALUE.has(c) || SHORT_OPTIONAL_NUMBER.has(c)) {
          const glued = w.slice(k + 1);
          let value: string | undefined = glued || undefined;
          if (value === undefined) {
            if (SHORT_VALUE.has(c)) value = words[++i];
            else if (/^\d+(\.\d+)?$/.test(words[i + 1] ?? '')) value = words[++i];
          }
          if (c === 'C' && value) out.dirs.push(value);
          else if (c === 'f' && value) out.files.push(value);
          else if (c === 'I' && value) out.includeDirs.push(value);
          else if (c === 'E') out.injected = true;
          else if (c === 'j') out.jobs ||= value === undefined || Number(value) !== 1;
          break;
        }
        if (!SHORT_FLAGS.has(c)) {
          out.unknown = w;
          break;
        }
        if (c === 'n') out.dryRun = true;
        else if (c === 'q') out.question = true;
        else if (c === 'e') out.envOverrides = true;
        else if (c === 'h' || c === 'v') out.probe = true;
        else if (c === 'r') out.noBuiltinRules = true;
        else if (c === 'R') out.noBuiltinVariables = true;
      }
      continue;
    }
    // A WORD THAT HOLDS `=` IS A VARIABLE DEFINITION TO MAKE, NEVER A GOAL (MK-01). The reader that took only `NAME=value` for one
    // let `CMD:=x`, `CMD?=x`, `'CMD = x'` and `.DEFAULT_GOAL=x` through as goals no rule defined - "absent" - while make used them. A name
    // with a colon in it (`a:b=c`) is the one exception: make reads it as a goal, and says so.
    const eq = w.indexOf('=');
    if (eq >= 0) {
      const a = readAssignment(w.replace(/^[ \t]+/, ''));
      if (a !== null && !/[:]/.test(a.name)) {
        out.assignments.push(a);
        continue;
      }
      if (!/^[^=]*:[^=]*=/.test(w)) {
        // `A B=c` is a definition of a variable called `A B` (checked against GNU make 3.81); `=c` is "empty variable name", a command
        // line make refuses. A word with an `=` is still never a goal.
        const before = w.slice(0, eq);
        const mark = /[?+!]$/.exec(before)?.[0];
        const name = (mark === undefined ? before : before.slice(0, -1)).trim();
        if (name === '') out.unknown ??= w;
        else out.assignments.push({ name, op: mark === undefined ? '=' : (`${mark}=` as AssignOp), value: w.slice(eq + 1).replace(/^[ \t]+/, '') });
        continue;
      }
    }
    out.goals.push(w.replace(/^(?:\.\/+)+/, ''));
  }
  return out;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * 3. THE VARIABLES
 * ------------------------------------------------------------------------------------------------------------- */

/** Where a variable's value came from, weakest first: a definition from a stronger source is NOT replaced by a weaker one. */
export type MakeOrigin = 'default' | 'environment' | 'file' | 'environment-override' | 'command-line' | 'override';
const ORIGIN_RANK: Record<MakeOrigin, number> = { default: 0, environment: 1, file: 2, 'environment-override': 3, 'command-line': 4, override: 5 };

/** What an unknown piece of a value is stored as: a reference to a variable no one can define, which always expands to "unknown". */
const UNKNOWN_REF = '$(\u0001)';

/** A value that was already expanded, in the form the store keeps: a `$` in it is a literal one, so it is written `$$` and expands to itself once. */
export function encodeMakeParts(parts: ReadonlyArray<string | null>): string {
  return parts.map((p) => (p === null ? UNKNOWN_REF : p.replace(/\$/g, '$$$$'))).join('');
}

interface MakeEntry {
  /** the value as text to be expanded once at each use (a simple variable's is its expansion, `$` doubled) */
  main: string;
  /** every other value a conditional branch could have given it */
  alts: Set<string>;
  simple: boolean;
  origin: MakeOrigin;
}

/** Names whose value is a path or a short word of the session a user logged in to - not a thing an agent writes. Undefined in the makefile
 *  they are the environment's, and the one place a recipe can name them without the makefile defining them is `$(HOME)`. They are
 *  spliced as the shell's own `$NAME`, which the shell reader already judges. */
export const AMBIENT_WORD_VARIABLES: ReadonlySet<string> = new Set([
  'HOME', 'USER', 'LOGNAME', 'PWD', 'OLDPWD', 'TMPDIR', 'LANG', 'LC_ALL', 'TERM', 'TZ', 'SHLVL', 'HOSTNAME', 'UID', 'EUID', 'OS', 'OSTYPE', 'HOSTTYPE', 'MACHTYPE',
]);

/**
 * THE VARIABLES OF ONE INVOCATION. One store serves the command line, the environment this make was started with, the built-in
 * defaults, and every makefile in the order make reads them - an include is read INLINE, so what it assigns, and what it declines to
 * (`?=`, an `ifndef` guard), is judged against what the includer had set (MK-06). A name is a name, however it was spelled: the store
 * is asked for `CMD` and gets the one value make would.
 */
export class MakeStore {
  private readonly entries = new Map<string, MakeEntry>();
  /** `$(wildcard PATTERN)`: the names a pattern denotes in the make directory, or null when they cannot be listed or are not plain words */
  wildcard: ((pattern: string) => string[] | null) | null = null;

  constructor(opts: { builtinVariables?: boolean } = {}) {
    if (opts.builtinVariables !== false)
      for (const [name, value] of BUILTIN_VARIABLES) this.entries.set(name, { main: value, alts: new Set(), simple: false, origin: 'default' });
  }

  has(name: string): boolean {
    return this.entries.has(name);
  }
  originOf(name: string): MakeOrigin | null {
    return this.entries.get(name)?.origin ?? null;
  }
  isSimple(name: string): boolean {
    return this.entries.get(name)?.simple ?? false;
  }
  /** the value make would use (the last assignment), as text to expand */
  text(name: string): string | undefined {
    return this.entries.get(name)?.main;
  }
  /** every value the variable could have: the current one first */
  candidates(name: string): string[] {
    const e = this.entries.get(name);
    return e ? [e.main, ...[...e.alts].filter((a) => a !== e.main)] : [];
  }
  names(): string[] {
    return [...this.entries.keys()];
  }

  /** A literal value (the make directory, the goals, the list of makefiles): nothing in it is a reference. */
  seed(name: string, value: string, origin: MakeOrigin = 'default'): void {
    this.set(name, [value.replace(/\$/g, '$$$$')], { origin, simple: true, conditional: false });
  }

  /**
   * The assignment itself. `texts` are the values the caller prepared for the operator (one, or several when the right-hand side
   * expanded to several alternatives); the first is the value make uses. Returns false when the definition did not take effect: one from
   * a stronger source already holds the name.
   */
  set(name: string, texts: string[], opts: { origin: MakeOrigin; simple: boolean; conditional: boolean }): boolean {
    const old = this.entries.get(name);
    if (old && ORIGIN_RANK[old.origin] > ORIGIN_RANK[opts.origin]) return false;
    // INSIDE A CONDITIONAL EVERY BRANCH IS POSSIBLE: the new values join the old ones; outside one the assignment REPLACES them - except that
    // an ENVIRONMENT value stays a candidate. Without `-e` the makefile's own `=` replaces it, and whether `-e` is in force is a thing a
    // `MAKEFLAGS` in the environment or in the makefile can say where this reader does not look (exit review 10, self-attack): both are read.
    const alts = new Set<string>(old && opts.conditional ? [old.main, ...old.alts] : old?.origin === 'environment' ? [old.main] : []);
    for (const t of texts.slice(1)) alts.add(t);
    this.entries.set(name, { main: texts[0]!, alts, simple: opts.simple, origin: opts.origin });
    return true;
  }

  /** `undefine NAME` (honouring the same precedence as an assignment) */
  undefine(name: string, origin: MakeOrigin): void {
    const old = this.entries.get(name);
    if (old && ORIGIN_RANK[old.origin] <= ORIGIN_RANK[origin]) this.entries.delete(name);
  }

  /** Expand `text` as make would, in this store, with the automatic variables and target-specific values of `scope`. */
  expand(text: string, scope: MakeScope = {}): MakeExpansion {
    const x = new Expander(this, scope);
    let branches: Br[];
    try {
      branches = x.text(text, null);
    } catch (e) {
      if (!(e instanceof Capped)) throw e;
      x.capped = true;
      branches = [[null]];
    }
    const alts: MakeExpansion['alts'] = [];
    const seen = new Set<string>();
    for (const b of branches) {
      const r = render(b);
      const key = `${r.text === null ? '\0' : r.text}\u0000${r.prefix}`;
      if (!seen.has(key)) {
        seen.add(key);
        alts.push(r);
      }
    }
    return { alts, branches, ran: [...x.ran], capped: x.capped, evals: x.evals, fileWrites: x.fileWrites, blind: x.blind };
  }
}

/* ------------------------------------------------------------------------------------------------------------- *
 * 4. THE EXPANSION
 * ------------------------------------------------------------------------------------------------------------- */

export interface MakeScope {
  /** `$@ $< $^ $+ $? $* $% $|` for the recipe line being expanded */
  auto?: Readonly<Record<string, string>>;
  /** target-specific values: recursive text, tried before the global ones */
  overlay?: ReadonlyMap<string, string>;
}

export interface MakeExpansion {
  /** one entry per value the text could take; `text` is null when part of it is unknowable, `prefix` is what is known before the first unknown */
  alts: Array<{ text: string | null; prefix: string }>;
  /** the same values as parts (a string, or null for an unknown piece), for a caller that stores one */
  branches: ReadonlyArray<ReadonlyArray<string | null>>;
  /** every command a `$(shell …)` ran while the text was expanded, whichever branch ran it */
  ran: string[];
  /** a limit was reached: the result is NOT complete */
  capped: boolean;
  /** `$(eval …)` was evaluated: makefile text this reader cannot follow */
  evals: boolean;
  /** `$(file >…)` was evaluated: a file written while the makefile is read */
  fileWrites: boolean;
  /** a `$(shell …)` command was not fully knowable */
  blind: boolean;
}

type Part = string | null;
type Br = Part[];
type Frame = ReadonlyMap<string, Br[]>;

/** the most alternatives one expansion follows, the most work one expansion may do, and the most text any alternative may hold */
const MAX_BRANCHES = 8;
const MAX_STEPS = 40_000;
const MAX_TEXT = 1 << 16;
const MAX_FOREACH = 128;
const MAX_DEPTH = 150;

class Capped extends Error {}

type MNode = string | { k: 'ref'; name: MNode[] } | { k: 'fn'; fn: string; args: MNode[][] } | { k: 'unk' };

/** Each text function's arguments: the fewest, and the most (0 = no limit; commas past the most belong to the last argument). */
const FUNCTIONS: Readonly<Record<string, readonly [number, number]>> = {
  subst: [3, 3], patsubst: [3, 3], strip: [1, 1], findstring: [2, 2], filter: [2, 2], 'filter-out': [2, 2], sort: [1, 1], word: [2, 2],
  wordlist: [3, 3], words: [1, 1], firstword: [1, 1], lastword: [1, 1], dir: [1, 1], notdir: [1, 1], suffix: [1, 1], basename: [1, 1],
  addsuffix: [2, 2], addprefix: [2, 2], join: [2, 2], wildcard: [1, 1], realpath: [1, 1], abspath: [1, 1], if: [2, 3], or: [1, 0], and: [1, 0],
  foreach: [3, 3], call: [1, 0], value: [1, 1], eval: [1, 1], origin: [1, 1], flavor: [1, 1], shell: [1, 1], error: [1, 1], warning: [1, 1],
  info: [1, 1], file: [1, 2], guile: [1, 1], let: [3, 3], intcmp: [2, 5],
};

function splitArguments(text: string, open: string, close: string, max: number): string[] {
  const out: string[] = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === open) depth++;
    else if (c === close) depth--;
    else if (c === ',' && depth <= 0 && (max === 0 || out.length < max - 1)) {
      out.push(text.slice(from, i));
      from = i + 1;
    }
  }
  out.push(text.slice(from));
  return out;
}

/** how deep references may nest in one text before the rest is unknown: a text of twenty thousand `$(` is an attack on the stack, not a makefile */
const MAX_NESTING = 100;

function parseMakeText(text: string, depth = 0): MNode[] {
  if (depth > MAX_NESTING) return [{ k: 'unk' }];
  const nodes: MNode[] = [];
  let lit = '';
  const flush = (): void => {
    if (lit) nodes.push(lit);
    lit = '';
  };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (ch !== '$') {
      lit += ch;
      continue;
    }
    const next = text[i + 1];
    if (next === undefined) {
      lit += '$';
      continue;
    }
    if (next === '$') {
      lit += '$'; // make emits ONE literal `$`: what follows is the SHELL's, so `$$(cmd)` is a substitution
      i++;
      continue;
    }
    if (next !== '(' && next !== '{') {
      flush();
      nodes.push({ k: 'ref', name: [next] });
      i++;
      continue;
    }
    const end = closeOfReference(text, i);
    flush();
    if (end < 0) {
      nodes.push({ k: 'unk' }); // an unterminated reference is a fatal error to make; nothing after it is known
      break;
    }
    const body = text.slice(i + 2, end);
    i = end;
    const close = next === '(' ? ')' : '}';
    const f = /^([A-Za-z][A-Za-z-]*)[ \t]+/.exec(body);
    const spec = f ? FUNCTIONS[f[1]!] : undefined;
    if (f && spec) {
      const args = splitArguments(body.slice(f[0].length), next, close, spec[1]);
      nodes.push({ k: 'fn', fn: f[1]!, args: args.map((a) => parseMakeText(a, depth + 1)) });
    } else nodes.push({ k: 'ref', name: parseMakeText(body, depth + 1) });
  }
  flush();
  return nodes;
}

const words = (s: string): string[] => s.split(/[ \t\n\r\f\v]+/).filter(Boolean);

function patternMatch(pat: string, word: string): string | null {
  const at = pat.indexOf('%');
  if (at < 0) return pat === word ? '' : null;
  return patternStem(pat, word, true);
}
function patsubstOne(from: string, to: string, word: string): string {
  const stem = patternMatch(from, word);
  if (stem === null) return word;
  return to.includes('%') ? to.replace('%', stem) : to;
}
const dirOf = (w: string): string => (w.includes('/') ? w.slice(0, w.lastIndexOf('/') + 1) : './');
const notdirOf = (w: string): string => w.slice(w.lastIndexOf('/') + 1);

/** The text functions that need nothing but their (already expanded) arguments. null = this reader does not compute it. */
function applyPure(fn: string, a: string[]): string | null {
  switch (fn) {
    case 'subst':
      // (an empty search string finds nothing to replace, and make appends the replacement: `$(subst ,X,abc)` is `abcX`)
      return a[0] === '' ? a[2]! + a[1]! : a[2]!.split(a[0]!).join(a[1]!);
    case 'patsubst':
      return words(a[2]!).map((w) => patsubstOne(a[0]!.trim(), a[1]!.trim(), w)).join(' ');
    case 'strip':
      return words(a[0]!).join(' ');
    case 'findstring':
      return a[1]!.includes(a[0]!) ? a[0]! : '';
    case 'filter':
    case 'filter-out': {
      const pats = words(a[0]!);
      const keep = fn === 'filter';
      return words(a[1]!).filter((w) => pats.some((p) => patternMatch(p, w) !== null) === keep).join(' ');
    }
    case 'sort':
      return [...new Set(words(a[0]!))].sort().join(' ');
    case 'word': {
      const n = Number(a[0]!.trim());
      const ws = words(a[1]!);
      return Number.isInteger(n) && n >= 1 ? (ws[n - 1] ?? '') : null;
    }
    case 'wordlist': {
      const s = Number(a[0]!.trim());
      const e = Number(a[1]!.trim());
      return Number.isInteger(s) && Number.isInteger(e) && s >= 1 ? words(a[2]!).slice(s - 1, Math.max(e, 0)).join(' ') : null;
    }
    case 'words':
      return String(words(a[0]!).length);
    case 'firstword':
      return words(a[0]!)[0] ?? '';
    case 'lastword':
      return words(a[0]!).pop() ?? '';
    case 'dir':
      return words(a[0]!).map(dirOf).join(' ');
    case 'notdir':
      return words(a[0]!).map(notdirOf).join(' ');
    case 'suffix':
      return words(a[0]!)
        .map((w) => {
          const base = notdirOf(w);
          const i = base.lastIndexOf('.');
          return i >= 0 ? base.slice(i) : '';
        })
        .filter(Boolean)
        .join(' ');
    case 'basename':
      return words(a[0]!)
        .map((w) => {
          const i = w.lastIndexOf('.');
          return i > w.lastIndexOf('/') ? w.slice(0, i) : w;
        })
        .join(' ');
    case 'addsuffix':
      return words(a[1]!).map((w) => w + a[0]!).join(' ');
    case 'addprefix':
      return words(a[1]!).map((w) => a[0]! + w).join(' ');
    case 'join': {
      const l = words(a[0]!);
      const r = words(a[1]!);
      return Array.from({ length: Math.max(l.length, r.length) }, (_v, i) => (l[i] ?? '') + (r[i] ?? '')).join(' ');
    }
    default:
      return null;
  }
}

/** Appends the parts of `b` to the branch `a`, which the CALLER OWNS (a branch that came out of a memo or a binding is never changed); two strings that
 *  meet are one string. Copying the branch at every reference was quadratic in the number of references, and a text of a hundred thousand of
 *  them took a minute (MK-09: the work counter was never reached, because the time was spent in the copy). */
const appendParts = (a: Br, b: Br): void => {
  for (const p of b) {
    const last = a[a.length - 1];
    if (typeof p === 'string' && typeof last === 'string') a[a.length - 1] = last + p;
    else a.push(p);
  }
};
const isKnown = (b: Br): boolean => b.every((p) => p !== null);
const brLength = (b: Br): number => b.reduce((n: number, p) => n + (p === null ? 1 : p.length), 0);
const unknown = (): Br[] => [[null]];

/**
 * A BRANCH, RENDERED: the text make hands the shell, and what is known of it before the first piece nobody can know. Quotes are followed
 * across the whole text, so a piece that is unknown INSIDE double quotes is one word however it comes out (`echo "building $(VERSION)"`
 * is not an opacity), and one outside them - or inside single quotes, where it can close the quote - is.
 */
function render(b: Br): { text: string | null; prefix: string } {
  let out = '';
  let prefix = '';
  let opaque = false;
  let inDouble = false;
  let inSingle = false;
  for (const p of b) {
    if (p === null) {
      if (inDouble) {
        out += '$MAKEVAR';
        if (!opaque) prefix = out;
      } else opaque = true;
      continue;
    }
    for (let i = 0; i < p.length; i++) {
      const ch = p[i]!;
      if (ch === '\\' && p[i + 1] !== undefined) {
        out += ch + p[i + 1]!;
        i++;
        if (!opaque) prefix = out;
        continue;
      }
      if (ch === "'" && !inDouble) inSingle = !inSingle;
      else if (ch === '"' && !inSingle) inDouble = !inDouble;
      out += ch;
      if (!opaque) prefix = out;
    }
  }
  return { text: opaque ? null : out, prefix };
}

class Expander {
  readonly ran = new Set<string>();
  capped = false;
  evals = false;
  fileWrites = false;
  blind = false;
  private steps = 0;
  private readonly parsed = new Map<string, MNode[]>();
  private readonly memo = new Map<string, Br[]>();
  private readonly active = new Set<string>();

  private readonly store: MakeStore;
  private readonly scope: MakeScope;

  constructor(store: MakeStore, scope: MakeScope) {
    this.store = store;
    this.scope = scope;
  }

  /** every node visited is paid for, here and in the decision's own counter: a few units for a step, one for a character */
  private tick(): void {
    if (++this.steps > MAX_STEPS) throw new Capped();
    chargeWork(8);
  }
  private check(b: Br): Br {
    if (brLength(b) > MAX_TEXT) throw new Capped();
    return b;
  }

  text(src: string, frame: Frame | null): Br[] {
    if (!src.includes('$')) {
      chargeWork(src.length);
      return [this.check([src])];
    }
    let nodes = this.parsed.get(src);
    if (nodes === undefined) {
      chargeWork(src.length);
      nodes = parseMakeText(src);
      this.parsed.set(src, nodes);
    }
    return this.nodes(nodes, frame);
  }

  private nodes(ns: readonly MNode[], frame: Frame | null): Br[] {
    // the branches built here are this call's own, and sizes[i] is the length of acc[i] - kept, not recomputed
    let acc: Br[] = [[]];
    let sizes: number[] = [0];
    for (const n of ns) {
      if (typeof n === 'string') {
        chargeWork(n.length);
        for (let i = 0; i < acc.length; i++) {
          appendParts(acc[i]!, [n]);
          if ((sizes[i]! += n.length) > MAX_TEXT) throw new Capped();
        }
        continue;
      }
      this.tick();
      const r = this.node(n, frame);
      if (r.length === 0) continue;
      const rs = r.map(brLength);
      if (r.length === 1) {
        for (let i = 0; i < acc.length; i++) {
          appendParts(acc[i]!, r[0]!);
          if ((sizes[i]! += rs[0]!) > MAX_TEXT) throw new Capped();
        }
        continue;
      }
      const next: Br[] = [];
      const nextSizes: number[] = [];
      for (let i = 0; i < acc.length; i++)
        for (let j = 0; j < r.length; j++) {
          if (next.length >= MAX_BRANCHES) {
            this.capped = true;
            continue;
          }
          if (sizes[i]! + rs[j]! > MAX_TEXT) throw new Capped();
          const copy = [...acc[i]!];
          appendParts(copy, r[j]!);
          next.push(copy);
          nextSizes.push(sizes[i]! + rs[j]!);
        }
      acc = next;
      sizes = nextSizes;
    }
    return acc;
  }

  private dedupe(bs: Br[]): Br[] {
    const seen = new Set<string>();
    const out: Br[] = [];
    for (const b of bs) {
      const key = JSON.stringify(b);
      if (seen.has(key)) continue;
      seen.add(key);
      if (out.length >= MAX_BRANCHES) {
        this.capped = true;
        break;
      }
      out.push(b);
    }
    return out;
  }

  /** how deep one expansion may recurse (a reference inside the value of a reference inside...): the JavaScript stack is not the bound */
  private depth = 0;

  private node(n: Exclude<MNode, string>, frame: Frame | null): Br[] {
    if (++this.depth > MAX_DEPTH) {
      this.depth--;
      throw new Capped();
    }
    try {
      return this.nodeInner(n, frame);
    } finally {
      this.depth--;
    }
  }

  private nodeInner(n: Exclude<MNode, string>, frame: Frame | null): Br[] {
    if (n.k === 'unk') return unknown();
    if (n.k === 'ref') {
      const names = this.nodes(n.name, frame);
      const out: Br[] = [];
      for (const nb of names) {
        if (!isKnown(nb)) {
          out.push([null]);
          continue;
        }
        out.push(...this.lookup(nb.join(''), frame));
      }
      return this.dedupe(out);
    }
    return this.call(n.fn, n.args, frame);
  }

  private lookup(raw: string, frame: Frame | null): Br[] {
    const name = raw.trim();
    // `$(VAR:a=b)` is `$(patsubst %a,%b,$(VAR))`
    const sub = /^([^:]+):([^=]*)=([\s\S]*)$/.exec(name);
    if (sub) {
      const from = sub[2]!.includes('%') ? sub[2]! : `%${sub[2]!}`;
      const to = sub[2]!.includes('%') ? sub[3]! : `%${sub[3]!}`;
      return this.lookup(sub[1]!, frame).map((b) => (isKnown(b) ? [words(b.join('')).map((w) => patsubstOne(from, to, w)).join(' ')] : [null]));
    }
    const bound = frame?.get(name);
    if (bound !== undefined) return bound;
    const am = /^([@<^+?*%|])([DF])?$/.exec(name);
    if (am) {
      const v = this.scope.auto?.[am[1]!];
      if (v === undefined) return unknown();
      return [[am[2] === 'D' ? words(v).map((w) => dirOf(w).replace(/\/$/, '') || '.').join(' ') : am[2] === 'F' ? words(v).map(notdirOf).join(' ') : v]];
    }
    const overlay = this.scope.overlay?.get(name);
    if (overlay !== undefined) return this.variable(`ov:${name}`, [overlay], frame);
    const cands = this.store.candidates(name);
    if (cands.length > 0) return this.variable(name, cands, frame);
    if (AMBIENT_WORD_VARIABLES.has(name)) return [[`$${name}`]];
    if (IMPLICIT_RULE_INPUTS.has(name)) return [['']];
    return unknown(); // a variable this reader never saw defined is not provably empty
  }

  private variable(name: string, cands: string[], frame: Frame | null): Br[] {
    if (this.active.has(name)) return unknown(); // a variable that refers to itself is an error to make
    this.active.add(name);
    try {
      const out: Br[] = [];
      for (const c of cands) {
        if (frame === null) {
          let m = this.memo.get(c);
          if (m === undefined) {
            m = this.text(c, null);
            this.memo.set(c, m);
          }
          out.push(...m);
        } else out.push(...this.text(c, frame));
      }
      return this.dedupe(out);
    } finally {
      this.active.delete(name);
    }
  }

  /** the texts a name could hold in this expansion: a target-specific value first, else the global ones */
  private valuesOf(name: string): string[] {
    const ov = this.scope.overlay?.get(name);
    return ov !== undefined ? [ov] : this.store.candidates(name);
  }

  private known(bs: Br[]): string | null {
    return bs.length === 1 && isKnown(bs[0]!) ? bs[0]!.join('') : null;
  }

  private call(fn: string, args: MNode[][], frame: Frame | null): Br[] {
    const spec = FUNCTIONS[fn]!;
    if (args.length < spec[0]) {
      for (const a of args) this.nodes(a, frame);
      return unknown();
    }
    switch (fn) {
      case 'shell':
      case 'guile': {
        for (const b of this.nodes(args[0]!, frame)) {
          const known = b.findIndex((p) => p === null);
          const cmd = (known < 0 ? b.join('') : b.slice(0, known).join('')).trim();
          if (cmd) this.ran.add(cmd);
          // a command no one can read is a command no one can judge
          if (known >= 0) this.blind = true;
        }
        return unknown(); // the command RAN; what it printed is not knowable
      }
      case 'eval':
        this.evals = true;
        this.nodes(args[0]!, frame);
        return [['']];
      case 'file': {
        const target = this.nodes(args[0]!, frame);
        const lead = target.map((b) => (isKnown(b) ? b.join('').trimStart() : '>'));
        if (args[1]) this.nodes(args[1], frame);
        if (lead.some((s) => s.startsWith('>'))) this.fileWrites = true;
        return args.length > 1 ? [['']] : unknown();
      }
      case 'info':
      case 'warning':
      case 'error':
        this.nodes(args[0]!, frame);
        return [['']];
      case 'if':
        return this.fnIf(args, frame);
      case 'or':
      case 'and':
        return this.fnLogic(fn, args, frame);
      case 'foreach':
        return this.fnForeach(args, frame);
      case 'call':
        return this.fnCall(args, frame);
      case 'value': {
        const name = this.known(this.nodes(args[0]!, frame))?.trim();
        const cands = name === undefined ? [] : this.valuesOf(name);
        // (the VALUE of a simple variable is the text it was expanded to; a recursive one's is the text as written)
        return cands.length ? cands.map((c) => [this.store.isSimple(name!) ? decodeText(c) : c]) : unknown();
      }
      case 'origin':
      case 'flavor': {
        const name = this.known(this.nodes(args[0]!, frame))?.trim();
        if (name === undefined || (!this.store.has(name) && !this.scope.overlay?.has(name))) return unknown();
        if (fn === 'flavor') return [[this.store.isSimple(name) && !this.scope.overlay?.has(name) ? 'simple' : 'recursive']];
        const o = this.scope.overlay?.has(name) ? 'file' : this.store.originOf(name)!;
        return [[o === 'command-line' ? 'command line' : o === 'environment-override' ? 'environment override' : o]];
      }
      case 'wildcard': {
        const out: Br[] = [];
        for (const b of this.nodes(args[0]!, frame)) {
          if (!isKnown(b) || this.store.wildcard === null) {
            out.push([null]);
            continue;
          }
          const found: string[] = [];
          let ok = true;
          for (const p of words(b.join(''))) {
            const names = this.store.wildcard(p);
            if (names === null) ok = false;
            else found.push(...names);
          }
          out.push(ok ? [found.join(' ')] : [null]);
        }
        return this.dedupe(out);
      }
      default:
        return this.pure(fn, args, frame);
    }
  }

  private pure(fn: string, args: MNode[][], frame: Frame | null): Br[] {
    let combos: string[][] | null = [[]];
    for (const a of args) {
      const alts = this.nodes(a, frame);
      const next: string[][] = [];
      for (const c of combos ?? []) {
        for (const b of alts) {
          if (!isKnown(b)) {
            combos = null;
            break;
          }
          if (next.length >= MAX_BRANCHES) {
            this.capped = true;
            break;
          }
          next.push([...c, b.join('')]);
        }
        if (combos === null) break;
      }
      if (combos === null) break;
      combos = next;
    }
    if (combos === null) return unknown();
    const out: Br[] = [];
    for (const c of combos) {
      const r = applyPure(fn, c);
      out.push(r === null ? [null] : [r]);
    }
    return this.dedupe(out);
  }

  private fnIf(args: MNode[][], frame: Frame | null): Br[] {
    const out: Br[] = [];
    const then = (): Br[] => this.nodes(args[1]!, frame);
    const otherwise = (): Br[] => (args[2] ? this.nodes(args[2], frame) : [['']]);
    for (const c of this.nodes(args[0]!, frame)) {
      if (!isKnown(c)) out.push(...then(), ...otherwise());
      else if (c.join('').trim() !== '') out.push(...then());
      else out.push(...otherwise());
    }
    return this.dedupe(out);
  }

  private fnLogic(fn: 'or' | 'and', args: MNode[][], frame: Frame | null): Br[] {
    const out: Br[] = [];
    for (let i = 0; i < args.length; i++) {
      const bs = this.nodes(args[i]!, frame);
      const k = this.known(bs);
      if (k !== null) {
        const empty = k.trim() === '';
        if (fn === 'or' && !empty) return [[k]];
        if (fn === 'and' && empty) return [['']];
        if (i === args.length - 1) return [[k]];
        continue;
      }
      // an argument that is several things, or unknown, leaves every way the rest can go
      out.push(...bs);
      for (let j = i + 1; j < args.length; j++) out.push(...this.nodes(args[j]!, frame));
      return this.dedupe(out.length ? out : [[null]]);
    }
    return [['']];
  }

  private fnForeach(args: MNode[][], frame: Frame | null): Br[] {
    const variable = this.known(this.nodes(args[0]!, frame))?.trim();
    const list = this.known(this.nodes(args[1]!, frame));
    if (variable === undefined || list === null) {
      this.nodes(args[2]!, frame); // the commands inside are still found
      return unknown();
    }
    const ws = words(list);
    if (ws.length > MAX_FOREACH) {
      this.capped = true;
      return unknown();
    }
    const parts: string[] = [];
    let exact = true;
    for (const w of ws) {
      const fr = new Map(frame ?? []);
      fr.set(variable, [[w]]);
      const r = this.nodes(args[2]!, fr);
      const k = this.known(r);
      if (k === null) exact = false;
      else parts.push(k);
    }
    return exact ? [[parts.join(' ')]] : unknown();
  }

  private fnCall(args: MNode[][], frame: Frame | null): Br[] {
    const name = this.known(this.nodes(args[0]!, frame))?.trim();
    const params = args.slice(1).map((a) => this.nodes(a, frame));
    if (name === undefined || name === '') return unknown();
    const cands = this.valuesOf(name);
    if (cands.length > 0) {
      // the parameters are variables for as long as the call lasts: `$(0)` is the name, `$(1)` the first argument, the rest empty
      const fr = new Map<string, Br[]>();
      for (let i = 0; i <= 9; i++) fr.set(String(i), i === 0 ? [[name]] : (params[i - 1] ?? [['']]));
      return this.variable(`call:${name}`, cands, fr);
    }
    if (FUNCTIONS[name] !== undefined) {
      const strs = params.map((p) => this.known(p));
      if (strs.every((s): s is string => s !== null)) {
        const r = applyPure(name, strs);
        if (r !== null) return [[r]];
      }
    }
    return unknown();
  }
}

/** The text a stored value stands for before it is expanded (a literal `$` is written `$$`). */
function decodeText(c: string): string {
  return c.replace(/\$\$/g, '$');
}
