// THE ONE LEXER FOR TEXT THE SHELL EXPANDS: where a quote, a `${ }`, a `$( )`, a backtick span or a word ends, and which spans of a
// text are COMMANDS the shell runs. Moved out of evaluate.ts so that the splitter, the redirection scanner and the readers of
// "which words does a builtin evaluate" (evaluated-words.ts) ask one reader and cannot drift (closure audit 2026-10-02, SH-1/SH-4).
import { chargeWork } from './work-bound.ts';

/* ------------------------------------------------------------------------------------------------------------- *
 * ONE LEXER FOR THE BODY OF `$( … )`.
 *
 * Three scanners counted parentheses for three callers, each with its own idea of what hides one: the splitter knew
 * quotes and `case`, the heredoc extractor knew neither, and none knew that a `)` can sit inside a comment, a `${…}`
 * expansion, an ANSI-C string, a nested substitution's own quoting, or a `case` pattern after a subject that contains a
 * space (exit review 10, self-attack: five findings, one cause). A substitution that ends early leaves the rest of its
 * body as TEXT, which is how `git push origin main` inside one became invisible. This reads the body the way the
 * shell does and returns where it really ends.
 * ------------------------------------------------------------------------------------------------------------- */
export function skipSingleQuoted(t: string, i: number): number {
  const e = t.indexOf("'", i);
  return e < 0 ? -1 : e + 1;
}
export function skipAnsiC(t: string, i: number): number {
  for (; i < t.length; i++) {
    if (t[i] === '\\') i++;
    else if (t[i] === "'") return i + 1;
  }
  return -1;
}
export function skipBacktickSpan(t: string, i: number): number {
  for (; i < t.length; i++) {
    if (t[i] === '\\') i++;
    else if (t[i] === '`') return i + 1;
  }
  return -1;
}
export function skipDoubleQuoted(t: string, i: number): number {
  while (i < t.length) {
    const c = t[i]!;
    if (c === '\\') i += 2;
    else if (c === '"') return i + 1;
    else if (c === '`') {
      i = skipBacktickSpan(t, i + 1);
      if (i < 0) return -1;
    } else if (c === '$' && t[i + 1] === '(') {
      const e = scanSubstitutionBody(t, i + 2);
      if (e < 0) return -1;
      i = e + 1;
    } else if (c === '$' && t[i + 1] === '{') {
      i = skipParameterExpansion(t, i + 2);
      if (i < 0) return -1;
    } else i++;
  }
  return -1;
}
/** after `${`: to just past the matching `}` */
export function skipParameterExpansion(t: string, i: number): number {
  while (i < t.length) {
    const c = t[i]!;
    if (c === '\\') i += 2;
    else if (c === '}') return i + 1;
    else if (c === "'") {
      i = skipSingleQuoted(t, i + 1);
      if (i < 0) return -1;
    } else if (c === '"') {
      i = skipDoubleQuoted(t, i + 1);
      if (i < 0) return -1;
    } else if (c === '`') {
      i = skipBacktickSpan(t, i + 1);
      if (i < 0) return -1;
    } else if (c === '$' && t[i + 1] === '(') {
      const e = scanSubstitutionBody(t, i + 2);
      if (e < 0) return -1;
      i = e + 1;
    } else if (c === '$' && t[i + 1] === '{') {
      i = skipParameterExpansion(t, i + 2);
      if (i < 0) return -1;
    } else i++;
  }
  return -1;
}
/** One shell WORD starting at `i`: quotes and expansions inside it are part of it. Returns its end (exclusive). */
export function skipWordAt(t: string, i: number): number {
  while (i < t.length) {
    const c = t[i]!;
    if (/[\s;&|()<>]/.test(c)) return i;
    if (c === '\\') i += 2;
    else if (c === "'") {
      i = skipSingleQuoted(t, i + 1);
      if (i < 0) return t.length;
    } else if (c === '"') {
      i = skipDoubleQuoted(t, i + 1);
      if (i < 0) return t.length;
    } else if (c === '`') {
      i = skipBacktickSpan(t, i + 1);
      if (i < 0) return t.length;
    } else if (c === '$' && t[i + 1] === "'") {
      i = skipAnsiC(t, i + 2);
      if (i < 0) return t.length;
    } else if (c === '$' && t[i + 1] === '(') {
      const e = scanSubstitutionBody(t, i + 2);
      if (e < 0) return t.length;
      i = e + 1;
    } else if (c === '$' && t[i + 1] === '{') {
      i = skipParameterExpansion(t, i + 2);
      if (i < 0) return t.length;
    } else i++;
  }
  return i;
}
/** `i` is just after `$(`. Returns the index of the `)` that ends the substitution, or -1 when it never does. */
export function scanSubstitutionBody(t: string, i: number): number {
  let depth = 1;
  /** open `case`s: the paren depth each opened at, and whether a PATTERN is what the scanner is reading */
  const cases: Array<{ depth: number; pattern: boolean }> = [];
  let cmdStart = true;
  while (i < t.length) {
    const c = t[i]!;
    if (c === '\\') {
      i += 2;
      cmdStart = false;
      continue;
    }
    if (c === "'" || c === '"' || c === '`' || c === '$') {
      // any word that begins with a quote or an expansion is read whole, so nothing inside it is structure
      const e = skipWordAt(t, i);
      if (e === i) {
        i++;
        continue;
      }
      i = e;
      cmdStart = false;
      continue;
    }
    if (c === '#' && (i === 0 || /[\s;&|(]/.test(t[i - 1]!))) {
      const nl = t.indexOf('\n', i);
      i = nl < 0 ? t.length : nl;
      continue;
    }
    const top = cases[cases.length - 1];
    if (c === '(') {
      // a pattern may be written `(a|b)`: that paren opens nothing
      if (top && top.depth === depth && top.pattern) {
        i++;
        continue;
      }
      depth++;
      i++;
      cmdStart = true;
      continue;
    }
    if (c === ')') {
      if (top && top.depth === depth && top.pattern) {
        top.pattern = false;
        i++;
        cmdStart = true;
        continue;
      }
      depth--;
      if (depth === 0) return i;
      i++;
      cmdStart = false;
      continue;
    }
    if (c === ';') {
      if ((t[i + 1] === ';' || t[i + 1] === '&') && top && top.depth === depth) {
        top.pattern = true;
        i += t[i + 1] === ';' && t[i + 2] === '&' ? 3 : 2;
      } else i++;
      cmdStart = true;
      continue;
    }
    if (c === '&' || c === '|' || c === '\n') {
      i++;
      cmdStart = true;
      continue;
    }
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    const e = skipWordAt(t, i);
    const w = t.slice(i, e);
    const inPattern = top !== undefined && top.depth === depth && top.pattern;
    if (cmdStart && !inPattern && w === 'case') {
      // `case SUBJECT in` - the subject is any word, spaces inside its quotes and expansions included
      let j = e;
      while (j < t.length && /\s/.test(t[j]!)) j++;
      const subjectEnd = skipWordAt(t, j);
      let k = subjectEnd;
      while (k < t.length && /\s/.test(t[k]!)) k++;
      const kwEnd = skipWordAt(t, k);
      if (subjectEnd > j && t.slice(k, kwEnd) === 'in') {
        cases.push({ depth, pattern: true });
        i = kwEnd;
        cmdStart = false;
        continue;
      }
    }
    if (cmdStart && !inPattern && w === 'esac' && top && top.depth === depth) {
      cases.pop();
      i = e;
      cmdStart = false;
      continue;
    }
    i = Math.max(e, i + 1);
    cmdStart = !inPattern && /^(do|then|else|elif|if|while|until|time|!|\{|\})$/.test(w);
  }
  return -1;
}

/** The commands SUBSTITUTED into a text: the inner command of every `$( )` and backtick span outside single
 *  quotes. Used for an UNQUOTED heredoc body, where the shell expands substitutions but the prose around them is
 *  data — `git push origin main` written in a release note is not a push. */
export function substitutionsIn(text: string, escapes = true): string[] {
  const out: string[] = [];
  // THERE IS NO QUOTING INSIDE A HEREDOC BODY. `'` and `"` are ordinary characters there, so a scanner that
  // tracked them skipped the substitutions that the shell does expand (exit review 4). Only the backslash escape
  // survives, and only before `$`, `` ` `` and `\`.
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    // (text the shell EVALUATES - a subscript, an arithmetic word - is read with no escapes either: a backslash there is not what
    // keeps a substitution from running, and reading it as if it were is how `a[\$(cmd)]` would escape the scan)
    if (ch === '\\' && escapes) {
      i++;
      continue;
    }
    if (ch === '$' && text[i + 1] === '(' && text[i + 2] === '(') {
      // `$((…))` closing with ADJACENT parens is arithmetic and runs nothing; anything else is `$( (…) …)`
      let d = 0;
      let j = i + 1;
      let prevClose = false;
      for (; j < text.length; j++) {
        if (text[j] === '(') d++;
        else if (text[j] === ')' && --d === 0) {
          prevClose = text[j - 1] === ')';
          break;
        }
      }
      if (prevClose) {
        for (const nested of substitutionsIn(text.slice(i + 3, j - 1), escapes)) out.push(nested);
        i = j;
        continue;
      }
      out.push(text.slice(i + 2, j));
      i = j;
      continue;
    }
    if (ch === '$' && text[i + 1] === '(') {
      const close = scanSubstitutionBody(text, i + 2);
      const end = close < 0 ? text.length : close;
      out.push(text.slice(i + 2, end));
      i = end;
      continue;
    }
    if (ch === '`') {
      // POSIX nests backticks by escaping the inner pair, so the closing one is the first UNESCAPED backtick
      const after = skipBacktickSpan(text, i + 1);
      if (after > i) {
        out.push(text.slice(i + 1, after - 1).replace(/\\([`$\\])/g, '$1'));
        i = after - 1;
      }
    }
  }
  return out;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * TEXT THE SHELL EVALUATES AS AN EXPRESSION - one reader of where its commands are (closure audit 2026-10-02, SH-1 / SH-4).
 *
 * A command runs wherever the shell EXPANDS text, and text is expanded in more places than a command line has words:
 *   - an arithmetic expansion, `$(( … ))` and the OLD form `$[ … ]`, and the arithmetic command `(( … ))` and `for (( … ))`;
 *   - an ARRAY SUBSCRIPT - `a[EXPR]=v`, `${a[EXPR]}`, `declare 'a[EXPR]=v'`, `read 'a[EXPR]'`, `unset 'a[EXPR]'`,
 *     `[[ 'a[EXPR]' -eq 1 ]]`, `printf -v 'a[EXPR]'` - which is an arithmetic expression, so a `$( )` or a backtick in it runs, and a
 *     QUOTE does not keep it from running (the quote protects the word from splitting and globbing; the builtin evaluates what it
 *     receives);
 *   - the value of a variable that has the integer attribute, a prompt string, a trap.
 * Each of these was handled where its author had met it (`$((` in the splitter, a heredoc body in `substitutionsIn`) and `$[ … ]`
 * and the quoted subscript were swallowed as inert text: `echo $[$(git push origin main)]` and `declare 'a[$(git push origin
 * main)]=1'` ran the push at ALLOW. The question "which spans of this text are commands" is asked here, once.
 * ------------------------------------------------------------------------------------------------------------- */

/** The commands a text runs when the shell EVALUATES it as an expression: every `$( )` and backtick span in it, wherever it stands -
 *  quoted, escaped, in a subscript, in the middle of an arithmetic word. This is the reader for text that has already had its
 *  quoting removed (a builtin's operand) or that is arithmetic by position, where no quote protects anything. */
export function expressionCommands(text: string): string[] {
  return /[$`]/.test(text) ? substitutionsIn(text, false) : [];
}

/** An arithmetic span: its body, and the index just past its closing `]` / `))`. */
export interface ArithmeticSpan {
  body: string;
  end: number;
}

/** The ARITHMETIC EXPANSION or COMMAND that begins at `t[i]`, or null when what stands there is not one:
 *    `$[ … ]`   the old form, still accepted by bash and zsh (dash reads the `$[` as text and the rest as ordinary words)
 *    `$(( … ))` closing with ADJACENT parens - anything else is `$( (…) …)`, a command substitution holding subshells
 *    `(( … ))`  the arithmetic command, on the same rule
 *  The extent is found the way the shell finds it: brackets and parentheses nest, and a quote, a `${ }`, a `$( )` or a backtick inside
 *  is read whole, so a `]` or a `)` in one of them closes nothing. A span that never closes is not one. */
export function arithmeticSpanAt(t: string, i: number): ArithmeticSpan | null {
  const span = arithmeticSpanScan(t, i);
  // (paid for by what was read: an opener inside an opener reads the rest of the line again)
  if (span !== undefined) chargeWork((span === null ? t.length : span.end) - i);
  return span ?? null;
}

/** undefined when nothing that opens an arithmetic span stands at `i`; null when one does and never closes properly */
function arithmeticSpanScan(t: string, i: number): ArithmeticSpan | null | undefined {
  let from: number;
  let old = false;
  if (t[i] === '$' && t[i + 1] === '[') {
    old = true;
    from = i + 2;
  } else if (t[i] === '$' && t[i + 1] === '(' && t[i + 2] === '(') from = i + 3;
  else if (t[i] === '(' && t[i + 1] === '(') from = i + 2;
  else return undefined;
  let depth = old ? 1 : 2;
  let j = from;
  while (j < t.length) {
    const c = t[j]!;
    if (c === '\\') {
      j += 2;
      continue;
    }
    if (c === "'" || c === '"' || c === '`' || (c === '$' && (t[j + 1] === "'" || t[j + 1] === '(' || t[j + 1] === '{'))) {
      let e: number;
      if (c === "'") e = skipSingleQuoted(t, j + 1);
      else if (c === '"') e = skipDoubleQuoted(t, j + 1);
      else if (c === '`') e = skipBacktickSpan(t, j + 1);
      else if (t[j + 1] === "'") e = skipAnsiC(t, j + 2);
      else if (t[j + 1] === '{') e = skipParameterExpansion(t, j + 2);
      else {
        const close = scanSubstitutionBody(t, j + 2);
        e = close < 0 ? -1 : close + 1;
      }
      if (e < 0) return null;
      j = e;
      continue;
    }
    if (old) {
      if (c === '[') depth++;
      else if (c === ']' && --depth === 0) return { body: t.slice(from, j), end: j + 1 };
    } else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) {
      // the two closing parens must be ADJACENT, and belong to the opening pair (`$((cmd) )` is a substitution of a subshell)
      return t[j - 1] === ')' && j - 1 >= from ? { body: t.slice(from, j - 1), end: j + 1 } : null;
    }
    j++;
  }
  return null;
}

/** The commands a PARAMETER EXPANSION `${…}` runs by evaluating text, for the one that begins at `t[i]` (`${`): the SUBSCRIPT of its name
 *  - `${a[EXPR]}`, `${!a[EXPR]}`, `${#a[EXPR]}`, `${(k)a[EXPR]}` - is an expression whatever quote it wears, and zsh's `(e)` and `(%)`
 *  flags expand the value again as shell text and as a prompt. The substitutions that stand OUTSIDE single quotes in an expansion's
 *  other parts (`${x:-$(cmd)}`) are found by the ordinary scan and are not repeated here. */
export function parameterExpansionCommands(t: string, i: number): string[] {
  const end = skipParameterExpansion(t, i + 2);
  // (an expansion is read to its end for every `${` that opens one: nested ones are paid for, and a line built of them ends at the bound)
  chargeWork((end < 0 ? t.length : end) - i);
  if (end < 0) return [];
  const body = t.slice(i + 2, end - 1);
  if (!/[$`]/.test(body)) return [];
  const flags = /^\(([A-Za-z0-9@%:]*)\)/.exec(body);
  if (flags !== null && /[e%]/.test(flags[1]!)) return expressionCommands(body);
  // the OFFSET and the LENGTH of `${x:OFFSET:LENGTH}` are arithmetic too (the operators `:-` `:=` `:+` `:?` are not)
  const substring = (from: number): string[] => (body[from] === ':' && !/[-=+?]/.test(body[from + 1] ?? '') ? expressionCommands(body.slice(from + 1)) : []);
  const plain = /^(?:\([^)]*\))?[!#]?[A-Za-z_][A-Za-z0-9_]*/.exec(body);
  if (plain === null) return [];
  const name = /^(?:\([^)]*\))?[!#]?[A-Za-z_][A-Za-z0-9_]*\[/.exec(body);
  if (name === null) return substring(plain[0].length);
  let depth = 1;
  let j = name[0].length;
  for (; j < body.length; j++) {
    if (body[j] === '[') depth++;
    else if (body[j] === ']' && --depth === 0) break;
  }
  return [...expressionCommands(body.slice(name[0].length, j)), ...substring(j + 1)];
}
