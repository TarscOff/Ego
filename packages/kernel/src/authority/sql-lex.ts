// WHERE A STATEMENT'S TEXT BELONGS TO THE SERVER AND WHERE IT BELONGS TO THE CLIENT.
//
// A database client reads its input twice: it lexes the text for itself first (to find the backslash commands that it runs
// and the server never sees) and sends what is left to the server. The scanner here is the kernel's copy of the FIRST
// reading, and its one job is that a command the client will run is a command the scanner reports. A scanner that
// disagrees with the client about where a string ends reads a real `\o |program` as the inside of a literal - and the
// statement is then judged as the plain text it is not.
//
// So the lexical rules are the CLIENT's, not the server's, and they are written once per dialect. PostgreSQL's psql lexes by
// the rules below (checked against the real psql 15, 16 and 17, which agree on all of them):
//   - an IDENTIFIER is a start character followed by any number of continue characters, and `$` is a CONTINUE character, so
//     `a$$$` is one name and nothing inside it opens a quote;
//   - a DOLLAR QUOTE starts where a token starts: after a space, a bracket, a string, a number - never inside a name;
//   - a NUMBER that runs straight into a letter is one token with that letter and the name that follows it, `$` included
//     (`1a$$` and `1e5$$` open nothing; `15$$` does);
//   - a lone `e` in front of a quote makes an ESCAPE string, where a backslash escapes the next character;
//   - a backslash outside a string starts a command, except `\;` and `\:`, which are a plain `;` and `:` and leave the line
//     going on as SQL;
//   - a backquote is no quote at all; and `:name` interpolates a variable's text into the script, which is then lexed again.
// Where two clients of one engine read a form differently, the form is REFUSED rather than guessed.

export type SqlDialect = 'pg' | 'mysql' | 'plain';

export interface SqlScan {
  /** the text with every string literal blanked and every dollar-quoted body kept as code */
  code: string;
  /** the client's own commands (psql `\name args`, mysql `\c`), which the server never sees */
  metas: Array<{ name: string; args: string }>;
  /** the psql variables the text interpolates UNQUOTED (`:name`) that the scan could not read the value of. psql replaces the
   *  reference with the variable's text and lexes THAT, so a value nobody saw is a script nobody read. Quoted references
   *  (`:'name'`, `:"name"`) are literals and are not here. */
  variables: string[];
}

/** The psql variables the command line has set (`-v NAME=VALUE`), by name: the text, or null when it is built at run time. A
 *  reference to one of them is replaced by its text and lexed, exactly as psql does; `\set` in the text adds to them. */
export type SqlVariables = ReadonlyMap<string, string | null>;

/** THE IDENTIFIER CHARACTERS, ONCE: PostgreSQL's (and psql's) own classes. Every non-ASCII character is a letter to the lexer,
 *  and a `$` continues a name but never starts one. The source strings are exported so the regexes elsewhere that ask the same
 *  question are built from this one answer. */
export const SQL_IDENT_START_SRC = 'A-Za-z_\\u0080-\\uffff';
export const SQL_IDENT_CONT_SRC = 'A-Za-z0-9_$\\u0080-\\uffff';
const IDENT_START = new RegExp(`[${SQL_IDENT_START_SRC}]`);
const IDENT_CONT = new RegExp(`[${SQL_IDENT_CONT_SRC}]`);
const isIdentStart = (c: string | undefined): c is string => c !== undefined && IDENT_START.test(c);
const isIdentCont = (c: string | undefined): c is string => c !== undefined && IDENT_CONT.test(c);
const isDigit = (c: string | undefined): boolean => c !== undefined && c >= '0' && c <= '9';

/** whether `before` (the text in front of a quote) ends in a LONE `e`/`E`: the one token that makes the quote an escape string.
 *  An `e` that ends a longer name (`a$e'`, `ée'`) or follows a digit (`1e'`) is not one. */
export const endsWithEscapePrefix = (before: string): boolean => new RegExp(`(^|[^${SQL_IDENT_CONT_SRC}])[eE]$`).test(before);

/** `$tag$` or `$$`: the tag is a name without a `$` in it */
const DOLLAR_QUOTE = new RegExp(`\\$(?:[${SQL_IDENT_START_SRC}][A-Za-z0-9_\\u0080-\\uffff]*)?\\$`, 'y');
const PARAMETER = /\$\d+/y;
const DECIMAL = /\d+(?:\.\d*)?|\.\d+/y;
const VARIABLE_NAME = new RegExp(`[A-Za-z0-9_\\u0080-\\uffff]+`, 'y');

/** Splits SQL text into what the SERVER reads (code) and what the CLIENT reads (backslash commands), with the strings
 *  taken out so a word inside a literal is not mistaken for one outside it.
 *
 *  Three things are refused rather than guessed, because each makes this scanner and the engine disagree about where a
 *  string ends - and a scanner that thinks text is inside a literal hides it: a comment of any kind (the engines differ
 *  on what opens one and whether it nests), and a session setting that changes how a backslash or a double quote is
 *  read (`standard_conforming_strings`, `NO_BACKSLASH_ESCAPES`, `ANSI_QUOTES`). */
export function sqlScan(text: string, dialect: SqlDialect, variables: SqlVariables = new Map()): SqlScan | { refused: string } {
  if (/--|\/\*/.test(text)) return { refused: 'a comment, which this reader cannot place the end of' };
  if (dialect === 'mysql' && text.includes('#')) return { refused: 'a # comment' };
  if (dialect === 'pg' && /standard_conforming_strings|backslash_quote|escape_string_warning/i.test(text))
    return { refused: 'a setting that changes how a backslash is read' };
  if (dialect === 'mysql' && /sql_mode|no_backslash_escapes|ansi_quotes/i.test(text))
    return { refused: 'a setting that changes how a quote is read' };
  return dialect === 'pg' ? scanPostgres(text, variables) : scanMysql(text, dialect);
}

/** What `\set` gives a variable, when the arguments say so in a form that cannot hide anything: no value (empty), one plain word, or
 *  one single-quoted run without a quote or a backslash in it. Anything else (escapes, several words, a backquote) is null - a
 *  value this reader will not claim to know. Null when the name is not one either. */
function setCommand(args: string): { name: string; value: string | null } | null {
  const m = /^(\S+)(?:\s+(.*))?$/s.exec(args);
  if (!m || !/^[A-Za-z0-9_\u0080-\uffff]+$/.test(m[1]!)) return null;
  const rest = (m[2] ?? '').trim();
  if (rest === '') return { name: m[1]!, value: '' };
  if (/^[A-Za-z0-9_.-]+$/.test(rest)) return { name: m[1]!, value: rest };
  const quoted = /^'([^'\\]*)'$/.exec(rest);
  return { name: m[1]!, value: quoted ? quoted[1]! : null };
}

/** the commands through which psql gets a variable a value this reader cannot see: a query result, the environment, the user */
const SETS_VARIABLES_UNSEEN = /^(gset|getenv|prompt)$/;
/** how many times one scan lets a variable's text be lexed in place of its reference: `\set x :x` would never end */
const MAX_SUBSTITUTIONS = 200;

/** The end of a quoted run that starts at `from` (the opening quote), or null when it is never closed. A doubled quote is the quote
 *  itself; a backslash escapes the next character only where the dialect says so. */
function quotedEnd(text: string, from: number, escapes: boolean): number | null {
  const q = text[from]!;
  let j = from + 1;
  for (;;) {
    if (j >= text.length) return null;
    if (escapes && text[j] === '\\') {
      j += 2;
      continue;
    }
    if (text[j] === q) {
      if (text[j + 1] === q) {
        j += 2;
        continue;
      }
      return j;
    }
    j++;
  }
}

/** A psql command at `i` (a backslash outside every string): its name, its arguments to the end of the line, and where the line ends. */
function backslashCommand(text: string, i: number, dialect: SqlDialect): { name: string; args: string; end: number } | { refused: string } {
  const eol = text.indexOf('\n', i);
  const line = text.slice(i + 1, eol < 0 ? text.length : eol);
  const name = dialect === 'pg' ? (/^(?:[A-Za-z0-9_]+\+?|.)/s.exec(line)?.[0] ?? '') : line.slice(0, 1);
  const args = line.slice(name.length).trim();
  // `\\` ends a meta-command and the line goes on as new input; this reader does not follow it
  if (args.includes('\\\\')) return { refused: 'a second backslash command on the same line' };
  return { name, args, end: eol < 0 ? text.length : eol };
}

function scanPostgres(input: string, known: SqlVariables): SqlScan | { refused: string } {
  let text = input;
  let code = '';
  const metas: SqlScan['metas'] = [];
  const variables: string[] = [];
  const values = new Map(known);
  let substitutions = 0;
  let n = text.length;
  // the name that ENDED at `nameEnd`: a quote right behind a lone `e` is an escape string, a quote behind anything else is not
  let nameEnd = -1;
  let name = '';
  let i = 0;
  while (i < n) {
    const c = text[i]!;
    if (c === "'" || c === '"') {
      const escapes = c === "'" && nameEnd === i && /^[eE]$/.test(name);
      const end = quotedEnd(text, i, escapes);
      if (end === null) return { refused: 'a quote that is never closed' };
      // an identifier is a NAME and stays visible (`"pg_read_file"(…)` is still that call); a literal is blanked
      code += c === '"' ? ` ${text.slice(i + 1, end)} ` : "''";
      i = end + 1;
      continue;
    }
    if (isIdentStart(c)) {
      let j = i + 1;
      while (isIdentCont(text[j])) j++;
      name = text.slice(i, j);
      nameEnd = j;
      code += name;
      i = j;
      continue;
    }
    if (isDigit(c) || (c === '.' && isDigit(text[i + 1]))) {
      DECIMAL.lastIndex = i;
      const num = DECIMAL.exec(text)![0];
      code += num;
      i += num.length;
      // a number that runs into a letter is ONE token with the name behind it, `$` included - and the lexers of older and newer
      // clients disagree about two spellings of it, so those are refused: an exponent straight into a `$` (`1e5$$`: a real
      // number and then a dollar quote to the older, one token to the newer) and a lone `e` straight into a quote (`1e'x'`: an
      // escape string to the older, junk and a plain string to the newer)
      if (isIdentStart(text[i])) {
        let j = i + 1;
        while (isIdentCont(text[j])) j++;
        const run = text.slice(i, j);
        if (/^[eE]\d+\$/.test(run)) return { refused: 'a number with an exponent that runs into a dollar sign, which older and newer clients lex differently' };
        if (/^[eE]$/.test(run) && text[j] === "'") return { refused: 'a number that runs into a lone e and a quote, which older and newer clients lex differently' };
        code += run;
        i = j;
      }
      nameEnd = -1;
      continue;
    }
    if (c === '$') {
      DOLLAR_QUOTE.lastIndex = i;
      const tag = DOLLAR_QUOTE.exec(text);
      if (tag) {
        const end = text.indexOf(tag[0], i + tag[0].length);
        if (end < 0) return { refused: 'a dollar-quoted body that is never closed' };
        // a body is CODE as often as it is text (`DO $$ … $$`), so it is read as code
        code += ` ${text.slice(i + tag[0].length, end)} `;
        i = end + tag[0].length;
        nameEnd = -1;
        continue;
      }
      // `$1` is a parameter, `$name` (never closed) is a token of its own, and a lone `$` is a character: none opens a quote
      PARAMETER.lastIndex = i;
      const param = PARAMETER.exec(text);
      let j = i + 1;
      if (param) j = i + param[0].length;
      else while (isIdentCont(text[j]) && text[j] !== '$') j++;
      code += text.slice(i, j);
      i = j;
      nameEnd = -1;
      continue;
    }
    if (c === ':') {
      // `::` is a cast; `:name` is a variable the client fills in, and what it holds is lexed as part of the script
      if (text[i + 1] === ':') {
        code += '::';
        i += 2;
        nameEnd = -1;
        continue;
      }
      VARIABLE_NAME.lastIndex = i + 1;
      const v = VARIABLE_NAME.exec(text);
      // (`a[1:2]` is a slice, not a variable named 2: a name made only of digits is no reference)
      if (v && !/^\d+$/.test(v[0])) {
        const value = values.get(v[0]);
        if (typeof value === 'string') {
          // psql puts the variable's TEXT where the reference stood and lexes it as part of the script (as a token of its own, which
          // the spaces keep it): the same is done here, so what the variable holds is read like everything else
          if (++substitutions > MAX_SUBSTITUTIONS) return { refused: 'variables that expand into one another without end' };
          text = `${text.slice(0, i)} ${value} ${text.slice(i + 1 + v[0].length)}`;
          n = text.length;
          nameEnd = -1;
          continue;
        }
        variables.push(v[0]);
      }
      code += ':';
      i++;
      nameEnd = -1;
      continue;
    }
    if (c === '\\') {
      // `\;` and `\:` put a `;` or a `:` into the statement and the line goes ON as SQL - they end nothing, and what follows
      // them on the line is still SQL or another command
      if (text[i + 1] === ';' || text[i + 1] === ':') {
        code += text[i + 1];
        i += 2;
        nameEnd = -1;
        continue;
      }
      const cmd = backslashCommand(text, i, 'pg');
      if ('refused' in cmd) return cmd;
      metas.push({ name: cmd.name, args: cmd.args });
      // what the command does to the variables that later references read
      if (cmd.name === 'set') {
        const set = setCommand(cmd.args);
        if (set) values.set(set.name, set.value);
      } else if (cmd.name === 'unset') values.delete(cmd.args.trim());
      else if (SETS_VARIABLES_UNSEEN.test(cmd.name)) values.clear();
      // (the line break that ends the command is consumed with it)
      i = cmd.end + 1;
      code += '\n';
      nameEnd = -1;
      continue;
    }
    code += c;
    i++;
    nameEnd = -1;
  }
  return { code, metas, variables };
}

/** MySQL's client (and ClickHouse's, which reads the same way): a backslash escapes inside a string, a backquote quotes a name, and
 *  `\x` is a client command wherever it stands outside a string. */
function scanMysql(text: string, dialect: SqlDialect): SqlScan | { refused: string } {
  let code = '';
  const metas: SqlScan['metas'] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === "'" || c === '"' || c === '`') {
      // a backslash escapes inside a MySQL string, and nowhere else
      const end = quotedEnd(text, i, dialect === 'mysql' && c !== '`');
      if (end === null) return { refused: 'a quote that is never closed' };
      // an identifier is a NAME and stays visible; a literal is blanked
      code += c === '`' || (c === '"' && dialect !== 'mysql') ? ` ${text.slice(i + 1, end)} ` : "''";
      i = end;
      continue;
    }
    if (c === '\\' && dialect !== 'plain') {
      const cmd = backslashCommand(text, i, 'mysql');
      if ('refused' in cmd) return cmd;
      metas.push({ name: cmd.name, args: cmd.args });
      i = cmd.end;
      code += '\n';
      continue;
    }
    code += c;
  }
  return { code, metas, variables: [] };
}
