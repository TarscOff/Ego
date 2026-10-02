// THE WORDS OF A COMMAND THAT ARE ANOTHER LANGUAGE'S TEXT: A PROGRAM, A PATTERN, A FILTER, A SEPARATOR, A REQUEST BODY.
//
// The readers of SHELL WORDS - the path scan, the wildcard enumerator, the option scan, the redirection scan, the matchers that
// anchor on the head of a command - are only right about words the shell hands over as arguments. A command line also carries
// words that are a second language: the code after `python3 -c`, the script of `sed` and `awk`, the filter of `jq` and of `gh
// --jq`, the pattern of `find -regex`, the `/` of `cut -d / -f 2`, the body of `curl -d`, the strings of `test`. A reader of shell
// words that is handed one invents a command, a path or a flag out of it: `/**` in a JSDoc comment is the wildcard that matches
// every file on the machine, `// a -o b` is an output flag, `expect(` is the launcher that starts a nested terminal session, and
// `(src|examples)/**` is a glob nobody can enumerate (ordinary-development review of wave 5, U-01..U-09: the dominant edit idiom of
// the agents, `python3 - <<'PY'`, went from a question to a refusal nobody can approve).
//
// operands.ts is the one reader of which words of a command are data (a search pattern, a message, a printed string - masked from
// the matchers) and, through this module, which are PROGRAM text (visible to the matchers, because they are the readers of what
// such a program may do; invisible to the readers of shell words). This module is the grammar of those tools, stated once: it
// reads each command with the option parser the tool really has (options.ts) and names the words that are text. A line it cannot
// place - an option nobody listed, whose arity is therefore unknown - is not read, and every word of it stays a shell word: the
// grammar only ever REMOVES words from what the shell readers see, and only words it has proved are not shell.
//
// WHAT IS NOT HERE: what a program does (the matchers read its text, and the readers of awk, sed and git in evaluate.ts read the
// commands it runs), and which of the remaining words is a path that is read or written (the path readers decide that).

import type { Scan, WordRole } from './operands.ts';
import { payloadSpans } from './carriers.ts';
import { type Grammar, type Parsed, parseOptions } from './options.ts';
import { scanSedScript } from './sed.ts';
import { AWK_GRAMMAR, PYTHON_GRAMMAR, SED_GRAMMAR, sedProgram } from './tools.ts';

const baseName = (w: string): string => w.replace(/^.*\//, '');

/* ------------------------------------------------------------------------------------------------------------- *
 * THE LANGUAGES: which commands run a program written in something that is not the shell
 * ------------------------------------------------------------------------------------------------------------- */

export type Language = 'python' | 'node' | 'ruby' | 'perl' | 'php' | 'rscript' | 'osascript';

/** The commands that run a program written in another language, by the name they are invoked with (versions included: `python3.12`,
 *  `ruby3.2`). ONE table: the heredoc reader, the carrier of `-c`, the stdin-script test and the word reader all ask it. */
const LANGUAGE_HEADS: ReadonlyArray<readonly [Language, RegExp]> = [
  ['python', /^(?:python|pypy)\d*(?:\.\d+)*$/],
  ['node', /^(?:node|nodejs)$/],
  ['ruby', /^ruby\d*(?:\.\d+)*$/],
  ['perl', /^perl\d*(?:\.\d+)*$/],
  ['php', /^php\d*(?:\.\d+)*$/],
  ['rscript', /^Rscript$/],
  ['osascript', /^osascript$/],
];

/** The language a command runs, or null when it is not an interpreter of one (a shell is not: its text IS shell words). */
export function languageOf(head: string): Language | null {
  const name = baseName(head);
  for (const [lang, re] of LANGUAGE_HEADS) if (re.test(name)) return lang;
  return null;
}

/** Whether a command that reads its program from standard input reads another language: `python3 -`, `node <<'EOF'`. What it
 *  reads is that language's text, whatever the shell makes of the characters around it. (osascript takes a file or `-e`.) */
export function readsLanguageFromStdin(head: string): boolean {
  const lang = languageOf(head);
  return lang !== null && lang !== 'osascript';
}

/** The commands that read standard input as TEXT - a string they search, count, transform or print, whatever it says - and do nothing
 *  else with it. A string fed to any other command (`docker run -i img sh`, `ssh host`, `xargs rm`, `mysql`, `patch`, a script of the
 *  project's own) may be a script, a list of arguments or a query, and stays what it was: shell words, read as such. A POSITIVE list:
 *  the commands nobody has listed are the ones nobody has read. */
const TEXT_STDIN =
  /^(?:cat|tac|rev|nl|grep|egrep|fgrep|rg|ag|ack|sed|gsed|awk|gawk|mawk|nawk|jq|yq|tr|cut|sort|uniq|wc|head|tail|column|fold|fmt|paste|join|comm|base64|xxd|od|hexdump|shasum|sha1sum|sha224sum|sha256sum|sha384sum|sha512sum|md5sum|md5|cksum|bc|dc|read|mapfile|readarray|iconv|expand|unexpand)$/;

/** Whether the standard input of a command is text for it to read (an interpreter's program, or the string a text tool works on). */
export function readsTextFromStdin(head: string): boolean {
  return languageOf(head) !== null || TEXT_STDIN.test(baseName(head));
}

/* ------------------------------------------------------------------------------------------------------------- *
 * THE ROLE BUILDER
 * ------------------------------------------------------------------------------------------------------------- */

class Roles {
  readonly roles: WordRole[];
  private readonly line: readonly string[];
  private readonly at: number;
  private readonly redirected: ReadonlySet<number>;
  constructor(line: readonly string[], at: number, redirected: ReadonlySet<number>) {
    this.line = line;
    this.at = at;
    this.redirected = redirected;
    // a redirection is not an operand of the command (`tr / _ < f.txt`): the operator and its target are the shell's
    this.roles = line.map((_, i) => (i <= at ? 'head' : redirected.has(i) ? 'option' : 'operand'));
  }
  /** the words of the command, redirections taken out, with where each stands in the line */
  words(): Array<{ text: string; at: number }> {
    const out: Array<{ text: string; at: number }> = [];
    for (let i = this.at + 1; i < this.line.length; i++) if (!this.redirected.has(i)) out.push({ text: this.line[i]!, at: i });
    return out;
  }
  mark(i: number | undefined, role: WordRole): void {
    if (i !== undefined && i > this.at && i < this.roles.length && !this.redirected.has(i)) this.roles[i] = role;
  }
  done(): Scan {
    return { roles: this.roles, glued: new Map() };
  }
}

/** The parse of a command's own words (redirections taken out), with each position mapped back to the line. null when the grammar
 *  met an option it does not know: the arity of that option is unknown, so no word after it can be placed. */
function parseKept(g: Grammar, r: Roles): { p: Parsed; map: number[] } | null {
  const kept = r.words();
  const p = parseOptions(g, kept.map((w) => w.text), 0);
  if (p.unknown.length > 0) return null;
  return { p, map: kept.map((w) => w.at) };
}

/** every option word of a parse is an option, every separate value word a value */
function markOptions(r: Roles, parsed: { p: Parsed; map: number[] }): void {
  for (const o of parsed.p.options) {
    r.mark(parsed.map[o.at], 'option');
    if (o.valueAt !== null && o.valueAt !== o.at) r.mark(parsed.map[o.valueAt], 'value');
  }
}

/* ------------------------------------------------------------------------------------------------------------- *
 * THE INTERPRETERS: the code after the option that names it
 * ------------------------------------------------------------------------------------------------------------- */

/** A scan of an interpreter's own options up to its program: `code` names the options whose NEXT word is the code (`-e`), `glued`
 *  recognises a word that carries the code in itself (`-eCODE`, `--eval=CODE`), `valued` the options whose next word is a value
 *  (`-r LIB`). The scan ends at the first word that is none of them - the script, or `-` - because every word after it is the
 *  script's own argument (`node script.js -e x` hands `-e x` to the script). An option whose arity is not listed and that takes a
 *  separate value ends the scan early, which only ever leaves words as shell words. */
function scanInterpreter(
  r: Roles,
  spec: { code: (w: string) => boolean; glued: (w: string) => boolean; valued: (w: string) => boolean },
): Scan {
  const words = r.words();
  for (let k = 0; k < words.length; k++) {
    const w = words[k]!;
    if (w.text === '--' || !w.text.startsWith('-') || w.text === '-') break;
    r.mark(w.at, 'option');
    if (spec.glued(w.text)) {
      r.mark(w.at, 'program');
      continue;
    }
    if (spec.code(w.text)) {
      const next = words[k + 1];
      if (next !== undefined) {
        r.mark(next.at, 'program');
        k++;
      }
      continue;
    }
    if (spec.valued(w.text)) {
      const next = words[k + 1];
      if (next !== undefined) {
        r.mark(next.at, 'value');
        k++;
      }
    }
  }
  return r.done();
}

function interpreterRoles(lang: Language, r: Roles): Scan | null {
  switch (lang) {
    case 'python': {
      // python's own table (tools.ts): `-c CODE` ends its options, `-m MODULE` is a module name
      const parsed = parseKept(PYTHON_GRAMMAR, r);
      if (parsed === null) return null;
      markOptions(r, parsed);
      for (const o of parsed.p.options) if (o.name === 'c' && o.valueAt !== null) r.mark(parsed.map[o.valueAt], 'program');
      return r.done();
    }
    case 'node':
      return scanInterpreter(r, {
        code: (w) => /^(?:-e|--eval|-p|--print|-pe|-ep)$/.test(w),
        glued: (w) => /^--(?:eval|print)=/.test(w),
        valued: (w) => /^(?:-r|--require|--import|--loader|--experimental-loader|-C|--conditions|--input-type|--title|--env-file)$/.test(w),
      });
    case 'ruby':
      return scanInterpreter(r, {
        // a cluster of flags ending in `e` (`-ne`, `-lane`, `-pe`, `-0777pe`), or `-eCODE`
        code: (w) => /^-(?:[acdlnpsSvwy]|0[0-7]*)*e$/.test(w),
        glued: (w) => /^-(?:[acdlnpsSvwy]|0[0-7]*)*e./.test(w),
        valued: (w) => /^(?:-C|-I|-r|-E|-F)$/.test(w),
      });
    case 'perl':
      return scanInterpreter(r, {
        // `-e` and `-E` end a cluster of flags (`-pe`, `-lane`, `-0777pe`, `-wle`); `-l` and `-0` take digits, `-i` takes the rest of its word
        code: (w) => /^-(?:[acnpsStTuUwWXCz]|l[0-7]*|0[0-7xX]*)*[eE]$/.test(w),
        glued: (w) => /^-(?:[acnpsStTuUwWXCz]|l[0-7]*|0[0-7xX]*)*[eE]./.test(w),
        valued: (w) => w === '-I',
      });
    case 'php':
      return scanInterpreter(r, {
        code: (w) => /^-[rBRE]$/.test(w),
        glued: () => false,
        valued: (w) => /^-[dcfzFtS]$/.test(w),
      });
    case 'rscript':
      return scanInterpreter(r, { code: (w) => w === '-e', glued: () => false, valued: () => false });
    case 'osascript':
      return scanInterpreter(r, { code: (w) => w === '-e', glued: () => false, valued: (w) => /^-[ls]$/.test(w) });
  }
}

/* ------------------------------------------------------------------------------------------------------------- *
 * SED, AWK, JQ: the script is the first operand unless an option supplies one
 * ------------------------------------------------------------------------------------------------------------- */

function sedRoles(r: Roles): Scan | null {
  const parsed = parseKept(SED_GRAMMAR, r);
  if (parsed === null) return null;
  markOptions(r, parsed);
  let supplied = false;
  for (const o of parsed.p.options) {
    if (o.name === 'expression' && o.valueAt !== null) {
      supplied = true;
      r.mark(parsed.map[o.valueAt], 'program');
    } else if (o.name === 'file') supplied = true;
  }
  if (supplied) return r.done();
  let operands = parsed.p.operands;
  // BSD sed's `-i ''`: the empty word right after the in-place flag is its suffix, and the script is the next operand
  const ip = parsed.p.options.find((o) => o.name === 'in-place');
  if (ip && ip.value === null && operands[0]?.text === '' && operands[0].at === ip.at + 1) {
    r.mark(parsed.map[operands[0].at], 'value');
    operands = operands.slice(1);
  }
  if (operands[0] !== undefined) r.mark(parsed.map[operands[0].at], 'program');
  return r.done();
}

function awkRoles(r: Roles): Scan | null {
  const parsed = parseKept(AWK_GRAMMAR, r);
  if (parsed === null) return null;
  markOptions(r, parsed);
  let supplied = false;
  for (const o of parsed.p.options) {
    if (o.valueAt === null) continue;
    // the separator and the assignments are strings; the program may come from an option; a file named by `-f` is a file
    if (o.name === 'field-separator' || o.name === 'assign') r.mark(parsed.map[o.valueAt], 'program');
    else if (o.name === 'source') {
      supplied = true;
      r.mark(parsed.map[o.valueAt], 'program');
    } else if (o.name === 'file' || o.name === 'exec') supplied = true;
  }
  if (!supplied && parsed.p.operands[0] !== undefined) r.mark(parsed.map[parsed.p.operands[0].at], 'program');
  return r.done();
}

/** Where the PROGRAM of the awk command whose head stands at `at` is in `line` - the first operand, unless an option supplies it - or null when
 *  an option supplies it (`-f`, `-e`, `--source`) or the line has an option the table cannot place. */
export function awkProgramAt(line: readonly string[], at: number): number | null {
  const r = new Roles(line, at, new Set());
  const parsed = parseKept(AWK_GRAMMAR, r);
  if (parsed === null) return null;
  for (const o of parsed.p.options) if (o.name === 'file' || o.name === 'exec' || o.name === 'source') return null;
  const first = parsed.p.operands[0];
  return first === undefined ? null : (parsed.map[first.at] ?? null);
}

const JQ_FLAGS = /^--(?:null-input|raw-input|slurp|compact-output|raw-output0?|join-output|ascii-output|sort-keys|color-output|monochrome-output|tab|unbuffered|stream|stream-errors|seq|exit-status|binary|version|help|build-configuration)$|^-[nRsrjacSCMebhV]+$/;
/** jq: the filter is the first operand unless `-f FILE` names it; `--arg NAME VALUE` and the words after `--args` are strings */
function jqRoles(r: Roles): Scan | null {
  const words = r.words();
  let filter = false;
  let fromFile = false;
  let strings = false;
  for (let k = 0; k < words.length; k++) {
    const w = words[k]!;
    if (strings) {
      r.mark(w.at, 'program');
      continue;
    }
    if (w.text === '--') {
      // after `--` the first word is the filter (when none came yet) and the rest are files
      const first = words[k + 1];
      if (!filter && !fromFile && first !== undefined) r.mark(first.at, 'program');
      break;
    }
    if (w.text.startsWith('-') && w.text.length > 1) {
      r.mark(w.at, 'option');
      if (w.text === '--arg' || w.text === '--argjson') {
        r.mark(words[k + 1]?.at, 'program');
        r.mark(words[k + 2]?.at, 'program');
        k += 2;
      } else if (w.text === '--slurpfile' || w.text === '--rawfile') {
        r.mark(words[k + 1]?.at, 'program');
        r.mark(words[k + 2]?.at, 'value');
        k += 2;
      } else if (w.text === '-f' || w.text === '--from-file') {
        fromFile = true;
        r.mark(words[k + 1]?.at, 'value');
        k++;
      } else if (w.text === '-L' || w.text === '--indent') {
        r.mark(words[k + 1]?.at, 'value');
        k++;
      } else if (w.text === '--args' || w.text === '--jsonargs') strings = true;
      else if (!JQ_FLAGS.test(w.text)) return null;
      continue;
    }
    if (!filter && !fromFile) {
      r.mark(w.at, 'program');
      filter = true;
    }
  }
  return r.done();
}

/* ------------------------------------------------------------------------------------------------------------- *
 * TEST: the string operands of a comparison are strings; the operands of a file test are files
 * ------------------------------------------------------------------------------------------------------------- */

const TEST_BINARY = /^(?:=|==|!=|<|>|-eq|-ne|-lt|-le|-gt|-ge)$/;
function testRoles(head: string, r: Roles): Scan | null {
  let words = r.words();
  // the `]` that closes `[`
  const close = words[words.length - 1];
  if (head === '[' && close?.text === ']') {
    r.mark(close.at, 'option');
    words = words.slice(0, -1);
  }
  // a binary operator takes the words on both sides of it, first, so that `-n = x` is a comparison of the string `-n`
  const taken = new Set<number>();
  const LOGIC = /^(?:!|\(|\)|-a|-o)$/;
  words.forEach((w, k) => {
    if (!TEST_BINARY.test(w.text) || taken.has(k)) return;
    for (const side of [k - 1, k + 1]) {
      const other = words[side];
      if (other === undefined || LOGIC.test(other.text)) continue;
      taken.add(side);
      r.mark(other.at, 'program');
    }
  });
  // `-n S` and `-z S` test a string
  words.forEach((w, k) => {
    if (taken.has(k) || (w.text !== '-n' && w.text !== '-z')) return;
    const other = words[k + 1];
    if (other !== undefined && !taken.has(k + 1) && !LOGIC.test(other.text)) r.mark(other.at, 'program');
  });
  return r.done();
}

/* ------------------------------------------------------------------------------------------------------------- *
 * THE TOOLS WHOSE OPTION VALUE IS TEXT: curl's request, gh's template, find's pattern, a delimiter
 * ------------------------------------------------------------------------------------------------------------- */

/** curl: a request body, a header, an agent, a method and credentials are text - unless the value names a FILE, which `@` says */
function curlRoles(r: Roles): Scan | null {
  const words = r.words();
  for (let k = 0; k < words.length; k++) {
    const w = words[k]!.text;
    const next = words[k + 1];
    if (/^(?:-d|--data|--data-raw|--data-ascii|--data-binary|--json)$/.test(w)) {
      if (next !== undefined && !next.text.startsWith('@')) r.mark(next.at, 'program');
      k++;
    } else if (w === '--data-urlencode') {
      // `name=content`, `=content`, `content` are text; `name@file` and `@file` read a file
      if (next !== undefined && !/^[^=]*@/.test(next.text)) r.mark(next.at, 'program');
      k++;
    } else if (/^(?:-H|--header)$/.test(w)) {
      if (next !== undefined && !next.text.startsWith('@')) r.mark(next.at, 'program');
      k++;
    } else if (/^(?:-A|--user-agent|-e|--referer|-X|--request|-u|--user)$/.test(w)) {
      r.mark(next?.at, 'program');
      k++;
    }
  }
  return r.done();
}

/** gh: the template of `--jq` / `-q` / `--template` and the title and body of what it writes are text the CLI renders or sends */
function ghRoles(r: Roles): Scan | null {
  const words = r.words();
  for (let k = 0; k < words.length; k++) {
    const w = words[k]!.text;
    if (/^(?:--jq|-q|--template|-t|--title|--body|-b|--notes)$/.test(w)) {
      r.mark(words[k + 1]?.at, 'program');
      k++;
    } else if (/^--(?:jq|template|title|body|notes)=/.test(w)) r.mark(words[k]!.at, 'program');
  }
  return r.done();
}

/** find: the value of `-regex` is a REGULAR EXPRESSION matched against the whole path - never a path, and not a wildcard either (`.*\.\(ts\|js\)`
 *  was a glob nobody could enumerate). The value of `-name`, `-path` and their kin is a WILDCARD, and it is deliberately not here: it
 *  decides which files a `-exec` clause or `-delete` acts on, so `find . -name .e\* -exec cat {} +` reads what the wildcard names, and
 *  the readers of wildcards must see it. A `-exec` clause is another command's words. */
const FIND_PATTERN_PREDICATES = /^-(?:regex|iregex)$/;
function findRoles(line: readonly string[], at: number, r: Roles): Scan | null {
  const inClause = new Set<number>();
  for (const [from, to] of payloadSpans(line, at)) for (let i = from; i < to; i++) inClause.add(i);
  // A PATTERN THAT SELECTS FILES FOR AN ACT stays in view of the readers of wildcards: `find . -regex '.*' -exec cat {} +` reads every
  // file under the root, `.env` among them, and the reading of the regex as a wildcard (which over-approximates it) is what said so
  if (r.words().some((w) => /^-(?:exec|execdir|ok|okdir|delete|fprint0?|fprintf|fls)$/.test(w.text))) return r.done();
  for (const w of r.words()) {
    if (inClause.has(w.at) || !FIND_PATTERN_PREDICATES.test(w.text)) continue;
    r.mark(w.at, 'option');
    if (!inClause.has(w.at + 1)) r.mark(w.at + 1, 'program');
  }
  return r.done();
}

/** tr: its operands are sets of characters, and there is no file among them */
function trRoles(r: Roles): Scan | null {
  let ended = false;
  for (const w of r.words()) {
    if (!ended && w.text === '--') {
      ended = true;
      r.mark(w.at, 'option');
    } else if (!ended && /^-/.test(w.text) && w.text.length > 1) {
      if (!/^(?:-[cCdst]+|--(?:complement|delete|squeeze-repeats|truncate-set1|help|version))$/.test(w.text)) return null;
      r.mark(w.at, 'option');
    } else r.mark(w.at, 'program');
  }
  return r.done();
}

/** The options of the text tools that take a SEPARATOR: `cut -d /`, `sort -t /`, `paste -d /`, `join -t /`, `column -s /`. The flags
 *  that may stand in front of the letter in a cluster are the tool's own (`sort -nrt /`). */
const SEPARATOR_OPTIONS: Readonly<Record<string, { words: RegExp; cluster: RegExp }>> = {
  cut: { words: /^(?:-d|--delimiter|--output-delimiter)$/, cluster: /^-[sz]*d$/ },
  sort: { words: /^(?:-t|--field-separator)$/, cluster: /^-[bdfgiMhnRrVuszcCm]*t$/ },
  paste: { words: /^(?:-d|--delimiters)$/, cluster: /^-[sz]*d$/ },
  join: { words: /^-t$/, cluster: /^-[i]*t$/ },
  column: { words: /^(?:-s|-o|--separator|--output-separator)$/, cluster: /^-[tnx]*[so]$/ },
};
function separatorRoles(head: string, r: Roles): Scan | null {
  const spec = SEPARATOR_OPTIONS[head]!;
  const words = r.words();
  for (let k = 0; k < words.length; k++) {
    const w = words[k]!;
    if (w.text === '--') break;
    if (!spec.words.test(w.text) && !spec.cluster.test(w.text)) continue;
    r.mark(w.at, 'option');
    r.mark(words[k + 1]?.at, 'program');
    k++;
  }
  return r.done();
}

/* ------------------------------------------------------------------------------------------------------------- *
 * THE ENTRY: the roles of the words of one command, when this module has a grammar for its head
 * ------------------------------------------------------------------------------------------------------------- */

/** The role of every word of the command whose head stands at `at`, with the program-text words marked `program`; null when the
 *  head has no grammar here or the line has an option the grammar does not know (every word then stays a shell word). `redirected`
 *  is the set of words that are redirection operators and their targets, which the caller read from the tokenizer's shapes. */
export function programRoles(head: string, line: readonly string[], at: number, redirected: ReadonlySet<number>): Scan | null {
  const r = new Roles(line, at, redirected);
  const lang = languageOf(head);
  if (lang !== null) return interpreterRoles(lang, r);
  switch (head) {
    case 'sed':
    case 'gsed':
      return sedRoles(r);
    case 'awk':
    case 'gawk':
    case 'mawk':
    case 'nawk':
      return awkRoles(r);
    case 'jq':
      return jqRoles(r);
    case 'test':
    case '[':
      return testRoles(head, r);
    case 'curl':
      return curlRoles(r);
    case 'gh':
      return ghRoles(r);
    case 'find':
    case 'gfind':
      return findRoles(line, at, r);
    case 'tr':
      return trRoles(r);
    case 'cut':
    case 'sort':
    case 'paste':
    case 'join':
    case 'column':
      return separatorRoles(head, r);
  }
  return null;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * WHETHER A SED PROGRAM RUNS A COMMAND
 * ------------------------------------------------------------------------------------------------------------- */

/** Whether the sed command whose head stands at `at` in `line` has a script that EXECUTES something: the `e` command (`1e id`), the `e`
 *  flag of a substitution (`s/a/b/2e`), or a script the scanner could not follow. The script is what sed's option parser says it is
 *  (tools.ts), and it is read the way sed reads it (sed.ts) - the regexes this replaces looked for the letter `e` after three of the
 *  same character anywhere in the line, which a file called `service.ts` has, and missed `s/a/b/2e`, which sed accepts. An option the
 *  table cannot place leaves the script unknown, and every word is then tried as one. */
export function sedExecutes(line: readonly string[], at: number, dynamic: ReadonlySet<string> = new Set()): boolean {
  const prog = sedProgram(line, at + 1);
  const scripts = prog.unknown.length > 0 ? line.slice(at + 1).filter((w) => !w.startsWith('-')) : prog.scripts;
  for (const script of scripts) {
    let text = script;
    // A SCRIPT THE SHELL BUILDS: one that is nothing but an expansion (`sed "$S"`) is a program nobody has read; one that holds expansions
    // among its own characters (`sed -n "${A},${B}p"`) is read with each of them as a number - the shape of the idiom - and an expansion in
    // the place of a command (`s/a/b/$FLAGS`) makes the script one the scanner cannot follow
    if (dynamic.has(script)) {
      if (EXPANSION.test(script) && script.replace(EXPANSION_G, '').trim() === '') return true;
      for (const m of script.matchAll(EXPANSION_G)) {
        const before = script[m.index - 1];
        const after = script[m.index + m[0].length];
        if (!(before === undefined || DATA_BEFORE.includes(before)) || !(after !== undefined && DATA_AFTER.includes(after))) return true;
      }
      text = script.replace(EXPANSION_G, '1');
    }
    const eff = scanSedScript(text);
    if (eff.executesPatternSpace || eff.commands.length > 0 || eff.confused) return true;
  }
  return false;
}
/** WHERE AN EXPANSION IS A NUMBER OR A PATTERN AND NOT A COMMAND: between the separators of an address and the command letters that take no
 *  argument (`${A},${B}p`), inside the delimiters of a regular expression or of the parts of `s` (`/$RE/p`, `s/$A/$B/g`). Anywhere else - right
 *  after a number, at the end - it can be the command or the flag. */
const DATA_BEFORE = ',;{} +~/|#:!\n';
const DATA_AFTER = ',~/|#:!;} pdqn=\n';
/** one expansion of the shell: `${…}`, `$(…)`, `$NAME`, a special parameter, or a backtick span */
const EXPANSION_G = /\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?$!-]|`[^`]*`/g;
const EXPANSION = new RegExp(EXPANSION_G.source);
