// THE ROLE OF A WORD: WHICH OF THE WORDS OF A COMMAND ARE DATA, AND WHICH COMMANDS NEVER RUN WHAT THEY ARE GIVEN.
//
// The control plane judges a command by TEXT matchers (regular expressions over the normalized segment), by path
// readers and by a scan for governed program names in argument position. All three read the segment as a bag of words,
// and a bag of words cannot tell the word `hook` in `ego hook claude-code PreToolUse` from the same word in
// `grep -rn "hook claude-code PreToolUse" docs/`: the first RUNS the human prompt hook, the second SEARCHES the
// documentation that describes it. Every matcher that was anchored at the command by one exit review was a fix at one
// spelling, and the next review found the sibling: `ego hook` (review 9), `decision answer` (review 9), `NODE_OPTIONS=`
// (review 7), `claude` (review 11, #194), `~/.ssh` (#143), `core.hooksPath` (#60), `rm -rf` in a hook file (#145),
// `touch` under `.harness/runtime` (#163). An ABSOLUTE deny on a word the operator only LOOKED for removes the human gate
// from reading the documentation of the gate itself (review 11, #142, critical).
//
// So the question is answered in ONE place, and every reader asks it: given the words of a command, which of them are
// DATA - a search pattern, a commit message, a string to print - and so can be neither the act nor the place the act is
// done? The answer is a GRAMMAR of the tools that take data (a positive list of what each of them accepts, in the options
// they really have), and a line the grammar cannot place - an option nobody listed, whose arity is therefore unknown, and
// whose next word may be a program - is read as it was: nothing is claimed, the words stay visible, the matchers see them.
// What this file adds is only ever a REDUCTION of what the matchers see, and only of words that are proven not to be
// the command. It never classifies anything and never allows anything.
//
// WHAT IS NOT HERE: which of the remaining words is a path that is read and which is written (the path readers in
// evaluate.ts decide that), and whether a command is a probe or a dry run (helpProbeHead).

/** What a word holds of the shell's redirection characters, by how it was WRITTEN: `none`; `real`, a `<` or `>` outside every quote -
 *  the shell's operator; `literal`, only characters a quote, a backslash or an ANSI-C string turned into text (`"=>"`, `\\>x`,
 *  `$'>'`); `mixed`, both, or a quoted part beside a real operator (`''>x`: an empty word and a redirection). The tokenizer is the
 *  one reader that knows, and a caller that does not have it passes nothing (see `redirectionWords`). */
export type OperatorShape = 'none' | 'real' | 'literal' | 'mixed';

/** What a word is to the command it belongs to. Only `data` is ever masked; `operand` and `value` are named so that the
 *  scan for governed programs in argument position can tell a file name from an option value that may be a program. */
export type WordRole = 'head' | 'option' | 'value' | 'data' | 'operand' | 'unread';

interface OptionGrammar {
  /** short letters whose value is DATA (`grep -e PATTERN`) */
  readonly dataShort: string;
  /** long options, without dashes, whose value is data */
  readonly dataLong: readonly string[];
  /** short letters that take a value which is NOT data: a count, a glob, a file, a program */
  readonly valueShort: string;
  readonly valueLong: readonly string[];
  /** letters and long names that take no value. An option in none of the four lists has an arity nobody can tell. */
  readonly flagShort: string;
  readonly flagLong: readonly string[];
  /** options that SUPPLY the pattern, so that the first operand is a file: `-e PATTERN`, `-f FILE` */
  readonly suppliesShort: string;
  readonly suppliesLong: readonly string[];
  /** long options after which there is no pattern at all (`rg --files` lists files) */
  readonly noPatternLong?: readonly string[];
  /** the first operand, when nothing else supplied one, is the pattern */
  readonly positionalPattern: boolean;
  /** `-5` is `-C 5` */
  readonly digitContext?: boolean;
}

const words = (s: string): readonly string[] => s.split(/\s+/).filter(Boolean);

/** grep, egrep, fgrep (GNU and BSD spellings). `--color` takes its value only glued, so it is a flag here. */
const GREP: OptionGrammar = {
  dataShort: 'e',
  dataLong: ['regexp'],
  valueShort: 'ABCDdfm',
  valueLong: words(
    'after-context before-context binary-files context devices directories exclude exclude-dir exclude-from file ' +
      'group-separator include include-dir label max-count',
  ),
  flagShort: 'abcEFGHhIiJLlnOoPpqRrSsTUuVvwXxyZz',
  flagLong: words(
    'basic-regexp binary byte-offset color colour count dereference-recursive extended-regexp files-with-matches ' +
      'files-without-match fixed-strings help ignore-case initial-tab invert-match line-buffered line-number line-regexp ' +
      'mmap no-filename no-group-separator no-ignore-case no-messages null null-data only-matching perl-regexp quiet ' +
      'recursive silent text unix-byte-offsets version with-filename word-regexp',
  ),
  suppliesShort: 'ef',
  suppliesLong: ['regexp', 'file'],
  positionalPattern: true,
  digitContext: true,
};

/** ripgrep. `-r` is `--replace` (it takes a value) and `--color` takes one too: the two places it differs from grep. `--pre` and
 *  `--hostname-bin` name a PROGRAM; they are values, never data. */
const RIPGREP: OptionGrammar = {
  dataShort: 'e',
  dataLong: ['regexp'],
  valueShort: 'ABCEdfgjmMrtT',
  valueLong: words(
    'after-context before-context color colors context context-separator dfa-size-limit encoding engine ' +
      'field-context-separator field-match-separator file glob iglob ignore-file hostname-bin hyperlink-format ' +
      'max-columns max-count max-depth maxdepth max-filesize path-separator pre pre-glob regex-size-limit replace sort ' +
      'sortr threads type type-add type-clear type-not',
  ),
  flagShort: 'abcFhHiIlLnNopPqsSuUvVwxz.0',
  flagLong: words(
    'auto-hybrid-regex binary block-buffered byte-offset case-sensitive column count count-matches crlf debug files ' +
      'files-with-matches files-without-match fixed-strings follow glob-case-insensitive heading help hidden ignore ' +
      'ignore-case ignore-dot ignore-exclude ignore-file-case-insensitive ignore-files ignore-global ignore-messages ' +
      'ignore-parent ignore-vcs include-zero invert-match json line-buffered line-number line-regexp max-columns-preview ' +
      'mmap multiline multiline-dotall no-binary no-block-buffered no-byte-offset no-column no-config no-crlf ' +
      'no-filename no-follow no-glob-case-insensitive no-heading no-hidden no-ignore no-ignore-dot no-ignore-exclude ' +
      'no-ignore-files no-ignore-global no-ignore-messages no-ignore-parent no-ignore-vcs no-line-buffered ' +
      'no-line-number no-max-columns-preview no-messages no-mmap no-multiline no-one-file-system no-pcre2-unicode ' +
      'no-require-git no-search-zip no-sort-files no-stats no-trim no-unicode null null-data one-file-system ' +
      'only-matching passthru pcre2 pcre2-version pretty quiet require-git search-zip smart-case sort-files stats ' +
      'stop-on-nonmatch text trace trim type-list unicode unrestricted version vimgrep with-filename word-regexp',
  ),
  suppliesShort: 'ef',
  suppliesLong: ['regexp', 'file'],
  noPatternLong: ['files', 'type-list', 'pcre2-version', 'version', 'help'],
  positionalPattern: true,
};

/** pgrep PATTERN: a name to look for among the processes, not a program to run. */
const PGREP: OptionGrammar = {
  dataShort: '',
  dataLong: [],
  valueShort: 'dgGPstuUF',
  valueLong: words('delimiter pgroup group parent session terminal euid uid pidfile'),
  flagShort: 'acfilnovwxqr',
  flagLong: words('count full ignore-case inverse lightweight list-full list-name newest oldest exact help version'),
  suppliesShort: '',
  suppliesLong: [],
  positionalPattern: true,
};

/** git grep. `-O` hands the matching files to a PAGER COMMAND and is deliberately not listed: a line that has it is not read. */
const GIT_GREP: OptionGrammar = {
  dataShort: 'e',
  dataLong: [],
  valueShort: 'ABCmf',
  valueLong: words('max-depth threads max-count after-context before-context context file'),
  flagShort: 'aIiwvhHnlLcopqrzEGPFWV',
  flagLong: words(
    'text ignore-case word-regexp invert-match no-recursive recursive full-name extended-regexp basic-regexp ' +
      'perl-regexp fixed-strings line-number column files-with-matches name-only files-without-match count color ' +
      'no-color break heading show-function function-context only-matching quiet null cached untracked no-index ' +
      'exclude-standard no-exclude-standard recurse-submodules and or not all-match textconv no-textconv',
  ),
  suppliesShort: 'ef',
  suppliesLong: [],
  positionalPattern: true,
  digitContext: true,
};

/** The plain-text readers whose short names are the GNU twins, and the ones that take a compressed file. */
const GREP_HEADS = new Set(['grep', 'egrep', 'fgrep', 'zgrep', 'zegrep', 'zfgrep', 'bzgrep', 'xzgrep', 'ggrep', 'gegrep', 'gfgrep']);

/** Heads whose operands are NEVER a program, whatever options they have: they print, count, list or compare the files
 *  and strings they are handed, and none of them has an option that runs a command. The scan for a governed program
 *  name in argument position (`LOCKED_HEADS`) exists for wrappers and launchers that RUN their operands; reading
 *  `wc -l claude` or `which claude` through it made looking for a program the same act as starting one (review 11, #194).
 *  A tool with an option that runs a program (`rg --pre`, `git grep -O`, `sort --compress-program`, `find -exec`) is not
 *  here: for those the grammar above names the words that ARE data, and the others stay in view. */
const NO_EXEC_READERS = new Set(
  words(
    'ls cat head tail wc tree stat file du df diff cmp comm uniq cut nl tac rev fold column paste join expand unexpand od ' +
      'xxd hexdump strings sha1sum sha256sum sha512sum shasum md5sum cksum b2sum which type whereis whatis basename ' +
      'dirname realpath readlink nproc uname whoami id date hostname pwd echo printf seq expr jq yq',
  ),
);
/** the commands whose operands are strings they print, so every operand is data */
const PRINTERS = new Set(['echo', 'printf']);

const baseName = (w: string): string => w.replace(/^.*\//, '');
/** A head is trusted to be the tool of that name only when it is a bare word or a system path: `./grep` is whatever the
 *  repository put there, and masking its arguments would hide the command it really is. */
const SYSTEM_BIN = /^\/(?:usr\/)?(?:local\/)?(?:s?bin)\/|^\/opt\/homebrew\/bin\//;
function trustedName(w: string): string | null {
  if (!w.includes('/')) return w;
  return SYSTEM_BIN.test(w) ? baseName(w) : null;
}

/** Whether this head never runs its operands (see NO_EXEC_READERS). `command -v NAME` and `type NAME` look a name up. */
export function runsNoOperand(head: string): boolean {
  const name = trustedName(head);
  return name !== null && NO_EXEC_READERS.has(name);
}

interface Scan {
  roles: WordRole[];
  /** a data word that is glued to its option (`-efoo`, `--regexp=foo`): the offset where the data starts */
  glued: Map<number, number>;
}

/** A word that is a redirection, or has one glued into it: it has a `<` or a `>` and NO whitespace. A word with whitespace in
 *  it can only be a quoted string - `grep "> control-plane/x.md" README.md` searches for that text - and a redirection
 *  operator is never written with a space inside it. */
const isRedirection = (w: string): boolean => /[<>]/.test(w) && !/\s/.test(w);

/** THE WORDS OF A LINE THAT ARE A REDIRECTION, and the word after a bare operator (its target). They are never data, even
 *  when the command prints: `echo x>.harness/runtime/ledger.json` is one word with the operator inside it, and masking it as
 *  the string it looks like hid a write to the runtime state (the bypass corpus).
 *
 *  WHETHER A WORD IS ONE DEPENDS ON HOW IT WAS WRITTEN, and only the caller that still has that can say: `grep => src` redirects,
 *  and `grep "=>" src` searches for an arrow. Both reach here as the word `=>`. With the shape of each word (the tokenizer's), a
 *  `real` operator is the redirection and a `literal` one is a plain word. Without it the question has no answer, and a wrong
 *  one MOVES THE PATTERN: reading the arrow as a redirection made the next word - the file, `~/.ssh/id_rsa` - the pattern, and
 *  masked the path. So a line with a word that cannot be placed (no shape, or a `mixed` one) is not read at all (null). */
function redirectionWords(line: readonly string[], from: number, shape?: readonly OperatorShape[]): Set<number> | null {
  const out = new Set<number>();
  for (let i = from; i < line.length; i++) {
    const w = line[i]!;
    if (shape !== undefined) {
      const sh = shape[i];
      if (sh === 'mixed') return null;
      if (sh !== 'real') continue;
    } else {
      if (!isRedirection(w)) continue;
      return null;
    }
    out.add(i);
    // a bare operator (`>`, `>>`, `2>`, `&>`, `<`, `>&`, `<<<`) takes the NEXT word as its target - and a target that is itself an
    // operator (`echo => > f`) is no line a shell runs: it is not read
    if (/^(?:\d*|&)(?:>>?|<<?<?|>&|<&|>\||<>)$/.test(w) && i + 1 < line.length) {
      if (shape !== undefined ? shape[i + 1] !== 'none' : isRedirection(line[i + 1]!)) return null;
      out.add(++i);
    }
  }
  return out;
}

/** Walks the options of one command under the grammar of its tool. Returns null as soon as it meets an option it does
 *  not know: from there on the line is not read. */
function scan(line: readonly string[], from: number, g: OptionGrammar, shape?: readonly OperatorShape[]): Scan | null {
  const roles: WordRole[] = line.map((_, i) => (i < from ? 'head' : 'operand'));
  const glued = new Map<number, number>();
  const noPattern = (g.noPatternLong ?? []).some((n) => line.slice(from).includes(`--${n}`));
  const redirected = redirectionWords(line, from, shape);
  if (redirected === null) return null;
  let supplied = false;
  let ended = false;
  for (let i = from; i < line.length; i++) {
    const w = line[i]!;
    // a redirection is not an operand of the command: `grep > out pattern file` has its pattern after the operator's target
    if (redirected.has(i)) {
      roles[i] = 'option';
      continue;
    }
    if (ended || w === '-' || !w.startsWith('-')) {
      if (!supplied && g.positionalPattern && !noPattern) {
        roles[i] = 'data';
        supplied = true;
      }
      continue;
    }
    roles[i] = 'option';
    if (w === '--') {
      ended = true;
      continue;
    }
    if (w.startsWith('--')) {
      const eq = w.indexOf('=');
      const name = eq < 0 ? w.slice(2) : w.slice(2, eq);
      const isData = g.dataLong.includes(name);
      if (isData || g.valueLong.includes(name)) {
        if (g.suppliesLong.includes(name)) supplied = true;
        if (eq >= 0) {
          if (isData) {
            roles[i] = 'data';
            glued.set(i, eq + 1);
          }
        } else {
          if (i + 1 >= line.length) return null;
          roles[++i] = isData ? 'data' : 'value';
        }
        continue;
      }
      if (g.flagLong.includes(name)) continue;
      return null;
    }
    for (let k = 1; k < w.length; k++) {
      const c = w[k]!;
      const isData = g.dataShort.includes(c);
      if (isData || g.valueShort.includes(c)) {
        if (g.suppliesShort.includes(c)) supplied = true;
        if (k + 1 < w.length) {
          // the value is the rest of the cluster
          if (isData) {
            roles[i] = 'data';
            glued.set(i, k + 1);
          }
        } else {
          if (i + 1 >= line.length) return null;
          roles[++i] = isData ? 'data' : 'value';
        }
        break;
      }
      if (g.flagShort.includes(c)) continue;
      if (g.digitContext === true && /[0-9]/.test(c)) continue;
      return null;
    }
  }
  return { roles, glued };
}

/* ------------------------------------------------------------------------------------------------------------- *
 * git
 * ------------------------------------------------------------------------------------------------------------- */

const GIT_GLOBAL_VALUE = /^(-C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--attr-source)$/;
const GIT_GLOBAL_FLAG =
  /^(--no-pager|-p|--paginate|-P|--bare|--no-replace-objects|--literal-pathspecs|--glob-pathspecs|--noglob-pathspecs|--icase-pathspecs|--no-optional-locks|--no-lazy-fetch|--no-advice|--exec-path|--html-path|--man-path|--info-path)$/;

/** Where the git VERB is, after git's global options; -1 when an option nobody listed stands in front of it. */
function gitVerbAt(line: readonly string[], at: number): number {
  let i = at + 1;
  for (; i < line.length; i++) {
    const w = line[i]!;
    if (!w.startsWith('-')) return i;
    if (w.includes('=') || GIT_GLOBAL_FLAG.test(w)) continue;
    if (GIT_GLOBAL_VALUE.test(w)) {
      i++;
      continue;
    }
    if (/^-C./.test(w) || /^-c./.test(w)) continue;
    return -1;
  }
  return -1;
}

/** `git log`, `diff` and `show` take their search strings in options: `-S<string>`, `-G<regex>`, `--grep=<pattern>`,
 *  `--author=`, `--committer=`. Only those words are read; every other word of the line keeps the role it had. */
const GIT_PICKAXE_VERBS = new Set(['log', 'show', 'diff', 'whatchanged', 'rev-list', 'shortlog']);
function scanPickaxe(line: readonly string[], from: number): Scan {
  const roles: WordRole[] = line.map((_, i) => (i < from ? 'head' : 'unread'));
  const glued = new Map<number, number>();
  for (let i = from; i < line.length; i++) {
    const w = line[i]!;
    if (w === '--') break;
    if (w === '-S' || w === '-G' || w === '--grep' || w === '--author' || w === '--committer') {
      if (i + 1 < line.length) roles[++i] = 'data';
    } else if (/^-[SG]./.test(w)) {
      roles[i] = 'data';
      glued.set(i, 2);
    } else {
      const m = /^--(grep|author|committer)=/.exec(w);
      if (m) {
        roles[i] = 'data';
        glued.set(i, m[0].length);
      }
    }
  }
  return { roles, glued };
}

/** The message options of the git verbs that take one. `-m` is the message for these and a parent NUMBER for `revert` and
 *  `cherry-pick`, which are therefore not here. A cluster may carry it (`-am MSG`, `-nm MSG`): the letters in front of it
 *  must be the verb's flags, because a letter that takes a value (`-C COMMIT`, `-F FILE`) makes the rest of the word its. */
const GIT_MESSAGE_VERBS: Record<string, string> = {
  commit: 'aiopnsqvezN',
  tag: 'afsdlv',
  merge: 'qnve',
  stash: 'aukq',
  notes: 'f',
};
function scanMessage(line: readonly string[], from: number, flags: string): Scan {
  const roles: WordRole[] = line.map((_, i) => (i < from ? 'head' : 'unread'));
  const glued = new Map<number, number>();
  for (let i = from; i < line.length; i++) {
    const w = line[i]!;
    if (w === '--') break;
    if (w === '--message') {
      if (i + 1 < line.length) roles[++i] = 'data';
    } else if (w.startsWith('--message=')) {
      roles[i] = 'data';
      glued.set(i, '--message='.length);
    } else if (/^-[A-Za-z]+$/.test(w) && !w.startsWith('--')) {
      const m = w.indexOf('m', 1);
      if (m < 0) continue;
      // every letter in front of the `m` must be a flag of the verb, or the cluster's value is something else
      if (![...w.slice(1, m)].every((c) => flags.includes(c))) continue;
      if (m + 1 < w.length) {
        roles[i] = 'data';
        glued.set(i, m + 1);
      } else if (i + 1 < line.length) roles[++i] = 'data';
    }
  }
  return { roles, glued };
}

/* ------------------------------------------------------------------------------------------------------------- *
 * the one reader
 * ------------------------------------------------------------------------------------------------------------- */

/** The role of every word of one command, or null when the head is not a tool this file has a grammar for, or the line
 *  has an option that grammar does not list. `at` is where the head stands in `line` (a wrapper or an assignment may be in
 *  front of it); every word in front of it has the role `head`. */
export function wordRoles(line: readonly string[], at = 0, shape?: readonly OperatorShape[]): Scan | null {
  const raw = line[at];
  if (raw === undefined) return null;
  const head = trustedName(raw);
  if (head === null) return null;
  if (GREP_HEADS.has(head)) return scan(line, at + 1, GREP, shape);
  if (head === 'rg' || head === 'ripgrep') return scan(line, at + 1, RIPGREP, shape);
  if (head === 'pgrep') return scan(line, at + 1, PGREP, shape);
  if (PRINTERS.has(head)) {
    // `echo -n -e text`: the leading options are echo's; everything from the first word that is not one is printed
    const redirected = redirectionWords(line, at + 1, shape);
    if (redirected === null) return null;
    const roles: WordRole[] = line.map((_, i) => (i <= at ? 'head' : 'data'));
    let i = at + 1;
    while (i < line.length && (head === 'echo' ? /^-[neE]+$/.test(line[i]!) : line[i] === '--')) roles[i++] = 'option';
    for (const r of redirected) roles[r] = 'option';
    return { roles, glued: new Map() };
  }
  if (head === 'git') {
    const v = gitVerbAt(line, at);
    if (v < 0) return null;
    const verb = line[v]!;
    if (verb === 'grep') return scan(line, v + 1, GIT_GREP, shape);
    // (a line whose words may be redirections is not read for a message or a pickaxe either: see redirectionWords)
    const pickaxe = GIT_PICKAXE_VERBS.has(verb);
    const flags = GIT_MESSAGE_VERBS[verb];
    if ((pickaxe || flags !== undefined) && redirectionWords(line, v + 1, shape) === null) return null;
    if (pickaxe) return scanPickaxe(line, v + 1);
    if (flags !== undefined) return scanMessage(line, v + 1, flags);
  }
  return null;
}

/** `sudo`/`doas`: their own options, then the command. Returns where the command starts, or -1. */
function privilegedCommandAt(line: readonly string[], at: number): number {
  let i = at + 1;
  while (i < line.length) {
    const t = line[i]!;
    if (t === '--') return i + 1;
    if (!t.startsWith('-')) return i;
    i += /^(-u|-g|-p|-C|-h|-U|-r|-t|-D|--user|--group|--prompt|--host|--role|--type|--chdir|--close-from)$/.test(t) ? 2 : 1;
  }
  return -1;
}

/** xargs and parallel: the options that take the NEXT word. The command starts at the first word that is not one of them. */
export const XARGS_VALUE_OPTS = /^(-n|-L|-P|-s|-E|-d|-a|--max-args|--max-procs|--delimiter|--arg-file|-j|--jobs)$/;
function xargsCommandAt(line: readonly string[], at: number): number {
  for (let i = at + 1; i < line.length; i++) {
    const t = line[i]!;
    if (!t.startsWith('-')) return i;
    // -I R / -J R take the placeholder; `--replace=R` and `-iR` carry it; the others consume their value
    if (/^(-I|-J)$/.test(t) || XARGS_VALUE_OPTS.test(t)) i++;
  }
  return -1;
}

/** The spans `find` and `fd` hand to a command: the words between `-exec` and its terminator. */
function execSpans(line: readonly string[], at: number): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  const starts = baseName(line[at] ?? '') === 'find' ? /^(-exec|-execdir|-ok|-okdir)$/ : /^(-x|--exec|-X|--exec-batch)$/;
  for (let i = at + 1; i < line.length; i++) {
    if (!starts.test(line[i]!)) continue;
    let j = i + 1;
    while (j < line.length && line[j] !== ';' && line[j] !== '\\;' && line[j] !== '+') j++;
    out.push([i + 1, j]);
    i = j;
  }
  return out;
}

/** The words of `line` with every DATA word replaced by `placeholder`, looking through the carriers that hand a command on
 *  (`sudo`, `xargs`, `parallel`, `find -exec`, `fd -x`). A word glued to its option keeps the option: `--grep=hook` becomes
 *  `--grep=<placeholder>`. A line the grammar cannot read is returned as it came. */
export function maskDataWords(line: readonly string[], placeholder: string, shape?: readonly OperatorShape[]): string[] {
  const out = [...line];
  const apply = (from: number, to: number): void => {
    const slice = out.slice(from, to);
    const masked = maskOne(slice, placeholder, 0, shape?.slice(from, to));
    for (let k = 0; k < masked.length; k++) out[from + k] = masked[k]!;
  };
  // the head: skip leading assignments, as the command starts after them
  let at = 0;
  while (at < out.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(out[at]!)) at++;
  const head = trustedName(out[at] ?? '');
  if (head === 'sudo' || head === 'doas') {
    const c = privilegedCommandAt(out, at);
    if (c >= 0) apply(c, out.length);
  } else if (head === 'xargs' || head === 'parallel') {
    const c = xargsCommandAt(out, at);
    if (c >= 0) apply(c, out.length);
  } else if (head === 'find' || head === 'fd' || head === 'fdfind') {
    for (const [from, to] of execSpans(out, at)) apply(from, to);
  } else {
    const masked = maskOne(out, placeholder, at, shape);
    for (let k = 0; k < masked.length; k++) out[k] = masked[k]!;
  }
  return out;
}

function maskOne(line: readonly string[], placeholder: string, at = 0, shape?: readonly OperatorShape[]): string[] {
  const s = wordRoles(line, at, shape);
  if (s === null) return [...line];
  return line.map((w, i) => {
    // (an UNQUOTED word with a redirection operator in it is a redirection, wherever the grammar put it: see redirectionWords)
    if (s.roles[i] !== 'data' || (shape !== undefined && shape[i] === 'real')) return w;
    const cut = s.glued.get(i);
    return cut === undefined ? placeholder : w.slice(0, cut) + placeholder;
  });
}

/** Where the values of the `find` predicates that take a NAME or a PATTERN stand: `find . -name claude` looks for files,
 *  and the word after `-name` is never a program. A value after `-exec` is not here. */
export function findPredicateValues(line: readonly string[], at: number): Set<number> {
  const out = new Set<number>();
  if (baseName(line[at] ?? '') !== 'find') return out;
  for (let i = at + 1; i < line.length - 1; i++)
    if (/^-(name|iname|path|ipath|wholename|iwholename|regex|iregex|lname|ilname|samefile|newer|user|group|perm|type|fstype|size|mtime|atime|ctime|mmin|amin|cmin|maxdepth|mindepth)$/.test(line[i]!))
      out.add(++i);
  return out;
}
