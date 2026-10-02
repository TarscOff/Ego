// WHERE A COMMAND'S OPERANDS COME FROM (closure audit 2026-10-02, wave 6, PA-01).
//
// Every reader of paths in the evaluator reads WORDS: the operand is a word of the command line. It is not always. `echo ~/.ssh/id_rsa |
// xargs cat`, `echo ~/.ssh/id_rsa | while read f; do cat "$f"; done` and `cat $(echo ~/.ssh/id_rsa)` read a credential store, and the word
// that names it is on another command's standard output - which the path readers skip, because `echo` and `printf` PRINT their operands
// and a look is not an act. That masking is right for the text matchers, and it removed the one accident that used to catch these (the
// matcher saw `~/.ssh` inside the echo segment). `echo cat ~/.ssh/id_rsa | sh` was still refused, because a pipe into a shell is read as an
// execution edge; the pipe into `xargs`, the read loop and the substitution are its siblings, and nothing read them.
//
// The rule is one: THE OPERANDS OF A COMMAND ARE THE WORDS IT IS GIVEN, WHEREVER THEY WERE PRODUCED.
//   - a producer whose output is KNOWN (`echo`, `printf`, `cat <<<`, `cat FILE` of a file in the workspace) hands over words, and the
//     consumer is judged as the command it is with those words as its operands - by the same readers, as a command that spells them;
//   - a producer that LISTS paths (`find`, `ls`, `git ls-files`) names things it has itself been allowed to look at, and the consumer is
//     judged as it always was;
//   - any other producer hands over something nobody here can read, and a consumer that opens its operands as files asks.
//
// This module is the pure part: which text a substitution leaves, how produced words are split the way their consumer splits them, and
// which producers and consumers are which. The analyzer (evaluate.ts) holds the stages and runs the judgement.
import { homedir } from 'node:os';
import { FILE_OPERAND_READERS } from './operands.ts';

/** where each `$SUBST` the splitter left stands in `text`, outside single quotes, and whether it is inside double quotes */
export function substitutionSites(text: string): Array<{ at: number; quoted: boolean }> {
  const out: Array<{ at: number; quoted: boolean }> = [];
  let single = false;
  let double = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '\\' && !single) {
      i++;
      continue;
    }
    if (c === "'" && !double) single = !single;
    else if (c === '"' && !single) double = !double;
    else if (!single && c === '$' && text.startsWith('$SUBST', i)) {
      out.push({ at: i, quoted: double });
      i += '$SUBST'.length - 1;
    }
  }
  return out;
}

/** a produced word as text the shell reads back as that word: the characters that would end it, start a quote or a substitution are escaped;
 *  `*`, `?`, `[`, `~` and a plain `$NAME` are left, because the consumer's own readers expand them and an expansion can only add a reading.
 *
 *  THE HOME DIRECTORY IS WRITTEN AS `~` AGAIN. The producer's words reach here with `~` and `$HOME` already replaced by the machine's directory (the
 *  readers of a producer expand them), and the consumer is analysed as a command LINE of that text: the same line, spelled with the machine's
 *  directory, costs as many units as the directory has characters, which made the price of `echo ~/.ssh/id_rsa | xargs cat` depend on where the
 *  machine keeps HOME (RB-7). The consumer's readers expand `~` to the very same directory, so the path they judge is the one they judged. */
export function producedWord(w: string): string {
  const home = homedir().replace(/\/+$/, '');
  const word = home !== '' && (w === home || w.startsWith(`${home}/`)) ? `~${w.slice(home.length)}` : w;
  return word.replace(/[\s'"\\;&|<>(){}`!#]/g, '\\$&').replace(/\$(?![A-Za-z_])/g, '\\$');
}

/** the text of a substitution as the shell leaves it: trailing newlines are removed; split into words when it stands unquoted */
export function substitutionWords(output: string): string[] {
  return output.replace(/\n+$/, '').split(/[ \t\n]+/).filter((w) => w !== '');
}

/**
 * `text` with the substitutions whose output is KNOWN replaced by that output (null at an index: unknown, left as the marker). Null when
 * nothing was replaced. An unquoted site becomes the words, each as one word; a quoted site becomes the text, inside the quotes it stood in.
 */
export function foldSubstitutions(text: string, outputs: ReadonlyArray<string | null>): string | null {
  const sites = substitutionSites(text);
  let out = '';
  let from = 0;
  let any = false;
  sites.forEach((site, k) => {
    const known = outputs[k];
    out += text.slice(from, site.at);
    from = site.at + '$SUBST'.length;
    if (known === null || known === undefined) {
      out += '$SUBST';
      return;
    }
    any = true;
    out += site.quoted ? known.replace(/\n+$/, '').replace(/[\\"$`]/g, '\\$&') : substitutionWords(known).map(producedWord).join(' ');
  });
  return any ? out + text.slice(from) : null;
}

/** The ways the consumer of a produced text may cut it into operands: on blanks, on lines, and as quoted words (xargs reads quotes). Every
 *  reading is judged, so an operand is never judged as a piece of another. */
export function operandReadings(output: string): string[][] {
  const text = output.replace(/\n+$/, '');
  const readings: string[][] = [];
  const add = (words: string[]): void => {
    const key = JSON.stringify(words);
    if (words.length > 0 && !readings.some((r) => JSON.stringify(r) === key)) readings.push(words);
  };
  add(text.split(/[ \t\n]+/).filter((w) => w !== ''));
  add(text.split(/\n|\0/).filter((w) => w !== ''));
  // (xargs without -0 reads quotes and backslashes: `'a b'` is the one operand `a b`)
  add(
    [...text.matchAll(/'([^']*)'|"((?:[^"\\]|\\.)*)"|((?:[^\s'"\\]|\\.)+)/g)].map((m) => (m[1] ?? m[2] ?? m[3] ?? '').replace(/\\(.)/g, '$1')),
  );
  return readings.slice(0, 4);
}

/* ------------------------------------------------------------------------------------------------------------- *
 * Which producer is which
 * ------------------------------------------------------------------------------------------------------------- */

/** Heads whose output is a list of NAMES of things that exist - or a fact about the machine - and not text somebody wrote: the consumer
 *  of such a list reads what the producer was itself allowed to look at. (`git` is by verb, below.) */
const LISTERS: ReadonlySet<string> = new Set(
  ('find fd fdfind ls tree du pwd which type whereis dirname basename realpath readlink date seq whoami id uname hostname nproc ps pgrep jobs ' +
    'locate mdfind stat df uptime').split(' '),
);
/** git verbs that list paths, refs or facts about the repository */
const GIT_LISTERS = /^(ls-files|ls-tree|diff|diff-tree|diff-index|diff-files|status|rev-parse|rev-list|branch|tag|describe|show-ref|for-each-ref|log|shortlog|remote|stash|worktree|cat-file|grep|blame|merge-base|name-rev)$/;
/** Heads that hand on a SUBSET of their standard input, in some order, unchanged: what they hand on is made of what they were handed. (`tr`, `sed`,
 *  `cut` and `awk` make something else of it, and what they hand on is not.) */
const FILTERS: ReadonlySet<string> = new Set('head tail sort uniq rev nl tac tee cat grep egrep fgrep'.split(' '));

/** the head of a command (a path stripped), after `sudo`-like wrappers have been taken off by the caller */
const headOf = (words: readonly string[]): string => (words[0] ?? '').replace(/^.*\//, '');

/** Does this command LIST names (see LISTERS)? `grep -l` and `rg -l` list the files that match. */
export function listsPaths(words: readonly string[]): boolean {
  const head = headOf(words);
  if (head === 'git') {
    const verb = words.slice(1).find((w) => !w.startsWith('-') && !/[=/]/.test(w) && w !== 'HEAD');
    return verb !== undefined && GIT_LISTERS.test(verb);
  }
  if (/^(grep|egrep|fgrep|rg|ag|ack)$/.test(head)) return words.some((w) => /^-[A-Za-z]*[lL]$/.test(w) || w === '--files-with-matches' || w === '--files-without-match' || w === '--files');
  return LISTERS.has(head);
}

/** Does this command only pass its input through? (`head -1`, `sort`, `grep foo` with no file operand: what it hands on is what it was handed.) */
export function passesInputThrough(words: readonly string[]): boolean {
  const head = headOf(words);
  if (!FILTERS.has(head)) return false;
  // `tee FILE` writes the copy to its operands and hands the original on
  if (head === 'tee') return true;
  // a file operand makes it a READER of that file, and its output is the file's
  const operands = words.slice(1).filter((w) => !w.startsWith('-'));
  const expected = /^(grep|egrep|fgrep)$/.test(head) ? 1 : 0;
  return operands.length <= expected;
}

/** Does this command open its operands as FILES (operands.ts)? The consumer of a produced list that asks when the list is unreadable. */
export function readsOperandsAsFiles(words: readonly string[]): boolean {
  const head = headOf(words);
  return FILE_OPERAND_READERS.has(head);
}
