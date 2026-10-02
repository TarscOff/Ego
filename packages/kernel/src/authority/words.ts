// THE WORD A SHELL HANDS A PROGRAM, KEPT WHOLE (closure audit 2026-10-02, wave 6, PA-03).
//
// The normalizer takes a segment apart into word VALUES - the quoting gone - and puts them back together as text for the matchers
// and the path readers (`touch 'a"b/pre-commit'` becomes `touch a"b/pre-commit`). The text is right for a matcher, which looks for a
// program and a flag, and wrong for a reader that tokenizes it again: the quote in the value opens a string that swallows the rest,
// a backslash is dropped, `<` and `>` start a redirection. The path that reader judges is then another, ordinary one (`ab/pre-commit`)
// while the shell opens a link called `a"b` that leads into .git/hooks. A hostile repository chooses the names of the links it ships,
// and git clones them, so every writer of the line was ALLOW for a write into the hooks, ~/.ssh, .claude and control-plane.
//
// The text is NOT changed for the matchers: they expect the words as they always read, and quoting the value of `--author="A <a@b>"`
// hid the option from the rule that names it (measured). The path readers get a TWIN of it: the same words, with each of the words
// whose value would be read differently the second time put back inside quotes, so that tokenizing it returns exactly the words the
// shell passed. The words come from the segment AS WRITTEN, where the quoting still exists; a word is replaced in one pass, longest
// first, so a quote that was just put back is never taken for one to put back.

/** `w` as one single-quoted shell word */
export function singleQuoted(w: string): string {
  return `'${w.replace(/'/g, `'\\''`)}'`;
}

const escapeRe = (s: string): string => s.replace(/[\\^$.*+?()[\]{}|/-]/g, '\\$&');

/** How many distinct hostile words one segment may carry before the rest are left as they were (a bound on the expression, not on the
 *  verdict: a segment with that many is asked about anyway, for being larger than any command anyone types). */
const MAX_HOSTILE_WORDS = 64;

/**
 * `text` with every occurrence of each of `values` put back inside single quotes. A value occurs in the normalized text exactly as the
 * normalizer joined it, so the replacement is a substring replacement; whatever it lands inside keeps its value (`x'a"b'y` is `xa"by`).
 */
export function restoreQuoting(text: string, values: readonly string[]): string {
  const hostile = [...new Set(values.filter((v) => v !== '' && text.includes(v)))]
    .sort((a, b) => b.length - a.length)
    .slice(0, MAX_HOSTILE_WORDS);
  if (hostile.length === 0) return text;
  const re = new RegExp(hostile.map(escapeRe).join('|'), 'g');
  return text.replace(re, (m) => singleQuoted(m));
}

/** THE PIECES THE TEXT READERS MAKE OF ONE WORD'S VALUE: they split the text at its blanks, and an angle bracket in it begins a redirection whose
 *  target is what follows. `cp x 'a b'/../'a<b'/f` is the words `a`, `b/../a` and (a source) `b/f` to the reader that found the destination, so the
 *  destination it names is one of these and the word is the destination as a whole (found by the filesystem oracle). */
export function textPieces(value: string): string[] {
  return value.split(/[ \t\n<>]+/).filter(Boolean);
}
