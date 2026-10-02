// CHANNEL INTEGRITY: TEXT THAT IS NOT EGO'S, SHOWN IN EGO'S VOICE (closure audit 2026-10-02, AUTH-6; the twelfth class).
//
// EGO speaks to two readers it does not control the input of: the model (SessionStart and UserPromptSubmit context, the reason of
// a refusal) and a person (doctor, init, the y/N question, the host's permission dialog). Both read EGO's words as EGO's. And some
// of the words EGO prints are not its own: an entry of a layer file that arrived in a teammate's commit, a name from a repository
// file, a command line, a tool input, a branch name, a statement. The local-target path was hardened so that repository text was
// printed as one token of a bounded grammar; every other string was printed raw, so a layer entry holding an ESC byte and a
// sentence could clear the confirmation line a person was about to answer, and a sentence in a matcher pattern was read by the
// model as an instruction from the kernel. No verdict is affected; the CHANNEL is.
//
// The property is not "this string was cleaned" but "text that is not EGO's is only ever shown AS DATA": quoted, so a reader can
// see where it starts and stops; on one line, so it cannot open a line of its own that reads as EGO's; bounded, so it cannot
// bury the line it sits in; and with every character that a terminal or a model reads as something other than a glyph turned into
// a visible escape. Two functions, because there are two things to guarantee:
//
//   - `shownText(untrusted)`: the quoting for a STRING THAT IS DATA inside a sentence EGO writes. The one function; a place that
//     renders text from a layer file, a repository file, a command line, a tool input, a branch or file name, or a reason that
//     embeds one calls it (the structural test in closure-authority2.test.ts finds the places that do not).
//   - `terminalSafe(text)`: the BOUNDARY, applied once where text leaves the kernel (the CLI's output, the hook adapters, the
//     y/N prompt). It keeps the newlines EGO itself writes and turns every other control character, escape sequence introducer
//     and invisible formatting character into a visible escape, whatever the text's origin - so a path that was never judged to
//     be untrusted cannot move the cursor either.
//
// This module is dependency-free on purpose: it is imported by the compiler, the cache, the hook and the CLI. The ranges below are
// NUMBERS, not a pattern with the characters written into it: a source file that holds a raw U+2028 does not parse, and one that
// holds a raw ESC cannot be reviewed.

/** The longest piece of foreign text one `shownText` shows: enough to recognise a pattern, not enough to hold an argument. */
export const SHOWN_MAX = 120;

/**
 * Code points that are not glyphs to a terminal or a model, as inclusive ranges: the C0 controls and DEL, the C1 controls (the
 * 8-bit CSI among them), the soft hyphen, the Hangul and Braille fillers, the Mongolian and Khmer invisible characters, the
 * zero-width and directional marks (U+200B..U+200F), the line and paragraph separators and the bidirectional embeddings and
 * overrides (U+2028..U+202E), the word joiner and the invisible operators and isolates (U+2060..U+206F), variation selectors,
 * the byte-order mark, the specials, the invisible musical formatting characters and the language-tag block, and any lone
 * surrogate (a pair arrives as one astral code point).
 */
const NON_GLYPH_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x001f],
  [0x007f, 0x009f],
  [0x00ad, 0x00ad],
  [0x034f, 0x034f],
  [0x061c, 0x061c],
  [0x115f, 0x1160],
  [0x17b4, 0x17b5],
  [0x180b, 0x180e],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x206f],
  [0x2800, 0x2800],
  [0x3164, 0x3164],
  [0xd800, 0xdfff],
  [0xfe00, 0xfe0f],
  [0xfeff, 0xfeff],
  [0xffa0, 0xffa0],
  [0xfff0, 0xffff],
  [0x1bca0, 0x1bca3],
  [0x1d173, 0x1d17a],
  [0xe0000, 0xe0fff],
];

const isNonGlyph = (cp: number): boolean => NON_GLYPH_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);

/** U+0085 is whitespace to a terminal and not to `\s`; U+2028 and U+2029 are both. */
const isSpace = (ch: string): boolean => ch.codePointAt(0) === 0x85 || /\s/u.test(ch);

const escapeOne = (cp: number): string =>
  cp <= 0xff ? `\\x${cp.toString(16).padStart(2, '0')}` : `\\u{${cp.toString(16)}}`;

/** One reading of foreign text on ONE line: whitespace runs are one space, non-glyphs are their visible escape, past `max` characters it is cut.
 *  `quote` additionally escapes the backslash and the quote (the caller wraps the result in quotes). */
function flatten(untrusted: unknown, max: number, quote: boolean): { text: string; left: number } {
  const source = typeof untrusted === 'string' ? untrusted : String(untrusted);
  let out = '';
  let used = 0;
  let left = 0;
  let space = false;
  for (const ch of source) {
    if (isSpace(ch)) {
      space = out.length > 0 || left > 0;
      continue;
    }
    const cp = ch.codePointAt(0)!;
    const glyph = quote && ch === '\\' ? '\\\\' : quote && ch === '"' ? '\\"' : isNonGlyph(cp) ? escapeOne(cp) : ch;
    const piece = (space ? ' ' : '') + glyph;
    space = false;
    if (left > 0 || used + piece.length > max) {
      left += 1;
      continue;
    }
    out += piece;
    used += piece.length;
  }
  return { text: out, left };
}

const more = (left: number): string => (left > 0 ? ` (+${left} more character${left === 1 ? '' : 's'})` : '');

/**
 * TEXT THAT IS NOT EGO'S, AS DATA INSIDE A SENTENCE EGO WRITES: `"…"`, one line, escaped, bounded.
 *
 *   - any run of whitespace (a newline included) is ONE space, so the text cannot start a line of its own;
 *   - a backslash and a quote are escaped, so the text cannot close the quotes it sits in and the escapes below are unambiguous;
 *   - every control character, escape-sequence introducer, bidirectional override and invisible formatting character is its
 *     visible escape (`\x1b`, `\u{202e}`): an ANSI or OSC sequence is inert text, because the ESC that makes it one is gone;
 *   - past `max` characters it is cut and says how much was left out, so it cannot bury what follows it.
 */
export function shownText(untrusted: unknown, max: number = SHOWN_MAX): string {
  const { text, left } = flatten(untrusted, max, true);
  return `"${text}"${more(left)}`;
}

/**
 * THE SAME READING WITHOUT THE QUOTES, for a field that already says what it holds (`target: …`, `effect: …` of an approval prompt, the
 * reason of a refusal): on one line, escaped, bounded - and never longer than `max`, which defaults to no bound.
 */
export function flatText(untrusted: unknown, max: number = Number.POSITIVE_INFINITY): string {
  const { text, left } = flatten(untrusted, max, false);
  return `${text}${more(left)}`;
}

/**
 * A NAME OF A BOUNDED GRAMMAR IS PRINTED AS IT IS; ANYTHING ELSE IS QUOTED DATA. The local-target registry takes names of letters, digits and
 * `_ . : @ / * -`; a name it refused because it is not one (it holds a quote, a space, an escape, a paragraph) is shown through `shownText`.
 * ONE function, so `ego init` and `ego doctor` cannot print the same refused name two ways.
 */
export function shownToken(name: unknown, max = 80): string {
  const text = typeof name === 'string' ? name : String(name);
  return text.length >= 1 && text.length <= max && /^[A-Za-z0-9_.:@/*-]+$/.test(text) ? text : shownText(text, max);
}

/** The first `limit` of a list of foreign strings, each `shownText`, then how many were left out. */
export function shownList(items: readonly unknown[], limit = 3, max: number = SHOWN_MAX): string {
  const head = items.slice(0, limit).map((x) => shownText(x, max));
  return items.length > limit ? `${head.join('; ')}; (+${items.length - limit} more)` : head.join('; ');
}

/**
 * THE BOUNDARY: what may leave the kernel as text for a terminal or a host. The newlines and tabs EGO writes itself are kept;
 * every other control character, every escape-sequence introducer, every bidirectional override and every invisible character
 * becomes its visible escape. It does not quote or bound anything (that is `shownText`'s job, at the place the foreign text is
 * embedded), and it is idempotent: its output contains nothing it would change.
 */
export function terminalSafe(text: string): string {
  let out = '';
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    out += (cp === 0x0a || cp === 0x09 || !isNonGlyph(cp)) ? ch : escapeOne(cp);
  }
  return out;
}
