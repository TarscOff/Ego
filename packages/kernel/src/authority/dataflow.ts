// THE PLAN FOR A STAGE WHOSE OPERANDS ARE PRODUCED BY ANOTHER COMMAND (closure audit 2026-10-02, wave 6, PA-01; the rule is in flow.ts).
//
// Three places take a command's operands off another command's output: a pipe into `xargs`, a read loop (`… | while read f; do cat
// "$f"; done`), and a command substitution (`cat $(echo ~/.ssh/id_rsa)`). For each, the plan is the same:
//   - the producer's output is KNOWN: the consumer is judged again, as the command it is with those words in place. The judging is the
//     analyzer's - this returns the command lines to judge;
//   - the producer LISTS paths, or the consumer does not open its operands as files: nothing is added;
//   - the producer is anything else and the consumer opens its operands as files: the plan says so, and the analyzer asks.
//
// Nothing here reads the disk or classifies. The analyzer hands in the readers it owns (`FlowReaders`), which keeps this module free of
// the evaluator and the evaluator free of one more block of its own.
import { foldSubstitutions, listsPaths, operandReadings, passesInputThrough, producedWord, readsOperandsAsFiles, substitutionSites } from './flow.ts';
import { wordRoles } from './operands.ts';

/** What a command leaves on its standard output, as far as anyone here can tell. */
export type Produced =
  | { kind: 'none' }
  | { kind: 'literal'; text: string; stale?: boolean }
  | { kind: 'listing' }
  | { kind: 'unknown' };

export interface FlowReaders {
  /** the exact text a command writes to standard output (echo, printf, a here-string, a heredoc), or null (literalStdout) */
  literal(text: string, heredoc?: { body: string; expanded: boolean }): string | null;
  /** the text of the files `cat FILE…` prints, when each is a file the analyzer may read; `stale` when something on this line may write one of them
   *  before it is read (an earlier stage, or a stage that runs beside it in the pipeline): the text is then what the file holds NOW */
  fileContent(text: string): { text: string; stale: boolean } | null;
  /** the words of a command with the wrappers (`env`, `time`, `sudo`) taken off */
  words(text: string): string[];
  /** a command text split into its stages */
  stages(text: string): Array<{ text: string; pipedFromPrevious: boolean; heredocBody?: string; heredocExpanded?: boolean }>;
  /** the files a command opens for input (`< f`), when each is a plain name */
  inputFiles(text: string): string[];
  /** the content of a file the analyzer may read, or null; see `fileContent` for `stale` */
  fileText(name: string): { text: string; stale: boolean } | null;
  /** an `xargs` stage: the command it runs as written, the placeholder it names, the file it reads its arguments from, the here-string
   *  (`<<< WORD`) it is fed; null when not xargs */
  xargs(text: string): { payload: string; placeholder: string | null; argFile: string | null; hereString?: { body: string; expanded: boolean } | null } | null;
  /** `$NAME` replaced by a value, outside single quotes */
  substitute(text: string, vars: ReadonlyMap<string, string>): string;
  /** a text with its braces expanded */
  expand(text: string): string;
  /** the names a `read` stage binds, or null when the stage is not one */
  readNames(text: string): string[] | null;
}

export const NO_OUTPUT: Produced = { kind: 'none' };
const NONE = NO_OUTPUT;

/** What the commands of one GROUP (`{ a; b; } | c`) hand on together: their outputs one after the other. A command nobody can read makes the
 *  whole unreadable; known text beats a list of names, which adds nothing the consumer does not already see. */
export function combineProduced(a: Produced, b: Produced): Produced {
  if (a.kind === 'none') return b;
  if (b.kind === 'none') return a;
  if (a.kind === 'unknown' || b.kind === 'unknown') return { kind: 'unknown' };
  if (a.kind === 'literal' && b.kind === 'literal') return { kind: 'literal', text: `${a.text}\n${b.text}`, stale: a.stale === true || b.stale === true };
  return a.kind === 'literal' ? a : b.kind === 'literal' ? b : a;
}

/** What ONE stage hands on, given what it was handed. */
export function producedBy(r: FlowReaders, text: string, stdin: Produced, heredoc?: { body: string; expanded: boolean }): Produced {
  const printed = r.literal(text, heredoc);
  if (printed !== null) return { kind: 'literal', text: printed };
  const file = r.fileContent(text);
  if (file !== null) return { kind: 'literal', text: file.text, stale: file.stale };
  const words = r.words(text);
  if (listsPaths(words)) return { kind: 'listing' };
  if (passesInputThrough(words) && stdin.kind !== 'none') return stdin;
  return { kind: 'unknown' };
}

/** What a whole command (the body of a substitution: possibly a pipeline) hands on. */
export function producedByCommand(r: FlowReaders, body: string): Produced {
  let last: Produced = NONE;
  for (const st of r.stages(body))
    last = producedBy(r, st.text, st.pipedFromPrevious ? last : NONE, st.heredocBody === undefined ? undefined : { body: st.heredocBody, expanded: st.heredocExpanded === true });
  return last;
}

export interface FlowPlan {
  /** command lines (each a list of segments, analysed together) to judge IN ADDITION to the stage as written */
  variants: string[][];
  /** why the stage asks: an operand it opens as a file comes from a command nobody here can read */
  asks: string[];
}

const EMPTY: FlowPlan = { variants: [], asks: [] };
const STALE = 'the list this stage reads its operands from may be rewritten on this line before it is read';
/** a file a stage reads its operands from: its text, or nothing anybody can read */
function fromFile(r: FlowReaders, name: string): Produced {
  const t = r.fileText(name);
  return t === null ? { kind: 'unknown' } : { kind: 'literal', text: t.text, stale: t.stale };
}
/** how many alternatives one produced text may add: a produced list is a few words, and a bound is a question, not an absence */
const MAX_WORDS = 64;

/** the heads whose first operand is a pattern, not a file - the reading of a line the role reader (operands.ts) cannot place (an option nobody listed) */
const PATTERN_FIRST = /^(grep|egrep|fgrep|zgrep|rg|ag|ack)$/;

/** Tokens of a stage that carry a `$SUBST` and are operands (not options, not a search pattern) of a command that opens operands as files.
 *  WHICH WORD IS THE PATTERN is the role reader's answer (operands.ts `wordRoles`, read leniently as the path scan reads a search tool): the
 *  reader that says it of `grep -A 3 PATTERN FILE` and `grep -e PATTERN FILE` for every other reader of the words of a line. Only a line it
 *  cannot place keeps the reading below (the first word that is not an option). */
function substitutedOperands(words: readonly string[]): number[] {
  if (!readsOperandsAsFiles(words)) return [];
  const head = (words[0] ?? '').replace(/^.*\//, '');
  const roles = wordRoles(words, 0, undefined, true);
  const out: number[] = [];
  let patternSeen = roles !== null || !PATTERN_FIRST.test(head) || words.some((w) => /^-[A-Za-z]*[ef]$/.test(w) || /^--(regexp|file)=/.test(w));
  for (let i = 1; i < words.length; i++) {
    const w = words[i]!;
    if (roles !== null && roles.roles[i] === 'data') continue;
    if (w.startsWith('-')) continue;
    if (!patternSeen) {
      patternSeen = true;
      continue;
    }
    if (w.includes('$SUBST')) out.push(i);
  }
  return out;
}

/** COMMAND SUBSTITUTION: `cat $(echo ~/.ssh/id_rsa)`. The substitutions whose output is known are folded into the line, which is then judged. */
export function planSubstitutions(r: FlowReaders, text: string, bodies: ReadonlyArray<string | null> | undefined): FlowPlan {
  if (bodies === undefined || bodies.length === 0 || !text.includes('$SUBST')) return EMPTY;
  // (a process substitution hands the command a FILE whose content is the output: reading it reads that text, which the producer's own judgement
  // covers, and names no path - it adds nothing here)
  const produced = bodies.map((b) => (b === null ? ({ kind: 'listing' } as Produced) : producedByCommand(r, b)));
  const outputs = produced.map((p) => (p.kind === 'literal' ? p.text : null));
  const stale = produced.some((p) => p.kind === 'literal' && p.stale === true);
  const folded = foldSubstitutions(text, outputs);
  const variants = folded === null ? [] : [[folded]];
  // the substitutions nobody can read, where the command opens them as files: which marker is which operand is the order they stand in
  const words = r.words(text);
  const sites = substitutionSites(text);
  const asks: string[] = [];
  const operandIdx = new Set(substitutedOperands(words));
  if (operandIdx.size > 0) {
    let seen = 0;
    words.forEach((w, i) => {
      const n = (w.match(/\$SUBST/g) ?? []).length;
      for (let k = seen; k < seen + n && k < sites.length; k++)
        if (operandIdx.has(i) && produced[k]?.kind === 'unknown') asks.push(`the operand ${w} of ${(words[0] ?? '').replace(/^.*\//, '')} is the output of \`${bodies[k] ?? 'a process'}\`, which this kernel cannot read`);
      seen += n;
    });
  }
  if (stale) asks.push(STALE);
  return { variants, asks };
}

/** `producer | xargs CMD`, `xargs CMD < list`, `xargs -a list CMD`: the words the producer hands over are CMD's last operands. */
export function planXargs(r: FlowReaders, text: string, stdin: Produced, heredoc?: { body: string; expanded: boolean }): FlowPlan {
  const x = r.xargs(text);
  if (x === null) return EMPTY;
  // where the words come from: a file named by -a, a file the line opens for input, a here-string / heredoc, or the pipe
  let source: Produced = stdin;
  if (x.argFile !== null) source = fromFile(r, x.argFile);
  else if (heredoc !== undefined) {
    const t = r.literal(text, heredoc);
    source = t === null ? { kind: 'unknown' } : { kind: 'literal', text: t };
  } else if (x.hereString) {
    // `xargs cat <<< ~//.ssh/id_rsa` runs `cat ~//.ssh/id_rsa`: a here-string feeds the word to xargs as its standard input exactly as
    // the pipe form does, and the pipe form was refused while this one was ALLOW (exit review 2026-10-07, RVP6-2)
    const t = r.literal(text, { body: x.hereString.body, expanded: x.hereString.expanded });
    source = t === null ? { kind: 'unknown' } : { kind: 'literal', text: t };
  } else {
    const files = r.inputFiles(text);
    if (files.length > 0) source = files.length === 1 ? fromFile(r, files[0]!) : { kind: 'unknown' };
  }
  const payloadWords = r.words(x.payload);
  if (source.kind === 'literal') {
    const variants: string[][] = [];
    for (const words of operandReadings(source.text)) {
      const w = words.slice(0, MAX_WORDS);
      const given = w.map(producedWord);
      if (x.placeholder !== null) {
        // -I R: the command is run once per word, with R replaced; and, where R is not in the command at all, with the words appended
        for (const one of given) variants.push([x.payload.split(x.placeholder).join(one)]);
        variants.push([`${x.payload} ${given.join(' ')}`]);
      } else variants.push([`${x.payload} ${given.join(' ')}`]);
    }
    return { variants, asks: source.stale === true ? [STALE] : [] };
  }
  if (source.kind === 'unknown' && readsOperandsAsFiles(payloadWords))
    return { variants: [], asks: [`the operands of ${(payloadWords[0] ?? '').replace(/^.*\//, '')} come from a command whose output this kernel cannot read (xargs)`] };
  return EMPTY;
}

/**
 * A READ LOOP: the stage at `index` reads a line into variables and the loop body (up to the `done` that closes it) uses them. `stdin` is what
 * the loop is fed. The body is judged once per value the producer hands over, with the variables replaced.
 */
export function planReadLoop(
  r: FlowReaders,
  stages: ReadonlyArray<{ text: string; pipedFromPrevious: boolean }>,
  index: number,
  stdin: Produced,
): FlowPlan {
  // a loop header (`while read f`), or a plain `read f` (which takes ONE line, and binds for the rest of the line: zsh runs the last element of
  // a pipeline in the shell itself, and `echo X | read f && cat $f` reads X)
  const names = r.readNames(stages[index]!.text);
  if (names === null || names.length === 0) return EMPTY;
  // the body: the stages after the loop header, up to the `done` that closes the loop
  const body: Array<{ text: string }> = [];
  let depth = 1;
  let doneAt = -1;
  const plainRead = !/^(?:(?:time|!)\s+)*(while|until)\b/.test(stages[index]!.text.trim());
  if (plainRead) depth = 0;
  for (let j = index + 1; j < stages.length; j++) {
    if (plainRead) {
      body.push(stages[j]!);
      continue;
    }
    const t = r.expand(stages[j]!.text).trim();
    if (/^(?:(?:time|!)\s+)*(for|while|until|select)\b/.test(t)) depth++;
    if (/^done\b/.test(t) && --depth <= 0) {
      doneAt = j;
      break;
    }
    body.push(stages[j]!);
  }
  if (body.length === 0) return EMPTY;
  // where the loop is fed from: the pipe into the `while`, or the `< FILE` on its `done`
  let source = stdin;
  if (source.kind === 'none' && doneAt >= 0) {
    const files = r.inputFiles(stages[doneAt]!.text);
    if (files.length > 0) source = files.length === 1 ? fromFile(r, files[0]!) : { kind: 'unknown' };
  }
  const uses = (text: string): boolean => names.some((n) => new RegExp(`\\$(?:\\{${n}\\b|${n}\\b)`).test(text));
  if (source.kind === 'literal') {
    const values = new Set<string>();
    for (const words of operandReadings(source.text)) for (const w of words.slice(0, MAX_WORDS)) values.add(w);
    for (const line of source.text.split('\n')) if (line.trim() !== '') values.add(line.trim());
    const variants: string[][] = [];
    for (const v of [...values].slice(0, MAX_WORDS)) {
      const vars = new Map(names.map((n) => [n, producedWord(v)] as const));
      const texts = body.map((st) => r.substitute(r.expand(st.text), vars));
      if (texts.some((t, k) => t !== r.expand(body[k]!.text))) variants.push(texts);
    }
    return { variants, asks: source.stale === true ? [STALE] : [] };
  }
  if (source.kind === 'unknown') {
    for (const st of body) {
      const words = r.words(st.text);
      if (readsOperandsAsFiles(words) && words.slice(1).some((w) => !w.startsWith('-') && uses(w)))
        return { variants: [], asks: [`the operand of ${(words[0] ?? '').replace(/^.*\//, '')} in this loop comes from a command whose output this kernel cannot read`] };
    }
  }
  return EMPTY;
}
