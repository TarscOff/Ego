// ONE OPTION PARSER, DRIVEN BY ONE DATA TABLE PER TOOL.
//
// The kernel kept asking "which flags are on, and where does this write" of a command line by scanning it with a regex per
// question: a regex for the output option, another for the program an option names, another for the archive mode, another
// for the shell's `-n`. Every one of them knew the spellings its author had met - `-o FILE`, `--output=FILE`, `-xf` - and
// none of them knew the ones the real option parser accepts: a letter inside a cluster (`-xvf`), a value glued to its letter
// (`-ofile`, `-o=file` for a Go tool), a long option cut to any unique prefix (`tar --extr`, `--use=`), a `+n` that turns a
// flag back off, a sed script command with its file glued to the letter (`w.env`). Each review found one more spelling, and
// each fix taught one more regex that spelling (independent reviews 7-11: RC-OPT).
//
// This module is the parser those tools really have, stated once. A tool is a GRAMMAR - the list of its options with the
// arity of each - and `parseOptions(grammar, argv)` reads an argv the way that grammar's tool reads it. The consumers ask
// the PARSE ("is `extract` on?", "what are the values of `file`?"), never the text, so a spelling the parser accepts is a
// spelling every consumer sees.
//
// A grammar is an ENUMERATION of the tool's documented options, which is wrong by omission unless the omission fails safe:
//   - an option the grammar does not know is reported in `unknown`, never dropped, so a consumer can ask rather than guess;
//   - a long option that is a prefix of SEVERAL options is reported with every candidate, and `has` / `valuesOf` answer for
//     any of them: accepting an abbreviation the real tool would reject as ambiguous is fail-closed, never fail-open
//     (the same rule expandGitAbbreviations states for git).

/** How an option takes its value. */
export type Arity =
  /** a flag */
  | 'none'
  /** the value is the rest of the word, or the next word: `-ofile`, `-o file`, `--output=file`, `--output file` */
  | 'value'
  /** the value is ATTACHED only (`-Wl,-Map,x`, `-fuse-ld=x`, `-Idir`) - the next word is an operand */
  | 'joined'
  /** a value only when attached (`--checkpoint=5`, `-iSUFFIX`); the next word is never taken */
  | 'optional'
  /** the value is a COMMAND LINE the tool runs (`env -S`, `su -c`, `flock -c`): a value that is a program, not a datum */
  | 'command'
  /** the value is the NEXT word only (`-Xlinker x`, `-Xclang x`) */
  | 'separate';

export interface OptionDef {
  /** the name every consumer asks for: the first spelling longer than a letter, else the letter */
  name: string;
  /** every spelling, WITH its dashes: `-s`, `--signal`, `-MF` */
  spellings: readonly string[];
  arity: Arity;
}

/**
 * HOW A TOOL READS ITS ARGUMENT VECTOR.
 *   gnu - getopt_long: `-abc` is a cluster of letters (a value-taking letter ends it), `--name[=value]`, any unique
 *         prefix of a long name, `--` ends the options, and options and operands interleave unless `stopAtOperand`;
 *   go  - the `flag` package: `-name`, `--name`, `-name=value`, `-name value`; no clusters and no abbreviations;
 *   cc  - compilers: a single-dash WORD is an option by longest prefix (`-MF`, `-fuse-ld=`, `-Idir`, `-ofile`); `--long`
 *         works as in gnu; no clusters.
 */
export interface Grammar {
  style: 'gnu' | 'go' | 'cc';
  /** `'-s|--signal:v'`: spellings joined by `|`, then `:` and the arity letter (v value, j joined, o optional, c command,
   *  s separate; none for a flag) */
  options: readonly string[];
  /** options end at the first operand (POSIX utilities and every wrapper); otherwise they interleave with operands */
  stopAtOperand?: boolean;
  /** `+x` is the inverse of `-x`: the shells' `set` flags (`bash -n +n` turns the syntax check off again) */
  plus?: boolean;
  /** `-5` is an option named `#` with the value `5` (`nice -10 cmd`, `head -5`) */
  numeric?: boolean;
  /** a lone `-` is this flag instead of an operand (`env -` is `env -i`) */
  dash?: string;
}

export interface ParsedOption {
  /** the canonical name; the first candidate when the spelling was an ambiguous abbreviation */
  name: string;
  /** how the option takes its value (`command`: the value is a command line the tool runs) */
  arity: Arity;
  /** every option the spelling could be, when it was an abbreviation of several (fail-closed readers ask for any) */
  candidates?: readonly string[];
  value: string | null;
  /** `+` for the shells' inverse spelling */
  sign: '-' | '+';
  /** where in argv the option's word is */
  at: number;
  /** the word as written */
  raw: string;
}

export interface Parsed {
  options: ParsedOption[];
  operands: Array<{ text: string; at: number }>;
  /** words that look like options and are not in the grammar, or whose value is missing */
  unknown: Array<{ raw: string; at: number }>;
  /** the index of the first word the parse did not consume as an option or an option's value; for a `stopAtOperand`
   *  grammar this is where the operands start */
  end: number;
  /** a `--` was met at this index (everything after it is an operand), or -1 */
  dashDashAt: number;
}

interface Compiled {
  byLetter: Map<string, OptionDef>;
  byLong: Map<string, OptionDef>;
  longNames: string[];
  /** single-dash spellings longer than a letter, longest first (compilers, Go) */
  words: Array<{ spelling: string; def: OptionDef }>;
}

const ARITY: Record<string, Arity> = { v: 'value', j: 'joined', o: 'optional', c: 'command', s: 'separate' };
const compiledCache = new WeakMap<Grammar, Compiled>();
const isLetter = (spelling: string): boolean => /^-[^-]$/.test(spelling);

function compile(g: Grammar): Compiled {
  const hit = compiledCache.get(g);
  if (hit) return hit;
  const byLetter = new Map<string, OptionDef>();
  const byLong = new Map<string, OptionDef>();
  const words: Array<{ spelling: string; def: OptionDef }> = [];
  for (const src of g.options) {
    const m = /^(.*?)(?::([vjocs]))?$/.exec(src)!;
    const spellings = m[1]!.split('|');
    const arity: Arity = m[2] ? ARITY[m[2]]! : 'none';
    const canonical = spellings.find((s) => s.startsWith('--')) ?? spellings.find((s) => !isLetter(s)) ?? spellings[0]!;
    const def: OptionDef = { name: canonical.replace(/^-+/, '').replace(/=$/, ''), spellings, arity };
    for (const sp of spellings) {
      if (sp.startsWith('--')) byLong.set(sp.slice(2).replace(/=$/, ''), def);
      else if (isLetter(sp)) byLetter.set(sp.slice(1), def);
      else words.push({ spelling: sp, def });
    }
  }
  words.sort((a, b) => b.spelling.length - a.spelling.length);
  const out: Compiled = { byLetter, byLong, longNames: [...byLong.keys()], words };
  compiledCache.set(g, out);
  return out;
}

/** The value of an option: attached (`--name=value`, `-ofile`), else the next word for the arities that take one. */
function readValue(def: OptionDef, attached: string | null, argv: readonly string[], at: number): { text: string | null; used: boolean } {
  switch (def.arity) {
    case 'none':
      return { text: null, used: false };
    case 'optional':
    case 'joined':
      return { text: attached, used: false };
    default: {
      if (attached !== null) return { text: attached, used: false };
      const next = argv[at + 1];
      return next === undefined ? { text: null, used: false } : { text: next, used: true };
    }
  }
}

/** Reads `argv` from `from` the way the grammar's tool reads it. */
export function parseOptions(g: Grammar, argv: readonly string[], from = 0): Parsed {
  const c = compile(g);
  const options: ParsedOption[] = [];
  const operands: Array<{ text: string; at: number }> = [];
  const unknown: Array<{ raw: string; at: number }> = [];
  let dashDashAt = -1;
  let end = argv.length;
  const add = (def: OptionDef | string, value: string | null, sign: '-' | '+', at: number, candidates?: readonly string[]): void => {
    options.push({
      name: typeof def === 'string' ? def : def.name,
      arity: typeof def === 'string' ? 'none' : def.arity,
      value,
      sign,
      at,
      raw: argv[at]!,
      ...(candidates && candidates.length > 1 ? { candidates } : {}),
    });
  };
  for (let i = from; i < argv.length; i++) {
    // an option whose value is a COMMAND LINE ends the tool's own options: what follows belongs to that line (env appends it
    // to the string it split), never to this grammar
    const last = options[options.length - 1];
    if (last?.arity === 'command' && last.value !== null) {
      end = i;
      break;
    }
    const w = argv[i]!;
    if (w === '--') {
      dashDashAt = i;
      end = i + 1;
      for (let k = i + 1; k < argv.length; k++) operands.push({ text: argv[k]!, at: k });
      break;
    }
    if (w === '-' && g.dash !== undefined) {
      add(c.byLetter.get(g.dash) ?? g.dash, null, '-', i);
      continue;
    }
    const plus = g.plus === true && /^\+[A-Za-z]/.test(w);
    if (!plus && !(w.startsWith('-') && w.length > 1)) {
      if (g.stopAtOperand) {
        end = i;
        break;
      }
      operands.push({ text: w, at: i });
      continue;
    }
    const sign: '-' | '+' = plus ? '+' : '-';
    // (`nice -10` raises the niceness by ten and `nice --10` lowers it: both are the number)
    if (g.numeric && /^--?\d+$/.test(w)) {
      add('#', w.replace(/^-+/, ''), '-', i);
      continue;
    }
    // ---- a long option: `--name`, `--name=value`, `--name value`, any unique prefix of a long name -----------------
    if (w.startsWith('--') && g.style !== 'go') {
      const eq = w.indexOf('=');
      const name = w.slice(2, eq < 0 ? undefined : eq);
      const spelled = c.byLong.has(name) ? [name] : c.longNames.filter((l) => l.startsWith(name));
      const defs = [...new Set(spelled.map((l) => c.byLong.get(l)!))];
      if (defs.length > 0) {
        // the strongest reading of an ambiguous abbreviation: a candidate that takes a value reads the value
        const def = defs.find((d) => d.arity !== 'none') ?? defs[0]!;
        const v = readValue(def, eq < 0 ? null : w.slice(eq + 1), argv, i);
        add(def, v.text, '-', i, defs.map((d) => d.name));
        if (v.used) i++;
        continue;
      }
      // a compiler spells some single-dash words with a doubled dash too; the word table below may know this one
      if (g.style !== 'cc') {
        unknown.push({ raw: w, at: i });
        continue;
      }
    }
    // ---- go: every option is `-name` or `--name`, optionally `=value`; no clusters, no abbreviations ----------------
    if (g.style === 'go') {
      const body = w.replace(/^--?/, '');
      const eq = body.indexOf('=');
      const name = eq < 0 ? body : body.slice(0, eq);
      const def =
        c.byLetter.get(name) ?? c.byLong.get(name) ?? c.words.find((x) => x.spelling.replace(/^-+/, '') === name)?.def;
      if (!def) {
        unknown.push({ raw: w, at: i });
        continue;
      }
      const v = readValue(def, eq < 0 ? null : body.slice(eq + 1), argv, i);
      add(def, v.text, '-', i);
      if (v.used) i++;
      continue;
    }
    // ---- cc: a single-dash WORD by longest prefix; a one-letter option may carry its value attached --------------------
    if (g.style === 'cc') {
      const word = c.words.find((x) => (x.def.arity === 'none' ? w === x.spelling : w.startsWith(x.spelling)));
      const letter = word === undefined && w.length >= 2 ? c.byLetter.get(w[1]!) : undefined;
      const def = word?.def ?? letter;
      if (!def) {
        unknown.push({ raw: w, at: i });
        continue;
      }
      const attached = w.slice(word ? word.spelling.length : 2);
      if (def.arity === 'none') {
        if (attached !== '') unknown.push({ raw: w, at: i });
        else add(def, null, '-', i);
        continue;
      }
      // `-o=file` is the file `=file` to a compiler and the file `file` to a Go tool: the value is kept as written, and a
      // consumer that does not know which reading is the real one judges both (see `valueReadings`)
      const v = readValue(def, attached === '' ? null : attached, argv, i);
      add(def, v.text, '-', i);
      if (v.used) i++;
      continue;
    }
    // ---- gnu short: a cluster of letters; a letter that takes a value takes the REST of the word, or the next word ----
    const letters = w.slice(1);
    for (let k = 0; k < letters.length; k++) {
      const def = c.byLetter.get(letters[k]!);
      if (!def) {
        // a single-dash WORD of the grammar (procps `-differences`, BSD `-arch`), taken whole
        const word = k === 0 ? c.words.find((x) => x.spelling === w) : undefined;
        if (word) {
          add(word.def, null, '-', i);
          break;
        }
        // a letter the table does not know is reported ONCE for the word and read as a flag, so the letters after it are still read: a
        // variant of the tool that has the letter (`tar -Exf`) must not hide a mode behind it
        if (!unknown.some((u) => u.at === i)) unknown.push({ raw: w, at: i });
        continue;
      }
      const rest = letters.slice(k + 1);
      if (def.arity === 'none') {
        add(def, null, sign, i);
        continue;
      }
      if (def.arity === 'optional' || def.arity === 'joined') {
        add(def, rest === '' && def.arity === 'optional' ? null : rest, sign, i);
        break;
      }
      if (rest !== '') {
        add(def, rest, sign, i);
        break;
      }
      const next = argv[i + 1];
      if (next === undefined) {
        add(def, null, sign, i);
        unknown.push({ raw: w, at: i });
      } else {
        add(def, next, sign, i);
        i++;
      }
      break;
    }
  }
  return { options, operands, unknown, end, dashDashAt };
}

/** The option a long name means in this grammar: exact, or the ONE option it is a prefix of. null when it names nothing or several
 *  (the real tool refuses an ambiguous abbreviation, and a reader that rewrites text must not guess which one was meant). */
export function resolveLong(g: Grammar, name: string): OptionDef | null {
  const c = compile(g);
  const exact = c.byLong.get(name);
  if (exact) return exact;
  const defs = [...new Set(c.longNames.filter((l) => l.startsWith(name)).map((l) => c.byLong.get(l)!))];
  return defs.length === 1 ? defs[0]! : null;
}

// ---- queries ---------------------------------------------------------------------------------------------------------

const answers = (o: ParsedOption, name: string): boolean => o.name === name || (o.candidates?.includes(name) ?? false);

/** Whether the option was given at all, in any spelling (an ambiguous abbreviation counts for every candidate). */
export function has(p: Parsed, name: string): boolean {
  return p.options.some((o) => answers(o, name));
}

/** Whether the option is ON at the end of the line: the last `-x` / `+x` decides (the shells' toggles). */
export function isOn(p: Parsed, name: string): boolean {
  let on = false;
  for (const o of p.options) if (answers(o, name)) on = o.sign === '-';
  return on;
}

/** Every value given to an option, in order; a value-less occurrence contributes nothing. */
export function valuesOf(p: Parsed, name: string): string[] {
  return p.options.filter((o) => answers(o, name) && o.value !== null).map((o) => o.value!);
}

/** The readings of a value a consumer must judge when it does not know which parser the tool has: `-o=file` is `=file` to a
 *  GNU or compiler parser and `file` to a Go flag parser, and the file it writes is one of them. */
export function valueReadings(value: string): string[] {
  return value.startsWith('=') ? [value, value.slice(1)] : [value];
}

/** The value the tool applies: the last one given. */
export function lastOf(p: Parsed, name: string): string | null {
  const all = valuesOf(p, name);
  return all.length ? all[all.length - 1]! : null;
}
