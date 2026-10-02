// THE MAKEFILE READER (closure audit 2026-10-02, wave 6, MK-02..MK-08): the lines of a makefile, classified the way GNU make's own reader
// classifies them, into ONE variable store (make.ts) and one model of rules.
//
// What the previous reader did was to try a list of patterns on each line and, for a line none of them took, to do nothing - which made
// every construct it did not model a construct that was "not there": a tab-indented assignment (MK-02), an assignment to a name make
// computes (MK-07), the rest of a file after an `override` line (MK-08). So the contract of this reader is the opposite one: every line
// ends up in exactly one of the kinds below, and a line that is none of them is RECORDED as a line this resolver does not read.
//
//   a recipe line      (a rule is open and the line starts with the recipe prefix)
//   a define block     (`define NAME` ... `endef`: a variable's value, not live makefile text)
//   a directive        (include, a conditional, vpath, load, export / unexport, undefine)
//   an assignment      (`NAME op value`, with `override` / `export` / `private` in front; the name may be computed)
//   a rule             (targets, a static pattern, a target-specific variable, a one-line recipe)
//   a function line    (a line that is only `$(...)`: `$(eval ...)`, `$(info ...)`; expanded, and its commands recorded)
//
// WHAT ENDS A RULE (checked against GNU make 3.81 with the logging harness): an assignment, an include, `export`, `vpath`, a rule line.
// What does NOT: a blank line, a comment, a conditional, a `define` block, and an `override` assignment - after which a tab-indented line is
// still a recipe line of the rule above. After a line that DOES end it, a tab-indented line is a makefile line when it is one (an
// assignment, a conditional, an include) and a fatal error to make otherwise; it is read here as BOTH the error and a recipe of the
// last rule, the more restrictive of the two (4.x may differ from 3.81 about which lines end a rule).
import { relative } from 'node:path';
import {
  MAKE_FILE_WRITE,
  MAKE_WILDCARD,
  cutMakeComment,
  collapseContinuations,
  encodeMakeParts,
  findRecipeSemicolon,
  makeLogicalLines,
  readAssignment,
  readMakeNames,
  recipeText,
  unescapeMakeHash,
  type AssignOp,
  type MakeAssignment,
  type MakeExpansion,
  type MakeOrigin,
  type MakeStore,
} from './make.ts';
import { patternStem } from './make-builtins.ts';

export interface MakeRule {
  recipes: string[];
  prereqs: string[];
  /** after the `|`: built first, never an input of the recipe (`$^` leaves them out) */
  orderOnly: string[];
}

export interface PatternRule {
  target: string;
  prereqs: string[];
  orderOnly: string[];
  recipes: string[];
}

/** What the reader needs from the evaluator: files and directories, read where the kernel may read them. */
export interface MakeHost {
  read(abs: string): string | null;
  /** the PHYSICAL file a name denotes in a directory; null when it cannot be turned into one */
  opened(dir: string, name: string): string | null;
  exists(abs: string): boolean;
  /** the names a make-style glob denotes in a directory (as written, not as paths) */
  glob(dir: string, pattern: string): { names: string[]; incomplete: boolean };
  /** is this SHELL / .SHELLFLAGS / PATH value an ordinary one rather than a rebinding */
  ordinaryShell(name: string, value: string): boolean;
}

export interface MakeModel {
  readonly store: MakeStore;
  rules: Map<string, MakeRule>;
  firstTarget: string | null;
  defaultGoal: string | null;
  /** EVERY goal any branch of the file could select (`.DEFAULT_GOAL` assigned inside a conditional) */
  altGoals: Set<string>;
  /** OPTIONAL INCLUDES THAT WERE NOT THERE, and glob patterns: "missing" is a claim about NOW, and an earlier unit of the same command may have just written them */
  pendingIncludes: string[];
  oneShell: boolean;
  /** constructs that affect the WHOLE file, so no conclusion drawn from it is complete */
  unsupported: string[];
  /** constructs that affect ONLY the targets defined under them, chiefly conditionals */
  unsupportedFor: Map<string, string[]>;
  /** true when the file has rules that can build a target no literal rule names (a pattern, a suffix rule, a wildcard, `.DEFAULT`, a computed target): a goal that no rule names is not PROVEN absent */
  hasPatternRules: boolean;
  /** true when it has rules whose targets no name can be matched against (built from a variable, a wildcard): any plain file may be built by one */
  hasOpaqueRules: boolean;
  /** `target: VAR = value`: recursive text, in force for the target and everything it is a prerequisite of */
  targetVars: Map<string, Map<string, string>>;
  /** `export NAME`, `export NAME = value`, and (with `exportAll`) every variable the makefile set */
  exported: Set<string>;
  unexported: Set<string>;
  exportAll: boolean;
  patternRules: PatternRule[];
  /** assignments that change WHICH PROGRAM a recipe line runs (`SHELL := ./bin/badsh`, `export PATH := ./bin:$(PATH)`) */
  rebinds: string[];
  /** commands make RUNS WHILE PARSING, for any goal and for `make -n` */
  parseRan: string[];
  sources: string[];
  /** the text of the makefiles named on the command line (what the fingerprint covers) */
  text: string;
  /** every makefile read, in the order make read it: `MAKEFILE_LIST` */
  makefileList: string[];
  /** every file an include named, so a rule that REMAKES one - wherever it sits - is caught after the parse */
  included: string[];
}

export function newMakeModel(store: MakeStore): MakeModel {
  return {
    store,
    rules: new Map(),
    firstTarget: null,
    defaultGoal: null,
    altGoals: new Set(),
    pendingIncludes: [],
    oneShell: false,
    unsupported: [],
    unsupportedFor: new Map(),
    hasPatternRules: false,
    hasOpaqueRules: false,
    targetVars: new Map(),
    exported: new Set(),
    unexported: new Set(),
    exportAll: false,
    patternRules: [],
    rebinds: [],
    parseRan: [],
    sources: [],
    text: '',
    makefileList: [],
    included: [],
  };
}

interface Flags {
  override: boolean;
  export: boolean;
  unexport: boolean;
  private: boolean;
}
interface Define {
  nameText: string;
  op: AssignOp;
  flags: Flags;
  lines: string[];
  depth: number;
}

const canon = (n: string): string => n.replace(/^(?:\.\/+)+/, '') || n;
/** the most files one `include` line is followed to */
const MAX_INCLUDE_NAMES = 512;
const KEYWORD = /^(override|export|unexport|private)(?=\s|$)[ \t]*/;

/** Special targets that define no recipe: skipped, and they do not end up as the default goal. */
const MAKE_NO_RECIPE_SPECIALS =
  /^\.(PHONY|SUFFIXES|PRECIOUS|INTERMEDIATE|SECONDARY|SECONDEXPANSION|DELETE_ON_ERROR|IGNORE|LOW_RESOLUTION_TIME|SILENT|EXPORT_ALL_VARIABLES|NOTPARALLEL|POSIX|ONESHELL|DEFAULT_GOAL|RECIPEPREFIX|MAKEFLAGS|NOTINTERMEDIATE)(?=\s*::?|\s*$)/;

/** Parses the subset of GNU make EGO models, following `include` directives INLINE and recording every construct it does NOT model.
 *  Both branches of a conditional are kept: EGO cannot evaluate the condition, and analysing the union is the safe direction. */
export class MakeReader {
  /** the recipe prefix is global once `.RECIPEPREFIX` sets it, and an include reads under whatever the includer set */
  private prefix = '\t';

  private readonly host: MakeHost;
  readonly model: MakeModel;
  private readonly includeDirs: readonly string[];

  constructor(host: MakeHost, model: MakeModel, includeDirs: readonly string[]) {
    this.host = host;
    this.model = model;
    this.includeDirs = includeDirs;
  }

  /** a command make runs while it reads the makefile; each is recorded once */
  private ran(cmd: string): void {
    if (cmd && !this.model.parseRan.includes(cmd)) this.model.parseRan.push(cmd);
  }

  /** a construct this reader does not read, recorded once */
  private note(why: string): void {
    if (!this.model.unsupported.includes(why)) this.model.unsupported.push(why);
  }

  /** Expand text make expands WHILE READING (an immediate site), and record what that does: the commands run, the constructs this reader cannot follow. */
  immediate(text: string): MakeExpansion {
    const m = this.model;
    const ex = m.store.expand(text);
    for (const c of ex.ran) this.ran(c);
    if (ex.evals) this.note(`$(eval) is evaluated: ${text.trim().slice(0, 100)}`);
    if (ex.fileWrites) this.note(`$(file) writes a file while the makefile is read: ${text.trim().slice(0, 100)}`);
    if (ex.blind) this.note(`a command run while the makefile is read cannot be determined: ${text.trim().slice(0, 100)}`);
    if (ex.capped) this.note(`too large to classify within the bound: ${text.trim().slice(0, 60)}`);
    return ex;
  }

  private display(path: string, dir: string): string {
    const rel = relative(dir, path);
    return rel === '' || rel.startsWith('..') || rel.startsWith('/') ? path : rel;
  }

  /** The roots, in the order make reads them: a root is the makefile named on the command line or found by default. */
  readRoot(path: string, dir: string): void {
    this.readFile(path, dir, 0, 0, true);
    // AN INCLUDED MAKEFILE THAT THIS MAKEFILE REMAKES IS A PRE-IMAGE. make remakes it, then RE-EXECUTES itself with the new content, so what
    // this parser read is not what will run - a `deploy:` that did not exist when EGO looked now pushes to the remote (exit review 7).
    for (const name of this.model.included) if (this.model.rules.has(name)) this.note(`an included makefile is remade by this makefile: ${name}`);
  }

  private readFile(path: string, dir: string, depth: number, condBase: number, root: boolean): void {
    const m = this.model;
    const text = this.host.read(path);
    if (text === null) {
      this.note(`${path} could not be read`);
      return;
    }
    m.sources.push(path);
    if (root) m.text += text + '\n';
    m.makefileList.push(this.display(path, dir));
    m.store.seed('MAKEFILE_LIST', ` ${m.makefileList.join(' ')}`);
    const lines = makeLogicalLines(text);
    // the rule(s) whose recipe lines are being read, and the most recent rule(s) for a tab-led line that matches nothing
    let current: MakeRule[] | null = null;
    let last: MakeRule[] | null = null;
    const conds: string[] = [];
    let def: Define | null = null;
    const inCond = (): boolean => conds.length + condBase > 0;

    for (const line of lines) {
      // A `define` BODY IS A VALUE, AND ITS LINES ARE READ AS ONE BEFORE ANYTHING ELSE. A tab-led line inside it is the normal way to
      // write a canned recipe, and the recipe-prefix test below took it for a recipe line of the PREVIOUS rule: the variable came out
      // empty and `$(CMD)` expanded to nothing (exit review 10). It is a variable like any other: expanded where it is USED - or, with
      // `define NAME :=`, where it is defined (MK-04).
      if (def !== null) {
        const t = line.trim();
        if (/^define(?=\s|$)/.test(t)) def.depth++;
        if (/^endef\b/.test(t) && def.depth-- === 0) {
          this.finishDefine(def, inCond());
          def = null;
          continue;
        }
        if (/\$[({]eval\b/.test(t)) this.note(`$(eval) inside define ${def.nameText}: ${t}`);
        if (MAKE_FILE_WRITE.test(t)) this.note(`$(file) writes a file inside define ${def.nameText}: ${t}`);
        def.lines.push(t);
        continue;
      }

      const prefixed = line.startsWith(this.prefix);
      // a line that starts with the CURRENT recipe prefix is a recipe line when a rule is open, whatever it says: a tab-indented
      // `.RECIPEPREFIX` is a command make hands to the shell, and reading it as a directive changed the prefix so every remaining
      // recipe line of that target became invisible (exit review 5)
      if (current !== null && prefixed) {
        const body = recipeText(line, this.prefix);
        for (const r of current) r.recipes.push(body);
        continue;
      }

      const collapsed = collapseContinuations(line);
      const stripped = cutMakeComment(collapsed);
      const trimmed = stripped.trim();
      if (!trimmed) continue;

      // A TAB-INDENTED LINE WITH NO RULE OPEN IS A MAKEFILE LINE (MK-02). The old reader skipped it as a recipe line of nothing, so
      // `\tCMD = git push origin main` above a rule never happened and `\tifndef FOO` hid a branch. It is read like any other line below.
      const body = stripped.trimStart();

      // ---- define -------------------------------------------------------------------------------------------------------------
      const defOpen = /^((?:(?:override|export|private)[ \t]+)*)define[ \t]+(.*?)[ \t]*(::?:?=|[+?!]=|=)?[ \t]*$/.exec(trimmed);
      if (defOpen) {
        const kw = defOpen[1]!;
        def = {
          nameText: defOpen[2]!,
          op: (defOpen[3] as AssignOp | undefined) ?? '=',
          flags: { override: /override/.test(kw), export: /export/.test(kw), unexport: false, private: /private/.test(kw) },
          lines: [],
          depth: 0,
        };
        // (a `define` does not end an open rule: checked against GNU make 3.81)
        continue;
      }

      // ---- include ------------------------------------------------------------------------------------------------------------
      const inc = /^([-s]?)include[ \t]+(.+)$/.exec(trimmed);
      if (inc) {
        current = null;
        this.include(inc[1] !== '', inc[2]!, dir, depth, conds.length + condBase);
        continue;
      }

      // ---- conditionals -------------------------------------------------------------------------------------------------------
      if (/^(ifeq|ifneq|ifdef|ifndef|else|endif)\b/.test(trimmed)) {
        // make expands the CONDITION while parsing, so a shell function in it runs for every target and for a dry run
        this.immediate(trimmed);
        if (/^endif\b/.test(trimmed)) conds.pop();
        else if (/^else\b/.test(trimmed)) conds[conds.length - 1] = `conditional: ${trimmed}`;
        else conds.push(`conditional: ${trimmed}`);
        // A CONDITIONAL DOES NOT END THE RULE IT SITS INSIDE. make allows `ifeq` at column 0 in the middle of a recipe, and the recipe
        // lines under it still belong to that target (exit review 6). Both branches are kept.
        continue;
      }

      if (/^(vpath|VPATH[ \t]*[:+?]?=)/.test(trimmed)) {
        this.immediate(trimmed);
        this.note(`VPATH: ${trimmed}`);
        current = null;
        continue;
      }
      // GNU make >= 4.0 `load FILE` (and `-load`) DLOPENS a shared object at MAKEFILE-PARSE time and calls its setup function: native code
      // in make's own process, for every goal and before any recipe, regardless of `-n` (exit review 10).
      if (/^-?load[ \t]+\S/.test(trimmed)) {
        this.immediate(trimmed);
        this.note(`load directive: ${trimmed}`);
        current = null;
        continue;
      }
      if (/^\.ONESHELL[ \t]*:/.test(trimmed)) {
        // the WHOLE recipe goes to one shell, so a `cd` on one line leaks into the next
        m.oneShell = true;
        current = null;
        continue;
      }
      if (/^\.EXPORT_ALL_VARIABLES[ \t]*:/.test(trimmed)) {
        m.exportAll = true;
        current = null;
        continue;
      }
      const undef = /^undefine[ \t]+(.+)$/.exec(trimmed);
      if (undef) {
        for (const n of this.names(undef[1]!)) m.store.undefine(n, 'file');
        current = null;
        continue;
      }

      // `$(shell …)` ANYWHERE outside a recipe runs while make PARSES - for every target, and for `make -n`. The expansion of every immediate
      // site is recorded where it happens (and a `define` body only where it is USED); this is the net under all of them, which is how a
      // construct this reader does not model is still found - and why a `$(shell …)` in a variable nothing uses is still read.
      this.immediate(trimmed);
      if (/\$[({]eval\b/.test(trimmed)) this.note(`$(eval): ${trimmed}`);
      if (MAKE_FILE_WRITE.test(trimmed)) this.note(`$(file) writes a file while the makefile is read: ${trimmed}`);

      // ---- keywords, assignments, export lists --------------------------------------------------------------------------------
      // `override`, `export`, `unexport` and `private` may precede an assignment, in any order and number
      const flags: Flags = { override: false, export: false, unexport: false, private: false };
      let rest = body;
      for (let k = KEYWORD.exec(rest); k !== null; k = KEYWORD.exec(rest)) {
        flags[k[1] as keyof Flags] = true;
        rest = rest.slice(k[0].length);
      }
      const assignment = rest ? readAssignment(rest) : null;
      if (assignment !== null) {
        this.assign(assignment, flags, trimmed, inCond());
        // AN `override` ASSIGNMENT DOES NOT END A RULE in GNU make 3.81; every other assignment does (MK-08)
        if (!flags.override) current = null;
        continue;
      }
      if ((flags.export || flags.unexport) && !flags.override) {
        // `export` ON ITS OWN exports every variable; `export NAME [NAME...]` exports those (the list may be computed)
        if (rest === '') m.exportAll = flags.export && !flags.unexport;
        else
          for (const n of this.names(rest)) {
            if (flags.export) {
              m.exported.add(n);
              m.unexported.delete(n);
            } else {
              m.unexported.add(n);
              m.exported.delete(n);
            }
          }
        current = null;
        continue;
      }

      // ---- a rule, a function line, or a line this reader does not know ----------------------------------------------------------
      // ONLY A TAB MARKS A RECIPE. GNU make accepts a rule line indented with SPACES, and rejecting every whitespace-led line made
      // `  deploy:` invisible: `make deploy` force-pushed under a proven-absent claim (exit review 7). A TAB-led line is never a rule: to
      // make it is a recipe line or an error.
      // NOT EVERY TARGET THAT BEGINS WITH A DOT IS SPECIAL. Skipping all of them dropped three real recipes: `.DEFAULT`, which make runs for
      // ANY goal that has no rule of its own; an old-style SUFFIX rule like `.c.o:`, which builds a target no literal rule names; and an
      // ordinary target a project simply chose to call `.deploy`, whose recipe then ran under ALLOW even as a prerequisite (exit review 6).
      // Only the special targets that genuinely define no recipe are skipped, and they are named.
      if (!prefixed && MAKE_NO_RECIPE_SPECIALS.test(trimmed)) {
        current = null;
        continue;
      }
      if (!prefixed) {
        const rule = this.rule(stripped, trimmed, conds);
        if (rule === 'variable') continue; // a target-specific variable: it creates no recipe and does not move the rule that is open
        if (rule !== null) {
          current = rule;
          if (rule.length) last = rule;
          continue;
        }
      }
      if (/^\$[({]/.test(trimmed)) {
        // a line that is only a function call: `$(eval …)`, `$(info …)`, `$(foreach …)`. Expanded above; make wants it to come out blank.
        current = null;
        continue;
      }
      // A LINE THIS READER DOES NOT KNOW IS A LINE IT DOES NOT KNOW (MK-02): never "not there". A tab-led one is a fatal error to make
      // ("commands commence before first target"); it is read as a recipe line of the last rule too, so that whichever way a make that
      // differs from 3.81 reads it, what it would run has been read.
      if (prefixed && last !== null) for (const r of last) r.recipes.push(recipeText(line, this.prefix));
      this.note(`a line this resolver does not read: ${trimmed.slice(0, 100)}`);
      current = null;
    }
    if (def !== null) {
      // an unterminated define: make reads to the end of the file as its value and stops with an error
      this.note(`define ${def.nameText} is never closed`);
      this.finishDefine(def, inCond());
    }
  }

  /** The names in a directive's operand list, computed as make computes them. */
  private names(text: string): string[] {
    const ex = this.immediate(text);
    const out: string[] = [];
    for (const a of ex.alts) {
      if (a.text === null) this.model.unsupported.push(`a name list this resolver cannot compute: ${text.trim().slice(0, 80)}`);
      else out.push(...a.text.split(/\s+/).filter(Boolean));
    }
    return [...new Set(out)];
  }

  /* ------------------------------------------------ include ------------------------------------------------ */

  private include(optional: boolean, operand: string, dir: string, depth: number, condDepth: number): void {
    const m = this.model;
    // THE LIST IS EXPANDED WHEN THE LINE IS READ (a variable, a function, a `$(shell …)` that runs now), and the files it names are read INLINE
    const ex = /[$`]/.test(operand) ? this.immediate(operand) : null;
    let texts: string[];
    if (ex === null) texts = [operand];
    else if (/`/.test(operand) || ex.alts.some((a) => a.text === null)) {
      this.note(`include with a computed path: ${operand}`);
      return;
    } else texts = ex.alts.map((a) => a.text!);
    if (depth >= 3) {
      this.note('include nested deeper than this resolver follows');
      return;
    }
    const names: string[] = [];
    for (const text of new Set(texts)) {
      m.included.push(...readMakeNames(text, false).names);
      for (const name of readMakeNames(text, false).names) {
        // A WILDCARD INCLUDE IS AN INCLUDE. `-include *.mk` is the idiom every dependency-generating project uses, and make expands the
        // pattern itself; the resolver read `*.mk` as a literal file name, found nothing, and concluded the goal it did not see was proven
        // absent. `evil.mk` holding `deploy: git push origin main` then ran under a proven-absent claim (exit review 7).
        if (!MAKE_WILDCARD.test(name)) {
          names.push(name);
          continue;
        }
        // the same reader `-f` uses: the directory make LISTS is the physical one, so `include d/../*.mk` reads the parent of d's TARGET
        const { names: matched, incomplete } = this.host.glob(dir, name);
        if (incomplete) this.note(`include with a pattern whose directory could not be read: ${operand}`);
        names.push(...matched);
        // A PATTERN INCLUDE TAKES WHATEVER MATCHES WHEN MAKE RUNS, and an earlier unit of the same command may have created a file that
        // matches it. The directory listing is a snapshot from BEFORE that write, so the pattern is recorded for the ledger.
        m.pendingIncludes.push(name.startsWith('/') ? name : `${dir === '/' ? '' : dir}/${name}`);
      }
    }
    // A REACHED CAP IS NOT AN ABSENCE: every name is a path to judge and a file to read, so one line that names thousands of them is more
    // than one decision may spend, and the rest are a gap, not files that were not there
    const unique = [...new Set(names)];
    if (unique.length > MAX_INCLUDE_NAMES) this.note(`too large to classify within the bound: an include of ${unique.length} files`);
    for (const name of unique.slice(0, MAX_INCLUDE_NAMES)) {
      // AN INCLUDED MAKEFILE THAT IS ITSELF A TARGET IS REMADE, and make then re-executes itself with the new file. What EGO read is a
      // PRE-IMAGE of what will run, so the file it read cannot carry a positive claim (exit review 7).
      if (m.rules.has(name)) this.note(`an included makefile is remade by this makefile: ${name}`);
      let includePath = this.host.opened(dir, name);
      if (includePath === null) {
        this.note(`include with a path that cannot be resolved: ${name}`);
        continue;
      }
      // A FILE NOT IN THE MAKE DIRECTORY IS LOOKED FOR IN THE `-I` DIRECTORIES, in the order they were given, and the first that has it
      // wins. Every candidate is a name the ledger must see too: a file written into one of them is the include that was not there.
      if (!name.startsWith('/') && !this.host.exists(includePath)) {
        for (const d of this.includeDirs) {
          const found = this.host.opened(d, name);
          if (found === null) continue;
          if (this.host.exists(found)) {
            includePath = found;
            break;
          }
          m.pendingIncludes.push(found);
        }
      }
      // `-include` and `sinclude` exist PRECISELY so that a missing file is not an error: make carries on. Marking an absent optional
      // include unsupported gated every ordinary `make build` in a project that generates its dependency files (exit review 5).
      if (optional && !this.host.exists(includePath)) {
        m.pendingIncludes.push(includePath);
        continue;
      }
      this.readFile(includePath, dir, depth + 1, condDepth, false);
    }
  }

  /* ----------------------------------------------- assignment ----------------------------------------------- */

  private assign(a: MakeAssignment, flags: Flags, line: string, conditional: boolean): void {
    const raw = unescapeMakeHash(a.value);
    // THE NAME IS COMPUTED WHEN IT HAS A REFERENCE IN IT (MK-07): `$(N) = …`, `CMD$(E) = …`, `export $(N) = …`. The reader that required
    // a literal name dropped such a line, so a harmless earlier value stayed in its model while make used the new one.
    let names: string[] = [a.name];
    if (a.name.includes('$')) {
      const ex = this.immediate(a.name);
      if (ex.alts.some((x) => x.text === null || x.text.trim() === '')) {
        this.note(`an assignment to a variable name this resolver cannot compute: ${line.slice(0, 100)}`);
        // the right-hand side still runs where make runs it
        if (a.op !== '=' && a.op !== '?=' && a.op !== '+=') this.immediate(raw);
        return;
      }
      names = [...new Set(ex.alts.map((x) => x.text!.trim()))];
    }
    for (const name of names) this.assignOne(name, a.op, raw, flags, line, conditional);
  }

  private assignOne(name: string, op: AssignOp, raw: string, flags: Flags, line: string, conditional: boolean): void {
    const m = this.model;
    const st = m.store;
    const origin: MakeOrigin = flags.override ? 'override' : 'file';
    const prior = st.has(name);
    // `?=` IS CONDITIONAL: it sets the variable only when it has no value yet - whatever set it before, and in whichever file (MK-06: the
    // included `config.mk` default no longer replaces the includer's value). Its right-hand side is not expanded when it is declined.
    if (op === '?=' && prior) return;

    let texts: string[];
    let simple = false;
    if (op === ':=' || op === '::=' || op === ':::=') {
      // `:=` and `::=` are SIMPLY EXPANDED: the value is fixed HERE, so a later assignment to what it referenced does not change it,
      // and a `$(shell …)` in it runs NOW
      const ex = this.immediate(raw);
      texts = [...new Set(ex.branches.map(encodeMakeParts))];
      simple = true;
    } else if (op === '!=') {
      // `X != CMD` IS `$(shell CMD)` BY ANOTHER NAME: the right-hand side runs while the makefile is read, for any goal and for `make -n`
      const ex = this.immediate(raw);
      for (const alt of ex.alts) {
        const cmd = (alt.text ?? alt.prefix).trim();
        if (cmd) this.ran(cmd);
        if (alt.text === null) this.note(`a command run while the makefile is read cannot be determined: ${line.slice(0, 100)}`);
      }
      texts = [encodeMakeParts([null])];
      simple = true;
    } else if (op === '+=') {
      const old = st.candidates(name);
      if (old.length === 0) texts = [raw];
      else if (st.isSimple(name)) {
        // appending to a SIMPLE variable expands the new text now
        const ex = this.immediate(raw);
        const add = [...new Set(ex.branches.map(encodeMakeParts))];
        texts = [];
        for (const o of old) for (const x of add) texts.push(`${o} ${x}`);
        simple = true;
      } else texts = old.map((o) => `${o} ${raw}`); // (always a blank between the two: checked against `make -p`)
    } else texts = [raw];
    texts = texts.slice(0, 8);
    if (texts.length === 0) texts = [''];

    // an assignment that redefines the interpreter or the lookup path for EVERY recipe line
    // `SHELL := /bin/bash` is the single most common line in a real makefile and names a system shell, not a rebinding. Only an
    // assignment naming something ELSE - a relative path, a repository program, a variable - re-points what the recipe runs.
    if (/^(SHELL|\.SHELLFLAGS|PATH)$/.test(name) && !this.host.ordinaryShell(name, raw)) m.rebinds.push(line);

    const took = st.set(name, texts, { origin, simple, conditional });
    if (flags.export) {
      m.exported.add(name);
      m.unexported.delete(name);
    }
    if (flags.unexport) {
      m.unexported.add(name);
      m.exported.delete(name);
    }
    if (name === '.RECIPEPREFIX') {
      this.prefix = raw.trim()[0] ?? '\t'; // an empty assignment restores the tab
      return;
    }
    if (name === '.DEFAULT_GOAL' && took) this.defaultGoal(raw, texts, conditional);
  }

  /** `.DEFAULT_GOAL := name`: the goal a bare `make` builds. Outside a conditional assignments are SEQUENTIAL and make takes the last. */
  private defaultGoal(raw: string, texts: string[], conditional: boolean): void {
    const m = this.model;
    // THE VALUE IS READ BY MAKE'S NAME GRAMMAR (GNU make 3.81 runs the target `a b` for `.DEFAULT_GOAL := a\ b`), and a value of several
    // words is an error to make unless the WHOLE text is itself the name of a target - so it is the first name, and every further name, and
    // the whole text, that are candidates; an over-reading here walks a goal make would refuse, never one it would run unread
    const values = this.immediate(texts[0]!).alts.map((a) => a.text ?? raw);
    let first: string | null = null;
    for (const value of values) {
      const names = readMakeNames(value, false).names;
      if (names.length === 0) continue;
      const whole = value.replace(/(^|[^\\])#.*$/, '$1').trim();
      const g = canon(names[0]!);
      first ??= g;
      if (names.length > 1) for (const extra of [...names.slice(1), whole]) m.altGoals.add(canon(extra));
      if (g !== first) m.altGoals.add(g);
    }
    if (first === null) return;
    if (conditional) {
      if (m.defaultGoal) m.altGoals.add(m.defaultGoal);
      m.altGoals.add(first);
      // ...AND IF THE CONDITION IS FALSE THE ASSIGNMENT NEVER HAPPENS, so make falls back to the FIRST RULE (the first target is a
      // candidate too; it is recorded as one the moment the goal becomes conditional, because the rule that defines it may not have been read yet)
      m.altGoals.add('\0firstTarget');
    }
    m.defaultGoal = first;
  }

  private finishDefine(d: Define, conditional: boolean): void {
    const body = d.lines.join('\n').trim();
    let names: string[] = [d.nameText];
    if (d.nameText.includes('$')) {
      const ex = this.immediate(d.nameText);
      if (ex.alts.some((x) => x.text === null || x.text.trim() === '')) {
        this.model.unsupported.push(`define ${d.nameText}: a name this resolver cannot compute`);
        return;
      }
      names = [...new Set(ex.alts.map((x) => x.text!.trim()))];
    }
    for (const name of names) this.assignOne(name, d.op, body, d.flags, `define ${name}`, conditional);
  }

  /* -------------------------------------------------- rules -------------------------------------------------- */

  /** A rule line. Returns the rules whose recipe lines follow, 'variable' for a target-specific variable, or null when the line is not a rule. */
  private rule(stripped: string, trimmed: string, conds: string[]): MakeRule[] | 'variable' | null {
    const src = stripped.trimStart();
    // GNU make strips the COMMENT before it looks for the `;` that starts a one-line recipe, so in `deploy: ## Deploy; never run git push
    // by hand` the text after the semicolon is prose (exit review 10)
    const semi = findRecipeSemicolon(src);
    const headRaw = semi < 0 ? src : src.slice(0, semi);
    // (the one-line recipe has had its comment cut and its `\#` unescaped, as the rest of the line has; a recipe on a line of its own has neither)
    const inline = semi < 0 ? undefined : unescapeMakeHash(src.slice(semi + 1));
    const rawHead = readMakeNames(headRaw, true);
    if (rawHead.assignment) return null;

    // A TARGET-SPECIFIC VARIABLE IS NOT A PREREQUISITE LIST. `deploy: DOCKER = docker --context production rm -f app` overrides DOCKER for
    // that target's recipes, and it was parsed as a rule whose prerequisites are the words of the assignment (exit review 7). THE WHOLE TAIL IS
    // THE VALUE: in GNU make 3.81 a target-specific assignment takes everything after the operator - a `;` and what follows it included -
    // and creates no recipe.
    if (rawHead.colon >= 0) {
      let at = rawHead.colon + 1;
      if (headRaw[at] === ':' && headRaw[at + 1] !== '=') at++;
      const whole = (inline !== undefined ? `${headRaw.slice(at)};${inline}` : headRaw.slice(at)).trim();
      const tsv = /^((?:override[ \t]+|export[ \t]+|private[ \t]+)*)([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*(::?:?=|[+?!]=|=)[ \t]*([\s\S]*)$/.exec(whole);
      if (tsv && headRaw[rawHead.colon + 1] !== '=') {
        this.targetVariable(headRaw.slice(0, rawHead.colon), tsv[1]!, tsv[2]!, tsv[3] as AssignOp, tsv[4]!, whole);
        return 'variable';
      }
    }

    // THE HEAD IS EXPANDED WHEN THE LINE IS READ: the targets and the prerequisites are the names the variables hold now (MK-10: `app: $(OBJS)`
    // is a rule with prerequisites, not an opacity). An unknown piece leaves the text as written and the line blind to what it names.
    let heads: string[];
    let computed = false;
    if (!headRaw.includes('$')) heads = [headRaw];
    else {
      const ex = this.immediate(headRaw);
      if (ex.alts.every((a) => a.text !== null)) heads = [...new Set(ex.alts.map((a) => a.text!))];
      else {
        heads = [headRaw];
        computed = true;
      }
    }
    const registered: MakeRule[] = [];
    let any = false;
    for (const h of heads) {
      const r = readMakeNames(h, true);
      if (r.assignment || r.colon < 0) continue;
      any = true;
      let at = r.colon + 1;
      if (h[at] === ':' && h[at + 1] !== '=') at++;
      const tail = h.slice(at);
      // `targets: target-pattern: prerequisite-patterns` is a STATIC PATTERN RULE: the second colon ends the pattern, and the stem of each
      // target replaces the `%` in the prerequisites
      const second = readMakeNames(tail, true);
      let prereqText = tail;
      let pattern: string | null = null;
      if (second.colon >= 0 && !second.assignment && second.names.length === 1) {
        pattern = second.names[0]!;
        prereqText = tail.slice(second.colon + 1);
      }
      const all = readMakeNames(prereqText, false).names;
      const bar = all.indexOf('|');
      const prereqs = bar < 0 ? all : all.slice(0, bar);
      const orderOnly = bar < 0 ? [] : all.slice(bar + 1);
      registered.push(...this.register(r.names, pattern, prereqs, orderOnly, inline, conds, computed || h.includes('$'), trimmed));
    }
    if (!any) return null;
    return registered;
  }

  private register(
    rawTargets: string[],
    pattern: string | null,
    prereqs: string[],
    orderOnly: string[],
    inline: string | undefined,
    conds: string[],
    computed: boolean,
    trimmed: string,
  ): MakeRule[] {
    const m = this.model;
    const targets = rawTargets;
    // A target that can build something NO LITERAL RULE DEFINES makes "this goal has no rule, so nothing runs" false. A `%` pattern is one;
    // so are `.DEFAULT`, which make runs for any goal with no rule of its own, and an old-style SUFFIX rule like `.c.o:` - both reached ALLOW
    // by proving a target absent that make in fact builds (exit review 6). A WILDCARD IS ANOTHER: make expands `*`, `?` and `[` in a target
    // name against the files that exist, so `dep*:` is a rule for `deploy` whenever that file is there - the text names no target.
    if (targets.some((t) => /[%$]/.test(t) || MAKE_WILDCARD.test(t) || /^\.DEFAULT$/i.test(t) || /^\.[A-Za-z0-9_+-]+\.[A-Za-z0-9_+-]+$/.test(t)))
      m.hasPatternRules = true;
    // ...but a `%` pattern, a suffix rule and `.DEFAULT` are rules the walk can MATCH against a name (patternRules, below), so they do not make
    // every plain file a thing a rule may build: every C makefile has `%.o: %.c`, and "a pattern rule may build it" gated each source file it
    // names (MK-10). What stays blind is what no name can be matched against: a target built from a variable, and a wildcard.
    if (targets.some((t) => t.includes('$') || MAKE_WILDCARD.test(t))) m.hasOpaqueRules = true;
    const oneLine = inline !== undefined && inline.trim() ? inline.trim() : null; // `target: ; cmd` one-line form
    const localBlind = [...conds];
    if (computed || prereqs.some((p) => p.includes('$')) || orderOnly.some((p) => p.includes('$')) || targets.some((t) => t.includes('$')))
      localBlind.push(`computed prerequisites: ${trimmed}`);
    // ...AND A WILDCARD PREREQUISITE NAMES WHATEVER FILES EXIST, any of which may be a target with a rule of its own
    if (prereqs.some((p) => MAKE_WILDCARD.test(p))) localBlind.push(`wildcard prerequisites: ${trimmed}`);
    const out: MakeRule[] = [];
    for (const raw of targets) {
      // `./deploy:` AND `deploy:` ARE THE SAME TARGET: make canonicalises a leading `./` away, so a makefile may define the safe recipe
      // under one spelling and the dangerous one under the other. Registered under the CANONICAL name, the two merge exactly as two `::`
      // rules do, and `make deploy` sees both (self-attack on exit review 9).
      const t = canon(raw);
      let mine = prereqs;
      if (pattern !== null) {
        const stem = patternStem(pattern, t);
        if (stem === null) {
          this.note(`a static pattern rule whose target does not match its pattern: ${trimmed}`);
          continue;
        }
        mine = prereqs.map((p) => p.replace(/%/g, stem));
      }
      if (localBlind.length) m.unsupportedFor.set(t, [...(m.unsupportedFor.get(t) ?? []), ...localBlind]);
      // both branches of a conditional, or a `::` rule declared twice: keep EVERY recipe, never the last one
      let rule = m.rules.get(t);
      if (rule) {
        rule.prereqs.push(...mine);
        rule.orderOnly.push(...orderOnly);
      } else {
        rule = { recipes: [], prereqs: [...mine], orderOnly: [...orderOnly] };
        m.rules.set(t, rule);
      }
      if (oneLine !== null) rule.recipes.push(oneLine);
      if (t.includes('%') && !t.includes('$')) m.patternRules.push({ target: t, prereqs: mine, orderOnly, recipes: rule.recipes });
      // An OLD-STYLE SUFFIX RULE is a pattern rule by another name: `.c.o:` is `%.o: %.c`, and `.c:` is `%: %.c`. It has no prerequisites;
      // a rule that has some is an ordinary target (checked against the make manual and 3.81).
      const suffix = pattern === null && mine.length === 0 && !/^\.DEFAULT$/i.test(t) ? /^\.([A-Za-z0-9_+-]+)(?:\.([A-Za-z0-9_+-]+))?$/.exec(t) : null;
      if (suffix) m.patternRules.push({ target: suffix[2] === undefined ? '%' : `%.${suffix[2]}`, prereqs: [`%.${suffix[1]}`], orderOnly: [], recipes: rule.recipes });
      out.push(rule);
      // A TARGET BEGINNING WITH A DOT IS SPECIAL ONLY IF IT HAS NO SLASH. That is make's own rule for picking the default goal -
      // ".PHONY" is skipped, "./deploy" is an ordinary file target and IS the default (exit review 9).
      // (...and neither is a pattern: a `%.o: %.c` above the real first rule made it the default goal, so `make` walked the pattern and never
      //  the rule make builds)
      if (!m.firstTarget && !(t.startsWith('.') && !t.includes('/')) && !t.includes('%') && !MAKE_NO_RECIPE_SPECIALS.test(t)) m.firstTarget = t;
    }
    return out;
  }

  private targetVariable(rawTargets: string, keywords: string, name: string, op: AssignOp, value: string, whole: string): void {
    const m = this.model;
    const targets = this.targetNames(rawTargets);
    // what this parser does not model is REPORTED, not approximated: an appending or conditional assignment, a keyword in front of it, or a
    // PATTERN-specific variable each change what the recipe expands to in ways a plain replacement gets wrong in BOTH directions
    const unmodelled =
      keywords.trim() !== '' ? `a target-specific assignment with ${keywords.trim()}` :
      /^[+?!]=$/.test(op) ? `a target-specific ${op} assignment` :
      targets.some((t) => t.includes('%')) ? 'a pattern-specific variable' : null;
    // a simply expanded value runs its shell functions NOW, whatever target it is for
    if (op === ':=' || op === '::=' || op === ':::=') this.immediate(value);
    // `build: SHELL := ./bin/badsh` re-points the recipe of that target (and of what it builds) exactly as a global assignment does
    if (/^(SHELL|\.SHELLFLAGS|PATH)$/.test(name) && !this.host.ordinaryShell(name, value)) m.rebinds.push(whole);
    for (const t of targets) {
      const tv = m.targetVars.get(t) ?? new Map<string, string>();
      tv.set(name, value);
      m.targetVars.set(t, tv);
      if (unmodelled) m.unsupportedFor.set(t, [...(m.unsupportedFor.get(t) ?? []), `${unmodelled}: ${whole}`]);
    }
    if (unmodelled && targets.some((t) => t.includes('%'))) this.note(`${unmodelled}: ${whole}`);
  }

  private targetNames(raw: string): string[] {
    if (!raw.includes('$')) return readMakeNames(raw, false).names.map(canon);
    const ex = this.immediate(raw);
    const out: string[] = [];
    for (const a of ex.alts) out.push(...readMakeNames(a.text ?? a.prefix, false).names.map(canon));
    if (ex.alts.some((a) => a.text === null)) {
      this.model.unsupported.push(`a target-specific variable for targets this resolver cannot compute: ${raw.trim().slice(0, 80)}`);
    }
    return [...new Set(out)];
  }
}
