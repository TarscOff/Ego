// GNU MAKE'S OWN BUILT-IN DATABASE: the variables it defines before it reads a makefile, and the implicit rules it applies to a file
// no rule of the makefile builds (closure audit 2026-10-02, wave 6, MK-05 and MK-10).
//
// WHY THIS IS DATA. "This goal has no rule, so nothing runs" is true only while make has no rule of its own for it, and it has about
// sixty: `make foo` with a `foo.c` beside it runs `$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH) foo.c $(LOADLIBES) $(LDLIBS) -o foo`,
// and `CC = git push origin main #` in the makefile - or `make CC=./tool.sh foo` with no makefile at all - makes that line a push. A
// resolver that asked only the makefile's own rules proved the goal absent and ran it under that proof. Every variable such a rule reads
// (`CC`, `COMPILE.c`, `LEX`, `YACC`, `CO`, `GET`...) is an execution input exactly as `SHELL` is, so the rules are kept as TEXT and are
// expanded by the one expander, against the one variable store, like a recipe the makefile wrote itself.
//
// WHERE THE TABLE COMES FROM. It was read off `make -p -f /dev/null` of GNU make 3.81 on 2026-10-02 (the implicit-rule section and the
// variables marked `default`), without the entries that describe the host (`MAKE_COMMAND`, `MAKEFILEPATH`, `.FEATURES`...). Nothing here
// is a judgement; test/closure-make2.test.ts re-derives both lists from whichever `make` is installed and fails when it knows a rule or
// a variable this table does not, so a newer make that adds one is noticed rather than assumed.

export interface BuiltinRule {
  /** the target pattern (`%.o`; `%` alone matches any name) */
  readonly target: string;
  readonly prereqs: readonly string[];
  readonly recipes: readonly string[];
}

export const BUILTIN_VARIABLES: ReadonlyArray<readonly [name: string, value: string]> = [
  ['AR', 'ar'],
  ['ARFLAGS', 'rv'],
  ['AS', 'as'],
  ['CC', 'cc'],
  ['CHECKOUT,v', '+$(if $(wildcard $@),,$(CO) $(COFLAGS) $< $@)'],
  ['CO', 'co'],
  ['COFLAGS', ''],
  ['COMPILE.C', '$(COMPILE.cc)'],
  ['COMPILE.F', '$(FC) $(FFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c'],
  ['COMPILE.S', '$(CC) $(ASFLAGS) $(CPPFLAGS) $(TARGET_MACH) -c'],
  ['COMPILE.c', '$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c'],
  ['COMPILE.cc', '$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c'],
  ['COMPILE.cpp', '$(COMPILE.cc)'],
  ['COMPILE.def', '$(M2C) $(M2FLAGS) $(DEFFLAGS) $(TARGET_ARCH)'],
  ['COMPILE.f', '$(FC) $(FFLAGS) $(TARGET_ARCH) -c'],
  ['COMPILE.m', '$(COMPILE.c)'],
  ['COMPILE.mod', '$(M2C) $(M2FLAGS) $(MODFLAGS) $(TARGET_ARCH)'],
  ['COMPILE.p', '$(PC) $(PFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c'],
  ['COMPILE.r', '$(FC) $(FFLAGS) $(RFLAGS) $(TARGET_ARCH) -c'],
  ['COMPILE.s', '$(AS) $(ASFLAGS) $(TARGET_MACH)'],
  ['CPP', '$(CC) -E'],
  ['CTANGLE', 'ctangle'],
  ['CWEAVE', 'cweave'],
  ['CXX', 'c++'],
  ['F77', '$(FC)'],
  ['F77FLAGS', '$(FFLAGS)'],
  ['FC', 'f77'],
  ['GET', 'get'],
  ['GNUMAKE', 'YES'],
  ['LD', 'ld'],
  ['LEX', 'lex'],
  ['LEX.l', '$(LEX) $(LFLAGS) -t'],
  ['LEX.m', '$(LEX) $(LFLAGS) -t'],
  ['LINK.C', '$(LINK.cc)'],
  ['LINK.F', '$(FC) $(FFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH)'],
  ['LINK.S', '$(CC) $(ASFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_MACH)'],
  ['LINK.c', '$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH)'],
  ['LINK.cc', '$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH)'],
  ['LINK.cpp', '$(LINK.cc)'],
  ['LINK.f', '$(FC) $(FFLAGS) $(LDFLAGS) $(TARGET_ARCH)'],
  ['LINK.m', '$(LINK.c)'],
  ['LINK.o', '$(CC) $(LDFLAGS) $(TARGET_ARCH)'],
  ['LINK.p', '$(PC) $(PFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH)'],
  ['LINK.r', '$(FC) $(FFLAGS) $(RFLAGS) $(LDFLAGS) $(TARGET_ARCH)'],
  ['LINK.s', '$(CC) $(ASFLAGS) $(LDFLAGS) $(TARGET_MACH)'],
  ['LINT', 'lint'],
  ['LINT.c', '$(LINT) $(LINTFLAGS) $(CPPFLAGS) $(TARGET_ARCH)'],
  ['M2C', 'm2c'],
  ['MAKEINFO', 'makeinfo'],
  ['OUTPUT_OPTION', '-o $@'],
  ['PC', 'pc'],
  ['PREPROCESS.F', '$(FC) $(FFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -F'],
  ['PREPROCESS.S', '$(CC) -E $(CPPFLAGS)'],
  ['PREPROCESS.r', '$(FC) $(FFLAGS) $(RFLAGS) $(TARGET_ARCH) -F'],
  ['RM', 'rm -f'],
  ['TANGLE', 'tangle'],
  ['TEX', 'tex'],
  ['TEXI2DVI', 'texi2dvi'],
  ['WEAVE', 'weave'],
  ['YACC', 'yacc'],
  ['YACC.m', '$(YACC) $(YFLAGS)'],
  ['YACC.y', '$(YACC) $(YFLAGS)'],
];

export const BUILTIN_RULES: readonly BuiltinRule[] = [
  { target: '%', prereqs: ['%.o'], recipes: ['$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%', prereqs: ['%.c'], recipes: ['$(LINK.c) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%.ln', prereqs: ['%.c'], recipes: ['$(LINT.c) -C$* $<'] },
  { target: '%.o', prereqs: ['%.c'], recipes: ['$(COMPILE.c) $(OUTPUT_OPTION) $<'] },
  { target: '%', prereqs: ['%.cc'], recipes: ['$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%.o', prereqs: ['%.cc'], recipes: ['$(COMPILE.cc) $(OUTPUT_OPTION) $<'] },
  { target: '%', prereqs: ['%.C'], recipes: ['$(LINK.C) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%.o', prereqs: ['%.C'], recipes: ['$(COMPILE.C) $(OUTPUT_OPTION) $<'] },
  { target: '%', prereqs: ['%.cpp'], recipes: ['$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%.o', prereqs: ['%.cpp'], recipes: ['$(COMPILE.cpp) $(OUTPUT_OPTION) $<'] },
  { target: '%', prereqs: ['%.p'], recipes: ['$(LINK.p) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%.o', prereqs: ['%.p'], recipes: ['$(COMPILE.p) $(OUTPUT_OPTION) $<'] },
  { target: '%', prereqs: ['%.f'], recipes: ['$(LINK.f) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%.o', prereqs: ['%.f'], recipes: ['$(COMPILE.f) $(OUTPUT_OPTION) $<'] },
  { target: '%', prereqs: ['%.F'], recipes: ['$(LINK.F) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%.o', prereqs: ['%.F'], recipes: ['$(COMPILE.F) $(OUTPUT_OPTION) $<'] },
  { target: '%.f', prereqs: ['%.F'], recipes: ['$(PREPROCESS.F) $(OUTPUT_OPTION) $<'] },
  { target: '%', prereqs: ['%.m'], recipes: ['$(LINK.m) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%.o', prereqs: ['%.m'], recipes: ['$(COMPILE.m) $(OUTPUT_OPTION) $<'] },
  { target: '%', prereqs: ['%.r'], recipes: ['$(LINK.r) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%.o', prereqs: ['%.r'], recipes: ['$(COMPILE.r) $(OUTPUT_OPTION) $<'] },
  { target: '%.f', prereqs: ['%.r'], recipes: ['$(PREPROCESS.r) $(OUTPUT_OPTION) $<'] },
  { target: '%.ln', prereqs: ['%.y'], recipes: ['$(YACC.y) $<', '$(LINT.c) -C$* y.tab.c', '$(RM) y.tab.c'] },
  { target: '%.c', prereqs: ['%.y'], recipes: ['$(YACC.y) $<', 'mv -f y.tab.c $@'] },
  { target: '%.ln', prereqs: ['%.l'], recipes: ['@$(RM) $*.c', '$(LEX.l) $< > $*.c', '$(LINT.c) -i $*.c -o $@', '$(RM) $*.c'] },
  { target: '%.c', prereqs: ['%.l'], recipes: ['@$(RM) $@', '$(LEX.l) $< > $@'] },
  { target: '%.r', prereqs: ['%.l'], recipes: ['$(LEX.l) $< > $@', 'mv -f lex.yy.r $@'] },
  { target: '%.m', prereqs: ['%.ym'], recipes: ['$(YACC.m) $<', 'mv -f y.tab.c $@'] },
  { target: '%.m', prereqs: ['%.lm'], recipes: ['@$(RM) $@', '$(LEX.m) $< > $@'] },
  { target: '%', prereqs: ['%.s'], recipes: ['$(LINK.s) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%.o', prereqs: ['%.s'], recipes: ['$(COMPILE.s) -o $@ $<'] },
  { target: '%', prereqs: ['%.S'], recipes: ['$(LINK.S) $^ $(LOADLIBES) $(LDLIBS) -o $@'] },
  { target: '%.o', prereqs: ['%.S'], recipes: ['$(COMPILE.S) -o $@ $<'] },
  { target: '%.s', prereqs: ['%.S'], recipes: ['$(PREPROCESS.S) $< > $@'] },
  { target: '%', prereqs: ['%.mod'], recipes: ['$(COMPILE.mod) -o $@ -e $@ $^'] },
  { target: '%.o', prereqs: ['%.mod'], recipes: ['$(COMPILE.mod) -o $@ $<'] },
  { target: '%.sym', prereqs: ['%.def'], recipes: ['$(COMPILE.def) -o $@ $<'] },
  { target: '%.dvi', prereqs: ['%.tex'], recipes: ['$(TEX) $<'] },
  { target: '%.info', prereqs: ['%.texinfo'], recipes: ['$(MAKEINFO) $(MAKEINFO_FLAGS) $< -o $@'] },
  { target: '%.dvi', prereqs: ['%.texinfo'], recipes: ['$(TEXI2DVI) $(TEXI2DVI_FLAGS) $<'] },
  { target: '%.info', prereqs: ['%.texi'], recipes: ['$(MAKEINFO) $(MAKEINFO_FLAGS) $< -o $@'] },
  { target: '%.dvi', prereqs: ['%.texi'], recipes: ['$(TEXI2DVI) $(TEXI2DVI_FLAGS) $<'] },
  { target: '%.info', prereqs: ['%.txinfo'], recipes: ['$(MAKEINFO) $(MAKEINFO_FLAGS) $< -o $@'] },
  { target: '%.dvi', prereqs: ['%.txinfo'], recipes: ['$(TEXI2DVI) $(TEXI2DVI_FLAGS) $<'] },
  { target: '%.c', prereqs: ['%.w'], recipes: ['$(CTANGLE) $< - $@'] },
  { target: '%.tex', prereqs: ['%.w'], recipes: ['$(CWEAVE) $< - $@'] },
  { target: '%.p', prereqs: ['%.web'], recipes: ['$(TANGLE) $<'] },
  { target: '%.tex', prereqs: ['%.web'], recipes: ['$(WEAVE) $<'] },
  { target: '%', prereqs: ['%.sh'], recipes: ['cat $< >$@', 'chmod a+x $@'] },
  { target: '(%)', prereqs: ['%'], recipes: ['$(AR) $(ARFLAGS) $@ $<'] },
  { target: '%.out', prereqs: ['%'], recipes: ['@rm -f $@', 'cp $< $@'] },
  { target: '%.c', prereqs: ['%.w', '%.ch'], recipes: ['$(CTANGLE) $^ $@'] },
  { target: '%.tex', prereqs: ['%.w', '%.ch'], recipes: ['$(CWEAVE) $^ $@'] },
  { target: '%', prereqs: ['%,v'], recipes: ['$(CHECKOUT,v)'] },
  { target: '%', prereqs: ['RCS/%,v'], recipes: ['$(CHECKOUT,v)'] },
  { target: '%', prereqs: ['RCS/%'], recipes: ['$(CHECKOUT,v)'] },
  { target: '%', prereqs: ['s.%'], recipes: ['$(GET) $(GFLAGS) $(SCCS_OUTPUT_OPTION) $<'] },
  { target: '%', prereqs: ['SCCS/s.%'], recipes: ['$(GET) $(GFLAGS) $(SCCS_OUTPUT_OPTION) $<'] },
];

/** The stem of `name` under the pattern `pat` (a pattern holds one `%`), or null when it does not match. The stem of a PATTERN RULE is never
 *  empty (`%.o` does not match a file called `.o`); the stem of `patsubst` and of `$(VAR:a=b)` may be (`$(patsubst %.c,%.o,.c)` is `.o`). */
export function patternStem(pat: string, name: string, allowEmpty = false): string | null {
  const at = pat.indexOf('%');
  if (at < 0) return pat === name ? '' : null;
  const pre = pat.slice(0, at);
  const post = pat.slice(at + 1);
  if (name.length < pre.length + post.length + (allowEmpty ? 0 : 1) || !name.startsWith(pre) || !name.endsWith(post)) return null;
  return name.slice(pre.length, name.length - post.length);
}

/** A pattern rule's target matched against a name the way make matches it: a pattern WITHOUT a slash is matched against the file part of
 *  the name, and the directory is put back on every prerequisite that has none (`sub/foo.o` against `%.o: %.c` wants `sub/foo.c`). */
export interface PatternMatch {
  /** `$*`: the stem with its directory (`sub/foo`) */
  readonly stem: string;
  readonly dir: string;
  readonly bare: string;
}
export function matchPatternRule(pattern: string, name: string): PatternMatch | null {
  // an archive member: `lib.a(foo.o)` is built by putting `foo.o` into `lib.a` with $(AR) - a program a variable names
  if (pattern === '(%)') {
    const member = /^[^()]+\(([^()]+)\)$/.exec(name)?.[1];
    return member === undefined ? null : { stem: member, dir: '', bare: member };
  }
  const dir = pattern.includes('/') ? '' : name.slice(0, name.lastIndexOf('/') + 1);
  const bare = patternStem(pattern, name.slice(dir.length));
  return bare === null ? null : { stem: dir + bare, dir, bare };
}
/** The prerequisite of a pattern rule for one match: the stem replaces the `%`. */
export const stemmed = (prereq: string, m: PatternMatch): string => (prereq.includes('/') ? '' : m.dir) + prereq.replace(/%/g, m.bare);

export interface BuiltinHit {
  readonly rule: BuiltinRule;
  readonly stem: string;
  /** the prerequisites with the stem put in */
  readonly prereqs: string[];
}

/** The suffixes make knows (its `.SUFFIXES`): a name that ends in one "indicates a specific type of data". */
export const BUILTIN_SUFFIXES: readonly string[] = [
  '.out', '.a', '.ln', '.o', '.c', '.cc', '.C', '.cpp', '.p', '.f', '.F', '.m', '.r', '.y', '.l', '.ym', '.lm', '.s', '.S', '.mod', '.sym', '.def',
  '.h', '.info', '.dvi', '.tex', '.texinfo', '.texi', '.txinfo', '.w', '.ch', '.web', '.sh', '.elc', '.el',
];

/**
 * THE BUILT-IN RULES THAT CAN BUILD `name`: every rule whose target pattern matches it and whose prerequisites are all there, or
 * can be built by another built-in rule (one level of chaining is what `foo` <- `foo.o` <- `foo.c` needs). `available` says whether a
 * FILE is there (on the disk, written earlier on the line, made by a rule of the makefile). All matching rules are returned, not the
 * first: make takes the first whose prerequisites exist, and which that is depends on files this reader sees only as a listing - the
 * union is the direction that over-reads rather than under-reads.
 *
 * A MATCH-ANYTHING RULE (`%: %.c`) IS NOT A RULE FOR EVERY NAME. make does not apply one to a prerequisite of another implicit rule or to a
 * name that already indicates a kind of data (`foo.o`, `foo.c`): without that, `foo` <- `foo.o` <- `foo.o.o` <- ... has no end, and a
 * reader that is told every file may have been written (a ledger entry for "anything") followed it until the work bound ended the decision.
 */
export function builtinRulesFor(name: string, available: (file: string) => boolean, viaImplicit = false): BuiltinHit[] {
  const hits: BuiltinHit[] = [];
  const typed = BUILTIN_SUFFIXES.some((s) => name.length > s.length && name.endsWith(s));
  for (const rule of BUILTIN_RULES) {
    if (rule.target === '%' && (viaImplicit || typed)) continue;
    const m = matchPatternRule(rule.target, name);
    if (m === null) continue;
    const prereqs = rule.prereqs.map((p) => stemmed(p, m));
    const ok = prereqs.every((p) => available(p) || (!viaImplicit && builtinRulesFor(p, available, true).length > 0));
    if (ok) hits.push({ rule, stem: m.stem, prereqs });
  }
  return hits;
}

/**
 * THE VARIABLES THE BUILT-IN TEXT READS BUT MAKE DOES NOT DEFINE (`CFLAGS`, `CPPFLAGS`, `LDFLAGS`, `LDLIBS`, `TARGET_ARCH`...): the
 * documented knobs of the implicit rules, which make leaves empty and takes from the environment or the command line when someone sets
 * them. Derived from the two tables above - every reference the default variables and the rule recipes make that no default defines -
 * so a rule added to the table brings its own knobs. One that nobody set on this command line is empty: the environment it could come
 * from is the user's own, and the ones an agent can set (a prefix assignment, `export`, the command line) are read before this is asked.
 */
export const IMPLICIT_RULE_INPUTS: ReadonlySet<string> = (() => {
  const defined = new Set(BUILTIN_VARIABLES.map(([n]) => n));
  const used = new Set<string>();
  const texts = [...BUILTIN_VARIABLES.map(([, v]) => v), ...BUILTIN_RULES.flatMap((r) => r.recipes)];
  for (const t of texts) for (const m of t.matchAll(/\$[({]([A-Za-z_][A-Za-z0-9_.,-]*)[)}]/g)) used.add(m[1]!);
  return new Set([...used].filter((n) => !defined.has(n) && !/^(MAKE$|MAKE_|CHECKOUT)/.test(n)));
})();
