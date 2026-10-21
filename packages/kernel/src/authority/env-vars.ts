// WHICH ENVIRONMENT VARIABLES CAN NAME A PROGRAM OR A LIBRARY TO LOAD, AND WHAT A VALUE OF THEM POINTS AT (closure audit wave 5, U-11).
//
// Three readers used to answer this, and they drifted. The evaluator's list of names that matter (ENV_INJECT_RE), the matcher that
// said which of those are refused outright and which are asked about (an alternation of the same names, copied into matchers.md), and a
// pair of matchers that looked for `NAME=` ANYWHERE in the text of a segment - in a python heredoc, in a script that assigns its own
// variable, in `subprocess.run(cmd, shell=True)` (`SHELL=` matched the keyword argument, the matchers being case-insensitive). The
// result was an absolute refusal of `PYTHONPATH=src pytest`, `GOPATH=$HOME/go go build ./...`, `JAVA_HOME=/usr/lib/jvm/... mvn clean
// install` and of any script that said `IFS=` (45 of 6,197 ordinary commands; 13 of 121 real project shell scripts). DENY cannot be
// approved, so none of those could be run at all.
//
// So the question is answered here, once, from data:
//   - NAMES THAT CHOOSE WHAT RUNS (`PROGRAM_NAMES`) are refused: the loader (`LD_PRELOAD`), the shell's startup files (`BASH_ENV`), the
//     options of an interpreter (`NODE_OPTIONS`), git's own environment, EGO's. The evaluator emits `env-inject` for these.
//   - every other name the evaluator watches (a kubeconfig, a profile, a registry) is asked about: `env-override`.
//   - A LOCATION VARIABLE (`LOCATIONS`) chooses where a runner LOOKS - for libraries, for its toolchain, for its store - and what that
//     means depends on the VALUE, which the table reads with the path reader's help (the caller resolves each element): a location
//     inside the checkout holds code the agent could have written, whose execution the runner's own verdict already accounts for, so
//     it asks; a toolchain outside the checkout and outside the scratch space holds what the developer installed, which no governed
//     command can have written, and a store at the tool's own default location is what the tool does with no variable at all - those
//     are ordinary. A location in the scratch space (which the agent can write), one a shell fills in, one that names a credential
//     store, and any name this table does not know, keep the refusal.

/** names whose value chooses a program, a library or a startup file: the ones that are refused */
export const PROGRAM_NAMES =
  /^(?:LD_PRELOAD|LD_LIBRARY_PATH|DYLD_|BASH_ENV|ENV$|PS4|BASH_XTRACEFD|PROMPT_COMMAND|NODE_OPTIONS|PYTHONSTARTUP|PYTHONPATH|PERL5OPT|RUBYOPT|GIT_|EGO_|CLAUDE_|CODEX_|SSH_ASKPASS|SUDO_ASKPASS|SWIFT_EXEC|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|LD_AUDIT|IFS|SHELL$|XDG_CONFIG_HOME|XDG_DATA_HOME|PERL5LIB|PERLLIB|PYTHONHOME|RUBYLIB|GEM_HOME|GEM_PATH|CLASSPATH|JAVA_HOME|NODE_PATH|CARGO_HOME|RUSTUP_HOME|GOPATH|GOROOT|GOBIN|COMPOSER_HOME|GLIBC_TUNABLES|OBJC_INSERT_LIBRARIES|LUA_PATH|LUA_CPATH)/;

/** Names a bare assignment does not export: a shell variable of the script that sets it. `IFS` is never inherited by a shell (POSIX
 *  resets it at start-up) and `ENV` is read only by an interactive `sh` at its start, so `IFS=$'\n'` and `ENV=${1:-dev}` on a line of
 *  their own re-point nothing - and are how most scripts that loop over lines or choose an environment begin. An `export` of either
 *  is a declaration, and a prefix before a command is a prefix: both are read as before. */
export const SHELL_LOCAL_NAMES = /^(?:IFS|ENV)$/;

/**
 * What a location variable holds the location OF.
 *   library    a search path in front of the runner's own (PYTHONPATH, CLASSPATH, NODE_PATH): the code in it loads before the standard one
 *   toolchain  the installation the runner is (JAVA_HOME, GOROOT, PYTHONHOME): read, never written, by the runner
 *   store      the directory the tool keeps its packages and caches in, and WRITES to (GOPATH, CARGO_HOME): `defaults` are where it
 *              keeps them when the variable is not set
 */
export interface Location {
  kind: 'library' | 'toolchain' | 'store';
  /** the locations of a store that are what the tool does without the variable, under the home directory */
  defaults?: readonly string[];
}

export const LOCATIONS: Readonly<Record<string, Location>> = {
  PYTHONPATH: { kind: 'library' },
  NODE_PATH: { kind: 'library' },
  CLASSPATH: { kind: 'library' },
  RUBYLIB: { kind: 'library' },
  PERL5LIB: { kind: 'library' },
  PERLLIB: { kind: 'library' },
  GEM_PATH: { kind: 'library' },
  JAVA_HOME: { kind: 'toolchain' },
  GOROOT: { kind: 'toolchain' },
  PYTHONHOME: { kind: 'toolchain' },
  GOPATH: { kind: 'store', defaults: ['go'] },
  CARGO_HOME: { kind: 'store', defaults: ['.cargo'] },
  RUSTUP_HOME: { kind: 'store', defaults: ['.rustup'] },
  GEM_HOME: { kind: 'store', defaults: ['.gem'] },
  COMPOSER_HOME: { kind: 'store', defaults: ['.composer', '.config/composer'] },
};

/** What an element of a location value turned out to be, as the caller's path reader reads it. */
export type Whereabouts =
  /** inside a registered root, or relative to the working directory (which is one) */
  | 'workspace'
  /** the home directory's own default for a store: `~/go` for GOPATH (the caller says which relative name it is) */
  | { home: string }
  /** outside every root, outside the scratch space, and not a path any rule governs */
  | 'external'
  /** anything else: the scratch space, a credential store, a word a shell fills in, a glob */
  | 'unsafe';

export type LocationVerdict = 'refuse' | 'ask' | 'ordinary';

/** The value of an assignment `NAME=value`, quotes taken off. */
export function assignedValue(assignment: string): string {
  return assignment.slice(assignment.indexOf('=') + 1).trim().replace(/^['"]|['"]$/g, '');
}

/** the elements of a search path: `:`-separated (`;` on Windows is not a shell matter here) */
export function locationElements(value: string): string[] {
  return value.split(':').filter((e) => e !== '');
}

/**
 * How a value of a location variable is judged. `where` reads one element; a reference to the variable itself (`$PYTHONPATH:src`,
 * `${PYTHONPATH}`) adds nothing to what it already was and is not an element.
 */
export function judgeLocation(name: string, value: string, where: (element: string) => Whereabouts): LocationVerdict {
  const loc = LOCATIONS[name];
  if (loc === undefined) return 'refuse';
  const elements = locationElements(value).filter((e) => !new RegExp(`^\\$\\{?${name}(?:[:-][^}]*)?\\}?$`).test(e));
  // (an empty value points nowhere: the runner falls back to its own)
  if (elements.length === 0) return 'ordinary';
  const places = elements.map(where);
  if (places.includes('unsafe')) return 'refuse';
  if (places.includes('workspace')) return 'ask';
  // outside the checkout: a toolchain is what was installed, a store is ordinary only where the tool keeps it anyway
  if (loc.kind === 'toolchain') return 'ordinary';
  if (loc.kind === 'store')
    return places.every((p) => typeof p === 'object' && (loc.defaults ?? []).includes(p.home)) ? 'ordinary' : 'ask';
  // a library path outside the checkout adds code in front of the standard library: asked about
  return 'ask';
}
