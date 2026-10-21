// THE MODELLED TOOLS: ONE TABLE EACH, READ BY ONE PARSER (options.ts).
//
// A tool's table says which options it has, how each takes a value, and what the value IS: a file the tool writes, a directory it
// writes into, a file it reads, a program it runs, code it evaluates, a directory it changes into. The destination readers ask
// `toolEffects(tool, argv)` for "where does this write" and "what does this run", and the flag readers ask the parse for "is
// this on" - so a spelling the parser accepts (a cluster, a glued value, a unique prefix, `+n`) is a spelling every reader sees.
// Before this each question was a regex per reader, and each regex knew the spellings its author had met (independent reviews
// 7-11: RC-OPT, RC-WRT).
//
// The tables are the tools' DOCUMENTED option sets. An option a table does not list is reported as unknown by the parser and
// never silently read as a flag that takes nothing; a long option cut to a prefix is resolved against the table's names, and
// an ambiguous one answers for every candidate (fail-closed).

import { type Grammar, type Parsed, type ParsedOption, has, isOn, lastOf, parseOptions, resolveLong, valuesOf } from './options.ts';

/** What an option's value IS. */
export type Role =
  /** a file the tool writes */
  | 'write'
  /** a directory the tool writes into (its contents are not enumerated) */
  | 'writeDir'
  /** a file the tool reads */
  | 'read'
  /** a program the tool runs */
  | 'program'
  /** a program the tool runs when the value names a PATH (`-fuse-ld=lld` selects a linker by name, `-fuse-ld=./x` runs a file) */
  | 'programPath'
  /** a command line or code the tool evaluates */
  | 'code'
  /** a directory the tool changes into before it does anything else */
  | 'chdir'
  /** a configuration file the tool loads: a script one is a program, a data one is a program when it NAMES one (plugins, hooks) */
  | 'config'
  /** a module the tool imports, named by a PATH (`./fmt.js`, `/abs/x.mjs`, `x.cjs`): a program. A bare package name is resolved from
   *  the installed dependencies, whose closure is not this table's business */
  | 'modulePath'
  /** a Python module the interpreter imports by NAME: from the working directory first, so a file of that name there is what runs */
  | 'pythonModule';

export interface ToolTable {
  grammar: Grammar;
  /** canonical option name -> what its value is */
  roles: Record<string, Role>;
  /** the table lists EVERY long option the tool has, so an abbreviation can be rewritten to the option it means; a partial
   *  table only finds the options it lists and must not guess what an abbreviation of an option it does not list means */
  complete?: boolean;
}

export interface ToolEffects {
  /** which table read the command (`tar`, `go`, `git archive`...) */
  key: string;
  /** configuration files named on the command line */
  configs: string[];
  /** Python modules named on the command line, to be looked up beside the command */
  pythonModules: string[];
  writes: string[];
  writeDirs: string[];
  reads: string[];
  programs: string[];
  code: string[];
  chdirs: string[];
  /** the parse, for the readers that ask about flags (`isOn`, `has`) */
  parsed: Parsed;
}

const gnu = (options: string[], extra: Partial<Grammar> = {}): Grammar => ({ style: 'gnu', options, ...extra });

// ---- tar ---------------------------------------------------------------------------------------------------------------------
// GNU tar 1.35 `--help`, every option. The long names are the point: `--extr`, `--use=`, `--dir=` are all unique prefixes tar
// accepts, and a reader that knows `--extract` and `--use-compress-program` as exact strings sees none of them.
const TAR_GRAMMAR = gnu([
  // main operations
  '-A|--catenate|--concatenate', '-c|--create', '-d|--diff|--compare', '--delete', '-r|--append', '-t|--list', '--test-label', '-u|--update',
  '-x|--extract|--get',
  // operation modifiers
  '--check-device', '--no-check-device', '-g|--listed-incremental:v', '-G|--incremental', '--hole-detection:v', '--ignore-failed-read',
  '--level:v', '-n|--seek', '--no-seek', '--occurrence:o', '--sparse-version:v', '-S|--sparse',
  // overwrite control
  '-k|--keep-old-files', '--keep-directory-symlink', '--keep-newer-files', '--no-overwrite-dir', '--one-top-level:o', '--overwrite',
  '--overwrite-dir', '--recursive-unlink', '--remove-files', '--skip-old-files', '-U|--unlink-first', '-W|--verify',
  // output stream
  '--ignore-command-error', '--no-ignore-command-error', '-O|--to-stdout', '--to-command:v',
  // file attributes
  '--atime-preserve:o', '--delay-directory-restore', '--no-delay-directory-restore', '--group:v', '--group-map:v', '--mode:v', '--mtime:v',
  '-m|--touch', '--no-same-owner', '--no-same-permissions', '--numeric-owner', '--owner:v', '--owner-map:v', '-p|--preserve-permissions|--same-permissions',
  '--preserve', '--same-owner', '-s|--preserve-order|--same-order', '--sort:v', '--acls', '--no-acls', '--selinux', '--no-selinux', '--xattrs',
  '--no-xattrs', '--xattrs-exclude:v', '--xattrs-include:v', '--clamp-mtime',
  // device selection and switching
  '-f|--file:v', '--force-local', '-F|--info-script|--new-volume-script:v', '-L|--tape-length:v', '-M|--multi-volume', '--rmt-command:v',
  '--rsh-command:v', '--volno-file:v',
  // device blocking
  '-b|--blocking-factor:v', '-B|--read-full-records', '-i|--ignore-zeros', '--record-size:v',
  // archive format and compression
  '-H|--format:v', '--old-archive', '--portability', '--pax-option:v', '--posix', '-V|--label:v', '-o', '-j|--bzip2', '-J|--xz', '--lzip', '--lzma',
  '--lzop', '--no-auto-compress', '-z|--gzip|--gunzip|--ungzip', '-Z|--compress|--uncompress', '--zstd', '-a|--auto-compress', '-I|--use-compress-program:v',
  // local file selection
  '--add-file:v', '--backup:o', '-C|--directory|--cd:v', '--exclude:v', '--exclude-backups', '--exclude-caches', '--exclude-caches-all',
  '--exclude-caches-under', '--exclude-tag:v', '--exclude-tag-all:v', '--exclude-tag-under:v', '--exclude-vcs', '--exclude-vcs-ignores',
  '--exclude-ignore:v', '--exclude-ignore-recursive:v', '--no-null', '--no-recursion', '--no-unquote', '--no-verbatim-files-from', '--null',
  '--one-file-system', '-P|--absolute-names', '--recursion', '--suffix:v', '-T|--files-from:v', '--unquote', '--verbatim-files-from',
  '-X|--exclude-from:v', '-h|--dereference', '--hard-dereference', '-K|--starting-file:v', '-N|--newer|--after-date:v', '--newer-mtime:v',
  // transformations and matching
  '--strip-components:v', '--transform|--xform:v', '--anchored', '--no-anchored', '--ignore-case', '--no-ignore-case', '--no-wildcards',
  '--no-wildcards-match-slash', '--wildcards', '--wildcards-match-slash',
  // informative output
  '--checkpoint:o', '--checkpoint-action:v', '--full-time', '--index-file:v', '-l|--check-links', '--no-quote-chars:v', '--quote-chars:v',
  '--quoting-style:v', '-R|--block-number', '--show-defaults', '--show-omitted-dirs', '--show-snapshot-field-ranges', '--show-transformed-names|--show-stored-names',
  '--totals:o', '-v|--verbose', '--warning:v', '-w|--interactive|--confirmation', '--restrict', '--utc', '--version', '--help', '--usage', '-?',
  '-0', '-1', '-2', '-3', '-4', '-5', '-6', '-7', '-y', '-e', '-q', '-Y',
]);
const TAR_ROLES: Record<string, Role> = {
  'use-compress-program': 'program',
  'to-command': 'program',
  'checkpoint-action': 'program',
  'info-script': 'program',
  'rmt-command': 'program',
  'rsh-command': 'program',
  'files-from': 'read',
  'exclude-from': 'read',
  'add-file': 'read',
  'group-map': 'read',
  'owner-map': 'read',
  'exclude-ignore': 'read',
  'volno-file': 'write',
  'index-file': 'write',
  'listed-incremental': 'write',
  directory: 'chdir',
};

// ---- sed -----------------------------------------------------------------------------------------------------------------------
export const SED_GRAMMAR: Grammar = gnu([
  '-n|--quiet|--silent', '-e|--expression:v', '-f|--file:v', '-i|--in-place:o', '-E|-r|--regexp-extended', '-s|--separate', '-u|--unbuffered',
  '-z|--null-data|--zero-terminated', '-l|--line-length:v', '-b|--binary', '--posix', '--debug', '--sandbox', '--follow-symlinks', '--help', '--version',
]);

// ---- the shells ------------------------------------------------------------------------------------------------------------
// `+n` turns a flag `-n` turned on back off, so the LAST of them decides; `-o noexec` / `+o noexec` is the same flag by name.
// EVERY LETTER IS A FLAG EXCEPT `-o` / `-O`, which name an option (`-o pipefail`, `-O extglob`): bash, dash, ksh and zsh all read them
// that way, and the union of their single letters is what a cluster may contain (`-euxo pipefail`, `-ec`, `-cx`).
const SHELL_LETTERS = 'abcdefghijklmnpqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ'.split('').map((c) => `-${c}`);
export const SHELL_GRAMMAR: Grammar = gnu(
  [...SHELL_LETTERS, '-o:v', '-O:v', '--rcfile|--init-file:v', '--login', '--noediting', '--noprofile', '--norc', '--posix', '--restricted', '--verbose',
    '--version', '--help', '--debugger', '--dump-po-strings', '--dump-strings', '--pretty-print', '--noexec'],
  { stopAtOperand: true, plus: true },
);

// ---- awk -------------------------------------------------------------------------------------------------------------------------
// gawk's long options are matched by any unique prefix: `--incl=inplace` rewrites its input file, `--fi prog.awk` takes its program from
// a file, `--prof=FILE` writes a profile. The options with an OPTIONAL value (`-p[FILE]`, `-d[FILE]`, `-o[FILE]`, `-D[FILE]`) take it glued only.
export const AWK_GRAMMAR = gnu([
  '-F|--field-separator:v', '-f|--file|--source-file:v', '-v|--assign:v', '-b|--characters-as-bytes', '-c|--traditional', '-C|--copyright', '-d|--dump-variables:o',
  '-D|--debug:o', '-e|--source:v', '-E|--exec:v', '-g|--gen-pot', '-h|--help', '-i|--include:v', '-l|--load:v', '-L|--lint:o', '-M|--bignum',
  '-n|--non-decimal-data', '-N|--use-lc-numeric', '-o|--pretty-print:o', '-O|--optimize', '-p|--profile:o', '-P|--posix', '-r|--re-interval',
  '-s|--no-optimize', '-S|--sandbox', '-t|--lint-old', '-V|--version', '--csv', '--ignore-case', '--persist:o', '--trace', '--disable-extensions',
]);
const AWK_ROLES: Record<string, Role> = {
  'dump-variables': 'write',
  debug: 'write',
  'pretty-print': 'write',
  profile: 'write',
};

// ---- sort ----------------------------------------------------------------------------------------------------------------------
const SORT_GRAMMAR = gnu([
  '-b|--ignore-leading-blanks', '-d|--dictionary-order', '-f|--ignore-case', '-g|--general-numeric-sort', '-i|--ignore-nonprinting', '-M|--month-sort',
  '-h|--human-numeric-sort', '-n|--numeric-sort', '-R|--random-sort', '--random-source:v', '-r|--reverse', '--sort:v', '-V|--version-sort',
  '--batch-size:v', '-c|--check:o', '-C', '--compress-program:v', '--debug', '--files0-from:v', '-k|--key:v', '-m|--merge', '-o|--output:v',
  '-s|--stable', '-S|--buffer-size:v', '-t|--field-separator:v', '-T|--temporary-directory:v', '--parallel:v', '-u|--unique', '-z|--zero-terminated',
  '--help', '--version',
]);
const SORT_ROLES: Record<string, Role> = {
  output: 'write',
  'compress-program': 'program',
  'files0-from': 'read',
  'random-source': 'read',
  'temporary-directory': 'writeDir',
};

// ---- go ------------------------------------------------------------------------------------------------------------------------
// Go's `flag` package: `-o=path` is the path, `-o path` is the path, `--o=path` is the path; there are no clusters and no
// abbreviations. `go test` also takes `-test.*` spellings of the test flags.
const GO_GRAMMAR: Grammar = {
  style: 'go',
  options: [
    '-a', '-n', '-p:v', '-race', '-msan', '-asan', '-cover', '-covermode:v', '-coverpkg:v', '-v', '-work', '-x', '-asmflags:v', '-buildmode:v', '-buildvcs:v',
    '-compiler:v', '-gccgoflags:v', '-gcflags:v', '-installsuffix:v', '-ldflags:v', '-linkshared', '-mod:v', '-modcacherw', '-modfile:v', '-overlay:v',
    '-pgo:v', '-pkgdir:v', '-tags:v', '-trimpath', '-toolexec:v', '-o:v', '-i', '-C:v', '-json', '-c', '-exec:v', '-bench:v', '-benchmem', '-benchtime:v',
    '-count:v', '-cpu:v', '-failfast', '-fuzz:v', '-fuzztime:v', '-fuzzminimizetime:v', '-run:v', '-short', '-shuffle:v', '-timeout:v', '-vet:v',
    '-coverprofile:v', '-cpuprofile:v', '-memprofile:v', '-memprofilerate:v', '-blockprofile:v', '-blockprofilerate:v', '-mutexprofile:v',
    '-mutexprofilefraction:v', '-outputdir:v', '-trace:v', '-parallel:v', '-list:v', '-skip:v', '-fullpath', '-args', '-test.coverprofile:v',
    '-test.cpuprofile:v', '-test.memprofile:v', '-test.blockprofile:v', '-test.mutexprofile:v', '-test.trace:v', '-test.outputdir:v', '-test.o:v',
    '-test.run:v', '-test.v', '-test.count:v', '-test.timeout:v', '-test.bench:v', '-test.short', '-test.failfast', '-test.paniconexit0',
    '-test.testlogfile:v', '-test.fuzzcachedir:v',
  ],
};
const GO_ROLES: Record<string, Role> = {
  o: 'write',
  coverprofile: 'write',
  cpuprofile: 'write',
  memprofile: 'write',
  blockprofile: 'write',
  mutexprofile: 'write',
  trace: 'write',
  modfile: 'write',
  'test.coverprofile': 'write',
  'test.cpuprofile': 'write',
  'test.memprofile': 'write',
  'test.blockprofile': 'write',
  'test.mutexprofile': 'write',
  'test.trace': 'write',
  'test.testlogfile': 'write',
  outputdir: 'writeDir',
  'test.outputdir': 'writeDir',
  pkgdir: 'writeDir',
  overlay: 'read',
  toolexec: 'program',
  exec: 'program',
  C: 'chdir',
};

// ---- C compilers and linkers -------------------------------------------------------------------------------------------------
// A compiler's options are single-dash WORDS read by longest prefix (`-MF`, `-fuse-ld=`, `-Idir`, `-ofile`), not clusters.
const CC_GRAMMAR: Grammar = {
  style: 'cc',
  options: [
    '-o:v', '-MF:v', '-MJ:v', '-MT:v', '-MQ:v', '-MD', '-MMD', '-MM', '-M', '-MP', '-MG', '-save-temps', '-save-temps=:j', '--save-temps=:j',
    '-fuse-ld=:j', '--ld-path=:j', '-B:v', '-wrapper:v', '-specs=:j', '--specs=:j', '-fplugin=:j', '-fplugin-arg-:j', '-Xclang:s', '-Xlinker:s',
    '-Xassembler:s', '-Xpreprocessor:s', '-Wl,:j', '-Wa,:j', '-Wp,:j', '-include:s', '-imacros:s', '-isystem:s', '-iquote:s', '-idirafter:s',
    '-I:v', '-L:v', '-l:v', '-D:v', '-U:v', '-x:v', '-c', '-S', '-E', '-g', '-shared', '-static', '-pipe', '-v', '-w', '-pthread',
    '--output=:j', '-isysroot:s', '--sysroot=:j', '-target:s', '--target=:j', '-fprofile-generate=:j', '-fprofile-use=:j', '-fprofile-dir=:j',
    '-ftime-report', '-fdump-tree-all', '-gen-cdb-fragment-path:s',
    // the other files a compiler writes: clang's serialized diagnostics (`--serialize-diagnostics F`, also spelled with one dash), its
    // optimization record and time trace, GCC's/clang's dump directory, and the crash reproducer directory (PA-14)
    '--serialize-diagnostics:v', '-serialize-diagnostics:v', '-foptimization-record-file=:j', '-ftime-trace=:j', '-fcrash-diagnostics-dir=:j',
    '-dumpdir:v', '-dumpbase:v',
  ],
};
const CC_ROLES: Record<string, Role> = {
  o: 'write',
  MF: 'write',
  MJ: 'write',
  'save-temps': 'writeDir',
  'fuse-ld': 'programPath',
  'ld-path': 'program',
  B: 'program',
  wrapper: 'program',
  specs: 'program',
  fplugin: 'program',
  output: 'write',
  'fprofile-dir': 'writeDir',
  'fprofile-generate': 'writeDir',
  'serialize-diagnostics': 'write',
  'foptimization-record-file': 'write',
  'ftime-trace': 'write',
  'fcrash-diagnostics-dir': 'writeDir',
  dumpdir: 'writeDir',
};

/** What the linker or the assembler is handed through a compiler's `-Wl,A,B` / `-Wa,A,B`: a comma-separated list of ITS options, and the ones that name a
 *  file it writes are the link map (`-Map=F`, `-Map,F`, `--Map=F`), its output (`-o,F`, `--output=F`) and the assembler's listing (`-al=F`, `-a=F`)
 *  (PA-14). They were an opaque `:j` value: the compiler's table read the option and not what is inside it. */
export function passThroughWrites(name: string, value: string): string[] {
  const parts = value.split(',');
  const out: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i]!;
    let m = /^-{1,2}(?:Map|output|dependency-file)=(.+)$/.exec(p) ?? (name === 'Wa,' ? /^-a[a-z]*=(.+)$/.exec(p) : null);
    if (m) {
      out.push(m[1]!);
      continue;
    }
    m = /^-{1,2}(?:Map|output|o)$/.exec(p);
    if (m && parts[i + 1] !== undefined) out.push(parts[++i]!);
  }
  return out;
}

// ---- mktemp ---------------------------------------------------------------------------------------------------------------------
// `mktemp TEMPLATE` CREATES a file (or, with -d, a directory) at the template: `mktemp .git/hooks/zz.XXXX` made a file in a governed tree, and
// `mktemp -p DIR` / `--tmpdir=DIR` creates one in DIR. -u (--dry-run) only prints a name. BSD's `-t PREFIX` and GNU's `-t` (a flag) both put the
// file in the temporary directory, so the template is not a path of the working directory then (PA-14).
const MKTEMP_GRAMMAR = gnu(['-d|--directory', '-u|--dry-run', '-q|--quiet', '-t', '-p:v', '--tmpdir:o', '--suffix:v', '--help', '--version']);
const MKTEMP_ROLES: Record<string, Role> = { p: 'writeDir', tmpdir: 'writeDir' };

// ---- linters and formatters that LOAD what their options name ----------------------------------------------------------------------
// These are in the bounded vocabulary because they execute nothing they were not named for - and a formatter, a parser, a plugin, a
// configuration or an init hook named on the command line IS something they were named for (independent review 11, RC-RUN rows).
const ESLINT_GRAMMAR = gnu([
  '-c|--config:v', '--no-config-lookup', '--no-eslintrc', '--env:v', '--ext:v', '--global:v', '--parser:v', '--parser-options:v', '--resolve-plugins-relative-to:v',
  '--plugin:v', '--rule:v', '--rulesdir:v', '--fix', '--fix-dry-run', '--fix-type:v', '--ignore-path:v', '--no-ignore', '--ignore-pattern:v', '--stdin',
  '--stdin-filename:v', '-o|--output-file:v', '-f|--format:v', '--color', '--no-color', '--max-warnings:v', '--quiet', '--debug', '--cache',
  '--cache-location:v', '--cache-strategy:v', '--no-inline-config', '--report-unused-disable-directives', '--exit-on-fatal-error', '--no-warn-ignored',
  '--init', '--inspect-config', '--flag:v', '--concurrency:v', '--stats', '--pass-on-no-patterns', '-h|--help', '-v|--version', '--print-config:v', '--no-error-on-unmatched-pattern',
]);
const ESLINT_ROLES: Record<string, Role> = {
  config: 'config',
  format: 'modulePath',
  parser: 'modulePath',
  plugin: 'modulePath',
  rulesdir: 'program',
  'output-file': 'write',
  'cache-location': 'write',
};
const PRETTIER_GRAMMAR = gnu([
  '--config:v', '--config-precedence:v', '--no-config', '--ignore-path:v', '--plugin:v', '-w|--write', '-c|--check', '-l|--list-different', '--cache',
  '--cache-location:v', '--cache-strategy:v', '--log-level:v', '--stdin-filepath:v', '--parser:v', '--no-editorconfig', '--no-error-on-unmatched-pattern',
  '--ignore-unknown|-u', '--with-node-modules', '--find-config-path:v', '--file-info:v', '--support-info', '--color', '--no-color', '--insert-pragma',
  '--require-pragma', '--tab-width:v', '--use-tabs', '--print-width:v', '--no-semi', '--single-quote', '--trailing-comma:v', '--end-of-line:v', '-h|--help', '-v|--version',
]);
const PRETTIER_ROLES: Record<string, Role> = { config: 'config', plugin: 'modulePath', parser: 'modulePath', 'cache-location': 'write' };
const PYLINT_GRAMMAR = gnu([
  '--rcfile:v', '--init-hook:v', '--load-plugins:v', '-j|--jobs:v', '--ignore:v', '--ignore-patterns:v', '--ignore-paths:v', '-d|--disable:v', '-e|--enable:v',
  '-f|--output-format:v', '-r|--reports:v', '-s|--score:v', '--msg-template:v', '--fail-under:v', '--fail-on:v', '--max-line-length:v', '--py-version:v',
  '--persistent:v', '--recursive:v', '-v|--verbose', '-E|--errors-only', '--generate-rcfile', '--list-msgs', '--help-msg:v', '--from-stdin', '--output:v', '--confidence:v',
  '--ignored-modules:v', '--extension-pkg-allow-list:v', '--suggestion-mode:v', '--clear-cache-post-run:v', '--bad-names:v', '-h|--help', '--version',
]);
const PYLINT_ROLES: Record<string, Role> = { rcfile: 'config', 'init-hook': 'code', 'load-plugins': 'pythonModule', output: 'write' };
// `python -m MOD` imports MOD from the working directory FIRST, so a file called MOD.py there is the program that runs
export const PYTHON_GRAMMAR = gnu(
  ['-B', '-b', '-d', '-E', '-i', '-I', '-O', '-P', '-q', '-s', '-S', '-u', '-v', '-V|--version', '-x', '-h|-?|--help', '-W:v', '-X:v', '--check-hash-based-pycs:v', '-c:c', '-m:c'],
  { stopAtOperand: true },
);
const PYTHON_ROLES: Record<string, Role> = { m: 'pythonModule' };

// ---- the network and copy tools: the files they write besides the one they were asked for -------------------------------------------
// wget's long options are matched by any unique prefix (`--output-doc=`, `--directory=`), rsync's too, and cargo's `--target-dir` takes
// `=` or a space: a regex of the spellings its author had met named none of them (independent review 11, RC-WRT).
const WGET_GRAMMAR = gnu([
  '-O|--output-document:v', '-o|--output-file:v', '-a|--append-output:v', '-P|--directory-prefix:v', '--save-cookies:v', '--load-cookies:v',
  '-i|--input-file:v', '--post-file:v', '--ca-certificate:v', '--certificate:v', '--private-key:v', '--config:v', '--hsts-file:v', '--warc-file:v',
  '--rejected-log:v', '-e|--execute:v', '-q|--quiet', '-v|--verbose', '-r|--recursive', '-N|--timestamping', '-c|--continue', '-nc|--no-clobber',
  '-nd|--no-directories', '-x|--force-directories', '-nH|--no-host-directories', '--save-headers', '-U|--user-agent:v', '--header:v', '-t|--tries:v',
  '-T|--timeout:v', '--no-check-certificate', '--no-verbose', '-S|--server-response', '--spider', '-b|--background', '-l|--level:v', '-np|--no-parent',
  '-A|--accept:v', '-R|--reject:v', '--user:v', '--password:v', '--http-user:v', '--http-password:v', '--limit-rate:v', '-h|--help', '-V|--version',
]);
const WGET_ROLES: Record<string, Role> = {
  'output-document': 'write',
  'output-file': 'write',
  'append-output': 'write',
  'directory-prefix': 'writeDir',
  'save-cookies': 'write',
  'hsts-file': 'write',
  'warc-file': 'write',
  'rejected-log': 'write',
  'load-cookies': 'read',
  'input-file': 'read',
  'post-file': 'read',
  'ca-certificate': 'read',
  certificate: 'read',
  'private-key': 'read',
  config: 'read',
};
// ---- curl: every file it writes besides the body (closure audit wave 5, U-18) ---------------------------------------------------------
// curl has a dozen options that name a file it WRITES, and the reader of record was a list of the ones its author had met
// (`--dump-header`, `--cookie-jar`, `--trace`, `--stderr`, `--etag-save`, `--hsts`): `--libcurl FILE`, `--alt-svc FILE`, `--ssl-sessions FILE`
// and `-w '%output{FILE}'` wrote a git hook at ASK, while the six listed ones into the same path were absolute. The table below is
// curl's own `--help all` (8.7.1, every option and whether it takes a value, plus the ones later releases added), read by the one
// parser; the roles say which values are files written. A `-w` format carries its destination INSIDE the value (`%output{FILE}`,
// `%output{>>FILE}`), which toolEffects reads for this table.
const CURL_GRAMMAR = gnu(
  (
      '--abstract-unix-socket:v --alt-svc:v --anyauth -a|--append --aws-sigv4:v --basic --ca-native --cacert:v --capath:v -E|--cert:v --cert-status ' +
      '--cert-type:v --ciphers:v --compressed --compressed-ssh -K|--config:v --connect-timeout:v --connect-to:v -C|--continue-at:v -b|--cookie:v ' +
      '-c|--cookie-jar:v --create-dirs --create-file-mode:v --crlf --crlfile:v --curves:v -d|--data:v --data-ascii:v --data-binary:v --data-raw:v ' +
      '--data-urlencode:v --delegation:v --digest -q|--disable --disable-eprt --disable-epsv --disallow-username-in-url --dns-interface:v ' +
      '--dns-ipv4-addr:v --dns-ipv6-addr:v --dns-servers:v --doh-cert-status --doh-insecure --doh-url:v -D|--dump-header:v --egd-file:v --engine:v ' +
      '--etag-compare:v --etag-save:v --expect100-timeout:v -f|--fail --fail-early --fail-with-body --false-start -F|--form:v --form-escape ' +
      '--form-string:v --ftp-account:v --ftp-alternative-to-user:v --ftp-create-dirs --ftp-method:v --ftp-pasv -P|--ftp-port:v --ftp-pret ' +
      '--ftp-skip-pasv-ip --ftp-ssl-ccc --ftp-ssl-ccc-mode:v --ftp-ssl-control -G|--get -g|--globoff --happy-eyeballs-timeout-ms:v --haproxy-clientip:v ' +
      '--haproxy-protocol -I|--head -H|--header:v -h|--help:v --hostpubmd5:v --hostpubsha256:v --hsts:v --http0.9 -0|--http1.0 --http1.1 --http2 ' +
      '--http2-prior-knowledge --http3 --http3-only --ignore-content-length -i|--include -k|--insecure --interface:v --ipfs-gateway:v -4|--ipv4 -6|--ipv6 ' +
      '--json:v -j|--junk-session-cookies --keepalive-time:v --key:v --key-type:v --krb:v --libcurl:v --limit-rate:v -l|--list-only --local-port:v ' +
      '-L|--location --location-trusted --login-options:v --mail-auth:v --mail-from:v --mail-rcpt:v --mail-rcpt-allowfails -M|--manual --max-filesize:v ' +
      '--max-redirs:v -m|--max-time:v --metalink --negotiate -n|--netrc --netrc-file:v --netrc-optional -:|--next --no-alpn -N|--no-buffer --no-clobber ' +
      '--no-keepalive --no-npn --no-progress-meter --no-sessionid --noproxy:v --ntlm --ntlm-wb --oauth2-bearer:v -o|--output:v --output-dir:v ' +
      '-Z|--parallel --parallel-immediate --parallel-max:v --pass:v --path-as-is --pinnedpubkey:v --post301 --post302 --post303 --preproxy:v ' +
      '-#|--progress-bar --proto:v --proto-default:v --proto-redir:v -x|--proxy:v --proxy-anyauth --proxy-basic --proxy-ca-native --proxy-cacert:v ' +
      '--proxy-capath:v --proxy-cert:v --proxy-cert-type:v --proxy-ciphers:v --proxy-crlfile:v --proxy-digest --proxy-header:v --proxy-http2 ' +
      '--proxy-insecure --proxy-key:v --proxy-key-type:v --proxy-negotiate --proxy-ntlm --proxy-pass:v --proxy-pinnedpubkey:v --proxy-service-name:v ' +
      '--proxy-ssl-allow-beast --proxy-ssl-auto-client-cert --proxy-tls13-ciphers:v --proxy-tlsauthtype:v --proxy-tlspassword:v --proxy-tlsuser:v ' +
      '--proxy-tlsv1 -U|--proxy-user:v --proxy1.0:v -p|--proxytunnel --pubkey:v -Q|--quote:v --random-file:v -r|--range:v --rate:v --raw -e|--referer:v ' +
      '-J|--remote-header-name -O|--remote-name --remote-name-all -R|--remote-time --remove-on-error -X|--request:v --request-target:v --resolve:v ' +
      '--retry:v --retry-all-errors --retry-connrefused --retry-delay:v --retry-max-time:v --sasl-authzid:v --sasl-ir --service-name:v -S|--show-error ' +
      '-s|--silent --socks4:v --socks4a:v --socks5:v --socks5-basic --socks5-gssapi --socks5-gssapi-nec --socks5-gssapi-service:v --socks5-hostname:v ' +
      '-Y|--speed-limit:v -y|--speed-time:v --ssl --ssl-allow-beast --ssl-auto-client-cert --ssl-no-revoke --ssl-reqd --ssl-revoke-best-effort -2|--sslv2 ' +
      '-3|--sslv3 --stderr:v --styled-output --suppress-connect-headers --tcp-fastopen --tcp-nodelay -t|--telnet-option:v --tftp-blksize:v ' +
      '--tftp-no-options -z|--time-cond:v --tls-max:v --tls13-ciphers:v --tlsauthtype:v --tlspassword:v --tlsuser:v -1|--tlsv1 --tlsv1.0 --tlsv1.1 ' +
      '--tlsv1.2 --tlsv1.3 --tr-encoding --trace:v --trace-ascii:v --trace-config:v --trace-ids --trace-time --unix-socket:v -T|--upload-file:v --url:v ' +
      '--url-query:v -B|--use-ascii -u|--user:v -A|--user-agent:v --variable:v -v|--verbose -V|--version -w|--write-out:v --xattr ' +
    '--ssl-sessions:v --ech:v --dump-ca-embed --out-null --follow --knownhosts:v --skip-existing --ip-tos:v --vlan-priority:v --tls-earlydata --upload-flags:v'
  ).split(/\s+/),
);
const CURL_ROLES: Record<string, Role> = {
  output: 'write',
  'output-dir': 'writeDir',
  'dump-header': 'write',
  'cookie-jar': 'write',
  trace: 'write',
  'trace-ascii': 'write',
  stderr: 'write',
  'etag-save': 'write',
  hsts: 'write',
  'alt-svc': 'write',
  libcurl: 'write',
  'ssl-sessions': 'write',
};
const RSYNC_GRAMMAR = gnu([
  '--log-file:v', '--backup-dir:v', '--write-batch:v', '--only-write-batch:v', '--read-batch:v', '-T|--temp-dir:v', '--partial-dir:v', '--link-dest:v',
  '--compare-dest:v', '--copy-dest:v', '-e|--rsh:v', '--rsync-path:v', '--files-from:v', '--exclude-from:v', '--include-from:v', '--password-file:v',
  '--config:v', '--exclude:v', '--include:v', '-f|--filter:v', '--bwlimit:v', '--port:v', '--timeout:v', '--chmod:v', '--chown:v', '--suffix:v',
  '-a|--archive', '-r|--recursive', '-v|--verbose', '-q|--quiet', '-z|--compress', '-n|--dry-run', '-u|--update', '-c|--checksum', '-t|--times', '-p|--perms',
  '-o|--owner', '-g|--group', '-l|--links', '-H|--hard-links', '-P', '--progress', '--partial', '--delete', '--delete-after', '--delete-before', '--delete-during',
  '--delete-excluded', '--remove-source-files', '-b|--backup', '--inplace', '--append', '-i|--itemize-changes', '-h|--human-readable', '--stats', '-x|--one-file-system',
  '-W|--whole-file', '-m|--prune-empty-dirs', '--numeric-ids', '--size-only', '--ignore-existing', '--existing', '--help', '--version',
]);
const RSYNC_ROLES: Record<string, Role> = {
  'log-file': 'write',
  'backup-dir': 'writeDir',
  'write-batch': 'write',
  'only-write-batch': 'write',
  'temp-dir': 'writeDir',
  'partial-dir': 'writeDir',
  rsh: 'program',
  'rsync-path': 'program',
  'read-batch': 'read',
  'files-from': 'read',
  'exclude-from': 'read',
  'include-from': 'read',
  'password-file': 'read',
  config: 'read',
};
const CARGO_GRAMMAR = gnu([
  '--target-dir:v', '--out-dir:v', '--artifact-dir:v', '--root:v', '--manifest-path:v', '--lockfile-path:v', '--path:v', '--timings:o', '--config:v',
  '-Z:v', '--message-format:v', '-j|--jobs:v', '-p|--package:v', '--workspace', '--all', '--exclude:v', '--lib', '--bin:v', '--bins', '--example:v',
  '--examples', '--test:v', '--tests', '--bench:v', '--benches', '--all-targets', '-F|--features:v', '--all-features', '--no-default-features', '--target:v',
  '-r|--release', '--profile:v', '--ignore-rust-version', '--locked', '--offline', '--frozen', '-v|--verbose', '-q|--quiet', '--color:v', '--keep-going',
  '--registry:v', '--index:v', '--git:v', '--branch:v', '--tag:v', '--rev:v', '--force', '-f', '--no-track', '--list', '--version:v', '--help',
]);
const CARGO_ROLES: Record<string, Role> = {
  'target-dir': 'writeDir',
  'out-dir': 'writeDir',
  'artifact-dir': 'writeDir',
  root: 'writeDir',
  'lockfile-path': 'write',
  'manifest-path': 'read',
  path: 'read',
};

// ---- git subcommands that write, and the options that name where --------------------------------------------------------------
// `git grep -O<cmd>` / `--open-files-in-pager[=<cmd>]` runs a COMMAND LINE with the matching files appended; git reads any unique prefix of the
// long name (`--open-f=`), which is why the table lists every option of the verb
const GIT_GREP = gnu(
  ['--cached', '--no-index', '--untracked', '--no-exclude-standard', '--exclude-standard', '--recurse-submodules', '--no-recurse-submodules',
    '--parent-basename:v', '-v|--invert-match', '-i|--ignore-case', '-w|--word-regexp', '-a|--text', '-I', '--textconv', '--no-textconv', '-r|--recursive',
    '--no-recursive', '-H', '-h', '--full-name', '-E|--extended-regexp', '-G|--basic-regexp', '-P|--perl-regexp', '-F|--fixed-strings', '-n|--line-number',
    '--column', '-l|--files-with-matches|--name-only', '-L|--files-without-match', '-O|--open-files-in-pager:o', '-z|--null', '-o|--only-matching',
    '-c|--count', '--all-match', '-q|--quiet', '--max-depth:v', '-m|--max-count:v', '-C|--context:v', '-A|--after-context:v', '-B|--before-context:v',
    '-W|--function-context', '-p|--show-function', '--threads:v', '-f:v', '-e:v', '--and', '--or', '--not', '--heading', '--break', '--color:o', '--no-color',
    '--no-line-number', '--no-column', '--help'],
  { numeric: true },
);
const GIT_CHECKOUT_INDEX = gnu(['-a|--all', '-f|--force', '-n|--no-create', '-q|--quiet', '-u|--index', '--prefix:v', '--stage:v', '--temp', '-z', '--stdin', '--ignore-skip-worktree-bits']);
const GIT_ARCHIVE = gnu(['-l|--list', '-v|--verbose', '--format:v', '-0', '-1', '-2', '-3', '-4', '-5', '-6', '-7', '-8', '-9', '--worktree-attributes', '--mtime:v', '-o|--output:v', '--remote:v', '--exec:v', '--prefix:v', '--add-file:v', '--add-virtual-file:v']);
const GIT_BUNDLE = gnu(['--progress', '--quiet', '-q', '--all', '--version:v']);
const GIT_FORMAT_PATCH = gnu([
  '-o|--output-directory:v', '--output:v', '--stdout', '--cover-letter', '--attach:o', '--inline:o', '--thread:o', '-n|--numbered', '-N|--no-numbered', '-k|--keep-subject',
  '-s|--signoff', '--start-number:v', '--zero-commit', '-p|--no-stat', '--subject-prefix:v', '--cc:v', '--to:v', '--from:o', '--in-reply-to:v', '--base:v',
  '--range-diff:v', '--creation-factor:v', '--interdiff:v', '-v|--reroll-count:v', '--rfc:o', '--filename-max-length:v', '--notes:o', '--no-notes', '--signature:v', '--signature-file:v',
  '--suffix:v', '-U|--unified:v', '-q|--quiet',
], { numeric: true });
const GIT_DIFFLIKE = gnu(['--output:v']);
const GIT_CLONE = gnu(['--separate-git-dir:v', '--template:v', '-u|--upload-pack:v', '--reference:v', '--reference-if-able:v', '-o|--origin:v', '-b|--branch:v', '--depth:v', '-c|--config:v', '-j|--jobs:v', '--bare', '--mirror', '-l|--local', '-s|--shared', '-n|--no-checkout', '-q|--quiet', '-v|--verbose', '--progress', '--recurse-submodules:o', '--shallow-submodules', '--single-branch', '--no-tags', '--filter:v', '--sparse', '--dissociate', '--hardlinks|--no-hardlinks', '--ref-format:v', '--server-option:v', '--bundle-uri:v']);
const GIT_INIT = gnu(['--separate-git-dir:v', '--template:v', '-b|--initial-branch:v', '--shared:o', '--bare', '-q|--quiet', '--object-format:v', '--ref-format:v']);
const GIT_CONFIG = gnu(['-f|--file:v', '--global', '--system', '--local', '--worktree', '--blob:v', '-l|--list', '--get', '--get-all', '--get-regexp', '--get-urlmatch', '--unset', '--unset-all', '--add', '--replace-all', '--rename-section', '--remove-section', '-e|--edit', '--type:v', '--bool', '--int', '--path', '-z|--null', '--name-only', '--show-origin', '--show-scope', '--includes', '--no-includes', '--default:v', '--fixed-value']);


export const TOOL_TABLES: Record<string, ToolTable> = {
  tar: { grammar: TAR_GRAMMAR, roles: TAR_ROLES, complete: true },
  sort: { grammar: SORT_GRAMMAR, roles: SORT_ROLES, complete: true },
  sed: { grammar: SED_GRAMMAR, roles: {}, complete: true },
  awk: { grammar: AWK_GRAMMAR, roles: AWK_ROLES, complete: true },
  go: { grammar: GO_GRAMMAR, roles: GO_ROLES },
  cc: { grammar: CC_GRAMMAR, roles: CC_ROLES },
  wget: { grammar: WGET_GRAMMAR, roles: WGET_ROLES },
  curl: { grammar: CURL_GRAMMAR, roles: CURL_ROLES, complete: true },
  rsync: { grammar: RSYNC_GRAMMAR, roles: RSYNC_ROLES },
  cargo: { grammar: CARGO_GRAMMAR, roles: CARGO_ROLES },
  mktemp: { grammar: MKTEMP_GRAMMAR, roles: MKTEMP_ROLES, complete: true },
  eslint: { grammar: ESLINT_GRAMMAR, roles: ESLINT_ROLES },
  prettier: { grammar: PRETTIER_GRAMMAR, roles: PRETTIER_ROLES },
  pylint: { grammar: PYLINT_GRAMMAR, roles: PYLINT_ROLES },
  python: { grammar: PYTHON_GRAMMAR, roles: PYTHON_ROLES },
  'git grep': { grammar: GIT_GREP, roles: { 'open-files-in-pager': 'code' }, complete: true },
  'git checkout-index': { grammar: GIT_CHECKOUT_INDEX, roles: { prefix: 'writeDir' } },
  'git archive': { grammar: GIT_ARCHIVE, roles: { output: 'write', exec: 'program', 'add-file': 'read' } },
  'git bundle': { grammar: GIT_BUNDLE, roles: {} },
  'git format-patch': { grammar: GIT_FORMAT_PATCH, roles: { output: 'write', 'output-directory': 'writeDir', 'signature-file': 'read' } },
  'git diff': { grammar: GIT_DIFFLIKE, roles: { output: 'write' } },
  'git clone': { grammar: GIT_CLONE, roles: { 'separate-git-dir': 'writeDir', template: 'read', 'upload-pack': 'program' } },
  'git init': { grammar: GIT_INIT, roles: { 'separate-git-dir': 'writeDir', template: 'read' } },
  'git config': { grammar: GIT_CONFIG, roles: { file: 'write' } },
};

/** compilers and linkers read by the `cc` table */
// (a compiler whose name carries its version - `gcc-13`, `clang-17`, `g++-12.2` - is the same compiler, and was read as no compiler at all)
export const CC_HEADS = /^(gcc|g\+\+|cc|c\+\+|clang|clang\+\+|icc|icx|tcc|cpp|ld|ld\.lld|ld\.gold|lld|gfortran|nvcc|armcc|[a-z0-9_-]+-(?:linux-)?(?:gnu-)?(?:gcc|g\+\+|clang))(?:-\d+(?:\.\d+)*)?$/;

/** The table a command is read by: the program, or the program and its subcommand (`git archive`). */
export function toolTableFor(head: string, argv: readonly string[]): { key: string; table: ToolTable; from: number } | null {
  const base = head.replace(/^.*\//, '');
  if (CC_HEADS.test(base)) return { key: 'cc', table: TOOL_TABLES['cc']!, from: 1 };
  if (base === 'tar' || base === 'gtar' || base === 'bsdtar') return { key: 'tar', table: TOOL_TABLES['tar']!, from: 1 };
  if (base === 'sort' || base === 'gsort') return { key: 'sort', table: TOOL_TABLES['sort']!, from: 1 };
  if (base === 'sed' || base === 'gsed') return { key: 'sed', table: TOOL_TABLES['sed']!, from: 1 };
  // (gawk and the awk that is gawk; BSD and mawk spell their options another way, and a GNU table must not rewrite theirs)
  if (base === 'awk' || base === 'gawk') return { key: 'awk', table: TOOL_TABLES['awk']!, from: 1 };
  if (base === 'eslint' || base === 'prettier' || base === 'pylint' || base === 'rsync') return { key: base, table: TOOL_TABLES[base]!, from: 1 };
  if (base === 'wget' || base === 'wget2') return { key: 'wget', table: TOOL_TABLES['wget']!, from: 1 };
  if (base === 'curl') return { key: 'curl', table: TOOL_TABLES['curl']!, from: 1 };
  if (base === 'mktemp' || base === 'gmktemp') return { key: 'mktemp', table: TOOL_TABLES['mktemp']!, from: 1 };
  if (base === 'cargo') {
    // `cargo +nightly build`: a toolchain selector comes first
    const at = argv[1]?.startsWith('+') ? 2 : 1;
    return /^(build|b|run|r|test|t|check|c|install|doc|d|bench|clippy|rustc|rustdoc|publish|package|clean|fetch|vendor|metadata|tree|update|fix|add|remove|rm|uninstall|miri|nextest|llvm-cov)$/.test(argv[at] ?? '')
      ? { key: 'cargo', table: TOOL_TABLES['cargo']!, from: at + 1 }
      : null;
  }
  if (/^(python|python2|python3|pypy|pypy3)(\.\d+)?$/.test(base)) return { key: 'python', table: TOOL_TABLES['python']!, from: 1 };
  if (base === 'go') {
    const sub = argv[1];
    return sub !== undefined && /^(build|install|test|run|vet|list|generate|get|clean|env|doc|fix|fmt|mod|work|tool|version|bug)$/.test(sub)
      ? { key: 'go', table: TOOL_TABLES['go']!, from: 2 }
      : null;
  }
  if (base === 'git') {
    const sub = argv[1];
    if (sub === 'diff' || sub === 'log' || sub === 'show' || sub === 'range-diff' || sub === 'diff-tree' || sub === 'diff-index' || sub === 'diff-files')
      return { key: 'git diff', table: TOOL_TABLES['git diff']!, from: 2 };
    const t = sub === undefined ? undefined : TOOL_TABLES[`git ${sub}`];
    return t ? { key: `git ${sub}`, table: t, from: 2 } : null;
  }
  return null;
}

/** Every role-bearing value of the command, in whatever spelling the tool's parser accepts. */
export function toolEffects(head: string, argv: readonly string[]): ToolEffects | null {
  const found = toolTableFor(head, argv);
  if (!found) return null;
  // the traditional tar spelling is the same options without their dashes (`tar xvf a.tar -C dir`)
  if (found.key === 'tar') argv = tarArgv(argv);
  // `go test -args ...` hands the rest to the test binary: they are its options, not go's
  const stop = found.key === 'go' ? argv.findIndex((w, i) => i >= found.from && (w === '-args' || w === '--args')) : -1;
  const parsed = parseOptions(found.table.grammar, stop < 0 ? argv : argv.slice(0, stop), found.from);
  const out: ToolEffects = { key: found.key, configs: [], pythonModules: [], writes: [], writeDirs: [], reads: [], programs: [], code: [], chdirs: [], parsed };
  for (const o of parsed.options) {
    if (o.value === null) continue;
    for (const name of [o.name, ...(o.candidates ?? [])]) {
      const role = found.table.roles[name];
      if (!role) continue;
      // `-o=file` is the file `=file` to a GNU or compiler parser and `file` to a Go one: both are judged
      const values = found.key === 'go' ? [o.value] : o.value.startsWith('=') ? [o.value, o.value.slice(1)] : [o.value];
      for (const v of values) bucket(out, role, v);
      break;
    }
  }
  // curl's `-w` format carries a destination inside its value: `%output{FILE}` writes FILE and `%output{>>FILE}` appends to it. A format
  // taken from a file (`-w @fmt`) is read by the evaluator, which can open files; this reads the ones written on the command line
  if (found.key === 'curl') for (const f of curlWriteOut(parsed)) for (const m of f.matchAll(/%output\{(?:>>)?([^}]*)\}/g)) out.writes.push(m[1]!);
  // what a compiler hands its linker and assembler: the files THEY write (`-Wl,-Map=F`)
  if (found.key === 'cc')
    for (const o of parsed.options)
      if ((o.name === 'Wl,' || o.name === 'Wa,') && o.value !== null) out.writes.push(...passThroughWrites(o.name, o.value));
  // `mktemp TEMPLATE` creates the template (unless it only prints a name, or the file goes to the temporary directory)
  if (found.key === 'mktemp' && !has(parsed, 'dry-run') && !has(parsed, 't')) out.writes.push(...parsed.operands.map((o) => o.text));
  // ...and `-u` creates nothing anywhere, in the directory `-p` names as much as at the template
  if (found.key === 'mktemp' && has(parsed, 'dry-run')) out.writeDirs = [];
  // `git config --file F --get KEY` (and --list, --get-all...) READS F; only a setting, an unsetting or an edit writes it
  if (found.key === 'git config' && gitConfigAsks(parsed)) {
    out.reads.push(...out.writes);
    out.writes = [];
  }
  return out;
}

/** The `-w` / `--write-out` formats of a curl command line, in whichever spelling the parser read them. */
export function curlWriteOut(parsed: Parsed): string[] {
  return parsed.options.filter((o) => o.value !== null && [o.name, ...(o.candidates ?? [])].includes('write-out')).map((o) => o.value!);
}

/** WHETHER A `git config` INVOCATION ASKS FOR A VALUE OR A LISTING AND SETS NOTHING: a get or a list option, or one bare key with
 *  nothing after it. The scope options (`--global`, `--file F`, `--blob B`) only say WHERE, and a write option anywhere (`--add`,
 *  `--unset`, `--replace-all`, `--edit`, a second operand) makes the whole line a write. An option the grammar does not know
 *  cannot be placed, and the line is not a read. ONE reader of this, asked by the table's file role (above) and by the scan that
 *  takes `--file` as an output flag for the tools that have one (`git config --file .git/config --get remote.origin.url` names the
 *  file it looks in; judged as an output it was an absolute refusal of a look - review 11, #62). */
export function gitConfigAsks(parsed: Parsed): boolean {
  if (parsed.unknown.length > 0) return false;
  if (['add', 'unset', 'unset-all', 'replace-all', 'rename-section', 'remove-section', 'edit'].some((a) => has(parsed, a))) return false;
  if (['get', 'get-all', 'get-regexp', 'get-urlmatch', 'list', 'name-only', 'show-origin', 'show-scope'].some((a) => has(parsed, a))) return true;
  return parsed.operands.length === 1;
}

function bucket(out: ToolEffects, role: Role, v: string): void {
  switch (role) {
    case 'write':
      out.writes.push(v);
      break;
    case 'writeDir':
      out.writeDirs.push(v);
      break;
    case 'read':
      out.reads.push(v);
      break;
    case 'program':
      out.programs.push(v);
      break;
    case 'programPath':
      if (/[\\/]/.test(v) || /^\.+$/.test(v)) out.programs.push(v);
      break;
    case 'modulePath':
      // a path (relative, absolute, home) or a script file name; a bare package name or a built-in (`stylish`) is not one
      if (/^(\.{1,2}\/|\/|~\/)/.test(v) || /\.(c|m)?[jt]s$|\.py$|\.rb$/.test(v)) out.programs.push(v);
      break;
    case 'config':
      out.configs.push(v);
      break;
    case 'pythonModule':
      // `pkg.mod` is looked up as `pkg`; `a,b` (pylint's plugin list) is two names
      for (const name of v.split(',')) if (name.trim()) out.pythonModules.push(name.trim().split('.')[0]!);
      break;
    case 'code':
      out.code.push(v);
      break;
    case 'chdir':
      out.chdirs.push(v);
      break;
  }
}

/** A COMMAND LINE WITH EVERY LONG OPTION IN ITS FULL SPELLING. A tool's option parser accepts any unique prefix of a long option, and
 *  the rules that match on the TEXT of the line (a program an option names, a destructive flag) know the full names only:
 *  `tar --use=./x` runs a program and `tar --rem` deletes the sources, and neither matched. Rewriting the abbreviation once, here,
 *  gives every text matcher the line the tool will read - for the tools whose table lists every long option; an abbreviation that
 *  is ambiguous, or names nothing, is left as it is. */
export function expandLongOptions(argv: readonly string[]): string[] {
  const found = toolTableFor(argv[0] ?? '', argv);
  if (!found?.table.complete) return [...argv];
  const out = [...argv];
  for (let i = found.from; i < out.length; i++) {
    const w = out[i]!;
    if (w === '--') break;
    const m = /^--([^=]+)(=[\s\S]*)?$/.exec(w);
    if (!m) continue;
    const def = resolveLong(found.table.grammar, m[1]!);
    if (def) out[i] = `--${def.name}${m[2] ?? ''}`;
  }
  return out;
}

// ---- tar: the mode, the archive and where an extraction lands --------------------------------------------------------------------
export interface TarShape {
  /** the operation letters/names that are on, canonical (`create`, `extract`, `append`, `update`, `catenate`, `delete`, `list`, `diff`) */
  ops: Set<string>;
  archive: string | null;
  /** the archive is written (create, append, update, catenate, delete) */
  writesArchive: boolean;
  extracts: boolean;
  /** the directory an extraction lands in: the cumulative `-C`s, or `.` */
  extractDir: string;
  toStdout: boolean;
  effects: ToolEffects;
}

const TAR_OPS: Record<string, string> = { create: 'create', extract: 'extract', append: 'append', update: 'update', catenate: 'catenate', delete: 'delete', list: 'list', diff: 'diff', 'test-label': 'list' };

/** The traditional first-operand spelling - `tar xvf a.tar -C dir`, `tar czf out.tgz src` - is the same options without the dash:
 *  the letters are options, and the operands that follow supply, in order, the values of the letters that take one. */
export function tarArgv(argv: readonly string[]): string[] {
  const first = argv[1];
  if (first === undefined || first.startsWith('-') || !/^[A-Za-z0-9]+$/.test(first)) return [...argv];
  const takesValue = new Set(['f', 'b', 'C', 'V', 'L', 'N', 'X', 'T', 'I', 'H', 'g', 'K']);
  const rest = argv.slice(2);
  const out: string[] = [argv[0]!];
  let used = 0;
  for (const ch of first) {
    if (takesValue.has(ch) && rest[used] !== undefined) out.push(`-${ch}`, rest[used++]!);
    else out.push(`-${ch}`);
  }
  return [...out, ...rest.slice(used)];
}

export function tarShape(argv: readonly string[]): TarShape | null {
  const effects = toolEffects('tar', argv);
  if (!effects) return null;
  const p = effects.parsed;
  const ops = new Set<string>();
  for (const o of p.options) for (const name of [o.name, ...(o.candidates ?? [])]) if (TAR_OPS[name]) ops.add(TAR_OPS[name]!);
  // the archive is the last `-f`; `-F` is a script and is a program role
  const archive = lastOf(p, 'file');
  const writesArchive = ['create', 'append', 'update', 'catenate', 'delete'].some((o) => ops.has(o));
  const extracts = ops.has('extract');
  // SUCCESSIVE `-C` ARE CUMULATIVE: tar enters each in turn, so `-C .harness -C runtime` extracts into `.harness/runtime`; taking
  // only the last one read it as `runtime` relative to the working directory, which is a different place (exit review 9)
  const cds = valuesOf(p, 'directory');
  const top = p.options.find((o) => o.name === 'one-top-level' || o.candidates?.includes('one-top-level'));
  const extractDir = top?.value ? top.value : cds.length ? cds.reduce((acc, d) => (d.startsWith('/') ? d : `${acc}/${d}`)) : '.';
  return { ops, archive, writesArchive, extracts, extractDir, toStdout: has(p, 'to-stdout'), effects };
}

// ---- sed: the script(s), the files and whether it edits in place ---------------------------------------------------------------
export interface SedProgram {
  /** script texts given by -e / --expression, or the first operand when none was */
  scripts: string[];
  /** script FILES given by -f / --file */
  scriptFiles: string[];
  inPlace: boolean;
  /** the input files */
  files: string[];
  /** options the table could not place */
  unknown: string[];
}

export function sedProgram(argv: readonly string[], from: number): SedProgram {
  const p = parseOptions(SED_GRAMMAR, argv, from);
  const scripts = valuesOf(p, 'expression');
  const scriptFiles = valuesOf(p, 'file');
  let operands = p.operands.map((x) => x.text);
  const inPlace = has(p, 'in-place');
  // BSD sed's `-i` takes the backup suffix as the NEXT word, and `-i ''` is the way to say "none": an empty word right after
  // the in-place flag is its value, not the script
  const ip = p.options.find((o) => o.name === 'in-place');
  if (ip && ip.value === null && operands[0] === '' && p.operands[0] && p.operands[0].at === ip.at + 1) operands = operands.slice(1);
  if (scripts.length === 0 && scriptFiles.length === 0 && operands.length) {
    scripts.push(operands[0]!);
    operands = operands.slice(1);
  }
  return { scripts, scriptFiles, inPlace, files: operands, unknown: p.unknown.map((u) => u.raw) };
}

// ---- the shells: a syntax check executes nothing ---------------------------------------------------------------------------------
/** True when the shell's own options leave it in NO-EXEC mode at the point the script starts: the last of `-n` / `+n` /
 *  `-o noexec` / `+o noexec` decides. `bash -n +n -c BODY` turns the check back off and RUNS the body. */
export function shellSyntaxOnly(argv: readonly string[], from: number): boolean {
  const p = parseOptions(SHELL_GRAMMAR, argv, from);
  let noexec = false;
  for (const o of p.options as ParsedOption[]) {
    if (o.name === 'n' || o.name === 'noexec') noexec = o.sign === '-';
    else if (o.name === 'o' && o.value === 'noexec') noexec = o.sign === '-';
  }
  return noexec;
}

export { has, isOn };
