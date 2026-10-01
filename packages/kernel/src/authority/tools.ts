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
  | 'chdir';

export interface ToolTable {
  grammar: Grammar;
  /** canonical option name -> what its value is */
  roles: Record<string, Role>;
  /** the table lists EVERY long option the tool has, so an abbreviation can be rewritten to the option it means; a partial
   *  table only finds the options it lists and must not guess what an abbreviation of an option it does not list means */
  complete?: boolean;
}

export interface ToolEffects {
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
};

// ---- git subcommands that write, and the options that name where --------------------------------------------------------------
const GIT_CHECKOUT_INDEX = gnu(['-a|--all', '-f|--force', '-n|--no-create', '-q|--quiet', '-u|--index', '--prefix:v', '--stage:v', '--temp', '-z', '--stdin', '--ignore-skip-worktree-bits']);
const GIT_ARCHIVE = gnu(['-l|--list', '-v|--verbose', '--format:v', '-0', '-1', '-2', '-3', '-4', '-5', '-6', '-7', '-8', '-9', '--worktree-attributes', '--mtime:v', '-o|--output:v', '--remote:v', '--exec:v', '--prefix:v', '--add-file:v', '--add-virtual-file:v']);
const GIT_BUNDLE = gnu(['--progress', '--quiet', '-q', '--all', '--version:v']);
const GIT_FORMAT_PATCH = gnu([
  '-o|--output-directory:v', '--output:v', '--stdout', '--cover-letter', '--attach:o', '--inline:o', '--thread:o', '-n|--numbered', '-N|--no-numbered', '-k|--keep-subject',
  '-s|--signoff', '--start-number:v', '--zero-commit', '--no-stat', '-p|--no-stat', '--subject-prefix:v', '--cc:v', '--to:v', '--from:o', '--in-reply-to:v', '--base:v',
  '--range-diff:v', '--creation-factor:v', '--interdiff:v', '-v|--reroll-count:v', '--rfc', '--filename-max-length:v', '--notes:o', '--no-notes', '--signature:v', '--signature-file:v',
  '--suffix:v', '-U|--unified:v', '-q|--quiet',
], { numeric: true });
const GIT_DIFFLIKE = gnu(['--output:v']);
const GIT_CLONE = gnu(['--separate-git-dir:v', '--template:v', '-u|--upload-pack:v', '--reference:v', '--reference-if-able:v', '-o|--origin:v', '-b|--branch:v', '--depth:v', '-c|--config:v', '-j|--jobs:v', '--bare', '--mirror', '-l|--local', '-s|--shared', '-n|--no-checkout', '-q|--quiet', '-v|--verbose', '--progress', '--recurse-submodules:o', '--shallow-submodules', '--single-branch', '--no-tags', '--filter:v', '--sparse', '--dissociate', '--hardlinks|--no-hardlinks', '--ref-format:v', '--server-option:v', '--bundle-uri:v']);
const GIT_INIT = gnu(['--separate-git-dir:v', '--template:v', '-b|--initial-branch:v', '--shared:o', '--bare', '-q|--quiet', '--object-format:v', '--ref-format:v']);
const GIT_CONFIG = gnu(['-f|--file:v', '--global', '--system', '--local', '--worktree', '--blob:v', '-l|--list', '--get', '--get-all', '--get-regexp', '--get-urlmatch', '--unset', '--unset-all', '--add', '--replace-all', '--rename-section', '--remove-section', '-e|--edit', '--type:v', '--bool', '--int', '--path', '-z|--null', '--name-only', '--show-origin', '--show-scope', '--includes', '--no-includes', '--default:v', '--fixed-value']);
const GIT_ROLES: Record<string, Role> = { output: 'write', 'output-directory': 'writeDir', 'separate-git-dir': 'writeDir', template: 'read', 'upload-pack': 'program', exec: 'program', file: 'write', 'add-file': 'read', 'signature-file': 'read' };

export const TOOL_TABLES: Record<string, ToolTable> = {
  tar: { grammar: TAR_GRAMMAR, roles: TAR_ROLES, complete: true },
  sort: { grammar: SORT_GRAMMAR, roles: SORT_ROLES, complete: true },
  sed: { grammar: SED_GRAMMAR, roles: {}, complete: true },
  go: { grammar: GO_GRAMMAR, roles: GO_ROLES },
  cc: { grammar: CC_GRAMMAR, roles: CC_ROLES },
  'git checkout-index': { grammar: GIT_CHECKOUT_INDEX, roles: { prefix: 'writeDir' } },
  'git archive': { grammar: GIT_ARCHIVE, roles: { output: 'write', exec: 'program', 'add-file': 'read' } },
  'git bundle': { grammar: GIT_BUNDLE, roles: {} },
  'git format-patch': { grammar: GIT_FORMAT_PATCH, roles: GIT_ROLES },
  'git diff': { grammar: GIT_DIFFLIKE, roles: GIT_ROLES },
  'git clone': { grammar: GIT_CLONE, roles: GIT_ROLES },
  'git init': { grammar: GIT_INIT, roles: GIT_ROLES },
  'git config': { grammar: GIT_CONFIG, roles: GIT_ROLES },
};

/** compilers and linkers read by the `cc` table */
export const CC_HEADS = /^(gcc|g\+\+|cc|c\+\+|clang|clang\+\+|icc|icx|tcc|cpp|ld|ld\.lld|ld\.gold|lld|gfortran|nvcc|armcc|[a-z0-9_-]+-(?:linux-)?(?:gnu-)?(?:gcc|g\+\+|clang))$/;

/** The table a command is read by: the program, or the program and its subcommand (`git archive`). */
export function toolTableFor(head: string, argv: readonly string[]): { key: string; table: ToolTable; from: number } | null {
  const base = head.replace(/^.*\//, '');
  if (CC_HEADS.test(base)) return { key: 'cc', table: TOOL_TABLES['cc']!, from: 1 };
  if (base === 'tar' || base === 'gtar' || base === 'bsdtar') return { key: 'tar', table: TOOL_TABLES['tar']!, from: 1 };
  if (base === 'sort' || base === 'gsort') return { key: 'sort', table: TOOL_TABLES['sort']!, from: 1 };
  if (base === 'sed' || base === 'gsed') return { key: 'sed', table: TOOL_TABLES['sed']!, from: 1 };
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
  const out: ToolEffects = { writes: [], writeDirs: [], reads: [], programs: [], code: [], chdirs: [], parsed };
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
  return out;
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
