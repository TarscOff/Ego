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
const WRAPPER_PAIRS: ReadonlyArray<readonly [string, string]> = [
  ['pnpm', 'exec'],
  ['pnpm', 'dlx'],
  ['yarn', 'dlx'],
  ['npm', 'exec'],
  ['bun', 'x'],
];
/** environment assignments that change what a command executes or where governance looks: never silently stripped */
const ENV_INJECT_RE =
  /^(LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]+|BASH_ENV|ENV|PROMPT_COMMAND|NODE_OPTIONS|PYTHONSTARTUP|PYTHONPATH|PERL5OPT|RUBYOPT|GIT_CONFIG[A-Z_]*|GIT_(DIR|WORK_TREE|INDEX_FILE|COMMON_DIR|SSH_COMMAND|SSH|PROXY_COMMAND|EXTERNAL_DIFF|EDITOR|PAGER|ASKPASS|CEILING_DIRECTORIES|NAMESPACE|ALTERNATE_OBJECT_DIRECTORIES|OBJECT_DIRECTORY)|EGO_[A-Z_]+|CLAUDE_[A-Z_]+|CODEX_[A-Z_]+|SSH_ASKPASS|SUDO_ASKPASS|KUBECONFIG|AWS_PROFILE|AWS_CONFIG_FILE|AWS_SHARED_CREDENTIALS_FILE|DOCKER_HOST|DOCKER_CONFIG|NPM_CONFIG_[A-Z_]+|HOME|PATH|SHELL|IFS)$/;

export function splitShellSegments(command: string): string[] {
  const segments: string[] = [];
  let cur = '';
  let inSingle = false;
  let inDouble = false;
  let i = 0;
  const push = () => {
    const t = cur.trim();
    if (t) segments.push(t);
    cur = '';
  };
  while (i < command.length) {
    const ch = command[i]!;
    const next = command[i + 1];
    if (ch === '\\' && !inSingle) {
      cur += ch + (next ?? '');
      i += 2;
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
      // a `|` preceded by `>` is the `>|` noclobber-override redirect operator, not a pipe — do not split there
      if (ch === ';' || ch === '\n' || (ch === '|' && command[i - 1] !== '>')) {
        push();
        i++;
        continue;
      }
      if (ch === '&' && next !== '&') {
        push();
        i++;
        continue;
      }
      if ((ch === '$' || ch === '<' || ch === '>') && next === '(') {
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
        for (const s of splitShellSegments(inner)) segments.push(s);
        cur += (cur.endsWith(' ') || cur === '' ? '' : ' ') + '$SUBST ';
        i = j;
        continue;
      }
      if (ch === '`') {
        const end = command.indexOf('`', i + 1);
        if (end > i) {
          for (const s of splitShellSegments(command.slice(i + 1, end))) segments.push(s);
          cur += (cur.endsWith(' ') || cur === '' ? '' : ' ') + '$SUBST ';
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
  const extra: string[] = [];
  // Assignments that SELECT THE TARGET of a database or Kubernetes client are not noise: stripping them made
  // `PGHOST=prod-db psql -c "DROP TABLE users"` read as the local socket (round 14). They are re-attached below so
  // the target resolver sees them, and are judged nowhere else.
  const targetEnv: string[] = [];
  // leading VAR=value assignments: stripped, except the ones that change what runs (surfaced as `env-inject VAR`)
  for (;;) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(?:'[^']*'|"[^"]*"|\S*)\s+/.exec(s);
    if (!m) break;
    if (ENV_INJECT_RE.test(m[1]!)) extra.push(`env-inject ${m[1]}`);
    if (TARGET_ENV_RE.test(m[1]!)) targetEnv.push(m[0].trim());
    s = s.slice(m[0].length);
  }
  // shell prefix keywords (`if git push`, `do npm test`, `then rm -rf x`) are normalization, not a safety
  // judgement: stripping them in the analyzer gives every producer AND the top level the same treatment.
  for (;;) {
    const m = /^(\S+)\s+/.exec(s);
    if (!m || !PREFIX_KEYWORDS.has(m[1]!)) break;
    s = s.slice(m[0].length).trim();
  }
  // two-word runners, stripped before wrapper handling so `pnpm exec vitest run` is `vitest run` everywhere
  for (;;) {
    const pair = WRAPPER_PAIRS.find((p) => new RegExp(`^${p[0]}\\s+${p[1]}\\s+`).test(s));
    if (!pair) break;
    s = s.replace(new RegExp(`^${pair[0]}\\s+${pair[1]}\\s+`), '');
  }
  const tokens = tokenize(s);
  if (tokens.length === 0) return extra;
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
              if (ENV_INJECT_RE.test(name)) extra.push(`env-inject ${name}`);
              if (TARGET_ENV_RE.test(name)) targetEnv.push(tokens[idx]!);
              idx++;
            }
          break;
        }
        if (t === 'env' && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) {
          // assignments passed through `env` are judged exactly like leading assignments — INCLUDING the ones that
          // select the target, which this branch used to drop (round 15)
          const name = tok.slice(0, tok.indexOf('='));
          if (ENV_INJECT_RE.test(name)) extra.push(`env-inject ${name}`);
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
    if (forced) rest = [...rest, 'force-ref-reset'];
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
    if (GIT_LONG_OPTS.includes(name!)) return t;
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

function normalizeTail(rest: string[]): string[] {
  const head = rest[0]!;
  if (head === 'bash' || head === 'sh' || head === 'zsh' || head === 'dash' || head === 'ksh' || head === 'fish') {
    // -c, or a combined short-flag cluster CONTAINING c (`-euc`, `-ec`, `-lc`, `-xc`, `-cx`) — `-c` takes the next
    // operand as the command string wherever it sits in the cluster. A `--` may separate it from that operand.
    const cIdx = rest.findIndex((t) => t === '-c' || /^-[a-z]*c[a-z]*$/i.test(t));
    if (cIdx >= 0) {
      const inner = rest[cIdx + 1] === '--' ? rest[cIdx + 2] : rest[cIdx + 1];
      if (inner) return [`${head} -c`, ...splitShellSegments(inner).flatMap(normalizeSegment)];
    }
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
    const after = rest.slice(i);
    return [rest.join(' '), ...(after.length ? [after.join(' ')] : [])];
  }
  return [rest.join(' ')];
}

/** git / gh / glab global options that may precede the subcommand; the option's argument is consumed with it. */
const GIT_GLOBAL_WITH_ARG = new Set([
  '-C',
  '-c',
  '--git-dir',
  '--work-tree',
  '--namespace',
  '--exec-path',
  '--super-prefix',
  '--config-env',
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
            `env-inject ${name === '--git-dir' ? 'GIT_DIR' : name === '--work-tree' ? 'GIT_WORK_TREE' : name === '--namespace' ? 'GIT_NAMESPACE' : 'GIT_EXEC_PATH'}`,
          );
        if (name === '-c' || name === '--config-env') {
          // an inline alias redefines a verb: `git -c alias.p=push p …` is `git push …`; an alias whose body is not a
          // literal (config-env) is an execution override the kernel cannot see
          const alias = /^alias\.([^=]+)=(.*)$/.exec(value);
          if (alias) {
            aliases.set(alias[1]!, name === '-c' ? alias[2]! : '');
            extra.push(`git alias-override ${alias[1]}`);
          }
          if (
            /^(core\.hooksPath|core\.fsmonitor|core\.editor|core\.pager|core\.sshCommand|core\.gitProxy|core\.askPass|init\.templateDir|sequence\.editor|merge\.[^.]+\.driver|diff\.[^.]+\.(textconv|command)|alias\.|credential\.|http\.|remote\.|url\.|include\.|includeIf\.|diff\.external|filter\.|receive\.|uploadpack\.|protocol\.)/i.test(
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
  const re = /(?:^|\s)(?:\d?<>|\d?>>?\|?|&>>?\|?)\s*((?:"[^"]*"|'[^']*'|\\.|[^\s;&|])+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(unglued))) {
    const target = unquoteShellWord(m[1]!);
    if (target.startsWith('&')) continue;
    // real device sinks are not writes to a governed path — but only after `..` is resolved away, so that
    // `/dev/../etc/x` is judged as `/etc/x` (round 13)
    const resolved = target.startsWith('/') ? resolve(target) : target;
    if (resolved === '/dev' || resolved.startsWith('/dev/')) continue;
    out.push(target);
  }
  return out;
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
  return (
    tryMatch(canonPosix, canonicalPath(homedir()).split(sep).join('/'), canonRoots) ||
    (lexPosix !== canonPosix && tryMatch(lexPosix, homedir().split(sep).join('/'), lexRoots))
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
const PREFIX_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'do', '!', '{', '}', 'time']);
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
  /^(EDITOR|VISUAL|PAGER|DIFFPROG|MERGE|SSH_ASKPASS|SUDO_ASKPASS|TERMINAL|BROWSER|MANPAGER|LESSOPEN|LESSCLOSE|CC|CXX|LD|AR|RANLIB|OBJCOPY|CARGO_TARGET_[A-Z0-9_]*RUNNER|RUSTC_WRAPPER|RUSTC|LD_PRELOAD|DYLD_[A-Z_]+)$/;

const RELEVANT_ENV_INPUTS: Record<ProducerResult['kind'], readonly RegExp[]> = {
  // A variable whose VALUE IS A PROGRAM re-points the tool itself, so it is relevant to EVERY producer and to no
  // producer at all — `EDITOR=<prog> git commit` and `CC=<prog> make build` run <prog> whichever branch resolved
  // the body. Listing it per kind meant it was relevant where someone remembered to list it.
  'make-target': [PROGRAM_NAMING_ENV, /^(MAKEFILES|MAKEFLAGS|GNUMAKEFLAGS|MAKE|SHELL|PATH)$/],
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
    if (RELEVANT_ENV_INPUTS[kind].some((re) => re.test(name)))
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
  /^(MAKEFILES|MAKEFLAGS|MAKE|GNUMAKEFLAGS|SHELL|BASH_ENV|ENV|CDPATH|PATH|NODE_OPTIONS|NODE_PATH|npm_config_[a-z_]+|YARN_[A-Z_]+|PNPM_[A-Z_]+|BUN_[A-Z_]+|PYTHONPATH|PYTHONSTARTUP|PERL5OPT|RUBYOPT|GIT_[A-Z_]+|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]+|EDITOR|VISUAL|PAGER|DIFFPROG|MERGE|SSH_ASKPASS|SUDO_ASKPASS|TERMINAL|BROWSER|MANPAGER|LESSOPEN|LESSCLOSE|CC|CXX|LD|AR|RANLIB|OBJCOPY|CARGO_TARGET_[A-Z0-9_]*RUNNER|RUSTC_WRAPPER|RUSTC|DOCKER_HOST|DOCKER_CONTEXT|CONTAINER_HOST|KUBECONFIG|KUBE_CONTEXT)$/;

export function segmentEnvInputs(segment: string): Record<string, string> {
  const out: Record<string, string> = {};
  // `VAR=x cmd`, `env VAR=x cmd`, `env -- VAR=x cmd`, `env -S 'VAR=x cmd'`, and the same behind any wrapper
  // (`timeout 60 env VAR=x cmd`). Anchoring on the LEADING position only made the dimension blind to spellings
  // the normalizer already knew how to parse — two readers for one dimension (challenge 8, finding 1).
  const scan = (text: string): void => {
    let s = text.trim();
    for (;;) {
      // skip wrappers and their options so `timeout 60 env FOO=1 make` is reached
      const w = /^(\S+)\s+/.exec(s);
      if (w && (WRAPPERS.has(w[1]!) || w[1] === 'timeout' || w[1] === '--')) {
        s = s.slice(w[0].length);
        continue;
      }
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=('[^']*'|"[^"]*"|\S*)\s+/.exec(s);
      if (m) {
        if (EXECUTION_ENV_INPUTS.test(m[1]!)) out[m[1]!] = m[2]!.replace(/^['"]|['"]$/g, '');
        s = s.slice(m[0].length);
        continue;
      }
      // a numeric or flag operand of a wrapper (`timeout 60`, `env -C dir`, `nice -n 5`)
      const opt = /^(-\S*|\d+\S*)\s+/.exec(s);
      if (opt && /^(-|\d)/.test(opt[1]!)) {
        s = s.slice(opt[0].length);
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
    if (ch === "'" || ch === '"') quote = ch;
    else if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]!))) break;
    out += ch;
  }
  return out;
}

/** Splits shell script text into classifiable segments, returning null when the script is opaque (dynamic commands). */
function scriptSegments(text: string): string[] | null {
  // PRODUCER CONTRACT: resolve WHICH lines execute, and hand every one of them over verbatim. Nothing is dropped
  // for looking harmless — that judgement belongs to the canonical analyzer, which classifies shell structure as
  // read-only itself. A heredoc BODY is data the script feeds to a command, not commands, so it is not emitted as
  // executable text; `eval` and a `$`-headed command cannot be resolved at all and are reported as UNKNOWN.
  const out: string[] = [];
  let heredoc: string | null = null;
  for (const raw of text.split(/\r?\n/)) {
    if (heredoc !== null) {
      if (raw.trim() === heredoc) heredoc = null;
      continue;
    }
    const line = stripComment(raw).trim();
    if (!line || line.startsWith('#!')) continue;
    const hd = /<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/.exec(line);
    if (hd) heredoc = hd[1]!;
    // an `eval` or a command built from a variable cannot be resolved: report UNKNOWN rather than guess
    for (const seg of splitShellSegments(line)) {
      for (const n of normalizeSegment(seg)) {
        const head = /^(\S+)/.exec(n)?.[1] ?? '';
        if (head === 'eval' || /^["']?\$/.test(head)) return null;
      }
    }
    out.push(line);
  }
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
  if (head === 'git' && /^(checkout|restore)$/.test(operands[0] ?? '')) {
    const dd = tokens.indexOf('--');
    if (dd >= 0) out.push(...tokens.slice(dd + 1).map(abs));
  } else if (/^(cp|mv|install|rsync|ln)$/.test(head) && operands.length >= 2)
    out.push(abs(operands[operands.length - 1]!));
  else if (/^(tee|truncate|touch)$/.test(head)) out.push(...operands.map(abs));
  else if (head === 'dd') {
    const of = tokens.find((t) => t.startsWith('of='));
    if (of) out.push(abs(of.slice(3)));
  } else if (/^(sed|perl)$/.test(head) && tokens.some((t) => /^-[a-z]*i/.test(t)) && operands.length)
    out.push(...operands.slice(1).map(abs));
  return out;
}

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
  /** CONFIGURATION CLOSURE + BINDING: assignments that change WHICH PROGRAM a recipe line runs, rather than what
   *  the line says. `SHELL := ./bin/badsh` and `export PATH := ./bin:$(PATH)` both make every command in every
   *  recipe mean something else, while the recipe text stays honest (challenge 6, findings 18, 24). */
  rebinds: string[];
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
  const added = v.replace(/\$[({]?PATH[)}]?/g, '').split(':').filter((p) => p.trim().length > 0);
  return added.every((p) => /^\/(usr|opt|bin|sbin|Library|System)\b/.test(p.trim()));
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
    rebinds: [],
    sources: [],
    text: '',
  };
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
  // GNU make lets `.RECIPEPREFIX` replace the tab that introduces a recipe line. A parser that only knows the tab
  // sees an EMPTY recipe and reports the target fully resolved — its own gap becoming a positive claim.
  let prefix = '\t';
  for (const line of lines) {
    const rp = /^\s*\.RECIPEPREFIX\s*[:+?]?=\s*(\S?)/.exec(line);
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

    // `include a.mk b.mk` — the included rules really execute, so an unreadable one is not "no such target"
    const inc = /^[-s]?include\s+(.+)$/.exec(trimmed);
    if (inc) {
      current = null;
      if (/[$`]/.test(inc[1]!)) {
        model.unsupported.push(`include with a computed path: ${trimmed}`);
        continue;
      }
      if (depth >= 3) {
        model.unsupported.push('include nested deeper than this resolver follows');
        continue;
      }
      for (const name of inc[1]!.split(/\s+/).filter(Boolean)) {
        const sub = parseMakefile(ctx, resolve(dir, name), dir, depth + 1);
        for (const [t, r] of sub.rules) {
          const existing = model.rules.get(t);
          if (existing) {
            existing.recipes.push(...r.recipes);
            existing.prereqs.push(...r.prereqs);
          } else model.rules.set(t, { recipes: [...r.recipes], prereqs: [...r.prereqs] });
        }
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
      if (/^endif\b/.test(trimmed)) openConditions.pop();
      else if (/^else\b/.test(trimmed)) openConditions[openConditions.length - 1] = `conditional: ${trimmed}`;
      else openConditions.push(`conditional: ${trimmed}`);
      current = null;
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
    const assign = /^(?:[^:=#]+:\s*)?(?:override\s+|export\s+)*(SHELL|\.SHELLFLAGS|PATH)\s*[:+?]?=\s*(.*)$/.exec(
      trimmed,
    );
    if (assign && !isOrdinaryShellAssignment(assign[1]!, assign[2]!)) model.rebinds.push(trimmed);
    if (/\$\(eval\b/.test(trimmed)) model.unsupported.push(`$(eval): ${trimmed}`);
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
    if (trimmed.startsWith('.')) {
      current = null;
      continue; // other special targets (.PHONY, .SUFFIXES, …) define no recipe EGO must run
    }
    // a rule: `targets [: | ::] prereqs [; recipe]`. A target or prerequisite list built from a variable is
    // recorded as unsupported rather than parsed as a literal name.
    const rule = /^([^:=#]+?)\s*::?(?!=)\s*([^;]*)(?:;(.*))?$/.exec(line);
    if (rule && !/^\s/.test(line)) {
      const targets = rule[1]!.trim().split(/\s+/).filter(Boolean);
      const prereqs = rule[2]!.trim().split(/\s+/).filter(Boolean);
      if (targets.some((t) => /[%$]/.test(t))) model.hasPatternRules = true;
      const shared: MakeRule = { recipes: [], prereqs };
      if (rule[3] && rule[3].trim()) shared.recipes.push(rule[3].trim()); // `target: ; cmd` one-line form
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
    new Set(['add', 'checkout', 'switch', 'restore', 'commit', 'merge', 'stash', 'clone', 'pull', 'reset', 'rm', 'mv', 'apply', 'am', 'cherry-pick', 'rebase', 'revert', 'archive']),
  ],
  [/^diff\.[^.]+\.(textconv|command)$/i, new Set(['diff', 'show', 'log', 'blame', 'difftool', 'range-diff'])],
  [/^core\.fsmonitor$/i, new Set(['status', 'add', 'diff', 'commit', 'checkout', 'switch', 'restore', 'stash'])],
  [/^core\.pager$/i, new Set(['log', 'show', 'diff', 'blame', 'branch', 'tag', 'shortlog', 'grep'])],
  [/^core\.(sshCommand|gitProxy)$/i, new Set(['fetch', 'push', 'pull', 'clone', 'ls-remote', 'submodule', 'remote'])],
  [/^core\.editor$/i, new Set(['commit', 'rebase', 'tag', 'merge', 'revert', 'cherry-pick', 'config'])],
];

/** REPOSITORY-LOCAL git config whose VALUE is a command git will run: clean/smudge filters, textconv, fsmonitor
 *  and the like. Local scope only \u2014 these are the keys an agent or a dependency can write into the checkout. */
function gitLocalProgramValues(root: string, verb: string): string[] {
  const out: string[] = [];
  const dump = git(['config', '--local', '--list'], root);
  if (!dump.ok || !dump.stdout) return out;
  for (const line of dump.stdout.split(/\r?\n/)) {
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
    const scope = CONFIG_PROGRAM_VERBS.find(([re]) => re.test(key));
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
      const ignore = tokens.some((t) => t === '--ignore-scripts' || t === '--ignore-scripts=true');
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
    const body = names.flatMap((n) => splitShellSegments(scripts[n] as string));
    // npm accepts its configuration as flags anywhere on the line, including AFTER the script name, and
    // `--script-shell` re-points the interpreter of every script (challenge 8, finding 3)
    const npmFlags = tokens.filter((t) =>
      /^--(script-shell|node-options|shell|ignore-scripts=false|foreground-scripts)(=|$)/.test(t),
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
      key: `npm:${dirname(pkgPath)}:${script}`,
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
      '-C', '--directory', '-f', '--file', '--makefile', '-j', '--jobs', '-l',
      '--load-average', '-o', '--old-file', '-W', '--what-if', '-I', '--include-dir',
    ]);
    const targets: string[] = [];
    const cliRebinds: string[] = [];
    const cliInputs: string[] = [];
    let makeDir = cwd;
    const makeFiles: string[] = []; // every -f/--file/--makefile: make reads them ALL, not just the last
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]!;
      if (t.startsWith('-')) {
        const dirEq = /^(?:--directory=|-C)(.+)$/.exec(t);
        const fileEq = /^(?:--file=|--makefile=|-f)(.+)$/.exec(t);
        // successive -C are CUMULATIVE in make: `make -C a -C b` enters a, then a/b (challenge 5, finding 17)
        if ((t === '-C' || t === '--directory') && tokens[i + 1]) makeDir = resolve(makeDir, tokens[i + 1]!);
        else if (dirEq) makeDir = resolve(makeDir, dirEq[1]!);
        if ((t === '-f' || t === '--file' || t === '--makefile') && tokens[i + 1]) makeFiles.push(tokens[i + 1]!);
        else if (fileEq) makeFiles.push(fileEq[1]!);
        if (MAKE_ARG_OPTS.has(t)) i++;
        continue;
      }
      if (t.includes('=')) {
        // a command-line variable assignment is not a target — but make takes execution inputs in this position
        // too, and the leading-assignment capture cannot see them (challenge 8, finding 2)
        if (/^(SHELL|\.SHELLFLAGS|PATH)=/.test(t)) cliRebinds.push(t);
        else if (EXECUTION_ENV_INPUTS.test(t.slice(0, t.indexOf('=')))) cliInputs.push(t);
        continue;
      }
      targets.push(t);
    }
    // `make -f -` reads the makefile from STDIN and `-E`/`--eval` injects makefile text on the command line:
    // neither is a file this resolver can read, and reporting "no Makefile" over them claimed proven absence of
    // a recipe an attacker supplies (exit review 2).
    if (makeFiles.includes('-') || tokens.some((t) => /^(-E|--eval)(=|$)/.test(t)))
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
      rebinds: [],
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
      merged.rebinds.push(...m.rebinds);
      merged.sources.push(...m.sources);
      merged.text += m.text + '\n';
      if (m.oneShell) merged.oneShell = true;
      if (m.defaultGoal) merged.defaultGoal = m.defaultGoal; // make takes the LAST assignment
      if (!merged.firstTarget) merged.firstTarget = m.firstTarget;
    }
    // A bare `make` builds .DEFAULT_GOAL when set, not the first rule (challenge 5, finding 16).
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
      const rule = merged.rules.get(t);
      if (!rule) {
        // a prerequisite with no rule is usually a FILE, which executes nothing; a requested TARGET with no rule is
        // only PROVEN absent when this makefile uses nothing the parser cannot see
        if (depth === 0) missing.push(t);
        return;
      }
      if (depth >= 8) {
        partial = `prerequisite chain of "${t}" is deeper than this resolver follows`;
        return;
      }
      for (const p of rule.prereqs) walk(p, depth + 1);
      for (const rl of rule.recipes) {
        const cmd = rl.replace(/^[@+-]+/, '').trim();
        if (!cmd) continue;
        if (/^\$[({]/.test(cmd) || /\$\((shell|eval)\b/.test(cmd)) {
          // ONE unresolvable line no longer discards the rest: the resolved lines are still analysed and the
          // remainder is reported (challenge 5, finding 8 — "known but incomplete body")
          partial = `a recipe line of "${t}" is a variable command`;
          continue;
        }
        body.push(cmd);
      }
    };
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
    const key = `make:${merged.sources.join(',') || makeDir}:${wanted.join(',')}`;
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
  '|--compress-program|--wrapper|-wrapper|-fplugin|-fplugin-arg-[\\w-]+|-specs|--specs|-toolexec|-ldflags|-gccgo|-B|-processor|-processorpath|-Xplugin|--plugin|-load|-Xclang|-fpass-plugin|--preprocessor|-no-integrated-cpp' +
  '|-e(?=\\s+\\S*(ssh|sh|bash|python|perl|ruby|node))';
const PROGRAM_OPERAND_LONG_RE = new RegExp(`\\s(${PROGRAM_OPERAND_LONG})(=|\\s)`);
/** the short forms whose value is GLUED to the letter: `gcc -B/tmp/evil`, `clang -Xclangfoo`, `-loadplugin` */
const PROGRAM_OPERAND_GLUED_RE = /\s(-B|-Xclang|-load|-fplugin|-specs|-wrapper)\S/;
/** the archive tools where a short `-I` names a compression PROGRAM (for make it is an include directory) */
const PROGRAM_OPERAND_TOOL_RE = /^(tar|bsdtar|gtar|pax)\b/;
const PROGRAM_OPERAND_RE = new RegExp(`\\s(${PROGRAM_OPERAND_LONG}|-I)(=|\\s)`);

const DB_CLIENT_HEADS = new Set([
  'psql', 'mysql', 'mariadb', 'mongosh', 'mongo', 'sqlite3', 'redis-cli', 'clickhouse-client', 'cqlsh',
]);
const DB_EXECUTES_UNREAD =
  // `\!` is psql's shell escape. Inside DOUBLE quotes the backslash is consumed before this test ever sees it,
  // so the de-escaped form — a `-c` value that BEGINS with `!` — is matched too. Matching a bare `!` anywhere
  // would be far too broad; anchoring it to the start of the statement is exactly the meta-command position
  // (challenge 8, finding 14).
  // The family is "this client runs something it was handed": a program file, a shell escape, a loadable
  // extension, or a COPY in either direction. Enumerating only one direction of COPY and only sqlite's `.shell`
  // left the neighbours open (decision challenge, findings 12, 34).
  /\s(-f|--file|-init|--init)(=|\s)|\s<\s|\\!|(-c|--command|--eval|-e|--execute)(=|\s+)["']?\s*!|\.(shell|system|read|load|import|output|once|excel|cd)\b|\bSYSTEM\b|\b(load_extension|sqlite3_load_extension)\b|\bCREATE\s+(VIRTUAL\s+TABLE|FUNCTION|EXTENSION)\b|COPY\b[\s\S]*\b(TO|FROM)\s+PROGRAM\b|\\copy\b[\s\S]*\bPROGRAM\b|\bsource\s+\S/i;

const TARGET_ENV_RE =
  /^(PGHOST|PGHOSTADDR|PGSERVICE|PGDATABASE|PGPORT|PGURI|MYSQL_HOST|MYSQL_TCP_PORT|REDIS_HOST|REDIS_URL|MONGODB_URI|MONGO_URL|DATABASE_URL|KUBECONFIG|KUBERNETES_MASTER|CLICKHOUSE_HOST)$/;
const TARGET_ENV_HEADS = new Set([
  'psql', 'mysql', 'mariadb', 'mongosh', 'mongo', 'redis-cli', 'clickhouse-client', 'cqlsh', 'sqlite3',
  'kubectl', 'oc', 'helm', 'kustomize', 'flyway', 'liquibase', 'alembic', 'dbmate', 'prisma', 'knex', 'sequelize',
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
const TARGET_SENSITIVE: Record<string, 'k8s' | 'db' | 'container'> = {
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
};

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
  /^(-n|--namespace|--context|--kube-context|--kubeconfig|--server|-s|--kube-apiserver|--token|--user|--username|--password|--cluster|--as|--as-uid|--as-group|--cache-dir|--certificate-authority|--client-certificate|--client-key|--request-timeout|--tls-server-name|-o|--output|-f|--filename|-l|--selector|--field-selector|--chart|--repo|--version|--values|--set|--set-string|--set-file|-v|--v)$/;

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

/** Resolves the Kubernetes target of a normalized segment and whether the verb mutates it. */
/** docker/podman global options that consume the next token, so their value is not the subcommand. */
const DOCKER_GLOBAL_VALUE_OPTS =
  /^(--log-level|-l|--config|--tlscacert|--tlscert|--tlskey|--context|-c|--host|-H|--url|--connection|--builder|--identity|--runtime|--namespace)$/;

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
    // the local daemon, however it is spelled, is local: a unix socket, a named pipe, or a loopback endpoint
    if (/^(unix:|npipe:|fd:)/i.test(v) || targets.dbLocalHosts.some((h) => v.includes(h)))
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
    const eq = /^(?:--host=|--context=|--url=|--connection=|--builder=|-H|-c)(.+)$/.exec(t);
    if ((t === '-H' || t === '--host' || t === '--url') && tokens[i + 1]) add(tokens[++i]!, 'engine');
    else if ((t === '-c' || t === '--context' || t === '--connection') && tokens[i + 1]) add(tokens[++i]!, 'context');
    else if (eq) add(eq[1]!, t.startsWith('-H') || t.startsWith('--host') || t.startsWith('--url') ? 'engine' : 'context');
  }
  // the engine is selected by ENVIRONMENT too — `DOCKER_HOST` and `DOCKER_CONTEXT` are the same two flags by
  // another name, and docker's own help documents `--context` as overriding `DOCKER_HOST`
  for (const [k, v] of Object.entries(envInputs))
    if (/^(DOCKER_HOST|CONTAINER_HOST)$/.test(k)) add(v, 'engine');
    else if (/^(DOCKER_CONTEXT)$/.test(k)) add(v, 'context');
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
  if (!signals.length) return { cls: 'LOCAL', target: 'local daemon', mutating: false };
  // a READ against another engine is not a mutation of it: `docker -H … ps` lists, it does not deploy
  const reads = new Set(['ps', 'images', 'image', 'inspect', 'logs', 'version', 'info', 'top', 'port', 'stats', 'events', 'history', 'diff', 'search', 'context']);
  const verb = tokens.slice(1).find((t) => !t.startsWith('-') && !signals.some((g) => g.target.endsWith(t)));
  const isUse = tokens.some((t, i) => t === 'use' && tokens[i - 1] === 'context');
  const mutating = isUse || verb === undefined || !reads.has(verb);
  const worst = signals.reduce((a, b) => (TARGET_SEVERITY[b.cls] > TARGET_SEVERITY[a.cls] ? b : a));
  return { ...worst, mutating };
}

function resolveK8sTarget(
  tokens: string[],
  targets: LocalTargets,
): { cls: TargetClass; target: string; mutating: boolean } {
  const head = tokens[0] ?? '';
  if (/^(kind|k3d|minikube)$/.test(head)) return { cls: 'LOCAL', target: head, mutating: true };
  // The verb is found BY NAME, not by skipping option values: any global option missing from a skip-list would
  // otherwise displace it and silently turn a mutation into a read (round 14).
  const known = head === 'helm' ? HELM_VERBS : KUBECTL_VERBS;
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
  // an unrecognised verb fails closed: the kernel cannot show it is a read
  const mutating = verb === undefined ? true : mutate.has(verb);
  // EVERY signal that can select the cluster is classified, and the MOST RESTRICTIVE one decides. kubectl resolves
  // them together — `--server` overrides the context's endpoint and `--kubeconfig` chooses the file the context is
  // looked up in — so a local-looking `--context` must never end the search (round 14).
  const signals: Array<{ cls: TargetClass; target: string }> = [];
  const add = (values: string[], patterns: string[], kind: string) => {
    for (const v of values) signals.push({ cls: classifyTargetName(v, patterns, targets), target: `${kind} ${v}` });
  };
  add(optionValues(tokens, '', ['--context', '--kube-context']), targets.k8sLocalContexts, 'context');
  add(optionValues(tokens, '', ['--kubeconfig']), [], 'kubeconfig');
  for (const t of tokens) {
    const env = /^(KUBECONFIG|KUBERNETES_MASTER)=(.+)$/.exec(t);
    if (env) signals.push({ cls: classifyTargetName(env[2]!, [], targets), target: env[1]! + '=' + env[2]! });
  }
  add(optionValues(tokens, 's', ['--server', '--kube-apiserver']), [], 'server');
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

function resolveDbTarget(
  tokens: string[],
  targets: LocalTargets,
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

  for (const t of tokens) {
    // a URI anywhere in the token, not only at its start: `-url=jdbc:postgresql://prod-db/app` hid the host
    for (const m of t.matchAll(/[a-z][a-z0-9+.-]*:\/\/(?:[^@/\s]*@)?\[?([^\]:/?\s]+)\]?/gi)) {
      if (isOpaqueTarget(m[0]!)) signals.push({ cls: 'UNCLASSIFIED', target: m[0]! });
      else push(m[1] ?? '', 'uri host');
    }
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
  }
  for (const h of optionValues(tokens, 'h', ['--host'])) push(h, 'host');
  // the first operand that is not an option NOR an option's value
  let bare: string | undefined;
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.startsWith('-')) {
      if (/^(-f|--file|-c|--command|-e|--execute|--eval|-U|--username|-p|--port|-d|--dbname|-o|--output)$/.test(t)) i++;
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
    /^[A-Za-z0-9][A-Za-z0-9.-]*(:\d+)?(\/[^\s]*)?$/.test(bare) &&
    /[.:]/.test(bare)
  )
    push(bare.split(/[:/]/)[0]!, 'host');
  if (signals.length === 0) return { cls: 'LOCAL', target: 'the local socket', executes };
  const worst = signals.reduce((a, b) => (TARGET_SEVERITY[b.cls] > TARGET_SEVERITY[a.cls] ? b : a));
  return { cls: worst.cls, target: worst.target, executes };
}

/** Re-judges a capability that ASSERTS a local target against the target the command actually names (Q98). */
function retargetLocalCapability(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  hit: CapabilityHit,
  norm: string,
  envInputs: Record<string, string> = {},
): CapabilityHit {
  const kind = TARGET_SENSITIVE[hit.capability];
  if (!kind) return hit;
  const targets = table.localTargets;
  if (!targets || targets.k8sLocalContexts.length === 0) return hit;
  const tokens = tokenize(norm);
  const resolved =
    kind === 'k8s'
      ? resolveK8sTarget(tokens, targets)
      : kind === 'db'
        ? resolveDbTarget(tokens, targets)
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
  const bodyEnv = effect.bodyEnv ?? state.env;
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
  for (const raw of tokenize(segment).slice(1)) {
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
function classifyShellPaths(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  seg: string,
  cwd: string,
): CapabilityHit[] {
  const hits: CapabilityHit[] = [];
  const tokens = tokenize(seg);
  const head0 = tokens[0] ?? '';
  const head = head0.slice(head0.lastIndexOf('/') + 1);
  if (!head || head.startsWith('$')) return hits;
  const paths = pathTokens(seg, cwd);
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
  const genericOutput = optionValue(tokenize(seg), 'o', ['--output', '--output-file', '--out-file']);
  const write = WRITE_HEADS.has(head) || (genericOutput !== null && /[/.]/.test(genericOutput));
  // destination of a write-ish command: last operand for cp/mv/ln/install/rsync, -C/-d dir for archives, of= for dd
  let dest: string | null = null;
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
    if (head === 'tar' || head === 'bsdtar' || head === 'gtar') {
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
      // `git checkout|restore <ref> -- <paths>` writes the paths
      const sub = tokens[1];
      const dd = tokens.indexOf('--');
      dest = (sub === 'checkout' || sub === 'restore') && dd > 0 ? 'AFTER_DASHDASH' : null;
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
        'perl',
        'ln',
        'shred',
        'unlink',
        'rename',
        'patch',
      ].includes(head)
    )
      dest = 'ALL'; // for ln every operand counts: a link TARGET inside a protected tree opens a route into it
  }
  // a generic `-o FILE` / `--output FILE` names a write destination whatever the tool is called; enumerating every
  // "read-only" tool that happens to accept one is the losing game (round 15)
  if (!dest && genericOutput && /[/.]/.test(genericOutput)) dest = genericOutput;
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
    for (const t of tokens.slice(1)) {
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
  if (paths.length === 0) return hits;
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
        (r.capability === 'fs.outside-workspace.read' && !/^\/dev\//.test(p.abs))
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
      const w = classifyPath(table, ctx, 'Write', p.abs);
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
        const candidates = isAbsolute(prefix) ? [prefix] : roots.map((r) => `${r}/${prefix}`);
        if (candidates.some((c) => c === posix)) {
          direct = pp;
          break;
        }
        if (!contains && candidates.some((c) => c.startsWith(posix + '/'))) contains = pp;
      }
      const pp = direct ?? contains;
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
  const startCwd = state.env.cwdVerified ? state.env.cwd : '\0dynamic';
  let cwd = startCwd;
  // each UNIT is one shell invocation; `cd a && b` inside a unit still moves the directory for `b`
  const units = segments.flatMap((u) => (isolatedShells ? [splitShellSegments(u)] : [[u]]));
  for (const unit of isolatedShells ? units : [segments]) {
    if (isolatedShells) {
      cwd = startCwd; // a fresh shell per recipe line / per pre|main|post script
      carriedEnv = {};
      rebound = null;
    }
    for (const seg of unit) {
    const hitsBefore = hits.length;
    // `cd DIR` moves the working directory for the following segments (a dynamic target makes it unknown). Options
    // and `--` are skipped (`cd -- .harness/generated`, `cd -P dir`), and the directory is the last positional.
    const cdTrimmed = seg.trim();
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
      ...(rebound !== null ? { binding: { kind: 'redefined' as const, why: rebound } } : {}),
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
    for (const norm of normalizeSegment(seg)) {
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
                hits.push({
                  capability: m.capability,
                  verdict: verdictFor(table, ctx, m.capability),
                  via: `locked operation carried in argument position: ${sub}`,
                  segment: norm,
                  absolute: isAbsoluteCap(table, m.capability),
                });
              break;
            }
          }
        }
      }
      // path arguments of the normalized command (after wrappers and global flags are stripped)
      for (const h of classifyShellPaths(table, ctx, norm, effectiveCwd)) hits.push(h);
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
    const bare = seg.trim().replace(/^export\s+/, '');
    if (/^[A-Za-z_][A-Za-z0-9_]*=\S*\s*$/.test(bare)) Object.assign(carriedEnv, segmentEnvInputs(bare + ' x'));
    const decl = /^(?:alias\s+([A-Za-z_][\w.-]*)=|(?:function\s+)?([A-Za-z_][\w.-]*)\s*\(\s*\)\s*\{)/.exec(seg.trim());
    if (decl) rebound = `the body defines ${decl[1] ?? decl[2]} before using it`;
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
  return analyzeSegments(table, ctx, compiled, splitShellSegments(command), {
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
      const literal = (cut < 0 ? reach : reach.slice(0, cut)).replace(/\/+$/, '') || '.';
      const home2 = expandHome(literal);
      const resolvedReach = canonicalPath(
        home2 !== null && isAbsolute(home2) ? home2 : resolve(abs, home2 ?? literal),
      );
      // a wildcard reads INSIDE the literal prefix, so the thing classified is the directory's CONTENTS: a path
      // matcher written as `~/.ssh/**` describes what is in it, not the directory entry itself
      const r = classifyPath(table, ctx, 'Read', cut < 0 ? resolvedReach : resolvedReach + '/');
      // a reach that leaves every registered root is not the `fs.repo.read` the base claimed it was
      if (r.via.startsWith('matcher path') || !r.capability.startsWith('fs.repo'))
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
