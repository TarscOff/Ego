// Evaluates a host tool call against the compiled authority table. Deterministic: no model involvement.
import { homedir, tmpdir } from 'node:os';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
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
            /^(core\.hooksPath|core\.fsmonitor|core\.editor|core\.pager|core\.sshCommand|core\.gitProxy|alias\.|credential\.|http\.|remote\.|url\.|include\.|includeIf\.|diff\.external|filter\.|receive\.|uploadpack\.|protocol\.)/i.test(
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
    if (underTrustDir(posix, home)) {
      return {
        capability: 'ego.trust.tamper',
        verdict: verdictFor(table, ctx, 'ego.trust.tamper'),
        via: 'EGO_HOME trust store',
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

/** The execution context a semantic conclusion was computed against (product decision, 2026-09-22).
 *
 *  EGO may report an effect as KNOWN only when the context required to resolve it has itself been VERIFIED. A
 *  resolver that cannot prove its context inputs match the real execution context must downgrade its conclusion to
 *  UNKNOWN/OPAQUE. Absence of proof is not proof of a safe context. */
export interface ResolutionContext {
  /** the directory this segment's relative operands resolve against */
  cwd: string;
  /** false when that directory could not be proven: a dynamic `cd`, an unresolvable `-C`, an unmodelled workspace
   *  selector. Any conclusion drawn from a relative path is then opaque rather than confident-and-wrong. */
  cwdVerified: boolean;
}

interface EffectState {
  depth: number;
  seen: Set<string>;
  res: ResolutionContext;
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

/** True when the path exists on disk, whatever our ability to read it. */
function fileExists(abs: string): boolean {
  try {
    statSync(abs);
    return true;
  } catch {
    return false;
  }
}

/** A manifest we could not read: `unread` when it is there (too large, wrong encoding, no permission, outside the
 *  workspace), `missing` when it is not — the command then fails on its own and nothing executes. */
function manifestUnresolved(
  ctx: EvaluationContext,
  abs: string | null,
  key: string,
  what: string,
): { kind: 'npm-script'; key: string; body: null; reason: string; unresolved: 'missing' | 'unread' } {
  const exists = abs !== null && fileExists(abs);
  return {
    kind: 'npm-script',
    key,
    body: null,
    reason: exists ? `${what} present but not readable` : `no ${what}`,
    unresolved: exists ? 'unread' : 'missing',
  };
}

/** THE PRODUCER CONTRACT (product decision, 2026-09-22 — "security true by construction").
 *
 *  A producer — make, a package script, a shell script, and any producer added later — MAY:
 *    - resolve WHICH body will execute;
 *    - resolve the execution context that body runs in;
 *    - provide structured provenance for what it inspected;
 *    - report UNKNOWN when it cannot resolve something.
 *
 *  A producer MAY NOT:
 *    - decide a segment is safe, or remove a builtin, redirection or substitution before analysis;
 *    - absorb UNKNOWN into a friendly parent class;
 *    - emit a verdict of its own, or weaken nested analysis.
 *
 *  The contract is enforced structurally rather than by convention: this return type has NO field that can carry a
 *  verdict, a capability or a hit, so a producer has nowhere to put one. `body` is the VERBATIM executable text,
 *  and the single caller always hands it to `analyzeSegments` — there is no alternate path around the analyzer.
 *  `packages/kernel/test/producer-contract.test.ts` proves no producer drops executable content. */
function resolveScriptCommand(
  ctx: EvaluationContext,
  norm: string,
  res: ResolutionContext,
): {
  kind: 'shell-script' | 'npm-script' | 'make-target';
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
   *  an npm script runs in the manifest's directory; a shell script runs in the caller's directory. Resolving a
   *  body against the parent's directory made EGO read a different file than the one that executes. */
  bodyRes?: ResolutionContext;
  /** Why the body is null. `missing`: the target does not exist, so nothing can execute and the command fails on
   *  its own. `unread`: something WILL execute that could not be read — unreadable, too large, malformed, wrongly
   *  encoded, reached through another working directory, dynamically constructed or unsupported. Only `missing`
   *  may keep a declared class's verdict; `unread` is opacity at every depth (decision "option B"). */
  unresolved?: 'missing' | 'unread';
} | null {
  const tokens = tokenize(norm);
  const head = tokens[0] ?? '';
  const cwd = res.cwd;
  // The product decision, applied at the root of every resolver: a semantic conclusion drawn from a RELATIVE path
  // is only trustworthy when the directory it is relative to has been proven. Absence of proof is not proof.
  if (!res.cwdVerified)
    return {
      kind: 'shell-script',
      key: `unverified:${norm}`,
      body: null,
      reason: 'the working directory this resolution depends on could not be verified',
      unresolved: 'unread',
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
    const text = readInsideWorkspace(ctx, abs);
    if (text === null)
      return {
        kind: 'shell-script',
        key: `script:${abs}`,
        body: null,
        reason: 'script not readable inside the workspace',
        unresolved: 'unread',
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
        unresolved: 'unread',
      };
    }
    const body = scriptSegments(text);
    return {
      kind: 'shell-script',
      key: `script:${abs}`,
      body,
      bodyRes: res,
      reason: body ? 'shell script analysed' : 'shell script uses dynamic commands',
      ...(body ? {} : { unresolved: 'unread' as const }),
    };
  }
  // package manager scripts
  if (head === 'npm' || head === 'pnpm' || head === 'yarn' || head === 'bun') {
    // A workspace/prefix/filter selector changes WHICH manifest the script comes from. EGO does not model the
    // workspace graph, so reading the root manifest would be a confident wrong answer: the conclusion is
    // downgraded instead (challenge findings 3, 22, 34).
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
        unresolved: 'unread',
      };
    let script: string | null = null;
    const sub = tokens[1] ?? '';
    // install commands (`npm install`/`ci`/`add`, bare `yarn`) run the install lifecycle scripts — analyse them, since
    // a preinstall/postinstall/prepare can push, mutate production, or write a protected tree just like `run`
    const INSTALL_SUBS = new Set(['install', 'i', 'ci', 'add', 'update', 'up', 'upgrade']);
    if (INSTALL_SUBS.has(sub) || (head === 'yarn' && sub === '')) {
      const pkgPath = findUp(ctx, cwd, 'package.json');
      const text = pkgPath ? readInsideWorkspace(ctx, pkgPath) : null;
      if (pkgPath === null || text === null)
        return manifestUnresolved(ctx, pkgPath, 'npm:install', 'package.json');
      let scripts: Record<string, unknown> = {};
      try {
        scripts = (JSON.parse(text) as { scripts?: Record<string, unknown> }).scripts ?? {};
      } catch {
        return { kind: 'npm-script', key: 'npm:install', body: null, reason: 'package.json unparsable', unresolved: 'unread' };
      }
      const names = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'preprepare', 'postprepare', 'dependencies'].filter(
        (n) => typeof scripts[n] === 'string',
      );
      if (!names.length) return null; // no lifecycle scripts: the install itself is an ordinary local mutation
      const body = names.map((n) => scripts[n] as string); // pre/main/post are separate processes
      return {
        kind: 'npm-script',
        key: `npm:${dirname(pkgPath)}:install`,
        body,
        bodyRes: { cwd: dirname(pkgPath), cwdVerified: res.cwdVerified },
        reason: 'install lifecycle scripts',
      };
    }
    if (sub === 'run' || sub === 'run-script')
      script = tokens.slice(2).find((t) => !t.startsWith('-')) ?? null;
    else if (sub === 'test' || sub === 'start' || sub === 'stop' || sub === 'restart') script = sub;
    else if (
      (head === 'yarn' || head === 'pnpm' || head === 'bun') &&
      sub &&
      !sub.startsWith('-') &&
      !PACKAGE_MANAGER_BUILTINS.has(sub)
    )
      script = sub;
    if (script === null) return null;
    const pkgPath = findUp(ctx, cwd, 'package.json');
    const text = pkgPath ? readInsideWorkspace(ctx, pkgPath) : null;
    if (pkgPath === null || text === null)
      return manifestUnresolved(ctx, pkgPath, `npm:${script}`, 'package.json');
    let scripts: Record<string, unknown> = {};
    try {
      const pkg = JSON.parse(text) as { scripts?: Record<string, unknown> };
      scripts = pkg.scripts ?? {};
    } catch {
      return { kind: 'npm-script', key: `npm:${script}`, body: null, reason: 'package.json unparsable', unresolved: 'unread' };
    }
    const names = [`pre${script}`, script, `post${script}`].filter((n) => typeof scripts[n] === 'string');
    if (!names.includes(script)) {
      if (script === 'start' && head === 'npm')
        return {
          kind: 'npm-script',
          key: `npm:${script}`,
          body: ['node server.js'],
          reason: 'npm start default',
        };
      return {
        kind: 'npm-script',
        key: `npm:${script}`,
        body: null,
        reason: `script "${script}" not found in package.json`,
        unresolved: 'missing',
      };
    }
    const body = names.flatMap((n) => splitShellSegments(scripts[n] as string));
    return {
      kind: 'npm-script',
      key: `npm:${dirname(pkgPath)}:${script}`,
      body,
      bodyRes: { cwd: dirname(pkgPath), cwdVerified: res.cwdVerified },
      reason: `package.json script "${script}"`,
    };
  }
  // make targets
  if (head === 'make' || head === 'gmake') {
    // options that consume the next token, so their argument is not a target
    const MAKE_ARG_OPTS = new Set([
      '-C', '--directory', '-f', '--file', '--makefile', '-j', '--jobs', '-l',
      '--load-average', '-o', '--old-file', '-W', '--what-if', '-I', '--include-dir',
    ]);
    const targets: string[] = [];
    let makeDir = cwd;
    let makeFile: string | null = null; // an explicit -f/--file/--makefile alternate makefile
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]!;
      if (t.startsWith('-')) {
        // both spellings: `-C DIR`/`--directory DIR` and `-CDIR`/`--directory=DIR`
        const dirEq = /^(?:--directory=|-C)(.+)$/.exec(t);
        const fileEq = /^(?:--file=|--makefile=|-f)(.+)$/.exec(t);
        if ((t === '-C' || t === '--directory') && tokens[i + 1]) makeDir = resolve(cwd, tokens[i + 1]!);
        else if (dirEq) makeDir = resolve(cwd, dirEq[1]!);
        if ((t === '-f' || t === '--file' || t === '--makefile') && tokens[i + 1]) makeFile = tokens[i + 1]!;
        else if (fileEq) makeFile = fileEq[1]!;
        if (MAKE_ARG_OPTS.has(t)) i++; // skip a separate option argument
        continue;
      }
      if (t.includes('=')) continue; // a variable assignment, not a target
      targets.push(t);
    }
    // a directory, makefile or target built from a variable or a substitution cannot be resolved
    if (tokens.slice(1).some((t) => /[$`]/.test(t)))
      return {
        kind: 'make-target',
        key: `make:dynamic:${norm}`,
        body: null,
        reason: 'the makefile, directory or target is built at runtime and cannot be resolved',
        unresolved: 'unread',
      };
    // an explicit makefile wins; otherwise the default names in the (possibly -C) directory
    const mkPath = makeFile
      ? readInsideWorkspace(ctx, resolve(makeDir, makeFile)) !== null
        ? resolve(makeDir, makeFile)
        : undefined
      : ['Makefile', 'makefile', 'GNUmakefile']
          .map((n) => join(makeDir, n))
          .find((f) => readInsideWorkspace(ctx, f) !== null);
    const text = mkPath ? readInsideWorkspace(ctx, mkPath) : null;
    if (text === null) {
      // "no Makefile anywhere" is missing: `make` fails and nothing runs. "a Makefile is there but we did not read
      // it" is unread: its recipe WILL run. Decided by existence, never by a reason string (challenge finding 1).
      const candidates = makeFile
        ? [resolve(makeDir, makeFile)]
        : ['Makefile', 'makefile', 'GNUmakefile'].map((n) => join(makeDir, n));
      const exists = candidates.some((f) => fileExists(f));
      return {
        kind: 'make-target',
        key: `make:${makeDir}:${targets.join(',')}`,
        body: null,
        reason: exists ? 'Makefile present but not readable' : 'no Makefile',
        unresolved: exists ? 'unread' : 'missing',
      };
    }
    const lines = text.split(/\r?\n/);
    const recipes = new Map<string, string[]>();
    let current: string[] | null = null;
    let firstTarget: string | null = null;
    for (const line of lines) {
      if (line.startsWith('\t')) {
        if (current) current.push(line.slice(1));
        continue;
      }
      const m = /^([A-Za-z0-9_./-]+)\s*::?(?!=)/.exec(line);
      if (m && !line.startsWith('.') && !/^\s/.test(line)) {
        current = [];
        for (const t of m[1]!.split(/\s+/)) recipes.set(t, current);
        if (!firstTarget) firstTarget = m[1]!;
      } else current = null;
    }
    const wanted = targets.length ? targets : firstTarget ? [firstTarget] : [];
    const body: string[] = [];
    for (const t of wanted) {
      const r = recipes.get(t);
      if (!r) {
        // "my parser did not find the target" is not "the target does not exist". An `include`, a pattern rule, a
        // `$(eval)`-generated rule or a VPATH target all execute while being invisible here (challenge findings
        // 5, 12, 21, 35). Only a makefile with none of those may claim the target is genuinely absent.
        const opaqueRules = /^\s*(-?include|sinclude)\b/m.test(text) || /^[^\s:]*%[^\s:]*\s*::?/m.test(text) || /\$\(eval\b/.test(text);
        return {
          kind: 'make-target',
          key: `make:${mkPath ?? makeDir}:${t}`,
          body: null,
          reason: opaqueRules
            ? `target "${t}" is not visible to the parser, and this makefile uses includes or pattern rules`
            : `target "${t}" not found`,
          unresolved: opaqueRules ? 'unread' : 'missing',
        };
      }
      for (const rl of r) {
        const cmd = rl.replace(/^[@+-]+/, '').trim();
        if (!cmd) continue;
        if (/^\$[({]/.test(cmd) || /\$\((shell|eval)\b/.test(cmd))
          return {
            kind: 'make-target',
            key: `make:${mkPath ?? makeDir}:${t}`,
            body: null,
            reason: 'recipe uses variable commands',
            unresolved: 'unread',
          };
        body.push(cmd); // one recipe LINE = one shell
      }
    }
    return {
      kind: 'make-target',
      // the cycle guard must key on the DIRECTORY too: a same-named target in another directory is a different
      // effect, and keying by name alone let the second one be skipped entirely (challenge findings 4, 30)
      key: `make:${mkPath ?? makeDir}:${wanted.join(',')}`,
      body,
      // the recipe runs in the -C directory, not in the caller's (challenge finding 1)
      bodyRes: { cwd: makeDir, cwdVerified: res.cwdVerified },
      reason: `Makefile target ${wanted.join(', ')}`,
    };
  }
  return null;
}

function opaqueHit(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  norm: string,
  reason: string,
  unread = true,
): CapabilityHit {
  return {
    capability: 'command.script-opaque',
    verdict: verdictFor(table, ctx, 'command.script-opaque'),
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
  '--use-compress-program|--checkpoint-action|--to-command|--rsh-command|--rsh|--exec|--ok-dir|-TT|--unzip-command|--filter=.*command|--pre|--hostname-bin|--upload-pack|--receive-pack|--editor|--pager|--ssh-command|--proxy-command|-e(?=\\s+\\S*(ssh|sh|bash|python|perl|ruby|node))';
const PROGRAM_OPERAND_LONG_RE = new RegExp(`\\s(${PROGRAM_OPERAND_LONG})(=|\\s)`);
/** the archive tools where a short `-I` names a compression PROGRAM (for make it is an include directory) */
const PROGRAM_OPERAND_TOOL_RE = /^(tar|bsdtar|gtar|pax)\b/;
const PROGRAM_OPERAND_RE = new RegExp(`\\s(${PROGRAM_OPERAND_LONG}|-I)(=|\\s)`);

const DB_CLIENT_HEADS = new Set([
  'psql', 'mysql', 'mariadb', 'mongosh', 'mongo', 'sqlite3', 'redis-cli', 'clickhouse-client', 'cqlsh',
]);
const DB_EXECUTES_UNREAD =
  /\s(-f|--file)(=|\s)|\s<\s|\\!|\.shell\b|\.system\b|\.read\b|\bSYSTEM\b|TO\s+PROGRAM\b/i;

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
const TARGET_SENSITIVE: Record<string, 'k8s' | 'db'> = {
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
): CapabilityHit {
  const kind = TARGET_SENSITIVE[hit.capability];
  if (!kind) return hit;
  const targets = table.localTargets;
  if (!targets || targets.k8sLocalContexts.length === 0) return hit;
  const tokens = tokenize(norm);
  const resolved =
    kind === 'k8s' ? resolveK8sTarget(tokens, targets) : resolveDbTarget(tokens, targets);
  const acts = kind === 'k8s' ? (resolved as { mutating: boolean }).mutating : (resolved as { executes: boolean }).executes;
  if (!acts || resolved.cls === 'LOCAL') return hit; // reads and genuinely local work keep their verdict
  const capability =
    resolved.cls === 'PRODUCTION'
      ? kind === 'k8s'
        ? 'production.k8s.mutate'
        : 'production.database.mutate'
      : resolved.cls === 'EXTERNAL'
        ? kind === 'k8s'
          ? 'k8s.nonlocal.mutate'
          : 'db.nonlocal.mutate'
        : kind === 'k8s'
          ? 'k8s.target.unclassified'
          : 'db.target.unclassified';
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
  for (const { m, re } of compiled) {
    if (re.test(norm)) {
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
  ];
  if (state.depth >= MAX_EFFECT_DEPTH)
    // Analysis truncation is UNKNOWN, never "whatever the parent was". Returning the enclosing declared class let a
    // chain of indirection launder anything past the gate (challenge findings 2, 11, 20, 29, 36).
    return [...hits, opaqueHit(table, ctx, norm, `analysis truncated at depth ${MAX_EFFECT_DEPTH}`)];
  const effect = resolveScriptCommand(ctx, norm, state.res);
  if (!effect) return hits;
  if (state.seen.has(effect.key)) return hits;
  const seen = new Set(state.seen).add(effect.key);
  if (effect.body === null) {
    // The effect could not be resolved. The layered security contract (decision "option B", 2026-09-22) forbids
    // unresolved EXECUTION from becoming a silent ALLOW while EGO claims no containment:
    //     KNOWN + AUTHORIZED          -> execute according to policy
    //     UNKNOWN/OPAQUE + CONTAINED  -> execute inside the containment boundary   (issue #26, not built)
    //     UNKNOWN/OPAQUE + NO SANDBOX -> ASK or DENY, never silently ALLOW
    // The only exception is a target that DOES NOT EXIST: `npm test` with no test script fails on its own, nothing
    // runs, and ordinary work must not be interrupted. That difference is decided structurally by
    // `effect.unresolved`, never by reading a prose reason (challenge finding 1).
    if (!declared) return [opaqueHit(table, ctx, norm, effect.reason)];
    return effect.unresolved === 'missing' ? hits : [...hits, opaqueHit(table, ctx, norm, effect.reason)];
  }
  // the body resolves against ITS OWN execution context, not the caller's
  const bodyRes = effect.bodyRes ?? state.res;
  // the producer's body re-enters THE SAME pipeline, with its own execution context — never a weaker sub-layer
  const inner = analyzeSegments(
    table,
    ctx,
    compiled,
    effect.body,
    { depth: state.depth + 1, seen, res: bodyRes },
    effect.kind !== 'shell-script', // a script is one shell; make recipe lines and npm pre/post are not
  ).map((h) => ({ ...h, effectOf: h.effectOf ?? effect.reason }));
  if (declared) {
    // INVARIANT 1: the same action gets the same classification at any depth. An inner opacity hit is therefore
    // KEPT, whichever producer built it — `opaqueHit()`, a matcher (`command.interpreter-script`), the `$`-head
    // branch or the no-matcher fallback (`command.unknown`). Filtering on `opaqueUnread` kept only the first of
    // those four, so `node scripts/deploy.js` was ASK on its own and ALLOW inside a target called `build`
    // (challenge findings 1, 18, 36). September alignment item 5 is superseded here: a declared class no longer
    // absorbs opacity at all. What it still absorbs is a target that DOES NOT EXIST, decided above by
    // `unresolved === 'missing'`, so `npm test` with no test script stays out of the operator's way.
    return [...hits, ...inner];
  }
  // undeclared script fully analysed: its effect replaces the unknown verdict
  return inner.length ? inner : [opaqueHit(table, ctx, norm, `${effect.reason}: empty`)];
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
  const program = (PROGRAM_OPERAND_TOOL_RE.test(seg) ? PROGRAM_OPERAND_RE : PROGRAM_OPERAND_LONG_RE).exec(seg);
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
      if (r.via.startsWith('matcher path') || r.capability.startsWith('fs.credential'))
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
  const startCwd = state.res.cwdVerified ? state.res.cwd : '\0dynamic';
  let cwd = startCwd;
  // each UNIT is one shell invocation; `cd a && b` inside a unit still moves the directory for `b`
  const units = segments.flatMap((u) => (isolatedShells ? [splitShellSegments(u)] : [[u]]));
  for (const unit of isolatedShells ? units : [segments]) {
    if (isolatedShells) cwd = startCwd; // a fresh shell per recipe line / per pre|main|post script
    for (const seg of unit) {
    // `cd DIR` moves the working directory for the following segments (a dynamic target makes it unknown). Options
    // and `--` are skipped (`cd -- .harness/generated`, `cd -P dir`), and the directory is the last positional.
    const cdTrimmed = seg.trim();
    const cdArgs = /^(?:cd|pushd)(?:\s|$)/.test(cdTrimmed)
      ? tokenize(cdTrimmed)
          .slice(1)
          .filter((a) => a !== '--' && !a.startsWith('-'))
      : null;
    if (cdArgs && cdArgs.length) {
      const target = expandHome(cdArgs[cdArgs.length - 1]!);
      const resolvedCd =
        target === null || /[$`*?]/.test(target)
          ? null
          : canonicalPath(
              isAbsolute(target)
                ? target
                : resolve(cwd === '\0dynamic' ? state.res.cwd : cwd, target),
            );
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
    const effectiveCwd = cwd === '\0dynamic' ? state.res.cwd : cwd;
    // the tracked working directory IS the resolution context; when `cd` went somewhere dynamic it is not proven,
    // and every conclusion drawn from a relative path below is downgraded rather than guessed
    const res: ResolutionContext = { cwd: effectiveCwd, cwdVerified: cwd !== '\0dynamic' };
    for (const norm of normalizeSegment(seg)) {
      const normHits = classifyNormalized(table, ctx, compiled, norm, { ...state, res });
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
      const h = classifyPath(
        table,
        ctx,
        'Write',
        isAbsolute(expanded) ? expanded : resolve(effectiveCwd, expanded),
      );
      hits.push({ ...h, via: `redirection > ${target} (${h.via})`, segment: seg });
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
  return analyzeSegments(table, ctx, compiled, splitShellSegments(command), {
    depth: 0,
    seen: new Set(),
    res: { cwd: ctx.cwd ?? process.cwd(), cwdVerified: true },
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
    if (
      abs === home ||
      home.startsWith(abs + '/') ||
      abs === '/' ||
      globCouldReachCredentials(abs + '/' + (tool === 'Glob' ? pattern : glob))
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
