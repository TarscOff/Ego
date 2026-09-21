// Evaluates a host tool call against the compiled authority table. Deterministic: no model involvement.
import { homedir, tmpdir } from 'node:os';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import type { CompiledAuthorityTable, CompiledMatcher } from './compile.ts';
import type { Verdict } from '../control-plane/types.ts';
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
  /** true when running inside the EGO source repository under HARNESS_MAINTENANCE */
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
  'doas',
  'gtimeout',
]);
/** wrapper options that consume the next token as their value (the command starts after it) */
const WRAPPER_VALUE_OPTS: Record<string, RegExp> = {
  env: /^(-u|--unset|-C|--chdir|-S|--split-string)$/,
  nice: /^(-n|--adjustment)$/,
  ionice: /^(-c|-n|-p|--class|--classdata)$/,
  watch: /^(-n|--interval|-d)$/,
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
      if (ch === ';' || ch === '|' || ch === '\n') {
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
export function normalizeSegment(segment: string): string[] {
  let s = segment.trim();
  const extra: string[] = [];
  // leading VAR=value assignments: stripped, except the ones that change what runs (surfaced as `env-inject VAR`)
  for (;;) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(?:'[^']*'|"[^"]*"|\S*)\s+/.exec(s);
    if (!m) break;
    if (ENV_INJECT_RE.test(m[1]!)) extra.push(`env-inject ${m[1]}`);
    s = s.slice(m[0].length);
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
              idx++;
            }
          break;
        }
        if (t === 'env' && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) {
          // assignments passed through `env` are judged exactly like leading assignments
          const name = tok.slice(0, tok.indexOf('='));
          if (ENV_INJECT_RE.test(name)) extra.push(`env-inject ${name}`);
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
      // flock [opts] <file> cmd | flock [opts] <file> -c 'cmd', su [-] user -c cmd, runuser -u user -- cmd
      const c = tokens.indexOf('-c', idx);
      if (c > 0 && tokens[c + 1])
        return [
          ...extra,
          ...splitShellSegments(tokens[c + 1]!).flatMap(normalizeSegment),
          tokens.slice(idx).join(' '),
        ];
      idx++;
      while (idx < tokens.length && tokens[idx]!.startsWith('-')) {
        const opt = tokens[idx]!;
        idx++;
        if (/^(-w|--timeout|-E|--conflict-exit-code|-u|--user|-g|--group)$/.test(opt)) idx++;
        if (opt === '--') break;
      }
      if (
        t === 'flock' ||
        t === 'su' ||
        (t === 'runuser' && tokens[idx] !== undefined && !tokens[idx]!.startsWith('-'))
      )
        idx++; // lock file / user
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
  const stripped = stripToolGlobalOptions(head, rest);
  rest = stripped.rest;
  extra.push(...stripped.extra);
  return [...extra, ...normalizeTail(rest)];
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
    for (let i = 1; i < rest.length; i++) {
      const t = rest[i]!;
      if (t === '-x' || t === '--exec' || t === '-X' || t === '--exec-batch') {
        const cmd: string[] = [];
        let j = i + 1;
        while (j < rest.length && rest[j] !== ';' && rest[j] !== '\\;') cmd.push(rest[j++]!);
        if (cmd.length) out.push(requote(cmd.filter((c) => !/^\{.*\}$/.test(c))));
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
  if (
    (head === 'bash' ||
      head === 'sh' ||
      head === 'zsh' ||
      head === 'dash' ||
      head === 'ksh' ||
      head === 'fish') &&
    rest.includes('-c')
  ) {
    const inner = rest[rest.indexOf('-c') + 1];
    if (inner) return [`${head} -c`, ...splitShellSegments(inner).flatMap(normalizeSegment)];
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
    const after = rest.slice(1).filter((t, i) => !(i === 0 && t.startsWith('-')));
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
  '-i',
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
  const unglued = segment.replace(/([^\s&|<>])(>{1,2})/g, '$1 $2');
  const re = /(?:^|\s)(?:\d?>>?|&>>?|>\|)\s*("[^"]*"|'[^']*'|[^\s;&|]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(unglued))) {
    const target = m[1]!.replace(/^["']|["']$/g, '');
    if (target.startsWith('&') || target === '/dev/null' || target.startsWith('/dev/')) continue;
    out.push(target);
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
  const home = canonicalPath(homedir());
  const posix = canonicalPath(absPath).split(sep).join('/');
  let pat = pattern;
  let base: string | null = null;
  if (pat.startsWith('~/')) {
    pat = pat.slice(2);
    base = home.split(sep).join('/');
  }
  const re = globToRegExp(pat);
  if (base) return re.test(posix.startsWith(base + '/') ? posix.slice(base.length + 1) : '\0');
  // repo-relative patterns: test against every registered root, then against the cwd root
  const roots = [...ctx.repoRoots, ...(ctx.cwd ? [ctx.cwd] : [])].map((r) =>
    canonicalPath(r).split(sep).join('/'),
  );
  for (const root of roots) {
    if (posix.startsWith(root + '/')) {
      if (re.test(posix.slice(root.length + 1))) return true;
    }
  }
  if (pat.startsWith('**/')) return re.test(posix);
  return false;
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
/** true when a posix path IS one of the EGO_HOME trust-store directories or lies within it (the dir node itself counts). */
function underTrustDir(posix: string, home: string): boolean {
  return TRUST_STORE_DIRS.some((d) => posix === `${home}/${d}` || posix.startsWith(`${home}/${d}/`));
}
/** Whether a path (or a glob's literal prefix) reaches the EGO_HOME trust store: at/under a trust dir; a glob that
 *  completes to one; or the EGO_HOME root itself under a glob or a recursive whole-tree op (parent copy/delete). */
function reachesTrustStore(prefixPosix: string, home: string, isGlob: boolean, recursive: boolean): boolean {
  if (prefixPosix === home) return isGlob || recursive;
  return TRUST_STORE_DIRS.some((d) => {
    const dir = `${home}/${d}`;
    if (prefixPosix === dir || prefixPosix.startsWith(dir + '/')) return true;
    if (isGlob && (dir.startsWith(prefixPosix + '/') || dir.startsWith(prefixPosix))) return true;
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
]);

export function classifyPath(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  tool: 'Read' | 'Write' | 'Edit',
  rawPath: string,
): CapabilityHit {
  const abs = isAbsolute(rawPath) ? rawPath : resolve(ctx.cwd ?? process.cwd(), rawPath);
  if (tool !== 'Read' && ctx.egoHome && 'harness.trust.tamper' in table.capabilities) {
    const home = canonicalPath(ctx.egoHome).split(sep).join('/');
    const posix = canonicalPath(abs).split(sep).join('/');
    if (underTrustDir(posix, home)) {
      return {
        capability: 'harness.trust.tamper',
        verdict: verdictFor(table, ctx, 'harness.trust.tamper'),
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
const STATEMENT_KEYWORDS = new Set([
  'fi',
  'done',
  'esac',
  'function',
  'local',
  'export',
  'return',
  'exit',
  'shift',
  'set',
  'unset',
  'declare',
  'readonly',
  'typeset',
  'trap',
  'true',
  'false',
  ':',
  'break',
  'continue',
  'wait',
  'cd',
  'pushd',
  'popd',
  'umask',
  'read',
  'echo',
  'printf',
  'test',
  '[',
  '[[',
  'for',
  'while',
  'until',
  'case',
  'select',
  'in',
]);
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

function findUp(ctx: EvaluationContext, start: string, name: string): string | null {
  let dir = resolve(start);
  for (let i = 0; i < 64; i++) {
    const candidate = join(dir, name);
    const text = readInsideWorkspace(ctx, candidate);
    if (text !== null) return candidate;
    const parent = dirname(dir);
    if (parent === dir || !insideRoots(parent, ctx)) return null;
    dir = parent;
  }
  return null;
}

interface EffectState {
  depth: number;
  seen: Set<string>;
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
    for (const seg of splitShellSegments(line)) {
      let t = seg.trim();
      // strip leading prefix keywords: `if git push`, `do npm test`, `then rm -rf x`
      for (;;) {
        const m = /^(\S+)\s*/.exec(t);
        if (!m || !PREFIX_KEYWORDS.has(m[1]!)) break;
        t = t.slice(m[0].length).trim();
      }
      // leading VAR=value assignments before a command; a bare assignment line is structure
      for (;;) {
        const m = /^[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S*)\s*/.exec(t);
        if (!m) break;
        t = t.slice(m[0].length).trim();
      }
      if (!t) continue;
      const head = /^(\S+)/.exec(t)?.[1] ?? '';
      if (
        STATEMENT_KEYWORDS.has(head) ||
        /^[A-Za-z_][A-Za-z0-9_-]*\s*\(\)/.test(t) ||
        /^[)]/.test(head) ||
        /^[A-Za-z0-9_*|-]+\)$/.test(head)
      )
        continue;
      if (head === 'eval' || /^["']?\$/.test(head)) return null;
      out.push(t);
    }
  }
  return out;
}

function resolveScriptCommand(
  ctx: EvaluationContext,
  norm: string,
): {
  kind: 'shell-script' | 'npm-script' | 'make-target';
  key: string;
  body: string[] | null;
  reason: string;
} | null {
  const tokens = tokenize(norm);
  const head = tokens[0] ?? '';
  const cwd = ctx.cwd ?? process.cwd();
  // shell scripts: ./x.sh, bash x.sh, sh x.sh, source x.sh, . x.sh, /abs/x.sh
  let scriptPath: string | null = null;
  if (/^\.{0,2}\//.test(head) || isAbsolute(head)) scriptPath = head;
  else if (
    (head === 'bash' || head === 'sh' || head === 'zsh' || head === 'source' || head === '.') &&
    tokens[1] &&
    !tokens.includes('-c')
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
      };
    }
    const body = scriptSegments(text);
    return {
      kind: 'shell-script',
      key: `script:${abs}`,
      body,
      reason: body ? 'shell script analysed' : 'shell script uses dynamic commands',
    };
  }
  // package manager scripts
  if (head === 'npm' || head === 'pnpm' || head === 'yarn' || head === 'bun') {
    let script: string | null = null;
    const sub = tokens[1] ?? '';
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
    if (text === null)
      return { kind: 'npm-script', key: `npm:${script}`, body: null, reason: 'package.json not readable' };
    let scripts: Record<string, unknown> = {};
    try {
      const pkg = JSON.parse(text) as { scripts?: Record<string, unknown> };
      scripts = pkg.scripts ?? {};
    } catch {
      return { kind: 'npm-script', key: `npm:${script}`, body: null, reason: 'package.json unparsable' };
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
      };
    }
    const body = names.flatMap((n) => splitShellSegments(scripts[n] as string));
    return { kind: 'npm-script', key: `npm:${script}`, body, reason: `package.json script "${script}"` };
  }
  // make targets
  if (head === 'make' || head === 'gmake') {
    const targets = tokens.slice(1).filter((t) => !t.startsWith('-') && !t.includes('='));
    const mkPath = ['Makefile', 'makefile', 'GNUmakefile']
      .map((n) => join(cwd, n))
      .find((f) => readInsideWorkspace(ctx, f) !== null);
    const text = mkPath ? readInsideWorkspace(ctx, mkPath) : null;
    if (text === null)
      return {
        kind: 'make-target',
        key: `make:${targets.join(',')}`,
        body: null,
        reason: 'Makefile not readable',
      };
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
      if (!r) return { kind: 'make-target', key: `make:${t}`, body: null, reason: `target "${t}" not found` };
      for (const rl of r) {
        const cmd = rl.replace(/^[@+-]+/, '').trim();
        if (!cmd) continue;
        if (/^\$[({]/.test(cmd) || /\$\((shell|eval)\b/.test(cmd))
          return {
            kind: 'make-target',
            key: `make:${t}`,
            body: null,
            reason: 'recipe uses variable commands',
          };
        for (const seg of splitShellSegments(cmd)) body.push(seg);
      }
    }
    return {
      kind: 'make-target',
      key: `make:${wanted.join(',')}`,
      body,
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
): CapabilityHit {
  return {
    capability: 'command.script-opaque',
    verdict: verdictFor(table, ctx, 'command.script-opaque'),
    via: reason,
    segment: norm,
    absolute: false,
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
      outer = {
        capability: m.capability,
        verdict: verdictFor(table, ctx, m.capability),
        via: `matcher /${m.command}/`,
        segment: norm,
        absolute: isAbsoluteCap(table, m.capability),
      };
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
  if (state.depth >= MAX_EFFECT_DEPTH) return hits;
  const effect = resolveScriptCommand(ctx, norm);
  if (!effect) return hits;
  if (state.seen.has(effect.key)) return hits;
  const seen = new Set(state.seen).add(effect.key);
  if (effect.body === null) {
    // opaque: a declared class keeps its verdict (the matchers accepted that it runs project code); an undeclared one is opaque
    return declared ? hits : [opaqueHit(table, ctx, norm, effect.reason)];
  }
  const inner: CapabilityHit[] = [];
  for (const seg of effect.body) {
    for (const n of normalizeSegment(seg)) {
      for (const h of classifyNormalized(table, ctx, compiled, n, { depth: state.depth + 1, seen }))
        inner.push({ ...h, effectOf: effect.reason });
    }
  }
  if (declared) {
    // positive effects (push, production, destructive, network...) escalate a declared class; opacity inside it does not
    return [...hits, ...inner.filter((h) => !OPACITY_CLASSES.has(h.capability))];
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
  const write = WRITE_HEADS.has(head);
  // destination of a write-ish command: last operand for cp/mv/ln/install/rsync, -C/-d dir for archives, of= for dd
  let dest: string | null = null;
  if (write) {
    const bareOperands = (): string[] => {
      // ignore redirections (`< list`, `2> err`) and their targets, then keep the bare operands even when a
      // destination is a bare name (`cd .harness/generated && cp x policy.json`)
      const operands: string[] = [];
      for (let i = 1; i < tokens.length; i++) {
        const t = tokens[i]!;
        if (/^\d*[<>]{1,2}$/.test(t) || t === '&>' || t === '>|') {
          if (!t.includes('/') && i + 1 < tokens.length) i++;
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
      // every archive-WRITING mode: create (c), append (r), update (u), catenate (A) — not just create
      const writeMode =
        tokens.some(
          (t) =>
            t === '--create' ||
            t === '--append' ||
            t === '--update' ||
            t === '--catenate' ||
            t === '--concatenate' ||
            /^-[A-Za-z]*[cruA]/.test(t),
        ) || /[cruA]/.test(modeTok);
      const extract =
        tokens.some((t) => t === '--extract' || t === '--get' || /^-[A-Za-z]*x/.test(t)) ||
        /x/.test(modeTok);
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
        // the change-directory flag has several spellings: -C DIR, --directory DIR, --directory=DIR, --cd DIR
        const eq = tokens.find((t) => t.startsWith('--directory='));
        const fi = tokens.findIndex((t) => t === '-C' || t === '--directory' || t === '--cd');
        dest = eq
          ? eq.slice('--directory='.length)
          : fi >= 0 && tokens[fi + 1]
            ? tokens[fi + 1]!
            : '.'; // extracts into the change-directory target, else the working directory
      } else dest = null; // list / compare: read-only
    } else if (head === 'zip') {
      const operands = bareOperands();
      dest = operands.length ? operands[0]! : null; // zip writes its archive: the first non-option operand
    } else if (head === 'unzip') {
      const i = tokens.indexOf('-d');
      dest = i > 0 && tokens[i + 1] ? tokens[i + 1]! : '.';
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
    } else if (['cp', 'install', 'rsync', 'scp', 'gcp', 'gmv', 'ditto', 'cpio'].includes(head)) {
      const operands = bareOperands();
      // cpio -p reads its file list from stdin and copies INTO its sole operand; cp/rsync/... write the last operand
      dest = operands.length
        ? head === 'cpio'
          ? operands[0]!
          : operands[operands.length - 1]!
        : null;
    } else if (head === 'git') {
      // `git checkout|restore <ref> -- <paths>` writes the paths
      const sub = tokens[1];
      const dd = tokens.indexOf('--');
      dest = (sub === 'checkout' || sub === 'restore') && dd > 0 ? 'AFTER_DASHDASH' : null;
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
        const wholeTree = recursive || head === 'mv' || head === 'rename';
        if (reachesTrustStore(litPosix, egoPosix, rawGlob, wholeTree))
          hits.push({
            capability: 'harness.trust.tamper',
            verdict: verdictFor(table, ctx, 'harness.trust.tamper'),
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
  for (let k = ci + 1; k < m.length; k++) {
    const prev = m[k - 1]!;
    // a message/file flag consumes the NEXT token as its value, so that token is data, not a flag — skip it. (The flag
    // itself must be an unquoted bare `-m`/`-F`/…; a quoted `"-m"` is not a message-introducer.)
    if (!prev.quoted && /^(-m|-F|--message|--file|--reuse-message|--reedit-message|-C|-c)$/.test(prev.text))
      continue;
    // the token's own quotes are already stripped: the shell strips `"-n"`/`-"n"`/`-n"m"` to `-n`/`-nm` before git
    // parses it, so a quoted hook-bypass flag bypasses just the same and must be caught
    const t = m[k]!.text;
    if (t === '--no-verify' || clusterNoVerify(t)) return true;
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

export function classifyCommand(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  command: string,
): CapabilityHit[] {
  const hits: CapabilityHit[] = [];
  const bashMatchers = table.matchers.filter((m) => m.command && (m.tool === 'Bash' || m.tool === 'any'));
  const compiled: Array<{ m: CompiledMatcher; re: RegExp }> = bashMatchers.map((m) => ({
    m,
    re: new RegExp(m.command!, 'i'),
  }));
  let cwd = ctx.cwd ?? process.cwd();
  for (const seg of splitShellSegments(command)) {
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
      cwd =
        target === null || /[$`*?]/.test(target)
          ? '\0dynamic'
          : canonicalPath(
              isAbsolute(target)
                ? target
                : resolve(cwd === '\0dynamic' ? (ctx.cwd ?? process.cwd()) : cwd, target),
            );
      if (cwd === '\0dynamic')
        hits.push({
          capability: 'command.unknown',
          verdict: verdictFor(table, ctx, 'command.unknown'),
          via: 'cd to a dynamic directory',
          segment: seg,
          absolute: false,
        });
      continue;
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
    const effectiveCwd = cwd === '\0dynamic' ? (ctx.cwd ?? process.cwd()) : cwd;
    for (const norm of normalizeSegment(seg)) {
      const normHits = classifyNormalized(table, ctx, compiled, norm, { depth: 0, seen: new Set() });
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
                m.capability === 'harness.gate.bypass'
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
              capability: 'harness.trust.tamper',
              verdict: verdictFor(table, ctx, 'harness.trust.tamper'),
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
  return hits;
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
    const paths = [...patch.matchAll(/^\*\*\* (?:Update|Add|Delete) File: (.+)$/gm)].map((m) => m[1]!.trim());
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
  if (hits.length === 0)
    return { verdict: 'ALLOW', hits, reason: 'no governed operation recognised for this tool' };
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
