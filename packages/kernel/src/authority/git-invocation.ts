// ONE READER OF A GIT COMMAND LINE (closure audit 2026-10-01, wave 3, "git").
//
// A git command line says four things the policy cares about, and each of them was read by its own code, at several places, with
// its own list: WHICH ACT it is (the verb and the options that change what the verb does), WHAT PROGRAM it makes git run (a
// configuration key whose value is a command), WHO it speaks as (a configuration key that names an author), and WHAT IT READS
// (the repository a transport verb is pointed at). The lists drifted. `git switch --force-create` skipped the gate its short
// spelling `-C` has; `man.man.path` named a program and was not on the list that `core.pager` is on; `author.name` was an
// identity and was not on the list that `user.name` is on; and `git clone file:///…` read a path the `git clone /…` spelling is
// asked about. Each was closed at the spelling reported and left its neighbours open, which is the history of this file.
//
// So the questions are asked here, once, of the line as git reads it:
//
//   - options are known by their CANONICAL names, taken from git's own usage text (git-verb-options.ts, generated): a long
//     option is any unambiguous prefix of the name, `-C` and `--force-create` are one option, `-fC` is two, and a value is the
//     rest of the word or the next word as the option's arity says;
//   - a configuration key is judged by a table of the keys git documents (`git help -c`), grouped by what the value is;
//   - a repository operand is a LOCAL PATH when it is a path or a file:// URL, and then it is a read of that path.
//
// WHAT THIS MODULE DOES NOT DO is judge: it knows nothing of capabilities, paths on disk or the table. It answers "what does
// this line say"; the evaluator decides what that costs.
import { GIT_BUILTIN_VERBS, GIT_KNOWN_VERBS, GIT_VERB_OPTIONS } from './git-verb-options.ts';

/* ------------------------------------------------------------------------------------------------------------- *
 * Configuration keys
 * ------------------------------------------------------------------------------------------------------------- */

/**
 * THE KEYS WHOSE VALUE IS A PROGRAM (or a command line, or the name of a program git looks up), by what the value is. Taken from
 * the 955 keys `git help -c` lists for git 2.50 and read once for the ones that run something; the pattern's `*` is one or more
 * characters (a subsection may hold dots), and keys are compared case-insensitively because git does.
 *
 * The same table answers three questions that three lists answered before: "does this `-c` / `--config` / `--config-env` name a
 * program?" (the line asks), "is the value a command line the kernel can read?" (it is read as one), and "does this key select
 * the program by NAME?" (`man.viewer`, `help.browser`: the program is then in another key, which is also on the table).
 */
export const PROGRAM_KEYS: ReadonlyArray<readonly [pattern: string, value: 'command' | 'path' | 'name' | 'config']> = [
  // a command line git runs through a shell, or a program with arguments
  ['core.alternateRefsCommand', 'command'],
  ['core.askPass', 'command'],
  ['core.editor', 'command'],
  ['core.fsmonitor', 'command'],
  ['core.gitProxy', 'command'],
  ['core.pager', 'command'],
  ['core.sshCommand', 'command'],
  ['credential.helper', 'command'],
  ['credential.*.helper', 'command'],
  ['diff.external', 'command'],
  ['diff.*.command', 'command'],
  ['diff.*.textconv', 'command'],
  ['difftool.*.cmd', 'command'],
  ['filter.*.clean', 'command'],
  ['filter.*.smudge', 'command'],
  ['filter.*.process', 'command'],
  ['gc.recentObjectsHook', 'command'],
  ['gpg.ssh.defaultKeyCommand', 'command'],
  ['guitool.*.cmd', 'command'],
  ['imap.tunnel', 'command'],
  ['interactive.diffFilter', 'command'],
  ['merge.*.driver', 'command'],
  ['mergetool.*.cmd', 'command'],
  ['man.*.cmd', 'command'],
  ['browser.*.cmd', 'command'],
  ['pager.*', 'command'],
  ['remote.*.receivepack', 'command'],
  ['remote.*.uploadpack', 'command'],
  ['remote.*.vcs', 'command'],
  ['sendemail.ccCmd', 'command'],
  ['sendemail.headerCmd', 'command'],
  ['sendemail.toCmd', 'command'],
  ['sequence.editor', 'command'],
  ['submodule.*.update', 'command'],
  ['trailer.*.cmd', 'command'],
  ['trailer.*.command', 'command'],
  ['uploadpack.packObjectsHook', 'command'],
  ['alias.*', 'command'],
  // the path of a program (git runs the file it names, with arguments of its own)
  ['browser.*.path', 'path'],
  ['difftool.*.path', 'path'],
  ['gpg.program', 'path'],
  ['gpg.*.program', 'path'],
  ['instaweb.httpd', 'path'],
  ['man.*.path', 'path'],
  ['mergetool.*.path', 'path'],
  ['sendemail.smtpServer', 'path'],
  // a directory git copies hooks from or looks for hooks in
  ['core.hooksPath', 'path'],
  ['init.templateDir', 'path'],
  // the NAME of a program or tool: the command that runs is the one the `*.cmd` / `*.path` key of that name holds
  ['diff.tool', 'name'],
  ['diff.guitool', 'name'],
  ['help.browser', 'name'],
  ['instaweb.browser', 'name'],
  ['man.viewer', 'name'],
  ['merge.tool', 'name'],
  ['merge.guitool', 'name'],
  ['web.browser', 'name'],
  // more configuration: a file whose own keys are any of the above
  ['include.path', 'config'],
  ['includeIf.*.path', 'config'],
];

/** whole families of keys the line has always been asked about: they redirect where git connects, who it trusts, which
 *  transports it may use and what it executes around a transfer, and a value of any of them is not "ordinary parameterisation" */
const PROGRAM_FAMILIES = /^(credential|http|remote|url|include|includeIf|receive|uploadpack|protocol|pager|difftool|mergetool|guitool|trailer|gpg|ssh|fsmonitor|filter|alias|man|browser|web|help|instaweb|imap|sendemail|interactive|submodule)\./i;

/** git's own convention: a key that ENDS in one of these words names a program. It stays as the net under the table, because a
 *  key git adds next year is named by the same convention before anyone lists it (exit review 6). */
const PROGRAM_KEY_SHAPE =
  /\.(command|cmd|driver|program|helper|textconv|clean|smudge|process|editor|pager|askpass|sshcommand|proxy|external|wrapper|exec|hookspath|templatedir|filter|difffilter|hook)$/i;

const keyPattern = (p: string): RegExp =>
  new RegExp('^' + p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.+') + '$', 'i');
const COMPILED_KEYS = PROGRAM_KEYS.map(([p, v]) => [keyPattern(p), v] as const);

/** What the value of this configuration key IS, when it names something git runs; null for an ordinary key. */
export function programKeyKind(key: string): 'command' | 'path' | 'name' | 'config' | 'family' | null {
  const k = key.trim();
  for (const [re, kind] of COMPILED_KEYS) if (re.test(k)) return kind;
  if (PROGRAM_FAMILIES.test(k) || PROGRAM_KEY_SHAPE.test(k)) return 'family';
  return null;
}

/** Does setting this key (on the command line, with `-c`, `--config-env` or clone's `--config`) change what git RUNS or where it talks to? */
export function isProgramConfigKey(key: string): boolean {
  return programKeyKind(key) !== null;
}

/** Is the VALUE of this key a command line, so that the kernel can read it as one? A bare path, a boolean or a number is not. */
export function isCommandConfigKey(key: string): boolean {
  return programKeyKind(key) === 'command';
}

/**
 * THE KEYS THAT SAY WHO WROTE SOMETHING. `user.name` and `user.email` are the default; `author.*` and `committer.*` override them
 * for the one role each, and git honours all three on a commit, a merge, a rebase and a tag. A line that sets any of them
 * attributes the commit to a name the agent was not given, which is `git.identity.override` however the key is spelled.
 */
const IDENTITY_KEY = /^(user\.(name|email|signingkey)|author\.(name|email)|committer\.(name|email))$/i;
export function isIdentityConfigKey(key: string): boolean {
  return IDENTITY_KEY.test(key.trim());
}

/* ------------------------------------------------------------------------------------------------------------- *
 * The command line
 * ------------------------------------------------------------------------------------------------------------- */

export interface GitConfigSetting {
  key: string;
  /** the value as written; null when the key is set from an environment variable (`--config-env`) */
  value: string | null;
  /** where the setting came from */
  via: '-c' | '--config-env' | '--config';
  /** for `--config-env=key=VAR`: the variable that holds the value */
  envVar?: string;
}

export interface GitArg {
  kind: 'option' | 'positional';
  /** the word as written */
  text: string;
  /** index in the token list the invocation was read from */
  index: number;
  /** for an option: its canonical names (`['-C', '--force-create']`); more than one name only for an option git reads as one */
  names?: readonly string[];
  /** for a long option: its name in full (`--force-create` for `--force-c`) */
  full?: string;
  /** for an option: the value it carries, when it carries one */
  value?: string | null;
  /** for a positional: it stands after `--` */
  afterDashDash?: boolean;
}

export interface GitInvocation {
  /** index of the verb in the token list; -1 when the line has none */
  verbIndex: number;
  verb: string;
  /** git's own options before the verb, with the value each one carries (`--git-dir=/x` is ['--git-dir', '/x']) */
  globals: Array<{ name: string; value: string | null }>;
  /** the settings of every `-c` / `--config-env` before the verb, and of `--config` / `-c` after a `clone` */
  configs: GitConfigSetting[];
  /** the verb's own arguments, in order */
  args: GitArg[];
}

/** git's own options, which stand BEFORE the verb: the ones that take a value (as the next word or after `=`), and the flags. */
const GLOBAL_WITH_VALUE = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix', '--config-env', '--config', '--list-cmds', '--attr-source']);
const GLOBAL_FLAGS = new Set([
  '-p', '--paginate', '-P', '--no-pager', '--no-replace-objects', '--bare', '--literal-pathspecs', '--glob-pathspecs',
  '--noglob-pathspecs', '--icase-pathspecs', '--no-optional-locks', '--no-lazy-fetch', '--no-advice',
]);

interface OptionEntry {
  /** every name the option goes by - `-C` and `--force-create` are one option, and `--no-force-create` is another */
  names: readonly string[];
  arg: 0 | 1 | 2;
}
const OPTION_TABLES = new Map<string, ReturnType<typeof compileOptions>>();
/** the options of a verb, and - when it has subcommands and one is named - of that subcommand beside them */
function compileOptions(verb: string, sub?: string) {
  const raw = [...(GIT_VERB_OPTIONS[verb] ?? []), ...(sub === undefined ? [] : (GIT_VERB_OPTIONS[`${verb} ${sub}`] ?? []))];
  const longs = new Map<string, OptionEntry>();
  const shorts = new Map<string, OptionEntry>();
  for (const [s, l, arg] of raw) {
    const longNames = l ? l.split(',').filter(Boolean) : [];
    const positive = longNames.filter((n) => !n.startsWith('no-') || !longNames.includes(n.slice(3)));
    const entry: OptionEntry = { names: [...[...s].map((c) => `-${c}`), ...positive.map((n) => `--${n}`)], arg };
    for (const n of longNames) {
      // the negation of an option is a different option: `--no-verify` must not answer to `--verify`
      const isTwin = n.startsWith('no-') && longNames.includes(n.slice(3));
      longs.set(n, isTwin ? { names: [`--${n}`], arg } : entry);
    }
    for (const c of s) shorts.set(c, entry);
  }
  return { longs, shorts, known: raw.length > 0 };
}
const tableOf = (verb: string, sub?: string): ReturnType<typeof compileOptions> => {
  const key = sub === undefined ? verb : `${verb} ${sub}`;
  let t = OPTION_TABLES.get(key);
  if (t === undefined) {
    t = compileOptions(verb, sub);
    OPTION_TABLES.set(key, t);
  }
  return t;
};
/** the subcommand a bare `git stash -u` means */
const DEFAULT_SUBCOMMAND: Readonly<Record<string, string>> = { stash: 'push' };

/** Reads `git [global options] verb [arguments]`. `tokens[0]` is the program (`git`); the words are the shell's, quotes removed. */
export function readGitInvocation(tokens: readonly string[]): GitInvocation {
  const configs: GitConfigSetting[] = [];
  const globals: Array<{ name: string; value: string | null }> = [];
  let i = 1;
  while (i < tokens.length) {
    const t = tokens[i]!;
    if (GLOBAL_FLAGS.has(t)) {
      globals.push({ name: t, value: null });
      i++;
      continue;
    }
    const eq = t.indexOf('=');
    const name = eq > 0 ? t.slice(0, eq) : t;
    if (!GLOBAL_WITH_VALUE.has(name)) break;
    const value = eq > 0 ? t.slice(eq + 1) : (tokens[i + 1] ?? '');
    globals.push({ name, value });
    if (name === '-c' || name === '--config') {
      const at = value.indexOf('=');
      configs.push({ key: at < 0 ? value : value.slice(0, at), value: at < 0 ? 'true' : value.slice(at + 1), via: '-c' });
    } else if (name === '--config-env') {
      const at = value.indexOf('=');
      configs.push({ key: at < 0 ? value : value.slice(0, at), value: null, via: '--config-env', ...(at < 0 ? {} : { envVar: value.slice(at + 1) }) });
    }
    i += eq > 0 ? 1 : 2;
  }
  const verbIndex = i < tokens.length ? i : -1;
  const verb = verbIndex < 0 ? '' : tokens[verbIndex]!;
  const args = verbIndex < 0 ? [] : readVerbArguments(verb, tokens, verbIndex + 1, configs);
  return { verbIndex, verb, globals, configs, args };
}

function readVerbArguments(verb: string, tokens: readonly string[], from: number, configs: GitConfigSetting[]): GitArg[] {
  // THE SUBCOMMAND IS THE FIRST WORD THAT IS NOT AN OPTION, and its options are read beside the verb's: `git stash push --include-untr`
  // and `git stash -u` are the same act, and `git worktree add -B` is not `git worktree`'s. A first pass finds the word.
  const first = readWith(tableOf(verb), tokens, from, verb, []);
  const word = first.find((a) => a.kind === 'positional')?.text;
  const sub = word !== undefined && GIT_VERB_OPTIONS[`${verb} ${word}`] !== undefined ? word : DEFAULT_SUBCOMMAND[verb];
  return sub === undefined ? readWith(tableOf(verb), tokens, from, verb, configs) : readWith(tableOf(verb, sub), tokens, from, verb, configs);
}

function readWith(table: ReturnType<typeof compileOptions>, tokens: readonly string[], from: number, verb: string, configs: GitConfigSetting[]): GitArg[] {
  const args: GitArg[] = [];
  let dashes = false;
  for (let i = from; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (dashes) {
      args.push({ kind: 'positional', text: t, index: i, afterDashDash: true });
      continue;
    }
    if (t === '--') {
      dashes = true;
      args.push({ kind: 'option', text: t, index: i, names: ['--'], value: null });
      continue;
    }
    if (t.startsWith('--') && t.length > 2) {
      const eq = t.indexOf('=');
      const text = eq > 0 ? t.slice(2, eq) : t.slice(2);
      const glued = eq > 0 ? t.slice(eq + 1) : null;
      // (a word the verb does not list, but that begins one of the governed options, is read as that option: git refuses it, and
      // "refused" is not a licence to read it as nothing - `git cherry-pick abc --no-verif` was a hook bypass in every table this
      // repository has kept)
      const found = resolveLong(table, text) ?? governedPrefix(text);
      const arg = found?.arg ?? 0;
      let value: string | null = glued;
      const at = i;
      if (glued === null && arg === 1 && i + 1 < tokens.length) value = tokens[++i]!;
      args.push({ kind: 'option', text: t, index: at, names: found?.names ?? [`--${text}`], full: found?.full ?? `--${text}`, value });
      recordConfig(verb, args[args.length - 1]!, configs);
      continue;
    }
    if (t.startsWith('-') && t.length > 1) {
      // a cluster of short options: each letter is an option, and the first that takes a value takes the rest of the word
      for (let k = 1; k < t.length; k++) {
        const c = t[k]!;
        const o = table.shorts.get(c);
        const arg = o?.arg ?? 0;
        const rest = t.slice(k + 1);
        let value: string | null = null;
        let consumed = false;
        const at = i;
        if (arg === 1) {
          value = rest !== '' ? rest : i + 1 < tokens.length ? tokens[++i]! : null;
          consumed = true;
        } else if (arg === 2 && rest !== '') {
          value = rest;
          consumed = true;
        }
        args.push({ kind: 'option', text: t, index: at, names: o?.names ?? [`-${c}`], value });
        recordConfig(verb, args[args.length - 1]!, configs);
        if (consumed) break;
      }
      continue;
    }
    args.push({ kind: 'positional', text: t, index: i });
  }
  return args;
}

/** `git clone --config k=v` (and `-c k=v` of clone) is the global `-c` by clone's own spelling, and it stands after the verb */
function recordConfig(verb: string, arg: GitArg, configs: GitConfigSetting[]): void {
  if (verb !== 'clone' || arg.value == null) return;
  const long = arg.names?.some((n) => n === '--config' || n === '-c') === true;
  if (!long) return;
  const at = arg.value.indexOf('=');
  configs.push({ key: at < 0 ? arg.value : arg.value.slice(0, at), value: at < 0 ? 'true' : arg.value.slice(at + 1), via: '--config' });
}

/**
 * THE LONG OPTIONS WHOSE SPELLING DECIDES WHAT A COMMAND DOES. git refuses an ambiguous abbreviation and runs nothing, so what a
 * line that carries one means is not a question git answers - but it IS a question the kernel must not answer with "nothing":
 * `git merge --no-verif` is a prefix of `--no-verify` and of `--no-verify-signatures`, and read as neither it is a hook bypass
 * nobody saw. An ambiguous prefix is therefore read as the first of these it could be, and a prefix that fits none stays as written.
 */
export const GOVERNED_LONG_OPTIONS: readonly string[] = [
  '--no-verify', '--force', '--force-with-lease', '--force-create', '--delete', '--amend', '--upload-pack', '--receive-pack',
  '--exec', '--template', '--discard-changes', '--prune', '--mirror', '--tags', '--all', '--hard', '--no-edit',
  '--set-upstream', '--unset-upstream', '--move', '--copy', '--config-env', '--global', '--system', '--unset',
  '--include-untracked', '--worktree', '--source', '--output',
];

/** The option a long word names: an exact name, else the unique name it is a prefix of; an ambiguous prefix is the first
 *  governed option it could be (above), else none. `full` is the name in full. */
function resolveLong(table: ReturnType<typeof compileOptions>, text: string): (OptionEntry & { full: string }) | null {
  const exact = table.longs.get(text);
  if (exact) return { ...exact, full: `--${text}` };
  const found: Array<OptionEntry & { full: string }> = [];
  const seen = new Set<OptionEntry>();
  for (const [name, o] of table.longs) {
    if (!name.startsWith(text) || seen.has(o)) continue;
    seen.add(o);
    found.push({ ...o, full: `--${name}` });
  }
  if (found.length === 1) return found[0]!;
  for (const g of GOVERNED_LONG_OPTIONS) {
    const hit = found.find((f) => f.full === g);
    if (hit) return hit;
  }
  return null;
}

/** the governed option a word is a prefix of, for a verb whose own options are not listed */
function governedPrefix(text: string): (OptionEntry & { full: string }) | null {
  const full = GOVERNED_LONG_OPTIONS.find((g) => g.startsWith(`--${text}`));
  return full === undefined ? null : { names: [full], arg: 0, full };
}

/** Is this option (by any of its canonical names) on the line? */
export function gitOption(inv: GitInvocation, ...names: string[]): GitArg | undefined {
  return inv.args.find((a) => a.kind === 'option' && a.names!.some((n) => names.includes(n)));
}

/** The words after the verb that are not options, in order (everything after `--` included). */
export function gitPositionals(inv: GitInvocation): GitArg[] {
  return inv.args.filter((a) => a.kind === 'positional');
}

/**
 * The tokens with every long option the verb lists written out in full: `--force-c` is `--force-create`, `--no-verif` is
 * `--no-verify`. Matchers are regular expressions over this text and name the full spelling; git accepts any unambiguous prefix,
 * so a matcher that sees the prefix has not seen the option. A word that is the VALUE of an option is left alone.
 */
export function canonicalGitTokens(tokens: readonly string[], inv: GitInvocation): string[] {
  const out = tokens.slice();
  for (const a of inv.args) {
    if (a.kind !== 'option' || a.full === undefined) continue;
    const eq = a.text.indexOf('=');
    const written = eq > 0 ? a.text.slice(0, eq) : a.text;
    if (written !== a.full && a.full.startsWith(written)) out[a.index] = a.full + (eq > 0 ? a.text.slice(eq) : '');
  }
  return out;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * What the line does
 * ------------------------------------------------------------------------------------------------------------- */

/**
 * DOES THIS LINE MOVE A BRANCH THAT EXISTS? `checkout -B`, `switch -C` and `branch -M` / `-C` reset a ref to a commit of the
 * caller's choosing and destroy what it pointed at, where `-b` / `-c` / `-m` create or rename. The long spelling of `switch -C`
 * is `--force-create`, which no list of the short ones names; the option table says they are one.
 */
export function forcesRefReset(inv: GitInvocation): boolean {
  switch (inv.verb) {
    case 'checkout':
      return gitOption(inv, '-B') !== undefined;
    case 'switch':
      return gitOption(inv, '-C', '--force-create') !== undefined;
    case 'branch':
      return gitOption(inv, '-M', '-C') !== undefined;
    case 'worktree':
      // `worktree add -B <branch> <path>` resets <branch> exactly as `checkout -B` does
      return inv.args.some((a) => a.kind === 'option' && a.text.startsWith('-') && /^-[a-zA-Z]*B/.test(a.text) && !a.text.startsWith('--'));
    default:
      return false;
  }
}

/**
 * THE PATHSPECS A `checkout` OR `restore` WRITES INTO THE WORKING TREE. After `--` they are the words that follow; without it, a
 * `checkout <tree-ish> <pathspec>` with two words is a path restore, and one word that is not a branch is too (git decides by
 * asking the repository; the kernel cannot, so one word that cannot be a ref name counts). Null when the line writes no path.
 */
export function restoredPathspecs(inv: GitInvocation): string[] | null {
  if (inv.verb !== 'checkout' && inv.verb !== 'restore') return null;
  // `restore --staged` alone touches the index, not the files
  if (inv.verb === 'restore' && gitOption(inv, '-S', '--staged') !== undefined && gitOption(inv, '-W', '--worktree') === undefined) return null;
  if (gitOption(inv, '-b', '-B', '--orphan', '-p', '--patch') !== undefined && inv.verb === 'checkout' && !inv.args.some((a) => a.afterDashDash)) return null;
  const after = inv.args.filter((a) => a.kind === 'positional' && a.afterDashDash === true).map((a) => a.text);
  if (after.length > 0) return after;
  const positional = gitPositionals(inv).map((a) => a.text);
  if (inv.verb === 'restore') return positional;
  if (positional.length >= 2) return positional.slice(1);
  if (positional.length === 1 && wholeTreePathspec(positional[0]!)) return positional;
  return null;
}

/** Does this pathspec name every file of the tree it is read in: `.`, `./`, `*`, `:/`, `:(top)`, and their padded spellings? */
export function wholeTreePathspec(spec: string): boolean {
  let s = spec.trim();
  const magic = /^:\(([^)]*)\)(.*)$/.exec(s);
  if (magic) s = magic[2]!;
  else if (s.startsWith(':/')) s = s.slice(2);
  else if (/^:[!^]/.test(s)) return false; // an exclusion names no file
  s = s.replace(/^(\.\/+)+/, '').replace(/\/+$/, '');
  return s === '' || s === '.' || s === '*' || s === '**' || s === './*' || s === '.*';
}

/**
 * THE REPOSITORY A TRANSPORT VERB IS POINTED AT. `clone <repo>`, `fetch <repo>`, `pull <repo>` and `ls-remote <repo>` read the
 * repository the first word names, and when that is a local path - or a `file://` URL, which is the same path - they read it
 * from disk, whatever it contains. `--reference <repo>` and `--shared` borrow its objects. Returns the raw words.
 */
export function transportOperands(inv: GitInvocation): string[] {
  const out: string[] = [];
  const positional = gitPositionals(inv);
  if (/^(clone|fetch|pull|ls-remote|fetch-pack)$/.test(inv.verb) && positional[0] !== undefined) out.push(positional[0].text);
  for (const a of inv.args)
    if (a.kind === 'option' && a.value != null && a.names!.some((n) => n === '--reference' || n === '--reference-if-able' || n === '--remote' || n === '--separate-git-dir'))
      out.push(a.value);
  return out;
}

/**
 * The local path a repository operand denotes, or null when it is a remote. A `file://` URL names a path (`file:///a/b`, or
 * `file://host/a/b` - git ignores the host - percent-decoded); `host:path` and `scheme://host/…` are remotes; anything else - absolute, relative,
 * `~`, a bare name - is a path as the shell hands it to git.
 */
export function localRepositoryPath(operand: string): string | null {
  // (git reads the path of a `file://` URL and ignores the host in front of it, so `file://anything/etc/x` is `/etc/x`)
  const file = /^file:\/\/[^/]*(\/.*)$/i.exec(operand);
  if (file) {
    try {
      return decodeURIComponent(file[1]!);
    } catch {
      return file[1]!;
    }
  }
  if (/^file:/i.test(operand)) return null;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(operand)) return null;
  if (/^[^/\\\s]*@?[^/\\\s]*:/.test(operand) && !/^[A-Za-z]:[\\/]/.test(operand)) return null; // `host:path`, `user@host:path`, `ext::cmd`
  return operand;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * Verbs
 * ------------------------------------------------------------------------------------------------------------- */

const KNOWN = new Set(GIT_KNOWN_VERBS);
const BUILTIN = new Set(GIT_BUILTIN_VERBS);

/**
 * THE HYPHENATED COMMANDS THAT HAVE A RULE OF THEIR OWN. A pattern that names a verb ends it with `\b`, and `\b` matches in front
 * of a hyphen, so `git remote-ext …` was `git remote`, `git checkout-index -f -a` was `git checkout` and `git status-evil` was
 * `git status`: a command that is a different program, read as the verb it begins with. Every hyphenated command is therefore
 * written with underscores for the matchers unless it is one a matcher names (control-plane/permissions/matchers.md) or one that
 * only reads; the test of this module checks that the list and the matchers agree.
 */
export const GIT_HYPHENATED_WITH_RULES: ReadonlySet<string> = new Set([
  'cat-file', 'check-attr', 'check-ignore', 'cherry-pick', 'commit-tree', 'count-objects', 'credential-store', 'diff-files',
  'diff-index', 'diff-tree', 'for-each-ref', 'ls-files', 'ls-remote', 'ls-tree', 'merge-base', 'merge-file', 'merge-index',
  'merge-tree', 'name-rev', 'receive-pack', 'remote-ext', 'rev-list', 'rev-parse', 'send-pack', 'show-branch', 'show-ref',
  'update-ref', 'upload-pack', 'verify-pack',
]);

/** Is this word a command git ships? (A word that is not is an external program, `git-<word>`, or an alias.) */
export function isKnownGitVerb(verb: string): boolean {
  return KNOWN.has(verb);
}

/** Is this a command built into the git binary? */
export function isBuiltinGitVerb(verb: string): boolean {
  return BUILTIN.has(verb);
}

/** The verb as the matchers should read it: a hyphenated name without a rule of its own is not the verb it starts with. */
export function matcherVerb(verb: string): string {
  return verb.includes('-') && !GIT_HYPHENATED_WITH_RULES.has(verb) ? verb.replace(/-/g, '_') : verb;
}
