// A COPY OF A LINK IS A LINK (closure audit 2026-10-02, wave 6, PA-05).
//
// The kernel judges each path a command writes at the moment it decides, when a name that this very command is about to make does not
// exist. Exit review 9 closed the case of a link made on the line (`ln -s ../.harness k/h && echo x > k/h/runtime/pin.json`): the link
// to a governed tree is refused when it is made. It is the same act when the link is made by a COPY - `cp -a lgen nl`, `cp -R lc nl`,
// `rsync -a`, a directory that merely holds links (`cp -R sub newcopy`, with `sub/up -> ../.git/hooks`) - and a repository that is cloned
// can ship a link into a governed tree. `cp -a` is the first thing a tool-using agent tries after `ln -s` is refused, and the write that
// follows (`echo x > nl/x`) was judged as the ordinary path it spells: .harness/generated, .git/hooks, .claude and control-plane
// were rewritten at ALLOW.
//
// So a copy that keeps links is asked what links it keeps: the links among its sources and below them, and where each leads. The
// question is whether any of them leads into a governed tree - the rule `ln -s` is judged by - and is answered by the caller, which has
// the table; this module only reads the disk, within a bound.
import { lstatSync, readdirSync } from 'node:fs';
import { join, sep } from 'node:path';
import { canonicalPath, chargeListing, GLOB_ENTRY_BUDGET } from './paths.ts';

/** What a copier does with a link it meets, from the last option that says: `-L` follows every link (the content is copied), `-P`, `-d`
 *  and `-a` keep them, `-H` follows the ones named on the command line and keeps the rest, and a recursive copy keeps them unless told
 *  otherwise (GNU and BSD alike). Not a copier of links at all: 'follow'. */
export function copiesLinks(head: string, tokens: readonly string[]): boolean {
  const name = head.replace(/^.*\//, '');
  const isCp = name === 'cp' || name === 'gcp';
  const isRsync = name === 'rsync';
  if (!isCp && !isRsync && name !== 'ditto') return false;
  if (name === 'ditto') return true; // ditto keeps symbolic links as links, and has no option to follow them
  let mode: 'unset' | 'keep' | 'follow' = 'unset';
  let recursive = false;
  for (const t of tokens.slice(1)) {
    if (t === '--') break;
    if (t.startsWith('--')) {
      if (/^--(dereference|copy-links)$/.test(t)) mode = 'follow';
      else if (/^--(no-dereference|archive|links)$/.test(t)) mode = 'keep';
      else if (/^--(recursive)$/.test(t)) recursive = true;
      continue;
    }
    if (!/^-[A-Za-z]+$/.test(t)) continue;
    for (const c of t.slice(1)) {
      if (c === 'L') mode = 'follow';
      else if (isCp && (c === 'P' || c === 'd' || c === 'a' || c === 'H')) mode = 'keep';
      else if (isRsync && (c === 'a' || c === 'l')) mode = 'keep';
      else if (isCp && (c === 'r' || c === 'R')) recursive = true;
      else if (isRsync && c === 'r') recursive = true;
    }
  }
  // a recursive copy keeps links unless told otherwise; rsync keeps nothing it was not told to
  return mode === 'keep' || (isCp && recursive && mode === 'unset');
}

/** The directories whose contents are not walked: a dependency tree and the object store are larger than every budget, and what a package
 *  ships or git stores is not a link into the working tree's governed paths. */
const NOT_WALKED: ReadonlySet<string> = new Set(['node_modules']);

export interface LinksUnder {
  /** where each link at or below the path really leads (canonical, posix) */
  readonly targets: string[];
  /** the walk stopped at its bound: the links beyond it are unknown */
  readonly bounded: boolean;
}

/** The links at `abs` (when it is one) and below it (when it is a directory), and where each leads. A directory link is a link: it is
 *  recorded, not entered. Bounded by the same entry budget a wildcard expansion has. */
export function linksUnder(abs: string): LinksUnder {
  const targets: string[] = [];
  let budget = GLOB_ENTRY_BUDGET;
  let bounded = false;
  const stack: string[] = [abs];
  while (stack.length > 0 && !bounded) {
    const here = stack.pop()!;
    let st;
    try {
      st = lstatSync(here);
    } catch {
      continue;
    }
    if (st.isSymbolicLink()) {
      targets.push(canonicalPath(here).split(sep).join('/'));
      continue;
    }
    if (!st.isDirectory()) continue;
    let entries;
    try {
      entries = readdirSync(here, { withFileTypes: true });
    } catch {
      continue;
    }
    chargeListing(entries.length);
    budget -= entries.length;
    if (budget < 0) {
      bounded = true;
      break;
    }
    for (const e of entries) {
      if (NOT_WALKED.has(e.name) || (e.name === 'objects' && here.endsWith(`${sep}.git`))) continue;
      stack.push(join(here, e.name));
    }
  }
  return { targets, bounded };
}
