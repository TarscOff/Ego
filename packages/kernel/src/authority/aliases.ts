// A PROTECTED PATH IS A PLACE, NOT A SPELLING (closure audit 2026-10-02, wave 6, PA-07 and PA-08).
//
// Every rule of the control plane names a path: `.claude/settings.json`, `.harness/generated/**`, `**/.git/hooks/**`, `~/.ssh/**`. The
// evaluator matched the rule against the NAME a command spells and against the path that name resolves to, which finds a link that leads
// INTO a protected tree (`d -> .claude/sub`). It never asked the question the other way round: where does the PROTECTED NAME lead?
//
//   - `.claude -> shared/claude` (a shared agent configuration linked into several worktrees; `~/.ssh -> dotfiles/ssh` for stow, yadm and
//     chezmoi): the host reads the hook registration and the keys through the link, and `echo x > shared/claude/settings.json` names the
//     same file by its real location - which no rule spelled;
//   - `.git` as a FILE (`gitdir: ./.bare`, `git init --separate-git-dir`, a worktree): git runs the hooks of, and reads the configuration
//     of, the directory the file names, and `echo x > .bare/hooks/pre-commit` is the protected `.git/hooks/pre-commit`.
//
// So the places a protected name really is are read ONCE here, for a path rule: `{ real, name }` says that what is under `real` is what the
// rule would call under `name`. The rule is then matched against the path as if it had been spelled with the protected name (see
// matchPathPattern). This module reads the disk (a link, a one-line file) and judges nothing.
import { readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve, sep } from 'node:path';
import { canonicalPath, memoPerEvaluation } from './paths.ts';

export interface Alias {
  /** where the protected name really is (canonical, posix separators) */
  readonly real: string;
  /** the protected name as a rule spells it, under a registered root or the home directory (canonical root, posix separators) */
  readonly name: string;
}

const posix = (p: string): string => p.split(sep).join('/');
const WILDCARD = /[*?[{]/;

/** The fixed head of a path rule: the components in front of the first wildcard (`.claude/hooks/**` -> `.claude/hooks`), where it begins
 *  (`root`, `home` or `fs`). A rule that begins with `**` / is a name anywhere has its head after that: it is where the rule matters at the
 *  root of a checkout (`**` + `/.git/hooks/**` -> `.git/hooks`). */
function headOf(pattern: string): { anchor: 'root' | 'home' | 'fs'; head: string[] } {
  let pat = pattern;
  let anchor: 'root' | 'home' | 'fs' = 'root';
  if (pat.startsWith('~/')) {
    anchor = 'home';
    pat = pat.slice(2);
  } else if (pat.startsWith('/')) {
    anchor = 'fs';
    pat = pat.slice(1);
  } else pat = pat.replace(/^\*\*\//, '');
  const head: string[] = [];
  for (const c of pat.split('/')) {
    if (c === '' || WILDCARD.test(c)) break;
    head.push(c);
  }
  return { anchor, head };
}

/** `gitdir: PATH` of a `.git` file, the git directory it names (canonical), and the common directory of a linked worktree
 *  (`<gitdir>/commondir`, relative to it). Null when `.git` is not a file that names a directory. */
function separateGitDirs(root: string): string[] {
  const dotGit = join(root, '.git');
  try {
    const st = statSync(dotGit);
    if (!st.isFile() || st.size > 4096) return [];
    const m = /^gitdir:\s*(.+?)\s*$/m.exec(readFileSync(dotGit, 'utf8'));
    if (!m) return [];
    const gitdir = canonicalPath(isAbsolute(m[1]!) ? m[1]! : resolve(root, m[1]!));
    const out = [gitdir];
    try {
      const common = readFileSync(join(gitdir, 'commondir'), 'utf8').trim();
      if (common !== '') out.push(canonicalPath(isAbsolute(common) ? common : resolve(gitdir, common)));
    } catch {
      /* not a linked worktree */
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Where the protected name a rule spells really leads, for each place the rule can be anchored (`roots`: the canonical registered
 * roots; the home directory; the filesystem). Empty for the common case, a rule whose head is not a link and a checkout whose `.git` is a
 * directory - which costs the lookups `canonicalPath` already caches, once per rule and root for the whole evaluation.
 */
export function aliasesOf(pattern: string, roots: readonly string[]): readonly Alias[] {
  return memoPerEvaluation(`alias\0${pattern}\0${roots.join('\0')}`, () => {
    const { anchor, head } = headOf(pattern);
    if (head.length === 0) return [];
    const bases = anchor === 'home' ? [posix(canonicalPath(homedir()))] : anchor === 'fs' ? [''] : [...roots];
    const out: Alias[] = [];
    for (const base of bases) {
      const name = `${base}/${head.join('/')}`;
      const real = posix(canonicalPath(name));
      if (real !== name) out.push({ real, name });
      // `.git` is a FILE: the git directory is where the name `.git/...` really is, and the common directory is where a linked worktree
      // keeps what is shared (the hooks, the configuration)
      if (anchor === 'root' && head[0] === '.git')
        for (const dir of separateGitDirs(base)) out.push({ real: [posix(dir), ...head.slice(1)].join('/'), name });
    }
    return out;
  });
}
