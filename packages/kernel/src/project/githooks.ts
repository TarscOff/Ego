// Repo-side git hooks (section H enforcement layer): pre-commit secret scan and freshness, pre-push governance in
// agent shells. Installed as thin shims chaining any pre-existing hook; husky-managed hooks gain one line instead.
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { homedir } from 'node:os';
import { chmodSync, existsSync, renameSync, copyFileSync, realpathSync, statSync } from 'node:fs';
import { ensureDir, isFile, readTextIfExists, writeAtomic } from '../util/fs.ts';
import { packageRoot } from '../launcher/self.ts';
import { git, gitConfigScope } from '../util/git.ts';
import { loadControlPlane } from '../control-plane/load.ts';
import { readPolicyCache } from '../policy/cache.ts';
import { sealFor } from '../policy/seal.ts';
import { flatText } from '../util/shown-text.ts';
import { readPin } from '../launcher/pin.ts';
import { explainOutcome, renderReason } from '../authority/reasons.ts';
import { redact, allDetectors, isSensitiveFileName } from '../redaction/redact.ts';
import { controlPlaneDir } from '../launcher/self.ts';

export const GIT_HOOK_NAMES = ['pre-commit', 'pre-push'] as const;
const MARK = '# ego-hook';

/** Resolves `core.hooksPath` the way git does: absolute as is, `~` expanded, otherwise relative to the work tree. */
export function resolveHooksPath(projectRoot: string, hooksPath: string): string {
  if (hooksPath.startsWith('~/')) return join(homedir(), hooksPath.slice(2));
  if (hooksPath === '~') return homedir();
  return isAbsolute(hooksPath) ? hooksPath : resolve(projectRoot, hooksPath);
}

/** The directory git actually runs hooks from (linked worktrees share the common hooks dir). */
/** @untrusted the directory the repository's own configuration says git runs hooks from */
export function gitHooksDir(projectRoot: string, hooksPath: string | null): string {
  if (hooksPath) return resolveHooksPath(projectRoot, hooksPath);
  const r = git(['rev-parse', '--path-format=absolute', '--git-path', 'hooks'], projectRoot);
  if (r.ok && r.stdout) return r.stdout;
  const rel = git(['rev-parse', '--git-path', 'hooks'], projectRoot);
  return rel.ok && rel.stdout ? resolve(projectRoot, rel.stdout) : join(projectRoot, '.git', 'hooks');
}

export interface GitHookInstallResult {
  installed: string[];
  notes: string[];
  /** a required hook could not be installed (machine-wide hooksPath): doctor reports NOT SATISFIED */
  refused: string | null;
}

function canonical(p: string): string {
  try {
    return realpathSync(resolve(p));
  } catch {
    return resolve(p);
  }
}

function insideProject(projectRoot: string, dir: string): boolean {
  const root = resolve(projectRoot);
  const d = resolve(dir);
  return d === root || d.startsWith(root + sep);
}

/** The generated hook: runs the EGO shim, or (in a checkout that is not governed by EGO) the chained user hooks only. */
export function shimScript(name: string): string {
  return `#!/bin/sh
${MARK}
top="$(git rev-parse --show-toplevel)"
here="$(cd "$(dirname "$0")" && pwd)"
# A linked worktree shares .git/hooks with the main worktree but keeps its OWN (untracked) .harness/, so the pin and
# the shim live in the MAIN worktree. Resolve it from the shared git common dir and check both, or EGO governance
# would silently not run in every linked worktree (fail open).
common="$(git rev-parse --git-common-dir 2>/dev/null)"
case "$common" in
  "") ;;
  /*) ;;
  *) common="$top/$common" ;;
esac
maintop=""
if [ -n "$common" ]; then maintop="$(CDPATH= cd "$(dirname "$common")" 2>/dev/null && pwd)"; fi
for base in "$top" "$maintop"; do
  [ -n "$base" ] || continue
  shim="$base/.harness/hooks/git-hook.sh"
  if [ -f "$shim" ]; then exec sh "$shim" ${name} "$here" "$@"; fi
done
for base in "$top" "$maintop"; do
  [ -n "$base" ] || continue
  if [ -f "$base/.harness/harness.md" ]; then
    echo "EGO: $base/.harness/hooks/git-hook.sh is missing in a checkout pinned to EGO; failing closed (run ego init)" >&2
    exit 1
  fi
done
echo "EGO: this checkout is not governed by EGO (no .harness/harness.md); only the chained hooks run" >&2
input=""
if [ "${name}" = "pre-push" ]; then input="$(cat)"; fi
for chained in "$here/${name}.pre-ego" "$here/${name}.pre-ego".*; do
  [ -f "$chained" ] || continue
  # keep "$chained" quoted: a hooks directory whose path contains spaces must not be word-split
  if [ "${name}" = "pre-push" ]; then
    if [ -x "$chained" ]; then printf '%s\\n' "$input" | "$chained" "$@" || exit $?; else printf '%s\\n' "$input" | sh "$chained" "$@" || exit $?; fi
  else
    if [ -x "$chained" ]; then "$chained" "$@" </dev/null || exit $?; else sh "$chained" "$@" </dev/null || exit $?; fi
  fi
done
exit 0
`;
}

/** Husky keeps its runner in `<dir>/_` (with `h`) and the user hooks in `<dir>`; returns the user-hook directory. */
export function huskyUserDir(gitRunsDir: string): string | null {
  if (!/[\\/]_$/.test(gitRunsDir)) return null;
  const parent = dirname(gitRunsDir);
  if (isFile(join(gitRunsDir, 'h')) || /[\\/]\.husky$/.test(parent)) return parent;
  return null;
}

export function installGitHooks(projectRoot: string, hooksPath: string | null): GitHookInstallResult {
  const installed: string[] = [];
  const notes: string[] = [];
  // git resolves hooks upward to an enclosing repository: a directory that is not itself a git toplevel would get its
  // hooks written into whatever repository contains it. Refuse instead.
  const top = git(['rev-parse', '--show-toplevel'], projectRoot);
  if (!top.ok || !top.stdout || canonical(top.stdout) !== canonical(projectRoot)) {
    const refused = `git hooks NOT installed: ${projectRoot} is not the top level of a git repository${top.ok && top.stdout ? ` (enclosing repository: ${top.stdout})` : ''}`;
    notes.push(refused);
    return { installed, notes, refused };
  }
  const shim = join(projectRoot, '.harness', 'hooks', 'git-hook.sh');
  if (!isFile(shim)) {
    ensureDir(join(projectRoot, '.harness', 'hooks'));
    copyFileSync(join(packageRoot(), 'runtime', 'posix', 'git-hook.sh'), shim);
    chmodSync(shim, 0o755);
  }
  // the directory git itself runs hooks from (core.hooksPath expanded by git, ~user included)
  const gitDir = gitHooksDir(projectRoot, null);
  if (
    hooksPath &&
    gitConfigScope(projectRoot, 'core.hooksPath') === 'global' &&
    !insideProject(projectRoot, gitDir)
  ) {
    // a machine-wide core.hooksPath (global or system git config) is never written: it would govern every repository
    const refused = `git hooks NOT installed: core.hooksPath=${flatText(hooksPath)} comes from the global git configuration and resolves outside this repository (${flatText(gitDir)}); set a repository-local hooks path (\`git config core.hooksPath .githooks\`) and run \`ego init\` again`;
    notes.push(refused);
    return { installed, notes, refused };
  }
  const husky = huskyUserDir(gitDir);
  const dir = husky ?? gitDir;
  ensureDir(dir);
  for (const name of GIT_HOOK_NAMES) {
    const path = join(dir, name);
    const existing = readTextIfExists(path);
    if (existing !== null && !existing.includes(MARK)) {
      // the user's hook keeps working unchanged, whatever its language: it is chained, never edited
      let backup = `${path}.pre-ego`;
      for (let n = 1; isFile(backup); n++) backup = `${path}.pre-ego.${n}`;
      renameSync(path, backup);
      notes.push(`git hooks: existing ${name} kept as ${backup.slice(dir.length + 1)} and chained`);
    }
    writeAtomic(path, shimScript(name));
    chmodSync(path, 0o755);
    installed.push(path);
  }
  if (husky && !isFile(join(gitDir, 'h')))
    notes.push(
      `git hooks: husky runner ${flatText(gitDir)}/h is missing (run \`npx husky\` or \`npm install\`); until then git runs no hooks`,
    );
  if (hooksPath)
    notes.push(
      `git hooks: installed in ${flatText(dir.startsWith(projectRoot) ? dir.slice(projectRoot.length + 1) : dir)} (core.hooksPath=${flatText(hooksPath)}${husky ? ', husky layout' : ''})`,
    );
  return { installed, notes, refused: null };
}

/** What doctor and check need to know about the installed git hooks. */
export interface GitHookStatus {
  ok: boolean;
  /** @untrusted where the repository's own configuration says git runs hooks from */
  dir: string;
  problems: string[];
}

export function gitHookStatus(projectRoot: string): GitHookStatus {
  const gitDir = gitHooksDir(projectRoot, null);
  const husky = huskyUserDir(gitDir);
  const dir = husky ?? gitDir;
  const problems: string[] = [];
  if (!isFile(join(projectRoot, '.harness', 'hooks', 'git-hook.sh')))
    problems.push('.harness/hooks/git-hook.sh missing');
  if (husky && !isFile(join(gitDir, 'h')))
    problems.push(`husky runner ${flatText(gitDir)}/h missing (git runs no hooks)`);
  for (const name of GIT_HOOK_NAMES) {
    const path = join(dir, name);
    const text = readTextIfExists(path);
    let executable: boolean;
    try {
      executable = (statSync(path).mode & 0o111) !== 0;
    } catch {
      executable = false;
    }
    if (text === null || !text.includes(MARK)) problems.push(`${name}: EGO hook missing`);
    else if (!executable && !husky) problems.push(`${name}: not executable`);
  }
  return { ok: problems.length === 0, dir, problems };
}

export interface GitHookResult {
  ok: boolean;
  messages: string[];
}

/** Agent shells are recognised by host environment markers; a human terminal has none. */
export function isAgentShell(env: NodeJS.ProcessEnv): boolean {
  return (
    env['CLAUDECODE'] === '1' ||
    env['CLAUDE_CODE'] === '1' ||
    Boolean(env['CLAUDE_PID']) ||
    Boolean(env['CODEX_SANDBOX']) ||
    env['CODEX_CLI'] === '1' ||
    Boolean(env['CODEX_THREAD_ID'])
  );
}

const SCAN_MAX_BUFFER = 256 * 1024 * 1024;

/** generated dependency lockfiles (integrity hashes trip detectors); any other *.lock file is scanned */
const LOCKFILE_EXCLUDES = [
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'Cargo.lock',
  'poetry.lock',
  'Pipfile.lock',
  'uv.lock',
  'Gemfile.lock',
  'composer.lock',
  'go.sum',
  'mix.lock',
  'flake.lock',
  'packages.lock.json',
].map((n) => `:(exclude,glob)**/${n}`);

/** The pre-push hook's answer for an agent shell, and the sentence it refuses with. The sentence carries the same code,
 *  rule source and configurability as the PreToolUse refusal for the same capability because it comes from the same
 *  mapping (`explainOutcome`), not from a second description of the tier. */
function pushDecision(projectRoot: string, env: NodeJS.ProcessEnv): { verdict: string; refusal: string } {
  const base =
    'pushes from agent sessions are governed by EGO (git.remote.push is DENY unless the organization policy widens it); a human pushes from their own terminal';
  try {
    const pin = readPin(projectRoot);
    const cache = readPolicyCache(projectRoot, sealFor(env));
    const mode = cache?.table.defaultMode ?? '';
    const verdict =
      cache?.table.profiles[pin.profile]?.modes[mode]?.['git.remote.push'] ??
      cache?.table.effective['git.remote.push'] ??
      'DENY';
    const outcome =
      cache && verdict !== 'ALLOW'
        ? explainOutcome(
            cache.table,
            { profile: pin.profile, mode },
            { capability: 'git.remote.push', verdict, absolute: false },
          )
        : undefined;
    return { verdict, refusal: outcome ? renderReason(base, outcome) : base };
  } catch {
    return { verdict: 'DENY', refusal: base };
  }
}

/** The temporary index git hands a hook it invoked itself (`git commit -a` stages into one), but only when it really
 *  belongs to this repository's git directory. An agent-supplied GIT_INDEX_FILE pointing anywhere else is ignored, so
 *  the scan can never be aimed at an attacker-chosen index. Returns null when the real index should be used. */
function hookIndexFile(projectRoot: string, env: NodeJS.ProcessEnv): string | null {
  const raw = env['GIT_INDEX_FILE'];
  if (!raw) return null;
  const common = git(['rev-parse', '--git-common-dir'], projectRoot);
  const gitDir = git(['rev-parse', '--git-dir'], projectRoot);
  const abs = isAbsolute(raw) ? raw : resolve(projectRoot, raw);
  const roots = [common.ok ? common.stdout : '', gitDir.ok ? gitDir.stdout : '']
    .filter(Boolean)
    .map((d) => (isAbsolute(d) ? d : resolve(projectRoot, d)));
  const real = (p: string): string => {
    try {
      return realpathSync(p);
    } catch {
      return resolve(p);
    }
  };
  const target = real(dirname(abs));
  return roots.some((r) => {
    const rr = real(r);
    return target === rr || target.startsWith(rr + sep);
  })
    ? abs
    : null;
}

/** Git hooks fail closed: a scan that cannot run (git error, buffer overflow, timeout) refuses instead of passing. */
export function runGitHook(
  name: string,
  projectRoot: string,
  env: NodeJS.ProcessEnv,
  stdin: string,
): GitHookResult {
  const messages: string[] = [];
  const cp = loadControlPlane(controlPlaneDir());
  const detectors = allDetectors(cp.secrets).filter((d) => d.severity === 'block');
  if (name === 'pre-commit') {
    const indexFile = hookIndexFile(projectRoot, env);
    const staged = git(
      ['-c', 'core.quotePath=false', 'diff', '--cached', '--name-only', '-z', '--diff-filter=ACMRT'],
      projectRoot,
      {
        maxBuffer: SCAN_MAX_BUFFER,
        ...(indexFile ? { indexFile } : {}),
      },
    );
    if (!staged.ok)
      return { ok: false, messages: [`refused: cannot list staged files (${staged.stderr || 'git error'})`] };
    const files = staged.stdout.split('\0').filter(Boolean);
    for (const f of files) {
      if (f.startsWith('.harness/runtime/') || f.startsWith('.harness/generated/'))
        messages.push(`refused: ${f} is runtime or generated state and is never committed`);
      if (
        isSensitiveFileName(f.split('/').pop() ?? f, cp.secrets) &&
        !/\.example$|\.sample$|\.template$/.test(f)
      )
        messages.push(`refused: ${f} looks like a secret-bearing file`);
      const content = git(['show', `:${f}`], projectRoot, {
        maxBuffer: SCAN_MAX_BUFFER,
        timeoutMs: 60_000,
        ...(indexFile ? { indexFile } : {}),
      });
      if (!content.ok) {
        messages.push(
          `refused: cannot read staged ${f} for the secret scan (${content.stderr || 'git error'})`,
        );
        continue;
      }
      const r = redact(content.stdout, detectors, { isFile: true });
      if (r.blocked) messages.push(`refused: ${f} contains ${r.findings.map((x) => x.detector).join(', ')}`);
    }
    return { ok: messages.length === 0, messages };
  }
  if (name === 'pre-push') {
    if (isAgentShell(env)) {
      // Q98: an organization may widen git.remote.push; then the PreToolUse decision (ASK answered by a human, or ALLOW) governs
      const push = pushDecision(projectRoot, env);
      if (push.verdict === 'DENY') {
        messages.push(`refused: ${push.refusal}`);
        return { ok: false, messages };
      }
    }
    const pushLines = stdin
      .split('\n')
      .filter(Boolean)
      .map((line) => line.split(' '));
    // Baseline for new-branch scans: the remote SHAs git itself reported for this push (computed from the real remote
    // during negotiation, so not forgeable locally). We deliberately do NOT use `--remotes`: a local remote-tracking
    // ref (`refs/remotes/origin/*`) can be planted by an agent to cover a secret commit and make `--not --remotes`
    // skip it. With no trustworthy baseline a new branch is scanned in full (correctness over speed for a secret scan).
    const remoteBaseline = pushLines
      .map((p) => p[3])
      .filter((s): s is string => !!s && !/^0+$/.test(s));
    for (const parts of pushLines) {
      const localSha = parts[1];
      const remoteSha = parts[3];
      if (!localSha || /^0+$/.test(localSha)) continue; // a branch deletion pushes nothing
      // every pushed commit's own patch is scanned (net-zero ranges and new branches included), never the working tree
      const args =
        remoteSha && !/^0+$/.test(remoteSha)
          ? ['log', '-p', '-m', '--text', '--format=commit %H', `${remoteSha}..${localSha}`]
          : remoteBaseline.length
            ? ['log', '-p', '-m', '--text', '--format=commit %H', localSha, '--not', ...remoteBaseline]
            : ['log', '-p', '-m', '--text', '--format=commit %H', localSha];
      const log = git([...args, '--', '.', ...LOCKFILE_EXCLUDES], projectRoot, {
        timeoutMs: 120_000,
        maxBuffer: SCAN_MAX_BUFFER,
      });
      if (!log.ok) {
        messages.push(
          `refused: cannot scan the pushed commits ${localSha.slice(0, 12)} (${log.stderr || 'git error or output too large'})`,
        );
        continue;
      }
      const r = redact(log.stdout, detectors);
      if (r.blocked)
        messages.push(
          `refused: pushed commits up to ${localSha.slice(0, 12)} contain ${r.findings.map((x) => x.detector).join(', ')}`,
        );
    }
    return { ok: messages.length === 0, messages };
  }
  return { ok: true, messages: [`no EGO check for git hook ${name}`] };
}

export { existsSync };
