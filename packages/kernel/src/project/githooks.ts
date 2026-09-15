// Repo-side git hooks (section H enforcement layer): pre-commit secret scan and freshness, pre-push governance in
// agent shells. Installed as thin shims chaining any pre-existing hook; husky-managed hooks gain one line instead.
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { homedir } from 'node:os';
import { chmodSync, existsSync, renameSync, copyFileSync } from 'node:fs';
import { ensureDir, isFile, readTextIfExists, writeAtomic } from '../util/fs.ts';
import { packageRoot } from '../launcher/self.ts';
import { git, gitConfigScope } from '../util/git.ts';
import { loadControlPlane } from '../control-plane/load.ts';
import { readPolicyCache } from '../policy/cache.ts';
import { readPin } from '../launcher/pin.ts';
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

function insideProject(projectRoot: string, dir: string): boolean {
  const root = resolve(projectRoot);
  const d = resolve(dir);
  return d === root || d.startsWith(root + sep);
}

/** Inserts the EGO line after the shebang of a hooks-directory script (never after an `exit`/`exec`), once. */
function ensureEgoLine(path: string, name: string): void {
  const line = `${MARK}\nsh "$(git rev-parse --show-toplevel)/.harness/hooks/git-hook.sh" ${name} "" "$@" || exit $?`;
  const text = readTextIfExists(path);
  if (text === null) writeAtomic(path, `#!/bin/sh\n${line}\n`);
  else if (!text.includes(MARK)) {
    const lines = text.split('\n');
    const at = lines[0]?.startsWith('#!') ? 1 : 0;
    lines.splice(at, 0, line);
    writeAtomic(path, lines.join('\n').replace(/\n*$/, '\n'));
  }
  chmodSync(path, 0o755);
}

export function installGitHooks(projectRoot: string, hooksPath: string | null): GitHookInstallResult {
  const installed: string[] = [];
  const notes: string[] = [];
  const shim = join(projectRoot, '.harness', 'hooks', 'git-hook.sh');
  if (!isFile(shim)) {
    copyFileSync(join(packageRoot(), 'runtime', 'posix', 'git-hook.sh'), shim);
    chmodSync(shim, 0o755);
  }
  const gitDir = gitHooksDir(projectRoot, null); // what git itself resolves, core.hooksPath included
  if (hooksPath) {
    const resolved = resolveHooksPath(projectRoot, hooksPath);
    if (gitConfigScope(projectRoot, 'core.hooksPath') === 'global' && !insideProject(projectRoot, resolved)) {
      // a machine-wide core.hooksPath (global or system git config) is never written: it would govern every repository
      const refused = `git hooks NOT installed: core.hooksPath=${hooksPath} comes from the global git configuration and resolves outside this repository (${resolved}); set a repository-local hooks path (\`git config core.hooksPath .githooks\`) and run \`harness init\` again`;
      notes.push(refused);
      return { installed, notes, refused };
    }
    // husky (v9 keeps the runner in .husky/_ and the user hooks one level up; older layouts run the scripts in place)
    const huskyGenerated = /[\\/]\.husky[\\/]_$/.test(resolved);
    const dir = huskyGenerated ? dirname(resolved) : resolved;
    ensureDir(dir);
    for (const name of GIT_HOOK_NAMES) {
      const path = join(dir, name);
      ensureEgoLine(path, name);
      installed.push(path);
    }
    notes.push(
      `git hooks: EGO checks inserted in ${dir.startsWith(projectRoot) ? dir.slice(projectRoot.length + 1) : dir}/pre-commit and pre-push (core.hooksPath=${hooksPath}${huskyGenerated ? ', husky layout' : ''})`,
    );
    return { installed, notes, refused: null };
  }
  const dir = gitDir;
  ensureDir(dir);
  for (const name of GIT_HOOK_NAMES) {
    const path = join(dir, name);
    const existing = readTextIfExists(path);
    if (existing !== null && !existing.includes(MARK)) {
      let backup = `${path}.pre-ego`;
      for (let n = 1; isFile(backup); n++) backup = `${path}.pre-ego.${n}`;
      renameSync(path, backup);
      notes.push(`git hooks: existing ${name} kept as ${backup.slice(dir.length + 1)} and chained`);
    }
    // the chained hooks live next to this script: the directory is passed to the shim, which runs every <name>.pre-ego*
    writeAtomic(
      path,
      `#!/bin/sh\n${MARK}\nshim="$(git rev-parse --show-toplevel)/.harness/hooks/git-hook.sh"\nif [ ! -f "$shim" ]; then echo "EGO: this checkout has no .harness/hooks (branch without EGO?); EGO git checks skipped" >&2; exit 0; fi\nexec sh "$shim" ${name} "$(cd "$(dirname "$0")" && pwd)" "$@"\n`,
    );
    chmodSync(path, 0o755);
    installed.push(path);
  }
  return { installed, notes, refused: null };
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

function pushVerdict(projectRoot: string): string {
  try {
    const pin = readPin(projectRoot);
    const cache = readPolicyCache(projectRoot);
    return (
      cache?.table.profiles[pin.profile]?.modes[cache.table.defaultMode]?.['git.remote.push'] ??
      cache?.table.effective['git.remote.push'] ??
      'DENY'
    );
  } catch {
    return 'DENY';
  }
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
    const staged = git(['diff', '--cached', '--name-only', '--diff-filter=ACMR'], projectRoot, {
      maxBuffer: SCAN_MAX_BUFFER,
    });
    if (!staged.ok)
      return { ok: false, messages: [`refused: cannot list staged files (${staged.stderr || 'git error'})`] };
    const files = staged.stdout.split('\n').filter(Boolean);
    for (const f of files) {
      if (f.startsWith('.harness/runtime/') || f.startsWith('.harness/generated/'))
        messages.push(`refused: ${f} is runtime or generated state and is never committed`);
      if (
        isSensitiveFileName(f.split('/').pop() ?? f, cp.secrets) &&
        !/\.example$|\.sample$|\.template$/.test(f)
      )
        messages.push(`refused: ${f} looks like a secret-bearing file`);
      const content = git(['show', `:${f}`], projectRoot, { maxBuffer: SCAN_MAX_BUFFER, timeoutMs: 60_000 });
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
      if (pushVerdict(projectRoot) === 'DENY') {
        messages.push(
          'refused: pushes from agent sessions are governed by EGO (git.remote.push is DENY unless the organization policy widens it); a human pushes from their own terminal',
        );
        return { ok: false, messages };
      }
    }
    for (const line of stdin.split('\n').filter(Boolean)) {
      const [, localSha, , remoteSha] = line.split(' ');
      if (!localSha || /^0+$/.test(localSha)) continue; // a branch deletion pushes nothing
      // every pushed commit's own patch is scanned (net-zero ranges and new branches included), never the working tree
      const args =
        remoteSha && !/^0+$/.test(remoteSha)
          ? ['log', '-p', '-m', '--text', '--format=commit %H', `${remoteSha}..${localSha}`]
          : ['log', '-p', '-m', '--text', '--format=commit %H', localSha, '--not', '--remotes'];
      const log = git([...args, '--', '.', ':!*.lock', ':!package-lock.json'], projectRoot, {
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
