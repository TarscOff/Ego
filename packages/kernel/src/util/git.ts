// Thin, synchronous git helper. EGO never shells out to network-capable git operations here (no fetch, no push).
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

export interface GitResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  status: number | null;
}

/** Ambient GIT_* variables would redirect every command to another repository or index: they are never inherited. */
function cleanGitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  // GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM stay: they tell git where the user's real configuration lives, and EGO must
  // see the same core.hooksPath git will honour. Repository redirection and inline parameter injection are dropped.
  for (const [k, v] of Object.entries(process.env))
    if (
      !/^GIT_(DIR|WORK_TREE|INDEX_FILE|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|COMMON_DIR|NAMESPACE|CEILING_DIRECTORIES|CONFIG_PARAMETERS|CONFIG_COUNT|CONFIG_KEY_\d+|CONFIG_VALUE_\d+|EXTERNAL_DIFF|PAGER|EDITOR|SSH_COMMAND|SSH|PROXY_COMMAND)$/.test(
        k,
      )
    )
      env[k] = v;
  env['GIT_TERMINAL_PROMPT'] = '0';
  env['LC_ALL'] = 'C';
  return env;
}

export function git(
  args: string[],
  cwd: string,
  opts: { input?: string; timeoutMs?: number; maxBuffer?: number; indexFile?: string } = {},
): GitResult {
  const env = cleanGitEnv();
  // A hook invoked by git itself may run against a TEMPORARY index: `git commit -a` stages into one and passes it as
  // GIT_INDEX_FILE. Stripping it (the default, against agent-supplied redirection) made the pre-commit scan read the
  // stale real index and find zero staged files, so `git commit -am` committed unscanned content (round 13). The
  // caller re-supplies it only after checking it belongs to this repository's git directory.
  if (opts.indexFile) env['GIT_INDEX_FILE'] = opts.indexFile;
  const r = spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    input: opts.input,
    timeout: opts.timeoutMs ?? 10_000,
    maxBuffer: opts.maxBuffer ?? 16 * 1024 * 1024,
    env,
  });
  if (r.error) return { ok: false, stdout: '', stderr: String(r.error.message), status: null };
  return {
    ok: r.status === 0,
    stdout: (r.stdout ?? '').toString().trim(),
    stderr: (r.stderr ?? '').toString().trim(),
    status: r.status,
  };
}

export function gitToplevel(cwd: string): string | null {
  const r = git(['rev-parse', '--show-toplevel'], cwd);
  return r.ok && r.stdout ? resolve(r.stdout) : null;
}

/** Main worktree root: the parent of the common git directory (Q40: one runtime root per logical workspace). */
export function gitMainWorktree(cwd: string): string | null {
  const r = git(['rev-parse', '--path-format=absolute', '--git-common-dir'], cwd);
  if (r.ok && r.stdout) return resolve(r.stdout, '..');
  const fallback = git(['rev-parse', '--git-common-dir'], cwd);
  if (fallback.ok && fallback.stdout) return resolve(cwd, fallback.stdout, '..');
  return null;
}

export function gitRemotes(cwd: string): Array<{ name: string; url: string }> {
  const r = git(['remote', '-v'], cwd);
  if (!r.ok) return [];
  const seen = new Map<string, string>();
  for (const line of r.stdout.split('\n')) {
    const m = /^(\S+)\s+(\S+)\s+\(fetch\)$/.exec(line.trim());
    if (m) seen.set(m[1]!, m[2]!);
  }
  return [...seen.entries()]
    .map(([name, url]) => ({ name, url }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function gitHead(cwd: string): string | null {
  const r = git(['rev-parse', 'HEAD'], cwd);
  return r.ok ? r.stdout : null;
}

export function gitDefaultBranch(cwd: string): string {
  const r = git(['symbolic-ref', '--short', 'refs/remotes/origin/HEAD'], cwd);
  if (r.ok && r.stdout) return r.stdout.replace(/^origin\//, '');
  const cur = git(['rev-parse', '--abbrev-ref', 'HEAD'], cwd);
  return cur.ok && cur.stdout && cur.stdout !== 'HEAD' ? cur.stdout : 'main';
}

export function gitConfigGet(cwd: string, key: string): string | null {
  const r = git(['config', '--get', key], cwd);
  return r.ok ? r.stdout : null;
}

/** Where a configuration value comes from: `local` (this repository, incl. worktree config) or `global` (user/system/xdg). */
export function gitConfigScope(cwd: string, key: string): 'local' | 'global' | null {
  const r = git(['config', '--show-scope', '--get', key], cwd);
  if (!r.ok || !r.stdout) return null;
  const scope = r.stdout.split(/\s+/)[0] ?? '';
  return scope === 'local' || scope === 'worktree' || scope === 'command' ? 'local' : 'global';
}

export function gitIsRepository(cwd: string): boolean {
  return git(['rev-parse', '--is-inside-work-tree'], cwd).stdout === 'true';
}
