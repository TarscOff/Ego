import { delimiter, join } from 'node:path';
import { accessSync, constants } from 'node:fs';

/** Resolves an executable on PATH the way a shell would (no shell spawned). */
export function resolveOnPath(name: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const path = env['PATH'] ?? '';
  for (const dir of path.split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, name);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      /* next */
    }
  }
  return null;
}

/**
 * Resolves EGO's own launcher on PATH. The package ships `bin: { ego }`; `harness` is the pre-rename name and is
 * still accepted so an installation made before the rename keeps working. One place, so doctor, the hook shims and
 * the launcher never disagree about what EGO is called.
 */
export function resolveLauncher(env: NodeJS.ProcessEnv = process.env): string | null {
  return resolveOnPath('ego', env) ?? resolveOnPath('harness', env);
}

/** The launcher names EGO answers to, current first. */
export const LAUNCHER_NAMES = ['ego', 'harness'] as const;
