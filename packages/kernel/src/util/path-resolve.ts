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
