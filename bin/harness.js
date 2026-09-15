#!/usr/bin/env node
// Global launcher shim. The bundle at dist/ego.js contains the launcher logic (pin resolution, cache, delegation).
import { pathToFileURL, fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const bundle = join(here, '..', 'dist', 'ego.js');
if (!existsSync(bundle)) {
  console.error('harness: dist/ego.js is missing. Run `npm run build` in the EGO source repository.');
  process.exit(2);
}
const mod = await import(pathToFileURL(bundle).href);
await mod.runFromProcess();
