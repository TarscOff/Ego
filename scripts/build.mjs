// Builds the single dependency-free EGO bundle: dist/ego.js (ESM, Node >= 24).
// Reproducible: SOURCE_DATE_EPOCH controls embedded build time; no wall-clock fields enter the bundle.
import { build } from 'esbuild';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const sha = (() => {
  try {
    return execSync('git rev-parse --short=12 HEAD', { encoding: 'utf8' }).trim();
  } catch {
    return 'nogit';
  }
})();
const dirty = (() => {
  try {
    return execSync('git status --porcelain', { encoding: 'utf8' }).trim().length > 0;
  } catch {
    return false;
  }
})();
const isRelease = process.env.EGO_RELEASE_BUILD === '1';
if (!isRelease && dirty && process.env.EGO_ALLOW_DIRTY !== '1') {
  console.error(
    'build refused: working tree is dirty and this is not a release build (set EGO_ALLOW_DIRTY=1 for a throwaway local build)',
  );
  process.exit(2);
}
// a dirty tree can never present itself as the clean build of its commit: the version carries `.dirty`
const version = isRelease ? pkg.version : `${pkg.version}-dev.${sha}${dirty ? '.dirty' : ''}`;
const sourceDateEpoch =
  process.env.SOURCE_DATE_EPOCH ??
  (() => {
    try {
      return execSync('git log -1 --format=%ct', { encoding: 'utf8' }).trim();
    } catch {
      return '0';
    }
  })();

mkdirSync(new URL('../dist/', import.meta.url), { recursive: true });
await build({
  entryPoints: ['packages/cli/src/main.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  outfile: 'dist/ego.js',
  banner: { js: '#!/usr/bin/env node' },
  define: {
    __EGO_VERSION__: JSON.stringify(version),
    __EGO_BUILD_EPOCH__: JSON.stringify(sourceDateEpoch),
    __EGO_PACKAGE_NAME__: JSON.stringify(pkg.name),
  },
  legalComments: 'none',
  logLevel: 'info',
});
writeFileSync(
  new URL('../dist/version.json', import.meta.url),
  JSON.stringify({ version, sourceDateEpoch }, null, 2) + '\n',
);
console.log(`built dist/ego.js version=${version}`);
