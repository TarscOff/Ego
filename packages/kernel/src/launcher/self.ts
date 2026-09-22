// Identity of the executing runtime: the package root of the bundle (dist/ego.js) or of the source checkout.
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isFile, readJson } from '../util/fs.ts';
import { computeRuntimeIdentity, isDevelopmentVersion, type RuntimeIdentity } from './identity.ts';
import { git } from '../util/git.ts';
import { LAUNCHER_NAMES } from '../util/path-resolve.ts';

declare const __EGO_VERSION__: string | undefined;
declare const __EGO_PACKAGE_NAME__: string | undefined;
declare const __EGO_BUILD_EPOCH__: string | undefined;

export const EGO_PACKAGE_NAME = '@tarscoff/ego';

/** The exec contract and state schemas this runtime implements (section J, K26). */
export const COMPATIBILITY = {
  execContract: 'ego.exec/1',
  runtimeStateSchema: 1,
  readableRuntimeStateSchemas: [1],
  pinSchema: 'ego.pin/1',
  policyCacheSchema: 'ego.policy-cache/1',
  overlaySchemas: {
    capabilities: 'ego.capabilities/1',
    matchers: 'ego.matchers/1',
    mcpTrust: 'ego.mcp-trust/1',
  },
} as const;

let cachedRoot: string | null = null;

/** Package root of the executing runtime: walks up from this module until the package.json named @tarscoff/ego. */
export function packageRoot(): string {
  if (cachedRoot) return cachedRoot;
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 8; i++) {
    const pkg = join(dir, 'package.json');
    if (isFile(pkg)) {
      const p = readJson<{ name?: string; bin?: Record<string, string> }>(pkg);
      if (p.name === EGO_PACKAGE_NAME || (p.bin && LAUNCHER_NAMES.some((n) => n in p.bin!))) {
        cachedRoot = dir;
        return dir;
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('cannot locate the EGO package root from ' + import.meta.url);
}

export function isBundled(): boolean {
  return typeof __EGO_VERSION__ !== 'undefined';
}

/** Version string of the executing runtime: the release or -dev.<sha> version when bundled, a live dev version from source. */
/**
 * Version string of the executing runtime: the release or `-dev.<sha>[.dirty]` version when bundled; a source run
 * (tests, `node --experimental-strip-types`) is `-dev.<sha>.src`, a distinct version string, so a source checkout and
 * the bundle built from the same commit never claim one version with two identities (IDENTITY_CONFLICT, Q79).
 */
export function selfVersion(): string {
  if (typeof __EGO_VERSION__ !== 'undefined') return __EGO_VERSION__;
  const root = packageRoot();
  const pkg = readJson<{ version?: string }>(join(root, 'package.json'));
  const sha = git(['rev-parse', '--short=12', 'HEAD'], root);
  return `${pkg.version ?? '0.0.0'}-dev.${sha.ok && sha.stdout ? sha.stdout : 'nogit'}.src`;
}

export function selfBuildEpoch(): string | null {
  return typeof __EGO_BUILD_EPOCH__ !== 'undefined' ? __EGO_BUILD_EPOCH__ : null;
}

let cachedIdentity: RuntimeIdentity | null = null;

/** Runtime identity of the executing runtime, computed once per process from the package root's runtime files. */
export function selfIdentity(): RuntimeIdentity {
  if (cachedIdentity) return cachedIdentity;
  cachedIdentity = computeRuntimeIdentity(packageRoot());
  return cachedIdentity;
}

export function selfIsDevelopment(): boolean {
  return isDevelopmentVersion(selfVersion()) || !isBundled();
}

/** True when `dir` is the EGO source repository itself (EGO_MAINTENANCE is available only there). */
export function isEgoSourceRepository(dir: string): boolean {
  const pkg = join(dir, 'package.json');
  if (!isFile(pkg)) return false;
  try {
    const p = readJson<{ name?: string }>(pkg);
    return (
      p.name === EGO_PACKAGE_NAME &&
      isFile(join(dir, 'control-plane', 'permissions', 'absolute-denies.md')) &&
      isFile(join(dir, 'packages', 'kernel', 'package.json'))
    );
  } catch {
    return false;
  }
}

export function controlPlaneDir(): string {
  return join(packageRoot(), 'control-plane');
}
