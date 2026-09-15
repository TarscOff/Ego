// Runtime identity (decision Q77): runtime_sha256 = sha256 over the internal manifest, a sorted list of every
// distributed runtime file with its hash, excluding only the `name` field of package.json and release-time metadata.
// Computable identically from an extracted install and from a tarball.
import { join } from 'node:path';
import { readFileSync, readdirSync } from 'node:fs';
import { walkFiles, isDir, isFile, readJson } from '../util/fs.ts';
import { sha256Hex, canonicalJson } from '../util/hash.ts';

export interface InternalManifestEntry {
  path: string;
  sha256: string;
}

export interface InternalManifest {
  schema: 'ego.internal-manifest/1';
  version: string;
  files: InternalManifestEntry[];
}

export interface RuntimeIdentity {
  runtimeSha256: string;
  version: string;
  name: string;
  manifest: InternalManifest;
}

/** Top-level directories of a source checkout that are never runtime files; applied at the package root ONLY. */
const EXCLUDED_TOP_DIRS = new Set([
  'node_modules',
  '.git',
  '.release',
  '.harness',
  'tests',
  'packages',
  'scripts',
  'coverage',
]);
/** Files that are never part of the identity, wherever they sit: the manifest describes the identity, it is not in it. */
const EXCLUDED_FILES = new Set(['package-lock.json', 'manifest.internal.json', '.DS_Store']);

/**
 * Lists the distributed runtime files of a package root (source checkout or extracted install). Every file under a
 * distributed directory counts, at any depth (a file planted under dist/tests/ or dist/node_modules/ changes the
 * identity and is detected by --reverify); only `node_modules` and `.git` are skipped inside, since npm never packs them.
 */
export function listRuntimeFiles(root: string): string[] {
  const pkgPath = join(root, 'package.json');
  if (!isFile(pkgPath)) throw new Error(`not a package root: ${root}`);
  const pkg = readJson<{ files?: string[] }>(pkgPath);
  const files = new Set<string>(['package.json']);
  const inner = { skipDirs: ['node_modules', '.git'] };
  if (Array.isArray(pkg.files) && pkg.files.length > 0) {
    for (const entry of pkg.files) {
      const clean = entry.replace(/\/$/, '');
      const full = join(root, clean);
      if (isDir(full)) for (const f of walkFiles(full, inner)) files.add(`${clean}/${f}`);
      else if (isFile(full)) files.add(clean);
    }
  } else {
    for (const top of walkFiles(root, { ...inner, maxDepth: 0 })) files.add(top);
    for (const d of readdirSync(root, { withFileTypes: true })) {
      if (!d.isDirectory() || EXCLUDED_TOP_DIRS.has(d.name)) continue;
      for (const f of walkFiles(join(root, d.name), inner)) files.add(`${d.name}/${f}`);
    }
  }
  return [...files]
    .filter(
      (f) =>
        !EXCLUDED_FILES.has(f.split('/').pop() ?? f) &&
        !f.startsWith('.release/') &&
        !f.startsWith('.harness/'),
    )
    .sort();
}

export function hashPackageJsonWithoutName(content: string): string {
  const parsed = JSON.parse(content) as Record<string, unknown>;
  const { name: _name, ...rest } = parsed;
  return sha256Hex(canonicalJson(rest));
}

export function computeInternalManifest(root: string): InternalManifest {
  const pkg = readJson<{ version?: string }>(join(root, 'package.json'));
  const files = listRuntimeFiles(root).map((path) => {
    const content = readFileSync(join(root, path));
    const sha256 =
      path === 'package.json' ? hashPackageJsonWithoutName(content.toString('utf8')) : sha256Hex(content);
    return { path, sha256 };
  });
  return { schema: 'ego.internal-manifest/1', version: pkg.version ?? '0.0.0', files };
}

export function identityFromManifest(manifest: InternalManifest): string {
  return sha256Hex(canonicalJson({ schema: manifest.schema, files: manifest.files }));
}

export function computeRuntimeIdentity(root: string): RuntimeIdentity {
  const manifest = computeInternalManifest(root);
  const pkg = readJson<{ name?: string; version?: string }>(join(root, 'package.json'));
  return {
    runtimeSha256: identityFromManifest(manifest),
    version: manifest.version,
    name: pkg.name ?? 'unknown',
    manifest,
  };
}

/** Recomputes the identity of a cached runtime directory and compares it with the directory name (Q79 reverify). */
export function verifyRuntimeDirectory(
  dir: string,
  expectedSha256: string,
): { ok: boolean; actual: string; unlisted: string[] } {
  const manifestPath = join(dir, 'manifest.internal.json');
  const manifest: InternalManifest = isFile(manifestPath)
    ? readJson<InternalManifest>(manifestPath)
    : computeInternalManifest(dir);
  const listed = new Set(manifest.files.map((f) => f.path));
  // every byte in the cache directory counts, including node_modules/.git planted after materialization
  const present = walkFiles(dir, { skipDirs: [], includeSymlinks: true }).filter(
    (f) => f !== 'manifest.internal.json',
  );
  const unlisted = present.filter((p) => !listed.has(p));
  const recomputed = computeInternalManifest(dir);
  const actual = identityFromManifest(recomputed);
  return { ok: actual === expectedSha256 && unlisted.length === 0, actual, unlisted };
}

export function isDevelopmentVersion(version: string): boolean {
  return /-dev\.[0-9a-f]{7,40}(\.dirty)?(\.src)?$/.test(version);
}

/** Minimal `>=X[.Y[.Z]]` / `^X` / exact range check for the pin's `ego.node` floor (npm semver subset, no dependency). */
export function nodeSatisfies(version: string, range: string): boolean {
  const parse = (v: string) =>
    v
      .replace(/^v/, '')
      .split('.')
      .map((n) => parseInt(n, 10) || 0);
  const cur = parse(version);
  for (const part of range
    .split('||')
    .map((p) => p.trim())
    .filter(Boolean)) {
    const m = /^(>=|>|<=|<|=|\^|~)?\s*v?(\d+(?:\.\d+){0,2})$/.exec(part);
    if (!m) continue;
    const op = m[1] ?? '=';
    const want = parse(m[2]!);
    const cmp = cur[0]! - want[0]! || cur[1]! - (want[1] ?? 0) || cur[2]! - (want[2] ?? 0);
    const ok =
      op === '>='
        ? cmp >= 0
        : op === '>'
          ? cmp > 0
          : op === '<='
            ? cmp <= 0
            : op === '<'
              ? cmp < 0
              : op === '^'
                ? cur[0] === want[0] && cmp >= 0
                : op === '~'
                  ? cur[0] === want[0] && cur[1] === (want[1] ?? cur[1]) && cmp >= 0
                  : cmp === 0;
    if (ok) return true;
  }
  return false;
}
