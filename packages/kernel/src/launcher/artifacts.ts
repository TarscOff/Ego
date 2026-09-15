// Release artifact handling: SHA256SUMS parsing, per-key signature files, minimal ustar + gzip tarball reader
// (no external tool, no dependency), external manifest reading.
import { gunzipSync } from 'node:zlib';
import { join, normalize, sep } from 'node:path';
import { readFileSync, readdirSync } from 'node:fs';
import { ensureDir, writeAtomic, isFile, isDir } from '../util/fs.ts';
import { sha256Hex } from '../util/hash.ts';

export interface SumsEntry {
  sha256: string;
  file: string;
}

export function parseSha256Sums(text: string): SumsEntry[] {
  const out: SumsEntry[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^([0-9a-fA-F]{64})\s+\*?(.+)$/.exec(line);
    if (!m) throw new Error(`malformed SHA256SUMS line: ${line}`);
    out.push({ sha256: m[1]!.toLowerCase(), file: m[2]!.trim() });
  }
  return out;
}

export function formatSha256Sums(entries: SumsEntry[]): string {
  return entries.map((e) => `${e.sha256}  ${e.file}`).join('\n') + '\n';
}

/** Signature files are named SHA256SUMS.<keyid>.sig and contain the raw 64-byte Ed25519 signature (binary or base64). */
export function listSignatureFiles(dir: string): Array<{ keyId: string; file: string; signature: Buffer }> {
  if (!isDir(dir)) return [];
  const out: Array<{ keyId: string; file: string; signature: Buffer }> = [];
  for (const f of readdirSync(dir).sort()) {
    const m = /^SHA256SUMS\.([A-Za-z0-9_-]+)\.sig$/.exec(f);
    if (!m) continue;
    const raw = readFileSync(join(dir, f));
    const signature = raw.length === 64 ? raw : Buffer.from(raw.toString('utf8').trim(), 'base64');
    out.push({ keyId: m[1]!, file: f, signature });
  }
  return out;
}

export interface ExternalManifest {
  schema: 'ego.release-manifest/1';
  name: string;
  version: string;
  commit: string;
  nodeFloor: string;
  runtimeSha256: string;
  tarballSha256: string;
  tarballFile: string;
  keyIds: string[];
  signedAt?: string;
  schemas: Record<string, string>;
  execContract: string;
  authorityChanges: unknown[];
  trustedKeyChanges: unknown[];
  adapterCapabilities?: Record<string, unknown>;
}

export function readExternalManifest(path: string): ExternalManifest {
  const m = JSON.parse(readFileSync(path, 'utf8')) as ExternalManifest;
  if (m.schema !== 'ego.release-manifest/1') throw new Error(`unexpected manifest schema in ${path}`);
  return m;
}

// ---------------------------------------------------------------------------------------------------------------
// Minimal tar reader (ustar / pax-tolerant) for npm tarballs: `package/...` entries, gzip-compressed.
// ---------------------------------------------------------------------------------------------------------------

export interface TarEntry {
  name: string;
  data: Buffer;
  mode: number;
}

function parseOctal(buf: Buffer, start: number, len: number): number {
  const s = buf
    .subarray(start, start + len)
    .toString('ascii')
    .replace(/\0.*$/, '')
    .trim();
  return s === '' ? 0 : parseInt(s, 8);
}

export function readTarGz(archive: Buffer): TarEntry[] {
  const tar = gunzipSync(archive);
  const entries: TarEntry[] = [];
  let offset = 0;
  let longName: string | null = null;
  let paxPath: string | null = null;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const mode = parseOctal(header, 100, 8);
    const size = parseOctal(header, 124, 12);
    const type = String.fromCharCode(header[156]!);
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    const dataStart = offset + 512;
    const data = tar.subarray(dataStart, dataStart + size);
    offset = dataStart + Math.ceil(size / 512) * 512;
    if (type === 'L') {
      longName = data.toString('utf8').replace(/\0.*$/, '');
      continue;
    }
    if (type === 'x') {
      const m = /path=(.+?)\n/.exec(data.toString('utf8').replace(/^\d+ /gm, ''));
      if (m) paxPath = m[1]!;
      continue;
    }
    if (type === 'g') continue;
    let full = longName ?? paxPath ?? (prefix ? `${prefix}/${name}` : name);
    longName = null;
    paxPath = null;
    if (type === '5' || full.endsWith('/')) continue;
    if (type !== '0' && type !== '\0' && type !== '7') continue;
    full = full.replace(/^\.\//, '');
    if (full.includes('..') || full.startsWith('/'))
      throw new Error(`refusing tar entry with unsafe path: ${full}`);
    entries.push({ name: full, data: Buffer.from(data), mode });
  }
  return entries;
}

/** Extracts an npm tarball (entries under `package/`) into `dest`. Refuses path traversal and absolute paths. */
export function extractNpmTarball(archive: Buffer, dest: string): string[] {
  const written: string[] = [];
  ensureDir(dest);
  for (const e of readTarGz(archive)) {
    const rel = e.name.startsWith('package/') ? e.name.slice('package/'.length) : e.name;
    if (!rel) continue;
    const target = normalize(join(dest, rel));
    if (!target.startsWith(normalize(dest) + sep))
      throw new Error(`refusing to write outside destination: ${rel}`);
    writeAtomic(target, e.data);
    written.push(rel);
  }
  return written.sort();
}

export function tarballSha256(path: string): string {
  return sha256Hex(readFileSync(path));
}

export function fileExists(path: string): boolean {
  return isFile(path);
}
