import { createHash } from 'node:crypto';

/** Canonical JSON: sorted keys, no whitespace, stable across platforms. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    const out: { [k: string]: unknown } = {};
    for (const k of Object.keys(value as object).sort())
      out[k] = sortKeys((value as { [k: string]: unknown })[k]);
    return out;
  }
  return value;
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function sha256Canonical(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}

/** Short, human-typable prefix of a hash for messages; never used for identity comparison. */
export function shortHash(hex: string, n = 12): string {
  return hex.slice(0, n);
}
