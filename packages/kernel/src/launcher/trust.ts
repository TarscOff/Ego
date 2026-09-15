// Machine-local trust store (Q91): seeded from the installed package's release-keys.md under bootstrap trust,
// extended only by cross-signed releases, revocations merged at every launcher start, keys never deleted.
import { join } from 'node:path';
import { createPublicKey, verify as cryptoVerify, createHash } from 'node:crypto';
import { readJsonIfExists, writeJsonAtomic, ensureDir } from '../util/fs.ts';
import type { EgoHome } from './home.ts';
import type { ReleaseKey } from '../control-plane/types.ts';

export interface TrustedKey {
  id: string;
  algorithm: 'ed25519';
  publicKey: string;
  fingerprint: string;
  status: 'active' | 'standby' | 'revoked';
  validFrom?: string;
  /** how the key entered the store */
  origin: 'bootstrap-seed' | 'cross-signed-release' | 'manual-independent-channel';
  addedAt: string;
}

export interface TrustStore {
  schema: 'ego.trust-store/1';
  keys: TrustedKey[];
  seededFromPackageVersion?: string;
}

export function trustStorePath(home: EgoHome): string {
  return join(home.trust, 'keys.json');
}

export function loadTrustStore(home: EgoHome): TrustStore {
  return readJsonIfExists<TrustStore>(trustStorePath(home)) ?? { schema: 'ego.trust-store/1', keys: [] };
}

export function saveTrustStore(home: EgoHome, store: TrustStore): void {
  ensureDir(home.trust);
  writeJsonAtomic(trustStorePath(home), store);
}

export function fingerprintOfPublicKey(publicKeyBase64: string): string {
  return createHash('sha256').update(Buffer.from(publicKeyBase64, 'base64')).digest('hex');
}

/**
 * Seeds keys from the package's release-keys.md at first run and merges revocations at every start.
 * Additions from the seed are accepted only when the store is empty (bootstrap trust); afterwards new keys enter
 * only through cross-signed releases or an explicit manual import from the independent channel.
 */
export function seedAndMergeRevocations(
  home: EgoHome,
  seed: ReleaseKey[],
  packageVersion: string,
  now: string,
): { store: TrustStore; added: string[]; revoked: string[] } {
  const store = loadTrustStore(home);
  const added: string[] = [];
  const revoked: string[] = [];
  const problems: string[] = [];
  for (const k of seed) {
    const expected = fingerprintOfPublicKey(k.publicKey);
    if (expected !== k.fingerprint)
      problems.push(`release key ${k.id}: fingerprint does not match public key`);
  }
  if (problems.length) throw new Error(problems.join('; '));
  if (store.keys.length === 0) {
    for (const k of seed) {
      const tk: TrustedKey = {
        id: k.id,
        algorithm: 'ed25519',
        publicKey: k.publicKey,
        fingerprint: k.fingerprint,
        status: k.status,
        origin: 'bootstrap-seed',
        addedAt: now,
      };
      if (k.validFrom) tk.validFrom = k.validFrom;
      store.keys.push(tk);
      added.push(k.id);
    }
    store.seededFromPackageVersion = packageVersion;
  } else {
    for (const k of seed) {
      const existing = store.keys.find((x) => x.id === k.id || x.fingerprint === k.fingerprint);
      if (existing && k.status === 'revoked' && existing.status !== 'revoked') {
        existing.status = 'revoked';
        revoked.push(existing.id);
      }
    }
  }
  if (added.length || revoked.length) saveTrustStore(home, store);
  return { store, added, revoked };
}

export function addCrossSignedKey(home: EgoHome, key: ReleaseKey, now: string): TrustedKey {
  const store = loadTrustStore(home);
  const existing = store.keys.find((x) => x.id === key.id || x.fingerprint === key.fingerprint);
  if (existing) return existing;
  if (fingerprintOfPublicKey(key.publicKey) !== key.fingerprint)
    throw new Error(`key ${key.id}: fingerprint mismatch`);
  const tk: TrustedKey = {
    id: key.id,
    algorithm: 'ed25519',
    publicKey: key.publicKey,
    fingerprint: key.fingerprint,
    status: key.status === 'revoked' ? 'revoked' : key.status,
    origin: 'cross-signed-release',
    addedAt: now,
  };
  store.keys.push(tk);
  saveTrustStore(home, store);
  return tk;
}

export function revokedKeyIds(store: TrustStore): Set<string> {
  return new Set(store.keys.filter((k) => k.status === 'revoked').map((k) => k.id));
}

export function trustedKeys(store: TrustStore): TrustedKey[] {
  return store.keys.filter((k) => k.status !== 'revoked');
}

// ---------------------------------------------------------------------------------------------------------------
// Ed25519 verification with Node's built-in crypto (zero dependencies). Raw 32-byte public keys are wrapped in SPKI.
// ---------------------------------------------------------------------------------------------------------------

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function publicKeyObject(publicKeyBase64: string) {
  const raw = Buffer.from(publicKeyBase64, 'base64');
  if (raw.length !== 32) throw new Error('ed25519 public key must be 32 bytes');
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

export function verifyEd25519(publicKeyBase64: string, data: Buffer, signature: Buffer): boolean {
  if (signature.length !== 64) return false;
  try {
    return cryptoVerify(null, data, publicKeyObject(publicKeyBase64), signature);
  } catch {
    return false;
  }
}

export interface SignatureCheck {
  keyId: string;
  ok: boolean;
  revoked: boolean;
}

/** Verifies `SHA256SUMS` against every provided per-key signature; returns the checks (at least one ok non-revoked = trusted). */
export function verifySignatures(
  store: TrustStore,
  sums: Buffer,
  signatures: Array<{ keyId: string; signature: Buffer }>,
): { trusted: boolean; verifiedByKeyId?: string; checks: SignatureCheck[] } {
  const checks: SignatureCheck[] = [];
  let verifiedByKeyId: string | undefined;
  for (const sig of signatures) {
    const key = store.keys.find((k) => k.id === sig.keyId);
    if (!key) {
      checks.push({ keyId: sig.keyId, ok: false, revoked: false });
      continue;
    }
    const ok = verifyEd25519(key.publicKey, sums, sig.signature);
    const revoked = key.status === 'revoked';
    checks.push({ keyId: sig.keyId, ok, revoked });
    if (ok && !revoked && !verifiedByKeyId) verifiedByKeyId = sig.keyId;
  }
  const out: { trusted: boolean; verifiedByKeyId?: string; checks: SignatureCheck[] } = {
    trusted: verifiedByKeyId !== undefined,
    checks,
  };
  if (verifiedByKeyId) out.verifiedByKeyId = verifiedByKeyId;
  return out;
}
