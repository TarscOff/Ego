---
schema: ego.release-keys/1
id: release-keys
absolute: true
title: Trusted release signing keys
independent_channel: >
  The active key fingerprints and any revocation notice are published on an independent channel outside the GitHub
  account trust boundary (a DNS TXT record and/or an HTTPS page on a separately administered domain; see
  docs/releases/integrity.md). A high-assurance first install compares against that channel, never against this file
  or the repository README. This file is the seed of the machine-local trust store and a convenience copy.
keys: []
---
# Trusted release signing keys

This is an absolute-core file: no organization policy, profile, product overlay, grant, mode, skill or model output
may reference or modify it. It changes only in the EGO source repository through the release process.

Each entry has `id` (short, human-typable), `algorithm` (`ed25519`), `publicKey` (base64 of the raw 32-byte public
key), `fingerprint` (sha256 of the raw public key, hex), `status` (`active`, `standby`, `revoked`), `validFrom`
(ISO date, informational). Keys are never deleted; a compromised key is flagged `revoked`, and a release that adds a key
must itself verify under an already trusted, non-revoked key (cross-sign). The release environment generates one active
and one standby key at launch (M19); their fingerprints are published on the independent channel before the first
signed release.

`keys` is empty until the first release environment exists; the launcher then seeds `~/.ego/trust/keys.json` from the
installed package's copy of this file under bootstrap trust and merges revocations from it at every start.
