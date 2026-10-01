// `ego init`'s local-development step (issue #16 section 7): detect the surfaces a repository says it develops against,
// PROPOSE them, and let a human ADOPT the ones that are theirs.
//
// WHAT THIS READS, AND WHAT IT DOES NOT. Only files inside the repository, named by fixed patterns: Compose files,
// kind and k3d cluster configs, Skaffold and Tilt files, the devcontainer, `.env.example`-style templates. It never
// reads `~/.kube/config`, `~/.docker`, the environment or any file a link points out of the repository - the kernel
// refuses to guess a local target from the machine it runs on, and "which context is current" is exactly the
// ambient state that makes an operation TARGET_UNCLASSIFIED.
//
// WHAT A PROPOSAL IS. Repository content is not a trusted instruction: a cloned repository can say anything, including
// `kubeContext: prod-eu`. So detection only ever PROPOSES. The names it prints are validated by the same function that
// validates a layer file (a production-marked name is listed as refused, never proposed), they are printed in a bounded
// grammar so a file cannot put prose in the terminal, and nothing is adopted until a human passes `--local-target`
// from their own terminal (see `adoptLocalTargets` and the agent-shell refusal in init.ts).
import { lstatSync, realpathSync, readdirSync } from 'node:fs';
import { join, sep } from 'node:path';
import { globToRegExp } from '../authority/evaluate.ts';
import {
  LOCAL_TARGET_NOUN,
  containerLocalPatterns,
  dbClientLocalPatterns,
  hasProductionMarker,
  kubeLocalPatterns,
  loadLocalTargetsLayer,
  mergeLocalTargets,
  refuseLocalTarget,
  type LocalTargetsLayerDoc,
} from '../control-plane/local-targets.ts';
import { loadControlPlane } from '../control-plane/load.ts';
import type { LocalTargetKind, LocalTargets } from '../control-plane/types.ts';
import { LAYER_FILES } from '../policy/cache.ts';
import { readTextIfExists, writeAtomic, ensureDir } from '../util/fs.ts';
import { dirname } from 'node:path';

export const PROJECT_LOCAL_TARGETS_FILE = LAYER_FILES.projectLocalTargets;

/** A repository file bigger than this is not a configuration file anyone reads for hints. */
const MAX_FILE_BYTES = 200_000;
const MAX_PROPOSALS = 24;

export type ProposalStatus = 'proposed' | 'already-local' | 'refused';

export interface LocalTargetProposal {
  kind: LocalTargetKind;
  name: string;
  status: ProposalStatus;
  /** the repository files that name it, each as `<file>: <what it says>` */
  evidence: string[];
  /** for `refused`: why it is not offered */
  reason?: string;
}

export interface LocalSurfaces {
  /** one line per file that revealed a local-development surface */
  detected: string[];
  proposals: LocalTargetProposal[];
}

/* ------------------------------------------------------------------------------------------------------------- *
 * READING THE REPOSITORY
 * ------------------------------------------------------------------------------------------------------------- */

/** A file inside the repository, as text. A link that resolves outside it, a directory and an oversized file are
 *  null: nothing outside the checkout is read. */
function readRepoFile(root: string, rel: string): string | null {
  const full = join(root, rel);
  try {
    const st = lstatSync(full);
    if (st.isSymbolicLink()) {
      const real = realpathSync(full);
      if (!real.startsWith(realpathSync(root) + sep)) return null;
    } else if (!st.isFile()) return null;
    if (st.size > MAX_FILE_BYTES) return null;
  } catch {
    return null;
  }
  return readTextIfExists(full);
}

function listDir(root: string, rel: string): string[] {
  try {
    return readdirSync(join(root, rel)).sort();
  } catch {
    return [];
  }
}

/** The directories configuration for local development usually lives in, one level deep and no deeper. */
const CONFIG_DIRS = [
  '',
  '.devcontainer',
  '.kind',
  'kind',
  'k3d',
  'deploy',
  'hack',
  'dev',
  'docker',
  'infra',
  'k8s',
  'kubernetes',
  'scripts',
];

function candidates(root: string, accept: (name: string) => boolean): string[] {
  const out: string[] = [];
  for (const d of CONFIG_DIRS) for (const f of listDir(root, d)) if (accept(f)) out.push(d ? `${d}/${f}` : f);
  return out;
}

/** WHAT A PRINTED NAME MAY CONTAIN. Repository text is data, and the terminal is where a person (or an agent that ran
 *  `ego init`) reads it. A name is printed as one token of the characters a context, a host or an image is made of -
 *  no space, no quote, no backtick, no `$`, no control character - so a file cannot put a sentence, a command or an
 *  escape sequence in front of the reader, only a short run of letters and dashes. */
const safe = (s: string): string => s.replace(/[^A-Za-z0-9_.:@/-]/g, '?').slice(0, 64);
const NAME_TOKEN = /^[A-Za-z0-9_.:@/-]{1,100}$/;

const stripComment = (line: string): string => line.replace(/(^|\s)#.*$/, '').trimEnd();
const unquote = (s: string): string => s.trim().replace(/^(['"])(.*)\1$/, '$2');

/* ------------------------------------------------------------------------------------------------------------- *
 * DETECTORS - each returns evidence, never a verdict
 * ------------------------------------------------------------------------------------------------------------- */

interface ComposeService {
  name: string;
  image: string;
  /** host ports published on the loopback or on every interface */
  ports: string[];
}

const DATASTORE_IMAGE =
  /^(postgres|postgis|timescaledb|mysql|mariadb|mongo|redis|valkey|memcached|rabbitmq|kafka|redpanda|zookeeper|clickhouse|cassandra|scylla|elasticsearch|opensearch|influxdb|couchdb|neo4j|nats|minio|localstack|mailhog|mailpit|cockroach)/;
const imageBase = (image: string): string => (image.split('/').pop() ?? '').split(':')[0]!.split('@')[0]!;

/** A lenient reader for the part of a Compose file this needs: service names, images and published ports. It is not a
 *  YAML parser (anchors, merges and flow styles are common in these files and the kernel's YAML subset rejects them);
 *  it reads the indentation. A file it cannot make sense of yields no services, never a guess. */
export function composeServices(text: string): ComposeService[] {
  const lines = text.split(/\r?\n/).map((l) => ({ raw: l, text: stripComment(l) }));
  const start = lines.findIndex((l) => /^services:\s*$/.test(l.text));
  if (start < 0) return [];
  const out: ComposeService[] = [];
  let indent = -1;
  let cur: ComposeService | null = null;
  let inPorts = false;
  let portsIndent = -1;
  for (const { text: t } of lines.slice(start + 1)) {
    if (t.trim() === '') continue;
    const ind = t.length - t.trimStart().length;
    if (ind === 0) break; // the next top-level key ends `services:`
    if (indent < 0) indent = ind;
    if (ind === indent) {
      const m = /^([A-Za-z0-9_.-]+):\s*$/.exec(t.trim());
      cur = m ? { name: m[1]!, image: '', ports: [] } : null;
      if (cur) out.push(cur);
      inPorts = false;
      continue;
    }
    if (!cur || ind <= indent) continue;
    const body = t.trim();
    const img = /^image:\s*(\S.*)$/.exec(body);
    if (img) {
      cur.image = unquote(img[1]!);
      inPorts = false;
      continue;
    }
    const portsInline = /^ports:\s*\[(.*)\]\s*$/.exec(body);
    if (portsInline) {
      for (const p of portsInline[1]!.split(',')) addPort(cur, unquote(p));
      inPorts = false;
      continue;
    }
    if (/^ports:\s*$/.test(body)) {
      inPorts = true;
      portsIndent = ind;
      continue;
    }
    if (inPorts && ind > portsIndent) {
      const item = /^-\s*(\S.*)$/.exec(body);
      if (item) addPort(cur, unquote(item[1]!));
      const published = /^published:\s*["']?(\d+)/.exec(body.replace(/^-\s*/, ''));
      if (published) cur.ports.push(published[1]!);
    } else if (ind <= portsIndent) inPorts = false;
  }
  return out;
}

function addPort(s: ComposeService, spec: string): void {
  const parts = spec.replace(/\/(tcp|udp)$/i, '').split(':');
  // `HOST_IP:HOST:CONTAINER` | `HOST:CONTAINER` | `CONTAINER` (published on an ephemeral port: not a fixed address)
  if (parts.length === 3) {
    if (/^(127\.0\.0\.1|0\.0\.0\.0|localhost|\[::1\]|\[::\])$/.test(parts[0]!) && /^\d+$/.test(parts[1]!))
      s.ports.push(parts[1]!);
  } else if (parts.length === 2 && /^\d+$/.test(parts[0]!) && /^\d+$/.test(parts[1]!))
    s.ports.push(parts[0]!);
}

/** Single-label host names: resolvable only inside a Compose network or a devcontainer, which is why they are local-
 *  development evidence at all. A dotted name is a real DNS name and says nothing about where it points. */
const SINGLE_LABEL = /^[A-Za-z][A-Za-z0-9_-]{0,62}$/;

const DB_KEY =
  /(^|_)(DATABASE|DB|POSTGRES(QL)?|PG|MYSQL|MARIADB|MONGO(DB)?|REDIS|VALKEY|AMQP|RABBIT(MQ)?|KAFKA|BROKER|CACHE|QUEUE|CLICKHOUSE|ELASTIC(SEARCH)?|OPENSEARCH|NATS|MEMCACHED?)(_|$)/i;

/** Hosts a `.env.example`-style file points the application at. Values are never kept; only the host. */
export function envExampleHosts(text: string): Array<{ key: string; host: string }> {
  const out: Array<{ key: string; host: string }> = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m || !DB_KEY.test(m[1]!)) continue;
    const value = unquote(stripComment(m[2]!));
    if (/[${}<>%\s]/.test(value) && !/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) continue;
    const url = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]+\]|[^:/?#,\s]+)/i.exec(value);
    const host = url ? url[1]! : /(_HOST|_HOSTNAME|_ADDR|_SERVER)$/i.test(m[1]!) ? value : '';
    if (host && !/[${}<>%\s]/.test(host)) out.push({ key: m[1]!, host: host.replace(/^\[|\]$/g, '') });
  }
  return out;
}

/** Strips line and block comments from JSONC (a devcontainer file is written that way), leaving strings alone. */
function jsonc(text: string): string {
  let out = '';
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inStr) {
      out += c;
      if (c === '\\') out += text[++i] ?? '';
      else if (c === '"') inStr = false;
    } else if (c === '"') {
      inStr = true;
      out += c;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i++;
    } else out += c;
  }
  return out;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * DETECTION
 * ------------------------------------------------------------------------------------------------------------- */

export function detectLocalSurfaces(projectRoot: string, targets: LocalTargets): LocalSurfaces {
  const detected: string[] = [];
  const found = new Map<string, LocalTargetProposal>();
  const note = (kind: LocalTargetKind, name: string, evidence: string): void => {
    if (!NAME_TOKEN.test(name)) return;
    const key = `${kind}|${name.toLowerCase()}`;
    const p = found.get(key);
    if (p) {
      if (!p.evidence.includes(evidence)) p.evidence.push(evidence);
    } else found.set(key, { kind, name, status: 'proposed', evidence: [evidence] });
  };

  // ---- Compose
  const composeFiles = candidates(projectRoot, (f) =>
    /^(docker-)?compose([.-][A-Za-z0-9._-]+)?\.ya?ml$/.test(f),
  );
  const composeByService = new Map<string, { file: string; svc: ComposeService }>();
  for (const f of composeFiles) {
    const services = composeServices(readRepoFile(projectRoot, f) ?? '');
    if (services.length === 0) continue;
    for (const s of services)
      if (!composeByService.has(s.name)) composeByService.set(s.name, { file: f, svc: s });
    const shown = services.slice(0, 6).map((s) => {
      const bits = [s.image ? safe(s.image) : '', ...s.ports.slice(0, 2).map((p) => `localhost:${p}`)].filter(
        Boolean,
      );
      return `${safe(s.name)}${bits.length ? ` (${bits.join(', ')})` : ''}`;
    });
    detected.push(
      `${f}: services ${shown.join(', ')}${services.length > 6 ? ` (+${services.length - 6} more)` : ''}`,
    );
    // a service that publishes a port is reached from this machine as localhost, which is already local
    for (const s of services)
      for (const p of s.ports.slice(0, 1))
        note('db', 'localhost', `${f}: service ${safe(s.name)} publishes port ${p} on localhost`);
  }

  // ---- devcontainer: the agent runs INSIDE the Compose network, where a service name is the host
  const devcontainerRuns = new Set<string>();
  for (const f of ['.devcontainer/devcontainer.json', '.devcontainer.json']) {
    const text = readRepoFile(projectRoot, f);
    if (text === null) continue;
    let cfg: Record<string, unknown> | null;
    try {
      cfg = JSON.parse(jsonc(text)) as Record<string, unknown>;
    } catch {
      continue; // a devcontainer file that does not parse says nothing
    }
    if (!cfg || typeof cfg !== 'object') continue;
    const run = Array.isArray(cfg['runServices'])
      ? (cfg['runServices'] as unknown[]).filter((x): x is string => typeof x === 'string')
      : [];
    const service = typeof cfg['service'] === 'string' ? (cfg['service'] as string) : '';
    const features = Object.keys((cfg['features'] as Record<string, unknown> | undefined) ?? {}).filter((k) =>
      /kind|minikube|k3d|kubectl/i.test(k),
    );
    const compose = cfg['dockerComposeFile'];
    detected.push(
      `${f}: ${compose ? 'compose-based' : 'image-based'} devcontainer${service ? `, service ${safe(service)}` : ''}${run.length ? `, runs ${run.slice(0, 6).map(safe).join(', ')}` : ''}${
        features.length
          ? `, kubernetes tooling (${features
              .slice(0, 3)
              .map((x) => safe(x.split('/').pop() ?? x))
              .join(', ')})`
          : ''
      }`,
    );
    if (compose)
      for (const [name, { svc }] of composeByService)
        if (name !== service && DATASTORE_IMAGE.test(imageBase(svc.image))) devcontainerRuns.add(name);
    for (const r of run) devcontainerRuns.add(r);
  }
  for (const name of devcontainerRuns) {
    const svc = composeByService.get(name);
    if (svc && DATASTORE_IMAGE.test(imageBase(svc.svc.image)) && SINGLE_LABEL.test(name))
      note(
        'db',
        name,
        `${svc.file}: datastore service ${safe(name)} (${safe(svc.svc.image)}), reached by name from inside the devcontainer`,
      );
  }

  // ---- .env.example: the hosts the application is told to use
  const envFiles = candidates(projectRoot, (f) =>
    /^(\.env\.(example|sample|template|dist)|\.env\.[A-Za-z0-9_-]+\.(example|sample|template)|(env|example|sample)\.env|env\.(example|sample))$/.test(
      f,
    ),
  );
  for (const f of envFiles) {
    const hosts = envExampleHosts(readRepoFile(projectRoot, f) ?? '');
    if (hosts.length === 0) continue;
    detected.push(
      `${f}: ${hosts
        .slice(0, 5)
        .map((h) => `${safe(h.key)} host ${safe(h.host)}`)
        .join(', ')}${hosts.length > 5 ? ` (+${hosts.length - 5} more)` : ''}`,
    );
    for (const { key, host } of hosts) {
      const svc = composeByService.get(host);
      // A SINGLE-LABEL NAME IS LOCAL EVIDENCE ONLY WHEN A COMPOSE SERVICE BEARS IT. Without one, `db` or `cache` is
      // whatever the machine's DNS search domain makes of it - possibly a shared host - so it is listed as detected
      // and never offered. A dotted name is somebody's DNS and says nothing about where it points.
      if (svc && SINGLE_LABEL.test(host))
        note('db', host, `${f}: ${safe(key)} host; ${svc.file} defines a service of that name`);
      else if (/^(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)$/i.test(host))
        note('db', host, `${f}: ${safe(key)} host`);
    }
  }

  // ---- kind and k3d cluster configs: the cluster they create is named in the file
  for (const f of candidates(projectRoot, (n) => /\.ya?ml$/.test(n) && /(kind|k3d)/i.test(n))) {
    const text = readRepoFile(projectRoot, f) ?? '';
    if (/^kind:\s*Cluster\s*$/m.test(text) && /kind\.x-k8s\.io/.test(text)) {
      const name = /^name:\s*["']?([A-Za-z0-9_.-]+)/m.exec(text)?.[1] ?? 'kind';
      detected.push(`${f}: kind cluster ${safe(name)} (context kind-${safe(name)})`);
      note('kube', `kind-${name}`, `${f}: kind cluster "${safe(name)}"`);
    } else if (/^apiVersion:\s*k3d\.io\//m.test(text)) {
      const name =
        /^metadata:\s*\n(?:[ \t]+.*\n)*?[ \t]+name:\s*["']?([A-Za-z0-9_.-]+)/m.exec(text)?.[1] ??
        'k3s-default';
      detected.push(`${f}: k3d cluster ${safe(name)} (context k3d-${safe(name)})`);
      note('kube', `k3d-${name}`, `${f}: k3d cluster "${safe(name)}"`);
    }
  }

  // ---- Skaffold and Tilt name the context a deploy is allowed to use
  for (const f of candidates(projectRoot, (n) => /^skaffold(\.[A-Za-z0-9_-]+)?\.ya?ml$/.test(n))) {
    const text = readRepoFile(projectRoot, f) ?? '';
    const names: string[] = [];
    for (const m of text.matchAll(/^\s*(?:-\s*)?kubeContext:\s*(\S+)\s*$/gm)) {
      const v = unquote(m[1]!);
      if (!names.includes(v)) names.push(v);
    }
    if (names.length === 0) continue;
    detected.push(`${f}: kubeContext ${names.slice(0, 4).map(safe).join(', ')}`);
    for (const n of names) note('kube', n, `${f}: kubeContext`);
  }
  for (const f of candidates(projectRoot, (n) => n === 'Tiltfile')) {
    const text = readRepoFile(projectRoot, f) ?? '';
    const names: string[] = [];
    for (const call of text.matchAll(/allow_k8s_contexts\s*\(([^)]*)\)/g))
      for (const q of call[1]!.matchAll(/(['"])([^'"]+)\1/g)) if (!names.includes(q[2]!)) names.push(q[2]!);
    if (names.length === 0) continue;
    detected.push(`${f}: allow_k8s_contexts ${names.slice(0, 4).map(safe).join(', ')}`);
    for (const n of names) note('kube', n, `${f}: allow_k8s_contexts`);
  }

  // ---- classify every candidate against the registry exactly as a layer file would be
  const markers = targets.productionMarkers;
  const patterns: Record<LocalTargetKind, string[]> = {
    kube: kubeLocalPatterns(targets),
    db: dbClientLocalPatterns(targets),
    container: containerLocalPatterns(targets),
  };
  const proposals = [...found.values()].sort(
    (a, b) => a.kind.localeCompare(b.kind) || a.name.toLowerCase().localeCompare(b.name.toLowerCase()),
  );
  for (const p of proposals) {
    // `localhost` appears as evidence for a published port; the registry refusal below would call it nothing, so
    // the order matters: a name that is already local is reported as such before anything else is asked of it
    const lower = p.name.toLowerCase();
    if (
      patterns[p.kind].some((g) => globToRegExp(g.toLowerCase()).test(lower)) &&
      !hasProductionMarker(lower, markers)
    ) {
      p.status = 'already-local';
      continue;
    }
    const why = refuseLocalTarget(p.kind, p.name, markers);
    if (why) {
      p.status = 'refused';
      p.reason = why;
    }
  }
  return { detected, proposals: proposals.slice(0, MAX_PROPOSALS) };
}

/** What the working tree says the registry is right now - the kernel's default plus the layer files as they stand,
 *  accepted or not. Used to validate an adoption against production markers a layer already added. */
export function workingTreeTargets(controlPlaneRoot: string, projectRoot: string): LocalTargets {
  const cp = loadControlPlane(controlPlaneRoot);
  const layers = [
    loadLocalTargetsLayer(projectRoot, LAYER_FILES.organizationLocalTargets, 'organization'),
    loadLocalTargetsLayer(projectRoot, LAYER_FILES.projectLocalTargets, 'project'),
  ].filter((l): l is LocalTargetsLayerDoc => l !== null);
  return mergeLocalTargets(cp.localTargets, layers);
}

/* ------------------------------------------------------------------------------------------------------------- *
 * ADOPTION
 * ------------------------------------------------------------------------------------------------------------- */

export interface LocalTargetSpec {
  kind: LocalTargetKind;
  name: string;
}

const SPEC_KINDS: Record<string, LocalTargetKind> = { kube: 'kube', db: 'db', container: 'container' };

/** `kube:team-dev` | `db:devdb.corp.internal` | `container:team-docker`. Throws the sentence a person needs. */
export function parseLocalTargetSpec(spec: string): LocalTargetSpec {
  const at = spec.indexOf(':');
  const kind = at > 0 ? SPEC_KINDS[spec.slice(0, at)] : undefined;
  if (!kind || at === spec.length - 1)
    throw new Error(
      `--local-target takes <kind>:<name> with kind kube, db or container (got "${safe(spec)}"), e.g. --local-target kube:team-dev`,
    );
  return { kind, name: spec.slice(at + 1) };
}

export interface AdoptionPlan {
  /** declarations to write */
  add: LocalTargetSpec[];
  /** already local by default, or already declared in the file: nothing to write */
  already: Array<LocalTargetSpec & { why: string }>;
}

/** Decides every `--local-target` BEFORE anything is written: one refusal and nothing changes. A name that is already
 *  local needs no entry, and production is refused with the same sentence a layer file would be ignored with. */
export function planAdoption(specs: LocalTargetSpec[], targets: LocalTargets): AdoptionPlan {
  const plan: AdoptionPlan = { add: [], already: [] };
  for (const s of specs) {
    const why = refuseLocalTarget(s.kind, s.name, targets.productionMarkers);
    if (why)
      throw new Error(
        `refused: ${s.kind}:${safe(s.name)} cannot be adopted as a ${LOCAL_TARGET_NOUN[s.kind]} - ${why}`,
      );
    const lower = s.name.toLowerCase();
    const declared = targets.declared.find((d) => d.kind === s.kind && d.name.toLowerCase() === lower);
    if (declared) {
      plan.already.push({ ...s, why: `already declared by the ${declared.layer} (${declared.file})` });
      continue;
    }
    const patterns = {
      kube: kubeLocalPatterns,
      db: dbClientLocalPatterns,
      container: containerLocalPatterns,
    }[s.kind](targets);
    if (patterns.some((g) => globToRegExp(g.toLowerCase()).test(lower))) {
      plan.already.push({ ...s, why: 'already local by default' });
      continue;
    }
    if (plan.add.some((a) => a.kind === s.kind && a.name.toLowerCase() === lower)) continue;
    plan.add.push(s);
  }
  return plan;
}

const KEYS: Record<LocalTargetKind, string> = {
  kube: 'k8s_local_contexts',
  db: 'db_local_hosts',
  container: 'container_local_contexts',
};

export const LOCAL_TARGETS_TEMPLATE = `---
schema: ego.local-targets/1
id: project-local-targets
title: Project local development targets
k8s_local_contexts: []
db_local_hosts: []
container_local_contexts: []
production_markers: []
---
# Project local development targets

The clusters, databases and container contexts this project develops against. EGO treats an operation on one of them
as ordinary local work: no approval prompt. Everything not listed here (and not in the kernel's own default list) is a
shared system, and an operation on it is refused or asks.

- \`k8s_local_contexts\`: kube contexts, for kubectl, helm and kustomize (\`team-dev\`, or a prefix pattern \`dev-*\`).
- \`db_local_hosts\`: database hosts, for psql, mysql, mongosh, redis-cli and the like (\`devdb.corp.internal\`).
- \`container_local_contexts\`: docker / podman contexts.
- \`production_markers\`: tokens that mark a name as PRODUCTION wherever they appear (\`uat\`). A marker only ever adds.

A production-marked name can never be declared local, and this file cannot remove one of the kernel's markers.
Declaring a target local WIDENS what EGO allows, so nothing here takes effect until a human runs \`ego init\` from their
own terminal and accepts it; \`ego init --local-target kube:<context>\` adds an entry for you. \`ego init\` lists what it
detects in this repository (Compose, kind, Skaffold, Tilt, devcontainer, \`.env.example\`) and proposes it.
`;

/**
 * Adds one entry to a layer file's frontmatter list, keeping every comment and every other line. The result is parsed
 * again by the caller before it is written: an edit that does not produce the file it meant to is not written.
 */
export function addToFrontmatterList(source: string, key: string, name: string): string {
  const item = `  - '${name}'`;
  const lines = source.split('\n');
  if (lines[0]?.trim() !== '---') throw new Error('the file has no frontmatter');
  const end = lines.indexOf('---', 1);
  if (end < 0) throw new Error('the file has unterminated frontmatter');
  const at = lines.findIndex((l, i) => i > 0 && i < end && new RegExp(`^${key}:`).test(l));
  if (at < 0) {
    lines.splice(end, 0, `${key}:`, item);
    return lines.join('\n');
  }
  const rest = lines[at]!.slice(key.length + 1)
    .replace(/(^|\s)#.*$/, '')
    .trim();
  if (rest === '[]' || rest === '') {
    // an empty list, or a block list that follows
    if (rest === '[]') {
      lines.splice(at, 1, `${key}:`, item);
      return lines.join('\n');
    }
  } else if (rest.startsWith('[')) {
    const inner = rest
      .slice(1, rest.lastIndexOf(']'))
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean);
    lines.splice(at, 1, `${key}:`, ...inner.map((x) => `  - ${x}`), item);
    return lines.join('\n');
  } else throw new Error(`${key} is not a list`);
  // a block list: insert after its last item (comments and blank lines inside it stay where they are)
  let last = at;
  for (let i = at + 1; i < end; i++) {
    if (/^\s+-\s/.test(lines[i]!) || /^\s+-$/.test(lines[i]!)) last = i;
    else if (/^\s*(#.*)?$/.test(lines[i]!)) continue;
    else break;
  }
  lines.splice(last + 1, 0, item);
  return lines.join('\n');
}

/** Writes the planned declarations into the project's local-targets file, creating it from the template when it does
 *  not exist. Returns the project-relative path. */
export function writeAdoption(projectRoot: string, add: LocalTargetSpec[]): string | null {
  if (add.length === 0) return null;
  const path = join(projectRoot, PROJECT_LOCAL_TARGETS_FILE);
  let text = readTextIfExists(path) ?? LOCAL_TARGETS_TEMPLATE;
  for (const s of add) text = addToFrontmatterList(text, KEYS[s.kind], s.name);
  ensureDir(dirname(path));
  writeAtomic(path, text.endsWith('\n') ? text : `${text}\n`);
  return PROJECT_LOCAL_TARGETS_FILE;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * PRESENTATION
 * ------------------------------------------------------------------------------------------------------------- */

/** The lines `ego init` prints. Empty when the repository shows no local-development surface. */
export function renderLocalSurfaces(s: LocalSurfaces): string[] {
  if (s.detected.length === 0 && s.proposals.length === 0) return [];
  const out: string[] = ['local development surfaces (read from files in this repository only):'];
  for (const d of s.detected) out.push(`  detected: ${d}`);
  const already = s.proposals.filter((p) => p.status === 'already-local');
  if (already.length)
    out.push(
      `  already LOCAL_DEV, nothing to adopt: ${already.map((p) => `${p.kind}:${p.name}`).join(', ')}`,
    );
  for (const p of s.proposals.filter((x) => x.status === 'proposed'))
    out.push(
      `  proposed LOCAL_DEV: ${p.kind}:${p.name} (${p.evidence.slice(0, 2).join('; ')}) - adopt with: ego init --local-target ${p.kind}:${p.name}`,
    );
  for (const p of s.proposals.filter((x) => x.status === 'refused'))
    out.push(`  not proposed: ${p.kind}:${p.name} (${p.reason ?? 'refused'}; ${p.evidence[0] ?? ''})`);
  if (s.proposals.some((p) => p.status === 'proposed'))
    out.push(
      '  a proposal changes nothing until a human adopts it from their own terminal; `ego init --no-local-targets` silences this list',
    );
  return out;
}
