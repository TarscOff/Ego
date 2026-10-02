// The local-development target registry (decision Q98; issue #16 sections 1, 7 and 8).
//
// THREE LAYERS, ONE SET OF RULES. The kernel authors a default (`control-plane/workspace/local-targets.md`: kind-*,
// minikube, localhost, ...). An organization (`policies/organization/local-targets.md`) and a project
// (`.harness/local-targets.md`) may ADD to it. For as long as the file said "a project or an organization may add
// targets it owns" and the compiler read exactly one file, a team's own development cluster or database could never
// be declared local, and every operation against it was a refusal or a question.
//
// WHAT A LAYER MAY DO, and why each rule is here:
//
//   - ADD a production marker. More names become production, which is a narrowing: it applies at once.
//   - NEVER remove one. The marker list a layer sees is the kernel's, and a layer can only make it longer.
//   - ADD a local target of a kind: a kube context, a database host, a container context. That is a WIDENING - it
//     turns a refusal into an allowed operation - so it is never applied from the working tree by a hook. It rides
//     the mechanism every other widening rides (`policy/cache.ts`: pending until a human runs `ego init`).
//   - NEVER declare a production-marked name local. Production wins here exactly as it does at evaluation time, and
//     it is refused where the list is BUILT, because one reader (the container engine resolver) tests the local hosts
//     before it looks for a marker, so a marked name that reached that list would be read as the local daemon.
//   - Declare one thing for ONE family of tools. The kernel's `db_local_hosts` mean "this machine" and are read by
//     the Docker engine resolver, the cloud-endpoint de-escalation and the network write rule. A host a team calls a
//     local DEVELOPMENT database is a database host and nothing else, so a declared host never reaches those readers.
//
// This module owns the rules; `compile.ts` calls `mergeLocalTargets`, `evaluate.ts` reads the pattern lists through
// the accessors below and the production-marker test through `hasProductionMarker`, so that "is this name
// production" and "what is local for this tool" each have exactly one reader.
import { lstatSync, realpathSync, statSync } from 'node:fs';
import { join, sep } from 'node:path';
import { parseMarkdown, optionalString } from '../util/markdown.ts';
import { readText } from '../util/fs.ts';
import {
  ControlPlaneValidationError,
  type DeclaredLocalTarget,
  type IgnoredLocalTarget,
  type LocalTargetKind,
  type LocalTargetLayer,
  type LocalTargets,
} from './types.ts';

/** The frontmatter key each kind of declaration is written under. The same names the kernel's own file uses. */
export const LOCAL_TARGET_KEYS: Record<LocalTargetKind, string> = {
  kube: 'k8s_local_contexts',
  db: 'db_local_hosts',
  container: 'container_local_contexts',
};
export const PRODUCTION_MARKERS_KEY = 'production_markers';
const META_KEYS = new Set(['schema', 'id', 'title']);

/** How a kind is named to a person: in the diagnostics, in the init proposal and in the authority diff. */
export const LOCAL_TARGET_NOUN: Record<LocalTargetKind, string> = {
  kube: 'kube context',
  db: 'database host',
  container: 'container context',
};

/** The five names in `k8s_local_contexts` that are the CONTAINER RUNTIME's own words for the local daemon.
 *  Kubernetes has no such convention: a kubeconfig context called `default` is whatever the operator's file
 *  says, and `kubectl --context default apply -f evil.yaml` was read as local because the container list and the
 *  Kubernetes list are one file (exit review 7). */
export const CONTAINER_ONLY_LOCAL = new Set(['default', 'unix', 'npipe', 'rootless', 'desktop-windows']);

/* ------------------------------------------------------------------------------------------------------------- *
 * READERS: what is local FOR WHICH TOOL FAMILY. evaluate.ts asks these and nothing else.
 * ------------------------------------------------------------------------------------------------------------- */

// (a table compiled before the registry had layers has no `declared`; every reader tolerates that)
const declaredNames = (t: LocalTargets, kind: LocalTargetKind): string[] =>
  (t.declared ?? []).filter((d) => d.kind === kind).map((d) => d.name);

/** Kube contexts that are local for kubectl, helm and kustomize: the kernel's, minus the container runtime's own
 *  words for its daemon, plus what a layer declared. */
export const kubeLocalPatterns = (t: LocalTargets): string[] => [
  ...t.k8sLocalContexts.filter((c) => !CONTAINER_ONLY_LOCAL.has(c)),
  ...declaredNames(t, 'kube'),
];

/** Contexts and connection names that are local for docker, podman and buildx. */
export const containerLocalPatterns = (t: LocalTargets): string[] => [
  ...t.k8sLocalContexts,
  ...declaredNames(t, 'container'),
];

/** Hosts that are local for a database CLIENT: the machine itself, plus the development databases a layer declared.
 *  Every other reader of `dbLocalHosts` (the engine host, the cloud endpoint, the network destination) asks "is this
 *  the local machine", and a declared database is not the answer to that. */
export const dbClientLocalPatterns = (t: LocalTargets): string[] => [
  ...t.dbLocalHosts,
  ...declaredNames(t, 'db'),
];

/** The WORDS of a name, which is what a production marker is a marker OF. A name is cut at every character that is not a
 *  letter or a digit (`aks-prd-weu`, `db.prod.eu`, `prod_eu`), between a letter and a digit (`prd1`, `prod01`, `live2`,
 *  `eu1prod`: a numbered environment is still that environment) and where the case changes (`eksProd`, `ProdEU`,
 *  `PRODCluster`). It is cut by what the name IS, not by a list of the words it may hold, so `products`, `productivity`,
 *  `produce`, `reproduction`, `liveness` and `delivery` stay whole and say nothing about production. */
export function nameWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/([A-Za-z])([0-9])/g, '$1 $2')
    .replace(/([0-9])([A-Za-z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/** Whether a name carries a production marker as a WORD of it (see `nameWords`): `kind-prod`, `aks-prd1-weu`,
 *  `prod-db.acme.com` and `db.live2.eu` do, `product-catalog` and `reproduce` do not. A marker that is itself several
 *  words (a layer's `sandbox-eu`) is those words in a row. THE ONE READER of "is this name production": the evaluator asks
 *  it to classify a Kubernetes context, a database host and a container engine, and the registry asks it to refuse a
 *  declaration, so no resolver has a test of its own to disagree with. It is asked of the fields that NAME A TARGET (a
 *  context, a cluster, a server, a host, an engine, a connection) and of nothing else: a release, an image or a
 *  statement says what is done, not where. */
export function hasProductionMarker(name: string, markers: string[]): boolean {
  const words = nameWords(name);
  if (words.length === 0) return false;
  return markers.some((m) => {
    const marker = nameWords(m);
    if (marker.length === 0 || marker.length > words.length) return false;
    for (let at = 0; at + marker.length <= words.length; at++)
      if (marker.every((w, k) => words[at + k] === w)) return true;
    return false;
  });
}

/* ------------------------------------------------------------------------------------------------------------- *
 * VALIDATION: what a layer may declare
 * ------------------------------------------------------------------------------------------------------------- */

/** Characters a name of each kind may carry. A kube context can be an ARN (`arn:aws:eks:eu-west-1:1:cluster/dev`) or
 *  `user@cluster`; a host is a DNS name or an address. No wildcard other than `*`, no whitespace, no quoting: a name
 *  that needs any of those is a name the kernel could not compare whole. */
const NAME_CHARS: Record<LocalTargetKind, RegExp> = {
  kube: /^[A-Za-z0-9_.:@/*-]+$/,
  db: /^[A-Za-z0-9_.*-]+$/,
  container: /^[A-Za-z0-9_.@*-]+$/,
};
const MARKER_SHAPE = /^[a-z0-9](?:[a-z0-9_-]{0,38}[a-z0-9])?$/;
/** A pattern is "everything" if it fixes too little: `*`, `k*`, `*-*` each name a whole class of clusters. */
const MIN_PREFIX = 3;

/**
 * Why a layer's declaration is refused, or null when it is taken. The refusal is a sentence a person reads in
 * `ego doctor` and `ego init`.
 */
export function refuseLocalTarget(kind: LocalTargetKind, name: string, markers: string[]): string | null {
  const noun = LOCAL_TARGET_NOUN[kind];
  if (name === '' || name.length > 253) return `not a valid ${noun}`;
  if (/[$`]|\$\{|\$\(/.test(name))
    return `opaque: a variable or a substitution cannot name a ${noun}, which has to be compared whole`;
  if (!NAME_CHARS[kind].test(name)) return `not a valid ${noun} (a name, optionally with * wildcards)`;
  // the registry refuses production where the list is built (see the header)
  if (hasProductionMarker(name, markers))
    return 'names production: production is never a local development target';
  if (name.includes('*')) {
    const prefix = name.slice(0, name.indexOf('*'));
    if (kind === 'db') {
      // a host pattern is `*.` followed by a domain the team owns: `*.com`, `10.*` and `db-*` each name hosts
      // nobody declared
      if (!/^[A-Za-z0-9_-]*\*[A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+){2,}$/.test(name))
        return 'too broad: a database host pattern is a wildcard in front of a domain of at least two labels (*.dev.acme.test)';
    } else if (prefix.length < MIN_PREFIX) {
      return `too broad: a ${noun} pattern needs at least ${MIN_PREFIX} literal characters before its first wildcard`;
    }
  }
  return null;
}

/**
 * What to tell a person whose operation was refused because its target is a shared system: how a HUMAN makes it a
 * development target. Only for a named context or host that the registry would take - never for production, never for
 * an unresolved variable. The words are for the human at the terminal; an agent shell cannot run the command (init
 * refuses it there), so naming it grants nothing.
 */
export function declareHint(kind: LocalTargetKind, resolvedTarget: string): string {
  const m = /^(?:context|host) (\S+)$/.exec(resolvedTarget);
  if (!m || refuseLocalTarget(kind, m[1]!, []) !== null) return '';
  return `; if ${m[1]} is a ${LOCAL_TARGET_NOUN[kind]} your team develops against, a human declares it with \`ego init --local-target ${kind}:${m[1]}\``;
}

/** Whether a production marker a layer adds is acceptable: a plain lowercase token. It is compiled into a pattern. */
export const refuseMarker = (m: string): string | null =>
  MARKER_SHAPE.test(m)
    ? null
    : 'not a valid production marker (a lowercase token of letters, digits, - and _)';

/* ------------------------------------------------------------------------------------------------------------- *
 * THE LAYER FILE
 * ------------------------------------------------------------------------------------------------------------- */

export interface LocalTargetsLayerDoc {
  layer: LocalTargetLayer;
  /** relative to the project root, with forward slashes */
  file: string;
  entries: Array<{ kind: LocalTargetKind; name: string }>;
  markers: string[];
  /** set when the file was not read: why */
  refused?: string;
}

/** A layer file is a short list of names. Anything bigger is not one, and is not read. */
const MAX_FILE_BYTES = 64 * 1024;
/** More declarations than this in one file are not taken: every command is compared against every one of them. */
const MAX_ENTRIES = 500;

/**
 * Reads a layer file. Null when there is none. A file that resolves outside the repository (through a link in the file
 * itself or in a directory above it), is not a regular file, or is too large is NOT READ and says why: the file is a
 * statement about what this checkout's own tools may do, and a link is how a file somebody else controls becomes part
 * of it. A malformed file throws, like every other layer: a registry that silently read nothing would be a refusal
 * nobody could see.
 */
export function loadLocalTargetsLayer(
  projectRoot: string,
  relFile: string,
  layer: LocalTargetLayer,
): LocalTargetsLayerDoc | null {
  const file = relFile.split(sep).join('/');
  const full = join(projectRoot, relFile);
  try {
    lstatSync(full);
  } catch {
    return null;
  }
  const refused = (why: string): LocalTargetsLayerDoc => ({
    layer,
    file,
    entries: [],
    markers: [],
    refused: why,
  });
  let real: string;
  let root: string;
  try {
    real = realpathSync(full);
    root = realpathSync(projectRoot);
  } catch {
    return refused('is a symbolic link whose target does not exist');
  }
  // the PATH is resolved, not just the last component: `.harness` may itself be the link
  if (!real.startsWith(root + sep))
    return refused('resolves outside the repository (it is, or sits under, a symbolic link)');
  const st = statSync(real);
  if (!st.isFile()) return refused('is not a regular file');
  if (st.size > MAX_FILE_BYTES) return refused(`is larger than ${MAX_FILE_BYTES / 1024} KiB`);
  return parseLocalTargetsLayerText(file, readText(real), layer);
}

/** The text of a layer file as a document. Throws `ControlPlaneValidationError` for a file that is not one. */
export function parseLocalTargetsLayerText(
  file: string,
  text: string,
  layer: LocalTargetLayer,
): LocalTargetsLayerDoc {
  const doc: LocalTargetsLayerDoc = { layer, file, entries: [], markers: [] };
  const parsed = parseMarkdown(file, text);
  const problems: string[] = [];
  if (optionalString(parsed, 'schema') !== 'ego.local-targets/1')
    problems.push(`${file}: schema must be ego.local-targets/1`);
  const known = new Set([...META_KEYS, ...Object.values(LOCAL_TARGET_KEYS), PRODUCTION_MARKERS_KEY]);
  for (const k of Object.keys(parsed.frontmatter))
    if (!known.has(k))
      problems.push(
        `${file}: unknown key "${k}" (known: ${[...known].filter((x) => !META_KEYS.has(x)).join(', ')})`,
      );
  const list = (key: string): string[] => {
    const v = parsed.frontmatter[key];
    if (v === undefined || v === null) return [];
    if (!Array.isArray(v)) {
      problems.push(`${file}: ${key} must be a list`);
      return [];
    }
    return v.map((x) => String(x).trim());
  };
  for (const kind of Object.keys(LOCAL_TARGET_KEYS) as LocalTargetKind[])
    for (const name of list(LOCAL_TARGET_KEYS[kind])) doc.entries.push({ kind, name });
  doc.markers = list(PRODUCTION_MARKERS_KEY).map((m) => m.toLowerCase());
  if (problems.length) throw new ControlPlaneValidationError(problems);
  return doc;
}

/* ------------------------------------------------------------------------------------------------------------- *
 * THE MERGE
 * ------------------------------------------------------------------------------------------------------------- */

const LAYER_ORDER: Record<LocalTargetLayer, number> = { organization: 0, project: 1 };
const keyOf = (d: { kind: string; name: string }): string => `${d.kind}|${d.name.toLowerCase()}`;

/**
 * The kernel's targets with the layers' additions applied under the rules in the header. Deterministic: the same
 * inputs in any order give the same result, because the table it ends up in is hashed.
 */
export function mergeLocalTargets(base: LocalTargets, layers: LocalTargetsLayerDoc[]): LocalTargets {
  const ordered = [...layers].sort((a, b) => LAYER_ORDER[a.layer] - LAYER_ORDER[b.layer]);
  const ignored: IgnoredLocalTarget[] = [];
  const markers = new Map<string, string>(base.productionMarkers.map((m) => [m.toLowerCase(), m]));

  // markers first, from EVERY layer: a name is production if any layer says so, whichever layer declared it local
  for (const l of ordered) {
    if (l.refused) {
      ignored.push({ kind: 'file', name: l.file, layer: l.layer, file: l.file, reason: l.refused });
      continue;
    }
    for (const m of l.markers) {
      const why = refuseMarker(m);
      if (why)
        ignored.push({ kind: 'production-marker', name: m, layer: l.layer, file: l.file, reason: why });
      else markers.set(m, m);
    }
  }
  const productionMarkers = [...markers.values()].sort();

  const declared = new Map<string, DeclaredLocalTarget>();
  for (const l of ordered) {
    if (l.refused) continue;
    if (l.entries.length > MAX_ENTRIES)
      ignored.push({
        kind: 'file',
        name: l.file,
        layer: l.layer,
        file: l.file,
        reason: `declares ${l.entries.length} targets; only the first ${MAX_ENTRIES} are taken`,
      });
    for (const e of l.entries.slice(0, MAX_ENTRIES)) {
      const why = refuseLocalTarget(e.kind, e.name, productionMarkers);
      if (why) {
        ignored.push({ kind: e.kind, name: e.name, layer: l.layer, file: l.file, reason: why });
        continue;
      }
      const k = keyOf(e);
      // one declaration is one entry: when both layers name it, the organization (first) is its source
      if (!declared.has(k)) declared.set(k, { kind: e.kind, name: e.name, layer: l.layer, file: l.file });
    }
  }
  const byName = (a: { kind: string; name: string; layer: string }, b: typeof a): number =>
    a.kind.localeCompare(b.kind) ||
    a.name.toLowerCase().localeCompare(b.name.toLowerCase()) ||
    a.layer.localeCompare(b.layer);
  return {
    ...base,
    productionMarkers,
    declared: [...declared.values()].sort(byName),
    ignored: ignored.sort((a, b) => byName(a, b) || a.reason.localeCompare(b.reason)),
  };
}

/* ------------------------------------------------------------------------------------------------------------- *
 * THE DIFF: what moving from one registry to another changes, for the widening gate and for the authority diff
 * ------------------------------------------------------------------------------------------------------------- */

export interface LocalTargetChange {
  kind: 'target-added' | 'target-removed' | 'marker-added' | 'marker-removed';
  detail: string;
  /** declaring a local target and un-marking a production name WIDEN what the kernel allows */
  widening: boolean;
}

/** Every difference between two registries. One reader: `tableWidenings` takes the widening ones as the lines a
 *  human is shown, `diffAuthorityTables` takes all of them as authority changes, and neither can miss one the other
 *  sees. */
export function diffLocalTargets(
  prev: LocalTargets | undefined,
  next: LocalTargets | undefined,
): LocalTargetChange[] {
  const out: LocalTargetChange[] = [];
  const a = prev?.declared ?? [];
  const b = next?.declared ?? [];
  const had = new Set(a.map(keyOf));
  const has = new Set(b.map(keyOf));
  for (const d of b)
    if (!had.has(keyOf(d)))
      out.push({
        kind: 'target-added',
        widening: true,
        detail: `${LOCAL_TARGET_NOUN[d.kind]} "${d.name}" declared LOCAL_DEV by the ${d.layer} (${d.file})`,
      });
  for (const d of a)
    if (!has.has(keyOf(d)))
      out.push({
        kind: 'target-removed',
        widening: false,
        detail: `${LOCAL_TARGET_NOUN[d.kind]} "${d.name}" no longer declared LOCAL_DEV (was the ${d.layer}'s, ${d.file})`,
      });
  const pm = new Set((prev?.productionMarkers ?? []).map((m) => m.toLowerCase()));
  const nm = new Set((next?.productionMarkers ?? []).map((m) => m.toLowerCase()));
  for (const m of nm)
    if (!pm.has(m))
      out.push({ kind: 'marker-added', widening: false, detail: `production marker "${m}" added` });
  for (const m of pm)
    if (!nm.has(m))
      out.push({ kind: 'marker-removed', widening: true, detail: `production marker "${m}" removed` });
  return out;
}

/** `next` with every declaration and every marker that `baseline` does not have taken back out: what a hook applies
 *  while a widening is pending. */
export function clampLocalTargets(next: LocalTargets, baseline: LocalTargets): LocalTargets {
  const accepted = new Set((baseline.declared ?? []).map(keyOf));
  const markers = new Map<string, string>(next.productionMarkers.map((m) => [m.toLowerCase(), m]));
  for (const m of baseline.productionMarkers) markers.set(m.toLowerCase(), m);
  return {
    ...next,
    productionMarkers: [...markers.values()].sort(),
    declared: next.declared.filter((d) => accepted.has(keyOf(d))),
  };
}
