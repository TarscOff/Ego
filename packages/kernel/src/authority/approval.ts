// TASK_APPROVAL PRESENTATION (issue #16 section 8). A human who is asked to approve an operation that leaves this machine
// has to see WHAT they are approving: the action, the service and repository or resource it lands on, the branch,
// environment, cluster, database or tool, a bounded summary of the arguments, why they are being asked, and how hard it
// is to take back. The host shows the hook's reason in its prompt, and until this existed that reason was the
// capability id and the matcher that fired - enough to debug a rule, not enough to decide.
//
// ONE FUNCTION builds these fields from the hit (capability, segment, resolved target), so a forge write, a push, a
// cluster mutation, a database statement and a network request are presented by the same rule and cannot drift into
// five formats. Whether an operation is an external effect is not decided here: it is `effect === 'external'` in the
// compiled table, the reader the session-grant ceiling already uses.
//
// WHAT THIS DOES NOT DO. It does not invent an audit reference. Durable tasks and claims are phase 2, so the task
// line says so; when a task exists the caller passes it. It does not widen anything and decides nothing: it formats a
// verdict the evaluator already reached.
import { isAbsolute } from 'node:path';
import { parseRemote } from '../project/detect.ts';
import { gitConfigGet } from '../util/git.ts';
import type { CompiledAuthorityTable } from './compile.ts';
import type { CapabilityHit, EvaluationContext, ToolRequest } from './evaluate.ts';

export interface ApprovalPresentation {
  /** the capability and what it means, in a few words */
  action: string;
  /** the service, repository, project or resource the effect lands on */
  target: string;
  /** the branch, environment, cluster, database or tool; null when the operation names none */
  where: string | null;
  /** a bounded, secret-masked summary of the arguments */
  effect: string;
  /** why a human is being asked, and whether configuration can change that */
  why: string;
  /** how reversible it is, and whether it is high-impact */
  impact: string;
  /** the task this belongs to; phase 1 has none */
  task: string;
}

export interface ApprovalOptions {
  /** the operation as the ledger records it (already secret-redacted); the hit's segment is used when absent */
  summary?: string;
  /** the open task's reference, once tasks exist (phase 2) */
  task?: string | null;
  /** resolves a Git remote's name to its URL; the default reads the repository's own configuration */
  remoteUrl?: (name: string) => string | null;
}

const EFFECT_MAX = 150;
const FIELD_MAX = 120;

/** The ASK hit that deserves the presentation: the first one whose effect leaves this machine. Null when there is none
 *  (a local operation asks with the evaluator's own short reason). */
export function externalAskHit(table: CompiledAuthorityTable, hits: CapabilityHit[]): CapabilityHit | null {
  return (
    hits.find((h) => h.verdict === 'ASK' && table.capabilities[h.capability]?.effect === 'external') ?? null
  );
}

export function approvalPresentation(
  table: CompiledAuthorityTable,
  ctx: EvaluationContext,
  request: ToolRequest,
  hit: CapabilityHit,
  opts: ApprovalOptions = {},
): ApprovalPresentation | null {
  const cap = table.capabilities[hit.capability];
  if (!cap || cap.effect !== 'external') return null;
  const seg = (hit.segment ?? commandOf(request)).trim();
  const tokens = seg.split(/\s+/).filter(Boolean);
  const head = (tokens[0] ?? '').replace(/^.*\//, '');
  const remoteUrl = opts.remoteUrl ?? ((name: string) => readRemoteUrl(ctx, name));
  const where = resolveWhere(hit, request, head, tokens, remoteUrl);
  return {
    action: `${hit.capability} - ${shortDescription(cap.description)}`,
    target: where.target,
    where: where.where,
    effect: bounded(mask(opts.summary ?? seg), EFFECT_MAX),
    why: whyAsked(table, ctx, hit),
    impact: impactOf(hit.capability),
    task: opts.task ? `task: ${opts.task}` : 'task: none (phase 2: durable tasks do not exist yet)',
  };
}

/** The lines the host shows. Compact on purpose: it is a prompt, not a report. */
export function renderApproval(
  p: ApprovalPresentation,
  ctx: { profile: string; mode: string },
  capability: string,
): string {
  return [
    `EGO: ${capability} requires human approval in profile ${ctx.profile}, mode ${ctx.mode}. This approves this one operation only.`,
    `  action: ${p.action}`,
    `  target: ${p.target}`,
    ...(p.where ? [`  where: ${p.where}`] : []),
    `  effect: ${p.effect}`,
    `  why: ${p.why}`,
    `  impact: ${p.impact}`,
    `  ${p.task}`,
  ].join('\n');
}

/* ------------------------------------------------------------------------------------------------------------- *
 * THE FIELDS
 * ------------------------------------------------------------------------------------------------------------- */

function commandOf(request: ToolRequest): string {
  const i = request.input;
  for (const k of ['command', 'cmd', 'url', 'file_path']) if (typeof i[k] === 'string') return i[k] as string;
  return '';
}

const bounded = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const oneLine = (s: string): string => s.replace(/[\r\n\t]+/g, ' ').replace(/[^\x20-\x7e]/g, '?');

/** Masks what a person must not see re-printed in a prompt: userinfo in a URL and the value of a secret-looking option.
 *  The ledger summary is already redacted by the redaction engine; this is the second wall for a caller that passes the
 *  raw segment. */
function mask(s: string): string {
  return oneLine(s)
    .replace(/(:\/\/)[^/@\s]*@/g, '$1***@')
    .replace(/(--?(?:token|password|passwd|secret|api-?key|auth|bearer)[= ])\S+/gi, '$1***')
    .replace(/(\b(?:Authorization|X-Api-Key)\s*:\s*)(?:Bearer\s+|Basic\s+|token\s+)?\S+/gi, '$1***');
}

function shortDescription(d: string): string {
  // the first clause: a description reads "<what it is>: <why it is governed>"
  const first = d
    .split(/(?<=\.)\s|[:;—]/)[0]!
    .replace(/`/g, '')
    .trim();
  return bounded(first.replace(/\.$/, ''), 90);
}

/** Option values for `--name value` and `--name=value`, and the short forms. */
function optionValue(tokens: string[], names: string[]): string | null {
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    for (const n of names) {
      if (t === n && tokens[i + 1] !== undefined) return tokens[i + 1]!;
      if (n.startsWith('--') && t.startsWith(`${n}=`)) return t.slice(n.length + 1);
    }
  }
  return null;
}

function readRemoteUrl(ctx: EvaluationContext, name: string): string | null {
  if (!/^[A-Za-z0-9._-]+$/.test(name)) return null;
  const cwd = ctx.cwd ?? ctx.repoRoots[0];
  if (!cwd || !isAbsolute(cwd)) return null;
  try {
    return gitConfigGet(cwd, `remote.${name}.url`);
  } catch {
    return null;
  }
}

/** The repository a remote URL names, without any credential the URL carried. */
function repositoryOf(url: string | null): string | null {
  if (!url) return null;
  const r = parseRemote('remote', url);
  const forge = {
    github: 'GitHub',
    gitlab: 'GitLab',
    'azure-devops': 'Azure DevOps',
    bitbucket: 'Bitbucket',
  }[r.provider as string];
  if (!r.path && !r.host) return null;
  return `${forge ? `${forge} ` : ''}${r.path ? `repository ${r.path}` : 'remote'}${r.host && !forge ? ` on ${r.host}` : ''}`;
}

const GIT_OPTS_WITH_VALUE = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path']);
const PUSH_OPTS_WITH_VALUE = new Set([
  '-o',
  '--push-option',
  '--repo',
  '--receive-pack',
  '--exec',
  '--signed',
  '--recurse-submodules',
]);

function resolveWhere(
  hit: CapabilityHit,
  request: ToolRequest,
  head: string,
  tokens: string[],
  remoteUrl: (name: string) => string | null,
): { target: string; where: string | null } {
  const id = hit.capability;

  // ---- MCP: the server and the tool are in the name the host gave the call
  if (request.tool.startsWith('mcp__')) {
    const [, server = 'unknown', ...tool] = request.tool.split('__');
    return {
      target: `MCP server ${oneLine(server)}`,
      where: `tool ${oneLine(tool.join('__') || 'unknown')}`,
    };
  }

  // ---- Git remotes
  if (head === 'git' && id.startsWith('git.remote.')) {
    let i = 1;
    while (i < tokens.length && tokens[i]!.startsWith('-')) i += GIT_OPTS_WITH_VALUE.has(tokens[i]!) ? 2 : 1;
    const sub = tokens[i] ?? '';
    const rest = tokens.slice(i + 1);
    const positional: string[] = [];
    for (let j = 0; j < rest.length; j++) {
      if (rest[j]!.startsWith('-')) {
        if (PUSH_OPTS_WITH_VALUE.has(rest[j]!)) j++;
        continue;
      }
      positional.push(rest[j]!);
    }
    if (sub === 'remote') {
      const name = positional[1] ?? positional[0] ?? '';
      return {
        target: `Git remote configuration${name ? ` (${bounded(oneLine(name), 40)})` : ''}`,
        where: null,
      };
    }
    const remote = positional[0];
    const url = remote ? remoteUrl(remote) : remoteUrl('origin');
    const repo =
      repositoryOf(url) ??
      (remote
        ? `remote ${bounded(oneLine(remote), 40)} (its URL was not read)`
        : "the branch's configured upstream (not resolved)");
    const refs = positional.slice(1);
    const deleting = rest.includes('--delete') || rest.includes('-d');
    const where = refs.length
      ? `${deleting ? 'delete ' : ''}${refs
          .slice(0, 4)
          .map((r) => bounded(oneLine(r), 50))
          .join(', ')}${rest.includes('--tags') ? ' + tags' : ''}`
      : rest.includes('--all')
        ? 'all branches'
        : rest.includes('--tags')
          ? 'all tags'
          : rest.includes('--mirror')
            ? 'every ref (mirror)'
            : 'the current branch (not resolved by EGO)';
    return {
      target: repo,
      where: refs.length || sub === 'push' ? `${refs.length ? 'ref ' : 'branch: '}${where}` : null,
    };
  }

  // ---- forge CLIs and APIs
  if (id.startsWith('forge.') || /^(gh|glab|az)$/.test(head)) {
    const provider =
      head === 'gh' ? 'GitHub' : head === 'glab' ? 'GitLab' : head === 'az' ? 'Azure DevOps' : 'the forge';
    let repo = optionValue(tokens, ['-R', '--repo']);
    if (!repo && (head === 'gh' || head === 'glab') && tokens[1] === 'api') {
      const endpoint = tokens.slice(2).find((t) => !t.startsWith('-') && t !== 'graphql');
      const m = endpoint
        ? (/(?:^|\/)repos\/([^/]+\/[^/]+)/.exec(endpoint) ?? /(?:^|\/)projects\/([^/]+)/.exec(endpoint))
        : null;
      if (m) repo = decodeURIComponent(m[1]!);
    }
    let target = repo
      ? `${provider} repository ${bounded(oneLine(repo), 60)}`
      : `${provider}, the repository of the origin remote (not resolved by EGO)`;
    if (!repo) {
      const r = repositoryOf(remoteUrl('origin'));
      if (r) target = `${r} (origin)`;
    }
    const nouns = tokens
      .slice(1)
      .filter((t) => !t.startsWith('-'))
      .slice(0, 3);
    const number = nouns.find((t) => /^#?\d+$/.test(t));
    const base = optionValue(tokens, ['-B', '--base']);
    const headRef = optionValue(tokens, ['-H', '--head']);
    const bits = [
      number ? `${/\bpr\b|\bmr\b/.test(tokens.slice(0, 3).join(' ')) ? 'PR/MR' : 'item'} ${number}` : '',
      base ? `base ${bounded(oneLine(base), 40)}` : '',
      headRef ? `head ${bounded(oneLine(headRef), 40)}` : '',
    ].filter(Boolean);
    return { target, where: bits.length ? bits.join(', ') : null };
  }

  // ---- a target the evaluator resolved: cluster, database host, container engine
  if (hit.target) {
    const tool = bounded(oneLine(head), 20);
    const ns = optionValue(tokens, ['-n', '--namespace']);
    const kind = /^k8s\.|\.k8s\.|^production\.(k8s|helm)/.test(id)
      ? 'cluster'
      : /^db\.|database/.test(id)
        ? 'database'
        : /^container\.|\.deploy$/.test(id)
          ? 'container engine'
          : 'target';
    const state =
      hit.target.cls === 'UNCLASSIFIED'
        ? 'TARGET_UNCLASSIFIED - could not be resolved'
        : hit.target.cls === 'PRODUCTION'
          ? 'production'
          : hit.target.cls === 'EXTERNAL'
            ? 'a shared system, not a declared local development target'
            : 'local';
    return {
      target: `${kind}: ${bounded(oneLine(hit.target.name), FIELD_MAX)} (${state})`,
      where: `tool ${tool}${ns ? `, namespace ${bounded(oneLine(ns), 40)}` : ''}`,
    };
  }

  // ---- a network request: the host it sends to
  const url =
    tokens.find((t) => /^https?:\/\//i.test(t)) ??
    (typeof request.input['url'] === 'string' ? (request.input['url'] as string) : '');
  if (url) {
    let host: string;
    let path = '';
    try {
      const u = new URL(url);
      host = u.host;
      path = u.pathname;
    } catch {
      host = url.replace(/^[a-z]+:\/\/(?:[^@/]*@)?/i, '').split(/[/?#]/)[0] ?? url;
    }
    const method = (
      optionValue(tokens, ['-X', '--request']) ??
      (tokens.some((t) => /^(-d|--data\S*|-F|--form|-T|--upload-file|--json)$/.test(t)) ? 'POST' : 'GET')
    ).toUpperCase();
    return {
      target: `${bounded(oneLine(host), 80)}${path && path !== '/' ? bounded(oneLine(path), 40) : ''}`,
      where: `tool ${bounded(oneLine(head), 20)}, method ${bounded(oneLine(method), 10)}`,
    };
  }

  // ---- a cloud CLI or a registry push
  if (/^(aws|gcloud|az|terraform|pulumi|vault)$/.test(head)) {
    const region = optionValue(tokens, [
      '--region',
      '--location',
      '--zone',
      '--project',
      '--subscription',
      '--profile',
    ]);
    const service = tokens.slice(1).find((t) => !t.startsWith('-')) ?? '';
    return {
      target:
        `${head} ${bounded(oneLine(service), 30)} (the provider's default account unless the command names one)`.trim(),
      where: region ? `${bounded(oneLine(region), 40)}` : null,
    };
  }
  if (id === 'container.registry.push') {
    const image =
      tokens.slice(1).find((t) => !t.startsWith('-') && !/^(push|image|manifest|buildx|build)$/.test(t)) ??
      '';
    const registry = /^[^/]+[.:][^/]*\//.test(image)
      ? image.split('/')[0]!
      : 'the default registry (Docker Hub)';
    return {
      target: `container registry ${bounded(oneLine(registry), 60)}`,
      where: image ? `image ${bounded(oneLine(image), 80)}` : null,
    };
  }

  return {
    target: `${id.split('.')[0]} resource named in the command (EGO could not resolve a narrower target)`,
    where: `tool ${bounded(oneLine(head || request.tool), 30)}`,
  };
}

/* ------------------------------------------------------------------------------------------------------------- *
 * WHY, AND HOW HARD IT IS TO TAKE BACK
 * ------------------------------------------------------------------------------------------------------------- */

function whyAsked(table: CompiledAuthorityTable, ctx: EvaluationContext, hit: CapabilityHit): string {
  const id = hit.capability;
  if (hit.target?.cls === 'UNCLASSIFIED' || /\.unclassified$/.test(id))
    return 'TARGET_UNCLASSIFIED: the target is not named, so EGO cannot say where this lands. Name it (--context, --host) or declare a development target (`ego init --local-target`) to remove the question; approving covers this one operation';
  const trace = table.provenance[id] ?? [];
  const last = trace[trace.length - 1];
  const lock = table.capabilities[id]?.lock;
  if (lock === 'organization' && last && /^organization \(widened/.test(last.layer))
    return `admin-governed: the organization policy enabled it (${last.file}) with ASK as the ceiling; only that policy can remove the question`;
  const profileCell = table.profiles[ctx.profile]?.modes[ctx.mode]?.[id];
  if (profileCell === 'ASK' && table.effective[id] !== 'ASK')
    return `profile ${ctx.profile} requires approval for it; the profile or the mode can change that`;
  if (last?.layer === 'overlay')
    return `this project's overlay requires approval (${last.file}); the project can change that`;
  return 'the kernel asks for every operation of this kind that leaves the machine; no phrase or setting lifts that, a project or organization can only make it stricter';
}

const IMPACT: Array<[RegExp, string]> = [
  [
    /\.unclassified$/,
    'unknown, treated as high-impact: the target is unresolved, so the effect cannot be bounded',
  ],
  [
    /(^|\.)(delete|destroy|drop|purge)(\.|$)|\.force$|^production\./,
    'high-impact: destroys or overwrites shared state; hard or impossible to undo',
  ],
  [
    /(^|\.)(merge|publish|protection|permissions|release|tag)(\.|$)|nonlocal\.|registry\.push/,
    'hard to undo: changes shared history, a release or a shared system others depend on',
  ],
  [
    /push|external-write|api\.mutate|transition|close|approve|modify|configure|assign/,
    'changes shared state; a follow-up change can correct it, and others see both',
  ],
];

/** How reversible the operation is. Derived from the capability id, the same grammar everything else reads. */
export function impactOf(capability: string): string {
  for (const [re, text] of IMPACT) if (re.test(capability)) return text;
  return 'reversible: can be edited or removed afterwards, but it notifies others';
}
