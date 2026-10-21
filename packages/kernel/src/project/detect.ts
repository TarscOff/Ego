// Deterministic project detection for `init` and `doctor`: git root, remotes → forge provider, stack fingerprint,
// legacy harness files, bounded sibling discovery. Never scans the machine; never touches the network.
import { basename, dirname, join } from 'node:path';
import { readdirSync } from 'node:fs';
import { gitToplevel, gitRemotes, gitDefaultBranch, gitMainWorktree, gitConfigGet } from '../util/git.ts';
import { isDir, isFile, readJsonIfExists, readTextIfExists } from '../util/fs.ts';
import { sha256Hex } from '../util/hash.ts';
import { HOST_IDS, type HostId } from '../hosts/matrix.ts';
import { isEgoSourceRepository } from '../launcher/self.ts';

export type ForgeProvider = 'github' | 'gitlab' | 'azure-devops' | 'bitbucket' | 'unknown' | 'none';

export interface RemoteIdentity {
  /** @untrusted a remote's name, from the repository's own configuration */
  name: string;
  /** @untrusted */
  url: string;
  provider: ForgeProvider;
  /** @untrusted owner/repo (or org/project/repo for Azure DevOps) when parseable */
  path?: string;
  /** @untrusted */
  host?: string;
}

export interface StackFingerprint {
  tags: string[];
  hash: string;
}

export interface LegacyFinding {
  path: string;
  kind:
    | 'hand-written-agents-md'
    | 'hand-written-claude-md'
    | 'legacy-harness-dir'
    | 'scratch-tracker'
    | 'husky'
    | 'host-hooks'
    | 'legacy-skills-docs';
  note: string;
}

export interface SiblingRepo {
  /** @untrusted a directory on the disk */
  path: string;
  /** @untrusted a directory name on the disk */
  name: string;
  hasPin: boolean;
  hasWorkspaceRegistry: boolean;
}

export interface Detection {
  cwd: string;
  gitRoot: string | null;
  mainWorktree: string | null;
  isWorktree: boolean;
  defaultBranch: string;
  remotes: RemoteIdentity[];
  forge: ForgeProvider;
  stack: StackFingerprint;
  legacy: LegacyFinding[];
  siblings: SiblingRepo[];
  hosts: Record<HostId, { configured: boolean; hooksPresent: boolean }>;
  isEgoRepository: boolean;
  hooksPath: string | null;
  proposedTaskSource: 'issue-preferred' | 'ad-hoc';
}

export function parseRemote(name: string, url: string): RemoteIdentity {
  const out: RemoteIdentity = { name, url, provider: 'unknown' };
  let host = '';
  let path = '';
  const ssh = /^(?:ssh:\/\/)?(?:[^@]+@)?([^:/]+)[:/](.+?)(?:\.git)?\/?$/.exec(url);
  const https = /^https?:\/\/(?:[^@]+@)?([^/]+)\/(.+?)(?:\.git)?\/?$/.exec(url);
  if (https) {
    host = https[1]!.toLowerCase();
    path = https[2]!;
  } else if (ssh) {
    host = ssh[1]!.toLowerCase();
    path = ssh[2]!;
  }
  if (host) out.host = host;
  if (host.includes('github')) out.provider = 'github';
  else if (host.includes('gitlab')) out.provider = 'gitlab';
  else if (
    host.includes('dev.azure.com') ||
    host.includes('visualstudio.com') ||
    host.startsWith('ssh.dev.azure')
  )
    out.provider = 'azure-devops';
  else if (host.includes('bitbucket')) out.provider = 'bitbucket';
  if (path) {
    if (out.provider === 'azure-devops') {
      const legacyHost =
        /^([^.]+)\.visualstudio\.com$/.exec(host) ?? /^vs-ssh\.visualstudio\.com$/.exec(host);
      const m = /^(?:v3\/)?([^/]+)\/([^/]+)\/(?:_git\/)?([^/]+)$/.exec(path);
      const legacy = /^(?:DefaultCollection\/)?([^/]+)\/_git\/([^/]+)$/.exec(path);
      // the legacy *.visualstudio.com form carries the organization in the host: it must win over the generic form
      if (legacyHost && legacy) out.path = `${legacyHost[1] ?? 'unknown'}/${legacy[1]}/${legacy[2]}`;
      else if (m && m[2] !== '_git') out.path = `${m[1]}/${m[2]}/${m[3]}`;
    } else {
      const segs = path.split('/').filter(Boolean);
      if (segs.length >= 2) out.path = segs.slice(-2).join('/');
    }
  }
  return out;
}

const STACK_RULES: Array<{
  tag: string;
  when: (root: string, pkg: Record<string, unknown> | null, deps: Set<string>) => boolean;
}> = [
  { tag: 'node', when: (_r, pkg) => pkg !== null },
  { tag: 'typescript', when: (r, _p, d) => d.has('typescript') || isFile(join(r, 'tsconfig.json')) },
  { tag: 'react', when: (_r, _p, d) => d.has('react') },
  { tag: 'nextjs', when: (_r, _p, d) => d.has('next') },
  { tag: 'angular', when: (_r, _p, d) => d.has('@angular/core') },
  { tag: 'vue', when: (_r, _p, d) => d.has('vue') },
  { tag: 'nestjs', when: (_r, _p, d) => d.has('@nestjs/core') },
  { tag: 'express', when: (_r, _p, d) => d.has('express') },
  { tag: 'fastify', when: (_r, _p, d) => d.has('fastify') },
  { tag: 'vite', when: (_r, _p, d) => d.has('vite') },
  { tag: 'prisma', when: (_r, _p, d) => d.has('prisma') || d.has('@prisma/client') },
  { tag: 'typeorm', when: (_r, _p, d) => d.has('typeorm') },
  { tag: 'postgres', when: (_r, _p, d) => d.has('pg') || d.has('postgres') || d.has('psycopg2') },
  { tag: 'redis', when: (_r, _p, d) => d.has('redis') || d.has('ioredis') },
  { tag: 'kafka', when: (_r, _p, d) => d.has('kafkajs') },
  { tag: 'jest', when: (_r, _p, d) => d.has('jest') },
  { tag: 'vitest', when: (_r, _p, d) => d.has('vitest') },
  { tag: 'playwright', when: (_r, _p, d) => d.has('@playwright/test') || d.has('playwright') },
  { tag: 'eslint', when: (_r, _p, d) => d.has('eslint') },
  {
    tag: 'python',
    when: (r) =>
      isFile(join(r, 'pyproject.toml')) || isFile(join(r, 'requirements.txt')) || isFile(join(r, 'setup.py')),
  },
  { tag: 'fastapi', when: (r) => textHas(r, ['pyproject.toml', 'requirements.txt'], /fastapi/i) },
  { tag: 'django', when: (r) => textHas(r, ['pyproject.toml', 'requirements.txt'], /django/i) },
  { tag: 'go', when: (r) => isFile(join(r, 'go.mod')) },
  { tag: 'rust', when: (r) => isFile(join(r, 'Cargo.toml')) },
  {
    tag: 'java',
    when: (r) =>
      isFile(join(r, 'pom.xml')) || isFile(join(r, 'build.gradle')) || isFile(join(r, 'build.gradle.kts')),
  },
  {
    tag: 'docker',
    when: (r) =>
      isFile(join(r, 'Dockerfile')) ||
      isFile(join(r, 'docker-compose.yml')) ||
      isFile(join(r, 'docker-compose.yaml')) ||
      isFile(join(r, 'compose.yaml')),
  },
  {
    tag: 'kubernetes',
    when: (r) => isDir(join(r, 'k8s')) || isDir(join(r, 'kubernetes')) || isDir(join(r, 'manifests')),
  },
  { tag: 'helm', when: (r) => isFile(join(r, 'Chart.yaml')) || isDir(join(r, 'charts')) },
  { tag: 'terraform', when: (r) => listTop(r).some((f) => f.endsWith('.tf')) || isDir(join(r, 'terraform')) },
  { tag: 'github-actions', when: (r) => isDir(join(r, '.github', 'workflows')) },
  { tag: 'gitlab-ci', when: (r) => isFile(join(r, '.gitlab-ci.yml')) },
  { tag: 'azure-pipelines', when: (r) => isFile(join(r, 'azure-pipelines.yml')) },
  { tag: 'monorepo-workspaces', when: (_r, pkg) => Array.isArray(pkg?.['workspaces']) },
  { tag: 'ego-source', when: (r) => isEgoSourceRepository(r) },
];

function listTop(root: string): string[] {
  try {
    return readdirSync(root);
  } catch {
    return [];
  }
}

function textHas(root: string, files: string[], re: RegExp): boolean {
  return files.some((f) => re.test(readTextIfExists(join(root, f)) ?? ''));
}

export function stackFingerprint(root: string): StackFingerprint {
  const pkg = readJsonIfExists<Record<string, unknown>>(join(root, 'package.json'));
  const deps = new Set<string>();
  for (const k of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const d = pkg?.[k];
    if (d && typeof d === 'object')
      for (const name of Object.keys(d as Record<string, unknown>)) deps.add(name);
  }
  const tags = STACK_RULES.filter((r) => r.when(root, pkg, deps))
    .map((r) => r.tag)
    .sort();
  return { tags, hash: sha256Hex(tags.join(',')).slice(0, 16) };
}

const GENERATED_MARK = 'generated by harness';

export function isGeneratedFile(path: string): boolean {
  const head = (readTextIfExists(path) ?? '').slice(0, 600);
  return head.includes(GENERATED_MARK) || /^---\n(?:.*\n)*?generated: true/m.test(head);
}

export function legacyFindings(root: string): LegacyFinding[] {
  const out: LegacyFinding[] = [];
  const agents = join(root, 'AGENTS.md');
  if (isFile(agents) && !isGeneratedFile(agents))
    out.push({
      path: 'AGENTS.md',
      kind: 'hand-written-agents-md',
      note: 'moved to .harness/overlay/standing-rules.md and folded into the generated root under the profile budget',
    });
  const claude = join(root, 'CLAUDE.md');
  if (isFile(claude) && !isGeneratedFile(claude) && (readTextIfExists(claude) ?? '').trim() !== '@AGENTS.md')
    out.push({
      path: 'CLAUDE.md',
      kind: 'hand-written-claude-md',
      note: 'replaced by `@AGENTS.md`; its content is folded into standing rules',
    });
  for (const d of ['.agents', 'governance', '.harness/legacy'])
    if (isDir(join(root, d)) && !isFile(join(root, d, 'harness.md')))
      out.push({
        path: d,
        kind: 'legacy-harness-dir',
        note: 'previous-generation harness directory; replaced by the pinned runtime, kept until you delete it',
      });
  if (isDir(join(root, '.scratch')))
    out.push({
      path: '.scratch',
      kind: 'scratch-tracker',
      note: 'local ticket tracker; forge issues are the canonical task source (Q51)',
    });
  if (isDir(join(root, '.husky')))
    out.push({ path: '.husky', kind: 'husky', note: 'kept; EGO git checks are appended to the husky hooks' });
  if (isDir(join(root, 'docs', 'agents')))
    out.push({ path: 'docs/agents', kind: 'legacy-skills-docs', note: 'candidate overlay skills' });
  const settings = readJsonIfExists<{ hooks?: Record<string, unknown> }>(
    join(root, '.claude', 'settings.json'),
  );
  if (settings?.hooks && !JSON.stringify(settings.hooks).includes('ego-hook.sh'))
    out.push({
      path: '.claude/settings.json',
      kind: 'host-hooks',
      note: 'existing Claude Code hooks are preserved; EGO hooks are added alongside them',
    });
  return out;
}

export function discoverSiblings(root: string): SiblingRepo[] {
  const parent = dirname(root);
  const out: SiblingRepo[] = [];
  for (const name of listTop(parent).sort()) {
    const p = join(parent, name);
    if (p === root || (!isDir(join(p, '.git')) && !isFile(join(p, '.git')))) continue;
    out.push({
      path: p,
      name,
      hasPin: isFile(join(p, '.harness', 'harness.md')),
      hasWorkspaceRegistry: isFile(join(p, '.harness', 'workspace.md')) || isFile(join(p, 'workspace.md')),
    });
  }
  return out;
}

export function detectProject(cwd: string): Detection {
  const gitRoot = gitToplevel(cwd);
  const root = gitRoot ?? cwd;
  const mainWorktree = gitRoot ? gitMainWorktree(gitRoot) : null;
  const remotes = gitRoot ? gitRemotes(gitRoot).map((r) => parseRemote(r.name, r.url)) : [];
  const origin = remotes.find((r) => r.name === 'origin') ?? remotes[0];
  const forge: ForgeProvider = origin ? origin.provider : 'none';
  const hosts = {} as Detection['hosts'];
  for (const h of HOST_IDS) {
    const configured = h === 'claude-code' ? isDir(join(root, '.claude')) : isDir(join(root, '.codex'));
    const settings =
      h === 'claude-code'
        ? readTextIfExists(join(root, '.claude', 'settings.json'))
        : readTextIfExists(join(root, '.codex', 'hooks.json'));
    hosts[h] = { configured, hooksPresent: (settings ?? '').includes('ego-hook.sh') };
  }
  const isEgo = isEgoSourceRepository(root);
  return {
    cwd,
    gitRoot,
    mainWorktree,
    isWorktree: gitRoot !== null && mainWorktree !== null && mainWorktree !== gitRoot,
    defaultBranch: gitRoot ? gitDefaultBranch(gitRoot) : 'main',
    remotes,
    forge,
    stack: stackFingerprint(root),
    legacy: legacyFindings(root),
    siblings: gitRoot ? discoverSiblings(gitRoot) : [],
    hosts,
    isEgoRepository: isEgo,
    hooksPath: gitRoot ? gitConfigGet(gitRoot, 'core.hooksPath') : null,
    proposedTaskSource: !isEgo && forge !== 'none' && forge !== 'unknown' ? 'issue-preferred' : 'ad-hoc',
  };
}

export function repoDisplayName(root: string): string {
  return basename(root);
}
