// `ego init`: detect, propose, pin (never re-pin), generate the thin overlay, adapter files and git hooks, verify
// freshness, run doctor, explain. Authored overlays are never overwritten; generated files carry provenance.
import { join, relative } from 'node:path';
import { chmodSync, copyFileSync, existsSync, renameSync } from 'node:fs';
import { detectProject, type Detection } from './detect.ts';
import { readPin, writePin, hasPin, PinError, type Pin } from '../launcher/pin.ts';
import {
  packageRoot,
  selfIdentity,
  selfVersion,
  selfIsDevelopment,
  COMPATIBILITY,
  controlPlaneDir,
  isEgoSourceRepository,
} from '../launcher/self.ts';
import {
  egoHome,
  ensureHome,
  materializeRuntime,
  indexAdd,
  readIndex,
  isRuntimeCached,
  listIndexEntries,
} from '../launcher/home.ts';
import { ensurePolicyCache, POLICY_CACHE_RELATIVE } from '../policy/cache.ts';
import { generateRootInstructions, STANDING_RULES_RELATIVE } from '../context/root-instructions.ts';
import { openRuntimeRoot } from '../runtime/root.ts';
import {
  ensureDir,
  isFile,
  readTextIfExists,
  writeAtomic,
  writeJsonAtomic,
  readJsonIfExists,
} from '../util/fs.ts';
import { sha256Hex } from '../util/hash.ts';
import { writeClaudeSettings, writeSlashCommands } from '../../../adapter-claude-code/src/dialect.ts';
import { writeCodexHooks } from '../../../adapter-codex-cli/src/dialect.ts';
import { installGitHooks, isAgentShell } from './githooks.ts';
import { promoteTrustFromSources } from '../launcher/sync.ts';
import { runDoctor, formatDoctor } from './doctor.ts';

export interface InitOptions {
  cwd: string;
  profile?: string;
  taskSource?: string;
  offline?: boolean;
  now?: () => string;
  env?: NodeJS.ProcessEnv;
  /** a human act: replace a hand-edited (stamp-mismatched) pin with a fresh pin on the executing runtime */
  repin?: boolean;
}

const TASK_SOURCES = ['issue-preferred', 'issue-required', 'ad-hoc'];

export interface InitReport {
  projectRoot: string;
  detection: Detection;
  pin: Pin;
  pinned: 'created' | 'kept';
  generated: string[];
  /** authored templates created by this run (never overwritten later) */
  authored: string[];
  moved: Array<{ from: string; to: string }>;
  notes: string[];
  doctorText: string;
  doctorOk: boolean;
}

export const DEFAULT_SOURCES = ['npm:@tarscoff/ego', 'github-release:tarscoff/ego'];

export const GENERATED_MANIFEST_RELATIVE = join('.harness', 'generated', 'manifest.json');

export interface GeneratedManifest {
  schema: 'ego.generated-manifest/1';
  runtimeSha256: string;
  runtimeVersion: string;
  files: Record<string, string>;
  /** authored sources the generated files were derived from (standing rules): a change makes the artifacts stale */
  sources: Record<string, string>;
  /** authored files init created from templates: listed for the report, never hashed (the user owns them) */
  authored: string[];
}

export function initProject(opts: InitOptions): InitReport {
  const now = opts.now ?? (() => new Date().toISOString());
  const env = opts.env ?? process.env;
  const detection = detectProject(opts.cwd);
  if (!detection.gitRoot)
    throw new Error(`not a git repository: ${opts.cwd}. EGO governs git checkouts; run \`git init\` first.`);
  const projectRoot = detection.gitRoot;
  const notes: string[] = [];
  const generated: string[] = [];
  const moved: Array<{ from: string; to: string }> = [];
  const self = selfIdentity();
  const version = selfVersion();
  const home = egoHome(env);
  ensureHome(home);

  // ---- pin (Q78, section C): never re-pin an initialized project
  let pin: Pin;
  let pinned: InitReport['pinned'];
  const isEgo = isEgoSourceRepository(projectRoot);
  const dev = selfIsDevelopment();
  let tamperedPin: string | null = null;
  if (hasPin(projectRoot) && opts.repin) {
    try {
      readPin(projectRoot);
      throw new Error('--repin refused: the pin is intact; use `ego upgrade` (phase 6) to change it');
    } catch (e) {
      if (!(e instanceof PinError)) throw e;
      tamperedPin = e.message;
      notes.push(`hand-edited pin replaced on --repin (${tamperedPin.split(';')[0]})`);
    }
  }
  if (hasPin(projectRoot) && !tamperedPin) {
    let existing: Pin;
    try {
      existing = readPin(projectRoot);
    } catch (e) {
      if (e instanceof PinError)
        throw new PinError(
          `${e.message.split(';')[0]}; a human may run \`ego init --repin\` from their own terminal to pin this repository to the executing runtime again`,
        );
      throw e;
    }
    const profile = opts.profile ?? existing.profile;
    validateProfile(profile, dev, isEgo);
    const base: Omit<Pin, 'stamp'> = {
      name: existing.name,
      version: existing.version,
      integrity: existing.integrity,
      sources: existing.sources,
      schemas: existing.schemas,
      node: existing.node,
      profile,
    };
    if (existing.release) base.release = existing.release;
    const ts = opts.taskSource ?? existing.taskSource;
    if (ts && !TASK_SOURCES.includes(ts))
      throw new Error(`task source must be ${TASK_SOURCES.join(', ')} (got ${ts})`);
    if (ts) base.taskSource = ts;
    if ((profile !== existing.profile || ts !== existing.taskSource) && isAgentShell(env))
      throw new Error(
        'refused: changing the profile or the task source of a pinned project is a human act from your own terminal, never from an agent shell',
      );
    pin = profile !== existing.profile || ts !== existing.taskSource ? writePin(projectRoot, base) : existing;
    pinned = 'kept';
    notes.push(
      `pinned to ${existing.version} (installed ${version}); use \`ego upgrade\` to change the pin`,
    );
    if (existing.integrity !== self.runtimeSha256)
      notes.push(
        `the executing runtime (${self.runtimeSha256.slice(0, 12)}) differs from the pin (${existing.integrity.slice(0, 12)}); generated artifacts are regenerated by the pinned runtime on the next launch`,
      );
  } else {
    const profile = opts.profile ?? (dev || isEgo ? 'STANDARD' : 'STRICT');
    validateProfile(profile, dev, isEgo);
    const own = readIndex(home, self.name, version);
    if (own?.state === 'TAMPERED' || own?.state === 'REVOKED')
      throw new Error(
        `refused: the executing runtime ${self.runtimeSha256.slice(0, 12)}… is ${own.state} in the index; a pin written now would be refused by every launch (see \`ego bootstrap doctor\`)`,
      );
    const clash = listIndexEntries(home).find(
      (e) => e.version === version && e.identity !== self.runtimeSha256,
    );
    if (clash)
      throw new Error(
        `IDENTITY_CONFLICT: version ${version} is already mapped to runtime ${clash.identity.slice(0, 12)}… (${clash.name}) but the executing runtime is ${self.runtimeSha256.slice(0, 12)}…; a pin written now would be refused by every launch. Rebuild from a clean tree or resolve the index with \`ego bootstrap doctor\`.`,
      );
    const taskSource = opts.taskSource ?? detection.proposedTaskSource;
    if (!TASK_SOURCES.includes(taskSource))
      throw new Error(`task source must be ${TASK_SOURCES.join(', ')} (got ${taskSource})`);
    const base: Omit<Pin, 'stamp'> = {
      name: self.name,
      version,
      integrity: self.runtimeSha256,
      sources: [...DEFAULT_SOURCES],
      schemas: {
        pin: COMPATIBILITY.pinSchema,
        policyCache: COMPATIBILITY.policyCacheSchema,
        runtimeState: String(COMPATIBILITY.runtimeStateSchema),
        execContract: COMPATIBILITY.execContract,
      },
      node: '>=24',
      profile,
      taskSource,
    };
    pin = writePin(projectRoot, base);
    pinned = 'created';
    notes.push(
      `pinned EGO ${version} (runtime ${self.runtimeSha256.slice(0, 12)}); profile ${profile}, task source ${taskSource}${dev ? ' (development identity: STANDARD only, never promotable)' : ''}`,
    );
    // materialize and index the launcher runtime (section J)
    if (!isRuntimeCached(home, self.runtimeSha256) && isFile(join(packageRoot(), 'dist', 'ego.js'))) {
      // THE RUNTIME CACHE IS A LAUNCHER OPTIMISATION, AND FAILING TO POPULATE IT MUST NOT LEAVE THE PROJECT
      // PINNED AND UNGOVERNED. The pin is written above; an unguarded throw here skipped the policy cache, the
      // generated artifacts and the git hooks, so `ego check` reported a project that looked initialised and
      // enforced nothing. One write to any distributed file while `ego init` ran produced exactly that, and this
      // repository's own process edits `docs/build/build-log.md` — a distributed file — every phase.
      try {
        materializeRuntime(home, packageRoot(), self.runtimeSha256);
        notes.push(`materialized runtime ${self.runtimeSha256.slice(0, 12)} into ${home.runtimes}`);
      } catch (e) {
        notes.push(`the runtime cache was NOT populated: ${(e as Error).message}`);
      }
    } else if (!isFile(join(packageRoot(), 'dist', 'ego.js')))
      notes.push('executing from source (no dist/ego.js): the runtime was not materialized into the cache');
    if (!readIndex(home, self.name, version)) {
      indexAdd(
        home,
        self.name,
        version,
        self.runtimeSha256,
        {
          source: dev ? 'source-checkout' : 'launcher',
          trust: dev ? 'local-tarball (unsigned)' : 'registry (unsigned)',
          cachedAt: now(),
        },
        now(),
      );
    }
    if (!dev && !opts.offline) {
      const promo = promoteTrustFromSources(home, pin, controlPlaneDir(), now(), { offline: false, env });
      notes.push(promo.message);
    } else if (opts.offline)
      notes.push(
        'trust promotion skipped: offline; run `ego sync` when a release-metadata source is reachable',
      );
  }

  // ---- overlay skeleton (authored; never overwritten)
  const overlayDir = join(projectRoot, '.harness', 'overlay');
  ensureDir(overlayDir);
  const authored: string[] = [];
  const permissions = join(projectRoot, '.harness', 'permissions.md');
  if (!isFile(permissions)) {
    writeAtomic(permissions, PERMISSIONS_TEMPLATE);
    authored.push(rel(projectRoot, permissions));
  }
  const mcpTrust = join(projectRoot, '.harness', 'mcp-trust.md');
  if (!isFile(mcpTrust)) {
    writeAtomic(mcpTrust, MCP_TRUST_TEMPLATE);
    authored.push(rel(projectRoot, mcpTrust));
  }
  const overlayReadme = join(overlayDir, 'README.md');
  if (!isFile(overlayReadme)) {
    writeAtomic(overlayReadme, OVERLAY_README);
    authored.push(rel(projectRoot, overlayReadme));
  }
  // a standing-rules skeleton always exists so its hash is a recorded source of the generated root
  const standingSkeleton = join(projectRoot, STANDING_RULES_RELATIVE);
  if (!isFile(standingSkeleton) && !isEgo) {
    writeAtomic(standingSkeleton, STANDING_RULES_TEMPLATE);
    authored.push(rel(projectRoot, standingSkeleton));
  }
  // legacy hand-written root instructions become standing rules (authored) before the root is generated; the EGO
  // source repository authors its own AGENTS.md and is never migrated
  const standing = join(projectRoot, STANDING_RULES_RELATIVE);
  for (const f of detection.legacy) {
    if ((f.kind === 'hand-written-agents-md' || f.kind === 'hand-written-claude-md') && !isEgo) {
      const src = join(projectRoot, f.path);
      const text = readTextIfExists(src) ?? '';
      if (!isFile(standing))
        writeAtomic(
          standing,
          `---\nschema: ego.standing-rules/1\nmigrated_from: ${f.path}\n---\n${text.trim()}\n`,
        );
      else if (!(readTextIfExists(standing) ?? '').includes(text.trim().slice(0, 200)))
        writeAtomic(
          standing,
          `${(readTextIfExists(standing) ?? '').trimEnd()}\n\n<!-- migrated from ${f.path} -->\n${text.trim()}\n`,
        );
      ensureDir(join(overlayDir, 'legacy'));
      let backup = join(overlayDir, 'legacy', f.path);
      for (let n = 1; existsSync(backup); n++) backup = join(overlayDir, 'legacy', `${f.path}.${n}`);
      renameSync(src, backup);
      moved.push({ from: f.path, to: rel(projectRoot, backup) });
      notes.push(`${f.path}: ${f.note}`);
    } else notes.push(`${f.path}: ${f.note}`);
  }

  // ---- runtime root and policy cache
  openRuntimeRoot(projectRoot, { runtimeSha256: self.runtimeSha256, version }, now());
  const agentShell = isAgentShell(env);
  const { cache } = ensurePolicyCache(
    controlPlaneDir(),
    projectRoot,
    { runtimeSha256: self.runtimeSha256, version },
    { acceptWidening: !agentShell },
  );
  generated.push(rel(projectRoot, join(projectRoot, POLICY_CACHE_RELATIVE)));
  if (cache.pendingWidening)
    notes.push(
      `policy widening NOT applied (${cache.pendingWidening.widenings.length} cell(s)): widenings take effect only when a human runs \`ego init\` from their own terminal`,
    );

  // ---- generated root instructions
  const root = generateRootInstructions({
    projectRoot,
    pin,
    table: cache.table,
    runtime: { version, runtimeSha256: self.runtimeSha256 },
    stackTags: detection.stack.tags,
    forge: detection.forge,
    taskSource: pin.taskSource ?? 'ad-hoc',
    hosts: ['claude-code', 'codex-cli'],
  });
  const agentsPath = join(projectRoot, 'AGENTS.md');
  if (!isEgo) {
    writeAtomic(agentsPath, root.content);
    generated.push('AGENTS.md');
    const claudePath = join(projectRoot, 'CLAUDE.md');
    if (!isFile(claudePath) || (readTextIfExists(claudePath) ?? '').trim() === '@AGENTS.md') {
      writeAtomic(claudePath, '@AGENTS.md\n');
      generated.push('CLAUDE.md');
    }
  } else notes.push('EGO source repository: AGENTS.md is authored here, not generated');
  if (root.overBudget)
    notes.push(
      `WARNING: generated root instructions use ~${root.tokens} tokens, over the ${pin.profile} budget of ${root.budget}; trim .harness/overlay/standing-rules.md (\`ego check\` fails until then)`,
    );

  // ---- hook shims, adapter configuration, git hooks
  const hooksDir = join(projectRoot, '.harness', 'hooks');
  ensureDir(hooksDir);
  for (const shim of ['ego-hook.sh', 'git-hook.sh']) {
    const src = join(packageRoot(), 'runtime', 'posix', shim);
    const dst = join(hooksDir, shim);
    copyFileSync(src, dst);
    chmodSync(dst, 0o755);
    generated.push(rel(projectRoot, dst));
  }
  writeClaudeSettings(projectRoot); // co-owned with the user: doctor checks the EGO hook entries, never the whole file hash
  for (const p of writeSlashCommands(projectRoot)) generated.push(rel(projectRoot, p));
  generated.push(rel(projectRoot, writeCodexHooks(projectRoot).path));
  const gh = installGitHooks(projectRoot, detection.hooksPath);
  // hooks in a custom hooks directory are co-owned scripts (husky, custom): reported, not hashed as generated
  if (!detection.hooksPath) generated.push(...gh.installed.map((p) => rel(projectRoot, p)));
  notes.push(...gh.notes);
  ensureGitignore(projectRoot);

  // ---- generated manifest (freshness)
  const manifest: GeneratedManifest = {
    schema: 'ego.generated-manifest/1',
    runtimeSha256: self.runtimeSha256,
    runtimeVersion: version,
    files: {},
    sources: { ...root.sources },
    authored: [...new Set(authored)].sort(),
  };
  for (const g of [...new Set(generated)].sort()) {
    const full = join(projectRoot, g);
    if (isFile(full)) manifest.files[g] = sha256Hex(readTextIfExists(full) ?? '');
  }
  writeJsonAtomic(join(projectRoot, GENERATED_MANIFEST_RELATIVE), manifest);

  // the capability matrix is a summary here: `ego init` already prints a page, and `ego doctor` has the rest
  const doctor = runDoctor({ cwd: projectRoot, env, now, offline: opts.offline ?? false, authority: 'summary' });
  return {
    projectRoot,
    detection,
    pin,
    pinned,
    generated: [...new Set(generated)].sort(),
    moved,
    notes,
    doctorText: formatDoctor(doctor),
    authored: [...new Set(authored)].sort(),
    doctorOk: doctor.ok,
  };
}

function validateProfile(profile: string, dev: boolean, isEgo: boolean): void {
  if (!['STANDARD', 'STRICT', 'HIGH_ASSURANCE'].includes(profile))
    throw new Error(`unknown profile ${profile}; use STANDARD, STRICT or HIGH_ASSURANCE`);
  if (dev && profile !== 'STANDARD')
    throw new Error(
      `profile ${profile} requires a signed release; a development identity (${isEgo ? 'the EGO source checkout' : 'a -dev build'}) can only run under STANDARD (M3, Q94)`,
    );
}

function rel(root: string, p: string): string {
  return relative(root, p).split('\\').join('/');
}

function ensureGitignore(projectRoot: string): void {
  const path = join(projectRoot, '.gitignore');
  const text = readTextIfExists(path) ?? '';
  const wanted = ['.harness/runtime/', '.harness/generated/'];
  const missing = wanted.filter(
    (w) => !text.split('\n').some((l) => l.trim() === w || l.trim() === w.replace(/\/$/, '')),
  );
  if (missing.length) {
    writeAtomic(
      path,
      `${text.trimEnd()}${text.trim() ? '\n' : ''}# EGO runtime and generated artifacts are never committed\n${missing.join('\n')}\n`,
    );
    // user-owned: the appended lines are reported, never hashed as a generated artifact
  }
}

export function readGeneratedManifest(projectRoot: string): GeneratedManifest | null {
  return readJsonIfExists<GeneratedManifest>(join(projectRoot, GENERATED_MANIFEST_RELATIVE));
}

const PERMISSIONS_TEMPLATE = `---
schema: ego.capabilities/1
id: product-overlay
family: overlay
title: Product permission overlay
---
# Product permission overlay

This file narrows EGO's compiled authority table for this product. It can move a capability toward DENY (ALLOW → ASK,
ASK → DENY) and never widen. Absolute denies cannot be referenced. Identifiers come from \`ego capabilities\`.

## Requires human approval

<!-- example: - [x] \`git.local.commit\` — every commit is reviewed by a human here -->

## Denied

<!-- example: - [x] \`command.network-tool\` — no curl/wget from agent shells in this product -->
`;

export const MCP_TRUST_TEMPLATE = `---
schema: ego.mcp-trust/1
id: mcp-trust
title: MCP server trust
servers: []
---
# MCP server trust

**Listing a server here currently has NO EFFECT.** Nothing reads this file yet: the resolver that turns a listed
server into per-tool capabilities is phase-2 work (EGO issue #10). Until it lands, EVERY \`mcp__<server>__<tool>\` call
is \`mcp.unknown\` and is DENIED, whether the server is listed below or not. The file is kept so that the declaration
exists when the resolver does; do not rely on it to enable anything today, and do not treat a listed server as trusted.

Reachability never implies trust. The intended contract: list each MCP server this product trusts with its class and
per-tool capability grants; an unlisted server or tool stays \`mcp.unknown\` (DENY), and privileged or destructive
tools are DENY by default.

\`\`\`yaml
# not read by anything yet (see above)
servers:
  - id: filesystem
    scope: local            # local | remote
    tools:
      read_file: mcp.local.read
      write_file: mcp.local.write
\`\`\`
`;

const STANDING_RULES_TEMPLATE = `---
schema: ego.standing-rules/1
---
<!-- Standing rules for this product: folded into the generated root AGENTS.md under the profile context budget.
     Keep them short; \`ego context explain\` shows their token cost. Run \`ego init\` after editing. -->
`;

const OVERLAY_README = `# .harness/overlay

Authored product overlay. EGO never overwrites files here.

- \`standing-rules.md\`: rules folded into the generated root \`AGENTS.md\` under the profile context budget.
- \`matchers.md\` (optional, schema \`ego.matchers/1\`): extra operation → capability matchers; narrowing only.
- \`skills/\` (phase 3): product skills.

Generated artifacts live in \`.harness/generated/\` and are regenerated by \`ego init\`, \`sync\`, \`upgrade\`,
\`rollback\` and \`check\`; runtime state lives in \`.harness/runtime/\`. Both are gitignored.
`;

export { existsSync };
