// The launcher (section C, J): runs on the global package, resolves the project pin, checks the index first, runs
// in-process when its own identity equals the pin, delegates to the cached pinned runtime otherwise, and executes the
// launcher set (`version`, `sync`, `distribution`, `bootstrap doctor`) without any pinned runtime.
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { existsSync } from 'node:fs';
import type { CliIo } from './io.ts';
import { parseFlags } from './io.ts';
import { runCommand, projectPrePromotion, PRE_PROMOTION_SET, type ProjectContext } from './commands.ts';
import { gitToplevel } from '../../kernel/src/util/git.ts';
import { renderFailure } from '../../kernel/src/authority/reasons.ts';
import { hasPin, readPin, PinError } from '../../kernel/src/launcher/pin.ts';
import {
  selfIdentity,
  selfVersion,
  selfIsDevelopment,
  packageRoot,
  controlPlaneDir,
  COMPATIBILITY,
} from '../../kernel/src/launcher/self.ts';
import {
  egoHome,
  readIndex,
  listIndexEntries,
  isRuntimeCached,
  runtimeDir,
  materializeRuntime,
  indexAdd,
  effectiveTrust,
} from '../../kernel/src/launcher/home.ts';
import { loadTrustStore, revokedKeyIds } from '../../kernel/src/launcher/trust.ts';
import {
  seedTrust,
  syncProject,
  importTarball,
  verifyDistribution,
  bootstrapDoctor,
  indexSummary,
} from '../../kernel/src/launcher/sync.ts';
import { isDevelopmentVersion, nodeSatisfies } from '../../kernel/src/launcher/identity.ts';
import { isFile } from '../../kernel/src/util/fs.ts';

export const LAUNCHER_SET = new Set(['version', 'sync', 'distribution', 'bootstrap', 'upgrade', 'rollback']);
export const OUTSIDE_PROJECT_SET = new Set([
  'init',
  'help',
  'version',
  'bootstrap',
  'distribution',
  'redact',
]);

export interface DelegationInfo {
  launcherVersion: string;
  launcherIdentity: string;
  execContract: string;
}

export interface LaunchOptions {
  delegatedBy?: DelegationInfo;
}

export async function launch(argv: string[], io: CliIo, opts: LaunchOptions = {}): Promise<number> {
  const major = Number(process.versions.node.split('.')[0]);
  if (major < 24) {
    io.err(`EGO requires Node >= 24 (running ${process.versions.node})`);
    return 2;
  }
  const home = egoHome(io.env);
  try {
    seedTrust(home, controlPlaneDir(), io.now());
  } catch (e) {
    io.err(`EGO: trust store seeding failed: ${(e as Error).message}`);
    return 2;
  }
  const cmd = argv[0] ?? 'help';
  const self = selfIdentity();
  const version = selfVersion();
  const gitRoot = gitToplevel(io.cwd);
  const projectRoot = gitRoot && hasPin(gitRoot) ? gitRoot : null;

  if (LAUNCHER_SET.has(cmd) && !opts.delegatedBy)
    return launcherCommand(cmd, argv.slice(1), io, home, projectRoot, {
      root: packageRoot(),
      runtimeSha256: self.runtimeSha256,
      version,
    });

  if (!projectRoot) {
    if (OUTSIDE_PROJECT_SET.has(cmd)) return runCommand(argv, io, null);
    io.err(
      `not initialized${gitRoot ? ` (${gitRoot} has no .harness/harness.md)` : ' (not inside a git repository)'}; run \`ego init\``,
    );
    return 2;
  }
  let pin;
  try {
    pin = readPin(projectRoot);
  } catch (e) {
    // `init` owns the hand-edited-pin remedy (--repin, a human act); every other command stops here
    if (cmd === 'init' && e instanceof PinError) return runCommand(argv, io, null);
    io.err(
      e instanceof PinError
        ? `EGO: ${renderFailure('POLICY_INVALID', e.message.split(';')[0]!, {
            source: 'the project pin, .harness/harness.md',
            changeable: true,
            changeBy: 'a human may run `ego init --repin` from their own terminal; an agent shell cannot',
          })}`
        : `pin unreadable: ${(e as Error).message}`,
    );
    return 2;
  }
  if (!nodeSatisfies(process.versions.node, pin.node)) {
    io.err(`EGO: this project pins node ${pin.node}; running ${process.versions.node}`);
    return 2;
  }
  // index-first dispatch (section C): one identity per version string, across package names
  const idx = readIndex(home, pin.name, pin.version);
  if (idx && idx.identity !== pin.integrity) {
    io.err(
      `IDENTITY_CONFLICT: the index maps ${pin.name}@${pin.version} to runtime ${idx.identity.slice(0, 12)}… but the pin says ${pin.integrity.slice(0, 12)}…; resolve with \`ego bootstrap doctor\` (see displaced identities) before continuing.`,
    );
    return 2;
  }
  const crossName = listIndexEntries(home).find(
    (e) => e.version === pin.version && e.identity !== pin.integrity,
  );
  if (crossName) {
    io.err(
      `IDENTITY_CONFLICT: version ${pin.version} is already mapped to runtime ${crossName.identity.slice(0, 12)}… under ${crossName.name}, the pin says ${pin.integrity.slice(0, 12)}…; one version string maps to exactly one runtime identity (Q79). See \`ego bootstrap doctor\`.`,
    );
    return 2;
  }
  if (idx?.state) {
    const remedy =
      idx.state === 'TAMPERED'
        ? 'ego distribution import --re-materialize <tarball>'
        : idx.state === 'REVOKED'
          ? 'ego upgrade --to <version> (re-signed metadata required)'
          : 'ego sync';
    io.err(`pinned runtime ${pin.integrity.slice(0, 12)}… is ${idx.state}; remedy: \`${remedy}\``);
    return 2;
  }
  const project: ProjectContext = { root: projectRoot, pin, prePromotion: projectPrePromotion(pin, io.env) };
  if (self.runtimeSha256 === pin.integrity) {
    if (!isRuntimeCached(home, pin.integrity) && isFile(join(packageRoot(), 'dist', 'ego.js'))) {
      try {
        materializeRuntime(home, packageRoot(), pin.integrity);
        indexAdd(
          home,
          pin.name,
          pin.version,
          pin.integrity,
          {
            source: 'launcher',
            trust: isDevelopmentVersion(pin.version) ? 'local-tarball (unsigned)' : 'registry (unsigned)',
            cachedAt: io.now(),
          },
          io.now(),
        );
      } catch (e) {
        io.err(`EGO: could not materialize the launcher runtime: ${(e as Error).message}`);
      }
    }
    return runCommand(argv, io, project);
  }
  if (opts.delegatedBy) {
    io.err(
      `EGO: delegated runtime ${self.runtimeSha256.slice(0, 12)} does not match the pin ${pin.integrity.slice(0, 12)}; refusing to run`,
    );
    return 2;
  }
  if (isRuntimeCached(home, pin.integrity) && idx) {
    // Q96 is applied by the launcher before delegating; the pinned runtime re-applies it with the effective profile
    if (project.prePromotion && !PRE_PROMOTION_SET.has(cmd)) {
      io.err(
        `EGO: profile ${pin.profile} permits only the pre-promotion set until the pinned runtime reaches signed-release trust (Q96). Run \`ego sync\`; \`ego doctor\` shows the trust transition.`,
      );
      return 2;
    }
    const dir = runtimeDir(home, pin.integrity);
    if (!existsSync(join(dir, 'manifest.internal.json'))) {
      io.err(`cached runtime ${pin.integrity.slice(0, 12)} has no internal manifest; run \`ego sync\``);
      return 2;
    }
    const mod = (await import(pathToFileURL(join(dir, 'dist', 'ego.js')).href)) as {
      main?: (argv: string[], opts: Record<string, unknown>) => Promise<number>;
    };
    if (typeof mod.main !== 'function') {
      io.err(
        `cached runtime ${pin.integrity.slice(0, 12)} does not export main (exec contract ${COMPATIBILITY.execContract})`,
      );
      return 2;
    }
    return mod.main(argv, {
      cwd: io.cwd,
      env: io.env,
      stdin: io.stdin,
      out: io.out,
      err: io.err,
      now: io.now,
      delegatedBy: {
        launcherVersion: version,
        launcherIdentity: self.runtimeSha256,
        execContract: COMPATIBILITY.execContract,
      },
    });
  }
  io.err(
    `EGO ${pin.version} (runtime ${pin.integrity.slice(0, 12)}…) is pinned but not installed. Run \`ego sync\`.`,
  );
  return 2;
}

async function launcherCommand(
  cmd: string,
  rest: string[],
  io: CliIo,
  home: ReturnType<typeof egoHome>,
  projectRoot: string | null,
  launcher: { root: string; runtimeSha256: string; version: string },
): Promise<number> {
  const { positional, flags } = parseFlags(rest);
  const offline = flags['offline'] === true || io.env['EGO_OFFLINE'] === '1';
  switch (cmd) {
    case 'version': {
      const dev = selfIsDevelopment();
      const li = indexSummary(home, selfIdentity().name, launcher.version);
      io.out(
        `launcher ${launcher.version} identity ${launcher.runtimeSha256} acquisition ${li.entry?.records.map((r) => r.source).join(',') ?? 'not indexed'} trust ${li.trust ?? 'none'} node ${process.versions.node}${dev ? ' (development identity, never promotable)' : ''}`,
      );
      if (!li.trust || li.trust.endsWith('(unsigned)'))
        io.out(
          'note: convenience installs derive their trust from the registry, TLS and account; EGO integrity checks add tamper detection, not publisher proof (K18)',
        );
      if (projectRoot) {
        try {
          const pin = readPin(projectRoot);
          const pi = indexSummary(home, pin.name, pin.version);
          const requires = pin.profile !== 'STANDARD';
          const trust = pi.trust;
          io.out(
            `pinned   ${pin.version} identity ${pin.integrity} acquisition ${pi.entry?.records.map((r) => r.source).join(',') ?? 'not indexed'} trust ${trust ?? 'none'} profile ${pin.profile} requirement ${requires ? (trust && !trust.endsWith('(unsigned)') ? 'SATISFIED' : 'NOT SATISFIED') : 'n/a'}`,
          );
        } catch (e) {
          io.out(`pinned   unreadable: ${(e as Error).message}`);
        }
      }
      return 0;
    }
    case 'sync': {
      if (!projectRoot) {
        io.err('not initialized; run `ego init`');
        return 2;
      }
      let pin;
      try {
        pin = readPin(projectRoot);
      } catch (e) {
        io.err((e as Error).message);
        return 2;
      }
      const r = syncProject(home, pin, launcher, controlPlaneDir(), io.now(), { offline, env: io.env });
      for (const m of r.messages) io.out(m);
      if (!r.ok) return 2;
      // delegate the regeneration of generated artifacts to the pinned runtime through the normal path
      const code = await launch(['init'], io, {});
      io.out('sync: complete');
      return code;
    }
    case 'distribution': {
      const [sub, path] = positional;
      if (sub === 'verify' && path) {
        const r = verifyDistribution(home, path);
        for (const l of r.lines) io.out(l);
        return r.ok ? 0 : 1;
      }
      if (sub === 'import' && path) {
        let requireSigned = false;
        if (projectRoot) {
          try {
            requireSigned = readPin(projectRoot).profile !== 'STANDARD';
          } catch {
            /* outside a readable pin: no requirement */
          }
        }
        const r = importTarball(home, path, io.now(), {
          reMaterialize: flags['re-materialize'] === true,
          requireSigned,
        });
        for (const m of r.messages) io.out(m);
        if (r.ok) io.out(`imported ${r.version} (${r.identity!.slice(0, 12)}…) trust ${r.trust}`);
        return r.ok ? 0 : 2;
      }
      if (sub === 'bundle') {
        io.err('ego distribution bundle lands in phase 6 (air-gap bundle production)');
        return 2;
      }
      io.err('usage: ego distribution import <tarball> [--re-materialize] | verify <tarball>');
      return 2;
    }
    case 'bootstrap': {
      if (positional[0] !== 'doctor') {
        io.err('usage: ego bootstrap doctor [--reverify]');
        return 2;
      }
      const r = bootstrapDoctor(home, controlPlaneDir(), io.now(), {
        reverify: flags['reverify'] === true,
        launcher: { name: selfIdentity().name, version: launcher.version, identity: launcher.runtimeSha256 },
      });
      for (const l of r.lines) io.out(l);
      return r.ok ? 0 : 1;
    }
    case 'upgrade':
    case 'rollback': {
      io.err(
        `ego ${cmd}: the upgrade and rollback protocols land in phase 6; the pin is unchanged. Trust state: ${projectRoot ? describeTrust(home, projectRoot) : 'no project'}`,
      );
      return 2;
    }
  }
  return 2;
}

function describeTrust(home: ReturnType<typeof egoHome>, projectRoot: string): string {
  try {
    const pin = readPin(projectRoot);
    const idx = readIndex(home, pin.name, pin.version);
    return idx ? `${effectiveTrust(idx, revokedKeyIds(loadTrustStore(home))) ?? 'none'}` : 'not indexed';
  } catch {
    return 'pin unreadable';
  }
}
