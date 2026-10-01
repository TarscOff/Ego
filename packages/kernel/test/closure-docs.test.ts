// CLOSURE-DOCS: the containment and isolation documentation, and the comments and `doctor` lines that repeat it, say
// what the code does (independent audit of 2026-10-01, truthfulness items 12, 15, 21, 22, X1-X13 and criterion items
// D5, D28, D29, D31).
//
// Two kinds of test live here, on purpose. Where a sentence describes BEHAVIOUR (what the evaluator does for a network
// tool, what PostToolUse records, what `ego doctor` prints) the test runs the code and the sentence is checked against
// the result, so the day the behaviour changes the test names the sentence that must change with it. Where a sentence
// is a CLAIM that used to be false (a worktree called containment, a host matrix said to drive `doctor`), the test
// refuses the false sentence and requires the true one, so it cannot be re-introduced by an edit that looks
// harmless. Nothing here reads a document to decide how the code behaves.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { loadControlPlane } from '../src/control-plane/load.ts';
import { HOST_CAPABILITY_KEYS, HOST_IDS, HOST_MATRIX } from '../src/hosts/matrix.ts';
import { handleHook, type HookRuntime } from '../src/hooks/handle.ts';
import type { HookEvent } from '../src/hooks/events.ts';
import { openRuntimeRoot, readLedger } from '../src/runtime/root.ts';
import { initProject } from '../src/project/init.ts';
import * as doctor from '../src/project/doctor.ts';
import { readPin, writePin } from '../src/launcher/pin.ts';
import { selfIdentity, selfVersion } from '../src/launcher/self.ts';
import { evaluate } from '../src/authority/evaluate.ts';
import { ctx, table, workspace } from './support/corpus.ts';

const REPO = new URL('../../../', import.meta.url).pathname;
const CP = join(REPO, 'control-plane') + '/';
const read = (rel: string): string => readFileSync(join(REPO, rel), 'utf8');
const cp = loadControlPlane(CP);

/** the body of a markdown file: what a human reads, without the machine frontmatter */
const body = (rel: string): string => read(rel).replace(/^---\n[\s\S]*?\n---\n/, '');

// ---------------------------------------------------------------------------------------------------------------
// X11 / item 12 / item 22 / D5 / D29 — two tables, one answer
// ---------------------------------------------------------------------------------------------------------------

test('controls.md and matrix.ts carry the same status for every control they both name, on every host', () => {
  // `control-plane/containment/controls.md` is what `ego doctor` prints; `hosts/matrix.ts` is the record of host
  // capabilities by key. They answered differently for three claude-code entries (worktree-isolation,
  // managed-settings-lock, sandboxed-command-execution) for as long as nothing compared them: the test that was
  // titled "consistent with the matrix" never read the matrix.
  const keys = new Set<string>(HOST_CAPABILITY_KEYS);
  const shared = cp.containment.filter((c) => keys.has(c.id));
  // the comparison must not be able to pass by comparing nothing
  for (const must of [
    'worktree-isolation',
    'managed-settings-lock',
    'sandboxed-command-execution',
    'network-egress-control',
  ])
    assert.ok(
      shared.some((c) => c.id === must),
      `${must} is no longer shared by both tables; if it was renamed in one, rename it in the other`,
    );
  for (const c of shared)
    for (const h of HOST_IDS) {
      const inMatrix = HOST_MATRIX[h].capabilities[c.id as (typeof HOST_CAPABILITY_KEYS)[number]].status;
      assert.equal(
        c.hosts[h],
        inMatrix,
        `${c.id} on ${h}: controls.md says ${c.hosts[h]}, matrix.ts says ${inMatrix}. Both are statements EGO authored; ` +
          'decide which is true and change the other (the lesser claim, unless the code gained the capability).',
      );
    }
});

test('matrix.ts says who reads it and what its statuses are, and does not claim what no code does', () => {
  const src = read('packages/kernel/src/hosts/matrix.ts');
  // the old header said doctor "renders this table for the active host and marks every profile requirement that
  // depends on an UNVERIFIED capability as NOT SATISFIED"; doctor reads ONE key of eighteen from it
  assert.doesNotMatch(src, /renders this table/);
  assert.doesNotMatch(src, /the kernel enforces isolation through held scopes/, 'held scopes are phase 2');
  assert.doesNotMatch(src, /records its presence/, 'nothing detects a host sandbox');
  assert.doesNotMatch(src, /observes Bash writes after execution/, 'PostToolUse inspects no path');
  assert.doesNotMatch(
    src,
    /trust comes from \.harness\/mcp-trust\.md/,
    'nothing parses that file (issue #10)',
  );
  const header = src.slice(0, src.indexOf('import type'));
  assert.match(header, /blocking-pre-tool-hook/, 'the header names the one key doctor reads');
  assert.match(header, /controls\.md/, 'the header names the table doctor reports containment from');
  assert.match(header, /closure-docs\.test\.ts/, 'the header names the test that keeps the two tables equal');
  assert.match(header, /declar/i, 'every status is a declaration, not a measurement');
});

test('trust-and-hosts.test.ts no longer claims a consistency it does not check', () => {
  const src = read('packages/kernel/test/trust-and-hosts.test.ts');
  assert.doesNotMatch(
    src,
    /containment controls reference known hosts and profiles and are consistent with the matrix/,
    'that test never read the matrix; the comparison lives in closure-docs.test.ts',
  );
});

// ---------------------------------------------------------------------------------------------------------------
// X1 / criterion 6 — a worktree is isolation of Git state, not containment
// ---------------------------------------------------------------------------------------------------------------

test('a worktree is isolation of Git state, and no control of kind containment is claimed in force', () => {
  const byId = new Map(cp.containment.map((c) => [c.id, c]));
  // `kind` is data, so `doctor` and the documents derive the word from the control rather than from a list
  for (const c of cp.containment) assert.ok(c.kind, `${c.id} declares no kind`);
  assert.equal(byId.get('worktree-isolation')?.kind, 'isolation');
  assert.equal(byId.get('held-scope-isolation')?.kind, 'isolation');
  assert.equal(byId.get('sandboxed-command-execution')?.kind, 'containment');
  // "Today, no profile provides OS-level containment" (security-model.md): a control that restricts what a process
  // can physically reach may not be declared SUPPORTED on any host while that sentence stands.
  for (const c of cp.containment.filter((x) => x.kind === 'containment'))
    for (const h of HOST_IDS)
      assert.notEqual(c.hosts[h], 'SUPPORTED', `${c.id} on ${h} is containment and no containment is built`);
});

test('controls.md does not call a worktree a containment control and states what doctor really reports', () => {
  const md = body('control-plane/containment/controls.md');
  const all = read('control-plane/containment/controls.md');
  assert.doesNotMatch(md, /sandbox or a worktree is a containment control/);
  assert.match(md, /worktree is none of the three[\s\S]{0,400}never reported as\s+containment/i);
  // line ~70: "reports a required control whose host status is not SUPPORTED as NOT SATISFIED" was false for UNVERIFIED
  assert.doesNotMatch(md, /not SUPPORTED as NOT SATISFIED/);
  assert.match(md, /UNVERIFIED/, 'the report rule must say what UNVERIFIED does');
  assert.doesNotMatch(
    md,
    /prefers technical isolation over prompt instructions/,
    'a design intent, not a behaviour',
  );
  // X3: no shell write is observed after the fact
  assert.doesNotMatch(all, /detected after shell writes/);
  // X2
  assert.doesNotMatch(all, /HIGH_ASSURANCE denies public network use by tools\./);
});

// ---------------------------------------------------------------------------------------------------------------
// X2 — what network-egress-control covers, checked against the evaluator
// ---------------------------------------------------------------------------------------------------------------

test('network-egress-control names what HIGH_ASSURANCE refuses and what it leaves open, and the evaluator agrees', () => {
  const d = workspace({ 'package.json': JSON.stringify({ name: 'x', scripts: { build: 'tsc' } }) });
  const ha = (tool: string, input: Record<string, unknown>): string =>
    evaluate(table, { ...ctx(d), profile: 'HIGH_ASSURANCE' }, { tool, input }).verdict;
  const bash = (command: string): string => ha('Bash', { command });
  // refused: the network clients the classifier recognises, and the web tools
  for (const c of [
    'curl https://example.com',
    'wget -q https://example.com',
    'scp a.txt host:/tmp/',
    'ssh host true',
  ])
    assert.equal(bash(c), 'DENY', c);
  assert.equal(ha('WebFetch', { url: 'https://example.com/docs' }), 'DENY');
  assert.equal(ha('WebSearch', { query: 'node test runner' }), 'DENY');
  // not refused: these reach the network and are classified as something else. The description must say so.
  const open = {
    'git fetch origin': 'git',
    'git clone https://github.com/a/b.git /tmp/b': 'git',
    'git ls-remote https://github.com/a/b': 'git',
    'npm view left-pad': 'npm view',
    'gh pr list': 'gh',
    'docker pull alpine': 'docker',
  } as const;
  const description = cp.containment.find((c) => c.id === 'network-egress-control')!.description;
  for (const [command, word] of Object.entries(open)) {
    assert.equal(
      bash(command),
      'ALLOW',
      `${command} is no longer an open egress path: update the description`,
    );
    assert.ok(description.includes(word), `network-egress-control does not name "${word}" as not restricted`);
  }
  assert.match(
    description,
    /no OS-level/i,
    'the description must say no operating-system egress restriction exists',
  );
  assert.match(description, /classif/i);
});

// ---------------------------------------------------------------------------------------------------------------
// X3 — PostToolUse observes nothing on the file system
// ---------------------------------------------------------------------------------------------------------------

test('PostToolUse records a ledger line and observes no shell write, and no document says it does', () => {
  const root = mkdtempSync(join(tmpdir(), 'ego-closure-hook-'));
  spawnSync('git', ['init', '-q'], { cwd: root });
  writeFileSync(join(root, 'package.json'), '{"name":"demo"}');
  const self = selfIdentity();
  writePin(root, {
    name: self.name,
    version: selfVersion(),
    integrity: self.runtimeSha256,
    sources: [],
    schemas: {},
    node: '>=24',
    profile: 'HIGH_ASSURANCE',
    taskSource: 'ad-hoc',
  });
  let t = 0;
  const rt: HookRuntime = {
    projectRoot: root,
    pin: readPin(root),
    now: () => new Date(Date.UTC(2026, 9, 1, 10, 0, t++)).toISOString(),
    controlPlaneRoot: CP,
    env: { EGO_HOME: mkdtempSync(join(tmpdir(), 'ego-closure-home-')), CLAUDE_PROJECT_DIR: root },
  };
  // the write has really happened by the time the hook runs
  mkdirSync(join(root, '.claude'), { recursive: true });
  writeFileSync(join(root, '.claude', 'settings.json'), '{"hooks":{}}\n');
  const ev: HookEvent = {
    host: 'claude-code',
    event: 'PostToolUse',
    sessionId: 's1',
    cwd: root,
    raw: {},
    tool: {
      name: 'Bash',
      input: { command: 'echo "{}" > .claude/settings.json' },
      response: { exit_code: 0 },
    },
  };
  const decision = handleHook(ev, rt);
  assert.equal(decision.action, 'continue');
  assert.equal(decision.context, undefined, 'PostToolUse now tells the model something about the write');
  const rr = openRuntimeRoot(root, { runtimeSha256: rt.pin.integrity, version: rt.pin.version }, rt.now());
  const post = readLedger(rr, { kinds: ['tool.post'] });
  assert.equal(post.length, 1);
  assert.deepEqual(
    Object.keys(post[0]!.data ?? {}).sort(),
    ['failed', 'summary', 'tool'],
    'PostToolUse now records more than the tool, its one-line summary and whether it failed: if it inspects a path, ' +
      'rewrite protected-paths in controls.md and post-tool-hook in matrix.ts',
  );

  const controls = read('control-plane/containment/controls.md');
  const matrix = read('packages/kernel/src/hosts/matrix.ts');
  assert.doesNotMatch(controls, /detected after shell writes/);
  assert.doesNotMatch(matrix, /observes Bash writes after execution/);
  const protectedPaths = cp.containment.find((c) => c.id === 'protected-paths')!.description;
  assert.match(protectedPaths, /before the call runs|before it runs|before execution/i);
  assert.match(
    protectedPaths,
    /ego check/,
    'drift in generated files is found on demand, and the text says by what',
  );
  assert.match(protectedPaths, /nothing observes|does not observe|inspects no path/i);
});

// ---------------------------------------------------------------------------------------------------------------
// X5 / X7 / X8 / item 15 — what `ego doctor` prints
// ---------------------------------------------------------------------------------------------------------------

function fixtureProject(): { dir: string; env: NodeJS.ProcessEnv } {
  // Every fixture lives under its own parent: `detectProject` lists the siblings of a repository, and a repository
  // created straight in $TMPDIR makes `ego init` stat every entry of the machine's temp directory (35 s per init).
  const parent = mkdtempSync(join(tmpdir(), 'ego-closure-'));
  const dir = join(parent, 'repo');
  mkdirSync(dir);
  const git = (...a: string[]) => {
    const env: NodeJS.ProcessEnv = {};
    for (const [k, v] of Object.entries(process.env)) if (!/^GIT_/.test(k)) env[k] = v;
    spawnSync('git', a, { cwd: dir, env });
  };
  git('init', '-q');
  git('config', 'user.email', 't@example.com');
  git('config', 'user.name', 't');
  writeFileSync(join(dir, 'package.json'), '{"name":"demo","version":"1.0.0"}');
  writeFileSync(join(dir, 'AGENTS.md'), '# Demo\n');
  git('add', '-A');
  git('commit', '-qm', 'init');
  const env: NodeJS.ProcessEnv = {
    PATH: process.env['PATH'],
    HOME: process.env['HOME'],
    EGO_HOME: mkdtempSync(join(parent, 'home-')),
    LANG: 'C',
  };
  initProject({ cwd: dir, env, now: () => '2026-10-01T10:00:00.000Z', offline: true });
  return { dir, env };
}

function doctorAs(
  fx: { dir: string; env: NodeJS.ProcessEnv },
  profile: string,
  host?: 'claude-code' | 'codex-cli',
): doctor.DoctorReport {
  const pin = readPin(fx.dir);
  const { stamp: _stamp, ...rest } = pin as typeof pin & { stamp?: string };
  // STRICT and HIGH_ASSURANCE cannot be reached with `ego init --profile` on a development identity (they need a
  // signed release), so the pin is written the way tests/integration/cli.test.ts writes it
  writePin(fx.dir, { ...rest, version: '9.9.9', profile } as typeof pin);
  const opts: doctor.DoctorOptions = {
    cwd: fx.dir,
    env: fx.env,
    now: () => '2026-10-01T10:00:00.000Z',
    offline: true,
  };
  if (host) opts.host = host;
  return doctor.runDoctor(opts);
}

const lineOf = (r: doctor.DoctorReport, item: RegExp): doctor.DoctorLine | undefined =>
  r.lines.find((l) => item.test(l.item));

test('doctor under HIGH_ASSURANCE reports the sandbox as not in force, a worktree as isolation, and agrees with itself on the managed tier', () => {
  const fx = fixtureProject();
  const r = doctorAs(fx, 'HIGH_ASSURANCE', 'claude-code');
  // item 15: the single most important absent control used to be unreported, because nothing required it and nothing
  // read `recommended_in`
  const sandbox = lineOf(r, /^sandboxed-command-execution on claude-code$/);
  assert.ok(sandbox, 'doctor prints no line for the sandbox control');
  assert.equal(sandbox.state, 'NOT SATISFIED');
  assert.equal(
    sandbox.required,
    false,
    'recommended, required by no profile: reported, never failing the exit code',
  );
  assert.match(sandbox.detail, /recommended in HIGH_ASSURANCE/);
  assert.match(sandbox.detail, /UNAVAILABLE/);
  assert.equal(sandbox.section, 'containment');
  // X1: a worktree is not filed under containment
  const worktree = lineOf(r, /^worktree-isolation on claude-code$/);
  assert.ok(worktree);
  assert.notEqual(worktree.section, 'containment');
  assert.equal(worktree.section, 'isolation');
  // X7: the integrity line and the requires_managed_tier line told two stories in one run
  const managedTier = lineOf(r, /^requires_managed_tier$/);
  assert.ok(managedTier, 'requires_managed_tier is reported');
  assert.equal(managedTier.state, 'NOT SATISFIED');
  const integrity = lineOf(r, /^integrity$/)!;
  assert.doesNotMatch(integrity.detail, /managed tier in HIGH_ASSURANCE/);
  assert.match(integrity.detail, /no managed tier/i);
  assert.match(integrity.detail, /on demand/i, 'detect-out-of-band is the on-demand hash comparison');
  // X5: UNVERIFIED stays UNVERIFIED and does not fail the run on its own
  assert.equal(lineOf(r, /^managed-settings-lock on claude-code$/)?.state, 'UNVERIFIED');
  assert.equal(r.ok, false, 'HIGH_ASSURANCE on a host that provides none of its controls never passes');
  // X8: every profile setting nothing reads is named
  const remote = lineOf(r, /^requires_remote_verify_backstop$/);
  assert.ok(remote, 'requires_remote_verify_backstop is declared and read by nothing');
  assert.equal(remote.state, 'NOT SATISFIED');
  const policies = lineOf(r, /^profile settings declared, not enforced$/);
  assert.ok(policies, 'the policy settings nothing reads are listed in one line');
  for (const key of [
    'shell_uncertain_mutation_with_foreign_live_session',
    'grilling_review_unavailable',
    'forge_unreachable_at_done',
  ])
    assert.ok(policies.detail.includes(key), `${key} is not named`);
  assert.equal(policies.required, false);
});

test('doctor under STRICT lists the recommended controls that are not in force, and the policy settings nothing reads', () => {
  const fx = fixtureProject();
  const r = doctorAs(fx, 'STRICT', 'claude-code');
  for (const id of [
    'worktree-isolation',
    'sandboxed-command-execution',
    'network-egress-control',
    'managed-settings-lock',
  ]) {
    const l = lineOf(r, new RegExp(`^${id} on claude-code$`));
    assert.ok(l, `STRICT recommends ${id} and doctor does not say whether it is in force`);
    assert.match(l.detail, /recommended in STRICT/);
    assert.equal(l.required, false, `${id} is only recommended in STRICT: reported, never failing the run`);
  }
  assert.equal(lineOf(r, /^requires_managed_tier$/), undefined, 'STRICT does not ask for a managed tier');
  assert.ok(
    lineOf(r, /^profile settings declared, not enforced$/)?.detail.includes(
      'shell_uncertain_mutation_with_foreign_live_session',
    ),
  );
  // with no host determined nothing is claimed and nothing fails
  const none = doctorAs(fx, 'STRICT');
  assert.equal(
    none.lines
      .filter((l) => /\bon (claude-code|codex-cli)$/.test(l.item))
      .every((l) => l.state === 'UNVERIFIED' && !l.required),
    true,
  );
});

test('doctor says what EGO establishes or detects, not what the host provides', () => {
  // a host may offer a sandbox EGO never detects: "neither the host nor EGO provides it" was a claim about the host
  const src = read('packages/kernel/src/project/doctor.ts');
  assert.doesNotMatch(src, /neither the host nor EGO provides it today/);
  assert.match(src, /EGO neither establishes nor detects it on this host/);
});

// ---------------------------------------------------------------------------------------------------------------
// X8 / D28 — profile documents: declared settings are marked, not promised
// ---------------------------------------------------------------------------------------------------------------

test('the profile documents separate what is enforced from what is declared and nothing reads', () => {
  const declared = doctor.DECLARED_ONLY_PROFILE_SETTINGS;
  assert.ok(declared.length >= 7, 'doctor lists the profile settings no code reads');
  for (const file of ['strict', 'high-assurance']) {
    const rel = `control-plane/profiles/${file}.md`;
    const md = body(rel);
    const raw = read(rel);
    assert.match(md, /declared, not enforced/i, `${rel} does not mark what is declared and not enforced`);
    const profile = cp.profiles.find((p) => p.file.endsWith(`${file}.md`))!;
    for (const s of declared) {
      const value = profile[s.field];
      if (value === s.baseline) continue;
      assert.ok(
        new RegExp('`' + s.key + '[`:]').test(md),
        `${rel} promises ${s.key} without marking it declared, not enforced`,
      );
      // and the machine front matter says the same thing next to the setting
      const line = raw.split('\n').findIndex((l) => l.startsWith(`${s.key}:`));
      assert.ok(line > 0, `${rel} lost the ${s.key} setting`);
      assert.match(
        raw.split('\n')[line - 1]!,
        /^#.*(declared, not enforced|read by no code)/i,
        `${rel}: ${s.key} carries no comment`,
      );
    }
  }
  // the sentences that stated these as facts
  assert.doesNotMatch(body('control-plane/profiles/strict.md'), /DONE is blocked while/);
  assert.doesNotMatch(body('control-plane/profiles/strict.md'), /uncertain shell mutations are denied when/);
  assert.doesNotMatch(
    body('control-plane/profiles/high-assurance.md'),
    /a second live session is refused in\s+a bound checkout\)/,
  );
  assert.doesNotMatch(
    body('control-plane/profiles/high-assurance.md'),
    /and no public network use by tools\./,
  );
  assert.doesNotMatch(
    body('control-plane/profiles/high-assurance.md'),
    /`doctor` reports every requirement of this profile as SATISFIED or NOT SATISFIED/,
  );
});

test('the signed-release-trust requirement is documented as enforced by profile identity, which is what the code does', () => {
  // `requires_signed_release_trust` is copied into the compiled table and read by nothing; doctor, the launcher and the
  // hooks test `profile !== 'STANDARD'`. The documents may say the requirement is enforced, but not that the setting is.
  for (const file of ['strict', 'high-assurance']) {
    const md = body(`control-plane/profiles/${file}.md`);
    assert.match(md, /requires_signed_release_trust/);
    assert.match(md, /profile['’]s identity|any profile other than STANDARD/i);
  }
});

// ---------------------------------------------------------------------------------------------------------------
// X9 / X10 / X12 / D5 / item 21 — security-model.md and the alignment table
// ---------------------------------------------------------------------------------------------------------------

test('security-model.md: containment is not said to exist in any profile, the columns are named, and the claims carry their exceptions', () => {
  const md = read('docs/architecture/security-model.md');
  // item 21
  const row = md.split('\n').find((l) => l.startsWith('| **Containment**'))!;
  assert.match(row, /does not exist today in any profile/);
  assert.doesNotMatch(row, /does not exist in every profile/);
  // X10: the two pointers counted differently
  assert.doesNotMatch(md, /the second column is the one/);
  assert.doesNotMatch(md, /The third column is why/);
  assert.equal((md.match(/"Actually in force today" column/g) ?? []).length >= 2, true);
  // X9: the claims cell and the invariant are conditional
  const standard = md.split('\n').find((l) => l.startsWith('| **STANDARD**'))!;
  assert.match(
    standard,
    /phase-1-residuals\.md/,
    'the cell that governs what may be claimed names the recorded exceptions',
  );
  const invariant = md.slice(md.indexOf('## The global invariant'), md.indexOf('## Execution closure'));
  assert.match(invariant, /phase-1-residuals\.md/);
  assert.match(invariant, /unread|not read|never read/i);
  // the isolation column states what is in force without understating
  const high = md.split('\n').find((l) => l.startsWith('| **HIGH_ASSURANCE**'))!;
  assert.match(high, /signed-release trust/);
  assert.match(high, /BLOCK/);
  // D5 / item 12: the two tables are said to AGREE, because a test makes them, and the text says which one doctor reads
  assert.doesNotMatch(md, /can drift apart with nothing to catch it/);
  assert.match(md, /closure-docs\.test\.ts/);
  assert.match(md, /ego doctor[^.]*controls\.md|controls\.md[^.]*ego doctor/);
});

test('alignment-2026-09.md items 2 and 3 state what the matrix and doctor do', () => {
  const md = read('docs/architecture/alignment-2026-09.md');
  const row = (n: number) => md.split('\n').find((l) => l.startsWith(`| ${n} |`))!;
  assert.doesNotMatch(row(2), /reported by `doctor`/);
  assert.match(row(2), /blocking-pre-tool-hook/, 'item 2 names the one key doctor reads');
  assert.match(row(2), /controls\.md/);
  assert.doesNotMatch(row(3), /Containment existed implicitly/);
  assert.doesNotMatch(row(3), /HIGH_ASSURANCE isolation\)/);
  assert.match(row(3), /issue #26/);
});

// ---------------------------------------------------------------------------------------------------------------
// X13 — control-plane/README.md
// ---------------------------------------------------------------------------------------------------------------

test('control-plane/README.md names the capability the evaluator returns and says the controls file enforces nothing', () => {
  const md = read('control-plane/README.md');
  const row = md.split('\n').find((l) => l.startsWith('| `containment/controls.md`'))!;
  assert.match(row, /enforces nothing/);
  assert.doesNotMatch(row, /Containment controls \(isolation, sandboxing\)/);
  // a script the kernel cannot find is `command.unknown` (ASK), not `command.script-opaque`
  assert.match(md, /command\.unknown/);
  assert.doesNotMatch(
    md,
    /\(missing, outside the workspace, dynamic commands, an interpreter program\) is `command\.script-opaque`/,
  );
  assert.doesNotMatch(md, /so unknown execution asks a human rather than being waved through/);
  assert.match(md, /issue #26/);
});

// ---------------------------------------------------------------------------------------------------------------
// D31 / item 12 of the task — a claim made on an issue must not be repeated in a repository document
// ---------------------------------------------------------------------------------------------------------------

test('no document repeats that the option-grammar family is closed generically', () => {
  // Issue #26 once called "the -o, --exec, --pre, --use-compress-program family" closed generically. Exit review 11
  // found about fifty tools of that family wrong by omission. The issue cannot be edited from here; the repository's
  // own documents must not carry the sentence. The scan stops at docs/build and phase-1-*.md, which another pass owns.
  const roots = ['control-plane', 'docs/architecture', 'README.md', 'CHANGELOG.md'];
  const files: string[] = [];
  const walk = (p: string): void => {
    const full = join(REPO, p);
    let st;
    try {
      st = statSync(full);
    } catch {
      return;
    }
    if (st.isDirectory()) for (const e of readdirSync(full)) walk(join(p, e));
    else if (p.endsWith('.md') && !/phase-1-/.test(p)) files.push(p);
  };
  for (const r of roots) walk(r);
  assert.ok(files.length > 10);
  for (const f of files) {
    const text = read(f);
    assert.doesNotMatch(
      text,
      /closed generically/i,
      `${relative(REPO, join(REPO, f))} repeats the issue's claim`,
    );
  }
});
