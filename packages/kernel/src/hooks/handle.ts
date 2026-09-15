// Hook handlers: one kernel for every host. Deterministic, no model, fail closed on any internal error (the adapter
// converts a thrown error into exit 2 with a one-line message).
import { join } from 'node:path';
import { evaluate, type EvaluationContext } from '../authority/evaluate.ts';
import { evaluateBudget, applyBudgetExtension, type BudgetCounters } from '../authority/budget.ts';
import type { ExecutionBudgets } from '../control-plane/types.ts';
import { ensurePolicyCache, type PolicyCache } from '../policy/cache.ts';
import {
  openRuntimeRoot,
  readSession,
  writeSession,
  newSession,
  appendLedger,
  withSessionLock,
  type RuntimeRoot,
  type SessionRecord,
} from '../runtime/root.ts';
import { recognizeGrants, recognizeModeMarker, recognizeCorrection } from '../session/grants.ts';
import { redact, allDetectors } from '../redaction/redact.ts';
import { loadControlPlane } from '../control-plane/load.ts';
import type { SecretDetector } from '../control-plane/types.ts';
import { readPin, type Pin } from '../launcher/pin.ts';
import { isEgoSourceRepository, controlPlaneDir, selfIdentity, selfVersion } from '../launcher/self.ts';
import { egoHome } from '../launcher/home.ts';
import { isFile } from '../util/fs.ts';
import type { HookEvent, HookDecision } from './events.ts';
import { frameForContext, provenance } from '../context/trust.ts';
import { resolveOnPath } from '../util/path-resolve.ts';

export interface HookRuntime {
  projectRoot: string;
  pin: Pin;
  now: () => string;
  /** override for tests */
  controlPlaneRoot?: string;
  /** STRICT / HIGH_ASSURANCE before trust promotion (Q96): only the pre-promotion set, no governed mutation */
  prePromotion?: boolean;
  /** process environment (EGO_HOME, PATH); defaults to process.env */
  env?: NodeJS.ProcessEnv;
}

/** Capabilities that are never "governed mutation": reads, searches, status queries (Q96 pre-promotion set). */
const READ_ONLY_CAPABILITIES = new Set([
  'fs.repo.read',
  'fs.repo.search',
  'command.read-only',
  'command.test',
  'command.build',
  'git.local.status',
  'git.remote.inspect',
  'forge.repo.read',
  'forge.pr.read',
  'forge.checks.read',
  'forge.issue.read',
  'network.localhost',
  'mcp.local.discover',
  'mcp.local.read',
  'harness.runtime.write',
]);

const NETWORK_CAPABILITY_PREFIXES = [
  'network.',
  'command.network-tool',
  'git.remote.fetch',
  'git.remote.pull',
  'git.remote.clone',
  'forge.',
  'mcp.remote.',
];

let detectorCache: { root: string; detectors: SecretDetector[] } | null = null;
function detectorsFor(controlPlaneRoot: string): SecretDetector[] {
  if (detectorCache && detectorCache.root === controlPlaneRoot) return detectorCache.detectors;
  const cp = loadControlPlane(controlPlaneRoot);
  detectorCache = { root: controlPlaneRoot, detectors: allDetectors(cp.secrets) };
  return detectorCache.detectors;
}

function redactForLedger(text: string, controlPlaneRoot: string): string {
  return redact(text, detectorsFor(controlPlaneRoot)).text;
}

function loadSession(root: RuntimeRoot, ev: HookEvent, rt: HookRuntime, cache: PolicyCache): SessionRecord {
  const existing = readSession(root, ev.sessionId);
  if (existing) return existing;
  const s = newSession({
    sessionId: ev.sessionId,
    host: ev.host,
    cwd: ev.cwd,
    mode: cache.table.defaultMode,
    profile: rt.pin.profile,
    now: rt.now(),
  });
  if (ev.hostPid !== undefined) s.pid = ev.hostPid;
  writeSession(root, s);
  return s;
}

function budgetsFor(cache: PolicyCache, profile: string, session: SessionRecord): ExecutionBudgets {
  const p = cache.table.profiles[profile] ?? cache.table.profiles['STRICT']!;
  return applyBudgetExtension(p.budgets, session.budgetExtensions as Partial<ExecutionBudgets>);
}

function countersOf(s: SessionRecord, now: string): BudgetCounters {
  const elapsedMinutes = Math.max(0, (Date.parse(now) - Date.parse(s.startedAt)) / 60000);
  return {
    elapsedMinutes,
    iterations: s.counters.iterations,
    toolCalls: s.counters.toolCalls,
    maxRetriesForOneStep: s.counters.maxRetriesForOneStep,
    delegationDepth: s.counters.delegationDepth,
    concurrentSubagents: s.counters.concurrentSubagents,
    networkOperations: s.counters.networkOperations,
  };
}

export function handleHook(ev: HookEvent, rt: HookRuntime): HookDecision {
  const cpRoot = rt.controlPlaneRoot ?? controlPlaneDir();
  const self = { runtimeSha256: selfIdentity().runtimeSha256, version: selfVersion() };
  const { cache } = ensurePolicyCache(cpRoot, rt.projectRoot, self);
  const root = openRuntimeRoot(rt.projectRoot, self, rt.now());
  return withSessionLock(root, ev.sessionId, () => handleLocked(ev, rt, cpRoot, cache, root));
}

function handleLocked(
  ev: HookEvent,
  rt: HookRuntime,
  cpRoot: string,
  cache: PolicyCache,
  root: RuntimeRoot,
): HookDecision {
  const self = { runtimeSha256: cache.runtimeSha256, version: cache.runtimeVersion };
  const session = loadSession(root, ev, rt, cache);
  const now = rt.now();
  session.heartbeatAt = now;
  const inEgo = isEgoSourceRepository(rt.projectRoot);
  // the session record is not trusted to widen authority: a mode the record names is honoured only when it exists in
  // the compiled table and, for HARNESS_MAINTENANCE, only inside the EGO source repository
  const knownModes = Object.keys(cache.table.profiles[rt.pin.profile]?.modes ?? {});
  const effectiveMode =
    knownModes.includes(session.mode) && !(session.mode === 'HARNESS_MAINTENANCE' && !inEgo)
      ? session.mode
      : cache.table.defaultMode;
  const ctx: EvaluationContext = {
    profile: rt.pin.profile,
    mode: effectiveMode,
    repoRoots: [rt.projectRoot, root.workspaceRoot],
    egoHome: egoHome(rt.env ?? process.env).root,
    grants: session.grants,
    inEgoRepository: inEgo,
    cwd: ev.cwd || rt.projectRoot,
  };
  const ledger = (kind: string, data: Record<string, unknown>) => {
    const entry: Parameters<typeof appendLedger>[1] = { at: now, kind, sessionId: ev.sessionId, data };
    if (ev.agentId) entry.agentId = ev.agentId;
    if (session.taskId) entry.taskId = session.taskId;
    appendLedger(root, entry);
  };

  switch (ev.event) {
    case 'SessionStart': {
      if (ev.source === 'startup' || ev.source === 'clear') session.counters.iterations = 0; // compact / resume continue the same budget
      writeSession(root, session);
      const launcher = resolveOnPath('harness', rt.env ?? process.env);
      const lines = [
        `EGO ${self.version} (runtime ${self.runtimeSha256.slice(0, 12)}) governs this repository. Profile ${rt.pin.profile}, mode ${session.mode}, task source ${rt.pin.taskSource ?? 'ad-hoc'}.`,
        `Authority: ${cache.table.absoluteDenies.length} absolute denies and ${cache.table.organizationLocked.length} organization-locked denies are enforced deterministically; ASK capabilities prompt the human once per grant.`,
        session.grants.length
          ? `Active grants (this session): ${session.grants.join(', ')}.`
          : 'No grants active.',
        session.activeCorrections.length
          ? `Active corrections: ${session.activeCorrections.map((c) => `"${c}"`).join('; ')}.`
          : '',
        launcher
          ? ''
          : 'WARNING: the `harness` launcher is not resolvable on PATH; hook shims fail closed until it is.',
        ev.source === 'compact' || ev.source === 'resume'
          ? 'Resumed: durable task state, not this transcript, is the source of truth. Run `harness status` before continuing.'
          : '',
        'Use `harness help` for what you can do here, `harness status` for the current state, `harness explain capability <id>` for any refusal.',
      ].filter(Boolean);
      ledger('session.start', {
        host: ev.host,
        source: ev.source ?? 'startup',
        launcherOnPath: launcher !== null,
      });
      return { event: ev.event, action: 'continue', context: lines.join('\n'), exitCode: 0 };
    }
    case 'UserPromptSubmit': {
      const prompt = ev.prompt ?? '';
      const notes: string[] = [];
      session.counters.iterations += 1;
      // Caller heuristic (K14, open item 13): a host-run hook carries the host's project-dir marker; an agent shell
      // invoking the hook entry point does not. Grants and mode changes from an unmarked caller are recorded as
      // refused. Deterministic caller verification is a phase-6 conformance deliverable; doctor reports the status.
      const env = rt.env ?? process.env;
      const callerUnverified = ev.host === 'claude-code' ? !env['CLAUDE_PROJECT_DIR'] : true;
      if (callerUnverified && (recognizeModeMarker(prompt) || recognizeGrants(prompt, cache.table).length)) {
        ledger('prompt.caller-unverified', {
          host: ev.host,
          hasProjectDirMarker: Boolean(env['CLAUDE_PROJECT_DIR']),
        });
        writeSession(root, session);
        return {
          event: ev.event,
          action: 'continue',
          context:
            'EGO: this prompt carried a grant or mode marker but did not arrive through a verified host channel; nothing was recorded (INPUT_CALLER_UNVERIFIED).',
          exitCode: 0,
        };
      }
      const marker = recognizeModeMarker(prompt);
      if (marker) {
        const mode = Object.keys(cache.table.profiles[rt.pin.profile]?.modes ?? {}).find((m) => m === marker);
        if (!mode) notes.push(`EGO: unknown mode "${marker}" ignored.`);
        else if (mode === 'HARNESS_MAINTENANCE' && !inEgo)
          notes.push(
            'EGO: HARNESS_MAINTENANCE is available only in the EGO source repository; mode unchanged.',
          );
        else if (mode === 'BENCHMARK')
          notes.push(
            'EGO: BENCHMARK mode is entered by `harness benchmark run`, not by prompt; mode unchanged.',
          );
        else {
          session.mode = mode;
          notes.push(`EGO: authority mode is now ${mode} (this session).`);
          ledger('mode.set', { mode, via: 'prompt-marker' });
        }
      }
      for (const g of recognizeGrants(prompt, cache.table)) {
        if (g.negated) {
          notes.push(`EGO: "${g.phrase}" was negated; no grant for ${g.capability}.`);
          continue;
        }
        const verdict =
          cache.table.profiles[rt.pin.profile]?.modes[session.mode]?.[g.capability] ??
          cache.table.effective[g.capability];
        if (verdict !== 'ASK') {
          notes.push(`EGO: ${g.capability} is ${verdict} here; a grant changes nothing.`);
          continue;
        }
        if (!session.grants.includes(g.capability)) {
          session.grants.push(g.capability);
          ledger('grant.recorded', { capability: g.capability, phrase: g.phrase });
        }
        notes.push(`EGO: grant recorded, ${g.capability} is ALLOW for this session.`);
      }
      const correctionRaw = recognizeCorrection(prompt);
      const correction = correctionRaw ? redactForLedger(correctionRaw, cpRoot) : null; // runtime state never holds a secret
      if (correction && !session.activeCorrections.includes(correction)) {
        session.activeCorrections = [...session.activeCorrections, correction].slice(-12);
        ledger('correction.recorded', { correction });
      }
      writeSession(root, session);
      const decision: HookDecision = { event: ev.event, action: 'continue', exitCode: 0 };
      if (notes.length) decision.context = notes.join('\n');
      return decision;
    }
    case 'PreToolUse': {
      if (!ev.tool || !ev.tool.name) {
        // a payload without a tool is not a decision the kernel can make: fail closed, never allow by default
        ledger('tool.pre', { tool: null, verdict: 'DENY', reason: 'payload without tool_name' });
        writeSession(root, session);
        return {
          event: ev.event,
          action: 'deny',
          reason: 'EGO: PreToolUse payload has no tool_name; failing closed',
          exitCode: 2,
        };
      }
      const tool = ev.tool;
      session.counters.toolCalls += 1;
      const evaluation = evaluate(cache.table, ctx, { tool: tool.name, input: tool.input });
      // a denied call never executes: only calls that may run count against the network budget
      const isNetwork =
        evaluation.verdict !== 'DENY' &&
        evaluation.hits.some((h) => NETWORK_CAPABILITY_PREFIXES.some((p) => h.capability.startsWith(p)));
      if (isNetwork) session.counters.networkOperations += 1;
      // execution budgets (alignment item 8): breach blocks or escalates until a human extends
      const budgets = budgetsFor(cache, rt.pin.profile, session);
      const bv = evaluateBudget(budgets, countersOf(session, now));
      // a DENY is never weakened into an escalation: budgets only ever tighten what the table allows
      if (bv.action !== 'CONTINUE' && evaluation.verdict !== 'DENY') {
        session.budgetState = {
          action: bv.action,
          breaches: bv.breaches,
          since: session.budgetState?.since ?? now,
        };
        writeSession(root, session);
        const what = bv.breaches.map((b) => `${b.dimension} ${b.observed} > ${b.limit}`).join(', ');
        ledger('budget.breach', { action: bv.action, breaches: bv.breaches, tool: tool.name });
        const reason = `EGO execution budget exceeded (${what}); ${bv.action === 'BLOCK' ? 'governed tool calls are blocked' : 'human decision required'} until a human runs \`harness budget extend\` for this session.`;
        return {
          event: ev.event,
          action: bv.action === 'BLOCK' ? 'deny' : 'ask',
          reason,
          userMessage: reason,
          exitCode: 0,
          details: { budget: bv },
        };
      }
      const summary = summarizeInput(tool.name, tool.input, cpRoot);
      // retry hard stop (alignment item 8): the same step may not run again once it failed more than the profile's retries
      const stepKey = `${tool.name}:${summary.slice(0, 80)}`;
      const failures = session.counters.failuresByStep[stepKey] ?? 0;
      if (failures > budgets.maxRetriesPerStep && evaluation.verdict !== 'DENY') {
        writeSession(root, session);
        ledger('budget.retry-stop', {
          step: stepKey,
          failures,
          limit: budgets.maxRetriesPerStep,
          action: budgets.onExceed,
        });
        const reason = `EGO: this step already failed ${failures} times (${budgets.maxRetriesPerStep} retries allowed); ${budgets.onExceed === 'BLOCK' ? 'it is blocked' : 'a human decision is required'}: change approach or ask for a decision.`;
        return {
          event: ev.event,
          action: budgets.onExceed === 'BLOCK' ? 'deny' : 'ask',
          reason,
          userMessage: reason,
          exitCode: 0,
        };
      }
      writeSession(root, session);
      if (
        rt.prePromotion &&
        evaluation.verdict !== 'DENY' &&
        evaluation.hits.some((h) => !READ_ONLY_CAPABILITIES.has(h.capability))
      ) {
        const cap = evaluation.hits.find((h) => !READ_ONLY_CAPABILITIES.has(h.capability))!.capability;
        ledger('tool.pre', {
          tool: tool.name,
          verdict: 'DENY',
          capability: cap,
          summary,
          prePromotion: true,
        });
        const reason = `EGO: profile ${rt.pin.profile} permits no governed mutation (${cap}) until the pinned runtime reaches signed-release trust; run \`harness sync\` (Q96).`;
        return { event: ev.event, action: 'deny', reason, userMessage: reason, exitCode: 0 };
      }
      ledger('tool.pre', {
        tool: tool.name,
        verdict: evaluation.verdict,
        capability: evaluation.decisive?.capability,
        summary,
      });
      const action = evaluation.verdict === 'ALLOW' ? 'allow' : evaluation.verdict === 'ASK' ? 'ask' : 'deny';
      const decision: HookDecision = {
        event: ev.event,
        action,
        reason: `EGO: ${evaluation.reason}`,
        exitCode: 0,
        details: { hits: evaluation.hits },
      };
      if (action === 'deny') {
        const cap = evaluation.decisive?.capability ?? 'unknown';
        decision.userMessage = `EGO refused ${tool.name}: ${cap} is DENY. \`harness explain capability ${cap}\` explains why.`;
      }
      return decision;
    }
    case 'PostToolUse': {
      const tool = ev.tool ?? { name: 'unknown', input: {} };
      const summary = summarizeInput(tool.name, tool.input, cpRoot);
      const failed = toolFailed(tool.response);
      if (failed) {
        const key = `${tool.name}:${summary.slice(0, 80)}`;
        const n = (session.counters.failuresByStep[key] ?? 0) + 1;
        session.counters.failuresByStep[key] = n;
        session.counters.maxRetriesForOneStep = Math.max(session.counters.maxRetriesForOneStep, n - 1);
        const keys = Object.keys(session.counters.failuresByStep);
        if (keys.length > 200) delete session.counters.failuresByStep[keys[0]!];
      }
      writeSession(root, session);
      ledger('tool.post', { tool: tool.name, summary, failed });
      const decision: HookDecision = { event: ev.event, action: 'continue', exitCode: 0 };
      const budgets = budgetsFor(cache, rt.pin.profile, session);
      const stepFailures = failed
        ? (session.counters.failuresByStep[`${tool.name}:${summary.slice(0, 80)}`] ?? 0)
        : 0;
      if (failed && stepFailures > budgets.maxRetriesPerStep) {
        decision.context = `EGO: this step has failed ${stepFailures} times, the profile allows ${budgets.maxRetriesPerStep} retries; the next identical attempt is ${budgets.onExceed === 'BLOCK' ? 'blocked' : 'escalated'}. Report the failure and ask for a decision.`;
      }
      return decision;
    }
    case 'SubagentStart': {
      const agentId = ev.agentId ?? `agent-${session.agents.length + 1}`;
      const rec: SessionRecord['agents'][number] = { agentId, startedAt: now };
      if (ev.parentAgentId) rec.parentAgentId = ev.parentAgentId;
      if (ev.agentType) rec.agentType = ev.agentType;
      session.agents.push(rec);
      session.counters.concurrentSubagents = session.agents.filter((a) => !a.endedAt).length;
      session.counters.delegationDepth = Math.max(
        session.counters.delegationDepth,
        depthOf(session, agentId),
      );
      writeSession(root, session);
      ledger('subagent.start', {
        agentId,
        parentAgentId: ev.parentAgentId ?? null,
        agentType: ev.agentType ?? null,
        depth: depthOf(session, agentId),
      });
      const budgets = budgetsFor(cache, rt.pin.profile, session);
      const bv = evaluateBudget(budgets, countersOf(session, now));
      const decision: HookDecision = { event: ev.event, action: 'continue', exitCode: 0 };
      if (bv.action !== 'CONTINUE') {
        decision.context = `EGO: subagent budget exceeded (${bv.breaches.map((b) => `${b.dimension} ${b.observed} > ${b.limit}`).join(', ')}); further governed tool calls are ${bv.action === 'BLOCK' ? 'blocked' : 'escalated'} until a human extends the budget.`;
        decision.userMessage = decision.context;
      } else
        decision.context =
          'EGO: subagents inherit the parent task, profile, mode, grants and budgets and can never widen them. Subagent identifiers are trace identity, never authority.';
      return decision;
    }
    case 'SubagentStop': {
      const a = session.agents.find((x) => x.agentId === ev.agentId && !x.endedAt);
      if (a) a.endedAt = now;
      session.counters.concurrentSubagents = session.agents.filter((x) => !x.endedAt).length;
      writeSession(root, session);
      ledger('subagent.stop', { agentId: ev.agentId ?? null });
      return { event: ev.event, action: 'continue', exitCode: 0 };
    }
    case 'Stop': {
      writeSession(root, session);
      if (ev.stopHookActive) return { event: ev.event, action: 'continue', exitCode: 0 };
      // Phase 1: the completion gate checks the budget state and the transcript-independent facts it owns; the task
      // gate (held scopes, unresolved conflicts, receipt) lands in phase 2 and extends this switch.
      if (session.budgetState) {
        ledger('stop.budget-breached', { breaches: session.budgetState.breaches });
        return {
          event: ev.event,
          action: 'continue',
          exitCode: 0,
          userMessage: `EGO: this session ended under a budget breach (${session.budgetState.breaches.map((b) => b.dimension).join(', ')}); the receipt must say so.`,
        };
      }
      ledger('stop', {});
      return { event: ev.event, action: 'continue', exitCode: 0 };
    }
    case 'SessionEnd': {
      session.endedAt = now;
      session.counters.concurrentSubagents = 0;
      writeSession(root, session);
      ledger('session.end', {});
      return { event: ev.event, action: 'continue', exitCode: 0 };
    }
  }
}

function depthOf(session: SessionRecord, agentId: string): number {
  let depth = 1;
  let cur = session.agents.find((a) => a.agentId === agentId);
  const seen = new Set<string>();
  while (cur && cur.parentAgentId && !seen.has(cur.agentId)) {
    seen.add(cur.agentId);
    const parent = session.agents.find((a) => a.agentId === cur!.parentAgentId);
    if (!parent) break;
    depth += 1;
    cur = parent;
  }
  return depth;
}

function summarizeInput(tool: string, input: Record<string, unknown>, cpRoot: string): string {
  const raw =
    typeof input['command'] === 'string'
      ? input['command']
      : typeof input['file_path'] === 'string'
        ? input['file_path']
        : typeof input['url'] === 'string'
          ? input['url']
          : typeof input['pattern'] === 'string'
            ? input['pattern']
            : JSON.stringify(input).slice(0, 200);
  return `${tool}: ${redactForLedger(raw.slice(0, 400), cpRoot)}`;
}

function toolFailed(response: unknown): boolean {
  if (!response || typeof response !== 'object') return false;
  const r = response as Record<string, unknown>;
  if (r['is_error'] === true || r['isError'] === true) return true;
  if (typeof r['exit_code'] === 'number' && r['exit_code'] !== 0) return true;
  if (typeof r['exitCode'] === 'number' && r['exitCode'] !== 0) return true;
  return false;
}

/** Frames untrusted text for injection into model context; exported for adapters that relay forge or web content. */
export function frameUntrusted(text: string, source: Parameters<typeof provenance>[0], ref: string): string {
  return frameForContext(text, provenance(source, ref));
}

export function projectHasHooks(projectRoot: string): boolean {
  return isFile(join(projectRoot, '.harness', 'hooks', 'ego-hook.sh'));
}

export { readPin };
