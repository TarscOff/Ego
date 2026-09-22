// claude-code adapter: translates Claude Code hook payloads to neutral events and neutral decisions to Claude Code
// hook output. UX only: no policy, permission, task, decision or secret logic lives here.
import { join } from 'node:path';
import type { HookEvent, HookDecision, HookEventName } from '../../kernel/src/hooks/events.ts';
import { isHookEventName } from '../../kernel/src/hooks/events.ts';
import { readJsonIfExists, writeAtomic, ensureDir } from '../../kernel/src/util/fs.ts';

export const HOST_ID = 'claude-code' as const;

export function parseClaudeCodeEvent(
  eventName: string,
  payload: Record<string, unknown>,
  env: NodeJS.ProcessEnv,
  cwdFallback: string,
): HookEvent {
  const name = typeof payload['hook_event_name'] === 'string' ? payload['hook_event_name'] : eventName;
  if (!isHookEventName(name)) throw new Error(`unknown hook event "${name}"`);
  const ev: HookEvent = {
    host: HOST_ID,
    event: name as HookEventName,
    sessionId:
      typeof payload['session_id'] === 'string' && payload['session_id']
        ? payload['session_id']
        : 'unknown-session',
    cwd: typeof payload['cwd'] === 'string' && payload['cwd'] ? payload['cwd'] : cwdFallback,
    raw: payload,
  };
  if (typeof payload['agent_id'] === 'string') ev.agentId = payload['agent_id'];
  if (typeof payload['parent_agent_id'] === 'string') ev.parentAgentId = payload['parent_agent_id'];
  if (typeof payload['agent_type'] === 'string') ev.agentType = payload['agent_type'];
  if (typeof payload['transcript_path'] === 'string') ev.transcriptPath = payload['transcript_path'];
  if (typeof payload['permission_mode'] === 'string') ev.permissionMode = payload['permission_mode'];
  const pid = env['CLAUDE_PID'] ? Number(env['CLAUDE_PID']) : NaN;
  if (Number.isFinite(pid)) ev.hostPid = pid;
  else if (process.ppid) ev.hostPid = process.ppid;
  if (typeof payload['tool_name'] === 'string') {
    const input =
      payload['tool_input'] && typeof payload['tool_input'] === 'object'
        ? (payload['tool_input'] as Record<string, unknown>)
        : {};
    ev.tool = { name: payload['tool_name'], input };
    if ('tool_response' in payload) ev.tool.response = payload['tool_response'];
    if (typeof payload['tool_use_id'] === 'string') ev.tool.useId = payload['tool_use_id'];
  }
  if (typeof payload['prompt'] === 'string') ev.prompt = payload['prompt'];
  if (typeof payload['source'] === 'string') ev.source = payload['source'];
  if (payload['stop_hook_active'] === true) ev.stopHookActive = true;
  return ev;
}

/** Renders a neutral decision as Claude Code hook JSON (stdout) plus the exit code. */
export function renderClaudeCodeOutput(d: HookDecision): { stdout: string; exitCode: number } {
  const out: Record<string, unknown> = {};
  if (d.userMessage) out['systemMessage'] = d.userMessage;
  switch (d.event) {
    case 'PreToolUse': {
      const permissionDecision = d.action === 'allow' ? 'allow' : d.action === 'ask' ? 'ask' : 'deny';
      out['hookSpecificOutput'] = {
        hookEventName: 'PreToolUse',
        permissionDecision,
        permissionDecisionReason: d.reason ?? '',
      };
      break;
    }
    case 'UserPromptSubmit': {
      if (d.action === 'block' || d.action === 'deny') {
        out['decision'] = 'block';
        out['reason'] = d.reason ?? '';
      } else if (d.context)
        out['hookSpecificOutput'] = { hookEventName: 'UserPromptSubmit', additionalContext: d.context };
      break;
    }
    case 'SessionStart': {
      if (d.context)
        out['hookSpecificOutput'] = { hookEventName: 'SessionStart', additionalContext: d.context };
      break;
    }
    case 'PostToolUse': {
      if (d.action === 'block' || d.action === 'deny') {
        out['decision'] = 'block';
        out['reason'] = d.reason ?? '';
      } else if (d.context)
        out['hookSpecificOutput'] = { hookEventName: 'PostToolUse', additionalContext: d.context };
      break;
    }
    case 'Stop':
    case 'SubagentStop': {
      if (d.action === 'block' || d.action === 'deny') {
        out['decision'] = 'block';
        out['reason'] = d.reason ?? '';
      }
      break;
    }
    case 'SubagentStart':
    case 'SessionEnd': {
      if (d.context) out['hookSpecificOutput'] = { hookEventName: d.event, additionalContext: d.context };
      break;
    }
  }
  return { stdout: JSON.stringify(out), exitCode: d.exitCode };
}

// ---------------------------------------------------------------------------------------------------------------
// Generated host configuration: .claude/settings.json hooks (merged, other keys preserved), slash commands.
// ---------------------------------------------------------------------------------------------------------------

export const CLAUDE_HOOK_EVENTS: HookEventName[] = [
  'SessionStart',
  'UserPromptSubmit',
  'PreToolUse',
  'PostToolUse',
  'SubagentStart',
  'SubagentStop',
  'Stop',
  'SessionEnd',
];

export function hookCommand(event: HookEventName): string {
  // a missing shim must block (exit 2), not fail open with sh's 127
  return `sh -c 'f="$CLAUDE_PROJECT_DIR/.harness/hooks/ego-hook.sh"; [ -f "$f" ] || { echo "EGO: hook shim missing; failing closed" >&2; exit 2; }; sh "$f" claude-code ${event}'`;
}

type HookGroup = { matcher?: string; hooks: Array<{ type: string; command: string; timeout?: number }> };

export function mergeClaudeSettings(existing: Record<string, unknown> | null): Record<string, unknown> {
  const settings: Record<string, unknown> = existing ? { ...existing } : {};
  const hooks: Record<string, HookGroup[]> =
    settings['hooks'] && typeof settings['hooks'] === 'object'
      ? { ...(settings['hooks'] as Record<string, HookGroup[]>) }
      : {};
  for (const ev of CLAUDE_HOOK_EVENTS) {
    const groups = Array.isArray(hooks[ev])
      ? hooks[ev]!.filter(
          (g) => !g.hooks?.some((h) => typeof h.command === 'string' && h.command.includes('ego-hook.sh')),
        )
      : [];
    const group: HookGroup = { hooks: [{ type: 'command', command: hookCommand(ev), timeout: 30 }] };
    if (ev === 'PreToolUse' || ev === 'PostToolUse') group.matcher = '';
    // EGO's hook runs first so a deny is never preceded by a foreign allow
    hooks[ev] = [group, ...groups];
  }
  settings['hooks'] = hooks;
  return settings;
}

export function writeClaudeSettings(projectRoot: string): { path: string; content: string } {
  const path = join(projectRoot, '.claude', 'settings.json');
  const merged = mergeClaudeSettings(readJsonIfExists<Record<string, unknown>>(path));
  const content = JSON.stringify(merged, null, 2) + '\n';
  writeAtomic(path, content);
  return { path, content };
}

export const SLASH_COMMANDS: Array<{ name: string; description: string; run: string }> = [
  {
    name: 'harness',
    description: 'EGO home: where you are, what you can do, next actions',
    run: 'ego help',
  },
  { name: 'harness-status', description: 'Current task, session, grants, budgets', run: 'ego status' },
  {
    name: 'harness-doctor',
    description: 'EGO health: runtime identity, trust, hooks, freshness',
    run: 'ego doctor',
  },
  { name: 'harness-issues', description: 'Open issues for this repository', run: 'harness issue list' },
  {
    name: 'harness-take',
    description: 'Take the next issue (or a given one) as a task',
    run: 'harness issue take $ARGUMENTS',
  },
  { name: 'harness-resume', description: 'Resume the durable task', run: 'harness task resume' },
  {
    name: 'harness-context',
    description: 'What is loaded in context and why',
    run: 'ego context explain',
  },
  { name: 'harness-decisions', description: 'Human decisions waiting', run: 'harness decision list' },
  { name: 'harness-grill', description: 'Grill the current work', run: 'harness grill $ARGUMENTS' },
];

export function writeSlashCommands(projectRoot: string): string[] {
  const dir = join(projectRoot, '.claude', 'commands');
  ensureDir(dir);
  const written: string[] = [];
  for (const c of SLASH_COMMANDS) {
    const path = join(dir, `${c.name}.md`);
    const body = `---
description: ${c.description}
allowed-tools: Bash(harness:*)
---
<!-- generated by harness; do not edit -->
Run \`${c.run}\` with the Bash tool and relay its output to the user verbatim, then follow its "what next" line.
Do not paraphrase verdicts, identities or hashes. If the command reports UNAVAILABLE, say so plainly.
`;
    writeAtomic(path, body);
    written.push(path);
  }
  return written;
}
