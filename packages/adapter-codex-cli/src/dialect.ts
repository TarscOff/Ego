// codex-cli adapter. Hook semantics are UNVERIFIED until the conformance suite runs on a machine with Codex CLI
// installed (K4, M10): this dialect emits the neutral JSON shape and fails closed on anything it cannot parse.
import { join } from 'node:path';
import type { HookEvent, HookDecision, HookEventName } from '../../kernel/src/hooks/events.ts';
import { isHookEventName } from '../../kernel/src/hooks/events.ts';
import { writeAtomic } from '../../kernel/src/util/fs.ts';

export const HOST_ID = 'codex-cli' as const;

export function parseCodexEvent(
  eventName: string,
  payload: Record<string, unknown>,
  cwdFallback: string,
): HookEvent {
  const name =
    typeof payload['hook_event_name'] === 'string'
      ? payload['hook_event_name']
      : typeof payload['event'] === 'string'
        ? payload['event']
        : eventName;
  if (!isHookEventName(name)) throw new Error(`unknown hook event "${name}"`);
  const ev: HookEvent = {
    host: HOST_ID,
    event: name as HookEventName,
    sessionId: firstString(payload, ['session_id', 'sessionId', 'thread_id']) ?? 'unknown-session',
    cwd: firstString(payload, ['cwd']) ?? cwdFallback,
    raw: payload,
  };
  const agent = firstString(payload, ['agent_id', 'agentId']);
  if (agent) ev.agentId = agent;
  const toolName = firstString(payload, ['tool_name', 'toolName', 'tool']);
  if (toolName) {
    const inputRaw = payload['tool_input'] ?? payload['input'] ?? payload['arguments'];
    const input =
      inputRaw && typeof inputRaw === 'object'
        ? (inputRaw as Record<string, unknown>)
        : typeof inputRaw === 'string'
          ? { command: inputRaw }
          : {};
    ev.tool = { name: normalizeCodexTool(toolName), input };
    if ('tool_response' in payload) ev.tool.response = payload['tool_response'];
    if ('output' in payload) ev.tool.response = payload['output'];
  }
  const prompt = firstString(payload, ['prompt', 'message']);
  if (prompt) ev.prompt = prompt;
  const source = firstString(payload, ['source', 'reason', 'trigger']);
  if (source) ev.source = source;
  if (payload['stop_hook_active'] === true) ev.stopHookActive = true;
  return ev;
}

function firstString(p: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) if (typeof p[k] === 'string' && p[k]) return p[k] as string;
  return undefined;
}

/** Codex tool names map onto the neutral vocabulary the kernel evaluates (shell → Bash, apply_patch stays). */
export function normalizeCodexTool(name: string): string {
  if (name === 'shell' || name === 'local_shell' || name === 'exec_command') return 'Bash';
  if (name === 'read_file' || name === 'view_image') return 'Read';
  if (name === 'write_file') return 'Write';
  return name;
}

/**
 * Until the conformance suite verifies Codex's JSON decision channel (K4, M10), nothing that must stop an action may
 * depend on it: DENY, ASK and every block exit 2, the one code all hook runners treat as a blocking error. ASK is
 * therefore a refusal on codex-cli, stated in the reason, never a silent allow.
 */
export function renderCodexOutput(d: HookDecision): { stdout: string; exitCode: number } {
  const out: Record<string, unknown> = {};
  let exitCode = d.exitCode;
  if (d.event === 'PreToolUse') {
    if (d.action === 'allow') out['decision'] = 'allow';
    else {
      out['decision'] = 'deny';
      out['reason'] =
        `${d.reason ?? ''}${d.action === 'ask' ? ' [codex-cli: ASK is refused until conformance verifies the ask channel; a human may run the operation from their own terminal]' : ''}`;
      exitCode = 2;
    }
  } else if (d.action === 'block' || d.action === 'deny') {
    out['decision'] = 'block';
    out['reason'] = d.reason ?? '';
    exitCode = 2;
  }
  if (d.context) out['additionalContext'] = d.context;
  if (d.userMessage) out['systemMessage'] = d.userMessage;
  return { stdout: JSON.stringify(out), exitCode };
}

export const CODEX_HOOK_EVENTS: HookEventName[] = [
  'SessionStart',
  'UserPromptSubmit',
  'PreToolUse',
  'PostToolUse',
  'Stop',
  'SessionEnd',
];

export function writeCodexHooks(projectRoot: string): { path: string; content: string } {
  const path = join(projectRoot, '.codex', 'hooks.json');
  const hooks: Record<string, unknown[]> = {};
  // the command finds the shim from the repository root and fails closed (exit 2) when the shim itself is missing
  const command = (ev: HookEventName) =>
    `sh -c 'f="$(git rev-parse --show-toplevel 2>/dev/null)/.harness/hooks/ego-hook.sh"; [ -f "$f" ] || { echo "EGO: hook shim missing; failing closed" >&2; exit 2; }; sh "$f" codex-cli ${ev}'`;
  for (const ev of CODEX_HOOK_EVENTS)
    hooks[ev] = [{ matcher: '', hooks: [{ type: 'command', command: command(ev), timeout: 30 }] }];
  const content =
    JSON.stringify(
      { _generated: 'by harness; do not edit. Hook semantics UNVERIFIED until conformance (K4).', hooks },
      null,
      2,
    ) + '\n';
  writeAtomic(path, content);
  return { path, content };
}
