// Neutral hook event model. Adapters translate host payloads into these events and kernel decisions back into host
// output; the kernel never sees host-specific shapes.
import type { HostId } from '../hosts/matrix.ts';
import type { ReasonCode } from '../authority/reasons.ts';

export const HOOK_EVENTS = [
  'SessionStart',
  'UserPromptSubmit',
  'PreToolUse',
  'PostToolUse',
  'SubagentStart',
  'SubagentStop',
  'Stop',
  'SessionEnd',
] as const;
export type HookEventName = (typeof HOOK_EVENTS)[number];

export interface HookEvent {
  host: HostId;
  event: HookEventName;
  sessionId: string;
  cwd: string;
  agentId?: string;
  parentAgentId?: string;
  agentType?: string;
  transcriptPath?: string;
  permissionMode?: string;
  hostPid?: number;
  tool?: { name: string; input: Record<string, unknown>; response?: unknown; useId?: string };
  prompt?: string;
  /** SessionStart: startup | resume | clear | compact */
  source?: string;
  stopHookActive?: boolean;
  /** original payload, for the ledger (redacted before storage) */
  raw: Record<string, unknown>;
}

export type HookAction = 'allow' | 'ask' | 'deny' | 'block' | 'continue';

export interface HookDecision {
  event: HookEventName;
  action: HookAction;
  reason?: string;
  /** WHY the action is not an allow, as a typed code (issue #16 section 10). The reason text carries it too; a host
   *  that renders `reason` through `decisionReason` shows it even when the text was written without it. */
  code?: ReasonCode;
  /** additional context for the model (SessionStart, UserPromptSubmit, PostToolUse) */
  context?: string;
  /** message on the host's user-visible channel */
  userMessage?: string;
  /** process exit code the adapter must use (0 = decision carried in output, 2 = fail closed) */
  exitCode: 0 | 2;
  /** structured details for the ledger and tests */
  details?: Record<string, unknown>;
}

export function isHookEventName(v: string): v is HookEventName {
  return (HOOK_EVENTS as readonly string[]).includes(v);
}

/**
 * THE REASON A HOST SHOWS, WITH ITS CODE. Both host dialects render a decision's reason into their own channel, and
 * each used to read `d.reason` itself; a code that lived only in the text the kernel happened to write would reach the
 * human only when every writer remembered it. This is the one reader: the code is in what the host shows, once.
 */
export function decisionReason(d: Pick<HookDecision, 'reason' | 'code'>): string {
  const reason = d.reason ?? '';
  if (!d.code || reason.includes(d.code)) return reason;
  return reason ? `${d.code}: ${reason}` : d.code;
}
