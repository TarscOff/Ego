// Neutral hook event model. Adapters translate host payloads into these events and kernel decisions back into host
// output; the kernel never sees host-specific shapes.
import type { HostId } from '../hosts/matrix.ts';
import type { ReasonCode } from '../authority/reasons.ts';
import { terminalSafe } from '../util/shown-text.ts';

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
  tool?: {
    /** @untrusted the host's payload: a tool name is whatever the caller of the hook says it is */
    name: string;
    input: Record<string, unknown>;
    response?: unknown;
    useId?: string;
  };
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

/** The host's payload cannot be what the hook was registered for: a payload that names another event than the one this hook
 *  answers, or that is not an object. The CLI turns it into a coded refusal (exit 2), never into an event of the wrong kind that
 *  answers `{}` and evaluates no tool. */
export class HookPayloadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HookPayloadError';
  }
}

/** The event a payload names, when it names one in a way a string can: the registered event stands, and a payload that disagrees with it
 *  is refused. The payload is the host's, and the host is not the one deciding which question the kernel is being asked - an agent
 *  that could make a PreToolUse hook read `"hook_event_name":"Stop"` would have the tool call answered `{}` with exit 0 and
 *  nothing evaluated (closure audit 2026-10-02, RB-4). */
export function checkPayloadEvent(registered: string, named: unknown): void {
  if (typeof named === 'string' && named !== registered)
    throw new HookPayloadError(`the payload names the event "${named.slice(0, 64)}" but this hook is registered for "${registered}"`);
}

/**
 * THE REASON A HOST SHOWS, WITH ITS CODE. Both host dialects render a decision's reason into their own channel, and
 * each used to read `d.reason` itself; a code that lived only in the text the kernel happened to write would reach the
 * human only when every writer remembered it. This is the one reader: the code is in what the host shows, once.
 */
export function decisionReason(d: Pick<HookDecision, 'reason' | 'code'>): string {
  const reason = d.reason ?? '';
  if (!d.code || reason.includes(d.code)) return terminalSafe(reason);
  return terminalSafe(reason ? `${d.code}: ${reason}` : d.code);
}

/**
 * THE BOUNDARY OF THE CHANNEL (closure audit 2026-10-02, AUTH-6). Every text a host shows - the reason of a decision, the context the model
 * reads, the message the person reads - leaves the kernel through one of these three readers, and each turns every control character,
 * escape-sequence introducer and invisible formatting character into a visible escape (`terminalSafe`) whatever the text's origin: a
 * command line, a layer file, a repository name. The dialects call them and nothing else; a test reads the dialects for a raw `d.context`.
 */
export const decisionContext = (d: Pick<HookDecision, 'context'>): string | undefined =>
  d.context === undefined ? undefined : terminalSafe(d.context);
export const decisionMessage = (d: Pick<HookDecision, 'userMessage'>): string | undefined =>
  d.userMessage === undefined ? undefined : terminalSafe(d.userMessage);
