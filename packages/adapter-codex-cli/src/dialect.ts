// codex-cli adapter. Hook semantics are UNVERIFIED until the conformance suite runs on a machine with Codex CLI
// installed (K4, M10): this dialect emits the neutral JSON shape and fails closed on anything it cannot parse.
import { join } from 'node:path';
import type { HookEvent, HookDecision, HookEventName } from '../../kernel/src/hooks/events.ts';
import { checkPayloadEvent, decisionReason, isHookEventName } from '../../kernel/src/hooks/events.ts';
import { writeAtomic } from '../../kernel/src/util/fs.ts';
import { argvToCommandLine, shellQuote } from '../../kernel/src/util/shell-quote.ts';

export const HOST_ID = 'codex-cli' as const;

export function parseCodexEvent(
  eventName: string,
  payload: Record<string, unknown>,
  cwdFallback: string,
): HookEvent {
  // THE REGISTERED EVENT STANDS, whichever key the payload names an event in (events.ts: checkPayloadEvent)
  checkPayloadEvent(eventName, payload['hook_event_name']);
  checkPayloadEvent(eventName, payload['event']);
  const name = eventName;
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
    const name = normalizeCodexTool(toolName);
    const input =
      name === 'Bash'
        ? shellInput(inputRaw)
        : inputRaw && typeof inputRaw === 'object'
          ? (inputRaw as Record<string, unknown>)
          : typeof inputRaw === 'string'
            ? { command: inputRaw }
            : {};
    ev.tool = { name, input };
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

/**
 * Codex runs a shell STRING as `["bash","-lc",<script>]`: that argv is how it spells "run this script", it is the HOST's
 * wrapper rather than anything the model chose, and judging it as the command `bash -lc '…'` (an unknown head, ASK)
 * would refuse EVERY real call while adding nothing, because the kernel reads the script inside it either way. The
 * exact three-element form (a shell, `-c`/`-lc`/`-cl`, one script) is therefore judged as the script. Any other shape —
 * a fourth element that becomes `$0`, `-i`, `-x`, `--rcfile` — keeps its wrapper and is judged as written.
 */
const HOST_SHELLS = new Set(['bash', 'sh', 'zsh', 'dash']);
function hostShellScript(argv: unknown): string | null {
  if (!Array.isArray(argv) || argv.length !== 3 || !argv.every((a) => typeof a === 'string')) return null;
  const [shell, flag, script] = argv as [string, string, string];
  return HOST_SHELLS.has(shell.replace(/^.*\//, '')) && (flag === '-c' || flag === '-lc' || flag === '-cl')
    ? script
    : null;
}
function commandLine(argv: unknown): string | null {
  return hostShellScript(argv) ?? argvToCommandLine(argv);
}

/**
 * THE COMMAND A CODEX SHELL CALL WILL RUN, AS THE STRING THE KERNEL CLASSIFIES. Codex does not send a string: its `shell`
 * tool sends an argv array (`["bash","-lc","git push"]`), often inside a JSON text in `arguments`, and `exec_command`
 * sends `cmd`. Wrapping that JSON as the command made every real call an unknown head — refused, which is safe and
 * unusable (audit 2026-10-01, item 13). The argv is therefore turned into the shell-quoted line that executes as that
 * very vector, so `["ls","-la"]` is judged as `ls -la`, `["git","push"]` as `git push`, and `["bash","-lc","git push"]`
 * as the script it runs; a `workdir` becomes the `cd` it is, so relative paths are judged against the directory the
 * command really runs in. Anything this does not recognise is left exactly as it arrived, and the kernel asks about a
 * call it cannot read.
 */
function shellInput(raw: unknown): Record<string, unknown> {
  let value = raw;
  if (typeof value === 'string' && /^\s*[[{]/.test(value)) {
    try {
      value = JSON.parse(value);
    } catch {
      /* not JSON after all (`[ -f x ] && ls`, `{ ls; }`): it is the command text itself */
    }
  }
  if (typeof value === 'string') return { command: value };
  if (Array.isArray(value)) {
    const line = commandLine(value);
    return line === null ? {} : { command: line };
  }
  if (!value || typeof value !== 'object') return {};
  const obj = { ...(value as Record<string, unknown>) };
  for (const key of ['command', 'cmd', 'argv']) {
    if (!(key in obj)) continue;
    const v = obj[key];
    const line = typeof v === 'string' ? v : commandLine(v);
    const workdir = obj['workdir'];
    if (line === null || (workdir !== undefined && (typeof workdir !== 'string' || workdir === ''))) return obj;
    delete obj[key];
    delete obj['workdir'];
    return { ...obj, command: typeof workdir === 'string' ? `cd ${shellQuote(workdir)} && ${line}` : line };
  }
  return obj;
}

/** Codex tool names map onto the neutral vocabulary the kernel evaluates (shell → Bash, apply_patch stays). */
export function normalizeCodexTool(name: string): string {
  if (
    name === 'shell' ||
    name === 'local_shell' ||
    name === 'exec_command' ||
    name === 'shell_command' ||
    name === 'container.exec'
  )
    return 'Bash';
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
        `${decisionReason(d)}${d.action === 'ask' ? ' [codex-cli: ASK is refused until conformance verifies the ask channel; a human may run the operation from their own terminal]' : ''}`;
      exitCode = 2;
    }
  } else if (d.action === 'block' || d.action === 'deny') {
    out['decision'] = 'block';
    out['reason'] = decisionReason(d);
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
