// codex-cli adapter. Hook semantics are UNVERIFIED until the conformance suite runs on a machine with Codex CLI
// installed (K4, M10): this dialect emits the neutral JSON shape and fails closed on anything it cannot parse.
import { join } from 'node:path';
import type { HookEvent, HookDecision, HookEventName } from '../../kernel/src/hooks/events.ts';
import { decisionReason, isHookEventName } from '../../kernel/src/hooks/events.ts';
import { writeAtomic } from '../../kernel/src/util/fs.ts';
import { argvToCommandLine, shellQuote } from '../../kernel/src/util/shell-quote.ts';

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
    const name = normalizeCodexTool(toolName);
    const input =
      name === 'Bash'
        ? shellInput(inputRaw)
        : inputRaw && typeof inputRaw === 'object'
          ? hostOperand(name, inputRaw as Record<string, unknown>)
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

/** Codex's own names for the operand of a tool the kernel models under another key: `apply_patch` sends the patch as `input`, `view_image` and
 *  `read_file` name the file `path`. An operand under a key the kernel does not read is a call it cannot judge (refused), and the call the host
 *  makes of it is not the one it asked about - so the key the host uses is mapped to the one the kernel judges, when the call carries no other. */
function hostOperand(name: string, input: Record<string, unknown>): Record<string, unknown> {
  const out = { ...input };
  if (name === 'apply_patch' && typeof out['input'] === 'string' && !('command' in out) && !('patch' in out)) {
    out['patch'] = out['input'];
    delete out['input'];
  }
  if ((name === 'Read' || name === 'Write') && typeof out['path'] === 'string' && !('file_path' in out)) {
    out['file_path'] = out['path'];
    delete out['path'];
  }
  return out;
}

/**
 * Codex runs a shell STRING as `["bash","-lc",<script>]`: that argv is how it spells "run this script", it is the HOST's
 * wrapper rather than anything the model chose, and judging it as the command `bash -lc '…'` (an unknown head, ASK)
 * would refuse EVERY real call while adding nothing, because the kernel reads the script inside it either way. The
 * exact three-element form (a shell, `-c`/`-lc`/`-cl`, one script) is therefore judged as the script. Any other shape —
 * a fourth element that becomes `$0`, `-i`, `-x`, `--rcfile` — keeps its wrapper and is judged as written.
 */
/** WHICH PROGRAM IS "THE HOST'S SHELL": a bare name the host finds on its PATH, or a path in the directories a system keeps its shells in. Matching
 *  the BASENAME made `./bash` - an executable of the repository, whose body is anything - the host's own wrapper, and the call was judged as
 *  the script after it while the host ran the file (PA-04). A path that is anywhere else is a program like any other, and is judged as one. */
const HOST_SHELL = /^(?:(?:\/(?:usr\/)?(?:local\/)?s?bin|\/opt\/homebrew\/bin)\/)?(?:bash|sh|zsh|dash)$/;
function hostShellScript(argv: unknown): string | null {
  if (!Array.isArray(argv) || argv.length !== 3 || !argv.every((a) => typeof a === 'string')) return null;
  const [shell, flag, script] = argv as [string, string, string];
  return HOST_SHELL.test(shell) && (flag === '-c' || flag === '-lc' || flag === '-cl') ? script : null;
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
  // A STRING THAT PARSES AS A JSON ARRAY is either the host's argv or a SCRIPT that happens to be valid JSON (PA-15), and the slot is the same.
  // The host that runs it as an argv runs no shell, so `$(...)` in an element is data; the host that hands it to a shell runs the substitution.
  // Both readings are judged when they can differ.
  let asText: string | null = null;
  if (typeof value === 'string' && /^\s*[[{]/.test(value)) {
    try {
      const parsed: unknown = JSON.parse(value);
      if (Array.isArray(parsed)) asText = value;
      value = parsed;
    } catch {
      /* not JSON after all (`[ -f x ] && ls`, `{ ls; }`): it is the command text itself */
    }
  }
  if (typeof value === 'string') return { command: value };
  if (Array.isArray(value)) {
    const line = commandLine(value);
    if (line === null) return {};
    return { command: asText !== null && value.some((a) => typeof a === 'string' && /[$`\\]/.test(a)) ? `${line}\n${asText}` : line };
  }
  if (!value || typeof value !== 'object') return {};
  const obj = { ...(value as Record<string, unknown>) };
  for (const key of ['command', 'cmd', 'argv']) {
    if (!(key in obj)) continue;
    const v = obj[key];
    // `exec_command` names the program that interprets `cmd`: a shell of its own choosing (`shell: "./bash"`), a login shell unless it says not
    const shell = key === 'cmd' && typeof v === 'string' && typeof obj['shell'] === 'string' && obj['shell'] !== '' ? obj['shell'] : null;
    const line = shell !== null ? commandLine([shell, obj['login'] === false ? '-c' : '-lc', v as string]) : typeof v === 'string' ? v : commandLine(v);
    // WHERE THE COMMAND RUNS: `workdir` and the other spellings of it become the `cd` they are, each one that is present (the host may honour any
    // of them, and they are all judged); a value that is not a plain string is not folded and stays beside the command, where the kernel asks
    const dirKeys = ['workdir', 'working_directory', 'cwd', 'dir'].filter((k) => k in obj);
    if (line === null || dirKeys.some((k) => typeof obj[k] !== 'string' || obj[k] === '')) return obj;
    const dirs = dirKeys.map((k) => obj[k] as string);
    // THE ENVIRONMENT it runs with: each pair is an `export` in front of the command, so an `LD_PRELOAD` or a `PATH` is judged as the injection it is
    let command = line;
    const env = obj['env'];
    if (env !== undefined) {
      const pairs = env !== null && typeof env === 'object' && !Array.isArray(env) ? Object.entries(env as Record<string, unknown>) : null;
      if (pairs === null || pairs.some(([k, x]) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) || typeof x !== 'string')) return obj;
      if (pairs.length > 0) command = `${pairs.map(([k, x]) => `export ${k}=${shellQuote(x as string)}`).join('; ')}; ${line}`;
    }
    for (const k of [key, 'shell', 'login', 'env', ...dirKeys]) delete obj[k];
    return { ...obj, command: dirs.length > 0 ? dirs.map((d) => `cd ${shellQuote(d)} && ${command}`).join('\n') : command };
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
