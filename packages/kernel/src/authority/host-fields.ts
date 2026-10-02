// THE FIELDS OF A SHELL TOOL CALL THAT CHANGE NOTHING (closure audit 2026-10-02, wave 6, PA-17 and PA-04).
//
// A host's shell tool carries more than the command: a description for the person, a timeout, a flag that runs the call in the background -
// and fields that change WHAT THE HOST DOES with the command. Claude Code's `dangerouslyDisableSandbox`, Codex's `with_escalated_permissions`
// and `sandbox_permissions: "require_escalated"` ask the host to run the call outside the sandbox it normally runs in; a `shell` that names
// another program, an `env` that adds `LD_PRELOAD`, a working directory the adapter did not read all change which program runs, in which
// directory, with what. The evaluator judged the command and said `allow`, which the host renders as the end of its own question - and an
// escalation request was granted by the hook that was supposed to be asking about it.
//
// The rule is the one the rest of the kernel keeps: accept what is KNOWN HARMLESS, ask about the rest. Every field of a shell tool call that is
// not in this table asks, whatever its value; a field that is in the table asks unless its value is the harmless one. The table is the
// complete list of what the kernel has read, so a host that ships a new field is asked about, not guessed at.

/** A field the host sends with a shell command that has no effect on the command itself, and the values for which that holds. */
const INERT: Readonly<Record<string, (v: unknown) => boolean>> = {
  // for the person who reads the prompt
  description: (v) => typeof v === 'string',
  justification: (v) => typeof v === 'string',
  // how long and how much
  timeout: (v) => typeof v === 'number',
  timeout_ms: (v) => typeof v === 'number',
  yield_time_ms: (v) => typeof v === 'number',
  max_output_tokens: (v) => typeof v === 'number',
  // whether the call waits
  run_in_background: (v) => typeof v === 'boolean',
  // Codex: a login shell is the host's wrapper, which the adapter has already read when it built the command line
  login: (v) => typeof v === 'boolean',
  // Codex: the approval policy's own prefix rule for an escalated call (harmless where the call is not escalated)
  prefix_rule: (v) => Array.isArray(v) && v.every((x) => typeof x === 'string'),
  // the requests to leave the sandbox: harmless only as the default they are not
  dangerouslyDisableSandbox: (v) => v === false,
  with_escalated_permissions: (v) => v === false,
  sandbox_permissions: (v) => v === 'use_default',
};

/** The fields of a shell tool call that are neither its command nor known to be inert: what the host might act on that nobody read. */
export function unreadShellFields(input: Readonly<Record<string, unknown>>): string[] {
  return Object.keys(input).filter((k) => k !== 'command' && !(INERT[k]?.(input[k]) ?? false));
}
