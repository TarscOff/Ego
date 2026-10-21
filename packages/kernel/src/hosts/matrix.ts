// Host capability matrix (alignment item 2, Q32, Q90). Keyed by host identifier, never by model name. A status of
// UNAVAILABLE or UNVERIFIED is honest; fake parity is not.
//
// WHAT A STATUS IS. Every status here is a DECLARATION EGO authored, read as "what EGO can claim on this host today",
// not "what the host might offer": a host with a sandbox EGO never detects is UNAVAILABLE for the sandbox control.
// Nothing is measured against a running host before the phase-6 conformance suite; `verifiedBy` names the check that
// will do it.
//
// WHO READS IT. `ego doctor` reads exactly one key from this table, `blocking-pre-tool-hook` (the hooks section).
// `hostCapability` and `hostSupports` have no production caller. The containment controls that doctor reports come
// from control-plane/containment/controls.md, which carries its own per-host statuses; for every id both files carry
// the statuses must be equal, and packages/kernel/test/closure-docs.test.ts fails when they differ.
import type { SupportStatus } from '../control-plane/types.ts';

export const HOST_IDS = ['claude-code', 'codex-cli'] as const;
export type HostId = (typeof HOST_IDS)[number];

export const HOST_CAPABILITY_KEYS = [
  'blocking-pre-tool-hook',
  'post-tool-hook',
  'session-start-hook',
  'stop-hook',
  'user-prompt-hook',
  'subagent-lifecycle-hooks',
  'system-message-injection',
  'per-call-agent-identity',
  'host-process-identity',
  'blocking-in-every-permission-mode',
  'managed-settings-lock',
  'sandboxed-command-execution',
  'network-egress-control',
  'model-identity-reporting',
  'token-usage-reporting',
  'cost-reporting',
  'mcp-server-configuration',
  'worktree-isolation',
] as const;
export type HostCapabilityKey = (typeof HOST_CAPABILITY_KEYS)[number];

export interface HostCapability {
  status: SupportStatus;
  /** how EGO uses it, or why it is not available */
  note: string;
  /** conformance check identifier that verifies this entry; UNVERIFIED entries name the check that will */
  verifiedBy?: string;
}

export interface HostProfile {
  id: HostId;
  displayName: string;
  /** host version range this matrix was verified against; empty when never verified */
  verifiedVersions: string;
  capabilities: Record<HostCapabilityKey, HostCapability>;
}

export const HOST_MATRIX: Record<HostId, HostProfile> = {
  'claude-code': {
    id: 'claude-code',
    displayName: 'Claude Code',
    verifiedVersions: '',
    capabilities: {
      'blocking-pre-tool-hook': {
        status: 'SUPPORTED',
        note: 'PreToolUse exit 2 / permissionDecision deny blocks the call',
        verifiedBy: 'conformance.hook.pretooluse.block',
      },
      'post-tool-hook': {
        status: 'SUPPORTED',
        note: 'PostToolUse arrives after the call; EGO counts failed steps against the retry budget and writes a ledger line (tool, one-line summary, failed). It inspects no path and detects no write: a shell write is judged before it runs, never observed after',
        verifiedBy: 'conformance.hook.posttooluse',
      },
      'session-start-hook': {
        status: 'SUPPORTED',
        note: 'SessionStart injects the governance summary, active grants and corrections, and a resume reminder',
        verifiedBy: 'conformance.hook.sessionstart',
      },
      'stop-hook': {
        status: 'SUPPORTED',
        note: 'Stop runs and records the stop and any budget breach in the ledger; it never blocks (the completion gate is phase 2)',
        verifiedBy: 'conformance.hook.stop',
      },
      'user-prompt-hook': {
        status: 'SUPPORTED',
        note: 'UserPromptSubmit recognises grants, corrections and slash commands',
        verifiedBy: 'conformance.hook.userprompt',
      },
      'subagent-lifecycle-hooks': {
        status: 'SUPPORTED',
        note: 'SubagentStart / SubagentStop carry the delegation trace',
        verifiedBy: 'conformance.hook.subagent',
      },
      'system-message-injection': {
        status: 'SUPPORTED',
        note: 'systemMessage field on hook output',
        verifiedBy: 'conformance.hook.systemmessage',
      },
      'per-call-agent-identity': {
        status: 'SUPPORTED',
        note: 'agent_id on each hook payload (trace identity, never authority)',
        verifiedBy: 'conformance.hook.agentid',
      },
      'host-process-identity': {
        status: 'SUPPORTED',
        note: 'CLAUDE_PID is used to recognise the host; liveness of held scopes (phase 2) would use it',
        verifiedBy: 'conformance.host.pid',
      },
      'blocking-in-every-permission-mode': {
        status: 'SUPPORTED',
        note: 'hook denies apply in default, acceptEdits, plan and bypassPermissions',
        verifiedBy: 'conformance.hook.allmodes',
      },
      'managed-settings-lock': {
        status: 'UNVERIFIED',
        note: 'a host feature (the design names allowManagedHooksOnly and allowManagedPermissionRulesOnly); EGO does not install, read or verify a managed tier, so it cannot claim it',
        verifiedBy: 'conformance.host.managed',
      },
      'sandboxed-command-execution': {
        status: 'UNAVAILABLE',
        note: 'not in force: EGO neither establishes, requires nor detects a sandbox, whatever the host offers (issue #26)',
        verifiedBy: 'conformance.host.sandbox',
      },
      'network-egress-control': {
        status: 'PARTIAL',
        note: 'no OS-level egress restriction; the classifier asks or denies the network clients and URLs it recognises (DENY in HIGH_ASSURANCE) and leaves git remotes, forge reads, registry reads and container runs open',
        verifiedBy: 'conformance.host.egress',
      },
      'model-identity-reporting': {
        status: 'UNVERIFIED',
        note: 'model name may appear in the session transcript; not relied upon',
        verifiedBy: 'conformance.host.model',
      },
      'token-usage-reporting': {
        status: 'UNVERIFIED',
        note: 'token budgets enforce only where the host reports usage',
        verifiedBy: 'conformance.host.tokens',
      },
      'cost-reporting': {
        status: 'UNVERIFIED',
        note: 'cost budgets enforce only where the host reports cost',
        verifiedBy: 'conformance.host.cost',
      },
      'mcp-server-configuration': {
        status: 'PARTIAL',
        note: 'the host can declare MCP servers, but EGO resolves no trust for them yet: .harness/mcp-trust.md is written by `ego init` and read by nothing, so every mcp__ tool is mcp.unknown (DENY) until the resolver lands (phase 2, issue #10)',
        verifiedBy: 'conformance.host.mcp',
      },
      'worktree-isolation': {
        status: 'UNAVAILABLE',
        note: 'isolation of Git state, not containment, and not implemented: the host can open worktrees, but EGO neither creates nor requires one and nothing refuses a second live session in a checkout (held scopes are phase 2)',
        verifiedBy: 'conformance.host.worktree',
      },
    },
  },
  'codex-cli': {
    id: 'codex-cli',
    displayName: 'Codex CLI',
    verifiedVersions: '',
    capabilities: {
      'blocking-pre-tool-hook': {
        status: 'UNVERIFIED',
        note: 'hooks exist; blocking semantics verified only by conformance. Until then the dialect exits 2 on every non-ALLOW verdict: ASK degrades to DENY on this host',
        verifiedBy: 'conformance.hook.pretooluse.block',
      },
      'post-tool-hook': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.hook.posttooluse',
      },
      'session-start-hook': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.hook.sessionstart',
      },
      'stop-hook': { status: 'UNVERIFIED', note: 'to verify', verifiedBy: 'conformance.hook.stop' },
      'user-prompt-hook': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.hook.userprompt',
      },
      'subagent-lifecycle-hooks': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.hook.subagent',
      },
      'system-message-injection': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.hook.systemmessage',
      },
      'per-call-agent-identity': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.hook.agentid',
      },
      'host-process-identity': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.host.pid',
      },
      'blocking-in-every-permission-mode': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.hook.allmodes',
      },
      'managed-settings-lock': {
        status: 'UNVERIFIED',
        note: 'requirements.toml candidate; to verify',
        verifiedBy: 'conformance.host.managed',
      },
      'sandboxed-command-execution': {
        status: 'UNVERIFIED',
        note: 'host sandbox exists; to verify',
        verifiedBy: 'conformance.host.sandbox',
      },
      'network-egress-control': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.host.egress',
      },
      'model-identity-reporting': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.host.model',
      },
      'token-usage-reporting': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.host.tokens',
      },
      'cost-reporting': { status: 'UNVERIFIED', note: 'to verify', verifiedBy: 'conformance.host.cost' },
      'mcp-server-configuration': {
        status: 'UNVERIFIED',
        note: 'to verify; whatever the host allows, EGO resolves no MCP trust yet and every mcp__ tool is mcp.unknown (DENY, exit 2 here) until the resolver lands (phase 2, issue #10)',
        verifiedBy: 'conformance.host.mcp',
      },
      'worktree-isolation': {
        status: 'UNVERIFIED',
        note: 'to verify',
        verifiedBy: 'conformance.host.worktree',
      },
    },
  },
};

export function hostCapability(host: HostId, key: HostCapabilityKey): HostCapability {
  return HOST_MATRIX[host].capabilities[key];
}

/** True when a profile requirement can be claimed on this host: only SUPPORTED counts; PARTIAL and UNVERIFIED never do. */
export function hostSupports(host: HostId, key: HostCapabilityKey): boolean {
  return hostCapability(host, key).status === 'SUPPORTED';
}

export function isHostId(v: string): v is HostId {
  return (HOST_IDS as readonly string[]).includes(v);
}
