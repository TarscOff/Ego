// Host capability matrix (alignment item 2, Q32, Q90). Keyed by host identifier, never by model name. A status of
// UNAVAILABLE or UNVERIFIED is honest; fake parity is not. `doctor` renders this table for the active host and marks
// every profile requirement that depends on an UNVERIFIED capability as NOT SATISFIED until conformance verifies it.
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
        note: 'PostToolUse observes Bash writes after execution (detect, not prevent)',
        verifiedBy: 'conformance.hook.posttooluse',
      },
      'session-start-hook': {
        status: 'SUPPORTED',
        note: 'SessionStart injects the resume context',
        verifiedBy: 'conformance.hook.sessionstart',
      },
      'stop-hook': {
        status: 'SUPPORTED',
        note: 'Stop runs the completion gate',
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
        note: 'CLAUDE_PID for liveness of held scopes',
        verifiedBy: 'conformance.host.pid',
      },
      'blocking-in-every-permission-mode': {
        status: 'SUPPORTED',
        note: 'hook denies apply in default, acceptEdits, plan and bypassPermissions',
        verifiedBy: 'conformance.hook.allmodes',
      },
      'managed-settings-lock': {
        status: 'SUPPORTED',
        note: 'managed tier: allowManagedHooksOnly, allowManagedPermissionRulesOnly (HIGH_ASSURANCE)',
        verifiedBy: 'conformance.host.managed',
      },
      'sandboxed-command-execution': {
        status: 'PARTIAL',
        note: 'host sandbox exists; EGO records its presence and never assumes it',
        verifiedBy: 'conformance.host.sandbox',
      },
      'network-egress-control': {
        status: 'PARTIAL',
        note: 'egress limits depend on the host sandbox; kernel classifies URLs and commands regardless',
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
        status: 'PARTIAL',
        note: 'host can open worktrees; the kernel enforces isolation through held scopes',
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
