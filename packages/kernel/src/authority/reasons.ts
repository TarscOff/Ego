// FAILURE REASON CODES (issue #16 section 10). A refusal used to be prose: "X is DENY (…deny)". A
// human or a host cannot branch on prose, and the prose did not say where the rule came from or whether anything could
// change it. Every non-ALLOW result now carries ONE typed code, the rule source, and whether configuration can change
// the outcome; the code is mapped from the decision in ONE function (`explainOutcome`), not at the thirty places that
// build a hit, so two readers of "why was this refused" cannot drift (the repository's most repeated defect).
//
//   HARD_LOCKED               an absolute deny (the HARD_LOCK tier). Nothing can change it.
//   ADMIN_DENIED              policy configuration said no: an ADMIN_GOVERNED capability the organization has not
//                             enabled, or a DENY the selected profile or authority mode chose.
//   HUMAN_APPROVAL_REQUIRED   an ASK. A human approves this one operation (TASK_APPROVAL).
//   SCOPE_DENIED              outside what a governed session may do: a protected path, a target that is named but not
//                             a declared local one, an operation the core table denies with no policy that enables it.
//   TARGET_UNCLASSIFIED       where the effect lands could not be resolved to a declared target (k8s, database,
//                             container engine, MCP server).
//   POLICY_INVALID            the policy did not load or compile; nothing runs under it (fail closed).
//   POLICY_STALE              the compiled policy, the pin or the trust level is behind what is on disk or required.
//
// The remaining four are DEFINED so the vocabulary is complete and a producer can be added without a schema change, but
// they have NO PRODUCER: each one needs a module that does not exist yet, and a code nothing can observe would be a
// code somebody faked. Their producers are documented below and arrive with the phase that owns the module.
import { VERDICT_RANK, type Verdict } from '../control-plane/types.ts';
import type { CompiledAuthorityTable } from './compile.ts';
import {
  LOCK_TIER_LABEL,
  capabilityCeiling,
  describeSource,
  isTargetUnclassified,
  verdictSource,
  widerElsewhere,
} from './vocabulary.ts';

export const REASON_CODES = [
  'HARD_LOCKED',
  'ADMIN_DENIED',
  'HUMAN_APPROVAL_REQUIRED',
  'SCOPE_DENIED',
  'TARGET_UNCLASSIFIED',
  'NETWORK_UNAVAILABLE',
  'SERVICE_UNAVAILABLE',
  'RUNTIME_CAPABILITY_UNAVAILABLE',
  'DOWNSTREAM_AUTH_DENIED',
  'POLICY_INVALID',
  'POLICY_STALE',
] as const;
export type ReasonCode = (typeof REASON_CODES)[number];

export interface ReasonCodeInfo {
  meaning: string;
  /** who or what can change an outcome carrying this code */
  configurable: string;
  producer: { status: 'live' | 'deferred'; where: string };
}

export const REASON_CODE_INFO: Record<ReasonCode, ReasonCodeInfo> = {
  HARD_LOCKED: {
    meaning:
      'An absolute deny: one of the non-widenable invariants of the HARD_LOCK tier (production mutation, gate and trust tampering, credential stores, writes outside the workspace, protection and hook bypass).',
    configurable:
      'Nothing. No organization policy, profile, overlay, grant, mode, skill, task approval or model can widen it.',
    producer: {
      status: 'live',
      where:
        'evaluate() through explainOutcome(): every capability in control-plane/permissions/absolute-denies.md',
    },
  },
  ADMIN_DENIED: {
    meaning:
      'Policy configuration refused it: an ADMIN_GOVERNED capability the organization has not enabled, or a DENY that the selected profile or authority mode chose.',
    configurable:
      'Yes: the organization policy layer (ADMIN_GOVERNED, then never past ASK), or the profile or mode that narrowed it.',
    producer: {
      status: 'live',
      where: 'evaluate() through explainOutcome(); the execution-budget stop in the PreToolUse hook',
    },
  },
  HUMAN_APPROVAL_REQUIRED: {
    meaning: 'An ASK: a human approves this one operation (TASK_APPROVAL), through the host prompt.',
    configurable:
      'A recognised grant phrase lifts a LOCAL_WORKSPACE capability for the session; an EXTERNAL_EFFECT one asks every time (ceiling ASK).',
    producer: {
      status: 'live',
      where: 'evaluate() through explainOutcome(); the execution-budget escalation in the PreToolUse hook',
    },
  },
  SCOPE_DENIED: {
    meaning:
      'Outside what a governed session may do: a protected path, a target that is named but not a declared local one, or an operation the core table denies and no policy enables.',
    configurable:
      'Rarely: only an authority mode that widens it (EGO_MAINTENANCE, in the EGO repository) or a change to EGO’s own control plane.',
    producer: {
      status: 'live',
      where: 'evaluate() through explainOutcome(), including an apply_patch whose paths cannot be known',
    },
  },
  TARGET_UNCLASSIFIED: {
    meaning:
      'Where the effect lands could not be resolved to a declared target: an ambient or variable kube context, database host or container engine, or an MCP tool whose server nothing resolves.',
    configurable:
      'Name the target so it resolves (a declared local target, control-plane/workspace/local-targets.md); a human may approve the one operation meanwhile.',
    producer: {
      status: 'live',
      where:
        'evaluate() through explainOutcome(): k8s, database and container target resolution, mcp.unknown; a PreToolUse payload that names no tool',
    },
  },
  NETWORK_UNAVAILABLE: {
    meaning: 'A remote could not be reached when the decision needed it.',
    configurable: 'Restore the network; no policy governs reachability.',
    producer: {
      status: 'deferred',
      where:
        'forge and MCP adapters (phase 2, issue #10) and the remote sync adapters (phase 6): the kernel makes no network call on a verdict path today, so nothing can observe an unreachable network',
    },
  },
  SERVICE_UNAVAILABLE: {
    meaning: 'A configured integration (forge, tracker, MCP server) answered with an outage.',
    configurable: 'Restore the service; no policy governs availability.',
    producer: {
      status: 'deferred',
      where:
        'forge, tracker and MCP adapters (phase 2, issue #10): there is no integration client to be unavailable yet',
    },
  },
  RUNTIME_CAPABILITY_UNAVAILABLE: {
    meaning:
      'The host or runtime lacks a control the profile requires (a blocking hook, a sandbox, a managed tier).',
    configurable: 'Install or enable the control, or select a profile that does not require it.',
    producer: {
      status: 'deferred',
      where:
        'host conformance (phase 6): `ego doctor` reports a missing host control as NOT SATISFIED or UNVERIFIED today, without a refusal',
    },
  },
  DOWNSTREAM_AUTH_DENIED: {
    meaning: 'EGO allowed the call and the downstream service refused the credential the human supplied.',
    configurable: 'Fix the credential at the service; EGO never holds or changes it.',
    producer: {
      status: 'deferred',
      where: 'forge and MCP adapters (phase 2, issue #10): EGO issues no downstream request yet',
    },
  },
  POLICY_INVALID: {
    meaning:
      'The policy does not load or compile: a malformed control-plane or layer file, a layer that widens what it may not, a pin that fails its stamp.',
    configurable:
      'Yes: fix the file named in the message; nothing runs under a policy that does not compile.',
    producer: {
      status: 'live',
      where:
        'main() for any command or hook that throws a ControlPlaneValidationError; the launcher for a pin that fails its stamp',
    },
  },
  POLICY_STALE: {
    meaning:
      'The compiled policy, the pin or the trust level is behind what is on disk or required: a cache from another runtime or naming, an edited layer file, a widening awaiting a human, a pin not yet at the required trust.',
    configurable:
      'Yes: regenerate (the next hook does for a runtime or naming change); a pending widening needs a human `ego init`; trust needs `ego sync`.',
    producer: {
      status: 'live',
      where:
        'policyCacheFreshness() (`ego check`, `ego doctor`), the pending-widening line at SessionStart, the pre-promotion refusal in the PreToolUse hook',
    },
  },
};

/** Why an outcome carries its code: the rule's source and whether configuration can change it. */
export interface RuleExplanation {
  /** the layer and file that decided */
  source: string;
  changeable: boolean;
  /** what can change it, or why nothing can, in one clause */
  changeBy: string;
}

export interface Outcome {
  code: ReasonCode;
  rule: RuleExplanation;
}

/** the part of a hit the mapping reads */
export interface HitLike {
  capability: string;
  verdict: Verdict;
  absolute: boolean;
}

/**
 * THE ONE MAPPING FROM A DECISION TO ITS CODE. By precedence: an ALLOW has none; a HARD_LOCK is HARD_LOCKED whatever
 * path found it; a capability that says its destination is unclassified is TARGET_UNCLASSIFIED, ASK or DENY; any other
 * ASK is HUMAN_APPROVAL_REQUIRED; a DENY of an ADMIN_GOVERNED capability, or one a profile or mode moved, is
 * ADMIN_DENIED (configuration chose it, configuration can change it); every remaining DENY is the core table's and is
 * SCOPE_DENIED. The tier, not the spelling or the code path, decides.
 */
export function explainOutcome(
  table: CompiledAuthorityTable,
  ctx: { profile: string; mode: string },
  hit: HitLike,
): Outcome | undefined {
  if (hit.verdict === 'ALLOW') return undefined;
  const cap = table.capabilities[hit.capability];
  const src = verdictSource(table, ctx.profile, ctx.mode, hit.capability);
  const moved = src.layer.startsWith('profile ') || src.layer.startsWith('mode ');
  const hardLocked = hit.absolute || cap?.lock === 'absolute';
  const code: ReasonCode = hardLocked
    ? 'HARD_LOCKED'
    : isTargetUnclassified(hit.capability)
      ? 'TARGET_UNCLASSIFIED'
      : hit.verdict === 'ASK'
        ? 'HUMAN_APPROVAL_REQUIRED'
        : cap?.lock === 'admin-governed' || moved
          ? 'ADMIN_DENIED'
          : 'SCOPE_DENIED';
  const tier = hardLocked
    ? `${LOCK_TIER_LABEL.absolute}, `
    : cap?.lock === 'admin-governed'
      ? `${LOCK_TIER_LABEL['admin-governed']}, `
      : '';
  return {
    code,
    rule: { source: tier + describeSource(src), ...configurability(table, ctx, hit, hardLocked) },
  };
}

/** Whether configuration can change an outcome, derived from the same table the verdict was: the ceiling against the
 *  verdict in force, and the profiles, modes and grant phrases that reach a wider one. */
function configurability(
  table: CompiledAuthorityTable,
  ctx: { profile: string; mode: string },
  hit: HitLike,
  hardLocked: boolean,
): { changeable: boolean; changeBy: string } {
  if (hardLocked)
    return {
      changeable: false,
      changeBy:
        'HARD_LOCK: no organization policy, profile, overlay, grant, mode, skill, task approval or model can widen it; a human can do it from their own terminal',
    };
  const cap = table.capabilities[hit.capability];
  const ceiling = capabilityCeiling(table, hit.capability);
  const paths: string[] = [];
  if (cap?.lock === 'admin-governed' && hit.verdict === 'DENY')
    paths.push(
      'the organization policy layer (policies/organization/permissions.md, accepted by a human with `ego init`) can enable it, and then every use is one human approval (TASK_APPROVAL; the ceiling is ASK)',
    );
  const wider = widerElsewhere(table, ctx.profile, ctx.mode, hit.capability);
  if (wider.profiles.length)
    paths.push(
      `the profile: ${wider.profiles.join(', ')} allows it (a human selects it with \`ego init --profile\`)`,
    );
  if (wider.modes.length)
    paths.push(
      `the authority mode: ${wider.modes.join(', ')} allows it (a human sets it; EGO_MAINTENANCE exists only in the EGO source repository)`,
    );
  if (
    cap?.effect === 'local' &&
    hit.verdict === 'ASK' &&
    table.grants.some((g) => g.capability === hit.capability)
  )
    paths.push('a recognised grant phrase lifts it for the session');
  if (paths.length && VERDICT_RANK[ceiling] < VERDICT_RANK[hit.verdict])
    return { changeable: true, changeBy: paths.join('; ') };
  if (hit.verdict === 'ASK')
    return {
      changeable: false,
      changeBy:
        cap?.effect === 'external'
          ? 'it asks a human for each occurrence (TASK_APPROVAL); no policy, mode or phrase makes an external effect unattended (ceiling ASK)'
          : 'it asks a human for each occurrence; no policy, mode or phrase removes the question (ceiling ASK)',
    };
  return {
    changeable: false,
    changeBy:
      'no organization policy, profile or overlay can widen it: it is part of EGO’s own control plane',
  };
}

/** The sentence form of an outcome, appended to the prose that names the capability and the call. */
export function renderReason(base: string, o: Outcome): string {
  return `${o.code}: ${base}. Rule source: ${o.rule.source}. Configuration ${o.rule.changeable ? 'can' : 'cannot'} change it: ${o.rule.changeBy}.`;
}

/** A refusal that is not a capability verdict (a policy that does not load, a cache that is behind): code, detail, source. */
export function renderFailure(code: ReasonCode, detail: string, rule: RuleExplanation): string {
  return `${code}: ${detail}. Rule source: ${rule.source}. Configuration ${rule.changeable ? 'can' : 'cannot'} change it: ${rule.changeBy}.`;
}

/** The rule behind POLICY_INVALID: the file the message names. */
export const POLICY_INVALID_RULE: RuleExplanation = {
  source:
    'the control-plane or layer file named in the detail (policies/organization/permissions.md, .harness/permissions.md, .harness/harness.md)',
  changeable: true,
  changeBy:
    'fix that file, then `ego check`; nothing runs under a policy that does not compile (EGO fails closed)',
};

/** The rule behind POLICY_STALE. */
export const POLICY_STALE_RULE: RuleExplanation = {
  source:
    'the compiled policy cache (.harness/generated/policy.json), the pin (.harness/harness.md) and the layer files, compared with the executing runtime',
  changeable: true,
  changeBy:
    'regenerate it (the next hook does for a runtime or naming change, `ego init` otherwise); a widening still pending needs a human `ego init` from their own terminal, and trust needs `ego sync`',
};
