// Canonical types for the authored control plane after loading and validation.

export type Verdict = 'ALLOW' | 'ASK' | 'DENY';

export const VERDICT_RANK: Record<Verdict, number> = { ALLOW: 0, ASK: 1, DENY: 2 };

export type LayerName = 'core' | 'organization' | 'profile' | 'overlay';

/**
 * Lock tier of a capability (Q98). `absolute`: never widenable by any layer. `organization`: DENY at the core and
 * widenable only by the organization policy layer, never by an overlay, grant, mode, skill or model. `none`: ordinary.
 */
export type CapabilityLock = 'absolute' | 'organization' | 'none';

export interface CapabilityDecl {
  id: string;
  verdict: Verdict;
  description: string;
  family: string;
  file: string;
  line: number;
  absolute: boolean;
  lock: CapabilityLock;
}

export interface CapabilityDoc {
  id: string;
  family: string;
  title: string;
  absolute: boolean;
  lock: CapabilityLock;
  layer: LayerName;
  file: string;
  capabilities: CapabilityDecl[];
}

export type MatcherTool = 'Bash' | 'Read' | 'Write' | 'Edit' | 'WebFetch' | 'any';

export interface Matcher {
  capability: string;
  tool: MatcherTool;
  command?: RegExp;
  commandSource?: string;
  path?: string;
  url?: RegExp;
  urlSource?: string;
  index: number;
  file: string;
}

export interface GrantRule {
  capability: string;
  phrases: string[];
}

export interface GrantsDoc {
  negationWindowTokens: number;
  negations: string[];
  grants: GrantRule[];
  file: string;
}

export interface ProfileNarrow {
  capability: string;
  verdict: Verdict;
}

export type UnavailablePolicy = 'CONTINUE_WITH_DISCLOSURE' | 'BLOCK_DONE';
export type ShellUncertainPolicy = 'DETECT_AFTER' | 'DENY' | 'REQUIRE_ISOLATION';
export type OwnerWeakeningPolicy = 'AUTO_WITH_INFORM' | 'DECISION';
export type ModelFlagPolicy = 'INFORM' | 'DECISION_WITH_KEEP';

export type BudgetExceedAction = 'BLOCK' | 'ESCALATE';

/** Execution budgets per profile (alignment item 8). `null` means the dimension is not observable on this host. */
export interface ExecutionBudgets {
  maxDurationMinutes: number;
  maxIterations: number;
  maxToolCalls: number;
  maxRetriesPerStep: number;
  maxDelegationDepth: number;
  maxConcurrentSubagents: number;
  maxNetworkOperations: number;
  maxTokens: number | null;
  maxCostUsd: number | null;
  onExceed: BudgetExceedAction;
}

export interface Profile {
  id: string;
  title: string;
  budgets: ExecutionBudgets;
  contextBudgetTokens: number;
  organizationCeilingTokens: number;
  requiresSignedReleaseTrust: boolean;
  requiresManagedTier: boolean;
  requiresRemoteVerifyBackstop: boolean;
  grillingReviewUnavailable: UnavailablePolicy;
  forgeUnreachableAtDone: UnavailablePolicy;
  shellUncertainMutation: ShellUncertainPolicy;
  ownerWeakeningPlainPolicy: OwnerWeakeningPolicy;
  modelFlaggedConflictOnControl: ModelFlagPolicy;
  narrow: ProfileNarrow[];
  file: string;
}

export interface ModeOverride {
  capability: string;
  verdict: Verdict;
}

export interface AuthorityMode {
  id: string;
  title: string;
  isDefault: boolean;
  onlyInEgoRepository: boolean;
  overrides: ModeOverride[];
  file: string;
}

export interface Intent {
  id: string;
  title: string;
  routesSkills: string[];
  file: string;
}

export type Severity = 'block' | 'warn';

export interface SecretDetector {
  id: string;
  family: string;
  name: string;
  pattern: RegExp;
  patternSource: string;
  flags: string;
  group: number;
  severity: Severity;
  locked: boolean;
  replacement: string;
  wholeDocument: boolean;
  onlyForFiles: boolean;
  file: string;
}

export interface SecretsDoc {
  family: string;
  title: string;
  sensitiveFiles: string[];
  detectors: SecretDetector[];
  file: string;
}

export interface ReleaseKey {
  id: string;
  algorithm: 'ed25519';
  publicKey: string;
  fingerprint: string;
  status: 'active' | 'standby' | 'revoked';
  validFrom?: string;
}

export interface ReleaseKeysDoc {
  keys: ReleaseKey[];
  independentChannel: string;
  file: string;
}

export interface CoordinationConstants {
  heartbeatTtlSeconds: number;
  heartbeatTtlWithoutPidSeconds: number;
  handoffGraceSeconds: number;
  lockTimeoutMs: number;
  lockStaleBreakMs: number;
  gcEndedSessionsDays: number;
  gcUnheldClaimsDays: number;
  file: string;
}

/** Decision Q98: the authored set of targets that count as repository-owned local development surfaces. Authorization
 *  is target-aware, so a Kubernetes or database command is judged by WHERE it points, never by the tool's name. */
export interface LocalTargets {
  /** glob patterns for kube contexts that are local development clusters (kind-*, minikube, docker-desktop, …) */
  k8sLocalContexts: string[];
  /** hostnames that are the local machine (localhost, 127.0.0.1, ::1, *.localhost, …) */
  dbLocalHosts: string[];
  /** tokens that mark a target as production wherever they appear in its name */
  productionMarkers: string[];
  file: string;
}

/** The class a concrete target resolves to. UNCLASSIFIED is a first-class answer, never a silent "local". */
export type TargetClass = 'LOCAL' | 'PRODUCTION' | 'EXTERNAL' | 'UNCLASSIFIED';

export type SupportStatus = 'SUPPORTED' | 'PARTIAL' | 'UNAVAILABLE' | 'UNVERIFIED';

/** A containment control (alignment item 3): technical isolation, distinct from policy and authority. */
export interface ContainmentControl {
  id: string;
  description: string;
  requiredIn: string[];
  recommendedIn: string[];
  hosts: Record<string, SupportStatus>;
  file: string;
}

export interface ControlPlane {
  root: string;
  absoluteDenies: CapabilityDoc;
  /** organization-locked denies: DENY at the core, widenable only by the organization layer (Q98) */
  organizationLocked: CapabilityDoc | null;
  capabilityDocs: CapabilityDoc[];
  containment: ContainmentControl[];
  matchers: Matcher[];
  grants: GrantsDoc;
  profiles: Profile[];
  modes: AuthorityMode[];
  intents: Intent[];
  secrets: SecretsDoc[];
  releaseKeys: ReleaseKeysDoc;
  coordination: CoordinationConstants;
  localTargets: LocalTargets;
  /** sha256 of every authored file, keyed by path relative to root, for provenance and freshness */
  sourceHashes: Record<string, string>;
}

export class ControlPlaneValidationError extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    super(
      `control plane failed validation (${problems.length} problem${problems.length === 1 ? '' : 's'}):\n- ${problems.join('\n- ')}`,
    );
    this.name = 'ControlPlaneValidationError';
    this.problems = problems;
  }
}
