// WHAT EACH KIND OF TARGET RESOLVES TO. For a Kubernetes tool, a database client or a container engine the resolver
// answers one of four classes (LOCAL, PRODUCTION, EXTERNAL, UNCLASSIFIED); this table says which capability each
// non-local class lands on, and which list of `local-targets.md` declares a local one. It is read by
// `retargetLocalCapability` (which picks the capability), by `targetRuleFor` (which prints the rule, so the rule
// `ego explain capability` shows a person is the rule the evaluator applies) and by the compiler (which lists the
// capabilities a pattern cannot reach but the target model can as pre-denied).
//
// It is a module of its own because the compiler needs it too. For as long as the production verdicts of
// `kubectl` and `helm` were ALSO two regexes in matchers.md, "is this production" had a second reader, and that copy
// answered `-n products` with an absolute deny on a local cluster (wave 5, K8-01). The regexes are gone; the capability
// is only ever reached through this table, and the compiler lists it as pre-denied from here, so the authority diff
// does not report a protection removed that was only ever the same one in a different place.
export const TARGET_KINDS = {
  k8s: {
    noun: 'kube context or namespace',
    declaredIn: ['k8s_local_contexts'],
    production: 'production.k8s.mutate',
    external: 'k8s.nonlocal.mutate',
    unclassified: 'k8s.target.unclassified',
  },
  db: {
    noun: 'database host',
    declaredIn: ['db_local_hosts'],
    production: 'production.database.mutate',
    external: 'db.nonlocal.mutate',
    unclassified: 'db.target.unclassified',
  },
  container: {
    noun: 'container engine context or host',
    declaredIn: ['k8s_local_contexts', 'db_local_hosts'],
    production: 'production.deploy',
    external: 'container.nonlocal.run',
    unclassified: 'container.target.unclassified',
  },
} as const;

/** A production Helm release is its own absolute capability (`production.helm.mutate`), reached through the same table:
 *  the head decides, the class does not. */
export const HELM_PRODUCTION = 'production.helm.mutate';

/** The production capability a head lands on when its target is production. */
export const productionCapabilityFor = (kind: keyof typeof TARGET_KINDS, head: string): string =>
  kind === 'k8s' && head === 'helm' ? HELM_PRODUCTION : TARGET_KINDS[kind].production;

/** Every capability the target model lands a production target on. */
export const PRODUCTION_LANDINGS: readonly string[] = [
  ...Object.values(TARGET_KINDS).map((k) => k.production),
  HELM_PRODUCTION,
];
