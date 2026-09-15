// Execution budget enforcement (alignment item 8). Deterministic: counters come from the ledger, limits from the
// compiled profile. Unobservable dimensions (token, cost) are skipped, never guessed.
import type { ExecutionBudgets } from '../control-plane/types.ts';

export interface BudgetCounters {
  elapsedMinutes: number;
  iterations: number;
  toolCalls: number;
  /** highest retry count observed for one step */
  maxRetriesForOneStep: number;
  delegationDepth: number;
  concurrentSubagents: number;
  networkOperations: number;
  tokens?: number;
  costUsd?: number;
}

export interface BudgetBreach {
  dimension: keyof ExecutionBudgets;
  limit: number;
  observed: number;
}

export interface BudgetVerdict {
  breaches: BudgetBreach[];
  action: 'CONTINUE' | 'BLOCK' | 'ESCALATE';
}

export function evaluateBudget(
  budgets: ExecutionBudgets,
  counters: BudgetCounters,
  extensions: Partial<ExecutionBudgets> = {},
): BudgetVerdict {
  const b = { ...budgets, ...extensions };
  const breaches: BudgetBreach[] = [];
  const check = (dimension: keyof ExecutionBudgets, limit: number | null, observed: number | undefined) => {
    if (limit === null || observed === undefined) return;
    if (observed > limit) breaches.push({ dimension, limit, observed });
  };
  check('maxDurationMinutes', b.maxDurationMinutes, counters.elapsedMinutes);
  check('maxIterations', b.maxIterations, counters.iterations);
  check('maxToolCalls', b.maxToolCalls, counters.toolCalls);
  check('maxRetriesPerStep', b.maxRetriesPerStep, counters.maxRetriesForOneStep);
  check('maxDelegationDepth', b.maxDelegationDepth, counters.delegationDepth);
  check('maxConcurrentSubagents', b.maxConcurrentSubagents, counters.concurrentSubagents);
  check('maxNetworkOperations', b.maxNetworkOperations, counters.networkOperations);
  check('maxTokens', b.maxTokens, counters.tokens);
  check('maxCostUsd', b.maxCostUsd, counters.costUsd);
  return { breaches, action: breaches.length === 0 ? 'CONTINUE' : b.onExceed };
}

/** A human grant of `harness.budget.extend` may raise numeric limits for the current task only; it can never lower on_exceed to silence. */
export function applyBudgetExtension(
  budgets: ExecutionBudgets,
  requested: Partial<ExecutionBudgets>,
): ExecutionBudgets {
  const out = { ...budgets };
  for (const key of Object.keys(requested) as Array<keyof ExecutionBudgets>) {
    if (key === 'onExceed') continue;
    const v = requested[key];
    if (typeof v === 'number' && Number.isFinite(v) && v > 0) (out as Record<string, unknown>)[key] = v;
  }
  return out;
}
