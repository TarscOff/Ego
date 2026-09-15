import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateBudget, applyBudgetExtension } from '../src/authority/budget.ts';
import type { ExecutionBudgets } from '../src/control-plane/types.ts';

const strict: ExecutionBudgets = {
  maxDurationMinutes: 240,
  maxIterations: 60,
  maxToolCalls: 1500,
  maxRetriesPerStep: 3,
  maxDelegationDepth: 2,
  maxConcurrentSubagents: 3,
  maxNetworkOperations: 200,
  maxTokens: null,
  maxCostUsd: null,
  onExceed: 'BLOCK',
};
const base = {
  elapsedMinutes: 10,
  iterations: 5,
  toolCalls: 50,
  maxRetriesForOneStep: 1,
  delegationDepth: 1,
  concurrentSubagents: 1,
  networkOperations: 3,
};

test('budgets pass when within limits and block on the first breach', () => {
  assert.equal(evaluateBudget(strict, base).action, 'CONTINUE');
  const r = evaluateBudget(strict, { ...base, maxRetriesForOneStep: 4 });
  assert.equal(r.action, 'BLOCK');
  assert.deepEqual(r.breaches, [{ dimension: 'maxRetriesPerStep', limit: 3, observed: 4 }]);
  assert.equal(
    evaluateBudget({ ...strict, onExceed: 'ESCALATE' }, { ...base, delegationDepth: 3 }).action,
    'ESCALATE',
  );
});

test('unobservable dimensions never breach; observable ones do', () => {
  assert.equal(evaluateBudget(strict, { ...base, tokens: 10_000_000 }).action, 'CONTINUE');
  assert.equal(
    evaluateBudget({ ...strict, maxTokens: 1000 }, { ...base, tokens: 1001 }).breaches[0]?.dimension,
    'maxTokens',
  );
  assert.equal(evaluateBudget({ ...strict, maxCostUsd: 5 }, base).action, 'CONTINUE');
});

test('a human extension raises numeric limits only and never changes on_exceed', () => {
  const ext = applyBudgetExtension(strict, {
    maxToolCalls: 3000,
    onExceed: 'ESCALATE',
    maxIterations: -1,
  } as Partial<ExecutionBudgets>);
  assert.equal(ext.maxToolCalls, 3000);
  assert.equal(ext.onExceed, 'BLOCK');
  assert.equal(ext.maxIterations, 60);
  assert.equal(
    evaluateBudget(strict, { ...base, toolCalls: 2000 }, { maxToolCalls: 3000 }).action,
    'CONTINUE',
  );
});
