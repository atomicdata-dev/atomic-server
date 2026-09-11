import test from 'node:test';
import assert from 'node:assert/strict';
import { reduceEvent, approvalChoices } from './model.mjs';
test('streaming completion replaces rather than duplicates text', () => {
  let items = reduceEvent([], 'item/agentMessage/delta', {
    itemId: 'a',
    delta: 'Hel',
  });
  items = reduceEvent(items, 'item/agentMessage/delta', {
    itemId: 'a',
    delta: 'lo',
  });
  items = reduceEvent(items, 'item/completed', {
    item: { id: 'a', type: 'agentMessage', text: 'Hello' },
  });
  assert.equal(items.length, 1);
  assert.equal(items[0].text, 'Hello');
});
test('interleaved command output preserves message identity', () => {
  let items = reduceEvent([], 'item/started', {
    item: { id: 'c', type: 'commandExecution', command: 'pwd' },
  });
  items = reduceEvent(items, 'item/agentMessage/delta', {
    itemId: 'a',
    delta: 'Checking',
  });
  items = reduceEvent(items, 'item/commandExecution/outputDelta', {
    itemId: 'c',
    delta: '/workspace',
  });
  assert.equal(items[0].aggregatedOutput, '/workspace');
  assert.equal(items[1].text, 'Checking');
});
test('approvals never offer blanket/session grants or invent unsupported decisions', () => {
  assert.deepEqual(
    approvalChoices('item/commandExecution/requestApproval', {}),
    ['accept', 'decline'],
  );
  assert.deepEqual(
    approvalChoices('item/commandExecution/requestApproval', {
      availableDecisions: ['decline'],
    }),
    ['decline'],
  );
  assert.deepEqual(approvalChoices('item/permissions/requestApproval', {}), []);
});
