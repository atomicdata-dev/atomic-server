import { it, expect } from 'vitest';
import { eventAutomationSource } from '../../browser/data-browser/src/chunks/PluginRuns/integrationAutomation';
it('wires arbitrary events to a sandbox script without prescribing an action', async () => {
  const source = eventAutomationSource({
    id: 'enrollment',
    name: 'Student enrolled',
    description: 'A different domain',
    filters: [
      { property: 'class', value: 'school"class' },
      { property: 'enrolled' },
    ],
  });
  const action = await import(
    /* @vite-ignore */ `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`
  );
  const read = () => ({ class: 'school"class', enrolled: true });
  expect(
    action.run({ trigger: { subject: 'did:ad:student' }, read }).intents,
  ).toEqual([]);
  expect(
    action.run({ trigger: {}, read, query: () => [] }).problems[0].severity,
  ).toBe('error');
  expect(
    action.run({ trigger: {}, read, query: () => ['did:ad:student'] }).problems,
  ).toEqual([]);
  expect(source).not.toContain('New issue:');
});
