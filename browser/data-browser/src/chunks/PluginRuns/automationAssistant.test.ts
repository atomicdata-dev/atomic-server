import { expect, it } from 'vitest';
import { automationAssistantAsk } from './automationAssistant';

it('hands the assistant the existing draft and selected integration without changing sync', () => {
  const ask = automationAssistantAsk(
    '  Triage bug reports  ',
    'did:ad:draft',
    'did:ad:connection',
    {
      id: 'issue-discovered',
      name: 'New issue discovered',
      description: 'Excludes initial imports',
      filters: [],
    },
  );
  expect(
    ask.context?.map(item => item.type === 'atomic-resource' && item.subject),
  ).toEqual(['did:ad:draft', 'did:ad:connection']);
  expect(ask.prompt).toContain('Triage bug reports');
  expect(ask.prompt).toContain('Excludes initial imports');
  expect(ask.prompt).toContain('Update the attached automation draft');
  expect(ask.prompt).toContain('Test the automation');
  expect(ask.prompt).toContain('Keep the integration sync schedule unchanged');
});
