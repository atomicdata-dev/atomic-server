import { expect, it } from 'vitest';
import {
  matchesCreationSearch,
  CREATION_TABLE_TEMPLATES,
} from './creationCatalog';
import { TABLE_TEMPLATES } from '../../chunks/TablePage/tableTemplates';
import { creationAssistantAsk } from './creationAssistant';
it('offers every configured table template and searches multiple words across its content', () => {
  expect(CREATION_TABLE_TEMPLATES.map(t => t.id)).toEqual(
    TABLE_TEMPLATES.filter(t => t.spec).map(t => t.id),
  );
  expect(
    matchesCreationSearch('  KANBAN issue ', 'Issue Tracker', 'A kanban board'),
  ).toBe(true);
  expect(
    matchesCreationSearch('calendar invoice', 'Issue Tracker', 'A calendar'),
  ).toBe(false);
});
it('hands off the actual request with the selected parent', () => {
  const ask = creationAssistantAsk('  A reading log  ', 'did:ad:nested-folder');
  expect(ask.prompt).toContain('A reading log');
  expect(ask.prompt).toContain('inside the attached parent');
  expect(ask.context).toEqual([
    {
      type: 'atomic-resource',
      subject: 'did:ad:nested-folder',
      id: expect.any(String),
    },
  ]);
});
