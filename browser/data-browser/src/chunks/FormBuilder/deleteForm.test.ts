import { expect, it, vi } from 'vitest';
import { forms, type Resource, type Store } from '@tomic/react';
import { deleteForm } from './deleteForm';

it('deletes form presentation, leaving shared columns and tags intact', async () => {
  const resource = (subjects: Record<string, string[]> = {}) => ({
    getSubjects: (p: string) => subjects[p] ?? [],
    destroy: vi.fn(async () => {}),
  });
  const form = resource({ [forms.properties.formPages]: ['page'] });
  const page = resource({
    [forms.properties.formFields]: ['field'],
    [forms.properties.formConditions]: ['page-condition'],
  });
  const field = resource({
    [forms.properties.formMapsTo]: ['column'],
    [forms.properties.formConditions]: ['field-condition'],
  });
  const resources = {
    page,
    field,
    'page-condition': resource(),
    'field-condition': resource(),
    column: resource(),
    tag: resource(),
  };
  const store = {
    getResource: async (s: string) => resources[s as keyof typeof resources],
  };
  await deleteForm(store as unknown as Store, form as unknown as Resource);
  for (const r of [
    form,
    page,
    field,
    resources['page-condition'],
    resources['field-condition'],
  ])
    expect(r.destroy).toHaveBeenCalledOnce();
  expect(resources.column.destroy).not.toHaveBeenCalled();
  expect(resources.tag.destroy).not.toHaveBeenCalled();
});
