import { describe, expect, it, vi } from 'vitest';
import { core, dataBrowser, Datatype, forms } from '@tomic/react';
import { formTestFixture as fixture } from './formTestFixture';
import { buildFormFromSpec, type FormSpec } from './createFormFromSpec';

// The tag palette imports app styling, which bootstraps browser routes.
vi.mock('@components/Tag/tagColours', () => ({ tagColours: ['blue'] }));

describe('create_form resource graph', () => {
  it('creates ordered pages, typed properties, choice tags and a response table before form genesis', async () => {
    const f = fixture();
    const result = await buildFormFromSpec(
      f.store,
      {
        name: 'Application',
        pages: [
          {
            name: 'About you',
            fields: [
              { label: 'Welcome', type: 'heading' },
              {
                label: 'Email',
                type: 'email',
                required: true,
                placeholder: 'you@example.com',
              },
            ],
          },
          {
            name: 'Preferences',
            fields: [
              {
                label: 'Role',
                type: 'radio',
                choices: ['Engineer', 'Designer'],
              },
            ],
          },
        ],
      },
      f.opts,
    );
    const form = f.resources.get(result.form)!;
    const table = f.resources.get(result.table)!;
    expect(form.get(forms.properties.formOwnsSchema)).toBe(true);
    expect(table.get(core.properties.parent)).toBe(result.form);
    expect(form.getSubjects(forms.properties.formPages)).toEqual(
      result.pages.map(p => p.subject),
    );
    const genesis = f.saved.find(s => s.subject === result.form)!;
    expect(genesis.values[forms.properties.formTargetTable]).toBe(result.table);
    expect(f.saved.findIndex(s => s.subject === result.table)).toBeLessThan(
      f.saved.indexOf(genesis),
    );
    const email = f.resources.get(result.pages[0].fields[1].subject)!;
    expect(email.get(forms.properties.required)).toBe(true);
    expect(
      f.resources
        .get(email.get(forms.properties.formMapsTo) as string)!
        .get(core.properties.datatype),
    ).toBe(Datatype.STRING);
    const choice = f.resources.get(
      result.pages[1].fields[0].property as string,
    )!;
    expect(choice.get(dataBrowser.properties.max)).toBe(1);
    expect(
      choice
        .getSubjects(core.properties.allowsOnly)
        .map(s => f.resources.get(s)!.get(core.properties.name)),
    ).toEqual(['Engineer', 'Designer']);
    expect(result.pages[0].fields[0].property).toBeUndefined();
  });

  function existingTable() {
    const f = fixture();
    const column = f.make({
      [core.properties.name]: 'Age',
      [core.properties.datatype]: Datatype.INTEGER,
    });
    const cls = f.make({ [core.properties.requires]: [column.subject] });
    const table = f.make({
      [core.properties.isA]: [dataBrowser.classes.table],
      [core.properties.classtype]: cls.subject,
    });

    return { ...f, column, cls, table };
  }

  it('reuses shared columns without changing them and preserves required constraints', async () => {
    const f = existingTable();
    const result = await buildFormFromSpec(
      f.store,
      {
        name: 'Survey',
        table: f.table.subject,
        pages: [
          {
            name: 'Page',
            fields: [
              {
                label: 'Your age',
                column: 'Age',
                type: 'number',
                required: false,
              },
            ],
          },
        ],
      },
      f.opts,
    );
    for (const r of [f.column, f.cls, f.table])
      expect(r.save).not.toHaveBeenCalled();
    const field = f.resources.get(result.pages[0].fields[0].subject)!;
    expect(field.get(core.properties.name)).toBe('Your age');
    expect(field.get(forms.properties.required)).toBe(true);
    expect(field.get(forms.properties.formMapsTo)).toBe(f.column.subject);
  });

  it.each([
    [{ label: 'Age', column: 'Missing', type: 'number' }],
    [{ label: 'Age', column: 'Age', type: 'email' }],
    [],
    [
      { label: 'Age', column: 'Age', type: 'number' },
      { label: 'Again', column: 'Age', type: 'number' },
    ],
  ])('rejects invalid table mappings before writes: %j', async (...fields) => {
    const f = existingTable();
    await expect(
      buildFormFromSpec(
        f.store,
        {
          name: 'Survey',
          table: f.table.subject,
          pages: [
            {
              name: 'Page',
              fields: fields as FormSpec['pages'][number]['fields'],
            },
          ],
        },
        f.opts,
      ),
    ).rejects.toThrow();
    expect(f.store.newResource).not.toHaveBeenCalled();
  });

  it('rejects missing choice options before creating a standalone schema', async () => {
    const f = fixture();
    await expect(
      buildFormFromSpec(
        f.store,
        {
          name: 'Survey',
          pages: [{ name: 'Page', fields: [{ label: 'Pick', type: 'radio' }] }],
        },
        f.opts,
      ),
    ).rejects.toThrow('Provide choices');
    expect(f.store.newResource).not.toHaveBeenCalled();
  });
});
