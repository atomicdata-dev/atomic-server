import { describe, expect, it, vi } from 'vitest';
import { core, dataBrowser, forms, Datatype } from '@tomic/react';
import { buildFormFromSpec } from './createFormFromSpec';
import { formTestFixture } from './formTestFixture';
import {
  configureForm,
  configureFormPage,
  configureFormField,
  describeForm,
  configureFormFieldSchema,
} from './formOps';
import { z } from 'zod';

vi.mock('@components/Tag/tagColours', () => ({ tagColours: ['blue'] }));

async function fixture() {
  const f = formTestFixture();
  const result = await buildFormFromSpec(
    f.store,
    {
      name: 'Survey',
      pages: [
        {
          name: 'Start',
          fields: [
            { label: 'Email', type: 'email' },
            { label: 'Role', type: 'radio', choices: ['Engineer', 'Designer'] },
          ],
        },
        { name: 'End', fields: [{ label: 'Thanks', type: 'paragraph' }] },
      ],
    },
    f.opts,
  );
  const form = f.resources.get(result.form)!;
  const page = f.resources.get(result.pages[0].subject)!;
  const email = f.resources.get(result.pages[0].fields[0].subject)!;
  const role = f.resources.get(result.pages[0].fields[1].subject)!;
  const property = f.resources.get(
    role.get(forms.properties.formMapsTo) as string,
  )!;
  f.saved.length = 0;

  return { ...f, result, form, page, email, role, property };
}

describe('form inspection and configuration', () => {
  it('describes the complete ordered graph and stable choice identities', async () => {
    const f = await fixture();
    const result = await describeForm(f.store, f.form.subject);
    expect(result.name).toBe('Survey');
    expect(result.ownsSchema).toBe(true);
    expect(result.pages.map(p => p.name)).toEqual(['Start', 'End']);
    expect(result.pages[0].fields[0]).toMatchObject({
      subject: f.email.subject,
      label: 'Email',
      type: 'email',
      required: false,
    });
    expect(result.pages[0].fields[1].choices.map(c => c.subject)).toEqual(
      f.property.getSubjects(core.properties.allowsOnly),
    );
    expect(result.pages[1].fields[0]).toMatchObject({
      type: 'paragraph',
      label: 'Thanks',
    });
    expect(result.columns.some(c => c.subject === f.property.subject)).toBe(
      true,
    );
    expect(f.saved).toEqual([]);
  });

  it('patches JSON keys, including serialized JSON, preserving other settings and publication', async () => {
    const f = await fixture();
    await f.form.set(
      forms.properties.formStyling,
      JSON.stringify({
        mainColor: 'red',
        showProgressBar: true,
        saveDrafts: false,
      }),
    );
    await f.form.set(forms.properties.formPublishedAt, 123);
    await configureForm(f.store, {
      form: f.form.subject,
      name: 'Renamed',
      styling: { mainColor: 'blue', showProgressBar: null },
    });
    expect(f.form.get(forms.properties.formStyling)).toEqual({
      mainColor: 'blue',
      saveDrafts: false,
    });
    expect(f.form.get(forms.properties.formPublishedAt)).toBe(123);
    expect(f.form.getSubjects(forms.properties.formPages)).toHaveLength(2);
  });

  it('adds, edits, reorders and removes an empty page without replacing existing pages', async () => {
    const f = await fixture();
    const added = await configureFormPage(f.store, {
      form: f.form.subject,
      name: 'Extra',
    });
    expect(added.page).toBeDefined();
    await configureFormPage(f.store, {
      form: f.form.subject,
      page: 'Extra',
      name: 'Last',
    });
    await configureForm(f.store, {
      form: f.form.subject,
      pageOrder: ['Last', 'Start', 'End'],
    });
    expect(f.form.getSubjects(forms.properties.formPages)[0]).toBe(added.page);
    await configureFormPage(f.store, {
      form: f.form.subject,
      page: 'Last',
      remove: true,
    });
    expect(f.resources.get(added.page!)!.destroy).toHaveBeenCalledOnce();
    expect(f.form.getSubjects(forms.properties.formPages)).toEqual(
      f.result.pages.map(p => p.subject),
    );
  });

  it('patches field presentation without changing the mapped Property', async () => {
    const f = await fixture();
    const property = f.resources.get(
      f.email.get(forms.properties.formMapsTo) as string,
    )!;
    const before = vi.mocked(property.save).mock.calls.length;
    await f.email.set(
      forms.properties.formFieldOptions,
      JSON.stringify({ placeholder: 'old', maxLength: 100 }),
    );
    await configureFormField(f.store, {
      form: f.form.subject,
      page: 'Start',
      field: 'Email',
      label: 'Contact',
      type: 'short-text',
      required: true,
      options: { placeholder: 'new' },
    });
    expect(f.email.get(forms.properties.formFieldOptions)).toMatchObject({
      placeholder: 'new',
      maxLength: 100,
    });
    expect(f.email.get(forms.properties.required)).toBe(true);
    expect(f.email.get(forms.properties.formFieldType)).toBe('short-text');
    expect(vi.mocked(property.save).mock.calls.length).toBe(before);
  });

  it('renames/reorders choice Tags by identity, adds choices and retains removed Tags', async () => {
    const f = await fixture();
    const [engineer, designer] = f.property.getSubjects(
      core.properties.allowsOnly,
    );
    await configureFormField(f.store, {
      form: f.form.subject,
      page: 'Start',
      field: 'Role',
      choices: [
        { subject: designer, label: 'Product Designer' },
        { label: 'Other' },
      ],
    });
    const tags = f.property.getSubjects(core.properties.allowsOnly);
    expect(tags[0]).toBe(designer);
    expect(f.resources.get(designer)!.get(core.properties.name)).toBe(
      'Product Designer',
    );
    expect(tags).toHaveLength(2);
    expect(f.resources.get(engineer)!.destroy).not.toHaveBeenCalled();
    expect(f.role.get(forms.properties.formMapsTo)).toBe(f.property.subject);
  });

  it('adds typed questions and layout blocks and can remove presentation without deleting data', async () => {
    const f = await fixture();
    const added = await configureFormField(f.store, {
      form: f.form.subject,
      page: 'End',
      label: 'Rating',
      type: 'rating',
      required: true,
    });
    expect(
      f.resources.get(added.property!)!.get(core.properties.datatype),
    ).toBe(Datatype.INTEGER);
    const box = await configureFormField(f.store, {
      form: f.form.subject,
      page: 'End',
      label: 'Remember this',
      type: 'info-box',
      infoBoxStyle: 'warning',
    });
    expect(
      f.resources.get(box.field!)!.get(forms.properties.formInfoBoxStyle),
    ).toBe('warning');
    await configureFormField(f.store, {
      form: f.form.subject,
      page: 'End',
      field: added.field,
      remove: true,
    });
    expect(f.resources.get(added.field!)!.destroy).toHaveBeenCalledOnce();
    expect(f.resources.get(added.property!)!.destroy).not.toHaveBeenCalled();
  });

  it('rejects edits to fields or pages outside the selected form', async () => {
    const f = await fixture();
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'Start',
        field: f.result.pages[1].fields[0].subject,
        label: 'Oops',
      }),
    ).rejects.toThrow('Unknown');
    await expect(
      configureFormPage(f.store, {
        form: f.form.subject,
        page: 'Missing',
        name: 'Oops',
      }),
    ).rejects.toThrow('Unknown');
    expect(f.saved).toEqual([]);
  });

  it('rejects incompatible types and inline choice source mutations before any writes', async () => {
    const f = await fixture();
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'Start',
        field: 'Email',
        label: 'Oops',
        type: 'number',
      }),
    ).rejects.toThrow('Incompatible');
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'Start',
        field: 'Role',
        type: 'multi-select',
      }),
    ).rejects.toThrow('Incompatible');
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'Start',
        field: 'Role',
        options: { options: [] } as never,
      }),
    ).rejects.toThrow('Unrecognized key');
    expect(f.saved).toEqual([]);
    expect(f.email.get(core.properties.name)).toBe('Email');
  });

  it('rejects incomplete/duplicate ordering and nonempty page deletion', async () => {
    const f = await fixture();
    await expect(
      configureForm(f.store, {
        form: f.form.subject,
        name: 'Oops',
        pageOrder: ['Start', 'Start'],
      }),
    ).rejects.toThrow('every');
    await expect(
      configureFormPage(f.store, {
        form: f.form.subject,
        page: 'Start',
        fieldOrder: ['Email'],
      }),
    ).rejects.toThrow('every');
    await expect(
      configureFormPage(f.store, {
        form: f.form.subject,
        page: 'Start',
        remove: true,
      }),
    ).rejects.toThrow('empty');
    expect(f.saved).toEqual([]);
    expect(f.form.get(core.properties.name)).toBe('Survey');
  });

  it('guards condition dependencies when deleting or reordering fields and pages', async () => {
    const f = await fixture();
    const condition = f.make({
      [forms.properties.formConditionField]: f.email.subject,
      [forms.properties.formConditionOperator]: 'not-empty',
    });
    await f.role.set(forms.properties.formConditions, [condition.subject]);
    await expect(
      configureFormPage(f.store, {
        form: f.form.subject,
        page: 'Start',
        fieldOrder: ['Role', 'Email'],
      }),
    ).rejects.toThrow('condition');
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'Start',
        field: 'Email',
        remove: true,
      }),
    ).rejects.toThrow('condition');
    await f.resources
      .get(f.result.pages[1].subject)!
      .set(forms.properties.formConditions, [condition.subject]);
    await expect(
      configureForm(f.store, {
        form: f.form.subject,
        pageOrder: ['End', 'Start'],
      }),
    ).rejects.toThrow('condition');
    expect(f.saved).toEqual([]);
  });

  it('requires subjects to disambiguate duplicate field labels', async () => {
    const f = await fixture();
    await f.role.set(core.properties.name, 'Email');
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'Start',
        field: 'Email',
        label: 'Oops',
      }),
    ).rejects.toThrow('ambiguous');
    await configureFormField(f.store, {
      form: f.form.subject,
      page: 'Start',
      field: f.email.subject,
      label: 'Correct',
    });
    expect(f.email.get(core.properties.name)).toBe('Correct');
  });

  it('protects shared choices and required columns while allowing unused column mapping', async () => {
    const f = await fixture();
    await f.form.set(forms.properties.formOwnsSchema, false);
    const cls = f.resources.get(f.result.class)!;
    const emailProperty = f.email.get(forms.properties.formMapsTo) as string;
    await cls.set(core.properties.requires, [emailProperty]);
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'Start',
        field: 'Email',
        required: false,
      }),
    ).rejects.toThrow('required');
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'Start',
        field: 'Email',
        remove: true,
      }),
    ).rejects.toThrow('required');
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'Start',
        field: 'Role',
        choices: [{ label: 'Other' }],
      }),
    ).rejects.toThrow('form-owned');
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'End',
        label: 'New',
        type: 'number',
      }),
    ).rejects.toThrow('existing');
    expect(f.saved).toEqual([]);
    const added = await configureFormField(f.store, {
      form: f.form.subject,
      page: 'End',
      label: 'Your name',
      type: 'short-text',
      column: 'name',
    });
    expect(added.property).toBe(core.properties.name);
    expect(
      f.saved.every(
        s => s.subject !== cls.subject && s.subject !== core.properties.name,
      ),
    ).toBe(true);
  });

  it('reorders fields and creates a choice question with exactly the requested Tags', async () => {
    const f = await fixture();
    await configureFormPage(f.store, {
      form: f.form.subject,
      page: 'Start',
      fieldOrder: ['Role', 'Email'],
    });
    expect(f.page.getSubjects(forms.properties.formFields)).toEqual([
      f.role.subject,
      f.email.subject,
    ]);
    const added = await configureFormField(f.store, {
      form: f.form.subject,
      page: 'End',
      label: 'Contact method',
      type: 'dropdown',
      choices: [{ label: 'Email' }, { label: 'Phone' }],
    });
    const property = f.resources.get(added.property!)!;
    expect(property.get(dataBrowser.properties.max)).toBe(1);
    expect(
      property
        .getSubjects(core.properties.allowsOnly)
        .map(s => f.resources.get(s)!.get(core.properties.name)),
    ).toEqual(['Email', 'Phone']);
  });

  it('rejects duplicate or foreign choice subjects and leaves all Tags untouched', async () => {
    const f = await fixture();
    const tag = f.property.getSubjects(core.properties.allowsOnly)[0];
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'Start',
        field: 'Role',
        choices: [
          { subject: tag, label: 'One' },
          { subject: tag, label: 'Two' },
        ],
      }),
    ).rejects.toThrow('distinct');
    await expect(
      configureFormField(f.store, {
        form: f.form.subject,
        page: 'Start',
        field: 'Role',
        choices: [{ subject: f.email.subject, label: 'Other' }],
      }),
    ).rejects.toThrow('distinct');
    expect(f.saved).toEqual([]);
  });

  it('keeps the last page even when empty', async () => {
    const f = formTestFixture();
    const created = await buildFormFromSpec(
      f.store,
      { name: 'Empty', pages: [{ name: 'Only', fields: [] }] },
      f.opts,
    );
    f.saved.length = 0;
    await expect(
      configureFormPage(f.store, {
        form: created.form,
        page: 'Only',
        remove: true,
      }),
    ).rejects.toThrow('last page');
    expect(f.saved).toEqual([]);
  });

  it('emits a finite JSON schema for the AI SDK, including nested JSON patches', () => {
    const schema = z.toJSONSchema(configureFormFieldSchema);
    expect(JSON.stringify(schema)).toContain('choices');
  });
});
