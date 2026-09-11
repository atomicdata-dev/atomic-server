import { describe, expect, it } from 'vitest';
import { TEMPLATE_CATALOG } from './catalog';
import { planTemplate, type TemplateDefinition } from './model';
import { TABLE_TEMPLATES } from '../TablePage/tableTemplates';
describe('shared template planning', () => {
  it('composes the exact table catalog into a workspace without copying schemas', () => {
    const workspace = TEMPLATE_CATALOG.find(t => t.id === 'student')!;
    const before = JSON.stringify(TEMPLATE_CATALOG);
    const plan = planTemplate(workspace, TEMPLATE_CATALOG);
    expect(plan.parts[0]).toEqual({
      key: 'project-tasks/table',
      kind: 'table',
      catalogId: 'project-tasks',
      name: 'Assignments',
    });
    expect(plan.examples).toBe(false);
    expect(JSON.stringify(TEMPLATE_CATALOG)).toBe(before);
    const single = planTemplate(
      TEMPLATE_CATALOG.find(t => t.id === 'table/project-tasks')!,
      TEMPLATE_CATALOG,
    );
    expect(single.parts[0]).toMatchObject({
      kind: 'table',
      catalogId: 'project-tasks',
    });
  });
  it('resolves every built-in workspace and table against the existing catalog', () => {
    for (const template of TEMPLATE_CATALOG) {
      for (const part of planTemplate(template, TEMPLATE_CATALOG).parts) {
        if (part.kind === 'table')
          expect(
            TABLE_TEMPLATES.find(t => t.id === part.catalogId)?.spec,
          ).toBeDefined();
      }
    }
  });
  it('keeps examples a mode of the same release', () => {
    const source = TEMPLATE_CATALOG.find(t => t.id === 'student')!;
    expect(planTemplate(source, TEMPLATE_CATALOG, true)).toEqual({
      ...planTemplate(source, TEMPLATE_CATALOG),
      examples: true,
    });
  });
  it('rejects cycles, duplicate keys and unavailable pinned versions before writes', () => {
    const source: TemplateDefinition = {
      id: 'cycle',
      version: '1',
      title: '',
      description: '',
      icon: '',
      entryPoints: ['workspace'],
      parts: [
        { kind: 'template', key: 'child', template: 'cycle', version: '1' },
      ],
    };
    expect(() => planTemplate(source, [source])).toThrow('Circular');
    expect(() => planTemplate({ ...source, version: '2' }, [])).toThrow(
      'Missing',
    );
    expect(() =>
      planTemplate(
        {
          ...source,
          parts: [
            { key: 'x', kind: 'document', name: '', text: '' },
            { key: 'x', kind: 'document', name: '', text: '' },
          ],
        },
        [],
      ),
    ).toThrow('Duplicate');
  });
});
