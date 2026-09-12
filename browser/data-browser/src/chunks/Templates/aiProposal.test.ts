import { describe, expect, it } from 'vitest';
import { parseTemplateProposal } from './aiProposal';
import { TEMPLATE_CATALOG } from './catalog';
import { planTemplate } from './model';
const draft = {
  message: 'Start with tasks and notes.',
  title: 'Study',
  tables: ['table/project-tasks', 'table/project-tasks'],
  documents: [{ name: 'Notes', text: 'Questions to explore' }],
};
describe('AI template proposals', () => {
  it('resolves through the same catalog and deduplicates table selections', () => {
    const proposal = parseTemplateProposal(
      JSON.stringify(draft),
      TEMPLATE_CATALOG,
    );
    const plan = planTemplate(proposal, TEMPLATE_CATALOG);
    expect(plan.parts).toHaveLength(2);
    expect(plan.examples).toBe(false);
    expect(plan.parts[0]).toMatchObject({
      kind: 'table',
      catalogId: 'project-tasks',
    });
  });
  it('rejects invented dependencies and oversized proposals before writing', () => {
    expect(() =>
      parseTemplateProposal(
        JSON.stringify({ ...draft, tables: ['https://example.org/code'] }),
        TEMPLATE_CATALOG,
      ),
    ).toThrow();
    expect(() =>
      parseTemplateProposal(
        JSON.stringify({
          ...draft,
          documents: Array(7).fill(draft.documents[0]),
        }),
        TEMPLATE_CATALOG,
      ),
    ).toThrow();
    expect(() => parseTemplateProposal('not json', TEMPLATE_CATALOG)).toThrow();
  });
  it('drops undeclared permissions and executable fields', () => {
    const proposal = parseTemplateProposal(
      JSON.stringify({ ...draft, write: ['attacker'], script: 'alert(1)' }),
      TEMPLATE_CATALOG,
    );
    expect(proposal).not.toHaveProperty('write');
    expect(proposal).not.toHaveProperty('script');
  });
});
