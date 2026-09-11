// @wc-ignore-file
import { TABLE_TEMPLATES } from '../TablePage/tableTemplates';
import type { TemplateDefinition, TemplatePart } from './model';
const version = '1';
const table = (id: string, name?: string): TemplatePart => ({
  key: id,
  kind: 'template',
  template: `table/${id}`,
  version,
  name,
});

/** Table definitions remain owned by TABLE_TEMPLATES; workspaces compose them. */
export const TEMPLATE_CATALOG: TemplateDefinition[] = [
  ...TABLE_TEMPLATES.filter(t => t.spec).map(t => ({
    id: `table/${t.id}`,
    version,
    title: t.title,
    description: t.description,
    icon: '▦',
    entryPoints: ['table'] as TemplateDefinition['entryPoints'],
    parts: [
      { key: 'table', kind: 'table' as const, catalogId: t.id, name: t.title },
    ],
  })),
  {
    id: 'student',
    version,
    title: 'Student',
    icon: '🎓',
    description: 'Assignments, reading and a place for your notes.',
    entryPoints: ['workspace'],
    parts: [
      table('project-tasks', 'Assignments'),
      table('reading-list'),
      {
        key: 'notes',
        kind: 'document',
        name: 'Lecture notes',
        text: '',
        exampleText:
          'Introduction to biology\n\nLiving systems exchange energy and information.\n\nQuestions to explore\nHow do cells respond to changes in their environment?',
      },
    ],
  },
  {
    id: 'team',
    version,
    title: 'Team',
    icon: '🧩',
    description: 'Projects, shared knowledge and meeting notes.',
    entryPoints: ['workspace'],
    parts: [
      table('project-tasks'),
      table('issue-tracker'),
      {
        key: 'wiki',
        kind: 'document',
        name: 'Team handbook',
        text: '',
        exampleText:
          'Welcome to the team\n\nWe keep decisions in writing and make room for focused work.',
      },
      {
        key: 'meetings',
        kind: 'document',
        name: 'Meeting notes',
        text: '',
        exampleText:
          'Weekly planning\n\nWhat went well?\nWhat should we focus on next?',
      },
    ],
  },
  {
    id: 'personal',
    version,
    title: 'Personal',
    icon: '🌱',
    description: 'Reading, projects and everyday ideas.',
    entryPoints: ['workspace'],
    parts: [table('project-tasks'), table('reading-list'), table('bookmarks')],
  },
  {
    id: 'interactive-demo',
    version,
    title: 'Meet the demo team',
    icon: '👋',
    description: 'Explore a live workspace with scripted teammates.',
    entryPoints: ['workspace'],
    parts: [{ key: 'demo', kind: 'interactive-demo' }],
  },
];
