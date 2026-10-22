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
    parts: [
      table('project-tasks'),
      table('reading-list'),
      table('bookmarks'),
      {
        key: 'notes',
        kind: 'document',
        name: 'Notes',
        text: '',
        exampleText: 'Ideas\n\nWrite down anything worth coming back to.',
      },
    ],
  },
  {
    id: 'welcome',
    version,
    title: 'Welcome to Atomic',
    icon: '👋',
    description: 'The drive a new person starts in.',
    // Not offered in the gallery: `startWelcomeDrive` builds it.
    entryPoints: [],
    parts: [
      {
        key: 'welcome',
        kind: 'document',
        name: 'Welcome to Atomic',
        text: [
          'Welcome to Atomic. This is a small drive to play in, at your own pace. There is nothing you have to do.',
          'Everything here is stored on this device and belongs only to you. Only you can read it, unless you share it.',
          'You can edit, rename or delete anything in this drive, including this document. Try it: the sidebar has a document, a table and a canvas.',
          'The browser app and the mobile apps use the same data. The browser app can do everything; the mobile apps offer a focused subset, and it is still growing.',
          'Keep your work safe: for now it only exists on this device. Save your secret, or connect an account or another device, to keep it somewhere else too. You will find these under Settings and on the Sync page.',
        ].join('\n'),
      },
      {
        key: 'notes',
        kind: 'document',
        name: 'Notes',
        text: 'Type something here, then select it to make it bold, a heading or a list.',
      },
      table('project-tasks', 'Tasks'),
      { key: 'sketch', kind: 'canvas', name: 'Sketch' },
    ],
  },
];
