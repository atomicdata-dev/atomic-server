import { ai, canvas, core, dataBrowser } from '@tomic/lib';
import { TABLE_TEMPLATES } from '../../chunks/TablePage/tableTemplates';
import { templates } from '../../components/Template/template';

export const BASIC_CREATIONS = [
  {
    subject: dataBrowser.classes.table,
    title: 'Table',
    description: 'Organize data in rows, boards and other views.',
  },
  {
    subject: dataBrowser.classes.documentV2,
    title: 'Document',
    description: 'Write notes, plans or something worth sharing.',
  },
  {
    subject: dataBrowser.classes.folder,
    title: 'Folder',
    description: 'Keep related work together.',
  },
  {
    subject: dataBrowser.classes.dashboard,
    title: 'Dashboard',
    description: 'Bring tables, charts and resources together.',
  },
  {
    subject: dataBrowser.classes.meeting,
    title: 'Meeting',
    description: 'Capture a conversation and its notes.',
  },
  {
    subject: dataBrowser.classes.chatroom,
    title: 'Chat room',
    description: 'Start a conversation with your team.',
  },
  {
    subject: dataBrowser.classes.bookmark,
    title: 'Bookmark',
    description: 'Save a link for later.',
  },
  {
    subject: canvas.classes.canvas,
    title: 'Canvas',
    description: 'Arrange ideas on a shared canvas.',
  },
  {
    subject: core.classes.ontology,
    title: 'Ontology',
    description: 'Define reusable resource types and properties.',
  },
  {
    subject: ai.classes.aiChat,
    title: 'AI chat',
    description: 'Start a dedicated conversation with an assistant.',
  },
];
export function matchesCreationSearch(
  query: string,
  ...values: string[]
): boolean {
  const haystack = values.join(' ').toLocaleLowerCase();

  return query
    .trim()
    .toLocaleLowerCase()
    .split(/\s+/)
    .every(word => haystack.includes(word));
}
export const CREATION_TABLE_TEMPLATES = TABLE_TEMPLATES.filter(t => t.spec);
export const CREATION_PAGE_TEMPLATES = templates;
