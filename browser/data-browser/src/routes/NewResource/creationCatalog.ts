import { ai, canvas, core, dataBrowser, forms } from '@tomic/lib';
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
    subject: forms.classes.form,
    title: 'Form',
    description: 'Collect answers from anyone with a link, into a table.',
  },
  {
    subject: ai.classes.aiChat,
    title: 'AI chat',
    description: 'Start a dedicated conversation with an assistant.',
  },
];

/**
 * These classes are minted per drive, so they must be offered before they exist.
 *
 * `searchOnly` ones stay out of the Start blank grid. A blank Website or App is
 * only a starting point for the assistant: without it, an App's code cannot be
 * changed from its page and a Website's design cannot be changed at all. They
 * still turn up when searched for by name, so they can be made without AI.
 */
export const DRIVE_CREATIONS = [
  {
    shortname: 'plugin-script',
    title: 'Plugin',
    description:
      'Create a script or automation and review its proposed changes.',
  },
  {
    shortname: 'website-project',
    title: 'Website',
    description: 'Build a website from your documents and tables.',
    searchOnly: true,
  },
  {
    shortname: 'app',
    title: 'App',
    description: 'Create an interactive app backed by its own data.',
    searchOnly: true,
  },
] as const;

export type DriveCreation = (typeof DRIVE_CREATIONS)[number]['shortname'];

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

/**
 * Offer assistant-filled alternatives to the blank starters above.
 *
 * Every seed is deliberately unfinished. A suggestion puts its seed in the
 * composer with the caret at the end instead of sending it, because "build me
 * an app" on its own tells the assistant nothing and it would only have to ask
 * the same question back.
 */
export const AI_BUILD_SUGGESTIONS: AIBuildSuggestion[] = [
  {
    id: 'app',
    title: 'App',
    seed: 'Build an app that ',
    shortname: 'app',
  },
  {
    id: 'website',
    title: 'Website',
    seed: 'Build a website for ',
    shortname: 'website-project',
  },
  {
    id: 'dashboard',
    title: 'Dashboard',
    seed: 'Build a dashboard showing ',
    subject: dataBrowser.classes.dashboard,
  },
  {
    id: 'table',
    title: 'Custom table',
    seed: 'Build a table for tracking ',
    subject: dataBrowser.classes.table,
  },
];

export interface AIBuildSuggestion {
  id: string;
  title: string;
  seed: string;
  /** The class whose icon this wears, for the ones with a fixed subject. */
  subject?: string;
  /** Used instead for App and Website, which are minted per drive. */
  shortname?: string;
}

/**
 * Whether the composer still holds nothing but a suggestion.
 *
 * Suggestions replace what is in the composer, so they are only offered while
 * there is nothing of the user's own to lose. Setting a textarea's value from
 * code does not go on the browser's undo stack, so a click that wiped a
 * half-written description could not be taken back.
 */
export function isUntouchedSuggestion(prompt: string): boolean {
  return (
    prompt === '' || AI_BUILD_SUGGESTIONS.some(item => item.seed === prompt)
  );
}
