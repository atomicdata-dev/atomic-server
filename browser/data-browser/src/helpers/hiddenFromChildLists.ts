import { ai, dataBrowser, isAgentSubject } from '@tomic/lib';

/**
 * Classes kept out of child lists (the AI sidebar and meeting UI reach them),
 * with the plural label Space usage bundles them under.
 */
export const HIDDEN_CLASS_LABELS: Record<string, string> = {
  [ai.classes.aiChat]: 'AI chats',
  [dataBrowser.classes.meeting]: 'Meetings',
};

/**
 * Is a resource hidden from child lists? True for the classes above and for a
 * PlainText about an agent (a private note on that agent, see agentNotes.ts).
 * Any other `about` stays visible: users can set it on their own documents.
 */
export function isHiddenFromChildLists(
  classes: readonly string[],
  about?: string | null,
): boolean {
  if (classes.some(c => c in HIDDEN_CLASS_LABELS)) return true;

  return (
    !!about &&
    isAgentSubject(about) &&
    classes.includes(dataBrowser.classes.plainText)
  );
}
