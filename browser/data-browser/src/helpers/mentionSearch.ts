import { core, type Resource, type Store } from '@tomic/react';
import { getRecentResources } from './recentResources';

export const MAX_MENTION_SUGGESTIONS = 10;

/** With nothing typed yet, offer what the user opened recently in this drive,
 * topped up with the drive's own children so a fresh drive isn't empty. */
const getSubjectsWithoutQuery = async (
  store: Store,
  drive: string,
  exclude: string | undefined,
): Promise<string[]> => {
  const subjects = getRecentResources(drive).filter(s => s !== exclude);

  if (subjects.length < MAX_MENTION_SUGGESTIONS) {
    try {
      const driveResource = await store.getResource(drive);
      const children = await driveResource.getChildrenCollection(
        MAX_MENTION_SUGGESTIONS,
      );

      for (const child of await children.getMembersOnPage(0)) {
        if (child !== exclude && !subjects.includes(child)) {
          subjects.push(child);
        }
      }
    } catch (e) {
      console.error('Could not list drive children for @ mentions', e);
    }
  }

  const resources = await Promise.all(
    subjects.map(subject => store.getResource(subject)),
  );

  // Recents can point at resources that were deleted or are no longer
  // readable since they were opened.
  return resources
    .filter(r => !r.error && r.title)
    .slice(0, MAX_MENTION_SUGGESTIONS)
    .map(r => r.subject);
};

/** Subjects to offer for an `@` mention in `drive`: a search for `query`, or
 * recent/child resources when nothing is typed yet. Shared by the document
 * editor and the chat composer. */
export const findMentionSubjects = async (
  store: Store,
  drive: string,
  query: string,
  exclude?: string,
): Promise<string[]> =>
  query.trim()
    ? store.search(query.toLowerCase(), {
        limit: MAX_MENTION_SUGGESTIONS,
        // Including the results could lead to weird behavior when the document itself is returned from the server.
        include: false,
        parents: [drive],
      })
    : getSubjectsWithoutQuery(store, drive, exclude);

/** Whether an agent matches a (lowercased, trimmed) typed query by subject,
 * name or shortname. Shared with the table cell resource search. */
export const agentMatchesQuery = (
  subject: string,
  resource: Resource | undefined,
  needle: string,
): boolean => {
  const name = String(resource?.get(core.properties.name) ?? '');
  const shortname = String(resource?.get(core.properties.shortname) ?? '');

  return (
    subject.toLowerCase().includes(needle) ||
    name.toLowerCase().includes(needle) ||
    shortname.toLowerCase().includes(needle)
  );
};

/** Agents with direct read or write rights on the drive whose name matches
 * `query`. Agents live outside the drive, so search never finds them. */
export const findMemberSubjects = async (
  store: Store,
  drive: string,
  query: string,
): Promise<string[]> => {
  const needle = query.trim().toLowerCase();

  if (!needle) return [];

  const driveResource = await store.getResource(drive);
  const writers = (driveResource.get(core.properties.write) ?? []) as string[];
  const readers = (driveResource.get(core.properties.read) ?? []) as string[];
  const members = [...new Set([...writers, ...readers])];
  const resources = await Promise.all(members.map(m => store.getResource(m)));

  return members
    .filter((m, i) => agentMatchesQuery(m, resources[i], needle))
    .slice(0, MAX_MENTION_SUGGESTIONS);
};
