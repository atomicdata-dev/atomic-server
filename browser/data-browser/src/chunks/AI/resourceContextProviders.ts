// @wc-ignore-file
/**
 * Per-class context providers (phase 2 of planning/json-ad-compact.md): when
 * a resource is attached to a chat or read via get_atomic_resource, the
 * matching provider expands it into what a person viewing it actually sees,
 * so acting on "this <thing>" needs no discovery tool calls. Tables carry
 * their row schema + rows, chatrooms their recent messages, folders their
 * children, ontologies their classes and properties, documents their body.
 *
 * A provider may return a text block (appended after the resource's compact
 * JSON) and/or enrich the compact object itself (documents set
 * `_documentContent` and strip the raw Loro body).
 */
import {
  CollectionBuilder,
  commits,
  core,
  dataBrowser,
  type Core,
  type Resource,
  type Store,
} from '@tomic/react';
import { shortenSubject } from '@tomic/react';
import { getDocumentContentForAgent } from './getDocumentContentForAgent';
import { hasDocumentContent } from '@chunks/RTE/readDocumentV2TiptapJson';
import { buildClassContext, describeClassCompact } from '@tomic/react';
import { getTableContextForAgent } from './tableContextProvider';

const MESSAGE_SAMPLE_LIMIT = 10;
const FOLDER_CHILD_LIMIT = 50;

/**
 * Renders the chatroom's message count and its last {@link
 * MESSAGE_SAMPLE_LIMIT} messages (oldest first, like the chat view), plus a
 * recipe for posting and for paging further back.
 */
const getChatroomContextForAgent = async (
  store: Store,
  chatroom: Resource,
): Promise<string> => {
  const collection = new CollectionBuilder(store)
    .setProperty(core.properties.parent)
    .setValue(chatroom.subject)
    .setFilters([
      { property: core.properties.isA, value: dataBrowser.classes.message },
    ])
    .setSortBy(commits.properties.createdAt)
    .setSortDesc(true)
    .setPageSize(MESSAGE_SAMPLE_LIMIT)
    .build();

  // Newest page first; fetching it also populates totalMembers.
  const newestFirst = await collection.getMembersOnPage(0);
  const total = collection.totalMembers;

  const lines: string[] = [];

  for (const subject of [...newestFirst].reverse()) {
    const message = await store.getResource(subject);

    if (message.error) {
      continue;
    }

    const text = message.get(core.properties.description) ?? '';
    const createdAt = message.getCreatedAt();
    const createdBy = message.getCreatedBy();
    const author = createdBy
      ? (await store.getResource(createdBy)).title
      : 'unknown';
    const time = createdAt ? new Date(createdAt).toISOString() : '';

    lines.push(
      `[${time}] ${author} (${shortenSubject(subject)}): ${text}`.trim(),
    );
  }

  const shownNote =
    total > lines.length ? ` (last ${lines.length} shown, oldest first)` : '';

  return [
    `Messages: ${total}${shownNote}`,
    ...lines,
    `To post a message: create_resource with {"@class": "${dataBrowser.classes.message}", "@parent": "${shortenSubject(chatroom.subject)}", "description": "<text>"}. To read older messages: query with class "${dataBrowser.classes.message}" and where [{"property": "${core.properties.parent}", "value": "${shortenSubject(chatroom.subject)}"}].`,
  ].join('\n');
};

/** Lists the folder's children as `- Title (#ref) [class]`. */
const getFolderContextForAgent = async (
  store: Store,
  folder: Resource,
): Promise<string> => {
  const collection = new CollectionBuilder(store)
    .setProperty(core.properties.parent)
    .setValue(folder.subject)
    .setPageSize(FOLDER_CHILD_LIMIT)
    .build();

  const children = await collection.getMembersOnPage(0);
  const total = collection.totalMembers;

  const lines: string[] = [];

  for (const subject of children) {
    const child = await store.getResource(subject);

    if (child.error) {
      continue;
    }

    const classSubject = child.getClasses()[0];
    const classTitle = classSubject
      ? (await store.getResource(classSubject)).title
      : '';

    lines.push(
      `- ${child.title} (${shortenSubject(subject)})${classTitle ? ` [${classTitle}]` : ''}`,
    );
  }

  const shownNote =
    total > lines.length ? ` (${lines.length} of ${total} shown)` : '';

  return [`Contains: ${total} resources${shownNote}`, ...lines].join('\n');
};

/** Lists the ontology's classes (as compact schema signatures) and
 *  standalone properties. */
const getOntologyContextForAgent = async (
  store: Store,
  ontology: Resource,
): Promise<string> => {
  const classSubjects = (ontology.get(core.properties.classes) ??
    []) as string[];
  const propertySubjects = (ontology.get(core.properties.properties) ??
    []) as string[];

  const lines: string[] = [];

  if (classSubjects.length > 0) {
    lines.push('Classes:');

    for (const classSubject of classSubjects) {
      const ctx = await buildClassContext(store, [classSubject]);
      lines.push(
        `- ${describeClassCompact(ctx, classSubject)} (${shortenSubject(classSubject)})`,
      );
    }
  }

  if (propertySubjects.length > 0) {
    lines.push('Properties:');

    for (const propertySubject of propertySubjects) {
      const property = await store.getResource<Core.Property>(propertySubject);

      if (property.error) {
        continue;
      }

      const datatypeName = (property.props.datatype as string | undefined)
        ?.split('/')
        .pop();

      lines.push(
        `- ${property.props.shortname}${datatypeName ? ` [${datatypeName}]` : ''} (${shortenSubject(propertySubject)})`,
      );
    }
  }

  return lines.join('\n');
};

/**
 * Documents don't add a text block; they enrich the compact object: the raw
 * Loro body is replaced with agent-readable `_documentContent` (TipTap XML) —
 * the shape edit_document_resource expects.
 */
const enrichDocumentCompact = async (
  store: Store,
  document: Resource,
  compact: Record<string, unknown>,
): Promise<void> => {
  delete compact[dataBrowser.properties.documentContent];

  const contentProperty = await store.getResource(
    dataBrowser.properties.documentContent,
  );
  const contentShortname = contentProperty.get(core.properties.shortname) as
    | string
    | undefined;

  if (contentShortname) {
    delete compact[contentShortname];
  }

  const content = getDocumentContentForAgent(document, store);
  compact._documentContent = content.ok ? content.text : null;

  if (!content.ok) {
    compact._documentContentError = content.error;
  }
};

/**
 * Applies the class-specific provider for an attached or read resource.
 * Returns the extra context block (if the class has one) and may enrich the
 * passed compact object in place.
 */
export const getClassContextForAgent = async (
  store: Store,
  resource: Resource,
  compact?: Record<string, unknown>,
): Promise<string | undefined> => {
  if (compact && hasDocumentContent(resource)) {
    await enrichDocumentCompact(store, resource, compact);

    return resource.hasClasses(dataBrowser.classes.meeting)
      ? getChatroomContextForAgent(store, resource)
      : undefined;
  }

  if (resource.hasClasses(dataBrowser.classes.table)) {
    return getTableContextForAgent(store, resource);
  }

  if (resource.hasClasses(dataBrowser.classes.chatroom)) {
    return getChatroomContextForAgent(store, resource);
  }

  if (resource.hasClasses(dataBrowser.classes.folder)) {
    return getFolderContextForAgent(store, resource);
  }

  if (resource.hasClasses(core.classes.ontology)) {
    return getOntologyContextForAgent(store, resource);
  }

  return undefined;
};
