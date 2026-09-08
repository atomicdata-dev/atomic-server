import {
  core,
  dataBrowser,
  enableLoro,
  type Resource,
  type Store,
} from '@tomic/react';
import type { JSONContent } from '@tiptap/core';
import {
  extractYDocBytes,
  isSerializedYDoc,
  isYjsMigrationCandidate,
  loroDocHasVisibleContent,
  resourceEmbedNode,
  tiptapJsonHasVisibleContent,
  wrapTiptapContent,
  yjsXmlFragmentToTiptapJSON,
} from './documentMigrationUtils';

const inFlight = new Map<string, Promise<boolean>>();

function markdownParseToContent(parsed: unknown): JSONContent[] {
  if (!parsed || typeof parsed !== 'object') {
    return [];
  }

  const rec = parsed as { content?: unknown; toJSON?: () => JSONContent };

  if (Array.isArray(rec.content)) {
    return rec.content as JSONContent[];
  }

  if (typeof rec.toJSON === 'function') {
    const json = rec.toJSON();

    return Array.isArray(json.content) ? json.content : [];
  }

  return [];
}

async function v1ElementsToTiptapDoc(
  resource: Resource,
  store: Store,
): Promise<{ doc: JSONContent; ownedParagraphs: Resource[] }> {
  const { MarkdownManager } = await import('@tiptap/markdown');
  const { getCollaborativeEditorSchema } =
    await import('@chunks/RTE/getCollaborativeEditorSchema');

  const { extensions } = getCollaborativeEditorSchema(store);
  const mdManager = new MarkdownManager({ extensions });

  const elements = (
    await Promise.allSettled(
      (resource.props.elements ?? []).map((element: string) =>
        store.getResource(element),
      ),
    )
  )
    .filter(
      (result): result is PromiseFulfilledResult<Resource> =>
        result.status === 'fulfilled',
    )
    .map(result => result.value);

  const tiptapContent: JSONContent[] = [];
  const ownedParagraphs: Resource[] = [];

  for (const element of elements) {
    if (element.hasClasses(dataBrowser.classes.paragraph)) {
      const description = element.get(core.properties.description);

      if (element.props.parent === resource.subject) {
        ownedParagraphs.push(element);
      }

      if (!description || typeof description !== 'string') {
        continue;
      }

      const parsed = mdManager.parse(description);
      const content = markdownParseToContent(parsed);

      if (content.length === 0) {
        continue;
      }

      tiptapContent.push(...content);
    } else {
      tiptapContent.push(resourceEmbedNode(element.subject));
    }
  }

  return { doc: wrapTiptapContent(tiptapContent), ownedParagraphs };
}

async function writeTiptapJsonToLoro(
  resource: Resource,
  store: Store,
  patchedJson: JSONContent,
): Promise<void> {
  await enableLoro();

  const loroDoc = resource.getLoroDoc();

  if (!loroDoc) {
    throw new Error('Loro failed to initialize while migrating a document');
  }

  const { applyPatchedJsonToLoroDocCollaborative } =
    await import('@chunks/RTE/applyPatchedJsonToLoroDocCollaborative');

  await applyPatchedJsonToLoroDocCollaborative({
    store,
    loroDoc,
    subject: resource.subject,
    patchedJson,
  });

  resource.markDirty();
}

async function yjsBytesToTiptapJSON(
  bytes: Uint8Array,
): Promise<JSONContent | undefined> {
  const Y = await import('yjs');

  const tryFragment = (apply: (doc: InstanceType<typeof Y.Doc>) => void) => {
    const ydoc = new Y.Doc();

    try {
      apply(ydoc);
      const fragment = ydoc.getXmlFragment('content');
      const json = yjsXmlFragmentToTiptapJSON(fragment);

      if (tiptapJsonHasVisibleContent(json) || fragment.length > 0) {
        return json;
      }

      return undefined;
    } finally {
      ydoc.destroy();
    }
  };

  try {
    const fromV2 = tryFragment(ydoc => {
      Y.applyUpdateV2(ydoc, bytes);
    });

    if (fromV2) {
      return fromV2;
    }
  } catch {
    // V2 updates fail on V1 payloads; try the original encoder next.
  }

  try {
    return tryFragment(ydoc => {
      Y.applyUpdate(ydoc, bytes);
    });
  } catch {
    return undefined;
  }
}

async function migrateLeftoverYjs(
  resource: Resource,
  store: Store,
): Promise<boolean> {
  await enableLoro();

  const loroDoc = resource.getLoroDoc();
  const hasVisible = !!loroDoc && loroDocHasVisibleContent(loroDoc);
  // Historical documents can contain binary Yjs data despite the current string type.
  const raw: unknown = resource.get(dataBrowser.properties.documentContent);

  if (!isYjsMigrationCandidate(raw, !hasVisible)) {
    return false;
  }

  if (hasVisible) {
    if (isSerializedYDoc(raw) || raw instanceof Uint8Array) {
      resource.remove(dataBrowser.properties.documentContent);
      await resource.save();

      return true;
    }

    return false;
  }

  const bytes = extractYDocBytes(raw);

  if (!bytes) {
    return false;
  }

  const json = await yjsBytesToTiptapJSON(bytes);

  if (!json) {
    return false;
  }

  await writeTiptapJsonToLoro(resource, store, json);
  resource.remove(dataBrowser.properties.documentContent);
  await resource.save();

  return true;
}

async function migrateV1(resource: Resource, store: Store): Promise<boolean> {
  const { doc, ownedParagraphs } = await v1ElementsToTiptapDoc(resource, store);

  await writeTiptapJsonToLoro(resource, store, doc);

  resource.remove(dataBrowser.properties.elements);
  await resource.set(core.properties.isA, [dataBrowser.classes.documentV2]);

  const leftover: unknown = resource.get(
    dataBrowser.properties.documentContent,
  );

  if (isSerializedYDoc(leftover) || leftover instanceof Uint8Array) {
    resource.remove(dataBrowser.properties.documentContent);
  }

  await resource.save();

  for (const paragraph of ownedParagraphs) {
    await paragraph.destroy();
  }

  return true;
}

async function upgradeDocumentInner(
  resource: Resource,
  store: Store,
): Promise<boolean> {
  if (resource.hasClasses(dataBrowser.classes.documentV2)) {
    return migrateLeftoverYjs(resource, store);
  }

  if (resource.hasClasses(dataBrowser.classes.document)) {
    return migrateV1(resource, store);
  }

  return false;
}

/**
 * Silently migrate a writable document onto the current Loro-backed
 * DocumentV2 format.
 *
 * - V1 (`elements` + paragraph children) → TipTap JSON → Loro `doc` map.
 * - Leftover Yjs `documentContent` (Yjs-era V2) → same, loading `yjs` only
 *   when those bytes are actually present.
 *
 * Concurrent calls for the same subject share one in-flight promise
 * (React Strict Mode, DocumentPage + DocumentV2FullPage overlap).
 *
 * @returns `true` when a migration commit was written.
 */
export async function upgradeDocument(
  resource: Resource,
  store: Store,
): Promise<boolean> {
  const existing = inFlight.get(resource.subject);

  if (existing) {
    return existing;
  }

  const promise = upgradeDocumentInner(resource, store).finally(() => {
    inFlight.delete(resource.subject);
  });

  inFlight.set(resource.subject, promise);

  return promise;
}

export {
  isSerializedYDoc,
  isYjsMigrationCandidate,
  loroDocBodyIsEmpty,
  loroDocHasVisibleContent,
} from './documentMigrationUtils';
