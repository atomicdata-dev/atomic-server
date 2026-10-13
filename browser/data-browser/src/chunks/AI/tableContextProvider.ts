// @wc-ignore-file
/**
 * Table context provider (phase 2 of planning/json-ad-compact.md): when a
 * table is attached to a chat (the auto-attached "what you're looking at"
 * item or an @-mention), expand it into what a person viewing it actually
 * sees — the row-class schema with tag options, the row count, and a compact
 * sample of rows — so "add some rows to this table" needs zero discovery
 * tool calls.
 */
import {
  CollectionBuilder,
  core,
  type Resource,
  type Store,
} from '@tomic/react';
import { shortenRefsDeep, shortenSubject } from '@tomic/react';
import {
  buildClassContext,
  describeClassCompact,
  toCompact,
} from '@tomic/react';

const ROW_SAMPLE_LIMIT = 20;

/**
 * Renders the table's row class, schema signature, row count, and up to
 * {@link ROW_SAMPLE_LIMIT} compact rows. Returns undefined when the table has
 * no classtype (never happens for tables made in the app).
 */
export const getTableContextForAgent = async (
  store: Store,
  table: Resource,
): Promise<string | undefined> => {
  const rowClass = table.get(core.properties.classtype) as string | undefined;

  if (!rowClass) {
    return undefined;
  }

  const ctx = await buildClassContext(store, [rowClass]);

  const collection = new CollectionBuilder(store)
    .setProperty(core.properties.parent)
    .setValue(table.subject)
    .setPageSize(ROW_SAMPLE_LIMIT)
    .build();

  // Fetching the first page also populates totalMembers.
  const sampleSubjects = await collection.getMembersOnPage(0);
  const total = collection.totalMembers;

  const rows: unknown[] = [];

  for (const subject of sampleSubjects) {
    const row = await store.getResource(subject);

    // A table's children include its saved views; only rows are instances of
    // the row class.
    if (row.error || !row.getClasses().includes(rowClass)) {
      continue;
    }

    rows.push(shortenRefsDeep(await toCompact(store, row, { context: ctx })));
  }

  const shownNote =
    total > rows.length ? ` (${rows.length} of ${total} shown)` : '';

  return [
    `Row schema: ${describeClassCompact(ctx, rowClass)}`,
    `Row class: ${shortenSubject(rowClass)}`,
    `Rows: ${total}${shownNote}`,
    ...(rows.length > 0 ? [JSON.stringify(rows)] : []),
    `To add rows: call create_resource ONCE with an ARRAY of compact objects, each {"@class": "${shortenSubject(rowClass)}", "@parent": "${shortenSubject(table.subject)}", "name": …, plus the schema shortnames above (tag names for select values)}. createdAt is added automatically. No further reads needed.`,
  ].join('\n');
};
