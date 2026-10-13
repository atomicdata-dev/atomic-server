import { NodeSelection, TextSelection } from '@tiptap/pm/state';
import type { Transaction } from '@tiptap/pm/state';

/** After inserting a block node it stays node-selected, so the next typed
 * character would replace it. Move the caret into the paragraph after it,
 * adding an empty one when there is none (#2139). */
export const placeCaretAfterSelectedNode = (tr: Transaction): void => {
  const { selection } = tr;

  if (!(selection instanceof NodeSelection) || selection.node.isInline) return;

  const after = selection.to;
  const next = tr.doc.resolve(after).nodeAfter;

  if (!next?.isTextblock) {
    const paragraph = tr.doc.type.schema.nodes.paragraph;

    if (!paragraph) return;

    tr.insert(after, paragraph.create());
  }

  tr.setSelection(TextSelection.create(tr.doc, after + 1)).scrollIntoView();
};
