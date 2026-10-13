import { describe, expect, it } from 'vitest';
import { Schema } from '@tiptap/pm/model';
import { EditorState, NodeSelection, TextSelection } from '@tiptap/pm/state';
import { placeCaretAfterSelectedNode } from './placeCaretAfterSelectedNode';

const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'text*' },
    resource: { group: 'block', atom: true, selectable: true },
    text: { group: 'inline' },
  },
});

const run = (doc: ReturnType<typeof schema.node>) => {
  const state = EditorState.create({
    doc,
    selection: NodeSelection.create(doc, 0),
  });
  const tr = state.tr;

  placeCaretAfterSelectedNode(tr);

  return tr;
};

describe('placeCaretAfterSelectedNode', () => {
  it('adds a trailing paragraph and puts the caret in it', () => {
    const tr = run(schema.node('doc', null, [schema.node('resource')]));

    expect(tr.doc.childCount).toBe(2);
    expect(tr.doc.lastChild?.type.name).toBe('paragraph');
    expect(tr.selection).toBeInstanceOf(TextSelection);
    expect(tr.selection.from).toBe(2);
  });

  it('reuses an existing paragraph after the node', () => {
    const tr = run(
      schema.node('doc', null, [
        schema.node('resource'),
        schema.node('paragraph', null, [schema.text('hi')]),
      ]),
    );

    expect(tr.doc.childCount).toBe(2);
    expect(tr.selection).toBeInstanceOf(TextSelection);
    expect(tr.selection.from).toBe(2);
  });
});
