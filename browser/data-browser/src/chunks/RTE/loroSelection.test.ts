import { describe, expect, it, vi } from 'vitest';
import { Schema } from '@tiptap/pm/model';
import { EditorState, TextSelection, type Transaction } from '@tiptap/pm/state';
import type { EditorView } from '@tiptap/pm/view';
import { LoroDoc } from 'loro-crdt';
import { LoroSyncPlugin, type LoroDocType } from 'loro-prosemirror';

// Share the native Loro instance with the binding in this Node-only test.
vi.mock('loro-crdt', () => import('loro-crdt/nodejs'));

describe('collaborative editor selection', () => {
  it('keeps typing at the cursor when resource metadata arrives between keystrokes', async () => {
    vi.useFakeTimers();
    const schema = new Schema({
      nodes: {
        doc: { content: 'paragraph+' },
        paragraph: { content: 'text*' },
        text: { inline: true },
      },
    });
    const doc: LoroDocType = new LoroDoc();
    const plugin = LoroSyncPlugin({ doc });
    const view = {
      state: EditorState.create({ schema, plugins: [plugin] }),
      isDestroyed: false,
      dispatch(transaction: Transaction) {
        this.state = this.state.applyTransaction(transaction).state;
      },
    };
    const lifecycle = plugin.spec.view!(view as unknown as EditorView);

    try {
      await vi.runOnlyPendingTimersAsync();
      view.dispatch(view.state.tr.insertText('ad'));
      view.dispatch(
        view.state.tr.setSelection(TextSelection.create(view.state.doc, 2)),
      );
      const remote = new LoroDoc();
      remote.import(doc.export({ mode: 'snapshot' }));
      remote.getMap('properties').set('name', 'Server acknowledgement');
      doc.import(remote.export({ mode: 'update', from: doc.oplogVersion() }));
      await Promise.resolve();
      view.dispatch(view.state.tr.insertText('b'));
      await vi.runOnlyPendingTimersAsync();
      view.dispatch(view.state.tr.insertText('c'));
      expect(view.state.doc.textContent).toBe('abcd');
    } finally {
      view.isDestroyed = true;
      lifecycle.destroy?.();
      vi.useRealTimers();
    }
  });
});
