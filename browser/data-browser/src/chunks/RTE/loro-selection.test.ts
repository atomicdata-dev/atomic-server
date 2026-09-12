import { afterEach, expect, it, vi } from 'vitest';
import { Schema } from '@tiptap/pm/model';
import { EditorState, TextSelection } from '@tiptap/pm/state';
import type { EditorView } from '@tiptap/pm/view';
import { LoroDoc } from 'loro-crdt';
import { LoroSyncPlugin, type LoroDocType } from 'loro-prosemirror';

// The app aliases Loro to its web build; this DOM-free test uses Node WASM.
vi.mock('loro-crdt', () => import('loro-crdt/nodejs'));

afterEach(() => vi.useRealTimers());

it('preserves the typing position when a remote property update arrives between keystrokes', async () => {
  vi.useFakeTimers();
  const schema = new Schema({
    nodes: {
      doc: { content: 'paragraph+' },
      paragraph: { content: 'text*', group: 'block' },
      text: { group: 'inline' },
    },
  });
  const doc = new LoroDoc() as unknown as LoroDocType;
  const plugin = LoroSyncPlugin({ doc });
  const view = {
    state: EditorState.create({ schema, plugins: [plugin] }),
    isDestroyed: false,
    dispatch(tr) {
      this.state = this.state.apply(tr);
    },
  } as EditorView;
  const pluginView = plugin.spec.view!(view);
  await vi.runOnlyPendingTimersAsync();
  view.dispatch(view.state.tr.insertText('abcd'));
  view.dispatch(
    view.state.tr.setSelection(TextSelection.create(view.state.doc, 3)),
  );

  const remote = new LoroDoc();
  remote.import(doc.export({ mode: 'snapshot' }));
  remote.getMap('properties').set('title', 'remote metadata');
  remote.commit();
  doc.import(remote.export({ mode: 'update' }));
  await Promise.resolve();

  // A network callback and the next key can run before any queued timer.
  expect(view.state.selection.anchor).toBe(3);
  view.dispatch(view.state.tr.insertText('X'));
  await vi.runOnlyPendingTimersAsync();
  view.dispatch(view.state.tr.insertText('Y'));
  expect(view.state.doc.textContent).toBe('abXYcd');
  pluginView.destroy?.();
});
