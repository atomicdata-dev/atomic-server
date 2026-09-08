import { describe, expect, it, vi } from 'vitest';
import type { Editor } from '@tiptap/react';
import { NodeSelectMenu } from './NodeSelectMenu';

const state = vi.hoisted(() => ({ editor: {} as Editor }));
vi.mock('./TiptapContext', () => ({ useTipTapEditor: () => state.editor }));
vi.mock('@tiptap/react', () => ({
  useEditorState: ({
    selector,
  }: {
    selector: (snapshot: { editor: Editor }) => unknown;
  }) => selector({ editor: state.editor }),
}));
vi.mock('../../components/forms/BasicSelect', () => ({
  BasicSelect: 'select',
}));

describe('node toolbar editor lifecycle', () => {
  it('does not read state or commands after editor destruction', () => {
    state.editor = {
      isDestroyed: true,
      isActive: () => {
        throw new Error('Editor has been destroyed');
      },
      get commands() {
        throw new Error('Command manager has been destroyed');
      },
    } as unknown as Editor;
    expect(NodeSelectMenu()).toBeNull();
  });
});
