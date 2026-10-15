import { useState } from 'react';
import { styled } from 'styled-components';
import { useEditorState, type Editor } from '@tiptap/react';
import { FaAt, FaCheck, FaImage, FaListOl, FaListUl } from 'react-icons/fa6';
import { useFormattingToolbarVisible } from './useFormattingToolbarVisible';
import { useTipTapEditor } from './TiptapContext';
import { NodeSelectMenu } from './NodeSelectMenu';
import { MarkToggleButtons } from './MarkToggleButtons';
import { LinkPopoverButton } from './LinkPopoverButton';
import { ToggleButton } from './ToggleButton';

/**
 * Formatting toolbar above the document editor, for people who don't know
 * the `/` and `@` commands yet. It is hidden by default; the toggle sits next
 * to the document title (see `FormattingToolbarToggle`).
 */
export function FormattingToolbar(): React.JSX.Element | null {
  const [visible] = useFormattingToolbarVisible();

  if (!visible) {
    return null;
  }

  return <Toolbar />;
}

function Toolbar(): React.JSX.Element {
  const editor = useTipTapEditor();
  const [linkMenuOpen, setLinkMenuOpen] = useState(false);

  const { isBulletList, isOrderedList, isTaskList } = useEditorState({
    editor,
    selector: snapshot => ({
      isBulletList: snapshot.editor.isActive('bulletList'),
      isOrderedList: snapshot.editor.isActive('orderedList'),
      isTaskList: snapshot.editor.isActive('taskList'),
    }),
  });

  // Pressing a button would otherwise move focus out of the editor, which
  // closes the on-screen keyboard on touch devices. The `<select>` still
  // needs its default so it can open.
  const keepEditorFocus = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('button')) {
      e.preventDefault();
    }
  };

  return (
    <ToolbarWrapper
      role='toolbar'
      aria-label='Formatting'
      onMouseDown={keepEditorFocus}
    >
      <Scroller>
        <Group>
          <NodeSelectMenu />
        </Group>
        <Group>
          <MarkToggleButtons />
          <LinkPopoverButton
            open={linkMenuOpen}
            onOpenChange={setLinkMenuOpen}
            side='bottom'
          />
        </Group>
        <Group>
          <ToggleButton
            title='Bullet list'
            $active={isBulletList}
            onClick={() => editor.chain().focus().toggleBulletList().run()}
            type='button'
          >
            <FaListUl />
          </ToggleButton>
          <ToggleButton
            title='Numbered list'
            $active={isOrderedList}
            onClick={() => editor.chain().focus().toggleOrderedList().run()}
            type='button'
          >
            <FaListOl />
          </ToggleButton>
          <ToggleButton
            title='Task list'
            $active={isTaskList}
            onClick={() => editor.chain().focus().toggleTaskList().run()}
            type='button'
          >
            <FaCheck />
          </ToggleButton>
        </Group>
        <Group>
          <ToggleButton
            title='Insert image'
            $active={false}
            onClick={() => editor.chain().focus().setImage({ src: '' }).run()}
            type='button'
          >
            <FaImage />
          </ToggleButton>
          <ToggleButton
            title='Mention a resource (@)'
            $active={false}
            onClick={() => insertMentionTrigger(editor)}
            type='button'
          >
            <FaAt />
          </ToggleButton>
        </Group>
      </Scroller>
    </ToolbarWrapper>
  );
}

// The `@` menu only opens at the start of a line or after a space, so pad
// the trigger when the caret sits right after a word.
function insertMentionTrigger(editor: Editor) {
  const { $from } = editor.state.selection;
  const charBefore = $from.parent.textBetween(
    Math.max(0, $from.parentOffset - 1),
    $from.parentOffset,
  );
  const needsSpace = charBefore !== '' && !/\s/.test(charBefore);

  editor
    .chain()
    .focus()
    .insertContent(needsSpace ? ' @' : '@')
    .run();
}

const ToolbarWrapper = styled.div`
  position: sticky;
  top: 0;
  z-index: 2;
  display: flex;
  align-items: center;
  margin-bottom: ${p => p.theme.size(3)};
  padding: ${p => p.theme.size(1)} ${p => p.theme.size(2)};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg1};
  cursor: default;

  @media print {
    display: none;
  }
`;

/* Narrow screens scroll the buttons sideways instead of wrapping onto several
 * rows that would push the text down. */
const Scroller = styled.div`
  display: flex;
  align-items: center;
  flex: 1;
  min-width: 0;
  gap: ${p => p.theme.size(4)};
  overflow-x: auto;
  scrollbar-width: none;
`;

const Group = styled.div`
  display: flex;
  align-items: center;
  flex-shrink: 0;
  gap: 0.25ch;
`;
