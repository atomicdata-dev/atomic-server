import { BubbleMenu as TipTapBubbleMenu } from '@tiptap/react';
import {
  FaBold,
  FaCode,
  FaItalic,
  FaLink,
  FaQuoteLeft,
  FaStrikethrough,
} from 'react-icons/fa6';
import { styled } from 'styled-components';
import * as RadixPopover from '@radix-ui/react-popover';
import { Row } from '../../components/Row';

import { Popover } from '../../components/Popover';
import { useState } from 'react';
import { transparentize } from 'polished';
import { EditLinkForm } from './EditLinkForm';
import { useTipTapEditor } from './TiptapContext';
import { ToggleButton } from './ToggleButton';
import { NodeSelectMenu } from './NodeSelectMenu';

export function BubbleMenu(): React.JSX.Element {
  const editor = useTipTapEditor();
  const [linkMenuOpen, setLinkMenuOpen] = useState(false);

  if (!editor) {
    return <></>;
  }

  return (
    <TipTapBubbleMenu editor={editor}>
      <BubbleMenuInner gap='0.5ch'>
        <NodeSelectMenu />
        <ToggleButton
          title='Toggle bold'
          $active={!!editor.isActive('bold')}
          onClick={() => editor.chain().focus().toggleBold().run()}
          disabled={!editor.can().chain().focus().toggleBold().run()}
          type='button'
        >
          <FaBold />
        </ToggleButton>
        <ToggleButton
          title='Toggle italic'
          $active={!!editor.isActive('italic')}
          onClick={() => editor.chain().focus().toggleItalic().run()}
          disabled={!editor.can().chain().focus().toggleItalic().run()}
          type='button'
        >
          <FaItalic />
        </ToggleButton>
        <ToggleButton
          title='Toggle strikethrough'
          $active={!!editor.isActive('strike')}
          onClick={() => editor.chain().focus().toggleStrike().run()}
          disabled={!editor.can().chain().focus().toggleStrike().run()}
          type='button'
        >
          <FaStrikethrough />
        </ToggleButton>
        <ToggleButton
          title='Toggle blockquote'
          $active={!!editor.isActive('blockquote')}
          onClick={() => editor.chain().focus().toggleBlockquote().run()}
          disabled={!editor.can().chain().focus().toggleBlockquote().run()}
          type='button'
        >
          <FaQuoteLeft />
        </ToggleButton>
        <ToggleButton
          title='Toggle inline code'
          $active={!!editor.isActive('code')}
          onClick={() => editor.chain().focus().toggleCode().run()}
          disabled={!editor.can().chain().focus().toggleCode().run()}
          type='button'
        >
          <FaCode />
        </ToggleButton>
        <StyledPopover
          modal
          open={linkMenuOpen}
          onOpenChange={setLinkMenuOpen}
          Trigger={
            <ToggleButton
              as={RadixPopover.Trigger}
              $active={!!editor.isActive('link')}
              disabled={!editor.can().chain().focus().toggleCode().run()}
              type='button'
            >
              <FaLink />
            </ToggleButton>
          }
        >
          <EditLinkForm onDone={() => setLinkMenuOpen(false)} />
        </StyledPopover>
      </BubbleMenuInner>
    </TipTapBubbleMenu>
  );
}

const BubbleMenuInner = styled(Row)`
  background-color: ${p => p.theme.colors.bg};
  border-radius: ${p => p.theme.radius};
  padding: ${p => p.theme.size(2)};
  box-shadow: ${p => p.theme.boxShadowSoft};

  @supports (backdrop-filter: blur(5px)) {
    background-color: ${p => transparentize(0.15, p.theme.colors.bg)};
    backdrop-filter: blur(5px);
  }
`;

const StyledPopover = styled(Popover)`
  background-color: ${p => p.theme.colors.bg};
  backdrop-filter: blur(5px);
  padding: ${p => p.theme.size()};
  border-radius: ${p => p.theme.radius};

  @supports (backdrop-filter: blur(5px)) {
    background-color: ${p => transparentize(0.15, p.theme.colors.bg)};
    backdrop-filter: blur(5px);
  }
`;
