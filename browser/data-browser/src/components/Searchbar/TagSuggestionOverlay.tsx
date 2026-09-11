import { useResourceSnapshot, type DataBrowser } from '@tomic/react';
import { Column } from '../Row';
import { styled } from 'styled-components';
import type { TagWithTitle } from './SearchbarInput';
import { useEffect, useRef } from 'react';
import { ScrollArea } from '../ScrollArea';

interface TagSuggestionOverlayProps {
  tags: TagWithTitle[];
  onTagHover: (index: number) => void;
  onTagClick: (index: number) => void;
  selectedIndex: number | undefined;
  startingRect: DOMRect | undefined;
  usingKeyboard: boolean;
}

function moveToAvailableSpace(menu: HTMLDivElement, triggerRect: DOMRect) {
  const menuRect = menu.getBoundingClientRect();
  const topPos = triggerRect.y - menuRect.height;

  // If the top is outside of the screen, render it below
  if (topPos < 0) {
    menu.style.top = `calc(${triggerRect.y + triggerRect.height / 2}px + 1rem)`;
  } else {
    menu.style.top = `calc(${topPos + triggerRect.height / 2}px - 1rem)`;
  }

  const rightPos = triggerRect.x + triggerRect.width + menuRect.width;

  if (rightPos > window.innerWidth) {
    menu.style.left = `${window.innerWidth - menuRect.width - 10}px`;
  } else {
    menu.style.left = `${triggerRect.x}px`;
  }
}

export const TagSuggestionOverlay: React.FC<TagSuggestionOverlayProps> = ({
  tags,
  onTagHover,
  onTagClick,
  selectedIndex,
  startingRect,
  usingKeyboard,
}) => {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (startingRect) {
      requestAnimationFrame(() => {
        if (ref.current) {
          moveToAvailableSpace(ref.current, startingRect);
        }
      });
    }
  }, [startingRect]);

  return (
    <SuggestionPopover tagRect={startingRect} ref={ref}>
      <StyledScrollArea>
        <Column gap='0px'>
          {tags.length === 0 && <EmptyMessage>No tags found</EmptyMessage>}
          {tags.map((tag, index) => (
            <TagSuggestionRow
              key={tag.subject}
              subject={tag.subject}
              selected={selectedIndex === index}
              onMouseOver={() => onTagHover(index)}
              onClick={() => onTagClick(index)}
              blockAutoscroll={!usingKeyboard}
            />
          ))}
        </Column>
      </StyledScrollArea>
    </SuggestionPopover>
  );
};

interface TagSuggestionRowProps {
  subject: string;
  selected: boolean;
  blockAutoscroll: boolean;
  onMouseOver: () => void;
  onClick: () => void;
}

const TagSuggestionRow: React.FC<TagSuggestionRowProps> = ({
  subject,
  selected,
  blockAutoscroll,
  onMouseOver,
  onClick,
}) => {
  const ref = useRef<HTMLButtonElement>(null);
  const { resource, ready } = useResourceSnapshot<DataBrowser.Tag>(subject);

  useEffect(() => {
    if (selected && !blockAutoscroll) {
      ref.current?.scrollIntoView({ block: 'nearest' });
    }
  }, [selected, blockAutoscroll]);

  if (!ready) return <div>Loading...</div>;

  return (
    <TagRow
      onMouseOver={onMouseOver}
      onClick={onClick}
      selected={selected}
      ref={ref}
      type='button'
      tabIndex={-1}
    >
      <Emote>{resource.props.emoji}</Emote>
      <div>{resource.title}</div>
    </TagRow>
  );
};

const SuggestionPopover = styled.div<{ tagRect: DOMRect | undefined }>`
  display: ${p => (p.tagRect ? 'block' : 'none')};
  opacity: ${p => (p.tagRect ? 1 : 0)};
  position: fixed;
  transition:
    opacity 0.1s ease,
    display 0.1s ease allow-discrete;
  border-radius: ${p => p.theme.radius};
  box-shadow: ${p => p.theme.boxShadowSoft};
  background-color: ${p => p.theme.colors.bg};
  padding: ${p => p.theme.size(2)};
  min-width: 10rem;
  @starting-style {
    opacity: 0;
  }
`;

const Emote = styled.div`
  text-shadow: 0 2px 2px rgba(0, 0, 0, 0.2);
`;

const TagRow = styled.button<{ selected: boolean }>`
  appearance: none;
  border: none;
  display: flex;
  align-items: center;
  gap: 1ch;
  cursor: pointer;
  background-color: ${p =>
    p.selected ? p.theme.colors.mainSelectedBg : 'transparent'};
  padding: ${p => p.theme.size(2)};
  border-radius: ${p => p.theme.radius};
  color: ${p =>
    p.selected ? p.theme.colors.mainSelectedFg : p.theme.colors.text};

  white-space: nowrap;
`;

const StyledScrollArea = styled(ScrollArea)`
  height: min(20rem, 30dvh);
`;

const EmptyMessage = styled.div`
  padding: ${p => p.theme.size(2)};
`;
