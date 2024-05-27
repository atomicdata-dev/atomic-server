import type { Editor, Range } from '@tiptap/react';
import { transparentize } from 'polished';
import {
  forwardRef,
  useState,
  useEffect,
  useImperativeHandle,
  useId,
} from 'react';
import type { IconType } from 'react-icons';
import { styled } from 'styled-components';
import { ScrollArea } from '../../../components/ScrollArea';

export type CommandListRefType = {
  onKeyDown: (event: KeyboardEvent) => boolean;
};

export type CommandItem = {
  title: string;
  icon: IconType;
  command: (props: { editor: Editor; range: Range }) => void;
};

export interface CommandListProps {
  items: CommandItem[];
  command: (item: CommandItem) => void;
}

const buildItemId = (compId: string, index: number) =>
  `command-list-${compId}-item-${index}`;

const scrollToSelectedItem = (compId: string, index: number) =>
  document
    .getElementById(buildItemId(compId, index))
    ?.scrollIntoView({ block: 'nearest' });

export const CommandList = forwardRef<CommandListRefType, CommandListProps>(
  ({ items, command }, ref) => {
    const compId = useId();

    const [selectedIndex, setSelectedIndex] = useState(0);

    const selectItem = (index: number) => {
      const item = items[index];

      if (item) {
        command(item);
      }
    };

    useEffect(() => setSelectedIndex(0), [items]);

    useImperativeHandle(
      ref,
      () => ({
        onKeyDown: event => {
          if (event.key === 'ArrowUp') {
            const index = (selectedIndex + items.length - 1) % items.length;
            setSelectedIndex(index);

            scrollToSelectedItem(compId, index);

            return true;
          }

          if (event.key === 'ArrowDown') {
            const index = (selectedIndex + 1) % items.length;
            setSelectedIndex(index);

            scrollToSelectedItem(compId, index);

            return true;
          }

          if (event.key === 'Enter') {
            selectItem(selectedIndex);

            return true;
          }

          return false;
        },
      }),
      [selectedIndex, items],
    );

    return (
      <ScrollingList type='hover'>
        {items.map((item, index) => {
          const Icon = item.icon;

          return (
            <ListItemButton
              key={item.title}
              id={buildItemId(compId, index)}
              onClick={() => selectItem(index)}
              onMouseEnter={() => setSelectedIndex(index)}
              active={selectedIndex === index}
            >
              <Icon />
              {item.title}
            </ListItemButton>
          );
        })}
      </ScrollingList>
    );
  },
);

CommandList.displayName = 'CommandList';

const ScrollingList = styled(ScrollArea)`
  background-color: ${p => p.theme.colors.bg};
  border-radius: ${p => p.theme.radius};
  box-shadow: ${p => p.theme.boxShadowSoft};
  padding: 1rem;
  max-height: min(50dvh, 20rem);
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  align-items: flex-start;
  @supports (backdrop-filter: blur(5px)) {
    background-color: ${p => transparentize(0.15, p.theme.colors.bg)};
    backdrop-filter: blur(5px);
  }
`;

const ListItemButton = styled.button<{ active: boolean }>`
  appearance: none;
  background: ${p => (p.active ? p.theme.colors.main : 'transparent')};
  color: ${p => (p.active ? p.theme.colors.bg : p.theme.colors.text)};
  border: none;
  display: flex;
  align-items: center;
  gap: 1ch;
  padding: 0.5rem;
  border-radius: ${p => p.theme.radius};
`;
