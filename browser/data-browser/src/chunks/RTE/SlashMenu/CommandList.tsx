import { transparentize } from 'polished';
import {
  forwardRef,
  useState,
  useImperativeHandle,
  useId,
  useCallback,
} from 'react';
import { styled } from 'styled-components';
import { ScrollArea } from '../../../components/ScrollArea';
import type { SuggestionItem } from '../types';
import { useOnValueChange } from '@helpers/useOnValueChange';
import { Column } from '@components/Row';
import { Spinner } from '@components/Spinner';

export type CommandListRefType = {
  onKeyDown: (event: KeyboardEvent) => boolean;
};

export interface CommandListProps {
  items: SuggestionItem[];
  /** True while the suggestion's async `items()` is still pending. */
  loading?: boolean;
  ownerDocument?: Document;
  command: (item: SuggestionItem) => void;
}

const buildItemId = (compId: string, index: number) =>
  `command-list-${compId}-item-${index}`;

const scrollToSelectedItem = (
  ownerDocument: Document,
  compId: string,
  index: number,
) =>
  ownerDocument
    .getElementById(buildItemId(compId, index))
    ?.scrollIntoView({ block: 'nearest' });

export const CommandList = forwardRef<CommandListRefType, CommandListProps>(
  ({ items, loading = false, command, ownerDocument = document }, ref) => {
    const compId = useId();

    const [selectedIndex, setSelectedIndex] = useState(0);

    const selectItem = useCallback(
      (index: number) => {
        const item = items[index];

        if (item) {
          command(item);
        }
      },
      [command, items],
    );

    useOnValueChange(() => setSelectedIndex(0), [items]);

    useImperativeHandle(
      ref,
      () => ({
        onKeyDown: event => {
          if (event.key === 'ArrowUp') {
            const index = (selectedIndex + items.length - 1) % items.length;
            setSelectedIndex(index);

            scrollToSelectedItem(ownerDocument, compId, index);

            return true;
          }

          if (event.key === 'ArrowDown') {
            const index = (selectedIndex + 1) % items.length;
            setSelectedIndex(index);

            scrollToSelectedItem(ownerDocument, compId, index);

            return true;
          }

          if (event.key === 'Enter') {
            selectItem(selectedIndex);

            return true;
          }

          return false;
        },
      }),
      [selectedIndex, items, compId, selectItem, ownerDocument],
    );

    return (
      <ScrollingList type='hover' data-testid='rte-command-list'>
        <ContainedColumn gap='0'>
          {loading && items.length === 0 && (
            <SearchingRow role='status' data-testid='rte-command-list-loading'>
              <Spinner size='1rem' inheritColor />
              <span>Searching...</span>
            </SearchingRow>
          )}
          {!loading && items.length === 0 && <div>No results found</div>}
          {items.map((item, index) => {
            const Icon = item.icon;

            return (
              <ListItemButton
                key={item.id}
                id={buildItemId(compId, index)}
                onClick={() => selectItem(index)}
                onMouseEnter={() => setSelectedIndex(index)}
                active={selectedIndex === index}
              >
                <Icon />
                <span>{item.title}</span>
              </ListItemButton>
            );
          })}
        </ContainedColumn>
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
  max-width: 60ch;
  overflow: hidden;

  & > svg {
    min-width: 1rem;
    flex-basis: 1rem;
  }

  & > span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
`;

const ContainedColumn = styled(Column)``;

// Fades in after a short delay so a fast (or static) item list never flashes
// the loading row.
const SearchingRow = styled.div`
  display: flex;
  align-items: center;
  gap: 1ch;
  padding: 0.5rem;
  color: ${p => p.theme.colors.textLight};
  opacity: 0;
  animation: searchingFadeIn 120ms ease-out 150ms forwards;

  @keyframes searchingFadeIn {
    to {
      opacity: 1;
    }
  }
`;
