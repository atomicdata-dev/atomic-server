import { core, JSONValue, Store, useResources, useStore } from '@tomic/react';
import { useMemo, useRef, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { IconButton } from '@components/IconButton/IconButton';
import { TagButton, Tag } from '@components/Tag';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Row } from '@components/Row';
import { loopingIndex } from '@helpers/loopingIndex';
import { fadeIn } from '@helpers/commonAnimations';
import { KeyboardInteraction, useCellOptions } from '@chunks/TableEditor';
import { AbsoluteCell } from './CellComponents';
import { FaXmark, FaPlus } from 'react-icons/fa6';
import { CustomPopover, usePopover } from '@components/CustomPopover';
import { optionSubjects, useRowConstraint } from '../useColumnConstraint';

const TAG_SPACING = '0.5rem';

const emptyArray: string[] = [];

function buildListWithTitles(
  store: Store,
  subjects: string[],
  ignore: string[],
): { subject: string; title: string }[] {
  return subjects
    .filter(v => !ignore.includes(v))
    .map(subject => {
      const resource = store.getResourceLoading(subject);
      // Same precedence as `useTitle`: the free-text name, else the slug.
      const title =
        resource?.get(core.properties.name) ??
        resource?.get(core.properties.shortname) ??
        subject;

      return { subject, title: title as string };
    });
}

function SelectCellEdit({
  value,
  property,
  onChange,
  resource: row,
}: EditCellProps<JSONValue>): JSX.Element {
  const inputRef = useRef<HTMLInputElement>(null);
  const val = (value as string[]) ?? emptyArray;
  const store = useStore();
  // Options and the pick limit come from the row's class `constraints`,
  // falling back to the Property's legacy `allowsOnly` and `max`.
  const constraint = useRowConstraint(row.getClasses(), property);
  const allowsOnly = optionSubjects(constraint);
  // The titles below are read from the store: wake up when an option's Tag
  // finishes loading or syncing, or a pick made right after the column was
  // created finds a Tag with no title yet and matches nothing.
  const optionKey = allowsOnly.join('\n');
  const optionList = useMemo(() => allowsOnly, [optionKey]);
  useResources(optionList);
  const [query, setQuery] = useState('');

  // `maxItems` caps how many tags may be picked at once. It is how
  // single-select is expressed, since a select column is always a
  // resourceArray. Form questions of a single-pick type set `maxItems: 1`.
  const max = constraint.maxItems;

  const filteredTags = buildListWithTitles(store, allowsOnly, val)
    .filter(v => v.title.toLowerCase().includes(query.toLowerCase()))
    .map(ft => ft.subject);

  const { triggerProps, popoverProps } = usePopover({
    defaultOpen: true,
    autoFocusElement: inputRef,
  });
  const [selectedIndex, setSelectedIndex] = useState(0);

  const disabledKeyboardInteractions = new Set<KeyboardInteraction>([
    KeyboardInteraction.EditNextRow,
  ]);

  const cellOptions = {
    disabledKeyboardInteractions,
    hideActiveIndicator: true,
  };

  useCellOptions(cellOptions);

  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    setQuery(e.target.value);
    setSelectedIndex(0);
  };

  const handleAddTag = (subject: string) => {
    const next = Array.from(new Set([...val, subject]));

    // At the cap, the new pick displaces the oldest rather than being
    // dropped — so a `max: 1` column behaves as a single-select swap.
    onChange(max !== undefined && next.length > max ? next.slice(-max) : next);
  };

  // Enter right after the column was created can find its Tags still loading,
  // with no title to match the typed text against. Wait for them, then pick,
  // instead of picking from a list that is empty only for now.
  const pickSelected = async () => {
    if (allowsOnly.some(o => store.getResourceLoading(o).loading)) {
      await Promise.all(
        allowsOnly.map(o => store.getResource(o).catch(() => undefined)),
      );
    }

    const subject = buildListWithTitles(store, allowsOnly, val)
      .filter(v => v.title.toLowerCase().includes(query.toLowerCase()))
      .map(ft => ft.subject)[selectedIndex];

    if (subject) {
      handleAddTag(subject);
    }
  };

  const handleRemoveTag = (subject: string) => {
    onChange(val.filter(tagSubject => tagSubject !== subject));
  };

  const changeSelection = (mod: number) => {
    setSelectedIndex(prev => loopingIndex(prev + mod, filteredTags.length));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    switch (e.key) {
      case 'ArrowUp':
        e.preventDefault();
        changeSelection(-1);
        break;
      case 'ArrowDown':
        e.preventDefault();
        changeSelection(1);
        break;
      case 'Enter':
        e.preventDefault();
        void pickSelected();
        break;
    }
  };

  return (
    <AbsoluteCell>
      <Row gap={TAG_SPACING} center wrapItems>
        {val.map(v => (
          <Tag subject={v} key={v}>
            <TagIconButton
              title='remove tag'
              onClick={() => handleRemoveTag(v)}
            >
              <FaXmark />
            </TagIconButton>
          </Tag>
        ))}
        <CustomPopover
          noLock
          Trigger={
            <IconButton title='Add tag' type='button' {...triggerProps}>
              <StyledIcon />
            </IconButton>
          }
          {...popoverProps}
        >
          <Content onKeyDown={handleKeyDown}>
            <SearchInputWrapper>
              <InputStyled
                placeholder='filter tags'
                onChange={handleSearch}
                ref={inputRef}
              />
            </SearchInputWrapper>
            <ResultWrapper>
              <Row wrapItems gap={TAG_SPACING}>
                {filteredTags.map((v, i) => (
                  <TagButton
                    key={v}
                    subject={v}
                    onClick={handleAddTag}
                    selected={i === selectedIndex}
                  />
                ))}
                {filteredTags.length === 0 && 'No results'}
              </Row>
            </ResultWrapper>
          </Content>
        </CustomPopover>
      </Row>
    </AbsoluteCell>
  );
}

function SelectCellDisplay({
  value,
}: DisplayCellProps<JSONValue>): JSX.Element {
  if (!value) {
    return <></>;
  }

  return (
    <Row gap={TAG_SPACING}>
      {(value as string[]).map(v => (
        <Tag subject={v} key={v} />
      ))}
    </Row>
  );
}

const StyledIcon = styled(FaPlus)`
  animation: ${fadeIn} 0.1s ease-in-out;
  color: ${p => p.theme.colors.textLight};
`;

const TagIconButton = styled(IconButton)`
  height: unset;
  width: unset;
  padding: unset;

  color: var(--tag-dark-color);
  background-blend-mode: lighten;

  &:not([disabled]):hover,
  &:not([disabled]):focus {
    transform: scale(1.2);
    background-color: unset;
  }
`;

const Content = styled.div`
  width: min(40ch, 90vh);
  border-radius: ${p => p.theme.radius};
`;

const ResultWrapper = styled.div`
  padding: ${p => p.theme.margin}rem;
  border: ${p =>
    p.theme.darkMode ? '1px solid ' + p.theme.colors.bg2 : 'none'};
  border-top: none;
  border-bottom-left-radius: ${p => p.theme.radius};
  border-bottom-right-radius: ${p => p.theme.radius};
`;

const SearchInputWrapper = styled(InputWrapper)`
  border-bottom-left-radius: 0;
  border-bottom-right-radius: 0;
`;

export const SelectCell: CellContainer<JSONValue> = {
  Edit: SelectCellEdit,
  Display: SelectCellDisplay,
};
