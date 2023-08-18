import {
  JSONValue,
  properties,
  Store,
  useArray,
  useResource,
  useStore,
} from '@tomic/react';
import React, { useCallback, useEffect, useMemo } from 'react';
import { FaPlus, FaTimes } from 'react-icons/fa';
import * as RadixPopover from '@radix-ui/react-popover';
import { styled } from 'styled-components';
import { IconButton } from '../../../components/IconButton/IconButton';
import { Popover } from '../../../components/Popover';
import { SelectableTag, Tag } from '../PropertyForm/Tag';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';
import {
  InputStyled,
  InputWrapper,
} from '../../../components/forms/InputStyles';
import { Row } from '../../../components/Row';
import { stringToSlug } from '../../../helpers/stringToSlug';
import { loopingIndex } from '../../../helpers/loopingIndex';
import { fadeIn } from '../../../helpers/commonAnimations';
import {
  KeyboardInteraction,
  useCellOptions,
} from '../../../components/TableEditor';
import { useTableEditorContext } from '../../../components/TableEditor/TableEditorContext';

const TAG_SPACING = '0.5rem';

const emptyArray: string[] = [];

function buildListWithTitles(
  store: Store,
  subjects: string[],
): { subject: string; title: string }[] {
  return subjects.map(subject => {
    const resource = store.getResourceLoading(subject);
    const title = resource?.get(properties.shortname) ?? subject;

    return { subject, title: title as string };
  });
}

function ResourceArrayCellEdit({
  value,
  property,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  const store = useStore();
  const propertyResource = useResource(property);
  const [allowsOnly] = useArray(propertyResource, properties.allowsOnly);
  const [filteredTags, setFilteredTags] = React.useState<string[]>(allowsOnly);
  const [open, setOpen] = React.useState(true);
  const [selectedIndex, setSelectedIndex] = React.useState(0);
  const [focusIndex, setFocusIndex] = React.useState(0);

  const { activeCellRef } = useTableEditorContext();

  const val = (value as string[]) ?? emptyArray;

  const cellOptions = useMemo(() => {
    const disabledKeyboardInteractions = new Set<KeyboardInteraction>([
      KeyboardInteraction.EditNextRow,
    ]);

    if (focusIndex !== 0) {
      disabledKeyboardInteractions.add(KeyboardInteraction.EditPreviousCell);
    }

    if (focusIndex !== val.length) {
      disabledKeyboardInteractions.add(KeyboardInteraction.EditNextCell);
    }

    return {
      disabledKeyboardInteractions,
      hideActiveIndicator: true,
    };
  }, [focusIndex, val]);

  useCellOptions(cellOptions);

  const listWithTitles = useMemo(
    () => buildListWithTitles(store, allowsOnly),
    [allowsOnly],
  );

  const handleSearch = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const query = stringToSlug(e.target.value);
      const filtered = listWithTitles.filter(v => v.title.includes(query));
      setFilteredTags(filtered.map(v => v.subject));
      setSelectedIndex(0);
    },
    [listWithTitles],
  );

  const handleAddTag = useCallback(
    (subject: string) => {
      onChange(Array.from(new Set([...val, subject])));
    },
    [val, onChange],
  );

  const handleRemoveTag = useCallback(
    (subject: string) => {
      onChange(val.filter(tagSubject => tagSubject !== subject));
    },
    [val, onChange],
  );

  const changeSelection = useCallback(
    (mod: number) => {
      setSelectedIndex(prev => loopingIndex(prev + mod, filteredTags.length));
    },
    [filteredTags],
  );

  useEffect(() => {
    if (!open) {
      activeCellRef.current?.focus();
    }
  }, [open]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
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
          handleAddTag(filteredTags[selectedIndex]);
          break;
        case 'Escape':
          e.preventDefault();

          setOpen(false);
          break;
      }
    },
    [changeSelection, filteredTags, selectedIndex, open],
  );

  return (
    <AbsoluteCell>
      <Row gap={TAG_SPACING} center wrapItems>
        {val.map((v, i) => (
          <Tag subject={v} key={v}>
            <TagIconButton
              title='remove tag'
              onFocus={() => {
                setFocusIndex(i);
              }}
              onClick={() => handleRemoveTag(v)}
            >
              <FaTimes />
            </TagIconButton>
          </Tag>
        ))}
        <Popover
          defaultOpen
          open={open}
          onOpenChange={setOpen}
          Trigger={
            <IconButton
              title='Add tag'
              as={RadixPopover.Trigger}
              onFocus={() => {
                setFocusIndex(val.length);
              }}
            >
              <StyledIcon />
            </IconButton>
          }
        >
          <Content onKeyDown={handleKeyDown}>
            <SearchInputWrapper>
              <InputStyled
                placeholder='Filter tags...'
                onChange={handleSearch}
              />
            </SearchInputWrapper>
            <ResultWrapper>
              <Row wrapItems gap={TAG_SPACING}>
                {filteredTags.map((v, i) => (
                  <SelectableTag
                    key={v}
                    subject={v}
                    onClick={handleAddTag}
                    selected={i === selectedIndex}
                  />
                ))}
              </Row>
            </ResultWrapper>
          </Content>
        </Popover>
      </Row>
    </AbsoluteCell>
  );
}

function ResourceArrayCellDisplay({
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

const AbsoluteCell = styled.div`
  position: absolute;
  display: flex;
  align-items: center;
  z-index: 10;
  left: 0;
  top: 0;
  background-color: ${p => p.theme.colors.bg};
  box-shadow: ${p => p.theme.boxShadowSoft};
  border: 2px solid ${p => p.theme.colors.main};
  height: fit-content;
  width: 100%;
  padding-inline: var(--table-inner-padding);
  padding-block: 3px;
  min-height: 40px;
`;

const Content = styled.div`
  width: min(40ch, 90vh);
  border-radius: ${p => p.theme.radius};
`;

const ResultWrapper = styled.div`
  padding: ${p => p.theme.margin}rem;
`;

const SearchInputWrapper = styled(InputWrapper)`
  border-bottom-left-radius: 0;
  border-bottom-right-radius: 0;
`;

export const ResourceArrayCell: CellContainer<JSONValue> = {
  Edit: ResourceArrayCellEdit,
  Display: ResourceArrayCellDisplay,
};
