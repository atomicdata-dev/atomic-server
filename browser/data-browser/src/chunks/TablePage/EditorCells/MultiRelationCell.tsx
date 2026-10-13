import {
  core,
  Core,
  JSONValue,
  unknownSubject,
  urls,
  useArray,
  useResource,
  useTitle,
} from '@tomic/react';
import { useEffect, useRef, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { getIconForClass } from '@helpers/iconMap';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';
import { useResourceSearch } from './useResourceSearch';
import { IconButton } from '@components/IconButton/IconButton';
import { KeyboardInteraction, useCellOptions } from '@chunks/TableEditor';
import {
  CursorMode,
  useTableEditorContext,
} from '@chunks/TableEditor/TableEditorContext';
import { InlineFormattedResourceList } from '@components/InlineFormattedResourceList';
import { FaPlus, FaXmark } from 'react-icons/fa6';
import {
  AbsoluteCell,
  SearchPopover,
  SearchResultWrapper,
} from './CellComponents';
import { Row } from '@components/Row';
import { Checkbox } from '@components/forms/Checkbox';
import { ResourceCell } from './ResourceCells/ResourceCell';
import { AtomicLink } from '@components/AtomicLink';
import { useRowConstraint } from '../useColumnConstraint';
import { usePopover } from '@components/CustomPopover';
import { CELL_WIDTH } from '@chunks/TableEditor/Cell';

// The linked class comes from the row's class constraints, falling back to the
// Property's legacy `classtype`.
const useClassType = (subject: string, rowClasses: string[]) => {
  const { class: linkedClass } = useRowConstraint(rowClasses, subject);

  const classType = useResource<Core.Class>(linkedClass);
  const hasClassType = classType?.subject !== unknownSubject;

  return {
    classType,
    hasClassType,
  };
};

function MultiRelationCellEdit({
  value,
  onChange,
  property,
  resource: row,
}: EditCellProps<JSONValue>): JSX.Element {
  const inputRef = useRef<HTMLInputElement>(null);
  const val = Array.isArray(value) ? value : [];
  const { classType, hasClassType } = useClassType(property, row.getClasses());
  const { triggerProps, popoverProps } = usePopover({
    defaultOpen: true,
    autoFocusElement: inputRef,
  });
  const { setCursorMode } = useTableEditorContext();
  const selectedElement = useRef<HTMLLIElement>(null);

  const [searchValue, setSearchValue] = useState('');

  const disabledKeyboardInteractions = new Set<KeyboardInteraction>([
    KeyboardInteraction.EditNextRow,
  ]);

  useCellOptions({
    disabledKeyboardInteractions,
    hideActiveIndicator: true,
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setSearchValue(e.target.value);
  };

  const handleResultClick = (result: string, source: 'keyboard' | 'mouse') => {
    if (!result) return;

    if (val.includes(result)) {
      onChange(val.filter(v => v !== result));
    } else {
      onChange([...val, result]);
    }

    // Enter picks and finishes: exiting edit mode unmounts this popover and
    // hands focus back to the grid (same path as the Escape key, see
    // TableEditor.tsx's Edit -> Visual layout effect), so arrow keys work
    // immediately after picking. Mouse clicks (e.g. on the result
    // checkboxes) keep the popover open so multi-select stays reachable.
    if (source === 'keyboard') {
      setCursorMode(CursorMode.Visual);
    }
  };

  const handleRemoveItem = (subject: string) => {
    onChange(val.filter(v => v !== subject));
  };

  const {
    results,
    selectedIndex,
    handleKeyDown,
    onMouseOver,
    onClick,
    usingKeyboard,
  } = useResourceSearch(
    searchValue,
    hasClassType ? classType.subject : undefined,
    handleResultClick,
    val as string[],
  );

  useEffect(() => {
    if (selectedElement.current && usingKeyboard) {
      selectedElement.current.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex, usingKeyboard]);

  const placehoder = hasClassType ? `Search ${classType.title}` : 'Search...';

  const showNoResults =
    results.length === 0 && classType.subject !== urls.classes.file;

  return (
    <AbsoluteCell>
      <Row wrapItems gap='1ch'>
        <SearchPopover
          noLock
          Trigger={
            <IconButton title='Add resource' {...triggerProps}>
              <FaPlus />
            </IconButton>
          }
          {...popoverProps}
        >
          <InputWrapper>
            <InputStyled
              type='search'
              value={searchValue}
              placeholder={placehoder}
              onChange={handleChange}
              onKeyDown={handleKeyDown}
              ref={inputRef}
            />
          </InputWrapper>
          <SearchResultWrapper>
            {results.length > 0 && (
              <ol>
                {results.map((result, index) => (
                  <li
                    key={result}
                    data-selected={index === selectedIndex}
                    ref={index === selectedIndex ? selectedElement : null}
                  >
                    <Result
                      subject={result}
                      onClick={() => onClick(index)}
                      onMouseOver={() => onMouseOver(index)}
                      selected={val.includes(result)}
                    />
                  </li>
                ))}
              </ol>
            )}
            {showNoResults && 'No results'}
          </SearchResultWrapper>
        </SearchPopover>
        {(val as string[])?.map(subject => (
          <ResourceItemButton
            subject={subject}
            key={subject}
            onRemove={handleRemoveItem}
          />
        ))}
      </Row>
    </AbsoluteCell>
  );
}

interface ResourceItemButtonProps {
  subject: string;
  onRemove: (subject: string) => void;
}

function ResourceItemButton({
  subject,
  onRemove,
}: ResourceItemButtonProps): JSX.Element {
  const resource = useResource(subject);

  return (
    <ResourceItemButtonWrapper>
      <TruncatedAtomicLink clean subject={resource.subject}>
        {resource.title}
      </TruncatedAtomicLink>
      <IconButton
        title={`remove ${resource.title}`}
        onClick={() => onRemove(subject)}
      >
        <FaXmark />
      </IconButton>
    </ResourceItemButtonWrapper>
  );
}

function MultiRelationCellDisplay({
  value,
}: DisplayCellProps<JSONValue>): JSX.Element {
  if (!value || !Array.isArray(value)) {
    return <></>;
  }

  return (
    <div>
      <InlineFormattedResourceList
        subjects={value as string[]}
        RenderComp={ResourceCell}
      />
    </div>
  );
}

interface ResultProps {
  subject: string;
  onClick: () => void;
  onMouseOver: () => void;
  selected: boolean;
}

function Result({ subject, onClick, onMouseOver, selected }: ResultProps) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  const [[classType]] = useArray(resource, core.properties.isA);

  const Icon = getIconForClass(classType);

  return (
    <ResultButton onClick={onClick} onMouseOver={onMouseOver} tabIndex={-1}>
      <Checkbox checked={selected} onChange={() => undefined}></Checkbox>
      <Icon />
      {title}
    </ResultButton>
  );
}

export const MultiRelationCell: CellContainer<JSONValue> = {
  Edit: MultiRelationCellEdit,
  Display: MultiRelationCellDisplay,
};

const TruncatedAtomicLink = styled(AtomicLink)`
  max-width: calc(${CELL_WIDTH.var()} - 4.5rem);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const ResourceItemButtonWrapper = styled.span`
  display: inline-flex;
  padding-inline: 1ch;
  align-items: center;
  border: 1px solid ${p => p.theme.colors.main};
  color: ${p => p.theme.colors.mainDark};
  border-radius: ${p => p.theme.radius};
`;

const ResultButton = styled.button`
  display: flex;
  width: 100%;
  align-items: center;
  gap: 0.5rem;
  background: none;
  border: none;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;
  padding: 0.3rem;
  border-radius: ${p => p.theme.radius};

  svg {
    color: ${p => p.theme.colors.textLight};
  }
`;
