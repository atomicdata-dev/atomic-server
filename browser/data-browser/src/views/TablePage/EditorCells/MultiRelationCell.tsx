import {
  Core,
  JSONValue,
  unknownSubject,
  urls,
  useArray,
  useResource,
  useTitle,
} from '@tomic/react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { styled } from 'styled-components';
import {
  InputStyled,
  InputWrapper,
} from '../../../components/forms/InputStyles';
import { useTableEditorContext } from '../../../components/TableEditor/TableEditorContext';
import { getIconForClass } from '../../../helpers/iconMap';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';
import { useResourceSearch } from './useResourceSearch';
import { IconButton } from '../../../components/IconButton/IconButton';
import {
  KeyboardInteraction,
  useCellOptions,
} from '../../../components/TableEditor';
import { InlineFormattedResourceList } from '../../../components/InlineFormattedResourceList';
import { FaPlus, FaXmark } from 'react-icons/fa6';
import {
  AbsoluteCell,
  PopoverTrigger,
  SearchPopover,
  SearchResultWrapper,
} from './CellComponents';
import { Row } from '../../../components/Row';
import { CellOptions } from '../../../components/TableEditor/hooks/useCellOptions';
import { Checkbox } from '../../../components/forms/Checkbox';
import { ResourceCell } from './ResourceCells/ResourceCell';
import { AtomicLink } from '../../../components/AtomicLink';

const useClassType = (subject: string) => {
  const property = useResource<Core.Property>(subject);

  const classType = useResource<Core.Class>(property.props.classtype);
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
}: EditCellProps<JSONValue>): JSX.Element {
  const val = Array.isArray(value) ? value : [];

  const { classType, hasClassType } = useClassType(property);
  const [open, setOpen] = useState(true);
  const { setCursorMode, activeCellRef } = useTableEditorContext();
  const selectedElement = useRef<HTMLLIElement>(null);

  const [searchValue, setSearchValue] = useState('');

  const cellOptions = useMemo((): CellOptions => {
    const disabledKeyboardInteractions = new Set<KeyboardInteraction>([
      KeyboardInteraction.EditNextRow,
    ]);

    if (open) {
      disabledKeyboardInteractions.add(KeyboardInteraction.ExitEditMode);
    }

    return {
      disabledKeyboardInteractions,
      hideActiveIndicator: true,
    };
  }, [val, open]);

  useCellOptions(cellOptions);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setSearchValue(e.target.value);
  }, []);

  const handleResultClick = useCallback(
    (result: string) => {
      if (!result) return;

      if (val.includes(result)) {
        onChange(val.filter(v => v !== result));
      } else {
        onChange([...val, result]);
      }
    },
    [onChange, val],
  );

  const handleRemoveItem = (subject: string) => {
    onChange(val.filter(v => v !== subject));
  };

  const handleOpenChange = useCallback(
    (state: boolean) => {
      setOpen(state);
    },
    [setCursorMode],
  );

  const { results, selectedIndex, handleKeyDown } = useResourceSearch(
    searchValue,
    hasClassType ? classType.subject : undefined,
    setOpen,
    handleResultClick,
  );

  const Trigger = useMemo(() => {
    return (
      <PopoverTrigger>
        <IconButton title={'Add resource'}>
          <FaPlus />
        </IconButton>
      </PopoverTrigger>
    );
  }, []);

  useEffect(() => {
    if (!open) {
      activeCellRef.current?.focus();
    }
  }, [open]);

  useEffect(() => {
    if (selectedElement.current) {
      selectedElement.current.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex]);

  const placehoder = hasClassType ? `Search ${classType.title}` : 'Search...';

  const showNoResults =
    results.length === 0 && classType.subject !== urls.classes.file;

  return (
    <AbsoluteCell>
      <Row wrapItems gap='1ch'>
        {(value as string[])?.map(subject => (
          <ResourceItemButton
            subject={subject}
            key={subject}
            onRemove={handleRemoveItem}
          />
        ))}
        <SearchPopover
          modal
          Trigger={Trigger}
          open={open}
          onOpenChange={handleOpenChange}
          noLock
        >
          <InputWrapper>
            <InputStyled
              type='search'
              value={searchValue}
              placeholder={placehoder}
              onChange={handleChange}
              onKeyDown={handleKeyDown}
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
                      onClick={handleResultClick}
                      selected={val.includes(result)}
                    />
                  </li>
                ))}
              </ol>
            )}
            {showNoResults && 'No results'}
          </SearchResultWrapper>
        </SearchPopover>
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
      <AtomicLink clean subject={resource.subject}>
        {resource.title}
      </AtomicLink>
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
  onClick: (subject: string) => void;
  selected: boolean;
}

function Result({ subject, onClick, selected }: ResultProps) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  const [[classType]] = useArray(resource, urls.properties.isA);

  const Icon = getIconForClass(classType);

  return (
    <ResultButton onClick={() => onClick(subject)} tabIndex={-1}>
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
  color: currentColor;
  cursor: pointer;
  padding: 0.3rem;
  border-radius: ${p => p.theme.radius};
  &:hover {
    background: ${p => p.theme.colors.main};
    color: white;

    svg {
      color: white;
    }
  }

  svg {
    color: ${p => p.theme.colors.textLight};
  }
`;
