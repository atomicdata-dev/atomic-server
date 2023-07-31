import {
  JSONValue,
  Resource,
  unknownSubject,
  urls,
  useArray,
  useResource,
  useString,
  useTitle,
} from '@tomic/react';
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { FaEdit, FaTimes } from 'react-icons/fa';
import * as RadixPopover from '@radix-ui/react-popover';
import styled from 'styled-components';
import { FileDropzoneInput } from '../../../components/forms/FileDropzone/FileDropzoneInput';
import {
  InputStyled,
  InputWrapper,
} from '../../../components/forms/InputStyles';
import { Popover } from '../../../components/Popover';
import {
  CursorMode,
  useTableEditorContext,
} from '../../../components/TableEditor/TableEditorContext';
import { getIconForClass } from '../../FolderPage/iconMap';
import { AgentCell } from './ResourceCells/AgentCell';
import { FileCell } from './ResourceCells/FileCell';
import { SimpleResourceLink } from './ResourceCells/SimpleResourceLink';
import {
  CellContainer,
  DisplayCellProps,
  EditCellProps,
  ResourceCellProps,
} from './Type';
import { useResourceSearch } from './useResourceSearch';
import { IconButton } from '../../../components/IconButton/IconButton';
import { AtomicLink } from '../../../components/AtomicLink';
import {
  KeyboardInteraction,
  useCellOptions,
} from '../../../components/TableEditor';

const useClassType = (subject: string) => {
  const resource = useResource(subject);
  const [classType] = useString(resource, urls.properties.classType);
  const classTypeResource = useResource(classType);
  const [classTypeTitle] = useTitle(classTypeResource);

  return {
    classType,
    classTypeTitle,
  };
};

const cellOptions = {
  disabledKeyboardInteractions: new Set([KeyboardInteraction.EditNextRow]),
};

function AtomicURLCellEdit({
  value,
  onChange,
  property,
  resource: row,
}: EditCellProps<JSONValue>): JSX.Element {
  const cell = useResource(value as string);
  const { classType, classTypeTitle } = useClassType(property);
  const [title] = useTitle(cell);
  const [open, setOpen] = useState(true);
  const { setCursorMode } = useTableEditorContext();
  const selectedElement = useRef<HTMLLIElement>(null);

  const [searchValue, setSearchValue] = useState('');

  useCellOptions(cellOptions);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setSearchValue(e.target.value);
  }, []);

  const handleResultClick = useCallback(
    (result: string) => {
      onChange(result);
      setOpen(false);
    },
    [onChange],
  );

  const handleOpenChange = useCallback(
    (state: boolean) => {
      setOpen(state);

      if (!state) {
        setCursorMode(CursorMode.Visual);
      }
    },
    [setCursorMode],
  );

  const { results, selectedIndex, handleKeyDown } = useResourceSearch(
    searchValue,
    classType,
    handleResultClick,
  );

  const modifiedHandleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);

        return;
      }

      handleKeyDown(e);
    },
    [handleKeyDown],
  );

  const handleFilesUploaded = useCallback(
    (files: string[]) => {
      const file = files[0];

      if (file) {
        onChange(file);
        setOpen(false);
      }
    },
    [onChange, setOpen],
  );

  const Trigger = useMemo(() => {
    return (
      <PopoverTrigger>
        <FaEdit />{' '}
        {cell.getSubject() === unknownSubject
          ? `select ${classTypeTitle ?? 'resource'}`
          : title}
      </PopoverTrigger>
    );
  }, [title, cell, classTypeTitle]);

  useEffect(() => {
    if (selectedElement.current) {
      selectedElement.current.scrollIntoView(false);
    }
  }, [selectedIndex]);

  const placehoder = classType ? `Search ${classTypeTitle}` : 'Search...';

  const showFileDropzone =
    results.length === 0 && classType === urls.classes.file;
  const showNoResults = results.length === 0 && classType !== urls.classes.file;

  return (
    <SearchPopover
      Trigger={Trigger}
      open={open}
      onOpenChange={handleOpenChange}
    >
      <InputWrapper>
        <InputStyled
          type='search'
          value={searchValue}
          placeholder={placehoder}
          onChange={handleChange}
          onKeyDown={modifiedHandleKeyDown}
        />
      </InputWrapper>
      <ResultWrapper>
        {results.length > 0 && (
          <ol>
            {results.map((result, index) => (
              <li
                key={result}
                data-selected={index === selectedIndex}
                ref={index === selectedIndex ? selectedElement : null}
              >
                <Result subject={result} onClick={handleResultClick} />
              </li>
            ))}
          </ol>
        )}
        {showNoResults && 'No results'}
        {showFileDropzone && (
          <FileUploadContainer
            cellResource={cell}
            onChange={onChange}
            row={row}
            onFilesUploaded={handleFilesUploaded}
          />
        )}
      </ResultWrapper>
    </SearchPopover>
  );
}

function AtomicURLCellDisplay({
  value,
}: DisplayCellProps<JSONValue>): JSX.Element {
  const resource = useResource(value as string);
  const [[classType]] = useArray(resource, urls.properties.isA);

  if (!value) {
    return <></>;
  }

  const Comp = getCellComponent(classType);

  return <Comp resource={resource} />;
}

function BasicCell({ resource }: ResourceCellProps) {
  const [title] = useTitle(resource);

  return <SimpleResourceLink resource={resource}>{title}</SimpleResourceLink>;
}

const getCellComponent = (classType: string) => {
  switch (classType) {
    case urls.classes.agent:
      return AgentCell;
    case urls.classes.file:
      return FileCell;
    default:
      return BasicCell;
  }
};

interface ResultProps {
  subject: string;
  onClick: (subject: string) => void;
}

function Result({ subject, onClick }: ResultProps) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  const [[classType]] = useArray(resource, urls.properties.isA);

  const Icon = getIconForClass(classType);

  const handleClick = useCallback(() => {
    onClick(subject);
  }, [subject]);

  return (
    <ResultButton onClick={handleClick} tabIndex={-1}>
      <Icon />
      {title}
    </ResultButton>
  );
}

interface FileUploadContainerProps {
  cellResource: Resource;
  onFilesUploaded: (files: string[]) => void;
  row: Resource;
  onChange: (value: JSONValue) => void;
}

function FileUploadContainer({
  cellResource,
  onFilesUploaded,
  row,
  onChange,
}: FileUploadContainerProps): JSX.Element {
  const [mimeType] = useString(cellResource, urls.properties.file.mimetype);
  const [downloadUrl] = useString(
    cellResource,
    urls.properties.file.downloadUrl,
  );
  const [filename] = useString(cellResource, urls.properties.file.filename);
  const [description] = useString(cellResource, urls.properties.description);

  const isImage = mimeType?.startsWith('image/');

  if (!mimeType) {
    return (
      <StyledFileDropzoneInput
        parentResource={row}
        onFilesUploaded={onFilesUploaded}
      />
    );
  }

  return (
    <ViewerWrapper>
      {isImage && (
        <PreviewImg src={downloadUrl ?? ''} alt={description ?? ''} />
      )}
      {!isImage ? (
        <AtomicLink subject={cellResource.getSubject()}>{filename}</AtomicLink>
      ) : null}
      <ClearFileButton title='Clear' onClick={() => onChange(undefined)}>
        <FaTimes />
      </ClearFileButton>
    </ViewerWrapper>
  );
}

export const AtomicURLCell: CellContainer<JSONValue> = {
  Edit: AtomicURLCellEdit,
  Display: AtomicURLCellDisplay,
};

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

const SearchPopover = styled(Popover)`
  padding: 1rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;

const ResultWrapper = styled.div`
  height: min(90vh, 20rem);
  width: min(90vw, 35rem);
  overflow-x: hidden;
  overflow-y: auto;

  ol {
    padding: 0;
    margin: 0;
  }

  li {
    list-style: none;
    &[data-selected='true'] button {
      background: ${p => p.theme.colors.main};
      color: white;

      svg {
        color: white;
      }
    }
  }
`;

const StyledFileDropzoneInput = styled(FileDropzoneInput)`
  height: 100%;
`;

const PopoverTrigger = styled(RadixPopover.Trigger)`
  border: none;
  background: none;
  color: ${p => p.theme.colors.main};
  display: inline-flex;
  gap: 1ch;
  align-items: center;
  user-select: none;
  cursor: pointer;
`;

const ViewerWrapper = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100%;
  position: relative;
  padding: ${p => p.theme.margin}rem;
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => p.theme.colors.bg2};
`;

const ClearFileButton = styled(IconButton)`
  position: absolute;
  height: fit-content;
  top: ${p => p.theme.margin}rem;
  right: ${p => p.theme.margin}rem;
`;

const PreviewImg = styled.img`
  height: 100%;
  border-radius: ${p => p.theme.radius};
`;
