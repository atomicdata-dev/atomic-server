import {
  Core,
  JSONValue,
  Resource,
  core,
  server,
  unknownSubject,
  useArray,
  useResource,
  useString,
  useTitle,
} from '@tomic/react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { FaEdit } from 'react-icons/fa';
import { styled } from 'styled-components';
import { FileDropzoneInput } from '../../../components/forms/FileDropzone/FileDropzoneInput';
import {
  InputStyled,
  InputWrapper,
} from '../../../components/forms/InputStyles';
import {
  CursorMode,
  useTableEditorContext,
} from '../../../components/TableEditor/TableEditorContext';
import { getIconForClass } from '../../FolderPage/iconMap';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';
import { useResourceSearch } from './useResourceSearch';
import { IconButton } from '../../../components/IconButton/IconButton';
import { AtomicLink } from '../../../components/AtomicLink';
import {
  KeyboardInteraction,
  useCellOptions,
} from '../../../components/TableEditor';
import { ResourceCell } from './ResourceCells/ResourceCell';
import {
  PopoverTrigger,
  SearchPopover,
  SearchResultWrapper,
} from './CellComponents';
import { FaXmark } from 'react-icons/fa6';

const useClassType = (subject: string) => {
  const property = useResource<Core.Property>(subject);

  const classType = useResource<Core.Class>(property.props.classtype);
  const hasClassType = classType?.subject !== unknownSubject;

  return {
    classType,
    hasClassType,
  };
};

function AtomicURLCellEdit({
  value,
  onChange,
  property,
  resource: row,
}: EditCellProps<JSONValue>): JSX.Element {
  const cell = useResource(value as string);
  const { classType, hasClassType } = useClassType(property);
  const [title] = useTitle(cell);
  const [open, setOpen] = useState(true);
  const { setCursorMode } = useTableEditorContext();
  const selectedElement = useRef<HTMLLIElement>(null);

  const [searchValue, setSearchValue] = useState('');

  const cellOptions = useMemo(() => {
    if (open) {
      return {
        disabledKeyboardInteractions: new Set([
          KeyboardInteraction.ExitEditMode,
        ]),
      };
    } else {
      return {};
    }
  }, [open]);

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
    hasClassType ? classType.subject : undefined,
    setOpen,
    handleResultClick,
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
        {cell.subject === unknownSubject
          ? `select ${hasClassType ? classType.title : 'resource'}`
          : title}
      </PopoverTrigger>
    );
  }, [title, cell, classType, hasClassType]);

  useEffect(() => {
    if (selectedElement.current) {
      selectedElement.current.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex]);

  const placehoder = hasClassType ? `Search ${classType.title}` : 'Search...';

  const showFileDropzone =
    results.length === 0 && classType.subject === server.classes.file;
  const showNoResults =
    results.length === 0 && classType.subject !== server.classes.file;

  return (
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
      </SearchResultWrapper>
    </SearchPopover>
  );
}

function AtomicURLCellDisplay({
  value,
}: DisplayCellProps<JSONValue>): JSX.Element {
  if (!value) {
    return <></>;
  }

  return <ResourceCell subject={value as string} />;
}

interface ResultProps {
  subject: string;
  onClick: (subject: string) => void;
}

function Result({ subject, onClick }: ResultProps) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  const [[classType]] = useArray(resource, core.properties.isA);

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
  const [mimeType] = useString(cellResource, server.properties.mimetype);
  const [downloadUrl] = useString(cellResource, server.properties.downloadUrl);
  const [filename] = useString(cellResource, server.properties.filename);
  const [description] = useString(cellResource, core.properties.description);

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
        <AtomicLink subject={cellResource.subject}>{filename}</AtomicLink>
      ) : null}
      <ClearFileButton title='Clear' onClick={() => onChange(undefined)}>
        <FaXmark />
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

const StyledFileDropzoneInput = styled(FileDropzoneInput)`
  height: 100%;
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
