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
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
} from 'react';
import { FaPencil } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { FileDropzoneInput } from '@components/forms/FileDropzone/FileDropzoneInput';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles'; ////
import { getIconForClass } from '@helpers/iconMap';
import { asSubject } from '@helpers/formatPlainValue';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';
import { useResourceSearch } from './useResourceSearch';
import { IconButton } from '@components/IconButton/IconButton';
import { AtomicLink } from '@components/AtomicLink';
import { KeyboardInteraction, useCellOptions } from '@chunks/TableEditor';
import { ResourceCell } from './ResourceCells/ResourceCell';
import {
  PopoverTrigger,
  SearchPopover,
  SearchResultWrapper,
} from './CellComponents';
import { FaXmark } from 'react-icons/fa6';
import { useRowConstraint } from '../useColumnConstraint';
import { usePopover } from '@components/CustomPopover';
import { useTableEditorContext } from '@chunks/TableEditor/TableEditorContext';

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

function AtomicURLCellEdit({
  value,
  onChange,
  property,
  resource: row,
}: EditCellProps<JSONValue>): JSX.Element {
  const inputRef = useRef<HTMLInputElement>(null);
  const cell = useResource(asSubject(value));
  const { classType, hasClassType } = useClassType(property, row.getClasses());
  const [title] = useTitle(cell);
  // `defaultOpen` only seeds the *initial* isOpen state — if this component
  // remounts (e.g. its row briefly re-resolving after this cell's own save,
  // see TableRow.tsx), a bare `true` would force the picker back open even
  // though a value was already picked and the popover was explicitly closed
  // moments earlier. Only auto-open for a cell that's actually empty.
  const { triggerProps, popoverProps, closePopover } = usePopover({
    defaultOpen: !value,
    autoFocusElement: inputRef,
  });
  const { isOpen } = popoverProps;
  const { exitEditMode } = useTableEditorContext();
  const selectedElement = useRef<HTMLLIElement>(null);

  const [searchValue, setSearchValue] = useState('');

  const cellOptions = useMemo(() => {
    if (isOpen) {
      return {
        disabledKeyboardInteractions: new Set([
          KeyboardInteraction.ExitEditMode,
        ]),
      };
    } else {
      return {};
    }
  }, [isOpen]);

  useCellOptions(cellOptions);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setSearchValue(e.target.value);
  }, []);

  // Exiting edit mode (not just closing the popover) reuses the same,
  // already-correct focus-restore path as the Escape key — TableEditor.tsx's
  // Edit -> Visual layout effect refocuses the grid once cursorMode flips.
  // Closing only the popover proved unreliable here (this cell's row can
  // still be settling from its own save when the pick happens), so this is
  // the belt-and-suspenders finish: pick a value, done editing, back to the
  // grid — matching how a single-value cell should behave.
  const finishEditing = useCallback(() => {
    closePopover();
    exitEditMode();
  }, [closePopover, exitEditMode]);

  const handleResultClick = useCallback(
    (result: string) => {
      onChange(result);
      finishEditing();
    },
    [onChange, finishEditing],
  );

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
  );

  const handleFilesUploaded = useCallback(
    (files: string[]) => {
      const file = files[0];

      if (file) {
        onChange(file);
        finishEditing();
      }
    },
    [onChange, finishEditing],
  );

  const Trigger = useMemo(() => {
    return (
      <PopoverTrigger {...triggerProps}>
        <FaPencil />{' '}
        {cell.subject === unknownSubject
          ? `select ${hasClassType ? classType.title : 'resource'}`
          : title}
      </PopoverTrigger>
    );
  }, [title, cell, classType, hasClassType, triggerProps]);

  useEffect(() => {
    if (selectedElement.current && usingKeyboard) {
      selectedElement.current.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex, usingKeyboard]);

  const placehoder = hasClassType ? `Search ${classType.title}` : 'Search...';

  const showFileDropzone =
    results.length === 0 && classType.subject === server.classes.file;
  const showNoResults =
    results.length === 0 && classType.subject !== server.classes.file;

  return (
    <SearchPopover Trigger={Trigger} noLock {...popoverProps}>
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
                />
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

  // A non-string value is shown as text by ResourceCell itself.
  return <ResourceCell subject={value as string} />;
}

interface ResultProps {
  subject: string;
  onClick: () => void;
  onMouseOver: () => void;
}

function Result({ subject, onClick, onMouseOver }: ResultProps) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  const [[classType]] = useArray(resource, core.properties.isA);

  const Icon = getIconForClass(classType);

  return (
    <ResultButton onClick={onClick} onMouseOver={onMouseOver} tabIndex={-1}>
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
        // The cell holds one file, so offer one.
        maxFiles={1}
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
  color: ${p => p.theme.colors.text};
  padding: 0.3rem;
  border-radius: ${p => p.theme.radius};

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
