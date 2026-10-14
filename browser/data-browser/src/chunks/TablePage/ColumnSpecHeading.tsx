import { useState, type JSX, type ReactNode } from 'react';
import { styled } from 'styled-components';
import { FaGripVertical, FaPencil, FaXmark } from 'react-icons/fa6';
import { DropdownMenu, type DropdownItem } from '@components/Dropdown';
import { buildDefaultTrigger } from '@components/Dropdown/DefaultTrigger';
import { AutoOpenTrigger } from '@components/Dropdown/AutoOpenTrigger';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '@components/ConfirmationDialog';
import type { DraggableAttributes } from '@dnd-kit/core';
import type { SyntheticListenerMap } from '@dnd-kit/core/dist/hooks/utilities';

export interface ColumnSpecHeadingProps {
  spec: { id: string; label: string };
  readOnly: boolean;
  dragListeners?: SyntheticListenerMap;
  dragAttributes?: DraggableAttributes;
  /** Tooltip on the label, from the generator registry. */
  generatorTitle?: string;
  /** Trigger of the edit menu, built once per caller with its own aria label. */
  Trigger: ReturnType<typeof buildDefaultTrigger>;
  removeTitle: string;
  /** The body of the remove confirmation. */
  removeBody: ReactNode;
  onRemove: () => void;
  /**
   * Renders the edit dialog. Called only while the dialog is open, so a table
   * with three such columns does not keep three closed dialogs in the DOM,
   * whose fields answer to the same test ids and labels as the open one.
   */
  renderEditDialog: (props: { bindShow: (show: boolean) => void }) => ReactNode;
}

/**
 * Heading of a column that is configured rather than stored (a computed column
 * or an action column): its label plus the menu that edits or removes it.
 * It drags like any other column, because where it sits is the view's column
 * order.
 */
export function ColumnSpecHeading({
  spec,
  readOnly,
  dragListeners,
  dragAttributes,
  generatorTitle,
  Trigger,
  removeTitle,
  removeBody,
  onRemove,
  renderEditDialog,
}: ColumnSpecHeadingProps): JSX.Element {
  const [showEdit, setShowEdit] = useState(false);
  const [showRemove, setShowRemove] = useState(false);
  const [menuPoint, setMenuPoint] = useState<{ x: number; y: number }>();

  const items: DropdownItem[] = [
    {
      id: 'edit',
      label: 'Edit',
      icon: <FaPencil />,
      onClick: () => setShowEdit(true),
    },
    {
      id: 'remove',
      label: 'Remove',
      icon: <FaXmark />,
      onClick: () => setShowRemove(true),
    },
  ];

  if (readOnly) {
    return <Wrapper>{spec.label}</Wrapper>;
  }

  return (
    <Wrapper
      onContextMenu={e => {
        e.preventDefault();
        setMenuPoint({ x: e.clientX, y: e.clientY });
      }}
    >
      {/* Same handle as a stored column: where the column sits is part of the
       *  view's configuration too. */}
      <DragIconButton
        {...dragListeners}
        {...dragAttributes}
        title='Drag column'
        aria-label='Drag column'
      >
        <FaGripVertical />
      </DragIconButton>
      <Label title={generatorTitle}>{spec.label}</Label>
      <MenuWrapper>
        <DropdownMenu Trigger={Trigger} items={items} />
      </MenuWrapper>
      {menuPoint && (
        <DropdownMenu
          Trigger={AutoOpenTrigger}
          items={items}
          anchorPoint={menuPoint}
          bindActive={active => !active && setMenuPoint(undefined)}
        />
      )}
      {showEdit && renderEditDialog({ bindShow: setShowEdit })}
      <ConfirmationDialog
        title={removeTitle}
        confirmLabel='Remove'
        show={showRemove}
        bindShow={setShowRemove}
        theme={ConfirmationDialogTheme.Alert}
        onConfirm={onRemove}
      >
        {removeBody}
      </ConfirmationDialog>
    </Wrapper>
  );
}

const Wrapper = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  width: 100%;
  align-self: stretch;
  color: ${p => p.theme.colors.textLight};
  /* Matches a property heading: the header cell is bold, its name button is not. */
  font-weight: normal;
  /* The menu button must survive a narrow column — it's the only way to edit
   * or remove this column. */
  min-width: 0;
`;

const DragIconButton = styled.button`
  background: none;
  color: currentColor;
  display: flex;
  align-items: center;
  border: none;
  height: 1rem;
  padding: 0;
  cursor: grab;
  flex-shrink: 0;

  &:active {
    cursor: grabbing;
  }

  svg {
    color: currentColor;
    max-width: 1rem;
    min-width: 1rem;
  }
`;

const Label = styled.span`
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const MenuWrapper = styled.div`
  margin-left: auto;
  flex-shrink: 0;

  & > button {
    color: ${p => p.theme.colors.textLight};
  }
`;
