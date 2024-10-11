import React, { useCallback, useMemo, useState } from 'react';
import { useArray, validateDatatype } from '@tomic/react';
import { Button } from '../Button';
import { InputProps } from './ResourceField';
import { ErrMessage } from './InputStyles';
import { ResourceSelector, ResourceSelectorProps } from './ResourceSelector';
import { Column, Row } from '../Row';
import { styled } from 'styled-components';
import { useIndexDependantCallback } from '../../hooks/useIndexDependantCallback';
import {
  DndContext,
  DragEndEvent,
  DragOverlay,
  useDraggable,
  useDroppable,
} from '@dnd-kit/core';
import { transition } from '../../helpers/transition';
import { FaGripVertical, FaPlus, FaTrash } from 'react-icons/fa6';
import { createPortal } from 'react-dom';
import { transparentize } from 'polished';
import { useValidation } from './formValidation/useValidation';

interface InputResourceArrayProps extends InputProps {
  isA?: string;
}

export default function InputResourceArray({
  resource,
  property,
  commit,
  required,
  id: _id,
  ...props
}: InputResourceArrayProps): JSX.Element {
  const [draggingSubject, setDraggingSubject] = useState<string>();
  const [addingNewItem, setAddingNewItem] = useState(false);

  const [array, setArray] = useArray(resource, property.subject, {
    validate: false,
    commit,
  });

  const { error, setError, setTouched } = useValidation(
    required ? (array.length > 0 ? undefined : 'Required') : undefined,
  );

  function handleAddRow() {
    setAddingNewItem(true);
  }

  function handleClear() {
    setArray(undefined);
    setAddingNewItem(false);
  }

  const handleRemoveRowList = useIndexDependantCallback(
    (index: number) => () => {
      const newArray = [...array];
      newArray.splice(index, 1);
      setArray(newArray.length === 0 ? undefined : newArray);

      if (required && newArray.length === 0) {
        setError('Required');
      }
    },
    array,
    [setArray, required, setError],
  );

  const handleSetSubject = useCallback(
    (index: number, value: string | undefined) => {
      const newArray = [...array];

      if (value) {
        newArray[index] = value;

        try {
          validateDatatype(newArray, property.datatype);
          setArray(newArray);
          setError(undefined);
        } catch (e) {
          setError(e.message);

          return;
        }
      }

      if (required) {
        setError(newArray.length === 0 ? 'Required' : undefined);
      }
    },
    [property.datatype, setArray, setError, required, addingNewItem, array],
  );

  const handleSetSubjectMemos = useMemo(() => {
    return array.map(
      (_, i) => (value: string | undefined) => handleSetSubject(i, value),
    );
  }, [array, handleSetSubject]);

  const handleDragEnd = ({ active, over }: DragEndEvent) => {
    setDraggingSubject(undefined);

    if (!over) {
      return;
    }

    const oldPos = array.indexOf(active.id as string);
    const newPos = over.id as number;
    const newArray = [...array];
    const [removed] = newArray.splice(oldPos, 1);
    newArray.splice(newPos > oldPos ? newPos - 1 : newPos, 0, removed);
    setArray(newArray);
  };

  return (
    <Column>
      {(array.length > 0 || addingNewItem) && (
        <DndContext
          onDragStart={event => setDraggingSubject(event.active.id as string)}
          onDragCancel={() => setDraggingSubject(undefined)}
          onDragEnd={handleDragEnd}
        >
          <RelativeContainer>
            <DropEdge visible={!!draggingSubject} index={0} />
            {array.map((subject, index) => (
              <React.Fragment key={`${property.subject}${index}`}>
                <DraggableResourceSelector
                  first={index === 0}
                  last={index === array.length - 1 && !addingNewItem}
                  subject={subject}
                  value={subject}
                  setSubject={handleSetSubjectMemos[index]}
                  isA={property.classType}
                  handleRemove={handleRemoveRowList[index]}
                  parent={resource.subject}
                  allowsOnly={property.allowsOnly}
                  hideClearButton
                  onBlur={setTouched}
                  {...props}
                />
                {!(subject === undefined && index === array.length - 1) && (
                  <DropEdge visible={!!draggingSubject} index={index + 1} />
                )}
              </React.Fragment>
            ))}
            {addingNewItem && (
              <ResourceSelector
                first={array.length === 0}
                last={true}
                value={undefined}
                setSubject={v => {
                  handleSetSubject(array.length, v);
                  setAddingNewItem(false);
                }}
                isA={property.classType}
                handleRemove={() => setAddingNewItem(false)}
                parent={resource.subject}
                allowsOnly={property.allowsOnly}
                hideClearButton
                onBlur={setTouched}
                {...props}
              />
            )}
            {createPortal(
              <StyledDragOverlay>
                {!!draggingSubject && (
                  <DummySelector
                    first
                    last
                    id={draggingSubject}
                    value={draggingSubject}
                    setSubject={() => undefined}
                    isA={property.classType}
                    handleRemove={() => undefined}
                    hideClearButton
                    onBlur={setTouched}
                    parent={resource.subject}
                    {...props}
                  />
                )}
              </StyledDragOverlay>,
              document.body,
            )}
          </RelativeContainer>
        </DndContext>
      )}
      {!props.disabled && (
        <Row justify='space-between'>
          <AddButton
            title={`Add an item to the ${property.shortname} list`}
            data-testid={`input-${property.shortname}-add-resource`}
            subtle
            type='button'
            onClick={handleAddRow}
            disabled={addingNewItem}
          >
            <FaPlus />
          </AddButton>
          {array.length > 1 && (
            <StyledButton
              title='Remove all items from this list'
              data-testid={`input-${property.shortname}-clear`}
              subtle
              type='button'
              onClick={handleClear}
            >
              <Row gap='.5rem'>
                <FaTrash /> Clear
              </Row>
            </StyledButton>
          )}
        </Row>
      )}
      {!!error && <ErrMessage>{error}</ErrMessage>}
    </Column>
  );
}

interface DropEdgeProps {
  index: number;
  visible: boolean;
}

const DropEdge = ({ index, visible }: DropEdgeProps) => {
  const { setNodeRef, isOver } = useDroppable({
    id: index,
  });

  return <DropEdgeElement ref={setNodeRef} active={isOver} visible={visible} />;
};

type DraggableResourceSelectorProps = ResourceSelectorProps & {
  subject: string;
};

const DraggableResourceSelector = ({
  subject,
  ...props
}: DraggableResourceSelectorProps) => {
  const { attributes, listeners, setNodeRef, active } = useDraggable({
    id: subject,
    disabled: props.disabled,
  });

  if (subject === undefined) {
    return <ResourceSelector {...props} />;
  }

  return (
    <DragWrapper ref={setNodeRef} active={active?.id === subject}>
      <ResourceSelector
        {...props}
        prefix={
          !props.disabled ? (
            <DragHandle
              {...listeners}
              {...attributes}
              disabled={props.disabled}
              type='button'
              title='Move item'
            >
              <FaGripVertical />
            </DragHandle>
          ) : null
        }
      />
    </DragWrapper>
  );
};

const DummySelector = (props: ResourceSelectorProps) => {
  return (
    <DragWrapper active={false}>
      <ResourceSelector
        {...props}
        prefix={
          <DragHandle type='button'>
            <FaGripVertical />
          </DragHandle>
        }
      />
    </DragWrapper>
  );
};

const StyledDragOverlay = styled(DragOverlay)`
  --search-box-bg: ${p => transparentize(0.5, p.theme.colors.bg)};
  backdrop-filter: blur(3px);
`;

const RelativeContainer = styled.div`
  position: relative;
`;

const DragHandle = styled.button`
  display: flex;
  align-items: center;
  cursor: grab;
  appearance: none;
  background: transparent;
  border: none;
  &:active {
    cursor: grabbing;
    svg {
      color: ${p => p.theme.colors.textLight};
    }
  }

  svg {
    color: ${p => p.theme.colors.textLight2};
  }
`;

const DragWrapper = styled(Row)<{ active: boolean }>`
  position: relative;
  opacity: ${p => (p.active ? 0.4 : 1)};
  width: 100%;

  &:hover {
    ${DragHandle} svg {
      color: ${p => p.theme.colors.textLight};
    }
  }
`;

const StyledButton = styled(Button)`
  align-self: flex-start;
`;

const AddButton = styled(Button)`
  align-self: flex-start;
  width: 100%;
  box-shadow: none;
  border: 1px dashed ${p => p.theme.colors.bg2};
  background: none;

  &:not(:disabled) {
    &:hover,
    &:focus-visible {
      border: 1px solid ${p => p.theme.colors.main};
      box-shadow: none !important;
    }
  }
`;

const DropEdgeElement = styled.div<{ visible: boolean; active: boolean }>`
  display: ${p => (p.visible ? 'block' : 'none')};
  position: absolute;
  height: 3px;
  border-radius: 1.5px;
  transform: scaleX(${p => (p.active ? 1.1 : 1)});
  background: ${p => p.theme.colors.main};
  opacity: ${p => (p.active ? 1 : 0)};
  z-index: 2;
  width: 100%;

  ${transition('opacity', 'transform')}
`;
