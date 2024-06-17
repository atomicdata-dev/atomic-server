import { useCallback, useState } from 'react';
import { ArrayError, useArray, validateDatatype } from '@tomic/react';
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

interface InputResourceArrayProps extends InputProps {
  isA?: string;
}

export default function InputResourceArray({
  resource,
  property,
  commit,
  ...props
}: InputResourceArrayProps): JSX.Element {
  const [err, setErr] = useState<ArrayError | undefined>(undefined);
  const [draggingSubject, setDraggingSubject] = useState<string>();
  const [array, setArray] = useArray(resource, property.subject, {
    validate: false,
    commit,
  });

  function handleAddRow() {
    setArray([...array, undefined]);
  }

  function handleClear() {
    setArray([]);
  }

  const handleRemoveRowList = useIndexDependantCallback(
    (index: number) => () => {
      const newArray = [...array];
      newArray.splice(index, 1);
      setArray(newArray);
    },
    array,
    [setArray],
  );

  const handleSetSubjectList = useIndexDependantCallback(
    (index: number) => (value: string | undefined) => {
      if (value) {
        const newArray = [...array];
        newArray[index] = value;

        try {
          validateDatatype(newArray, property.datatype);
          setArray(newArray);
          setErr(undefined);
        } catch (e) {
          setErr(e);
        }
      }
    },
    array,
    [property.datatype, setArray],
  );

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

  const errMaybe = useCallback(
    (index: number) => {
      if (err && err.index === index) {
        return err;
      }

      return undefined;
    },
    [err],
  );

  return (
    <Column>
      {array.length > 0 && (
        <DndContext
          onDragStart={event => setDraggingSubject(event.active.id as string)}
          onDragCancel={() => setDraggingSubject(undefined)}
          onDragEnd={handleDragEnd}
        >
          <RelativeContainer>
            <DropEdge visible={!!draggingSubject} index={0} />
            {array.map((subject, index) => (
              <>
                <DraggableResourceSelector
                  first={index === 0}
                  last={index === array.length - 1}
                  subject={subject}
                  key={`${property.subject}${index}`}
                  value={subject}
                  setSubject={handleSetSubjectList[index]}
                  error={errMaybe(index)}
                  isA={property.classType}
                  handleRemove={handleRemoveRowList[index]}
                  parent={resource.subject}
                  allowsOnly={property.allowsOnly}
                  hideClearButton
                  {...props}
                />
                {!(subject === undefined && index === array.length - 1) && (
                  <DropEdge visible={!!draggingSubject} index={index + 1} />
                )}
              </>
            ))}
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
      {!!err && <ErrMessage>{err?.message}</ErrMessage>}
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

  &:hover,
  &:focus-visible {
    border: 1px solid ${p => p.theme.colors.main};
    box-shadow: none !important;
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
