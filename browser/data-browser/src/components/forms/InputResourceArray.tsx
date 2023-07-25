import React, { useState } from 'react';
import { ArrayError, useArray } from '@tomic/react';
import { Button } from '../Button';
import { InputProps } from './ResourceField';
import { ErrMessage } from './InputStyles';
import { ResourceSelector } from './ResourceSelector';
import { FaPlus, FaTrash } from 'react-icons/fa';
import { Column, Row } from '../Row';
import styled from 'styled-components';

export default function InputResourceArray({
  resource,
  property,
  ...props
}: InputProps): JSX.Element {
  const [err, setErr] = useState<ArrayError | undefined>(undefined);
  const [array, setArray] = useArray(resource, property.subject, {
    handleValidationError: setErr,
  });
  /** Add focus to the last added item */
  const [lastIsNew, setLastIsNew] = useState(false);

  function handleAdd() {
    setArray([...array, undefined]);
    setLastIsNew(true);
  }

  function handleClear() {
    setArray([]);
    setLastIsNew(false);
  }

  function handleRemove(index: number) {
    array.splice(index, 1);
    const newArray = [...array];
    setArray(newArray);
  }

  function handleSetSubject(
    value: string | undefined,
    _handleErr,
    index: number,
  ) {
    if (value) {
      array[index] = value;
      setArray(array);
      setLastIsNew(false);
    }
  }

  function errMaybe(index: number) {
    if (err && err.index === index) {
      return err;
    }

    return undefined;
  }

  return (
    <Column>
      {array.length > 0 && (
        <div>
          {array.map((subject, index) => (
            <ResourceSelector
              key={`${property.subject}${index}`}
              value={subject}
              setSubject={(set, handleErr) =>
                handleSetSubject(set, handleErr, index)
              }
              error={errMaybe(index)}
              setError={setErr}
              classType={property.classType}
              handleRemove={() => handleRemove(index)}
              parent={resource.getSubject()}
              {...props}
              autoFocus={lastIsNew && index === array.length - 1}
            />
          ))}
        </div>
      )}
      <Row justify='space-between'>
        <StyledButton
          disabled={props.disabled}
          title='Add an item to this list'
          data-test={`input-${property.shortname}-add-resource`}
          subtle
          type='button'
          onClick={handleAdd}
        >
          <FaPlus />
        </StyledButton>
        {array.length > 1 && (
          <StyledButton
            disabled={props.disabled}
            title='Remove all items from this list'
            data-test={`input-${property.shortname}-clear`}
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
      {err?.index && <ErrMessage>{err?.message}</ErrMessage>}
    </Column>
  );
}

const StyledButton = styled(Button)`
  align-self: flex-start;
`;
