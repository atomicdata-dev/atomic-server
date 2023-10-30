import React, { useCallback, useState } from 'react';
import { ArrayError, useArray, validateDatatype } from '@tomic/react';
import { Button } from '../Button';
import { InputProps } from './ResourceField';
import { ErrMessage } from './InputStyles';
import { ResourceSelector } from './ResourceSelector';
import { FaPlus, FaTrash } from 'react-icons/fa';
import { Column, Row } from '../Row';
import { styled } from 'styled-components';
import { useIndexDependantCallback } from '../../hooks/useIndexDependantCallback';

export default function InputResourceArray({
  resource,
  property,
  commit,
  ...props
}: InputProps): JSX.Element {
  const [err, setErr] = useState<ArrayError | undefined>(undefined);
  const [array, setArray] = useArray(resource, property.subject, {
    validate: false,
    commit,
  });

  /** Add focus to the last added item */
  const [lastIsNew, setLastIsNew] = useState(false);

  function handleAddRow() {
    setArray([...array, undefined]);
    setLastIsNew(true);
  }

  function handleClear() {
    setArray([]);
    setLastIsNew(false);
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
          setLastIsNew(false);
          setErr(undefined);
        } catch (e) {
          setErr(e);
        }
      }
    },
    array,
    [property.datatype, setArray],
  );

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
        <div>
          {array.map((subject, index) => (
            <ResourceSelector
              key={`${property.subject}${index}`}
              value={subject}
              setSubject={handleSetSubjectList[index]}
              error={errMaybe(index)}
              isA={property.classType}
              handleRemove={handleRemoveRowList[index]}
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
          title={`Add an item to the ${property.shortname} list`}
          data-test={`input-${property.shortname}-add-resource`}
          subtle
          type='button'
          onClick={handleAddRow}
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
      {!!err && <ErrMessage>{err?.message}</ErrMessage>}
    </Column>
  );
}

const StyledButton = styled(Button)`
  align-self: flex-start;
`;
