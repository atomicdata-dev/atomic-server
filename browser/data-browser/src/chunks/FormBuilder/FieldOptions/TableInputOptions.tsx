import { Resource, type JSONValue } from '@tomic/react';
import { useEffect, useState, type JSX } from 'react';
import { FaPlus, FaTrash } from 'react-icons/fa6';
import Field from '@components/forms/Field';
import { BasicSelect } from '@components/forms/BasicSelect';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Column, Row } from '@components/Row';
import {
  IconButton,
  IconButtonVariant,
} from '@components/IconButton/IconButton';
import { useDebounce } from '@helpers/useDebounce';
import { AddButton } from './StringListEditor';
import { useFieldOptions } from './useFieldOptions';

interface TableColumn {
  label: string;
  type: 'text' | 'number';
}

interface TableInputOptionsProps {
  field: Resource;
}

/** Columns of a `table-input` question: a label and a cell type each, plus
 * optional bounds on how many rows a visitor may fill in. */
export function TableInputOptions({
  field,
}: TableInputOptionsProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);

  const stored = normalizeColumns(options.columns);
  const [columns, setColumns] = useState<TableColumn[]>(stored);
  const debouncedColumns = useDebounce(columns, 150);

  useEffect(() => {
    setColumns(stored);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [field.subject]);

  useEffect(() => {
    if (JSON.stringify(debouncedColumns) !== JSON.stringify(stored)) {
      // A plain object array is valid JSON; TS just can't see it without an
      // index signature on TableColumn.
      setOptions({
        ...options,
        columns: debouncedColumns as unknown as JSONValue,
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedColumns]);

  const setBound = (key: 'minRows' | 'maxRows', value: string) => {
    const next = { ...options };

    if (value.trim() === '') {
      delete next[key];
    } else {
      next[key] = Number(value);
    }

    setOptions(next);
  };

  return (
    <>
      <Field label='Columns'>
        <Column gap='0.4rem'>
          {columns.map((column, index) => (
            <Row key={`column-${index}`} gap='0.4rem'>
              <InputWrapper>
                <InputStyled
                  data-testid='table-column-input'
                  value={column.label}
                  onChange={e => {
                    const next = [...columns];
                    next[index] = { ...column, label: e.target.value };
                    setColumns(next);
                  }}
                />
              </InputWrapper>
              <BasicSelect
                value={column.type}
                onChange={e => {
                  const next = [...columns];
                  next[index] = {
                    ...column,
                    type: e.target.value as TableColumn['type'],
                  };
                  setColumns(next);
                }}
              >
                <option value='text'>Text</option>
                <option value='number'>Number</option>
              </BasicSelect>
              <IconButton
                variant={IconButtonVariant.Simple}
                size='0.8rem'
                color='textLight'
                title='Remove column'
                type='button'
                onClick={() =>
                  setColumns(columns.filter((_, i) => i !== index))
                }
              >
                <FaTrash />
              </IconButton>
            </Row>
          ))}
          <AddButton
            type='button'
            subtle
            onClick={() =>
              setColumns([
                ...columns,
                { label: `Column ${columns.length + 1}`, type: 'text' },
              ])
            }
          >
            <Row gap='.5rem' center>
              <FaPlus /> Add column
            </Row>
          </AddButton>
        </Column>
      </Field>
      <Row gap='0.5rem' wrapItems>
        <Field label='Min rows'>
          <InputWrapper>
            <InputStyled
              type='number'
              min={0}
              value={(options.minRows as number | undefined) ?? ''}
              onChange={e => setBound('minRows', e.target.value)}
            />
          </InputWrapper>
        </Field>
        <Field label='Max rows'>
          <InputWrapper>
            <InputStyled
              type='number'
              min={1}
              value={(options.maxRows as number | undefined) ?? ''}
              onChange={e => setBound('maxRows', e.target.value)}
            />
          </InputWrapper>
        </Field>
      </Row>
    </>
  );
}

/** Tolerates the plain-string column shape a `choice-matrix` stores under the
 * same key, so a hand-edited options bag can't crash the editor. */
function normalizeColumns(raw: JSONValue | undefined): TableColumn[] {
  if (!Array.isArray(raw)) return [];

  return raw.map(column =>
    typeof column === 'string'
      ? { label: column, type: 'text' }
      : {
          label: String((column as { label?: unknown }).label ?? ''),
          type:
            (column as { type?: unknown }).type === 'number'
              ? 'number'
              : 'text',
        },
  );
}
