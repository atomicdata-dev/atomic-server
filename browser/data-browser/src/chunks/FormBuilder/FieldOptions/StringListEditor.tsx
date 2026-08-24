import { useEffect, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaPlus, FaTrash } from 'react-icons/fa6';
import Field from '@components/forms/Field';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import {
  IconButton,
  IconButtonVariant,
} from '@components/IconButton/IconButton';
import { useDebounce } from '@helpers/useDebounce';

interface StringListEditorProps {
  label: string;
  value: string[];
  onChange: (next: string[]) => void;
  /** Changing this resets the local draft — pass the field's subject so
   * selecting another question doesn't carry the previous one's draft over. */
  resetKey: string;
  addLabel: string;
  removeLabel: string;
  newItemLabel: (index: number) => string;
  itemTestId?: string;
}

/**
 * Editable list of short strings — choice options, matrix rows, matrix
 * columns. Edits are kept in a local draft and committed on a debounce:
 * `form-field-options` validates against a Property fetch that can be slow, so
 * one `onChange` per keystroke can race and let an earlier edit's commit land
 * after (and clobber) a later one.
 */
export function StringListEditor({
  label,
  value,
  onChange,
  resetKey,
  addLabel,
  removeLabel,
  newItemLabel,
  itemTestId,
}: StringListEditorProps): JSX.Element {
  const [list, setList] = useState<string[]>(value);
  const debouncedList = useDebounce(list, 150);

  useEffect(() => {
    setList(value);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetKey]);

  useEffect(() => {
    if (JSON.stringify(debouncedList) !== JSON.stringify(value)) {
      onChange(debouncedList);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedList]);

  return (
    <Field label={label}>
      <Column gap='0.4rem'>
        {list.map((item, index) => (
          <Row key={`item-${index}`} gap='0.4rem'>
            <InputWrapper>
              <InputStyled
                data-testid={itemTestId}
                value={item}
                onChange={e => {
                  const next = [...list];
                  next[index] = e.target.value;
                  setList(next);
                }}
              />
            </InputWrapper>
            <IconButton
              variant={IconButtonVariant.Simple}
              size='0.8rem'
              color='textLight'
              title={removeLabel}
              type='button'
              onClick={() => setList(list.filter((_, i) => i !== index))}
            >
              <FaTrash />
            </IconButton>
          </Row>
        ))}
        <AddButton
          type='button'
          subtle
          onClick={() => setList([...list, newItemLabel(list.length + 1)])}
        >
          <Row gap='.5rem' center>
            <FaPlus /> {addLabel}
          </Row>
        </AddButton>
      </Column>
    </Field>
  );
}

export const AddButton = styled(Button)`
  align-self: flex-start;
  box-shadow: none;
  border: 1px dashed ${p => p.theme.colors.bg2};
  background: none;
`;
