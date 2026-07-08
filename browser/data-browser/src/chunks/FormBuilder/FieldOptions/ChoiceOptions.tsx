import { forms, Resource, useValue, type JSONValue } from '@tomic/react';
import { useEffect, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaPlus, FaTrash } from 'react-icons/fa6';
import Field from '@components/forms/Field';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { IconButton, IconButtonVariant } from '@components/IconButton/IconButton';
import { useDebounce } from '@helpers/useDebounce';

interface ChoiceOptionsProps {
  field: Resource;
}

/** Editable list of choice labels for `radio` / `multi-select` fields. */
export function ChoiceOptions({ field }: ChoiceOptionsProps): JSX.Element {
  const [options, setOptions] = useValue(
    field,
    forms.properties.formFieldOptions,
    { commit: true },
  );

  const opts = (options as Record<string, JSONValue> | undefined) ?? {};
  const initialList = (opts.options as string[] | undefined) ?? [];

  // Local draft, committed on a debounce — `formFieldOptions` validates
  // against a Property fetch that can be slow, so firing a `setOptions` per
  // keystroke can race and let an earlier edit's commit land after (and
  // clobber) a later one. Mirrors `FieldLabelInput`'s pattern.
  const [list, setList] = useState<string[]>(initialList);
  const debouncedList = useDebounce(list, 150);

  useEffect(() => {
    setList(initialList);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [field.subject]);

  useEffect(() => {
    if (JSON.stringify(debouncedList) !== JSON.stringify(initialList)) {
      setOptions({ ...opts, options: debouncedList });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedList]);

  return (
    <Field label='Options'>
      <Column gap='0.4rem'>
        {list.map((option, index) => (
          <Row key={`option-${index}`} gap='0.4rem'>
            <InputWrapper>
              <InputStyled
                data-testid='choice-option-input'
                value={option}
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
              title='Remove option'
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
          onClick={() => setList([...list, `Option ${list.length + 1}`])}
        >
          <Row gap='.5rem' center>
            <FaPlus /> Add option
          </Row>
        </AddButton>
      </Column>
    </Field>
  );
}

const AddButton = styled(Button)`
  align-self: flex-start;
  box-shadow: none;
  border: 1px dashed ${p => p.theme.colors.bg2};
  background: none;
`;
