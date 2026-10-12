import { useEffect, useRef, useState, type JSX } from 'react';
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
import { ReorderableList } from '../ReorderableList';

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
 * One row of the draft. The `id` exists only for this editing session: the
 * committed value is a bare string, but dragging and keying a list needs an
 * identity that survives editing the text and does not collide when two rows
 * happen to read the same — see {@link ReorderableList}, which addresses items
 * by id.
 */
interface DraftItem {
  id: string;
  value: string;
}

let idCounter = 0;

const toDraft = (values: string[]): DraftItem[] =>
  values.map(value => ({ id: `item-${idCounter++}`, value }));

/**
 * Editable list of short strings — matrix rows and matrix columns (choice
 * options moved to {@link TagListEditor}, where each option is a Tag). Rows can
 * be dragged into a different order, the same way fields and pages are.
 *
 * Edits are kept in a local draft and committed on a debounce:
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
  const [list, setList] = useState<DraftItem[]>(() => toDraft(value));
  // Debounce the draft itself rather than the strings it carries: `useDebounce`
  // restarts its timer whenever the value's identity changes, and a freshly
  // mapped array would be a new one on every render.
  const debouncedList = useDebounce(list, 150);

  useEffect(() => {
    setList(toDraft(value));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetKey]);

  useEffect(() => {
    const next = debouncedList.map(item => item.value);

    if (JSON.stringify(next) !== JSON.stringify(value)) {
      onChange(next);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedList]);

  // The row whose input should take focus once it renders: the one just added,
  // so a run of rows can be typed without reaching for the mouse.
  const [focusId, setFocusId] = useState<string>();
  const inputs = useRef(new Map<string, HTMLInputElement>());

  useEffect(() => {
    if (!focusId) return;

    const input = inputs.current.get(focusId);

    input?.focus();
    input?.select();
  }, [focusId]);

  /** Adds a row at `index` (default: the end) and hands it the focus. */
  const addItem = (index = list.length) => {
    const [item] = toDraft([newItemLabel(list.length + 1)]);
    const next = [...list];

    next.splice(index, 0, item);
    setList(next);
    setFocusId(item.id);
  };

  const reorder = (ids: string[]) => {
    setList(
      ids
        .map(id => list.find(item => item.id === id))
        .filter((item): item is DraftItem => item !== undefined),
    );
  };

  return (
    <Field label={label}>
      <Column gap='0.4rem'>
        <ReorderableList
          subjects={list.map(item => item.id)}
          onReorder={reorder}
          gap='0.4rem'
          renderItem={(id, index) => (
            <Row gap='0.4rem'>
              <InputWrapper>
                <InputStyled
                  ref={element => {
                    if (element) {
                      inputs.current.set(id, element);
                    } else {
                      inputs.current.delete(id);
                    }
                  }}
                  data-testid={itemTestId}
                  value={list[index]?.value ?? ''}
                  onChange={e => {
                    const next = [...list];
                    next[index] = { ...next[index], value: e.target.value };
                    setList(next);
                  }}
                  onKeyDown={e => {
                    if (e.key !== 'Enter') return;

                    // Enter inside a form would submit it.
                    e.preventDefault();
                    addItem(index + 1);
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
          )}
        />
        <AddButton type='button' subtle onClick={() => addItem()}>
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
