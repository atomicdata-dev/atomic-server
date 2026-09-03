import {
  core,
  dataBrowser,
  Resource,
  useArray,
  useResource,
  useStore,
  useString,
  type Store,
} from '@tomic/react';
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type JSX,
  type ReactNode,
} from 'react';
import { styled } from 'styled-components';
import { FaPlus, FaTrash } from 'react-icons/fa6';
import Field from '@components/forms/Field';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Column, Row } from '@components/Row';
import {
  IconButton,
  IconButtonVariant,
} from '@components/IconButton/IconButton';
import { stringToSlug } from '@helpers/stringToSlug';
import { randomItem } from '@helpers/randomItem';
import { useDraftString } from '@helpers/useDraftString';
import { tagColours } from '@components/Tag/tagColours';
import { ReorderableList } from '../ReorderableList';
import { AddButton } from './StringListEditor';

interface TagListEditorProps {
  /** The SelectProperty whose `allowsOnly` holds the option Tags. */
  property: Resource;
  label: string;
  addLabel: string;
  removeLabel: string;
  itemTestId?: string;
  /** Rendered beside the `label` — the button that links these options to a
   * table (see `LinkOptionsDialog`). */
  labelAction?: ReactNode;
  /** Rendered left of the label input — `picture-choice`'s thumbnail. */
  leading?: (tagSubject: string) => ReactNode;
  /** Rendered under the label input — `picture-choice`'s image picker. */
  belowInput?: (tagSubject: string) => ReactNode;
}

/**
 * Editable list of choice options: one text input per option, a remove button
 * beside each, an add button below — the same shape as {@link StringListEditor}
 * (matrix rows, table columns), which is what these options used to be.
 *
 * The difference is underneath. Each option is a **Tag** on the mapped
 * SelectProperty's `allowsOnly`, not a string in the field's options bag, so
 * editing a label rewrites it everywhere it has already been submitted instead
 * of stranding old answers with a copy of the old text.
 *
 * A tag's color is assigned on creation and edited from the table column's own
 * settings (`SelectPropertyForm`), deliberately not here: this panel is about
 * the question's wording.
 */
export function TagListEditor({
  property,
  label,
  addLabel,
  removeLabel,
  itemTestId,
  labelAction,
  leading,
  belowInput,
}: TagListEditorProps): JSX.Element {
  const store = useStore();

  const [allowsOnly, setAllowsOnly] = useArray(
    property,
    core.properties.allowsOnly,
    { commit: true },
  );

  // The option whose input should take focus once it renders: the one just
  // added, so a run of options can be typed without reaching for the mouse.
  const [focusSubject, setFocusSubject] = useState<string>();

  const addOption = useCallback(
    async (index = allowsOnly.length) => {
      const subject = await createOptionTag(
        store,
        property.subject,
        `Option ${allowsOnly.length + 1}`,
      );
      const next = [...allowsOnly];
      next.splice(index, 0, subject);
      // Before the list update that mounts the row, so it is already marked
      // for focus by the time it first renders.
      setFocusSubject(subject);
      await setAllowsOnly(next);
    },
    [store, property.subject, allowsOnly, setAllowsOnly],
  );

  const removeOption = useCallback(
    async (subject: string) => {
      // Answers already referencing this tag keep the reference; the results
      // view folds them into "Other" rather than silently relabelling them.
      await setAllowsOnly(allowsOnly.filter(s => s !== subject));
      await store.getResourceLoading(subject).destroy();
    },
    [store, allowsOnly, setAllowsOnly],
  );

  return (
    <Field label={label} labelAction={labelAction}>
      <Column gap='0.4rem'>
        <ReorderableList
          subjects={allowsOnly}
          onReorder={setAllowsOnly}
          gap='0.4rem'
          align='start'
          renderItem={(subject, index) => (
            <OptionRow gap='0.4rem'>
              {leading?.(subject)}
              <GrowColumn gap='0.3rem'>
                <OptionLabelInput
                  subject={subject}
                  testId={itemTestId}
                  takeFocus={subject === focusSubject}
                  onEnter={() => addOption(index + 1)}
                />
                {belowInput?.(subject)}
              </GrowColumn>
              <IconButton
                variant={IconButtonVariant.Simple}
                size='0.8rem'
                color='textLight'
                title={removeLabel}
                type='button'
                onClick={() => removeOption(subject)}
              >
                <FaTrash />
              </IconButton>
            </OptionRow>
          )}
        />
        <AddButton type='button' subtle onClick={() => addOption()}>
          <Row gap='.5rem' center>
            <FaPlus /> {addLabel}
          </Row>
        </AddButton>
      </Column>
    </Field>
  );
}

/**
 * Creates one option Tag under the SelectProperty — the same shape
 * `createSelectPropertyOnClass` and `CreateTagRow` produce, so an option is
 * indistinguishable from a tag made by hand on the table's column.
 */
export async function createOptionTag(
  store: Store,
  parent: string,
  label: string,
): Promise<string> {
  // A DID parent derives subjects from the genesis signature, so no path is
  // pre-computed for it (same branch as `CreateTagRow`).
  const subject = parent.startsWith('did:')
    ? undefined
    : await store.buildUniqueSubjectFromParts(['tag', label], parent);

  const tag = await store.newResource({
    subject,
    parent,
    isA: dataBrowser.classes.tag,
    propVals: {
      // `shortname` is the slug the Tag class requires; `name` keeps the label
      // verbatim. `useTitle` prefers `name`, so tags render as written.
      [core.properties.shortname]: stringToSlug(label),
      [core.properties.name]: label,
      [dataBrowser.properties.color]: randomItem(tagColours),
    },
  });
  await tag.save();

  return tag.subject;
}

/** One option's label, written to its Tag's `name` (and `shortname` as a
 * slug). Debounced, and flushed on unmount — see `useDraftString`. */
function OptionLabelInput({
  subject,
  testId,
  takeFocus,
  onEnter,
}: {
  subject: string;
  testId?: string;
  /** Focus this input and select its placeholder label once it has one. */
  takeFocus?: boolean;
  /** Enter adds the next option below this one. */
  onEnter: () => void;
}): JSX.Element {
  const tag = useResource(subject);
  const [name, setName] = useString(tag, core.properties.name, {
    commit: true,
  });
  const [, setShortname] = useString(tag, core.properties.shortname, {
    commit: true,
  });

  const commit = useCallback(
    (value: string) => {
      setName(value);
      setShortname(stringToSlug(value));
    },
    [setName, setShortname],
  );

  const draft = useDraftString(name, commit, subject);

  const inputRef = useRef<HTMLInputElement>(null);
  const selected = useRef(false);

  useEffect(() => {
    if (!takeFocus || selected.current || !inputRef.current) return;

    inputRef.current.focus();

    // The Tag's `name` can land a render after the row mounts (see
    // `useDraftString`), and selecting an empty box selects nothing — so wait
    // for the label before selecting it, then stop.
    if (draft.value) {
      inputRef.current.select();
      selected.current = true;
    }
  }, [takeFocus, draft.value]);

  return (
    <InputWrapper>
      <InputStyled
        ref={inputRef}
        data-testid={testId}
        value={draft.value}
        onChange={e => draft.onChange(e.target.value)}
        onKeyDown={e => {
          if (e.key !== 'Enter') return;

          // Enter inside a form would submit it.
          e.preventDefault();
          onEnter();
        }}
      />
    </InputWrapper>
  );
}

const OptionRow = styled(Row)`
  align-items: flex-start;
`;

const GrowColumn = styled(Column)`
  flex: 1;
  min-width: 0;
`;
