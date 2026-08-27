import {
  core,
  forms,
  Resource,
  unknownSubject,
  useArray,
  useProperty,
  useResource,
  useString,
} from '@tomic/react';
import { useEffect, useRef, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaPencil } from 'react-icons/fa6';
import Field from '@components/forms/Field';
import { IconButton } from '@components/IconButton/IconButton';
import InputSwitcher from '@components/forms/InputSwitcher';
import {
  ErrMessage,
  InputStyled,
  InputWrapper,
} from '@components/forms/InputStyles';
import { Column } from '@components/Row';
import { useDebounce } from '@helpers/useDebounce';
import { slugWhileTyping, stringToSlug } from '@helpers/stringToSlug';
import { TextOptions } from './FieldOptions/TextOptions';
import { CountryDefaultField } from './FieldOptions/CountryDefaultField';
import { NumberOptions } from './FieldOptions/NumberOptions';
import { ChoiceOptions } from './FieldOptions/ChoiceOptions';
import { CurrencyOptions } from './FieldOptions/CurrencyOptions';
import { LikertOptions, RatingOptions } from './FieldOptions/ScaleOptions';
import { PictureChoiceOptions } from './FieldOptions/PictureChoiceOptions';
import { MatrixOptions } from './FieldOptions/MatrixOptions';
import { TableInputOptions } from './FieldOptions/TableInputOptions';
import type { FormFieldType } from './fieldTypes';
import { InfoBoxOptions } from './FieldOptions/InfoBoxOptions';
import { useFormFieldPropertySync } from './useFormFieldPropertySync';
import { ConditionsEditor } from './ConditionsEditor';

interface FieldSettingsPanelProps {
  fieldSubject: string;
  dataClassSubject: string;
  form: Resource;
}

export function FieldSettingsPanel({
  fieldSubject,
  dataClassSubject,
  form,
}: FieldSettingsPanelProps): JSX.Element {
  const field = useResource(fieldSubject);
  const descriptionProp = useProperty(core.properties.description);
  const requiredProp = useProperty(forms.properties.required);
  const [fieldType] = useString(field, forms.properties.formFieldType);
  const { renameField, setFieldShortname } =
    useFormFieldPropertySync(dataClassSubject);

  // Subscribed read of `isA` — see the note in `FieldRow`: `hasClasses()`
  // never re-renders when the class lands late, which would leave this panel
  // showing the question editor for a heading/paragraph after a reload.
  const [classes] = useArray(field, core.properties.isA);
  const isHeading = classes.includes(forms.classes.formHeading);
  const isParagraph = classes.includes(forms.classes.formParagraph);
  const isInfoBox = classes.includes(forms.classes.formInfoBox);

  if (isHeading) {
    return (
      <Panel>
        <Field label='Heading text' required>
          <FieldLabelInput field={field} renameField={renameField} />
        </Field>
        <ConditionsEditor
          resource={field}
          form={form}
          beforeField={fieldSubject}
        />
      </Panel>
    );
  }

  if (isInfoBox) {
    return (
      <Panel>
        <InfoBoxOptions field={field} />
        <ConditionsEditor
          resource={field}
          form={form}
          beforeField={fieldSubject}
        />
      </Panel>
    );
  }

  if (isParagraph) {
    return (
      <Panel>
        <Field label='Paragraph text' required>
          <InputSwitcher
            commit
            resource={field}
            property={descriptionProp}
            required
          />
        </Field>
        <ConditionsEditor
          resource={field}
          form={form}
          beforeField={fieldSubject}
        />
      </Panel>
    );
  }

  return (
    <Panel>
      <Field label='Label' required>
        <FieldLabelInput field={field} renameField={renameField} />
      </Field>
      {/* Keyed on the field: selecting another question remounts the row, so a
          half-finished edit never carries over to the next one. */}
      <FieldShortnameField
        key={fieldSubject}
        field={field}
        setFieldShortname={setFieldShortname}
      />
      <Field label='Helper text'>
        <InputSwitcher commit resource={field} property={descriptionProp} />
      </Field>
      <Field label='Required'>
        <InputSwitcher commit resource={field} property={requiredProp} />
      </Field>
      <TypeOptions
        field={field}
        type={fieldType as FormFieldType | undefined}
      />
      <ConditionsEditor
        resource={field}
        form={form}
        beforeField={fieldSubject}
      />
    </Panel>
  );
}

interface FieldLabelInputProps {
  field: Resource;
  renameField: (field: Resource, newLabel: string) => Promise<void>;
}

/**
 * A field's Label doubles as the mapped Property's name, so renaming has to
 * go through `renameField` (not a plain InputSwitcher commit) to keep the
 * Table column label in sync.
 */
function FieldLabelInput({
  field,
  renameField,
}: FieldLabelInputProps): JSX.Element {
  const [name] = useString(field, core.properties.name);
  const [draft, setDraft] = useState(name ?? '');
  const debounced = useDebounce(draft, 100);

  useEffect(() => {
    setDraft(name ?? '');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [field.subject]);

  useEffect(() => {
    if (debounced.trim() && debounced !== (name ?? '')) {
      renameField(field, debounced);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);

  return (
    <InputWrapper>
      <InputStyled
        data-testid='field-label-input'
        value={draft}
        onChange={e => setDraft(e.target.value)}
      />
    </InputWrapper>
  );
}

interface FieldShortnameFieldProps {
  field: Resource;
  setFieldShortname: (
    field: Resource,
    shortname: string,
  ) => Promise<string | undefined>;
}

/**
 * The mapped Property's `shortname` — the identifier the question's answers
 * are stored under, and the header of its column in the results table (a
 * form-generated Property has no `name`, so `useTitle` shows this).
 *
 * Deliberately quiet: it sits under the Label as read-only text, because for
 * most questions it is derived and nobody needs to touch it. The pencil turns
 * it into an input for the people who do. Typing pins it — later Label edits
 * leave it be; clearing it un-pins it, handing it back to the Label.
 */
function FieldShortnameField({
  field,
  setFieldShortname,
}: FieldShortnameFieldProps): JSX.Element | null {
  const [mapsTo] = useString(field, forms.properties.formMapsTo);
  const property = useResource(mapsTo ?? unknownSubject);
  const [shortname] = useString(property, core.properties.shortname);
  const [label] = useString(field, core.properties.name);

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | undefined>(undefined);
  const inputRef = useRef<HTMLInputElement>(null);

  const derived = stringToSlug(label ?? '');

  useEffect(() => {
    if (editing) {
      inputRef.current?.focus();
      inputRef.current?.select();
    }
  }, [editing]);

  const startEditing = () => {
    setDraft(shortname ?? derived);
    setError(undefined);
    setEditing(true);
  };

  const commit = async () => {
    // Empty means "follow the Label again": re-derive rather than write an
    // empty shortname, which the Property class does not allow.
    const next = stringToSlug(draft) || derived;

    if (next === '' || next === shortname) {
      setEditing(false);
      setError(undefined);

      return;
    }

    const failure = await setFieldShortname(field, next);
    setError(failure);

    // A rejected slug stays on screen, in edit mode, with its error.
    if (!failure) {
      setEditing(false);
    }
  };

  if (!mapsTo) {
    return null;
  }

  // Editing swaps the value for an input in place — same row, same quiet
  // label — rather than expanding into a full labelled Field, so clicking the
  // pencil doesn't shove the rest of the panel down.
  return (
    <div title='How this question is identified in the data, and the column header in the results table. Defaults to the label — clear it to follow the label again.'>
      <ShortnameRow>
        <ShortnameLabel>Data name</ShortnameLabel>
        {editing ? (
          <ShortnameInputWrapper $invalid={!!error}>
            <InputStyled
              ref={inputRef}
              data-testid='field-shortname-input'
              value={draft}
              placeholder={derived}
              onChange={e => setDraft(slugWhileTyping(e.target.value))}
              onBlur={commit}
              onKeyDown={e => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  commit();
                } else if (e.key === 'Escape') {
                  e.preventDefault();
                  setError(undefined);
                  setEditing(false);
                }
              }}
            />
          </ShortnameInputWrapper>
        ) : (
          <>
            <ShortnameValue data-testid='field-shortname-value'>
              {shortname ?? derived}
            </ShortnameValue>
            <IconButton
              type='button'
              title='Edit data name'
              size='0.8em'
              data-testid='field-shortname-edit'
              onClick={startEditing}
            >
              <FaPencil />
            </IconButton>
          </>
        )}
      </ShortnameRow>
      {error && <ErrMessage>{error}</ErrMessage>}
    </div>
  );
}

function TypeOptions({
  field,
  type,
}: {
  field: Resource;
  type: FormFieldType | undefined;
}): JSX.Element | null {
  switch (type) {
    case 'short-text':
    case 'long-text':
    case 'email':
    case 'url':
      return <TextOptions field={field} />;
    case 'phone':
      return (
        <>
          <TextOptions field={field} />
          <CountryDefaultField
            field={field}
            helper='The country the number selector starts on. Visitors can still pick another one.'
          />
        </>
      );
    case 'country':
      return (
        <>
          <TextOptions field={field} />
          <CountryDefaultField
            field={field}
            helper='Pre-selected when the form opens. Leave on "No default" to make the visitor choose.'
          />
        </>
      );
    case 'number':
      return <NumberOptions field={field} />;
    case 'currency':
      return <CurrencyOptions field={field} />;
    case 'radio':
    case 'dropdown':
      return <ChoiceOptions field={field} />;
    case 'multi-select':
    case 'dropdown-multi':
      return <ChoiceOptions field={field} multiple />;
    case 'picture-choice':
      return <PictureChoiceOptions field={field} />;
    case 'likert':
      return <LikertOptions field={field} />;
    case 'rating':
      return <RatingOptions field={field} />;
    case 'choice-matrix':
      return <MatrixOptions field={field} />;
    case 'table-input':
      return <TableInputOptions field={field} />;
    // checkbox, date, datetime and address have nothing to configure.
    default:
      return null;
  }
}

const Panel = styled(Column)`
  gap: 0.75rem;
`;

/** The Data name row: quiet by design — it is metadata about the question,
 * not a question setting, so it reads as a caption under the Label rather
 * than as another labelled field. */
const ShortnameRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.4rem;
  margin-top: -0.4rem;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;

const ShortnameLabel = styled.span`
  flex-shrink: 0;
`;

/** Sized down to the row's caption scale, so the input replaces the value
 * without the row changing height. */
const ShortnameInputWrapper = styled(InputWrapper)`
  flex: 1;
  min-width: 0;
  height: 1.6rem;

  & input {
    font-family: monospace;
    font-size: 0.85rem;
  }
`;

const ShortnameValue = styled.span`
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-family: monospace;
  color: ${p => p.theme.colors.text};
`;
