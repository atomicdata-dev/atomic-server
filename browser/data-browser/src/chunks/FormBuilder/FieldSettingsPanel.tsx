import {
  core,
  forms,
  Resource,
  useProperty,
  useResource,
  useString,
} from '@tomic/react';
import { useEffect, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import Field from '@components/forms/Field';
import InputSwitcher from '@components/forms/InputSwitcher';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Column } from '@components/Row';
import { useDebounce } from '@helpers/useDebounce';
import { TextOptions } from './FieldOptions/TextOptions';
import { NumberOptions } from './FieldOptions/NumberOptions';
import { ChoiceOptions } from './FieldOptions/ChoiceOptions';
import type { FormFieldType } from './fieldTypes';
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
  const { renameField } = useFormFieldPropertySync(dataClassSubject);

  const isHeading = field.hasClasses(forms.classes.formHeading);
  const isParagraph = field.hasClasses(forms.classes.formParagraph);

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
      return <TextOptions field={field} />;
    case 'number':
      return <NumberOptions field={field} />;
    case 'radio':
    case 'multi-select':
      return <ChoiceOptions field={field} />;
    default:
      return null;
  }
}

const Panel = styled(Column)`
  gap: 0.75rem;
`;
