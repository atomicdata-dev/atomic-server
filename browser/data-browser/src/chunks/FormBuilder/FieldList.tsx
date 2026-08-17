import { forms, useArray, useResource, useStore } from '@tomic/react';
import type { JSX } from 'react';
import { styled } from 'styled-components';
import { Column } from '@components/Row';
import { AddFieldMenu } from './AddFieldMenu';
import { FieldRow } from './FieldRow';
import { ReorderableList } from './ReorderableList';
import { useFormFieldPropertySync } from './useFormFieldPropertySync';
import { FIELD_TYPE_META, type AddableFieldType } from './fieldTypes';

interface FieldListProps {
  dataClassSubject: string;
  pageSubject: string;
  selectedField: string | undefined;
  onSelectField: (subject: string | undefined) => void;
}

export function FieldList({
  dataClassSubject,
  pageSubject,
  selectedField,
  onSelectField,
}: FieldListProps): JSX.Element {
  const store = useStore();
  const page = useResource(pageSubject);
  const [fields, setFields] = useArray(page, forms.properties.formFields, {
    commit: true,
  });

  const { createField, deleteField } =
    useFormFieldPropertySync(dataClassSubject);

  const handleAdd = async (type: AddableFieldType) => {
    const field = await createField(page, {
      type,
      label: FIELD_TYPE_META[type].label,
    });
    onSelectField(field.subject);
  };

  const handleDelete = async (subject: string) => {
    const field = await store.getResource(subject);
    await deleteField(page, field);

    if (selectedField === subject) {
      onSelectField(undefined);
    }
  };

  return (
    <Column gap='0.75rem'>
      <ReorderableList
        subjects={fields}
        onReorder={setFields}
        renderItem={subject => (
          <FieldRow
            subject={subject}
            selected={subject === selectedField}
            onSelect={() => onSelectField(subject)}
            onDelete={() => handleDelete(subject)}
          />
        )}
      />
      <MenuWrapper>
        <AddFieldMenu onAdd={handleAdd} />
      </MenuWrapper>
    </Column>
  );
}

const MenuWrapper = styled.div`
  align-self: flex-start;
`;
