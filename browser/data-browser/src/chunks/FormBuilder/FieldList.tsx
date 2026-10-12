import { useTableFormColumns } from './useTableFormColumns';
import { useFormQuestions } from './useFormQuestions';
import toast from 'react-hot-toast';
import { Resource, forms, useArray, useResource, useStore } from '@tomic/react';
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
  form: Resource;
  ownsSchema: boolean;
  tableSubject?: string;
  pageSubject: string;
  selectedField: string | undefined;
  onSelectField: (subject: string | undefined) => void;
}

export function FieldList({
  dataClassSubject,
  form,
  ownsSchema,
  tableSubject,
  pageSubject,
  selectedField,
  onSelectField,
}: FieldListProps): JSX.Element {
  const store = useStore();
  const page = useResource(pageSubject);
  const [fields, setFields] = useArray(page, forms.properties.formFields, {
    commit: true,
  });

  const { createField, deleteField } = useFormFieldPropertySync(
    dataClassSubject,
    ownsSchema,
  );

  const { columns } = useTableFormColumns(dataClassSubject);
  const questions = useFormQuestions(form);
  const unused = columns.filter(
    p => !questions.some(q => q.mapsTo === p.subject),
  );

  const handleAdd = async (
    type: AddableFieldType,
    existingProperty?: Resource,
  ) => {
    try {
      const field = await createField(page, {
        type,
        existingProperty,
        label: FIELD_TYPE_META[type].label,
      });
      onSelectField(field.subject);
    } catch (error) {
      toast.error((error as Error).message);
    }
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
        <AddFieldMenu
          onAdd={handleAdd}
          columns={ownsSchema ? undefined : unused}
          tableSubject={tableSubject}
        />
      </MenuWrapper>
    </Column>
  );
}

const MenuWrapper = styled.div`
  align-self: flex-start;
`;
