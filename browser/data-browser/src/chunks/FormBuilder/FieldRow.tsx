import {
  core,
  forms,
  useArray,
  useResource,
  useString,
  useTitle,
} from '@tomic/react';
import type { JSX } from 'react';
import { styled } from 'styled-components';
import { FaCodeBranch, FaTrash } from 'react-icons/fa6';
import { Column, Row } from '@components/Row';
import {
  IconButton,
  IconButtonVariant,
} from '@components/IconButton/IconButton';
import { FIELD_TYPE_META, type AddableFieldType } from './fieldTypes';

interface FieldRowProps {
  subject: string;
  selected: boolean;
  onSelect: () => void;
  onDelete: () => void;
}

export function FieldRow({
  subject,
  selected,
  onSelect,
  onDelete,
}: FieldRowProps): JSX.Element {
  const resource = useResource(subject);
  const [name] = useTitle(resource);
  const [fieldType] = useString(resource, forms.properties.formFieldType);
  const [description] = useString(resource, core.properties.description);
  const [conditions] = useArray(resource, forms.properties.formConditions);
  const isHeading = resource.hasClasses(forms.classes.formHeading);
  const isParagraph = resource.hasClasses(forms.classes.formParagraph);

  const type: AddableFieldType = isHeading
    ? 'heading'
    : isParagraph
      ? 'paragraph'
      : ((fieldType as AddableFieldType | undefined) ?? 'short-text');

  const meta = FIELD_TYPE_META[type];
  const Icon = meta.icon;

  const label = isParagraph ? description : name;

  return (
    <RowWrapper $selected={selected}>
      <SelectButton
        type='button'
        // While the resource is loading, `type` is just the fallback — don't
        // claim a concrete testid yet, or every hydrating row briefly reads
        // as `field-row-short-text` (breaks e2e strict-mode selectors).
        data-testid={
          resource.loading ? 'field-row-loading' : `field-row-${type}`
        }
        onClick={onSelect}
      >
        <Column fullWidth>
          <FieldTypeRow gap='0.5rem' center>
            <Icon />
            <Label light>{meta.label}</Label>
          </FieldTypeRow>
          {label ? <Label>{label}</Label> : null}
          {conditions.length > 0 && (
            <FieldTypeRow gap='0.35rem' center>
              <FaCodeBranch />
              <Label light>Conditional</Label>
            </FieldTypeRow>
          )}
        </Column>
      </SelectButton>
      <IconButton
        variant={IconButtonVariant.Simple}
        size='0.8rem'
        color='textLight'
        title='Delete field'
        type='button'
        onClick={onDelete}
      >
        <FaTrash />
      </IconButton>
    </RowWrapper>
  );
}

const FieldTypeRow = styled(Row)`
  color: ${p => p.theme.colors.textLight};
`;
const RowWrapper = styled.div<{ $selected: boolean }>`
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 0.5rem 0.7rem;
  border: 1px solid
    ${p => (p.$selected ? p.theme.colors.main : p.theme.colors.bg2)};
  border-radius: ${p => p.theme.radius};
  background-color: ${p =>
    p.$selected ? p.theme.colors.mainSelectedBg : p.theme.colors.bg};

  &:hover {
    border-color: ${p => p.theme.colors.main};
  }
`;

const SelectButton = styled.button`
  flex: 1;
  display: flex;
  align-items: center;
  border: none;
  background: none;
  padding: 0;
  cursor: pointer;
  text-align: left;
  min-width: 0;
`;

const Label = styled.span<{ light?: boolean }>`
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
  white-space: nowrap;
  color: ${p => (p.light ? p.theme.colors.textLight : p.theme.colors.text)};
`;
