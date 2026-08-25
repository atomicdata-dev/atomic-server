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
import { transition } from '@helpers/transition';
import {
  FIELD_TYPE_META,
  isLayoutType,
  type AddableFieldType,
} from './fieldTypes';
import { FormMarkdown } from '@tomic/form-renderer';
import { FieldRowOptions } from './FieldRowOptions';

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

  const isLayout = isLayoutType(type);

  return (
    <RowWrapper $selected={selected} $plain={isLayout} data-selected={selected}>
      <SelectButton
        type="button"
        // While the resource is loading, `type` is just the fallback — don't
        // claim a concrete testid yet, or every hydrating row briefly reads
        // as `field-row-short-text` (breaks e2e strict-mode selectors).
        data-testid={
          resource.loading ? 'field-row-loading' : `field-row-${type}`
        }
        onClick={onSelect}
      >
        <Column fullWidth gap="0.35rem">
          {/* A layout block is nothing but the text it puts on the form, so it
              renders as that text — no card, no type, no icon. A question
              leads with what it asks, its type and options beneath. */}
          {isHeading ? (
            <HeadingText>
              {name || <Placeholder>Empty heading</Placeholder>}
            </HeadingText>
          ) : isParagraph ? (
            description ? (
              <ParagraphText>
                {/* The same renderer the published form uses, so the card
                    shows what the respondent will read. */}
                <FormMarkdown text={description} />
              </ParagraphText>
            ) : (
              <Placeholder>Empty paragraph</Placeholder>
            )
          ) : (
            <>
              {name ? (
                <FieldLabel gap="0.35rem" center>
                  <Icon />
                  <Label bold>{name}</Label>
                </FieldLabel>
              ) : null}
              {/* <FieldTypeRow gap="0.5rem" center>
                <Label light>{meta.label}</Label>
              </FieldTypeRow> */}
              <FieldRowOptions field={resource} type={type} />
            </>
          )}
          {conditions.length > 0 && (
            <FieldTypeRow gap="0.35rem" center>
              <FaCodeBranch />
              <Label light>Conditional</Label>
            </FieldTypeRow>
          )}
        </Column>
      </SelectButton>
      <DeleteButton
        variant={IconButtonVariant.Simple}
        size="0.8rem"
        color="textLight"
        title="Delete field"
        type="button"
        onClick={onDelete}
      >
        <FaTrash />
      </DeleteButton>
    </RowWrapper>
  );
}

const FieldTypeRow = styled(Row)`
  color: ${p => p.theme.colors.textLight};
`;
/** `$plain` is a layout block: no card at rest, because the row _is_ the text
 * the form will show. It still highlights on hover and while selected —
 * otherwise nothing says it can be clicked. */
const RowWrapper = styled.div<{ $selected: boolean; $plain?: boolean }>`
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 0.5rem 0.7rem;
  border: 1px solid
    ${p =>
      p.$selected
        ? p.theme.colors.main
        : p.$plain
          ? 'transparent'
          : p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background-color: ${p =>
    p.$selected
      ? p.theme.colors.mainSelectedBg
      : p.$plain
        ? 'transparent'
        : p.theme.colors.bg};

  &:hover {
    border-color: ${p => p.theme.colors.main};
  }
`;

/** Hidden until the row is hovered, focused or selected: a column of trash cans
 * beside every question is a lot of visual weight for an action nobody takes
 * often. It stays in the DOM — and in the tab order — so keyboard users reach
 * it, which is why focus brings it back. Touch has no hover to reveal it, so
 * there it is simply always shown. */
const DeleteButton = styled(IconButton)`
  opacity: 0;
  ${transition('opacity')}

  ${RowWrapper}:hover &,
  ${RowWrapper}:focus-within &,
  ${RowWrapper}[data-selected='true'] & {
    opacity: 1;
  }

  &:focus-visible {
    opacity: 1;
  }

  @media (hover: none) {
    opacity: 1;
  }
`;

const SelectButton = styled.button`
  flex: 1;
  display: flex;
  align-items: center;
  border: none;
  background: none;
  /* A button does not inherit the page's text color on its own, and the
     layout blocks below render bare text rather than a styled Label. */
  color: ${p => p.theme.colors.text};
  padding: 0;
  cursor: pointer;
  text-align: left;
  min-width: 0;
`;

const HeadingText = styled.span`
  font-family: ${p => p.theme.fontFamilyHeader};
  font-weight: bold;
  font-size: 1.1rem;
  line-height: 1.2;
  word-break: break-word;
`;

const ParagraphText = styled.div`
  width: 100%;
  /* The row is a select button: a link inside it must not swallow the click,
     nor navigate away from the builder. */
  pointer-events: none;

  /* The renderer's own block spacing would leave a gap under the last line. */
  & > div > *:last-child {
    margin-bottom: 0;
  }
`;

const Placeholder = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-style: italic;
`;

const Label = styled.span<{ light?: boolean; bold?: boolean }>`
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
  white-space: nowrap;
  font-weight: ${p => (p.bold ? 'bold' : 'normal')};
  color: ${p => (p.light ? p.theme.colors.textLight : p.theme.colors.text)};
`;

const FieldLabel = styled(Row)`
  & svg {
    color: ${p => p.theme.colors.textLight};
  }
`;
