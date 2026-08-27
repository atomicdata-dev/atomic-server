import {
  core,
  forms,
  useArray,
  useBoolean,
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
import { VisuallyHidden } from '@components/VisuallyHidden';
import { transition } from '@helpers/transition';
import {
  isLayoutType,
  type AddableFieldType,
  type FormFieldType,
} from './fieldTypes';
import { FormMarkdown, infoBoxStyle } from '@tomic/form-renderer';
import { FieldPreview } from './FieldPreview';

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
  const [required] = useBoolean(resource, forms.properties.required);
  const [infoStyle] = useString(resource, forms.properties.formInfoBoxStyle);
  // The info box's title, read raw rather than through `useTitle`: it is
  // optional, and `useTitle`'s fallback would invent one from the subject.
  const [infoTitle] = useString(resource, core.properties.name);
  // Read `isA` through `useArray`, NOT `resource.hasClasses()`. `hasClasses`
  // is a raw read with no subscription, and `useResource`'s snapshot only
  // changes when the store calls `notify()` — so a row whose `isA` lands
  // late (reload hydration) never re-renders and stays stuck on the
  // `short-text` fallback below. The input types escape this because they
  // key off `form-field-type` via `useString`, which subscribes to that
  // property; the layout blocks are the only ones that depend on `isA`.
  const [classes] = useArray(resource, core.properties.isA);
  const isHeading = classes.includes(forms.classes.formHeading);
  const isParagraph = classes.includes(forms.classes.formParagraph);
  const isInfoBox = classes.includes(forms.classes.formInfoBox);

  const type: AddableFieldType = isHeading
    ? 'heading'
    : isParagraph
      ? 'paragraph'
      : isInfoBox
        ? 'info-box'
        : ((fieldType as AddableFieldType | undefined) ?? 'short-text');

  const isLayout = isLayoutType(type);
  // Like the published form, a checkbox puts its label beside the box rather
  // than above it — so the preview draws it and the row must not.
  const labelAbovePreview = !isLayout && type !== 'checkbox';

  return (
    <RowWrapper $selected={selected} data-selected={selected}>
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
        <Column fullWidth gap='0.35rem'>
          {/* A layout block is nothing but the text it puts on the form, so it
              renders as that text. A question renders the way the respondent
              will meet it: label, helper text, and the actual control. */}
          {isHeading ? (
            <HeadingText>
              {name || <Placeholder>Empty heading</Placeholder>}
            </HeadingText>
          ) : isInfoBox ? (
            // Not the renderer's `InfoBox`: its stylesheet is only loaded by
            // the preview dialog, so the row draws the same shape from the
            // app theme instead.
            <InfoBoxPreview $style={infoBoxStyle(infoStyle)}>
              {infoTitle && <InfoBoxTitle>{infoTitle}</InfoBoxTitle>}
              {description ? (
                <ParagraphText>
                  <FormMarkdown text={description} />
                </ParagraphText>
              ) : (
                <Placeholder>Empty info box</Placeholder>
              )}
            </InfoBoxPreview>
          ) : isParagraph ? (
            description ? (
              <ParagraphText>
                {/* The same renderer the published form uses, so the row
                    shows what the respondent will read. */}
                <FormMarkdown text={description} />
              </ParagraphText>
            ) : (
              <Placeholder>Empty paragraph</Placeholder>
            )
          ) : (
            <>
              {labelAbovePreview ? (
                <FieldLabel>
                  {name || <Placeholder>Untitled question</Placeholder>}
                  {required && <RequiredMark>*</RequiredMark>}
                </FieldLabel>
              ) : (
                // The preview draws the checkbox's label, but it is
                // `aria-hidden` — so the select button would otherwise have no
                // accessible name at all.
                <VisuallyHidden>{name}</VisuallyHidden>
              )}
              {description && (
                <Description>
                  <FormMarkdown text={description} />
                </Description>
              )}
              {/* Not a layout block, so `type` is an input type — the ternary
                  above has already handled every other case. */}
              <FieldPreview
                field={resource}
                type={type as FormFieldType}
                label={name}
              />
            </>
          )}
          {conditions.length > 0 && (
            <ConditionRow gap='0.35rem' center>
              <FaCodeBranch />
              <Label light>Conditional</Label>
            </ConditionRow>
          )}
        </Column>
      </SelectButton>
      <DeleteButton
        variant={IconButtonVariant.Simple}
        size='0.8rem'
        color='textLight'
        title='Delete field'
        type='button'
        onClick={onDelete}
      >
        <FaTrash />
      </DeleteButton>
    </RowWrapper>
  );
}

const ConditionRow = styled(Row)`
  color: ${p => p.theme.colors.textLight};
`;

/** No card at rest — the row draws the field itself, and a border around a
 * bordered input just reads as a box in a box. It still highlights on hover
 * and while selected, otherwise nothing says it can be clicked. */
const RowWrapper = styled.div<{ $selected: boolean }>`
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 0.5rem 0.7rem;
  border: 1px solid ${p => (p.$selected ? p.theme.colors.main : 'transparent')};
  border-radius: ${p => p.theme.radius};
  background-color: ${p =>
    p.$selected ? p.theme.colors.mainSelectedBg : 'transparent'};

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
  align-self: flex-start;
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
  font-size: 1em;
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

/** Mirrors `.atomic-form-info-box` in the renderer's stylesheet, in the app's
 * own theme colors. `info` follows the app's main color the same way the
 * published box follows the form's accent. */
const InfoBoxPreview = styled.div<{ $style: string }>`
  --info-box-color: ${p =>
    ({
      info: p.theme.colors.main,
      note: p.theme.colors.textLight,
      tip: '#0d9488',
      success: '#15803d',
      warning: '#b45309',
      danger: p.theme.colors.alert,
    })[p.$style] ?? p.theme.colors.main};

  width: 100%;
  border-left: 3px solid var(--info-box-color);
  background: color-mix(in srgb, var(--info-box-color) 10%, transparent);
  border-radius: ${p => p.theme.radius};
  padding: 0.5rem 0.75rem;
`;

const InfoBoxTitle = styled.span`
  display: block;
  font-weight: bold;
  color: var(--info-box-color);
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

/** The question's label, styled like `.atomic-form-label` in the renderer. */
const FieldLabel = styled.span`
  font-weight: bold;
  word-break: break-word;
`;

const RequiredMark = styled.span`
  color: ${p => p.theme.colors.alert};
  margin-left: 0.2rem;
`;

/** The helper text, under the label and above the control — where the
 * published form puts it. */
const Description = styled.div`
  width: 100%;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
  /* The row is a select button: a link inside it must not swallow the click. */
  pointer-events: none;

  & > div > *:last-child {
    margin-bottom: 0;
  }
`;
