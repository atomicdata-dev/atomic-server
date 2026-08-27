import {
  core,
  forms,
  Resource,
  server,
  useArray,
  useResource,
  useString,
  useTitle,
  useValue,
} from '@tomic/react';
import type { JSX } from 'react';
import { styled, css } from 'styled-components';
import {
  FaCalendar,
  FaCalendarDays,
  FaChevronDown,
  FaImage,
} from 'react-icons/fa6';
import {
  ADDRESS_FIELDS,
  likertScale,
  matrixColumns,
  ratingMax,
  tableColumns,
  type FieldOptions,
} from '@tomic/form-renderer';
import { Row } from '@components/Row';
import { parseFieldOptions } from './FieldOptions/useFieldOptions';
import { isChoiceFieldType, type FormFieldType } from './fieldTypes';

/** Picture options stop here; the rest collapses into an `and x more`. They
 * are cards with thumbnails, so a long list costs several rows of height —
 * unlike the radio and checkbox lists, which show every option. */
const MAX_VISIBLE_PICTURE_OPTIONS = 6;

/** What an empty input of this type shows the respondent — either the
 * browser's own hint (`date`), the shape the answer takes (`email`), or
 * nothing. Only used when the question has no placeholder of its own, and it
 * is the main thing telling the otherwise identical text-ish types apart. */
const TYPE_HINT: Partial<Record<FormFieldType, string>> = {
  email: 'name@example.com',
  url: 'https://example.com',
  phone: '+31 6 12345678',
  number: '0',
  currency: '0.00',
  date: 'dd/mm/yyyy',
  datetime: 'dd/mm/yyyy, --:--',
  country: 'Select a country',
  dropdown: 'Select an option',
  'dropdown-multi': 'Select options',
};

const CURRENCY_SYMBOLS: Record<string, string> = {
  EUR: '€',
  USD: '$',
  GBP: '£',
  JPY: '¥',
  CNY: '¥',
  INR: '₹',
  BRL: 'R$',
  CHF: 'CHF',
  SEK: 'kr',
  NOK: 'kr',
  DKK: 'kr',
  PLN: 'zł',
  CAD: 'C$',
  AUD: 'A$',
};

const RATING_GLYPHS: Record<string, string> = { star: '☆', heart: '♡' };

interface FieldPreviewProps {
  field: Resource;
  type: FormFieldType;
  /** The question's label — only `checkbox` renders it itself, next to the
   * box, the way the published form does. */
  label: string;
}

/**
 * A dead ringer for the control the respondent will get, drawn in the app's
 * own theme rather than the renderer's stylesheet (which is only loaded by
 * the preview dialog).
 *
 * Every control is a `div`, not the themed `Checkbox`/`RadioInput` it
 * imitates: the whole row is one big `<button>` that selects the field, and
 * nesting a real input inside a button is invalid HTML — it would also steal
 * the click. So the preview is inert and hidden from assistive tech, and the
 * row stays a single tab stop.
 *
 * This is what makes the builder's field list read as the form itself. The
 * options a choice question has, the scale a likert uses, the columns of a
 * table — all of it is visible without opening the settings panel.
 */
export function FieldPreview({
  field,
  type,
  label,
}: FieldPreviewProps): JSX.Element {
  return (
    <Inert aria-hidden='true'>
      <PreviewBody field={field} type={type} label={label} />
    </Inert>
  );
}

function PreviewBody({
  field,
  type,
  label,
}: FieldPreviewProps): JSX.Element | null {
  // A dropdown shows a closed select, not its option list — same as the
  // published form. Checked before the choice branch, which the two dropdown
  // types also match.
  if (type === 'dropdown' || type === 'dropdown-multi') {
    return <SingleLinePreview field={field} type={type} />;
  }

  if (isChoiceFieldType(type)) {
    return <ChoicePreview field={field} type={type} />;
  }

  switch (type) {
    case 'long-text':
      return <TextAreaPreview field={field} />;
    case 'checkbox':
      return <CheckboxPreview label={label} />;
    case 'currency':
      return <CurrencyPreview field={field} />;
    case 'likert':
      return <LikertPreview field={field} />;
    case 'rating':
      return <RatingPreview field={field} />;
    case 'choice-matrix':
      return <MatrixPreview field={field} />;
    case 'table-input':
      return <TableInputPreview field={field} />;
    case 'address':
      return <AddressPreview />;
    default:
      return <SingleLinePreview field={field} type={type} />;
  }
}

/** Reads the `form-field-options` bag in the shape the renderer's helpers
 * expect. The two describe the same JSON — the builder just types it loosely,
 * because it also has to write it. */
function useOptions(field: Resource): FieldOptions {
  const [raw] = useValue(field, forms.properties.formFieldOptions);

  return parseFieldOptions(raw) as unknown as FieldOptions;
}

function placeholderFor(
  options: FieldOptions,
  type: FormFieldType,
): string | undefined {
  return options.placeholder || TYPE_HINT[type];
}

/** Everything that is a plain one-line box: the text-ish types, number, the
 * dates and the two selects. They differ only in the hint they show and
 * whether they carry a trailing icon. */
function SingleLinePreview({
  field,
  type,
}: {
  field: Resource;
  type: FormFieldType;
}): JSX.Element {
  const options = useOptions(field);
  const trailing =
    type === 'date' ? (
      <FaCalendar />
    ) : type === 'datetime' ? (
      <FaCalendarDays />
    ) : type === 'country' ||
      type === 'dropdown' ||
      type === 'dropdown-multi' ? (
      <FaChevronDown />
    ) : undefined;

  return (
    <FakeInput>
      <Hint>{placeholderFor(options, type)}</Hint>
      {trailing && <Trailing>{trailing}</Trailing>}
    </FakeInput>
  );
}

function TextAreaPreview({ field }: { field: Resource }): JSX.Element {
  const options = useOptions(field);

  return (
    <FakeTextArea>
      <Hint>{options.placeholder}</Hint>
    </FakeTextArea>
  );
}

function CurrencyPreview({ field }: { field: Resource }): JSX.Element {
  const options = useOptions(field);
  const code = (options.currency ?? 'EUR').toUpperCase();

  return (
    <FakeInput>
      <Affix>{CURRENCY_SYMBOLS[code] ?? code}</Affix>
      <Hint>{placeholderFor(options, 'currency')}</Hint>
    </FakeInput>
  );
}

/** A checkbox is the one question whose label sits beside the control rather
 * than above it — `FormRenderer` skips the label element entirely for it, so
 * the preview has to draw it. */
function CheckboxPreview({ label }: { label: string }): JSX.Element {
  return (
    <ChoiceRow>
      <Box />
      <span>{label}</span>
    </ChoiceRow>
  );
}

/**
 * Radios, checkbox lists, dropdowns and picture cards, all fed by the same
 * source: the options of a choice question are Tags on the Property it maps
 * to (see `TagListEditor`), not values on the field.
 *
 * Empty for a question whose options come from a table's *rows* — that list
 * only exists server-side, at publish time.
 */
function ChoicePreview({
  field,
  type,
}: {
  field: Resource;
  type: FormFieldType;
}): JSX.Element {
  const [mapsTo] = useString(field, forms.properties.formMapsTo);
  const property = useResource(mapsTo);
  const [allowsOnly] = useArray(property, core.properties.allowsOnly);

  if (allowsOnly.length === 0) {
    return <Empty>No options yet</Empty>;
  }

  if (type === 'picture-choice') {
    const visible = allowsOnly.slice(0, MAX_VISIBLE_PICTURE_OPTIONS);
    const hidden = allowsOnly.length - visible.length;

    return (
      <PictureGrid>
        {visible.map(subject => (
          <PictureOption key={subject} subject={subject} />
        ))}
        {hidden > 0 && <More>and {hidden} more</More>}
      </PictureGrid>
    );
  }

  // Every option, however many: a radio group's list is the question, and
  // truncating it hides the thing the row exists to show.
  return (
    <ChoiceGroup>
      {allowsOnly.map(subject => (
        <TagChoice
          key={subject}
          subject={subject}
          multiple={type !== 'radio'}
        />
      ))}
    </ChoiceGroup>
  );
}

function TagChoice({
  subject,
  multiple,
}: {
  subject: string;
  multiple: boolean;
}): JSX.Element {
  const tag = useResource(subject);
  const [title] = useTitle(tag);

  return (
    <ChoiceRow>
      {multiple ? <Box /> : <Circle />}
      <OneLine>{title}</OneLine>
    </ChoiceRow>
  );
}

/** The option Tag's `cover-image`, resolved the same way `PictureChoiceOptions`
 * resolves it for the settings panel. */
function PictureOption({ subject }: { subject: string }): JSX.Element {
  const tag = useResource(subject);
  const [title] = useTitle(tag);
  const fileSubject = tag.get(forms.properties.coverImage) as
    | string
    | undefined;
  const file = useResource(fileSubject);
  const url = fileSubject
    ? (file.get(server.properties.downloadUrl) as string | undefined)
    : undefined;

  return (
    <PictureCard>
      {url ? (
        <PictureImage src={url} alt='' loading='lazy' />
      ) : (
        <PicturePlaceholder>
          <FaImage />
        </PicturePlaceholder>
      )}
      <OneLine>{title}</OneLine>
    </PictureCard>
  );
}

function LikertPreview({ field }: { field: Resource }): JSX.Element {
  const options = useOptions(field);
  const scale = likertScale(options);

  return (
    <LikertRow gap='0.5rem' center wrapItems>
      {options.minLabel && <EndLabel>{options.minLabel}</EndLabel>}
      <Row gap='0.35rem' center>
        {Array.from({ length: scale }, (_, i) => (
          <Step key={i}>{i + 1}</Step>
        ))}
      </Row>
      {options.maxLabel && <EndLabel>{options.maxLabel}</EndLabel>}
    </LikertRow>
  );
}

function RatingPreview({ field }: { field: Resource }): JSX.Element {
  const options = useOptions(field);
  const max = ratingMax(options);
  const glyph = RATING_GLYPHS[options.icon ?? 'star'] ?? RATING_GLYPHS.star;

  return (
    <Glyphs>
      {Array.from({ length: max }, (_, i) => (
        <span key={i}>{glyph}</span>
      ))}
    </Glyphs>
  );
}

function MatrixPreview({ field }: { field: Resource }): JSX.Element {
  const options = useOptions(field);
  const rows = options.rows ?? [];
  const columns = matrixColumns(options);

  if (rows.length === 0 || columns.length === 0) {
    return <Empty>No rows or columns yet</Empty>;
  }

  return (
    <Scroller>
      <MiniTable>
        <thead>
          <tr>
            <th />
            {columns.map(column => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map(row => (
            <tr key={row}>
              <RowHeader>{row}</RowHeader>
              {columns.map(column => (
                <td key={column}>
                  <Circle />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </MiniTable>
    </Scroller>
  );
}

function TableInputPreview({ field }: { field: Resource }): JSX.Element {
  const options = useOptions(field);
  const columns = tableColumns(options);

  if (columns.length === 0) {
    return <Empty>No columns yet</Empty>;
  }

  return (
    <Scroller>
      <MiniTable>
        <thead>
          <tr>
            {columns.map(column => (
              <th key={column.label}>{column.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          <tr>
            {columns.map(column => (
              <td key={column.label}>
                <FakeInput $small />
              </td>
            ))}
          </tr>
        </tbody>
      </MiniTable>
    </Scroller>
  );
}

function AddressPreview(): JSX.Element {
  return (
    <AddressGrid>
      {ADDRESS_FIELDS.map(({ key, label }) => (
        <AddressField key={key} $wide={key === 'line1' || key === 'line2'}>
          <SubLabel>{label}</SubLabel>
          <FakeInput $small>
            {key === 'country' && (
              <Trailing>
                <FaChevronDown />
              </Trailing>
            )}
          </FakeInput>
        </AddressField>
      ))}
    </AddressGrid>
  );
}

/** Nothing in here may take a click or a tab stop — the row around it is the
 * button that selects the field. */
const Inert = styled.div`
  width: 100%;
  min-width: 0;
  pointer-events: none;
  user-select: none;
`;

const inputBox = css`
  display: flex;
  align-items: center;
  gap: 0.4rem;
  width: 100%;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg};
  padding-inline: 0.5rem;
`;

const FakeInput = styled.div<{ $small?: boolean }>`
  ${inputBox}
  height: ${p => (p.$small ? '1.6rem' : '2rem')};
`;

const FakeTextArea = styled.div`
  ${inputBox}
  align-items: flex-start;
  min-height: 4rem;
  padding-block: 0.4rem;
`;

const Hint = styled.span`
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: ${p => p.theme.colors.textLight};
`;

/** The currency symbol, inside the box the way the published form puts it. */
const Affix = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const Trailing = styled.span`
  display: flex;
  align-items: center;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.8rem;
`;

const ChoiceGroup = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  width: 100%;
`;

const ChoiceRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  min-width: 0;
`;

const controlDot = css`
  flex-shrink: 0;
  width: 0.9rem;
  height: 0.9rem;
  border: 1px solid ${p => p.theme.colors.textLight2};
  background-color: ${p => p.theme.colors.bg};
`;

const Circle = styled.span`
  ${controlDot}
  display: inline-block;
  border-radius: 50%;
`;

const Box = styled.span`
  ${controlDot}
  display: inline-block;
  border-radius: 2px;
`;

const OneLine = styled.span`
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const More = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-style: italic;
  font-size: 0.85rem;
`;

const Empty = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-style: italic;
`;

const LikertRow = styled(Row)`
  color: ${p => p.theme.colors.textLight};
`;

const EndLabel = styled.span`
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;

const Step = styled.span`
  display: flex;
  align-items: center;
  justify-content: center;
  width: 1.5rem;
  height: 1.5rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: 50%;
  font-size: 0.75rem;
  color: ${p => p.theme.colors.textLight};
`;

const Glyphs = styled.div`
  display: flex;
  gap: 0.15rem;
  font-size: 1.2rem;
  line-height: 1.2;
  color: ${p => p.theme.colors.textLight};
`;

/** Matrices and table inputs are as wide as their columns make them; let them
 * scroll rather than squeeze the whole field list. */
const Scroller = styled.div`
  width: 100%;
  max-width: 100%;
  overflow-x: auto;
`;

const MiniTable = styled.table`
  border-collapse: collapse;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};

  th,
  td {
    padding: 0.2rem 0.5rem;
    text-align: center;
    font-weight: normal;
    white-space: nowrap;
  }

  thead th {
    color: ${p => p.theme.colors.textLight};
  }
`;

const RowHeader = styled.th`
  text-align: left !important;
  color: ${p => p.theme.colors.text} !important;
  max-width: 12rem;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const PictureGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(5rem, 6rem));
  gap: 0.5rem;
  width: 100%;
`;

const PictureCard = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  min-width: 0;
  font-size: 0.85rem;
`;

const pictureThumb = css`
  width: 100%;
  aspect-ratio: 1;
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => p.theme.colors.bg2};
`;

const PictureImage = styled.img`
  ${pictureThumb}
  object-fit: cover;
`;

const PicturePlaceholder = styled.div`
  ${pictureThumb}
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: ${p => p.theme.colors.bg1};
  color: ${p => p.theme.colors.textLight};
`;

const AddressGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.4rem 0.5rem;
  width: 100%;
`;

const AddressField = styled.div<{ $wide?: boolean }>`
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
  min-width: 0;
  grid-column: ${p => (p.$wide ? 'span 2' : 'auto')};
`;

const SubLabel = styled.span`
  font-size: 0.75rem;
  color: ${p => p.theme.colors.textLight};
`;
