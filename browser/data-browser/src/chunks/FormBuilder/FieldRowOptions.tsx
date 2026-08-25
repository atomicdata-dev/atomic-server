import {
  core,
  forms,
  Resource,
  useArray,
  useResource,
  useString,
  useTitle,
  useValue,
} from '@tomic/react';
import type { JSX, ReactNode } from 'react';
import { styled } from 'styled-components';
import { parseFieldOptions } from './FieldOptions/useFieldOptions';
import { isChoiceFieldType, type AddableFieldType } from './fieldTypes';

/** Past this many, the rest collapse into an `and x more`. */
const MAX_VISIBLE = 5;

interface FieldRowOptionsProps {
  field: Resource;
  type: AddableFieldType;
}

/**
 * The answer options of a question, listed on its card in the builder's field
 * list — so the list reads as the form itself rather than as a stack of type
 * names. Only the types that _have_ a fixed set of options render anything.
 */
export function FieldRowOptions({
  field,
  type,
}: FieldRowOptionsProps): JSX.Element | null {
  if (isChoiceFieldType(type)) {
    return <ChoiceOptionsPreview field={field} />;
  }

  if (type === 'choice-matrix') {
    return <MatrixOptionsPreview field={field} />;
  }

  return null;
}

/**
 * A choice question's options are Tags on the Property it maps to (see
 * `TagListEditor`), so each one needs resolving for its name. Empty for a
 * question whose options come from a table's *rows* — that list only exists
 * server-side, at publish time.
 */
function ChoiceOptionsPreview({
  field,
}: {
  field: Resource;
}): JSX.Element | null {
  const [mapsTo] = useString(field, forms.properties.formMapsTo);
  const property = useResource(mapsTo);
  const [allowsOnly] = useArray(property, core.properties.allowsOnly);

  return (
    <OptionPreview
      items={allowsOnly}
      renderItem={subject => <TagOption key={subject} subject={subject} />}
    />
  );
}

/**
 * A matrix is one radio group per row, all sharing the same columns. The rows
 * are what the question actually asks, so they are the list worth showing —
 * the columns are the answer scale, and repeating them on every matrix card
 * would say little.
 */
function MatrixOptionsPreview({
  field,
}: {
  field: Resource;
}): JSX.Element | null {
  const [raw] = useValue(field, forms.properties.formFieldOptions);
  const options = parseFieldOptions(raw);

  const rows = (options.rows as string[] | undefined) ?? [];

  return <OptionPreview items={rows} renderItem={renderStringOption} />;
}

function TagOption({ subject }: { subject: string }): JSX.Element {
  const resource = useResource(subject);
  const [title] = useTitle(resource);

  return <OptionItem>{title}</OptionItem>;
}

const renderStringOption = (value: string, index: number) => (
  <OptionItem key={`${index}-${value}`}>{value}</OptionItem>
);

interface OptionPreviewProps<T> {
  items: T[];
  renderItem: (item: T, index: number) => ReactNode;
}

function OptionPreview<T>({
  items,
  renderItem,
}: OptionPreviewProps<T>): JSX.Element | null {
  if (items.length === 0) {
    return null;
  }

  const hidden = items.length - MAX_VISIBLE;

  return (
    <OptionList>
      {items.slice(0, MAX_VISIBLE).map(renderItem)}
      {hidden > 0 && <More>and {hidden} more</More>}
    </OptionList>
  );
}

const OptionList = styled.ul`
  margin: 0;
  padding: 0;
  list-style: none;
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
  max-width: 100%;
`;

/* `margin: 0` on every item: the global stylesheet indents `ul li` and gives
   it a disc, which this list draws itself. */
const OptionItem = styled.li`
  list-style: none;
  margin: 0;
  padding-left: 1rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;

  &::before {
    content: '•';
    display: inline-block;
    width: 1rem;
    margin-left: -1rem;
  }
`;

const More = styled.li`
  list-style: none;
  margin: 0;
  padding-left: 1rem;
  font-style: italic;
`;
