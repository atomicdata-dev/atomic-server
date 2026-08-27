import { forms, Resource, useResource, useString } from '@tomic/react';
import type { JSX } from 'react';
import { LinkableTagList } from './LinkableTagList';
import { BoundField } from './BoundField';
import { FieldPair } from './FieldPair';
import { useFieldOptions } from './useFieldOptions';

interface ChoiceOptionsProps {
  field: Resource;
  /** Whether the question takes several answers, i.e. `multi-select` or
   * `dropdown-multi`. Only those get the selection bounds. */
  multiple?: boolean;
}

/**
 * The options of a `radio` / `multi-select` / `dropdown` / `dropdown-multi`
 * question: an editable list of labels, as it has always looked — or a link to
 * another table's column, which replaces the list. See
 * {@link LinkableTagList}.
 *
 * Each option is a Tag on the mapped Property's `allowsOnly` rather than a
 * string in the field's options bag.
 */
export function ChoiceOptions({
  field,
  multiple,
}: ChoiceOptionsProps): JSX.Element {
  const [mapsTo] = useString(field, forms.properties.formMapsTo);
  const property = useResource(mapsTo);

  // Only while the field's mapped Property is still loading — every saved
  // choice field has one.
  if (!mapsTo) {
    return <></>;
  }

  return (
    <>
      <LinkableTagList
        field={field}
        property={property}
        label='Options'
        addLabel='Add option'
        removeLabel='Remove option'
        itemTestId='choice-option-input'
      />
      {multiple && <SelectionBounds field={field} />}
    </>
  );
}

/**
 * How many options a visitor may tick. Both bounds are optional — an
 * unbounded multi-select is the common case — and live in the field's own
 * options bag rather than on the mapped Property, because they constrain this
 * question rather than the column its answers land in.
 */
function SelectionBounds({ field }: { field: Resource }): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);

  return (
    <FieldPair>
      <BoundField
        label='Min selected'
        optionKey='minSelected'
        options={options}
        setOptions={setOptions}
        min={1}
        helper='The fewest options an answer may carry. An unanswered question still counts as unanswered rather than as too few — that is what Required is for.'
      />
      <BoundField
        label='Max selected'
        optionKey='maxSelected'
        options={options}
        setOptions={setOptions}
        min={1}
        helper='The most options a visitor may tick. Once they reach it the remaining options grey out.'
      />
    </FieldPair>
  );
}
