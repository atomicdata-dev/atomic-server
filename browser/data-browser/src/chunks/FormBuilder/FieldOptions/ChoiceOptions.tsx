import { constructOpenURL } from '@helpers/navigation';
import { ResourceInline } from '@views/ResourceInline/ResourceInline';
import { AtomicLink } from '@components/AtomicLink';
import { forms, Resource, useResource, useString } from '@tomic/react';
import type { JSX } from 'react';
import { LinkableTagList } from './LinkableTagList';
import { BoundField } from './BoundField';
import { FieldPair } from './FieldPair';
import { useFieldOptions } from './useFieldOptions';
import { Divider } from './Divider';
import { useColumnOptions, useFieldConstraint } from '../formDataClass';

interface ChoiceOptionsProps {
  field: Resource;
  readOnly?: boolean;
  tableSubject?: string;
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
 * Each option is a Tag in the `enum` the form's data class sets for the mapped
 * column rather than a string in the field's options bag.
 */
export function ChoiceOptions({
  field,
  multiple,
  readOnly,
  tableSubject,
}: ChoiceOptionsProps): JSX.Element {
  const [mapsTo] = useString(field, forms.properties.formMapsTo);
  const property = useResource(mapsTo);

  const [tags] = useColumnOptions(mapsTo);
  const columnLimits = useFieldConstraint(field);

  // Only while the field's mapped Property is still loading — every saved
  // choice field has one.
  if (!mapsTo) {
    return <></>;
  }

  return (
    <>
      {readOnly ? (
        <>
          <div>
            {tags.map(subject => (
              <div key={subject}>
                <ResourceInline subject={subject} />
              </div>
            ))}
          </div>
          <AtomicLink
            path={
              tableSubject
                ? constructOpenURL(tableSubject, { editColumn: mapsTo ?? '' })
                : undefined
            }
          >
            Edit column on table
          </AtomicLink>
        </>
      ) : (
        <LinkableTagList
          field={field}
          property={property}
          label='Options'
          addLabel='Add option'
          removeLabel='Remove option'
          itemTestId='choice-option-input'
        />
      )}
      {multiple && (
        <>
          <Divider />
          <SelectionBounds
            field={field}
            floor={columnLimits.minItems}
            max={columnLimits.maxItems}
          />
        </>
      )}
    </>
  );
}

/**
 * How many options a visitor may tick. Both bounds are optional — an
 * unbounded multi-select is the common case — and live in the field's own
 * options bag, as `minItems` / `maxItems`, because they constrain this
 * question rather than the column its answers land in. They may only tighten
 * the column's own `minItems` / `maxItems` in the data class (`floor` and
 * `max` here).
 */
function SelectionBounds({
  field,
  floor,
  max,
}: {
  field: Resource;
  floor?: number;
  max?: number;
}): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);

  return (
    <FieldPair>
      <BoundField
        label='Min selected'
        optionKey='minItems'
        options={options}
        setOptions={setOptions}
        min={1}
        floor={floor}
        max={max}
        helper='The fewest options an answer may carry. An unanswered question still counts as unanswered rather than as too few — that is what Required is for.'
      />
      <BoundField
        label='Max selected'
        optionKey='maxItems'
        options={options}
        setOptions={setOptions}
        min={1}
        floor={floor}
        max={max}
        helper='The most options a visitor may tick. Once they reach it the remaining options grey out.'
      />
    </FieldPair>
  );
}
