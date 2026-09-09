import { constructOpenURL } from '@helpers/navigation';
import { ResourceInline } from '@views/ResourceInline/ResourceInline';
import { AtomicLink } from '@components/AtomicLink';
import {
  core,
  dataBrowser,
  forms,
  Resource,
  useArray,
  useNumber,
  useResource,
  useString,
} from '@tomic/react';
import type { JSX } from 'react';
import { LinkableTagList } from './LinkableTagList';
import { BoundField } from './BoundField';
import { FieldPair } from './FieldPair';
import { useFieldOptions } from './useFieldOptions';
import { Divider } from './Divider';

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
 * Each option is a Tag on the mapped Property's `allowsOnly` rather than a
 * string in the field's options bag.
 */
export function ChoiceOptions({
  field,
  multiple,
  readOnly,
  tableSubject,
}: ChoiceOptionsProps): JSX.Element {
  const [mapsTo] = useString(field, forms.properties.formMapsTo);
  const property = useResource(mapsTo);

  const [tags] = useArray(property, core.properties.allowsOnly);
  const [columnMax] = useNumber(property, dataBrowser.properties.max);

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
            max={readOnly ? columnMax : undefined}
          />
        </>
      )}
    </>
  );
}

/**
 * How many options a visitor may tick. Both bounds are optional — an
 * unbounded multi-select is the common case — and live in the field's own
 * options bag rather than on the mapped Property, because they constrain this
 * question rather than the column its answers land in.
 */
function SelectionBounds({
  field,
  max,
}: {
  field: Resource;
  max?: number;
}): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);

  return (
    <FieldPair>
      <BoundField
        label='Min selected'
        optionKey='minSelected'
        options={options}
        setOptions={setOptions}
        min={1}
        max={max}
        helper='The fewest options an answer may carry. An unanswered question still counts as unanswered rather than as too few — that is what Required is for.'
      />
      <BoundField
        label='Max selected'
        optionKey='maxSelected'
        options={options}
        setOptions={setOptions}
        min={1}
        max={max}
        helper='The most options a visitor may tick. Once they reach it the remaining options grey out.'
      />
    </FieldPair>
  );
}
