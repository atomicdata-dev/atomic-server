import { forms, Resource, useResource, useString } from '@tomic/react';
import type { JSX } from 'react';
import { LinkableTagList } from './LinkableTagList';

interface ChoiceOptionsProps {
  field: Resource;
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
export function ChoiceOptions({ field }: ChoiceOptionsProps): JSX.Element {
  const [mapsTo] = useString(field, forms.properties.formMapsTo);
  const property = useResource(mapsTo);

  // Only while the field's mapped Property is still loading — every saved
  // choice field has one.
  if (!mapsTo) {
    return <></>;
  }

  return (
    <LinkableTagList
      field={field}
      property={property}
      label='Options'
      addLabel='Add option'
      removeLabel='Remove option'
      itemTestId='choice-option-input'
    />
  );
}
