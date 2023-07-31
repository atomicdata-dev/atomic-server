import React from 'react';
import { ResourceInline } from '../views/ResourceInline';

interface InlineFormattedResourceListProps {
  subjects: string[];
}

const formatter = new Intl.ListFormat('en-GB', {
  style: 'long',
  type: 'conjunction',
});

export function InlineFormattedResourceList({
  subjects,
}: InlineFormattedResourceListProps): JSX.Element {
  return (
    <>
      {formatter.formatToParts(subjects).map(({ type, value }) => {
        if (type === 'literal') {
          return value;
        }

        return <ResourceInline subject={value} key={value} />;
      })}
    </>
  );
}
