import { ResourceInline } from '../views/ResourceInline';

interface InlineFormattedResourceListProps {
  subjects: string[];
  /** Optional component to render items instead of an inline resource */
  RenderComp?: React.FC<{ subject: string }>;
}

const formatter = new Intl.ListFormat('en-GB', {
  style: 'long',
  type: 'conjunction',
});

export function InlineFormattedResourceList({
  subjects,
  RenderComp,
}: InlineFormattedResourceListProps): JSX.Element {
  // There are rare cases where a resource array can locally have an undefined value, we filter these out to prevent the formatter from throwing an error.
  const filteredSubjects = subjects.filter(subject => subject !== undefined);

  return (
    <>
      {formatter.formatToParts(filteredSubjects).map(({ type, value }) => {
        if (type === 'literal') {
          return value;
        }

        if (RenderComp) {
          return <RenderComp subject={value} key={value} />;
        }

        return <ResourceInline subject={value} key={value} />;
      })}
    </>
  );
}
