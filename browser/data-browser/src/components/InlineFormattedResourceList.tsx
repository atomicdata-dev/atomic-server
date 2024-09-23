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
  const parts = formatter.formatToParts(filteredSubjects);

  return (
    <>
      {parts.map(({ type, value }, i) => {
        if (type === 'literal') {
          return value;
        }

        let key = value;

        // If the value is repeated, we add a suffix to make it unique
        if (parts.findIndex(p => p.value === value) !== i) {
          key = `${value}-${i}`;
        }

        if (RenderComp) {
          return <RenderComp subject={value} key={key} />;
        }

        return <ResourceInline subject={value} key={key} />;
      })}
    </>
  );
}
