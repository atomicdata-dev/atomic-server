import {
  core,
  useArray,
  useCollection,
  useEffectiveConstraint,
  useMemberFromCollection,
  useResource,
  useTitle,
  type Collection,
  type DataBrowser,
  type Resource,
} from '@tomic/react';
import { Card } from '../../components/Card';
import { Column } from '../../components/Row';
import { InlineFormattedResourceList } from '../../components/InlineFormattedResourceList';
import { optionSubjects } from '@helpers/withConstraint';

interface TagPropertyCardProps {
  resource: Resource<DataBrowser.Tag>;
}

/**
 * Where this tag is an option: the classes whose `constraints` list it for its
 * property (Tags are children of the property they were made for), plus the
 * properties that still list it in their legacy `allowsOnly`.
 */
export function TagPropertyCard({ resource }: TagPropertyCardProps) {
  return (
    <>
      <TagClassUsage resource={resource} />
      <LegacyTagPropertyCard resource={resource} />
    </>
  );
}

function TagClassUsage({ resource }: TagPropertyCardProps) {
  const propertySubject = resource.props.parent;

  // Class members are only looked up for a tag that lives under a property.
  const parent = useResource(propertySubject);

  if (!parent.hasClasses(core.classes.property)) {
    return null;
  }

  return (
    <TagClassUsageRows
      propertySubject={propertySubject}
      tagSubject={resource.subject}
    />
  );
}

interface TagClassUsageRowsProps {
  propertySubject: string;
  tagSubject: string;
}

function TagClassUsageRows({
  propertySubject: target,
  tagSubject,
}: TagClassUsageRowsProps) {
  const { collection: required } = useCollection({
    property: core.properties.requires,
    value: target,
  });
  const { collection: recommended } = useCollection({
    property: core.properties.recommends,
    value: target,
  });

  const rows = [
    ...Array.from({ length: required.totalMembers }, (_, index) => ({
      key: `requires-${index}`,
      collection: required,
      index,
    })),
    ...Array.from({ length: recommended.totalMembers }, (_, index) => ({
      key: `recommends-${index}`,
      collection: recommended,
      index,
    })),
  ];

  if (rows.length === 0) {
    return null;
  }

  return (
    <Card>
      <Column>
        {rows.map(({ key, collection, index }) => (
          <ClassUsageRow
            key={key}
            index={index}
            collection={collection}
            propertySubject={target}
            tagSubject={tagSubject}
          />
        ))}
      </Column>
    </Card>
  );
}

interface ClassUsageRowProps {
  index: number;
  collection: Collection;
  propertySubject: string;
  tagSubject: string;
}

function ClassUsageRow({
  index,
  collection,
  propertySubject,
  tagSubject,
}: ClassUsageRowProps) {
  const klass = useMemberFromCollection(collection, index);
  const constraint = useEffectiveConstraint([klass.subject], propertySubject);
  const [className] = useTitle(klass);
  const options = optionSubjects(constraint);

  if (klass.loading || !options.includes(tagSubject)) {
    return <></>;
  }

  return (
    <Column>
      <h2>{className}</h2>
      <div>
        <InlineFormattedResourceList subjects={options} />
      </div>
    </Column>
  );
}

function LegacyTagPropertyCard({ resource }: TagPropertyCardProps) {
  const { collection } = useCollection(
    {
      property: core.properties.allowsOnly,
      value: resource.subject,
    },
    { pageSize: 100 },
  );

  if (collection.totalMembers === 0) {
    return null;
  }

  return (
    <Card>
      <Column>
        {Array.from({ length: collection.totalMembers }).map((_, index) => (
          <PropertyRow key={index} index={index} collection={collection} />
        ))}
      </Column>
    </Card>
  );
}

interface PropertyRowProps {
  index: number;
  collection: Collection;
}

function PropertyRow({ index, collection }: PropertyRowProps) {
  const resource = useMemberFromCollection(collection, index);
  const [allowsOnlyList] = useArray(resource, core.properties.allowsOnly);
  const [shortname] = useTitle(resource);

  if (resource.loading) {
    return <></>;
  }

  return (
    <Column>
      <h2>{shortname}</h2>
      <div>
        <InlineFormattedResourceList subjects={allowsOnlyList} />
      </div>
    </Column>
  );
}
