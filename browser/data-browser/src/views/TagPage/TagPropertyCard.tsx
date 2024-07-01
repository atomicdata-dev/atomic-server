import {
  core,
  useArray,
  useCollection,
  useMemberFromCollection,
  useTitle,
  type Collection,
  type DataBrowser,
  type Resource,
} from '@tomic/react';
import { Card } from '../../components/Card';
import { Column } from '../../components/Row';
import { InlineFormattedResourceList } from '../../components/InlineFormattedResourceList';

interface TagPropertyCardProps {
  resource: Resource<DataBrowser.Tag>;
}

export function TagPropertyCard({ resource }: TagPropertyCardProps) {
  const { collection } = useCollection(
    {
      property: core.properties.allowsOnly,
      value: resource.subject,
    },
    { pageSize: 100 },
  );

  if (collection.totalMembers === 0) {
    return <Card>Not used in any properties</Card>;
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
