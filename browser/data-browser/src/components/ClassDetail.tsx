import { properties, Resource, useArray } from '@tomic/react';
import { Detail } from './Detail';
import { getIconForClass } from '../views/FolderPage/iconMap';
import { InlineFormattedResourceList } from './InlineFormattedResourceList';

type Props = {
  resource: Resource;
};

/** Renders the is-a Class for some resource */
export function ClassDetail({ resource }: Props): JSX.Element {
  const [classes] = useArray(resource, properties.isA);

  return (
    <>
      {classes && (
        <Detail>
          <>
            {'is a '}
            {getIconForClass(classes[0])}
            <InlineFormattedResourceList subjects={classes} />
          </>
        </Detail>
      )}
    </>
  );
}
