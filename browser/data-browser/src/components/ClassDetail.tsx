import React from 'react';
import { properties, Resource, useString } from '@tomic/react';
import { ResourceInline } from '../views/ResourceInline';
import { Detail } from './Detail';
import { getIconForClass } from '../views/FolderPage/iconMap';

type Props = {
  resource: Resource;
};

/** Renders the is-a Class for some resource */
export function ClassDetail({ resource }: Props): JSX.Element {
  const [klass] = useString(resource, properties.isA);

  return (
    <React.Fragment>
      {klass && (
        <Detail>
          <>
            {'is a '}
            {getIconForClass(klass)}
            <ResourceInline subject={klass} />
          </>
        </Detail>
      )}
    </React.Fragment>
  );
}
