import { Datatype, core, server } from '@tomic/react';
import { useEffect } from 'react';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';

export function FilePropertyForm({
  resource,
}: PropertyCategoryFormProps): JSX.Element {
  useEffect(() => {
    resource.set(core.properties.datatype, Datatype.ATOMIC_URL);
    resource.set(core.properties.classtype, server.classes.file);
  }, []);

  return <></>;
}
