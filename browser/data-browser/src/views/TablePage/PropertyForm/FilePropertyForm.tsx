import { urls, useStore } from '@tomic/react';
import { useEffect } from 'react';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';

export function FilePropertyForm({
  resource,
}: PropertyCategoryFormProps): JSX.Element {
  const store = useStore();

  useEffect(() => {
    resource.set(urls.properties.datatype, urls.datatypes.atomicUrl, store);
    resource.set(urls.properties.classType, urls.classes.file, store);
  }, []);

  return <></>;
}
