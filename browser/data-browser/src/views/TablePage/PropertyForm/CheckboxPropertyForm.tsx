import { urls, useStore } from '@tomic/react';
import React, { useEffect } from 'react';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';

export function CheckboxPropertyForm({
  resource,
}: PropertyCategoryFormProps): JSX.Element {
  const store = useStore();

  useEffect(() => {
    resource.set(urls.properties.datatype, urls.datatypes.boolean, store);
  }, []);

  return <></>;
}
