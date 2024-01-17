import { Resource, urls, useArray, useStore } from '@tomic/react';
import { useCallback, useEffect } from 'react';
import { Row } from '../../../components/Row';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';
import { CreateTagRow, EditableTag } from '../../../components/Tag';

const valueOpts = {
  commit: false,
  validate: false,
};

function removeFromArray<T>(array: T[], item: T) {
  return array.filter(i => i !== item);
}

export function SelectPropertyForm({
  resource,
}: PropertyCategoryFormProps): JSX.Element {
  const store = useStore();

  const [allowOnly, setAllowOnly] = useArray(
    resource,
    urls.properties.allowsOnly,
    valueOpts,
  );

  const [subResources, setSubResources] = useArray(
    resource,
    urls.properties.subResources,
    valueOpts,
  );

  const handleNewTag = useCallback(
    async (tag: Resource) => {
      await setAllowOnly([...allowOnly, tag.getSubject()]);
      await setSubResources([...subResources, tag.getSubject()]);

      await tag.save(store);
    },
    [allowOnly, setAllowOnly, subResources, setSubResources, store],
  );

  const handleDeleteTag = useCallback(
    async (subject: string) => {
      const tag = store.getResourceLoading(subject);
      tag.destroy(store);

      await setAllowOnly(removeFromArray(allowOnly, subject));
      await setSubResources(removeFromArray(subResources, subject));
    },
    [store, setAllowOnly, setSubResources, allowOnly, subResources],
  );

  useEffect(() => {
    resource.addClasses(
      store,
      urls.classes.constraintProperties.selectProperty,
    );

    resource.set(urls.properties.datatype, urls.datatypes.resourceArray, store);
  }, []);

  return (
    <>
      <Row wrapItems>
        {allowOnly.map(tag => (
          <EditableTag subject={tag} key={tag} onDelete={handleDeleteTag} />
        ))}
      </Row>
      <CreateTagRow parent={resource.getSubject()} onNewTag={handleNewTag} />
    </>
  );
}
