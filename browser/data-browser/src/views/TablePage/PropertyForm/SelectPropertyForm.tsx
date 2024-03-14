import {
  Datatype,
  Resource,
  core,
  dataBrowser,
  useArray,
  useStore,
} from '@tomic/react';
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
    core.properties.allowsOnly,
    valueOpts,
  );

  const [subResources, setSubResources] = useArray(
    resource,
    dataBrowser.properties.subResources,
    valueOpts,
  );

  const handleNewTag = useCallback(
    async (tag: Resource) => {
      await setAllowOnly([...allowOnly, tag.subject]);
      await setSubResources([...subResources, tag.subject]);

      await tag.save();
    },
    [allowOnly, setAllowOnly, subResources, setSubResources],
  );

  const handleDeleteTag = useCallback(
    async (subject: string) => {
      const tag = store.getResourceLoading(subject);
      tag.destroy();

      await setAllowOnly(removeFromArray(allowOnly, subject));
      await setSubResources(removeFromArray(subResources, subject));
    },
    [store, setAllowOnly, setSubResources, allowOnly, subResources],
  );

  useEffect(() => {
    resource.addClasses(dataBrowser.classes.selectProperty);

    resource.set(core.properties.datatype, Datatype.RESOURCEARRAY);
  }, []);

  return (
    <>
      <Row wrapItems>
        {allowOnly.map(tag => (
          <EditableTag subject={tag} key={tag} onDelete={handleDeleteTag} />
        ))}
      </Row>
      <CreateTagRow parent={resource.subject} onNewTag={handleNewTag} />
    </>
  );
}
