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

  const handleNewTag = useCallback(
    async (tag: Resource) => {
      await setAllowOnly([...allowOnly, tag.subject]);

      await tag.save();
    },
    [allowOnly, setAllowOnly],
  );

  const handleDeleteTag = useCallback(
    async (subject: string) => {
      const tag = store.getResourceLoading(subject);
      tag.destroy();

      await setAllowOnly(removeFromArray(allowOnly, subject));
    },
    [store, setAllowOnly, allowOnly],
  );

  useEffect(() => {
    resource.addClasses(dataBrowser.classes.selectProperty);

    resource.set(core.properties.datatype, Datatype.RESOURCEARRAY);
    resource.set(core.properties.classtype, dataBrowser.classes.tag);
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
