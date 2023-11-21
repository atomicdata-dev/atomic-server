import { Resource, urls, useArray, useStore } from '@tomic/react';
import { lazy, Suspense, useCallback, useEffect, useState } from 'react';
import { FaPlus } from 'react-icons/fa';
import { Button } from '../../../components/Button';
import {
  InputStyled,
  InputWrapper,
} from '../../../components/forms/InputStyles';
import { Row } from '../../../components/Row';
import { randomItem } from '../../../helpers/randomItem';
import { randomString } from '../../../helpers/randomString';
import { stringToSlug } from '../../../helpers/stringToSlug';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';
import { EditableTag, tagColors } from './Tag';

const EmojiInput = lazy(() => import('../../../chunks/EmojiInput/EmojiInput'));
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
      <CreateTagRow property={resource} onNewTag={handleNewTag} />
    </>
  );
}

interface CreateTagRowProps {
  property: Resource;
  onNewTag: (tag: Resource) => void;
}

function CreateTagRow({ property, onNewTag }: CreateTagRowProps) {
  const store = useStore();
  const [tagName, setTagName] = useState<string>('');
  const [emoji, setEmoji] = useState<string | undefined>();
  const [resetKey, setResetKey] = useState<number>(0);

  const createNewTag = useCallback(async () => {
    const tag = store.getResourceLoading(
      `${property.getSubject()}/${randomString()}`,
      {
        newResource: true,
      },
    );

    await tag.addClasses(store, urls.classes.tag);
    await tag.set(urls.properties.parent, property.getSubject(), store);
    await tag.set(urls.properties.shortname, tagName, store);
    await tag.set(urls.properties.color, randomItem(tagColors), store);

    if (emoji) {
      await tag.set(urls.properties.emoji, emoji, store);
    }

    tag.loading = false;
    onNewTag(tag);
    setTagName('');
    setEmoji(undefined);
    setResetKey(prev => prev + 1);
  }, [property, store, tagName, emoji, onNewTag]);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setTagName(stringToSlug(e.target.value));
  }, []);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Enter') {
        createNewTag();
      }
    },
    [createNewTag],
  );

  return (
    <Suspense fallback={<div>Loading...</div>}>
      <Row>
        <InputWrapper>
          <EmojiInput onChange={setEmoji} key={resetKey} />
          <InputStyled
            placeholder='New tag'
            value={tagName}
            onChange={handleChange}
            onKeyDown={handleKeyDown}
          />
        </InputWrapper>
        <Button title='Add tag' onClick={createNewTag}>
          <FaPlus />
        </Button>
      </Row>
    </Suspense>
  );
}
