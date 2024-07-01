import { Resource, core, dataBrowser, useStore } from '@tomic/react';
import { useState, useCallback } from 'react';
import { FaPlus } from 'react-icons/fa';
import { randomItem } from '../../helpers/randomItem';
import { stringToSlug } from '../../helpers/stringToSlug';
import { Button } from '../Button';
import { Row } from '../Row';
import { InputWrapper, InputStyled } from '../forms/InputStyles';
import { tagColours } from './tagColours';
import { EmojiInput } from '../forms/EmojiInput';

interface CreateTagRowProps {
  parent: string;
  onNewTag: (tag: Resource) => void;
}

export function CreateTagRow({ parent, onNewTag }: CreateTagRowProps) {
  const store = useStore();
  const [tagName, setTagName] = useState<string>('');
  const [emoji, setEmoji] = useState<string | undefined>();
  const [resetKey, setResetKey] = useState<number>(0);

  const createNewTag = useCallback(async () => {
    const subject = await store.buildUniqueSubjectFromParts(
      ['tag', tagName],
      parent,
    );
    const tag = await store.newResource({
      subject,
      parent,
      isA: dataBrowser.classes.tag,
      propVals: {
        [core.properties.shortname]: tagName,
        [dataBrowser.properties.color]: randomItem(tagColours),
      },
    });

    if (emoji) {
      await tag.set(dataBrowser.properties.emoji, emoji);
    }

    onNewTag(tag);
    setTagName('');
    setEmoji(undefined);
    setResetKey(prev => prev + 1);
  }, [parent, store, tagName, emoji, onNewTag]);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setTagName(stringToSlug(e.target.value));
  }, []);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        createNewTag();
      }
    },
    [createNewTag],
  );

  return (
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
      <Button title='Add tag' onClick={createNewTag} disabled={!tagName}>
        <FaPlus />
      </Button>
    </Row>
  );
}
