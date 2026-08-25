import { Resource, core, dataBrowser, useStore } from '@tomic/react';
import { useState, useCallback } from 'react';
import { FaPlus } from 'react-icons/fa6';
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
    // When the parent is a DID, subjects are derived from the genesis commit
    // signature and must not have a path appended. Only pre-compute a path-based
    // subject for HTTP parents.
    const subject = parent.startsWith('did:')
      ? undefined
      : await store.buildUniqueSubjectFromParts(['tag', tagName], parent);

    const tag = await store.newResource({
      subject,
      parent,
      isA: dataBrowser.classes.tag,
      propVals: {
        // `shortname` is the slug the Tag class requires; `name` keeps the
        // text as typed, since labels like "Strongly agree — daily" do not
        // survive slugification. `useTitle` prefers `name`, so tags render
        // as written.
        [core.properties.shortname]: stringToSlug(tagName),
        [core.properties.name]: tagName,
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
    setTagName(e.target.value);
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
    <Row gap='0.5rem'>
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
