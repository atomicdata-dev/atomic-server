import { i18n, langTagRegex, useResource } from '@tomic/react';
import { useEffect, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaPlus, FaTrash } from 'react-icons/fa6';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from './Dialog';
import { Button } from './Button';
import { Column, Row } from './Row';
import {
  InputStyled,
  InputWrapper,
  InlineErrMessage,
} from './forms/InputStyles';
import { useSettings } from '../helpers/AppSettings';
import { useSaveResource } from './forms/hooks/useSaveResource';

interface EditLanguagesDialogProps {
  show: boolean;
  bindShow: (show: boolean) => void;
}

/**
 * Edits the drive's declared `languages` set — the contract that language
 * pickers, completeness indicators, and split columns work against.
 */
export function EditLanguagesDialog({
  show,
  bindShow,
}: EditLanguagesDialogProps): JSX.Element {
  const [dialogProps, showDialog, hideDialog, dialogVisible] = useDialog({
    bindShow,
  });
  const { drive, contentLanguage, setContentLanguage } = useSettings();
  const driveResource = useResource(drive);

  const [tags, setTags] = useState<string[]>([]);
  const [newTag, setNewTag] = useState('');
  const [tagError, setTagError] = useState<string | undefined>(undefined);

  useEffect(() => {
    if (show) {
      const declared = driveResource.get(i18n.properties.languages);
      setTags(
        Array.isArray(declared)
          ? (declared.filter(t => typeof t === 'string') as string[])
          : [],
      );
      setNewTag('');
      setTagError(undefined);
      showDialog();
    } else {
      hideDialog();
    }
    // The declared set should only reseed when the dialog opens, not on
    // every remote change while editing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [show, showDialog, hideDialog]);

  const [save, saving, error] = useSaveResource(driveResource, () =>
    hideDialog(true),
  );

  function addTag(): void {
    const tag = newTag.trim();

    if (tag.match(langTagRegex) === null) {
      setTagError('Invalid language tag');

      return;
    }

    if (tags.includes(tag)) {
      setTagError('Language already added');

      return;
    }

    setTags([...tags, tag]);
    setNewTag('');
    setTagError(undefined);
  }

  async function handleSave(e: React.SyntheticEvent): Promise<void> {
    if (tags.length === 0) {
      driveResource.remove(i18n.properties.languages);
    } else {
      await driveResource.set(i18n.properties.languages, tags, false);

      // Keep the app's content language inside the declared set.
      if (!tags.includes(contentLanguage)) {
        setContentLanguage(tags[0]);
      }
    }

    save(e);
  }

  return (
    <Dialog {...dialogProps} width='50ch'>
      {dialogVisible && (
        <>
          <DialogTitle>
            <h1>Languages</h1>
          </DialogTitle>
          <DialogContent>
            <Column gap='0.5rem'>
              <p>
                The languages this drive publishes content in (BCP 47 tags, e.g.{' '}
                <code>en</code> or <code>nl-BE</code>). Language pickers offer
                these, and a missing translation is flagged against this set.
              </p>
              {tags.map(tag => (
                <Row gap='1ch' center key={tag}>
                  <LangTag>{tag}</LangTag>
                  <Button
                    icon
                    subtle
                    type='button'
                    title={`Remove ${tag}`}
                    onClick={() => setTags(tags.filter(t => t !== tag))}
                  >
                    <FaTrash />
                  </Button>
                </Row>
              ))}
              <Row gap='1ch' center>
                <TagInputWrapper $invalid={!!tagError}>
                  <InputStyled
                    value={newTag}
                    placeholder='e.g. en or de-DE'
                    aria-label='New language tag'
                    autoFocus
                    onChange={e => {
                      setNewTag(e.target.value);
                      setTagError(undefined);
                    }}
                    onKeyDown={e => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        addTag();
                      }
                    }}
                  />
                </TagInputWrapper>
                <Button
                  subtle
                  type='button'
                  title='Add a language'
                  disabled={newTag.trim() === ''}
                  onClick={addTag}
                >
                  <Row gap='.5rem' center>
                    <FaPlus /> <span>Add</span>
                  </Row>
                </Button>
              </Row>
              {tagError && <InlineErrMessage>{tagError}</InlineErrMessage>}
            </Column>
          </DialogContent>
          <DialogActions>
            {error && <InlineErrMessage>{error.message}</InlineErrMessage>}
            <Button subtle onClick={() => hideDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleSave} disabled={saving}>
              Save
            </Button>
          </DialogActions>
        </>
      )}
    </Dialog>
  );
}

const LangTag = styled.span`
  min-width: 8ch;
  font-family: monospace;
`;

const TagInputWrapper = styled(InputWrapper)`
  max-width: 16ch;
  flex: 0 1 auto;
`;
