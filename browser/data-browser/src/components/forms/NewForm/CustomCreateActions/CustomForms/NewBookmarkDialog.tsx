import { core, dataBrowser } from '@tomic/react';
import { useState, useCallback, FormEvent, useEffect, FC } from 'react';
import { Button } from '../../../../Button';
import {
  useDialog,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '../../../../Dialog';
import Field from '../../../Field';
import { InputWrapper, InputStyled } from '../../../InputStyles';
import { CustomResourceDialogProps } from '../../useNewResourceUI';
import { useCreateAndNavigate } from '../../../../../hooks/useCreateAndNavigate';

function normalizeWebAddress(url: string) {
  if (/^[http://|https://]/i.test(url)) {
    return url;
  }

  return `https://${url}`;
}

export const NewBookmarkDialog: FC<CustomResourceDialogProps> = ({
  parent,
  onClose,
}) => {
  const [url, setUrl] = useState('');

  const { dialogProps, show, close } = useDialog({ onCancel: onClose });

  const createResourceAndNavigate = useCreateAndNavigate();

  const onDone = useCallback(
    (e: FormEvent) => {
      e.preventDefault();

      const normalizedUrl = normalizeWebAddress(url);

      createResourceAndNavigate(
        dataBrowser.classes.bookmark,
        {
          [core.properties.name]: 'New Bookmark',
          [dataBrowser.properties.url]: normalizedUrl,
        },
        {
          parent,
        },
      );

      onClose();
    },
    [url, onClose],
  );

  useEffect(() => {
    show();
  }, []);

  return (
    <>
      <Dialog {...dialogProps}>
        <DialogTitle>
          <h1>New Bookmark</h1>
        </DialogTitle>
        <DialogContent>
          <form onSubmit={onDone}>
            <Field required label='url'>
              <InputWrapper>
                <InputStyled
                  placeholder='https://example.com'
                  value={url}
                  autoFocus={true}
                  onChange={e => setUrl(e.target.value)}
                />
              </InputWrapper>
            </Field>
          </form>
        </DialogContent>
        <DialogActions>
          <Button onClick={close} subtle>
            Cancel
          </Button>
          <Button onClick={onDone} disabled={url.trim() === ''}>
            Ok
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};
