import { classes, properties, useResource, useTitle } from '@tomic/react';
import { FormEvent, useCallback, useState } from 'react';
import { Button } from '../Button';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../Dialog';
import Field from '../forms/Field';
import { InputStyled, InputWrapper } from '../forms/InputStyles';
import { Base } from './Base';
import { useCreateAndNavigate } from './useCreateAndNavigate';
import { NewInstanceButtonProps } from './NewInstanceButtonProps';

function normalizeWebAddress(url: string) {
  if (/^[http://|https://]/i.test(url)) {
    return url;
  }

  return `https://${url}`;
}

export function NewBookmarkButton({
  klass,
  subtle,
  icon,
  IconComponent,
  parent,
  children,
  label,
}: NewInstanceButtonProps): JSX.Element {
  const resource = useResource(klass);
  const [title] = useTitle(resource);

  const [url, setUrl] = useState('');

  const [dialogProps, show, hide] = useDialog();

  const createResourceAndNavigate = useCreateAndNavigate(klass, parent);

  const onDone = useCallback(
    (e: FormEvent) => {
      e.preventDefault();

      const normalizedUrl = normalizeWebAddress(url);

      createResourceAndNavigate('bookmark', {
        [properties.name]: 'New Bookmark',
        [properties.bookmark.url]: normalizedUrl,
        [properties.isA]: [classes.bookmark],
      });
    },
    [url],
  );

  return (
    <>
      <Base
        onClick={show}
        title={title}
        icon={icon}
        IconComponent={IconComponent}
        subtle={subtle}
        label={label}
      >
        {children}
      </Base>
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
          <Button onClick={() => hide(false)} subtle>
            Cancel
          </Button>
          <Button onClick={onDone} disabled={url.trim() === ''}>
            Ok
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
