import { useCallback, useEffect, useId, useState } from 'react';
import {
  core,
  dataBrowser,
  useResource,
  useStore,
  useString,
} from '@tomic/react';
import { Button } from './Button';
import { Column, Row } from './Row';
import Field from './forms/Field';
import { Input } from './forms/InputStyles';
import { AvatarCropper } from './AvatarCropper';
import { ResourceGlyph } from './ResourceGlyph';
import { ErrorLook } from './ErrorLook';
import { styled } from 'styled-components';

/** The same Atomic profile is used in FOSS and hosted collaboration. */
export function TeamProfileStep({
  subject,
  onContinue,
}: {
  subject: string;
  onContinue: () => void | Promise<void>;
}) {
  const store = useStore();
  const resource = useResource(subject);
  const [name] = useString(resource, core.properties.name);
  const [draft, setDraft] = useState<string>();
  const [source, setSource] = useState<File>();
  const [picture, setPicture] = useState<File>();
  const [preview, setPreview] = useState<string>();
  useEffect(
    () => () => {
      if (preview) URL.revokeObjectURL(preview);
    },
    [preview],
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  const id = useId();
  const handleCropVisibility = useCallback((open: boolean) => {
    if (!open) setSource(undefined);
  }, []);

  async function save() {
    if (busy || !resource.isReady()) return;
    setBusy(true);
    setError(undefined);

    try {
      const fullName = (draft ?? name ?? '').trim();
      if (!fullName) throw new Error('Enter your full name.');

      if (picture) {
        const [uploaded] = await store.uploadFiles([picture], subject);
        if (!uploaded)
          throw new Error('Your profile picture could not be uploaded.');
        await resource.set(dataBrowser.properties.icon, uploaded);
      }

      await resource.set(core.properties.name, fullName);
      await resource.save();
      await onContinue();
    } catch (caught) {
      setError(caught instanceof Error ? caught : new Error(String(caught)));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Column gap='1rem'>
      <h2>How your colleagues see you</h2>
      <p>
        Use your full name and a picture so people recognize you. This updates
        your Atomic profile wherever you collaborate.
      </p>
      <Field label='Full name' fieldId={id}>
        <Input
          id={id}
          autoComplete='name'
          value={draft ?? name ?? ''}
          disabled={busy}
          onChange={event => setDraft(event.target.value)}
        />
      </Field>
      <Row>
        <Avatar>
          {preview ? (
            <img src={preview} alt='Your selected avatar' />
          ) : (
            <ResourceGlyph resource={resource} />
          )}
        </Avatar>
        <Column>
          <label htmlFor={`${id}-picture`}>Profile picture (optional)</label>
          <input
            id={`${id}-picture`}
            type='file'
            accept='image/*'
            disabled={busy}
            onChange={event => {
              const file = event.target.files?.[0];
              if (file) setSource(file);
              event.target.value = '';
            }}
          />
        </Column>
      </Row>
      {picture && <p>Picture ready to save.</p>}
      <p>You can add or change your picture later in your profile.</p>
      {source && (
        <AvatarCropper
          file={source}
          show
          circle
          onShowChange={handleCropVisibility}
          onCropped={file => {
            setPicture(file);
            setPreview(URL.createObjectURL(file));
          }}
        />
      )}
      {(error || resource.error) && (
        <ErrorLook>{(error || resource.error)?.message}</ErrorLook>
      )}
      <Button
        disabled={busy || !resource.isReady() || !(draft ?? name ?? '').trim()}
        onClick={() => void save()}
      >
        {busy ? 'Saving…' : 'Save and continue'}
      </Button>
    </Column>
  );
}

const Avatar = styled.div`
  width: 4rem;
  height: 4rem;
  flex-shrink: 0;
  display: grid;
  place-items: center;
  font-size: 3rem;
  overflow: hidden;
  border-radius: 50%;
  background: ${p => p.theme.colors.bg1};
  img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }
`;
