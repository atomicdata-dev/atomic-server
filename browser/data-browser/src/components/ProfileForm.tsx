import { useCallback, useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { FaUser } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { Button } from './Button';
import { Column, Row } from './Row';
import Field from './forms/Field';
import { Input } from './forms/InputStyles';
import { AvatarCropper } from './AvatarCropper';
import { ErrorLook } from './ErrorLook';

/**
 * The one profile form: a full name and an optional picture. Used when someone
 * creates an account, accepts an invite and shares for the first time, so all
 * three ask the same question in the same words.
 *
 * It only collects. Saving belongs to the caller, because an account being
 * created has no agent resource yet while an existing one does.
 */
export function ProfileForm({
  initialName = '',
  currentAvatar,
  fieldId,
  autoFocus,
  disabled,
  error: outsideError,
  onSave,
}: {
  initialName?: string;
  /** The picture already on the profile, if any. */
  currentAvatar?: ReactNode;
  /** A stable id for the name input; tests and the portal address it. */
  fieldId?: string;
  autoFocus?: boolean;
  disabled?: boolean;
  error?: Error;
  onSave: (profile: { name: string; picture?: File }) => void | Promise<void>;
}) {
  const [name, setName] = useState<string>();
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
  const generatedId = useId();
  const id = fieldId ?? generatedId;
  const fileInput = useRef<HTMLInputElement>(null);
  const handleCropVisibility = useCallback((open: boolean) => {
    if (!open) setSource(undefined);
  }, []);

  const value = name ?? initialName;
  const locked = busy || !!disabled;

  async function save(event: React.FormEvent) {
    event.preventDefault();
    const fullName = value.trim();

    if (locked || !fullName) return;

    setBusy(true);
    setError(undefined);

    try {
      await onSave({ name: fullName, picture });
    } catch (caught) {
      setError(caught instanceof Error ? caught : new Error(String(caught)));
    } finally {
      setBusy(false);
    }
  }

  const shownError = error ?? outsideError;

  return (
    <form onSubmit={save}>
      <Column gap='1rem'>
        <h2>How your colleagues see you</h2>
        <p>
          Use your full name and a picture so people recognize you. You can
          change both later in your profile.
        </p>
        <Field label='Full name' fieldId={id}>
          <Input
            id={id}
            autoComplete='name'
            value={value}
            disabled={locked}
            autoFocus={autoFocus}
            onChange={event => setName(event.target.value)}
          />
        </Field>
        <Row>
          <Avatar
            type='button'
            aria-label='Choose profile picture'
            disabled={locked}
            onClick={() => fileInput.current?.click()}
          >
            {preview ? (
              <img src={preview} alt='Your selected avatar' />
            ) : (
              (currentAvatar ?? <FaUser aria-hidden />)
            )}
          </Avatar>
          <Column>
            <label htmlFor={`${id}-picture`}>Profile picture (optional)</label>
            <input
              ref={fileInput}
              id={`${id}-picture`}
              type='file'
              accept='image/*'
              disabled={locked}
              onChange={event => {
                const file = event.target.files?.[0];
                if (file) setSource(file);
                event.target.value = '';
              }}
            />
          </Column>
        </Row>
        {picture && <p>Picture ready to save.</p>}
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
        {shownError && <ErrorLook>{shownError.message}</ErrorLook>}
        <Row>
          <Button type='submit' disabled={locked || !value.trim()}>
            {busy ? 'Saving…' : 'Save and continue'}
          </Button>
        </Row>
      </Column>
    </form>
  );
}

const Avatar = styled.button`
  cursor: pointer;
  border: 0;
  padding: 0;
  color: inherit;
  &:focus-visible {
    outline: 2px solid currentColor;
    outline-offset: 3px;
  }
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
