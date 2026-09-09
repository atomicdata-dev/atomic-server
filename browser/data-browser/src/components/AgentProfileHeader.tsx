import { useEffect, useRef, useState } from 'react';
import { styled } from 'styled-components';
import { FaArrowUpRightFromSquare, FaCamera, FaUser } from 'react-icons/fa6';
import {
  core,
  dataBrowser,
  useResource,
  useString,
  useSubject,
} from '@tomic/react';
import { AvatarCropper } from './AvatarCropper';
import { ResourceGlyph } from './ResourceGlyph';
import { useUpload } from '../hooks/useUpload';
import { useSettings } from '../helpers/AppSettings';
import { fetchManagedInfo } from '../helpers/managedServer';
import {
  getManagedAccount,
  PRODUCT_NAME,
  safePortalUrl,
  type ManagedAccount,
} from '../helpers/managed';
import { errorHandler } from '../handlers/errorHandler';

const valueOpts = { commit: true, validate: false } as const;

/**
 * Identity at the top of user settings: your picture and your name, both
 * editable in place. These are the only two things on this page that are
 * *about you* rather than about your data, so they lead — and neither should
 * need a trip to a separate edit form.
 */
export function AgentProfileHeader({ subject }: { subject: string }) {
  const resource = useResource(subject);
  const [name, setName] = useString(resource, core.properties.name, valueOpts);
  const [, setIcon] = useSubject(
    resource,
    dataBrowser.properties.icon,
    valueOpts,
  );
  const { upload } = useUpload(resource);

  const [iconImage] = useSubject(resource, dataBrowser.properties.icon);
  const [emoji] = useString(resource, dataBrowser.properties.emoji);
  const hasPicture = !!(iconImage || emoji);

  // Only set on a managed node: self-hosted users have no account behind the
  // agent, so nothing extra is shown for them.
  const { baseURL } = useSettings();
  const [account, setAccount] = useState<ManagedAccount | null>(null);
  const [portalUrl, setPortalUrl] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      const [session, info] = await Promise.all([
        getManagedAccount().catch(() => null),
        fetchManagedInfo(baseURL).catch(() => null),
      ]);

      if (cancelled) return;

      setAccount(session);
      setPortalUrl(safePortalUrl(info?.portalUrl) ?? null);
    })();

    return () => {
      cancelled = true;
    };
  }, [baseURL]);

  const [draft, setDraft] = useState(name ?? '');
  const [pendingFile, setPendingFile] = useState<File>();
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Keep the field in step with the resource once it loads (or changes
  // elsewhere), without clobbering what the user is currently typing.
  const [focused, setFocused] = useState(false);
  useEffect(() => {
    if (!focused) setDraft(name ?? '');
  }, [name, focused]);

  async function commitName() {
    const trimmed = draft.trim();

    if (!trimmed || trimmed === (name ?? '')) {
      setDraft(name ?? '');

      return;
    }

    try {
      await setName(trimmed);
    } catch (e) {
      errorHandler(e as Error);
      setDraft(name ?? '');
    }
  }

  async function handleCropped(cropped: File) {
    const [uploaded] = await upload([cropped]);

    if (!uploaded) return;

    try {
      await setIcon(uploaded);
    } catch (e) {
      errorHandler(e as Error);
    }
  }

  return (
    <Header>
      <AvatarButton
        type='button'
        onClick={() => inputRef.current?.click()}
        title={hasPicture ? 'Change your picture' : 'Add a picture'}
        data-test='change-avatar'
      >
        {hasPicture ? (
          <Glyph resource={resource} />
        ) : (
          // Not `ResourceGlyph`'s class-icon fallback: that renders the Agent
          // class glyph (an atom), which reads as "a thing in the system"
          // rather than "you, without a picture yet".
          <PlaceholderAvatar aria-hidden>
            <FaUser />
          </PlaceholderAvatar>
        )}
        <AvatarOverlay aria-hidden>
          <FaCamera />
        </AvatarOverlay>
      </AvatarButton>

      <NameField>
        <NameLabel htmlFor='agent-display-name'>Your name</NameLabel>
        <NameInput
          id='agent-display-name'
          data-test='agent-name-input'
          value={draft}
          placeholder='Add your name'
          onChange={e => setDraft(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => {
            setFocused(false);
            void commitName();
          }}
          onKeyDown={e => {
            if (e.key === 'Enter') e.currentTarget.blur();

            if (e.key === 'Escape') {
              setDraft(name ?? '');
              e.currentTarget.blur();
            }
          }}
        />
        <NameHint>Others can see this. Change it whenever.</NameHint>
        {account ? (
          // The account email isn't editable here — it's the control plane's
          // record, not a profile field — so it links out to the portal
          // rather than pretending to be a form field.
          <AccountLink
            href={portalUrl ? `${portalUrl}/dashboard` : undefined}
            target='_blank'
            rel='noopener noreferrer'
            title={`Manage ${account.email} on ${PRODUCT_NAME}`}
            data-test='account-email'
          >
            {account.email}
            <FaArrowUpRightFromSquare aria-hidden />
          </AccountLink>
        ) : null}
      </NameField>

      <HiddenFileInput
        ref={inputRef}
        type='file'
        accept='image/*'
        onChange={e => {
          const file = e.currentTarget.files?.[0];

          if (file) setPendingFile(file);

          // Allow re-picking the same file.
          e.currentTarget.value = '';
        }}
      />
      {pendingFile && (
        <AvatarCropper
          file={pendingFile}
          show
          circle
          onShowChange={open => {
            if (!open) setPendingFile(undefined);
          }}
          onCropped={handleCropped}
        />
      )}
    </Header>
  );
}

const Header = styled.div`
  display: flex;
  align-items: center;
  gap: ${p => p.theme.size(4)};
  flex-wrap: wrap;
`;

const AvatarButton = styled.button`
  position: relative;
  flex-shrink: 0;
  width: 5.5rem;
  height: 5.5rem;
  padding: 0;
  border: none;
  border-radius: 50%;
  background: ${p => p.theme.colors.bg1};
  cursor: pointer;
  overflow: hidden;
  display: grid;
  place-items: center;

  &:hover [data-avatar-overlay],
  &:focus-visible [data-avatar-overlay] {
    opacity: 1;
  }

  &:focus-visible {
    outline: 2px solid ${p => p.theme.colors.main};
    outline-offset: 2px;
  }
`;

/** `IconImg` renders at 1.2em, so this font-size fills the circle exactly. */
const Glyph = styled(ResourceGlyph)`
  font-size: 4.6rem;
`;

const PlaceholderAvatar = styled.span`
  display: grid;
  place-items: center;
  width: 100%;
  height: 100%;
  color: ${p => p.theme.colors.textLight};
  font-size: 2.5rem;
`;

const AvatarOverlay = styled.span.attrs(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  () => ({ 'data-avatar-overlay': 'true' }) as any,
)`
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  background: rgba(0, 0, 0, 0.45);
  color: white;
  opacity: 0;
  transition: opacity 0.15s ease;
  font-size: 1.25rem;
`;

const NameField = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
  min-width: 12rem;
  flex: 1;
`;

const NameLabel = styled.label`
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
`;

const NameInput = styled.input`
  font-size: 1.75rem;
  font-weight: bold;
  color: ${p => p.theme.colors.text};
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  border-radius: 0;
  padding: 0.1rem 0;
  width: 100%;

  &:hover {
    border-bottom-color: ${p => p.theme.colors.bg2};
  }

  &:focus {
    outline: none;
    border-bottom-color: ${p => p.theme.colors.main};
  }

  &::placeholder {
    color: ${p => p.theme.colors.textLight};
    font-weight: normal;
  }
`;

const NameHint = styled.span`
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
`;

const AccountLink = styled.a`
  display: inline-flex;
  align-items: center;
  gap: 0.4em;
  margin-top: 0.35rem;
  width: fit-content;
  font-size: 0.9rem;
  color: ${p => p.theme.colors.textLight};

  svg {
    font-size: 0.75em;
  }

  &:hover {
    color: ${p => p.theme.colors.main};
  }
`;

const HiddenFileInput = styled.input`
  display: none;
`;
