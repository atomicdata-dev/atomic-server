import React, {
  cloneElement,
  isValidElement,
  useCallback,
  useEffect,
  useRef,
  useState,
  type JSX,
} from 'react';
import {
  core,
  dataBrowser,
  urls,
  useArray,
  useCanWrite,
  useCurrentAgent,
  useResource,
  useResourceSnapshot,
  useStore,
  useString,
  useTitle,
  type Resource,
} from '@tomic/react';
import toast from 'react-hot-toast';
import { styled } from 'styled-components';
import { FaTriangleExclamation } from 'react-icons/fa6';

import { Dialog, useDialog } from '../Dialog';
import { Button } from '../Button';
import { ErrorLook } from '../ErrorLook';
import { TeamProfileStep } from '../TeamProfileStep';
import {
  profileReviewedBefore,
  rememberProfileReviewed,
} from './profileReviewed';
import { useIsPrivateDrive } from '@hooks/useIsPrivateDrive';
import { useInheritedRights } from '../../routes/Share/useInheritedRights';
import { getManagedPortalUrl } from '../../helpers/managed/cloudSync';
import {
  accountAddress,
  getManagedAccount,
} from '../../helpers/managed/session';
import { sendShareInvites } from '../../helpers/managed/shareInvites';
import { EmailInviteInput, isEmailAddress } from './EmailInviteInput';
import { describeEditorSeats, useEditorSeats } from './useEditorSeats';
import { PeopleWithAccess, effectiveRole } from './PeopleWithAccess';
import { ResourceLinkNavigationContext } from '../ResourceLinkNavigationContext';
import { PublicAccess } from './PublicAccess';
import { RoleSwitch, type ShareRole } from './RoleSelect';
import { useShareRights } from './useShareRights';
import { useClassLabel } from './useClassLabel';
import { inviteLinkPrefix, useCreateInviteLink } from './useCreateInviteLink';
import {
  UNLIMITED,
  UsageLimitField,
  parseMaxUsages,
  type UsageLimitState,
} from './UsageLimit';

export interface ShareDialogProps {
  subject: string;
  trigger: JSX.Element;
}

/**
 * Share a resource: invite people (by email on hosted Atomic, by link
 * everywhere), see and change who has access, and make it public.
 */
export function ShareDialog({
  subject,
  trigger,
}: ShareDialogProps): JSX.Element {
  const [dialogProps, show, close, isOpen] = useDialog();

  const triggerEl = trigger as React.ReactElement<{
    onClick?: (e: React.MouseEvent) => void;
  }>;
  const triggerWithOpen = isValidElement(trigger)
    ? cloneElement(triggerEl, {
        onClick: (e: React.MouseEvent) => {
          triggerEl.props.onClick?.(e);
          e.stopPropagation();
          show();
        },
      })
    : trigger;

  return (
    <>
      {triggerWithOpen}
      <Dialog {...dialogProps} width='38rem'>
        {isOpen && <ShareDialogBody subject={subject} onDone={close} />}
      </Dialog>
    </>
  );
}

/**
 * The same dialog, open from the moment it mounts, for a caller with no
 * trigger of its own: an app asking the host to share something it shows.
 * `onClosed` runs once the person closes it.
 */
export function OpenShareDialog({
  subject,
  onClosed,
}: {
  subject: string;
  onClosed: () => void;
}): JSX.Element {
  // Stable, so `show` keeps its identity and the effect below opens the
  // dialog once rather than again after every render.
  const onClosedRef = useRef(onClosed);
  useEffect(() => {
    onClosedRef.current = onClosed;
  });
  const bindShow = useCallback((open: boolean) => {
    if (!open) onClosedRef.current();
  }, []);
  const [dialogProps, show, close, isOpen] = useDialog({ bindShow });

  useEffect(() => {
    show();
  }, [show]);

  return (
    <Dialog {...dialogProps} width='38rem'>
      {isOpen && <ShareDialogBody subject={subject} onDone={close} />}
    </Dialog>
  );
}

function ShareDialogBody({
  subject,
  onDone,
}: {
  subject: string;
  onDone: () => void;
}): JSX.Element | null {
  const { resource } = useResourceSnapshot(subject);
  const canWrite = useCanWrite(resource);
  const [agent] = useCurrentAgent();
  const { resource: profile, ready: profileReady } = useResourceSnapshot(
    agent?.subject,
  );
  const [icon] = useString(profile, dataBrowser.properties.icon);
  const [profileReviewed, setProfileReviewed] = useState(() =>
    profileReviewedBefore(agent?.subject),
  );
  const classLabel = useClassLabel(resource);
  const [title] = useTitle(resource);

  // Inviting shows who you are to the people you invite, so the first time
  // someone shares they get to check their name and picture.
  if (canWrite && agent?.subject && !icon && !profileReviewed) {
    if (!profileReady) return null;
    const agentSubject = agent.subject;

    return (
      <>
        <Dialog.Title>
          <ShareTitle>Share {title}</ShareTitle>
        </Dialog.Title>
        <Dialog.Content>
          <TeamProfileStep
            subject={agentSubject}
            onContinue={() => {
              rememberProfileReviewed(agentSubject);
              setProfileReviewed(true);
            }}
          />
        </Dialog.Content>
      </>
    );
  }

  return (
    <ShareOverview
      resource={resource}
      canWrite={canWrite}
      classLabel={classLabel}
      onDone={onDone}
    />
  );
}

function ShareOverview({
  resource,
  canWrite,
  classLabel,
  onDone,
}: {
  resource: Resource;
  canWrite: boolean;
  classLabel: string;
  onDone: () => void;
}): JSX.Element {
  const isSaas = !!getManagedPortalUrl();
  const isPrivateDrive = useIsPrivateDrive(resource.subject);
  const [agent] = useCurrentAgent();
  const [title] = useTitle(resource);
  const [rights, setRole] = useShareRights(resource);
  const inheritedRights = useInheritedRights(resource);
  const createInviteLink = useCreateInviteLink(resource);
  const editorSeats = useEditorSeats(resource);
  const agentDetail = useCurrentAgentDetail(agent?.subject, isSaas);
  const agentResource = useResource(agent?.subject);
  const [agentName] = useTitle(agentResource);

  const [emails, setEmails] = useState<string[]>([]);
  const [draft, setDraft] = useState('');
  const [emailRole, setEmailRole] = useState<ShareRole>('write');
  const [message, setMessage] = useState('');
  const [sending, setSending] = useState(false);
  const [err, setErr] = useState<Error>();

  const composing =
    isSaas && canWrite && (emails.length > 0 || draft.trim() !== '');

  const publicRight = rights.find(
    r => r.agentSubject === urls.instances.publicAgent,
  );
  const inheritedPublic = inheritedRights.find(
    r => r.agentSubject === urls.instances.publicAgent && (r.read || r.write),
  );

  const resetCompose = () => {
    setEmails([]);
    setDraft('');
    setMessage('');
    setErr(undefined);
  };

  const handleSend = async () => {
    const typed = draft.trim().toLowerCase();
    const recipients = typed ? [...emails, typed] : emails;
    const invalid = recipients.find(e => !isEmailAddress(e));

    if (invalid) {
      setErr(new Error(`${invalid} is not an email address.`));

      return;
    }

    if (recipients.length === 0) return;

    setSending(true);
    setErr(undefined);

    try {
      const link = await createInviteLink({ write: emailRole === 'write' });
      await sendShareInvites({
        emails: Array.from(new Set(recipients)),
        link,
        title,
        write: emailRole === 'write',
        inviterName: agentName,
        message: message.trim(),
      });
      toast.success(
        recipients.length === 1
          ? `Invite sent to ${recipients[0]}`
          : `Invite sent to ${recipients.length} people`,
      );
      resetCompose();
    } catch (e) {
      setErr(e as Error);
    }

    setSending(false);
  };

  return (
    <>
      <Dialog.Title>
        <ShareTitle>Share {title}</ShareTitle>
      </Dialog.Title>
      <Dialog.Content>
        <Stack>
          {isPrivateDrive && <PrivateDriveWarning />}
          {canWrite && isSaas && (
            <EmailInviteInput
              emails={emails}
              onEmailsChange={setEmails}
              draft={draft}
              onDraftChange={setDraft}
              role={emailRole}
              onRoleChange={setEmailRole}
              disabled={sending}
            />
          )}
          {canWrite && isSaas && editorSeats && (
            <SeatsNote>{describeEditorSeats(editorSeats)}</SeatsNote>
          )}
          {canWrite && !isSaas && (
            <InviteLinkField createInviteLink={createInviteLink} />
          )}
          {composing ? (
            <MessageField>
              <label htmlFor='share-invite-message'>
                <strong>Message</strong> <Optional>(optional)</Optional>
              </label>
              <textarea
                id='share-invite-message'
                rows={5}
                maxLength={2000}
                placeholder="Add a note for the people you're inviting"
                value={message}
                onChange={e => setMessage(e.target.value)}
                disabled={sending}
              />
            </MessageField>
          ) : (
            <>
              {/* Opening a profile closes the dialog behind it. */}
              <ResourceLinkNavigationContext.Provider value={onDone}>
                <PeopleWithAccess
                  rights={rights}
                  inheritedRights={inheritedRights}
                  currentAgent={agent?.subject}
                  currentRole={effectiveRole(
                    agent?.subject,
                    rights,
                    inheritedRights,
                    canWrite,
                  )}
                  currentAgentDetail={agentDetail}
                  onSetRole={canWrite ? setRole : undefined}
                />
              </ResourceLinkNavigationContext.Provider>
              <PublicAccess
                level={publicRight?.role ?? 'off'}
                inherited={
                  inheritedPublic && {
                    level: inheritedPublic.write ? 'write' : 'read',
                    setIn: inheritedPublic.setIn,
                  }
                }
                classLabel={classLabel}
                onChange={
                  canWrite
                    ? level =>
                        setRole(
                          urls.instances.publicAgent,
                          level === 'off' ? 'remove' : level,
                        )
                    : undefined
                }
              />
            </>
          )}
          {err && <ErrorLook>{err.message}</ErrorLook>}
        </Stack>
      </Dialog.Content>
      <Actions>
        {composing ? (
          <>
            <Button clean onClick={resetCompose} disabled={sending}>
              <CancelLabel>Cancel</CancelLabel>
            </Button>
            <Button
              onClick={handleSend}
              loading={sending ? 'Sending…' : undefined}
              data-test='share-send'
            >
              Send
            </Button>
          </>
        ) : (
          <>
            {canWrite && isSaas && (
              <CopyInviteLinkSplit createInviteLink={createInviteLink} />
            )}
            <Spacer />
            <Button onClick={onDone}>Done</Button>
          </>
        )}
      </Actions>
    </>
  );
}

type CreateInviteLink = ReturnType<typeof useCreateInviteLink>;

async function copyInviteLink(
  createInviteLink: CreateInviteLink,
  role: ShareRole,
  maxUsages?: number,
): Promise<string> {
  const link = await createInviteLink({ write: role === 'write', maxUsages });

  try {
    await navigator.clipboard.writeText(link);
    toast.success('Invite link copied');
  } catch {
    toast.error('Could not copy the link. Select it and copy it by hand.');
  }

  return link;
}

/** Hosted: a secondary way to invite, next to email. */
function CopyInviteLinkSplit({
  createInviteLink,
}: {
  createInviteLink: CreateInviteLink;
}): JSX.Element {
  const [role, setRole] = useState<ShareRole>('read');
  const [busy, setBusy] = useState(false);

  const handleCopy = async () => {
    setBusy(true);

    try {
      await copyInviteLink(createInviteLink, role);
    } catch (e) {
      toast.error((e as Error).message);
    }

    setBusy(false);
  };

  return (
    <Split>
      <SplitButton
        type='button'
        onClick={handleCopy}
        disabled={busy}
        aria-busy={busy}
      >
        Copy invite link
      </SplitButton>
      <RoleSwitch
        value={role}
        onChange={setRole}
        aria-label='Role for people who join with the link'
      />
    </Split>
  );
}

/**
 * Open source servers have no mail server, so the link is the invite. The
 * token is signed when it is first copied (and again when the role changes):
 * making one can link a local drive for peer sync, which opening the dialog
 * should not do on its own.
 */
function InviteLinkField({
  createInviteLink,
}: {
  createInviteLink: CreateInviteLink;
}): JSX.Element {
  const store = useStore();
  const [role, setRole] = useState<ShareRole>('write');
  const [limit, setLimit] = useState<UsageLimitState>(UNLIMITED);
  const [link, setLink] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<Error>();

  const handleCopy = async () => {
    setBusy(true);
    setErr(undefined);

    try {
      const maxUsages = parseMaxUsages(limit);
      setLink(await copyInviteLink(createInviteLink, role, maxUsages));
    } catch (e) {
      setErr(e as Error);
    }

    setBusy(false);
  };

  return (
    <>
      <LinkRow>
        <LinkBox>
          <LinkText
            data-test='invite-link'
            data-invite-link={link}
            $muted={!link}
            title={link}
          >
            {link ?? inviteLinkPrefix(store.getServerUrl())}
          </LinkText>
          <RoleSwitch
            value={role}
            onChange={r => {
              setRole(r);
              setLink(undefined);
            }}
            aria-label='Role for people who join with the link'
          />
        </LinkBox>
        <Button onClick={handleCopy} disabled={busy} data-test='copy-invite'>
          {busy ? 'Preparing invite…' : 'Copy invite link'}
        </Button>
      </LinkRow>
      <UsageLimitField
        limit={limit}
        onChange={next => {
          setLimit(next);
          setLink(undefined);
        }}
        disabled={busy}
      />
      {err && <ErrorLook>{err.message}</ErrorLook>}
    </>
  );
}

/**
 * What to show under your own name: your account email on hosted Atomic,
 * otherwise "Owner" when you can edit the drive this lives in.
 */
function useCurrentAgentDetail(
  agent: string | undefined,
  isSaas: boolean,
): string | undefined {
  const store = useStore();
  const drive = useResource(store.getDrive());
  const [driveWriters] = useArray(drive, core.properties.write);
  const [email, setEmail] = useState<string>();

  useEffect(() => {
    if (!isSaas) return;
    let cancelled = false;
    getManagedAccount()
      .then(
        account =>
          !cancelled && setEmail(account ? accountAddress(account) : undefined),
      )
      .catch(() => {
        /* The name alone is fine. */
      });

    return () => {
      cancelled = true;
    };
  }, [isSaas]);

  if (email) return email;
  if (agent && driveWriters.includes(agent)) return 'Owner';

  return undefined;
}

function PrivateDriveWarning(): JSX.Element {
  return (
    <PrivateDriveWarningBox role='alert'>
      <FaTriangleExclamation />
      <span>
        This is your <strong>private drive</strong>. Sharing it shares your
        drive list, favourites, notifications and AI chats along with it. To
        work with someone, make a drive for the work and share that instead.
      </span>
    </PrivateDriveWarningBox>
  );
}

/** Long names are cut off, not wrapped, so the close button keeps its place. */
const ShareTitle = styled.h1`
  margin: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const Stack = styled.div`
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
  padding-top: 0.25rem;
`;

/** On phones the invite link and Done go on two rows instead of squeezing. */
const Actions = styled(Dialog.Actions)`
  flex-wrap: wrap;
  row-gap: 0.75rem;

  button {
    white-space: nowrap;
  }
`;

const Spacer = styled.span`
  flex: 1;
`;

const CancelLabel = styled.span`
  padding: 0.5rem 1rem;
  color: ${p => p.theme.colors.text};
  font-weight: 600;
`;

const MessageField = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;

  textarea {
    width: 100%;
    resize: vertical;
    min-height: 8rem;
    padding: 0.75rem 1rem;
    border: 1px solid ${p => p.theme.colors.bg2};
    border-radius: ${p => p.theme.radius};
    background-color: ${p => p.theme.colors.bg};
    color: ${p => p.theme.colors.text};
    font: inherit;
    outline: none;

    &:focus {
      border-color: ${p => p.theme.colors.main};
      box-shadow: 0 0 0 1px ${p => p.theme.colors.main};
    }

    &::placeholder {
      color: ${p => p.theme.colors.textLight};
    }
  }
`;

const SeatsNote = styled.p`
  margin: 0;
  font-size: 0.9em;
  color: ${p => p.theme.colors.textLight};
`;

const Optional = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const Split = styled.div`
  display: inline-flex;
  align-items: center;
  gap: 0.75rem;
`;

const SplitButton = styled.button`
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg};
  color: ${p => p.theme.colors.text};
  font: inherit;
  padding: 0.5rem 1rem;
  cursor: pointer;

  &:hover:not(:disabled) {
    background: ${p => p.theme.colors.bg1};
  }

  &:disabled {
    cursor: progress;
    color: ${p => p.theme.colors.textLight};
  }
`;

const LinkRow = styled.div`
  display: flex;
  align-items: stretch;
  gap: 0.75rem;

  & > button {
    flex-shrink: 0;
  }

  @media (max-width: 500px) {
    flex-direction: column;
  }
`;

const LinkBox = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex: 1;
  min-width: 0;
  padding: 0.4rem 0.4rem 0.4rem 1rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
`;

const LinkText = styled.span<{ $muted: boolean }>`
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: ${p => (p.$muted ? p.theme.colors.textLight : p.theme.colors.text)};
  user-select: all;
`;

/**
 * Shown above the invite and the rights, not below them.
 *
 * By the time someone opens this dialog they have decided to share something;
 * a caution underneath the controls arrives after the decision. What makes it
 * work is naming what is actually in there — "private" alone reads as "not
 * shared yet", which is an invitation rather than a warning.
 */
const PrivateDriveWarningBox = styled.div`
  display: flex;
  align-items: flex-start;
  gap: 0.6rem;
  padding: 0.6rem 0.75rem;
  border: 1px solid ${p => p.theme.colors.alert};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg1};
  color: ${p => p.theme.colors.text};

  svg {
    color: ${p => p.theme.colors.alert};
    flex-shrink: 0;
    margin-top: 0.2rem;
  }
`;
