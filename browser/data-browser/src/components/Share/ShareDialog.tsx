import React, {
  cloneElement,
  isValidElement,
  useEffect,
  useState,
  type JSX,
} from 'react';
import {
  core,
  ResourceEvents,
  useCanWrite,
  useResource,
  useStore,
} from '@tomic/react';

import { Dialog, useDialog } from '../Dialog';
import { Button } from '../Button';
import { InviteForm } from '../InviteForm';
import toast from 'react-hot-toast';
import { Title } from '../Title';
import { FaTriangleExclamation } from 'react-icons/fa6';
import { useIsPrivateDrive } from '@hooks/useIsPrivateDrive';
import { ErrorLook } from '../ErrorLook';
import { Column, Row } from '../Row';
import {
  FaArrowLeft,
  FaChevronDown,
  FaChevronRight,
  FaLink,
  FaShare,
} from 'react-icons/fa6';
import { useRights } from '../../routes/Share/useRights';
import { AgentRights } from '../../routes/Share/AgentRights';
import { useInheritedRights } from '../../routes/Share/useInheritedRights';
import { PermissionRow } from '../../routes/Share/PermissionRow';
import styled from 'styled-components';

export interface ShareDialogProps {
  subject: string;
  trigger: JSX.Element;
}

/** Dialog for managing and viewing rights for a resource */
export function ShareDialog({
  subject,
  trigger,
}: ShareDialogProps): JSX.Element {
  const [dialogProps, show, , isOpen] = useDialog();
  const resource = useResource(subject);
  const canWrite = useCanWrite(resource);
  const isPrivateDrive = useIsPrivateDrive(subject);
  const [err, setErr] = useState<Error | undefined>(undefined);
  const inheritedRights = useInheritedRights(resource);
  const [resourceRights, updateResourceRights] = useRights(resource, setErr);

  // Track `hasUnsavedChanges` locally. `useResource`'s `track` option also
  // triggers re-renders on LocalChange, but every render creates a fresh
  // proxy that tears down the listener and the subscriber-store can trample
  // the dirty state. Keeping a dedicated flag here is simpler and resilient.
  const [hasLocalChanges, setHasLocalChanges] = useState(false);

  useEffect(() => {
    setHasLocalChanges(resource.hasUnsavedChanges());
    const stable = resource.stable;

    return stable.on(ResourceEvents.LocalChange, prop => {
      if (prop === core.properties.read || prop === core.properties.write) {
        setHasLocalChanges(stable.hasUnsavedChanges());
      }
    });
  }, [resource.stable]);
  const [showInherited, setShowInherited] = useState(false);
  const [view, setView] = useState<'share' | 'invite'>('share');

  const handleSave = async () => {
    try {
      await resource.save();
      setHasLocalChanges(false);
      toast.success('Share settings saved');
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const handleTriggerClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    setView('share');
    show();
  };

  const triggerEl = trigger as React.ReactElement<{
    onClick?: (e: React.MouseEvent) => void;
  }>;
  const triggerWithOpen = isValidElement(trigger)
    ? cloneElement(triggerEl, {
        onClick: (e: React.MouseEvent) => {
          triggerEl.props.onClick?.(e);
          handleTriggerClick(e);
        },
      })
    : trigger;

  return (
    <>
      {triggerWithOpen}
      <Dialog {...dialogProps} width='500px'>
        {isOpen && view === 'share' && (
          <>
            <Dialog.Title>
              <Title resource={resource} prefix='Share' />
            </Dialog.Title>
            <Dialog.Content>
              <Column gap='1rem'>
                {isPrivateDrive && (
                  <PrivateDriveWarning role='alert'>
                    <FaTriangleExclamation />
                    <span>
                      This is your <strong>private drive</strong>. Sharing it
                      shares your drive list, favourites, notifications and AI
                      chats along with it. To work with someone, make a drive
                      for the work and share that instead.
                    </span>
                  </PrivateDriveWarning>
                )}
                <Row>
                  <CopyLinkButton subject={subject} />
                  {canWrite && (
                    <Button onClick={() => setView('invite')}>
                      <FaShare />
                      <span>Create Invite</span>
                    </Button>
                  )}
                </Row>
                <RightsCard>
                  <Column>
                    <RightsHeader>Permissions set here:</RightsHeader>
                    {resourceRights.map(right => (
                      <AgentRights
                        hideInherit
                        key={JSON.stringify(right)}
                        {...right}
                        handleSetRight={
                          canWrite && resource.isReady()
                            ? updateResourceRights
                            : undefined
                        }
                      />
                    ))}
                  </Column>
                </RightsCard>
                {canWrite && (
                  <Button disabled={!hasLocalChanges} onClick={handleSave}>
                    Save
                  </Button>
                )}
                {err && <ErrorLook>{err.message}</ErrorLook>}
                {inheritedRights.length > 0 && (
                  <>
                    <InheritedToggle
                      onClick={() => setShowInherited(!showInherited)}
                    >
                      {showInherited ? <FaChevronDown /> : <FaChevronRight />}
                      <span>Inherited permissions</span>
                    </InheritedToggle>
                    {showInherited && (
                      <RightsCard>
                        <Column>
                          {inheritedRights.map(right => (
                            <AgentRights
                              setIn={right.setIn}
                              key={right.agentSubject + right.setIn}
                              read={right.read}
                              write={right.write}
                              agentSubject={right.agentSubject}
                            />
                          ))}
                        </Column>
                      </RightsCard>
                    )}
                  </>
                )}
              </Column>
            </Dialog.Content>
          </>
        )}
        {isOpen && view === 'invite' && (
          <>
            <Dialog.Title>
              <BackButton onClick={() => setView('share')}>
                <FaArrowLeft /> <span>Back</span>
              </BackButton>
              <span>Create Invite</span>
            </Dialog.Title>
            <Dialog.Content>
              <InviteForm target={resource} />
            </Dialog.Content>
          </>
        )}
      </Dialog>
    </>
  );
}

const BackButton = styled.button`
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  background: none;
  border: none;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;
  font-size: 0.85rem;
  padding: 0;
  margin-right: 0.5rem;

  &:hover {
    color: ${p => p.theme.colors.text};
  }
`;

const RightsCard = styled.div`
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  overflow: hidden;
`;

const InheritedToggle = styled.button`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  background: none;
  border: none;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;
  font-size: 0.9rem;
  padding: 0;

  &:hover {
    color: ${p => p.theme.colors.text};
  }

  svg {
    font-size: 0.7rem;
  }
`;

function CopyLinkButton({ subject }: { subject: string }): JSX.Element {
  const store = useStore();

  const handleCopy = () => {
    let link: string;

    if (subject.startsWith('did:')) {
      const server = store.getServerUrl().replace(/\/$/, '');
      link = `${server}/${subject}`;
    } else {
      link = subject;
    }

    navigator.clipboard.writeText(link);
    toast.success('Link copied to clipboard');
  };

  return (
    <Button subtle onClick={handleCopy}>
      <FaLink />
      <span>Copy link</span>
    </Button>
  );
}

const RightsHeaderRow = styled.div`
  padding: 0.4rem ${p => p.theme.size()};
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
`;

function RightsHeader({ children }: React.PropsWithChildren): JSX.Element {
  return (
    <RightsHeaderRow>
      <PermissionRow>
        <PermissionRow.TitleColumn>{children}</PermissionRow.TitleColumn>
        <PermissionRow.ControlsColumn>
          <span>Read</span>
          <span>Write</span>
        </PermissionRow.ControlsColumn>
      </PermissionRow>
    </RightsHeaderRow>
  );
}

/**
 * Shown above the rights, not below them.
 *
 * By the time someone opens this dialog they have decided to share something;
 * a caution underneath the controls arrives after the decision. What makes it
 * work is naming what is actually in there — "private" alone reads as "not
 * shared yet", which is an invitation rather than a warning.
 */
const PrivateDriveWarning = styled.div`
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
