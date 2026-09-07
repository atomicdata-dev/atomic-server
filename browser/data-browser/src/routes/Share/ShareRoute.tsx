import { useEffect, useState, type JSX } from 'react';
import { core, ResourceEvents, useCanWrite, useResource } from '@tomic/react';
import { ContainerNarrow } from '../../components/Containers';
import { Card, CardInsideFull } from '../../components/Card';
import { Button } from '../../components/Button';
import { InviteForm } from '../../components/InviteForm';
import toast from 'react-hot-toast';
import { Title } from '../../components/Title';
import { constructOpenURL } from '../../helpers/navigation';
import { ErrorLook } from '../../components/ErrorLook';
import { Column } from '../../components/Row';
import { Main } from '../../components/Main';
import { FaShare } from 'react-icons/fa6';
import { useRights } from './useRights';
import { AgentRights } from './AgentRights';
import { useInheritedRights } from './useInheritedRights';
import { PermissionRow } from './PermissionRow';
import styled from 'styled-components';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { appRoute } from '../RootRoutes';
import { pathNames } from '../paths';
import { createRoute } from '@tanstack/react-router';

export interface ShareRouteSearchParams {
  subject: string;
}

export const ShareRoute = createRoute({
  path: pathNames.share,
  component: () => <SharePage />,
  getParentRoute: () => appRoute,
  validateSearch: search => ({
    subject: search.subject as string,
  }),
});

/** Form for managing and viewing rights for this resource */
function SharePage(): JSX.Element {
  const { subject } = ShareRoute.useSearch();
  const resource = useResource(subject);
  const canWrite = useCanWrite(resource);
  const [showInviteForm, setShowInviteForm] = useState(false);
  const [err, setErr] = useState<Error | undefined>(undefined);
  const navigate = useNavigateWithTransition();
  const inheritedRights = useInheritedRights(resource);

  const [resourceRights, updateResourceRights] = useRights(resource, setErr);

  // `useRights` mutates the resource locally with `commit: false`, so the Save
  // button's `resource.hasUnsavedChanges()` read would never re-evaluate
  // without a re-render trigger. Track the dirty state explicitly via the
  // LocalChange event for read/write.
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

  if (!subject) {
    return <>No subject passed</>;
  }

  async function handleSave() {
    try {
      await resource.save();
      setHasLocalChanges(false);
      toast.success('Share settings saved');
      navigate(constructOpenURL(subject!));
    } catch (e) {
      toast.error(e.message);
    }
  }

  return (
    <Main subject={subject}>
      <ContainerNarrow>
        <Column>
          <Title resource={resource} prefix='Permissions for' link />
          {canWrite && !showInviteForm && (
            <span>
              <Button onClick={() => setShowInviteForm(true)}>
                <FaShare />
                <span>Create Invite</span>
              </Button>
            </span>
          )}
          {showInviteForm && <InviteForm target={resource} />}
          <Card>
            <Column>
              <RightsHeader>Permissions set here:</RightsHeader>
              <CardInsideFull>
                {/* This key might be a bit too much, but the component wasn't properly re-rendering before */}
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
              </CardInsideFull>
            </Column>
          </Card>
          {canWrite && (
            <span>
              <Button disabled={!hasLocalChanges} onClick={handleSave}>
                Save
              </Button>
            </span>
          )}
          {err && <ErrorLook>{err.message}</ErrorLook>}
          {inheritedRights.length > 0 && (
            <Card>
              <Column>
                <RightsHeader>Inherited permissions:</RightsHeader>
                <CardInsideFull>
                  {inheritedRights.map(right => (
                    <AgentRights
                      setIn={right.setIn}
                      key={right.agentSubject + right.setIn}
                      read={right.read}
                      write={right.write}
                      agentSubject={right.agentSubject}
                    />
                  ))}
                </CardInsideFull>
              </Column>
            </Card>
          )}
          <p>
            <span>Read more about permissions in the</span>{' '}
            <a
              target='_blank'
              href='https://docs.atomicdata.dev/hierarchy'
              rel='noreferrer'
            >
              Atomic Data Docs
            </a>
          </p>
        </Column>
      </ContainerNarrow>
    </Main>
  );
}

function RightsHeader({ children }: React.PropsWithChildren): JSX.Element {
  return (
    <PermissionRow>
      <PermissionRowTitleHeader>{children}</PermissionRowTitleHeader>
      <PermissionRow.ControlsColumn>
        <span>Read</span>
        <span>Write</span>
      </PermissionRow.ControlsColumn>
    </PermissionRow>
  );
}

const PermissionRowTitleHeader = styled(PermissionRow.TitleColumn)`
  font-weight: bold;
`;
