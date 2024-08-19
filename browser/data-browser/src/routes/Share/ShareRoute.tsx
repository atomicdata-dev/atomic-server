import { useState } from 'react';
import { useCanWrite, useResource } from '@tomic/react';
import { ContainerNarrow } from '../../components/Containers';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { Card, CardInsideFull } from '../../components/Card';
import { Button } from '../../components/Button';
import { InviteForm } from '../../components/InviteForm';
import toast from 'react-hot-toast';
import { Title } from '../../components/Title';
import { constructOpenURL } from '../../helpers/navigation';
import { useNavigate } from 'react-router-dom';
import { ErrorLook } from '../../components/ErrorLook';
import { Column } from '../../components/Row';
import { Main } from '../../components/Main';
import { FaShare } from 'react-icons/fa6';
import { useRights } from './useRights';
import { AgentRights } from './AgentRights';
import { useInheritedRights } from './useInheritedRights';
import { PermissionRow } from './PermissionRow';
import styled from 'styled-components';

/** Form for managing and viewing rights for this resource */
export function ShareRoute(): JSX.Element {
  const [subject] = useCurrentSubject();
  const resource = useResource(subject);
  const [canWrite] = useCanWrite(resource);
  const [showInviteForm, setShowInviteForm] = useState(false);
  const [err, setErr] = useState<Error | undefined>(undefined);
  const navigate = useNavigate();
  const inheritedRights = useInheritedRights(resource);

  const [resourceRights, updateResourceRights] = useRights(resource, setErr);

  if (!subject) {
    return <>No subject passed</>;
  }

  async function handleSave() {
    try {
      await resource.save();
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
                Create Invite
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
              <Button
                disabled={!resource.hasUnsavedChanges()}
                onClick={handleSave}
              >
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
            Read more about permissions in the{' '}
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
