import React, { useEffect, useState } from 'react';
import {
  Right,
  urls,
  useArray,
  useCanWrite,
  useResource,
  useStore,
} from '@tomic/react';
import { ContainerNarrow } from '../components/Containers';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import { ResourceInline } from '../views/ResourceInline';
import { Card, CardInsideFull, CardRow } from '../components/Card';
import { FaGlobe } from 'react-icons/fa';
import { styled } from 'styled-components';
import { Button } from '../components/Button';
import { InviteForm } from '../components/InviteForm';
import toast from 'react-hot-toast';
import { Title } from '../components/Title';
import { constructOpenURL } from '../helpers/navigation';
import { useNavigate } from 'react-router-dom';
import { ErrorLook } from '../components/ErrorLook';
import { Column } from '../components/Row';
import { Main } from '../components/Main';

/** Form for managing and viewing rights for this resource */
export function ShareRoute(): JSX.Element {
  const [subject] = useCurrentSubject();
  const resource = useResource(subject);
  const store = useStore();
  const [canWrite] = useCanWrite(resource);
  const [showInviteForm, setShowInviteForm] = useState(false);
  const [err, setErr] = useState<Error | undefined>(undefined);
  const navigate = useNavigate();

  const useValueOpts = {
    commit: false,
    handleValidationError: setErr,
  };

  const [writers, setWriters] = useArray(
    resource,
    urls.properties.write,
    useValueOpts,
  );
  const [readers, setReaders] = useArray(
    resource,
    urls.properties.read,
    useValueOpts,
  );

  const [inheritedRights, setInheritedRights] = useState<Right[]>([]);

  useEffect(() => {
    async function getTheRights() {
      const allRights = await resource.getRights(store);
      const inherited = allRights.filter(r => r.setIn !== subject);

      // Make sure the public agent is always the top of the list
      const sorted = inherited.sort((a, _b) => {
        return a.for === urls.instances.publicAgent ? -1 : 1;
      });

      setInheritedRights(sorted);
    }

    getTheRights();
  }, [resource]);

  if (!subject) {
    return <>No subject passed</>;
  }

  function handleSetRight(agent: string, write: boolean, setToTrue: boolean) {
    let agents = write ? writers : readers;

    if (setToTrue) {
      // remove previous occurence
      agents = agents.filter(s => s !== agent);
      agents.push(agent);
    } else {
      agents = agents.filter(s => s !== agent);
    }

    if (write) {
      setWriters(agents);
    } else {
      setReaders(agents);
    }
  }

  function constructAgentProps(): AgentRight[] {
    const rightsMap: Map<string, RightBools> = new Map();

    // Always show the public agent
    rightsMap.set(urls.instances.publicAgent, { read: false, write: false });

    readers.map(agent => {
      rightsMap.set(agent, {
        read: true,
        write: false,
      });
    });

    writers.map(agent => {
      const old = rightsMap.get(agent);
      rightsMap.set(agent, {
        read: old ? old.read : false,
        write: true,
      });
    });

    const rights: AgentRight[] = [];

    rightsMap.forEach((right, agent) => {
      rights.push({
        agentSubject: agent,
        read: right.read,
        write: right.write,
      });
    });

    // Make sure the public agent is always the top of the list
    const sorted = rights.sort(a => {
      return a.agentSubject === urls.instances.publicAgent ? -1 : 1;
    });

    return sorted;
  }

  async function handleSave() {
    try {
      await resource.save(store);
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
          <Title resource={resource} prefix='Share settings' link />
          {canWrite && !showInviteForm && (
            <span>
              <Button onClick={() => setShowInviteForm(true)}>
                Send Invite...
              </Button>
            </span>
          )}
          {showInviteForm && <InviteForm target={resource} />}
          <Card>
            <RightsHeader text='rights set here:' />
            <CardInsideFull>
              {/* This key might be a bit too much, but the component wasn't properly re-rendering before */}
              {constructAgentProps().map(right => (
                <AgentRights
                  key={JSON.stringify(right)}
                  {...right}
                  handleSetRight={
                    canWrite && resource.isReady() ? handleSetRight : undefined
                  }
                />
              ))}
            </CardInsideFull>
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
              <RightsHeader text='inherited rights:' />
              <CardInsideFull>
                {inheritedRights.map(right => (
                  <AgentRights
                    inheritedFrom={right.setIn}
                    key={right.for + right.type}
                    read={right.type === 'read'}
                    write={right.type === 'write'}
                    agentSubject={right.for}
                  />
                ))}
              </CardInsideFull>
            </Card>
          )}
        </Column>
      </ContainerNarrow>
    </Main>
  );
}

interface RightBools {
  read: boolean;
  write: boolean;
}

interface AgentRight extends RightBools {
  agentSubject: string;
}

interface AgentRightsProps extends AgentRight {
  inheritedFrom?: string;
  handleSetRight?: (agent: string, write: boolean, setToTrue: boolean) => void;
}

function AgentRights({
  handleSetRight,
  agentSubject,
  inheritedFrom,
  read,
  write,
}: AgentRightsProps): JSX.Element {
  const isPublicRight = agentSubject === urls.instances.publicAgent;
  const resource = useResource(agentSubject);
  const disabled = !resource.isReady() || !handleSetRight;

  return (
    <CardRow>
      <div
        style={{ display: 'flex' }}
        data-test={isPublicRight ? 'right-public' : null}
      >
        <div style={{ flex: 1 }}>
          {isPublicRight ? (
            <>
              <FaGlobe /> Public (anyone){' '}
            </>
          ) : (
            <ResourceInline subject={agentSubject} />
          )}
          {inheritedFrom && (
            <>
              {' (via '}
              <ResourceInline subject={inheritedFrom} />
              {') '}
            </>
          )}
        </div>
        <div style={{ alignSelf: 'flex-end' }}>
          <StyledCheckbox
            type='checkbox'
            disabled={disabled}
            onChange={e =>
              handleSetRight &&
              handleSetRight(agentSubject, false, e.target.checked)
            }
            checked={read}
            title={
              read
                ? 'Read access. Toggle to remove access.'
                : 'No read access. Toggle to give read access.'
            }
          />
          <StyledCheckbox
            type='checkbox'
            disabled={disabled}
            onChange={e =>
              handleSetRight &&
              handleSetRight(agentSubject, true, e.target.checked)
            }
            checked={write}
            title={
              write
                ? 'Write access. Toggle to remove access.'
                : 'No write access. Toggle to give write access.'
            }
          />
        </div>
      </div>
    </CardRow>
  );
}

const StyledCheckbox = styled.input`
  width: 2rem;
`;

function RightsHeader({ text }: { text: string }): JSX.Element {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'row',
        flex: 1,
        marginBottom: '1rem',
      }}
    >
      <div style={{ flex: 1, fontWeight: 'bold' }}>{text}</div>
      <div style={{ alignSelf: 'flex-end', justifyContent: 'center' }}>
        <span>read </span>
        <span>write</span>
      </div>
    </div>
  );
}
