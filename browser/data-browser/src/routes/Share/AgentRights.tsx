import { urls, useResource } from '@tomic/react';
import { FaGlobe } from 'react-icons/fa6';
import styled from 'styled-components';
import { CardRow } from '../../components/Card';
import { ResourceInline } from '../../views/ResourceInline';
import type { MergedRight } from './useRights';
import { PermissionRow } from './PermissionRow';

interface AgentRightsProps extends MergedRight {
  hideInherit?: boolean;
  handleSetRight?: (agent: string, write: boolean, setToTrue: boolean) => void;
}

export function AgentRights({
  handleSetRight,
  hideInherit,
  agentSubject,
  setIn,
  read,
  write,
}: AgentRightsProps): JSX.Element {
  const isPublicRight = agentSubject === urls.instances.publicAgent;
  const resource = useResource(agentSubject);
  const disabled = !resource.isReady() || !handleSetRight;

  return (
    <CardRow>
      <PermissionRow data-test={isPublicRight ? 'right-public' : null}>
        <PermissionRow.TitleColumn>
          {isPublicRight ? (
            <>
              <FaGlobe /> Public (anyone){' '}
            </>
          ) : (
            <TruncatedResourceTitle subject={agentSubject} />
          )}
          {!hideInherit && setIn && (
            <>
              {' (via '}
              <ResourceInline subject={setIn} />
              {') '}
            </>
          )}
        </PermissionRow.TitleColumn>
        <PermissionRow.ControlsColumn>
          <StyledCheckbox
            type='checkbox'
            disabled={disabled}
            onChange={e =>
              handleSetRight?.(agentSubject, false, e.target.checked)
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
              handleSetRight?.(agentSubject, true, e.target.checked)
            }
            checked={write}
            title={
              write
                ? 'Write access. Toggle to remove access.'
                : 'No write access. Toggle to give write access.'
            }
          />
        </PermissionRow.ControlsColumn>
      </PermissionRow>
    </CardRow>
  );
}

const StyledCheckbox = styled.input`
  width: 1rem;
  height: 1rem;
`;

const TruncatedResourceTitle = styled(ResourceInline)`
  text-overflow: ellipsis;
  white-space: nowrap;
`;
