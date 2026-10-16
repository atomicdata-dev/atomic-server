import { useArray, useResource, useTitle, core } from '@tomic/react';
import {
  SideBarMenuItemLink,
  SideBarMenuRow,
  SideBarMenuRowIcon,
  SideBarMenuRowLabel,
} from './SideBarMenuItem';
import { AgentAvatar } from '../Presence/AgentAvatar';
import { getIconForClass } from '../../helpers/iconMap';
import type { JSX } from 'react';

type SharedWithMeLinkProps = {
  subject: string;
  onClick?: () => void;
  'data-testid'?: string;
};

/** One shared resource: same row layout as {@link SideBarMenuRow} (icon + label). */
export function SharedWithMeLink({
  subject,
  onClick,
  'data-testid': dataTestId,
}: SharedWithMeLinkProps): JSX.Element {
  const resource = useResource(subject);
  const [isA] = useArray(resource, core.properties.isA);
  const Icon = getIconForClass(isA[0] ?? '');
  const isAgent = isA.includes(core.classes.agent);
  // Reactive title — `resource.title` doesn't subscribe to LocalChange
  // and goes stale when the shared resource is renamed.
  const [title] = useTitle(resource);
  const label = title || subject;
  const description = resource.get(core.properties.description) as
    | string
    | undefined;

  return (
    <SideBarMenuItemLink subject={subject} clean data-testid={dataTestId}>
      <SideBarMenuRow onClick={onClick} title={description}>
        <SideBarMenuRowIcon>
          {isAgent ? (
            <AgentAvatar agentSubject={subject} size='1.2rem' />
          ) : (
            <Icon />
          )}
        </SideBarMenuRowIcon>
        <SideBarMenuRowLabel>{label}</SideBarMenuRowLabel>
      </SideBarMenuRow>
    </SideBarMenuItemLink>
  );
}
