import { urls, useString, useResource, useTitle } from '@tomic/react';
import { ResourceInline } from './ResourceInline/ResourceInline';
import { ErrorLook } from '../components/ErrorLook';
import { styled } from 'styled-components';
import { getIconForClass } from '../helpers/iconMap';
import { constructOpenURL } from '../helpers/navigation';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';

import type { JSX, MouseEvent, ReactNode } from 'react';

type Props = {
  subject: string;
  clickable?: boolean;
  className?: string;
  selected?: boolean;
  /** Make the title link a tab stop, so the row works from the keyboard. */
  tabbable?: boolean;
  /** Quiet content aligned to the right end of the row. */
  trailing?: ReactNode;
};

const RootDiv = styled.div<{ $clickable?: boolean }>`
  width: 100%;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: ${p => (p.$clickable ? 'pointer' : 'default')};
`;

/** Renders a Resource in a single row. Each row is clickable. Used in search preview and various cards showing multiple resources. */
function ResourceRow({
  subject,
  clickable,
  className,
  tabbable,
  trailing,
}: Props): JSX.Element {
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  let [description] = useString(resource, urls.properties.description);
  const navigate = useNavigateWithTransition();

  if (resource.loading) {
    return <span about={subject}>Loading...</span>;
  }

  if (resource.error) {
    return (
      <ErrorLook about={subject}>Error: {resource.error.message}</ErrorLook>
    );
  }

  const TRUNCATE_LENGTH = 40;

  if (description && description.length >= TRUNCATE_LENGTH) {
    description = description.slice(0, TRUNCATE_LENGTH) + '...';
  }

  const classes = resource.getClasses();
  const mainClass = classes[0];
  const ClassIcon = mainClass ? getIconForClass(mainClass) : null;

  const handleClick = (e: MouseEvent) => {
    // The title link navigates on its own.
    if (clickable && !(e.target as Element).closest('a')) {
      navigate(constructOpenURL(subject));
    }
  };

  return (
    <RootDiv
      about={subject}
      className={className}
      onClick={handleClick}
      $clickable={clickable}
    >
      {ClassIcon && (
        <IconWrapper>
          <ClassIcon />
        </IconWrapper>
      )}
      <Content>
        {clickable ? (
          <ResourceInline untabbable={!tabbable} subject={subject} basic />
        ) : (
          <b>{title}</b>
        )}
        <ResourceRowDescription>
          {description ? ` - ${description}` : null}
        </ResourceRowDescription>
      </Content>
      {trailing}
    </RootDiv>
  );
}

const Content = styled.div`
  flex: 1;
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const IconWrapper = styled.div`
  flex-shrink: 0;
  opacity: 0.5;
  font-size: 0.875em;
  display: flex;
  align-items: center;
`;

export const ResourceRowDescription = styled.span`
  color: ${p => p.theme.colors.textLight};
  white-space: nowrap;
`;

export { ResourceRow };

export default ResourceRow;
