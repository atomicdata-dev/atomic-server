import { styled } from 'styled-components';
import { AtomicLink, AtomicLinkProps } from '../AtomicLink';
import { SideBarItem } from './SideBarItem';
import { useLocation } from '@tanstack/react-router';

/** Full-width row; matches resource links in the tree (clean AtomicLink is inline by default). */
export const SideBarMenuItemLink = styled(AtomicLink)`
  display: block;
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
`;

/** Full-width menu / shared-with-me row (hover fills sidebar). */
export const SideBarMenuRow = styled(SideBarItem)`
  background-color: transparent;
  width: 100%;
  min-width: 0;
`;

export const SideBarMenuRowLabel = styled.span`
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  text-align: start;
`;

export interface SideBarMenuItemProps extends AtomicLinkProps {
  label: string;
  helper?: string;
  icon?: React.ReactNode;
  disabled?: boolean;
  /** Is called when clicking on the item. Used for closing the menu. */
  onClick?: () => void;
}

export function SideBarMenuItem({
  helper,
  label,
  icon,
  path,
  href,
  subject,
  onClick,
}: SideBarMenuItemProps) {
  const { pathname } = useLocation();
  const targetPath = path || href || subject;
  const current: boolean = pathname === targetPath;

  return (
    <SideBarMenuItemLink href={href} subject={subject} path={path} clean>
      <SideBarMenuRow
        key={label}
        title={helper}
        onClick={onClick}
        current={current}
      >
        {icon && <SideBarMenuRowIcon>{icon}</SideBarMenuRowIcon>}
        <SideBarMenuRowLabel>{label}</SideBarMenuRowLabel>
      </SideBarMenuRow>
    </SideBarMenuItemLink>
  );
}

/** Icon column for APP menu rows and Shared with me (matches tree LeadingSlot). */
export const SideBarMenuRowIcon = styled.span`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 1.5rem;
  margin-right: 0.4rem;

  svg {
    font-size: 0.8rem;
  }
`;
