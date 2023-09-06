import React from 'react';
import { styled } from 'styled-components';
import { AtomicLink, AtomicLinkProps } from '../AtomicLink';
import { SideBarItem } from './SideBarItem';

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
  return (
    <AtomicLink href={href} subject={subject} path={path} clean>
      <SideBarItem key={label} title={helper} onClick={onClick}>
        {icon && <SideBarIcon>{icon}</SideBarIcon>}
        {label}
      </SideBarItem>
    </AtomicLink>
  );
}

const SideBarIcon = styled.span`
  display: flex;
  margin-right: 0.5rem;
  font-size: 1.5rem;
`;
