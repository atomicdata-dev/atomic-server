import type { ReactNode } from 'react';
import { styled } from 'styled-components';
import { useSettings } from '../../helpers/AppSettings';
import { AtomicLink } from '../AtomicLink';
import { SideBarItem } from './SideBarItem';

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

/** Icon column for sidebar menu rows (account, Shared with me) (matches tree LeadingSlot). */
const IconSlot = styled.span`
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

/**
 * The icon column of a menu row. With "Show icons in the sidebar" off it is
 * not rendered at all, so the label starts at the row's own padding.
 */
export function SideBarMenuRowIcon({
  children,
}: {
  children: ReactNode;
}): React.JSX.Element | null {
  const { showSidebarIcons } = useSettings();

  return showSidebarIcons ? <IconSlot>{children}</IconSlot> : null;
}
