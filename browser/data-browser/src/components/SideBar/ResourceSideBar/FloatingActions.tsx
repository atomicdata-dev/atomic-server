import { useState, type JSX } from 'react';
import { FaEllipsisVertical } from 'react-icons/fa6';
import { styled, css } from 'styled-components';
import { buildDefaultTrigger } from '../../Dropdown/DefaultTrigger';
import { ResourceContextMenu } from '../../ResourceContextMenu';

export interface FloatingActionsProps {
  subject: string;
  className?: string;
  /** The menu mounts once the row was hovered or focused. */
  armed: boolean;
}

/** Contains actions for a SideBarResource, such as a context menu and a new item button */
export function FloatingActions({
  subject,
  className,
  armed,
}: FloatingActionsProps): JSX.Element {
  const [dropdownActive, setDropdownActive] = useState(false);

  return (
    <Wrapper className={className} dropdownActive={dropdownActive}>
      {armed && (
        <ResourceContextMenu
          simple
          subject={subject}
          trigger={SideBarDropDownTrigger}
          bindActive={setDropdownActive}
        />
      )}
    </Wrapper>
  );
}

const Wrapper = styled.span<{ dropdownActive: boolean }>`
  visibility: hidden;
  font-size: 0.9rem;
  color: ${p => p.theme.colors.main};

  @media (pointer: fine) {
    visibility: ${p => (p.dropdownActive ? 'visible' : 'hidden')};
  }
`;

export const floatingHoverStyles = css`
  position: relative;

  &:hover ${Wrapper}, &:focus-within ${Wrapper} {
    @media (pointer: fine) {
      visibility: visible;
    }
  }
`;

const SideBarDropDownTrigger = buildDefaultTrigger(<FaEllipsisVertical />);
