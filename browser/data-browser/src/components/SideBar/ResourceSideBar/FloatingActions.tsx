import { useState } from 'react';
import { FaEllipsisVertical } from 'react-icons/fa6';
import { styled, css } from 'styled-components';
import { buildDefaultTrigger } from '../../Dropdown/DefaultTrigger';
import ResourceContextMenu from '../../ResourceContextMenu';

export interface FloatingActionsProps {
  subject: string;
  className?: string;
}

/** Contains actions for a SideBarResource, such as a context menu and a new item button */
export function FloatingActions({
  subject,
  className,
}: FloatingActionsProps): JSX.Element {
  const [dropdownActive, setDropdownActive] = useState(false);

  return (
    <Wrapper className={className} dropdownActive={dropdownActive}>
      <ResourceContextMenu
        simple
        subject={subject}
        trigger={SideBarDropDownTrigger}
        bindActive={setDropdownActive}
      />
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
