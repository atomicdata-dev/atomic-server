import { useResource, useTitle } from '@tomic/react';
import { useState } from 'react';
import { FaEllipsisV, FaPlus } from 'react-icons/fa';
import { styled, css } from 'styled-components';
import { useNewRoute } from '../../../helpers/useNewRoute';
import { buildDefaultTrigger } from '../../Dropdown/DefaultTrigger';
import { IconButton } from '../../IconButton/IconButton';
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
  const parentResource = useResource(subject);
  const [parentName] = useTitle(parentResource);
  const [dropdownActive, setDropdownActive] = useState(false);

  const handleAddClick = useNewRoute(subject);

  return (
    <Wrapper className={className} dropdownActive={dropdownActive}>
      <IconButton
        data-test='add-subresource'
        onClick={handleAddClick}
        title={`Create new resource under ${parentName}`}
      >
        <FaPlus />
      </IconButton>
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
  visibility: ${p => (p.dropdownActive ? 'visible' : 'hidden')};
  font-size: 0.9rem;
  color: ${p => p.theme.colors.main};
`;

export const floatingHoverStyles = css`
  position: relative;

  &:hover ${Wrapper}, &:focus-within ${Wrapper} {
    visibility: visible;
  }
`;

const SideBarDropDownTrigger = buildDefaultTrigger(<FaEllipsisV />);
