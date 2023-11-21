import { ButtonBar } from '../Button';
import { FaEllipsisV } from 'react-icons/fa';
import { DropdownTriggerRenderFunction } from '../Dropdown/DropdownTrigger';
import { shortcuts } from '../HotKeyWrapper';

export const MenuBarDropdownTrigger: DropdownTriggerRenderFunction = (
  { onClick, isActive, menuId },
  ref,
) => (
  <ButtonBar
    aria-controls={menuId}
    selected={isActive}
    ref={ref}
    title={`Open menu (${shortcuts.menu})`}
    type='button'
    data-test='context-menu'
    onClick={onClick}
    rightPadding
  >
    <FaEllipsisV />
  </ButtonBar>
);

MenuBarDropdownTrigger.displayName = 'MenuBarDropdownTrigger';
