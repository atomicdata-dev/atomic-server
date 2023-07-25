import React from 'react';
import { IconButton } from '../IconButton/IconButton';
import { DropdownTriggerRenderFunction } from './DropdownTrigger';

export const buildDefaultTrigger = (
  icon: React.ReactNode,
  title = 'Open menu',
  ButtonComp: typeof IconButton = IconButton,
): DropdownTriggerRenderFunction => {
  const Comp = ({ onClick, menuId }, ref: React.Ref<HTMLButtonElement>) => (
    <ButtonComp
      aria-controls={menuId}
      onClick={onClick}
      ref={ref}
      title={title}
    >
      {icon}
    </ButtonComp>
  );

  Comp.DisplayName = 'DefaultTrigger';

  return Comp;
};
