export interface DropdownTriggerProps {
  onClick: (event: React.MouseEvent) => void;
  menuId: string;
  isActive: boolean;
}

export type DropdownTriggerRenderFunction = React.ForwardRefRenderFunction<
  HTMLButtonElement,
  DropdownTriggerProps
>;
