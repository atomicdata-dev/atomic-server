import { createContext } from 'react';

export const DropdownPortalContext = createContext<
  React.RefObject<HTMLDivElement>
>(null!);
