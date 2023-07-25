import React, { createContext } from 'react';

export const DialogPortalContext = createContext<
  React.RefObject<HTMLDivElement>
>(null!);

export const DialogTreeContext = createContext<boolean>(false);
