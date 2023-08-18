import React, { useRef } from 'react';
import { styled } from 'styled-components';
import { DialogPortalContext } from './dialogContext';

export const DialogContainer: React.FC<React.PropsWithChildren<unknown>> = ({
  children,
}) => {
  const portalRef = useRef<HTMLDivElement>(null);

  return (
    <DialogPortalContext.Provider value={portalRef}>
      {children}
      <StyledDiv ref={portalRef}></StyledDiv>
    </DialogPortalContext.Provider>
  );
};

const StyledDiv = styled.div`
  display: contents;
`;
