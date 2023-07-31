import React, { useRef } from 'react';
import styled from 'styled-components';
import { DropdownPortalContext } from './dropdownContext';

export const DropdownContainer: React.FC<React.PropsWithChildren<unknown>> = ({
  children,
}) => {
  const portalRef = useRef<HTMLDivElement>(null);

  return (
    <DropdownPortalContext.Provider value={portalRef}>
      {children}
      <DropdownContainerDiv ref={portalRef}></DropdownContainerDiv>
    </DropdownPortalContext.Provider>
  );
};

const DropdownContainerDiv = styled.div`
  display: contents;
`;
