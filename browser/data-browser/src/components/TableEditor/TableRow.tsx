import React, { forwardRef } from 'react';
import styled from 'styled-components';

type TableRowProps = React.PropsWithChildren<
  Omit<React.HTMLAttributes<HTMLDivElement>, 'children'>
>;

export const TableRow = forwardRef<HTMLDivElement, TableRowProps>(
  ({ children, ...props }, ref) => {
    return (
      <StyledDiv role='row' {...props} ref={ref}>
        {children}
      </StyledDiv>
    );
  },
);

TableRow.displayName = 'TableRow';

const StyledDiv = styled.div`
  display: grid;
  grid-template-columns: var(--table-template-columns);
  height: var(--table-row-height);

  & > div {
    border-bottom: 1px solid ${p => p.theme.colors.bg2};
    border-right: 1px solid ${p => p.theme.colors.bg2};

    &:last-child {
      border-right: none;
    }
  }

  &:last-child > div {
    border-bottom: none;
  }
`;
