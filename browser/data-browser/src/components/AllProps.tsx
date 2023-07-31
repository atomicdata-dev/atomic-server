import { Resource } from '@tomic/react';
import React from 'react';
import styled, { css } from 'styled-components';
import PropVal from './PropVal';

type Props = {
  resource: Resource;
  /** A list of property subjects (URLs) that need not be rendered */
  except?: string[];
  /** If set to true, adds a button which opens up a form for each property */
  editable?: boolean;
  /**
   * Render the properties in the left column, and the Values in the right one,
   * but only on large screens.
   */
  columns?: boolean;
  basic?: boolean;
};

/** Lists all PropVals for some resource. Optionally ignores a bunch of subjects */
function AllProps({ resource, except = [], editable, columns, basic }: Props) {
  return (
    <AllPropsWrapper basic={basic}>
      {[...resource.getPropVals()]
        .filter(([prop]) => !except.includes(prop))
        .map(
          ([prop]): JSX.Element => (
            <StyledPropVal
              columns={columns}
              key={prop}
              basic={basic}
              propertyURL={prop}
              resource={resource}
              editable={!!editable}
            />
          ),
        )}
    </AllPropsWrapper>
  );
}

const AllPropsWrapper = styled.div<{ basic: boolean | undefined }>`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  border-radius: ${p => p.theme.radius};
  border: ${p => (p.basic ? 'none' : `1px solid ${p.theme.colors.bg2}`)};
`;

const StyledPropVal = styled(PropVal)<{ basic: boolean | undefined }>`
  ${p =>
    !p.basic &&
    css`
      padding: 0.5rem;
      &:nth-child(1) {
        border-top-left-radius: ${p.theme.radius};
        border-top-right-radius: ${p.theme.radius};
      }
      &:nth-child(odd) {
        background-color: ${p.theme.colors.bgBody};
      }
    `}
`;

export default AllProps;
