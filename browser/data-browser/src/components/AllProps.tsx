import { Resource } from '@tomic/react';
import React from 'react';
import styled from 'styled-components';
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
};

const AllPropsWrapper = styled.div`
  margin-bottom: ${props => props.theme.margin}rem;
`;

/** Lists all PropVals for some resource. Optionally ignores a bunch of subjects */
function AllProps({ resource, except = [], editable, columns }: Props) {
  return (
    <AllPropsWrapper>
      {[...resource.getPropVals()].map(
        // This is a place where you might want to use the _val, because of performance. However, we currently don't, because of the form renderer.
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        ([prop, _val]): JSX.Element => {
          if (except.includes(prop)) {
            return <></>;
          }

          return (
            <PropVal
              columns={columns}
              key={prop}
              propertyURL={prop}
              resource={resource}
              editable={!!editable}
            />
          );
        },
      )}
    </AllPropsWrapper>
  );
}

export default AllProps;
