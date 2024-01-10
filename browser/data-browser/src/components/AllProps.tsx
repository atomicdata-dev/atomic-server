import { Resource } from '@tomic/react';

import { styled, css } from 'styled-components';
import PropVal from './PropVal';
import { ALL_PROPS_CONTAINER } from '../helpers/containers';

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
  const propvals = [...resource.getPropVals()].filter(
    ([prop]) => !except.includes(prop),
  );

  if (!propvals || propvals.length === 0) {
    return null;
  }

  return (
    <AllPropsWrapper basic={basic}>
      {propvals.map(
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
  container: ${ALL_PROPS_CONTAINER} / inline-size;

  display: flex;
  flex-direction: column;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => (p.basic ? 'transparent' : p.theme.colors.bg)};
  border: ${p => (p.basic ? 'none' : `1px solid ${p.theme.colors.bg2}`)};
`;

const StyledPropVal = styled(PropVal)<{ basic: boolean | undefined }>`
  ${p =>
    !p.basic &&
    css`
      padding: 0.5rem;
      border-top: solid 1px ${p.theme.colors.bg1};

      &:nth-child(1) {
        border-top-left-radius: ${p.theme.radius};
        border-top: none;
        border-top-right-radius: ${p.theme.radius};
      }
    `}
`;

export default AllProps;
