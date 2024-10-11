import { useProperty, truncateUrl, Resource } from '@tomic/react';

import { styled } from 'styled-components';
import { AtomicLink } from './AtomicLink';
import { ErrorLook } from './ErrorLook';
import { ValueForm } from './forms/ValueForm';
import ValueComp from './ValueComp';
import { ALL_PROPS_CONTAINER } from '../helpers/containers';
import { LoaderInline } from './Loader';

type Props = {
  propertyURL: string;
  resource: Resource;
  editable: boolean;
  // If set to true, will render the properties in a left column, and the Values in the right one, but only on large screens.
  columns?: boolean;
  className?: string;
};

/**
 * A single Property / Value renderer that shows a label on the left, and the
 * value on the right. The value is editable.
 */
function PropVal({
  propertyURL,
  resource,
  editable,
  columns,
  className,
}: Props): JSX.Element {
  const property = useProperty(propertyURL);
  const truncated = truncateUrl(propertyURL, 10, true);

  if (property.loading) {
    return (
      <PropValRow columns={columns}>
        <StyledLoader title={`Loading ${truncated}`} />
      </PropValRow>
    );
  }

  if (property.error) {
    return (
      <PropValRow columns={columns}>
        <PropertyLabel title={propertyURL + ' could not be loaded'}>
          <AtomicLink subject={propertyURL}>
            <ErrorLook>{truncated}</ErrorLook>
          </AtomicLink>
        </PropertyLabel>
        <code>{JSON.stringify(resource.get(propertyURL))}</code>
      </PropValRow>
    );
  }

  return (
    <PropValRow columns={columns} className={className}>
      <AtomicLink subject={propertyURL}>
        <PropertyLabel title={property.description}>
          {property.shortname || truncated}
        </PropertyLabel>
      </AtomicLink>
      {editable ? (
        <ValueForm resource={resource} propertyURL={propertyURL} />
      ) : (
        <ValueComp
          datatype={property.datatype}
          value={resource.get(propertyURL)}
        />
      )}
    </PropValRow>
  );
}

export default PropVal;

export const PropValRow = styled.div<PropValRowProps>`
  word-break: break-word;
  display: grid;
  grid-template-columns: 1fr;
  grid-template-rows: auto 1fr;

  @container ${ALL_PROPS_CONTAINER} (min-width: 500px) {
    grid-template-columns: 23ch auto;
    grid-template-rows: 1fr;
  }
`;

export const PropertyLabel = styled.span`
  font-weight: bold;
`;

const StyledLoader = styled(LoaderInline)`
  grid-column: 1 / 3;
  margin-inline: 1rem;
  margin-block: 0.5rem;
  width: calc(100% - 2rem);
`;

interface PropValRowProps {
  columns?: boolean;
}
