import { ResourceEvents, type Resource } from '@tomic/react';
import { useEffect, useState } from 'react';
import styled from 'styled-components';

interface UnsavedIndicatorProps {
  resource: Resource;
}

export const UnsavedIndicator: React.FC<UnsavedIndicatorProps> = ({
  resource,
}) => {
  const [hasChanges, setHasChanges] = useState(resource.hasUnsavedChanges());

  useEffect(() => {
    setHasChanges(resource.hasUnsavedChanges());

    return resource.on(ResourceEvents.LocalChange, () => {
      setHasChanges(resource.hasUnsavedChanges());
    });
  }, [resource]);

  if (!hasChanges) {
    return null;
  }

  return <Indicator>*</Indicator>;
};

const Indicator = styled.span`
  color: ${p => p.theme.colors.warning};
`;
