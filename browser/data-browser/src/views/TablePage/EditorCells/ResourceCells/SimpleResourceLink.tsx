import { Resource } from '@tomic/react';
import React, { useMemo } from 'react';
import { constructOpenURL } from '../../../../helpers/navigation';
import { useNavigateWithTransition } from '../../../../hooks/useNavigateWithTransition';
import { styled } from 'styled-components';

export type SimpleResourceLinkProps = {
  resource: Resource;
} & Omit<React.HTMLAttributes<HTMLAnchorElement>, 'children' | 'resource'>;

export function SimpleResourceLink({
  resource,
  children,
  ...props
}: React.PropsWithChildren<SimpleResourceLinkProps>): JSX.Element {
  const navigate = useNavigateWithTransition();

  const url = useMemo(() => {
    try {
      return constructOpenURL(resource.getSubject());
    } catch (e) {
      return '#';
    }
  }, [resource]);

  const handleClick = (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    // @ts-ignore
    navigate(url);
  };

  try {
    return (
      <StyledAnchor href={url} onClick={handleClick} {...props}>
        {children}
      </StyledAnchor>
    );
  } catch (e) {
    return <>{resource.getSubject()}</>;
  }
}

const StyledAnchor = styled.a`
  text-decoration: none;

  &:hover,
  &:focus-visible {
    text-decoration: underline;
  }
`;
