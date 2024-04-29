import { useResource, useTitle } from '@tomic/react';
import { complement, setLightness } from 'polished';

import { styled } from 'styled-components';
import { ResourceCellProps } from '../Type';
import { SimpleResourceLink } from './SimpleResourceLink';

export function AgentCell({ subject }: ResourceCellProps) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);

  return (
    <StyledLink resource={resource}>
      <span>@</span> {title}
    </StyledLink>
  );
}

const StyledLink = styled(SimpleResourceLink)`
  background-color: ${p => bg(p.theme.colors.main, p.theme.darkMode)};
  padding-inline: 8px;
  padding-block: 1px;
  border-radius: 40px;
  color: ${p => fg(p.theme.colors.main, p.theme.darkMode)};
  text-decoration: none;

  span {
    color: ${p => p.theme.colors.textLight};
  }

  :hover {
    box-shadow: 0px 0px 0px 1px
      ${p => fg(p.theme.colors.main, p.theme.darkMode)};
  }
`;

const lightColor = (base: string) => setLightness(0.92, complement(base));

const darkColor = (base: string) => setLightness(0.25, complement(base));

const fg = (base: string, darkMode: boolean) =>
  darkMode ? lightColor(base) : darkColor(base);

const bg = (base: string, darkMode: boolean) =>
  darkMode ? darkColor(base) : lightColor(base);
