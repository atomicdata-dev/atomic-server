import { styled } from 'styled-components';

import { FaGithub, FaDiscord, FaBook } from 'react-icons/fa';
import { IconButtonLink, IconButtonVariant } from '../IconButton/IconButton';
import { FaRadiation } from 'react-icons/fa6';
import { isDev } from '../../config';

interface AboutItem {
  icon: React.ReactNode;
  helper: string;
  href: string;
}

const aboutMenuItems: AboutItem[] = [
  {
    icon: <FaGithub />,
    helper: 'Github; View the source code for this application',
    href: 'https://github.com/atomicdata-dev/atomic-data-browser',
  },
  {
    icon: <FaDiscord />,
    helper: 'Discord; Chat with the Atomic Data community',
    href: 'https://discord.gg/a72Rv2P',
  },
  {
    icon: <FaBook />,
    helper: 'Docs; Read the Atomic Data documentation',
    href: 'https://docs.atomicdata.dev',
  },
];

export function About() {
  return (
    <>
      <AboutWrapper>
        {aboutMenuItems.map(({ href, icon, helper }) => (
          <IconButtonLink
            target='_blank'
            rel='noreferrer'
            key={href}
            href={href}
            title={helper}
            size='1.2em'
            color='textLight'
            variant={IconButtonVariant.Square}
          >
            {icon}
          </IconButtonLink>
        ))}
        {isDev() && (
          <IconButtonLink
            href='/sandbox'
            title='Sandbox, test components in isolation'
            size='1.2em'
            color='textLight'
            variant={IconButtonVariant.Square}
          >
            <FaRadiation />
          </IconButtonLink>
        )}
      </AboutWrapper>
    </>
  );
}

const AboutWrapper = styled.div`
  --inner-padding: 0.5rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-left: calc(1rem - var(--inner-padding));
`;
