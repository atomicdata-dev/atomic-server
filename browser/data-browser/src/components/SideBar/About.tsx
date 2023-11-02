import { styled } from 'styled-components';
import React from 'react';
import { FaGithub, FaDiscord, FaBook } from 'react-icons/fa';
import { IconButtonLink, IconButtonVariant } from '../IconButton/IconButton';
import { useMediaQuery } from '../../hooks/useMediaQuery';
import { useSettings } from '../../helpers/AppSettings';
import { transition } from '../../helpers/transition';

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
  const narrow = useMediaQuery('(max-width: 920px)');
  const { navbarFloating } = useSettings();
  const elivate = narrow && navbarFloating;

  return (
    <>
      {/* <SideBarHeader>
        <Logo style={{ height: '1.1rem', maxWidth: '100%' }} />
      </SideBarHeader> */}
      <AboutWrapper $elivate={elivate}>
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
      </AboutWrapper>
    </>
  );
}

const AboutWrapper = styled.div<{ $elivate: boolean }>`
  --inner-padding: 0.5rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-left: calc(1rem - var(--inner-padding));
  padding-bottom: ${p => (p.$elivate ? '3.5rem' : '0rem')};
  ${transition('padding-bottom')}
`;
