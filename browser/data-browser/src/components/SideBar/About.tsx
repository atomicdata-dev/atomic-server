import { styled } from 'styled-components';
import { Logo } from '../Logo';
import { SideBarHeader } from './SideBarHeader';
import React from 'react';
import { FaGithub, FaDiscord, FaBook } from 'react-icons/fa';
import { IconButtonLink } from '../IconButton/IconButton';

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
      <SideBarHeader>
        <Logo style={{ height: '1.1rem', maxWidth: '100%' }} />
      </SideBarHeader>
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
          >
            {icon}
          </IconButtonLink>
        ))}
      </AboutWrapper>
    </>
  );
}

const AboutWrapper = styled.div`
  --inner-padding: 0.5rem;
  display: flex;
  /* flex-direction: column; */
  align-items: center;
  gap: 0.5rem;
  margin-left: calc(1rem - var(--inner-padding));
`;
