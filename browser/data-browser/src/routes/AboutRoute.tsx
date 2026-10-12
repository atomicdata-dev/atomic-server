import * as React from 'react';
import { styled } from 'styled-components';
import { FaGithub, FaDiscord, FaBook, FaGlobe } from 'react-icons/fa6';

import { createRoute } from '@tanstack/react-router';
import { ContainerNarrow } from '../components/Containers';
import { Main } from '../components/Main';
import { Logo } from '../components/Logo';
import { pathNames } from './paths';
import { appRoute } from './RootRoutes';

export const AboutRoute = createRoute({
  path: pathNames.about,
  component: () => <About />,
  getParentRoute: () => appRoute,
});

/**
 * Kept deliberately close to the feature table in the repo's README, which
 * carries a comment naming itself the source for every copy of this list, and
 * to the wording on atomic.place so the product reads the same everywhere.
 * When the README's table changes, change this too.
 */
const features: [title: string, description: string][] = [
  [
    'Local-first, no server required',
    'Create and edit with no server at all. Resources are addressed by did:ad identifiers and resolve peer-to-peer, so your identity is a keypair you hold rather than an account on someone else’s machine.',
  ],
  [
    'Encrypted at rest, per agent',
    'Each agent’s in-browser database is encrypted under a key wrapped by that agent’s own private key. Signing out leaves the cache in place but unreadable to the next session.',
  ],
  [
    'Passkey-backed recovery',
    'A passkey wraps the backup of your agent secret, so signing up hands you nothing to write down and a lost device does not have to mean a lost account.',
  ],
  [
    'Documents, tables, chat and files',
    'Write together in rich documents, organise structured work in typed tables, keep conversations next to the data they are about, and store the files alongside them.',
  ],
  [
    'Your own data models',
    'Shape Atomic around your own concepts with the built-in Ontology Editor. Atomic Schema gives the data shared meaning, so another app can read the same documents and tables instead of forcing an import/export round trip.',
  ],
  [
    'Signed, versioned history',
    'Every edit is a cryptographically signed commit, so you get a complete, tamper-evident history and time travel for free.',
  ],
  [
    'Real-time sync, and offline',
    'Keep working when the connection is gone. Changes merge conflict-free as CRDTs and sync instantly across tabs and devices over WebSockets when it comes back.',
  ],
  [
    'Fast, open and self-hostable',
    'Sub-millisecond median responses from a single self-contained binary with full-text search and the database built in. MIT licensed, with a REST API and libraries for JS, React, Svelte, Rust and Dart.',
  ],
];

const links: {
  icon: React.ReactNode;
  label: string;
  description: string;
  href: string;
}[] = [
  {
    icon: <FaBook />,
    label: 'Documentation',
    description: 'Concepts, guides and the full API reference.',
    href: 'https://docs.atomicdata.dev',
  },
  {
    icon: <FaGithub />,
    label: 'GitHub',
    description: 'Source code, issues and releases.',
    href: 'https://github.com/atomicdata-dev/atomic-server',
  },
  {
    icon: <FaDiscord />,
    label: 'Discord',
    description: 'Ask questions and chat with the community.',
    href: 'https://discord.gg/a72Rv2P',
  },
  {
    icon: <FaGlobe />,
    label: 'Site',
    description: 'atomic.place: hosted workspaces and pricing.',
    href: 'https://atomic.place',
  },
];

const buildDate = (() => {
  try {
    return new Date(__BUILD_TIME__).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return __BUILD_TIME__;
  }
})();

export const About: React.FunctionComponent = () => {
  return (
    <Main>
      <ContainerNarrow>
        <Logo
          style={{ width: '22rem', maxWidth: '100%', marginBottom: '1.5rem' }}
        />
        <Tagline>The one workspace for everything, owned by you.</Tagline>
        <Intro>
          Documents, tables, files, chat and custom apps in one place.
          AtomicServer starts on your device, and can run with no server at all.
          It adds backup, sharing and always-on availability when you want them.
          Everything you make is Atomic Data: typed, linked and portable, so it
          stays readable by other apps and by you.
        </Intro>

        <h2>Features</h2>
        <FeatureList>
          {features.map(([title, description]) => (
            <Feature key={title}>
              <strong>{title}</strong>
              <span>{description}</span>
            </Feature>
          ))}
        </FeatureList>

        <h2>Learn more &amp; get involved</h2>
        <LinkGrid>
          {links.map(({ icon, label, description, href }) => (
            <LinkCard key={href} href={href} target='_blank' rel='noreferrer'>
              <LinkIcon>{icon}</LinkIcon>
              <LinkText>
                <LinkLabel>{label}</LinkLabel>
                <LinkDescription>{description}</LinkDescription>
              </LinkText>
            </LinkCard>
          ))}
        </LinkGrid>

        <BuildInfo>
          <span>Atomic&nbsp;Data&nbsp;Browser</span>
          <Mono title='Version'>v{__APP_VERSION__}</Mono>
          <Mono title='Build commit'>{__GIT_COMMIT__}</Mono>
          <span title={__BUILD_TIME__}>built {buildDate}</span>
        </BuildInfo>
      </ContainerNarrow>
    </Main>
  );
};

const Tagline = styled.p`
  font-size: 1.3rem;
  font-style: italic;
  color: ${p => p.theme.colors.textLight};
  margin-bottom: 0.5rem;
`;

const Intro = styled.p`
  font-size: 1.05rem;
  margin-bottom: 2rem;
`;

const FeatureList = styled.ul`
  list-style: none;
  padding: 0;
  margin: 0 0 2rem 0;
  display: grid;
  gap: 0.75rem;
`;

const Feature = styled.li`
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
  padding-inline-start: 1rem;
  border-inline-start: 3px solid ${p => p.theme.colors.main};

  strong {
    color: ${p => p.theme.colors.text};
  }

  span {
    color: ${p => p.theme.colors.textLight};
  }
`;

const LinkGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr));
  gap: 1rem;
  margin-bottom: 3rem;
`;

const LinkCard = styled.a`
  display: flex;
  align-items: center;
  gap: 0.85rem;
  padding: 1rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg};
  color: ${p => p.theme.colors.text};
  text-decoration: none;
  transition:
    border-color 0.1s ease,
    transform 0.1s ease;

  &:hover,
  &:focus-visible {
    border-color: ${p => p.theme.colors.main};
    transform: translateY(-2px);
  }
`;

const LinkIcon = styled.span`
  font-size: 1.6rem;
  color: ${p => p.theme.colors.main};
  display: flex;
`;

const LinkText = styled.div`
  display: flex;
  flex-direction: column;
`;

const LinkLabel = styled.span`
  font-weight: bold;
`;

const LinkDescription = styled.span`
  font-size: 0.9rem;
  color: ${p => p.theme.colors.textLight};
`;

const BuildInfo = styled.footer`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem 0.75rem;
  padding-top: 1.5rem;
  border-top: 1px solid ${p => p.theme.colors.bg2};
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;
`;

const Mono = styled.code`
  background-color: ${p => p.theme.colors.bg1};
  border-radius: ${p => p.theme.radius};
  padding: 0.1rem 0.4rem;
`;
