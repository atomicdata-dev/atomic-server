// @wc-ignore-file
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { ThemeProvider, type DefaultTheme } from 'styled-components';
import { ActivityFeed, belongsToDrive } from './DriveHome';

const parents: Record<string, string> = {
  'did:ad:a-doc': 'did:ad:drive-a',
  'did:ad:b-doc': 'did:ad:drive-b',
  'did:ad:orphan-doc': 'did:ad:unloaded-folder',
};
const loaded = new Set([
  'did:ad:drive-a',
  'did:ad:drive-b',
  'did:ad:a-doc',
  'did:ad:b-doc',
  'did:ad:orphan-doc',
  'https://atomicdata.dev/properties/name',
]);
const store = {
  driveOfSubject: (s: string) => parents[s] ?? s,
  resources: { has: (s: string) => loaded.has(s) },
};
const recents: Record<string, string[]> = {
  'did:ad:drive-a': [
    'did:ad:b-doc',
    'https://atomicdata.dev/properties/name',
    'did:ad:orphan-doc',
  ],
  'did:ad:drive-b': ['did:ad:a-doc'],
};

vi.mock('@helpers/recentResources', () => ({
  getRecentResources: (d: string) => recents[d] ?? [],
}));
vi.mock('@tomic/react', () => ({
  dataBrowser: { classes: {} },
  isNotFound: () => false,
  isUnauthorized: () => false,
  useDrivePresence: () => [],
  useStore: () => store,
  useResources: (subjects: string[]) =>
    new Map(
      subjects.map(s => [
        s,
        {
          error: undefined,
          loading: false,
          getLoroDoc: () => undefined,
          getCreatedAt: () => 1_700_000_000_000,
        },
      ]),
    ),
}));
vi.mock('@views/ResourceRow', () => ({
  ResourceRow: ({ subject }: { subject: string }) => <i>{subject}</i>,
  ResourceRowDescription: ({ children }: { children: React.ReactNode }) => (
    <span>{children}</span>
  ),
}));
vi.mock('@components/Presence/PresenceAvatarMenu', () => ({
  PresenceAvatarMenu: () => null,
}));
vi.mock('@components/forms/NewForm/useNewResourceUI', () => ({
  useNewResourceUI: () => vi.fn(),
}));
vi.mock('@helpers/useNewRoute', () => ({ useNewRoute: () => vi.fn() }));
vi.mock('@components/Button', () => ({
  Button: ({ children }: { children: React.ReactNode }) => (
    <button>{children}</button>
  ),
}));
vi.mock('@components/Row', () => ({
  Row: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock('react-icons/fa6', async importOriginal => importOriginal());

const render = (drive: string, subjects: string[]) =>
  renderToStaticMarkup(
    <ThemeProvider theme={{ colors: {} } as unknown as DefaultTheme}>
      <ActivityFeed key={drive} drive={drive} subjects={subjects} />
    </ThemeProvider>,
  );

describe('belongsToDrive', () => {
  it('accepts the drive tree and unloaded chains, rejects loaded foreign roots', () => {
    expect(
      belongsToDrive(store as never, 'did:ad:a-doc', 'did:ad:drive-a'),
    ).toBe(true);
    expect(
      belongsToDrive(store as never, 'did:ad:b-doc', 'did:ad:drive-a'),
    ).toBe(false);
    expect(
      belongsToDrive(
        store as never,
        'https://atomicdata.dev/properties/name',
        'did:ad:drive-a',
      ),
    ).toBe(false);
    expect(
      belongsToDrive(store as never, 'did:ad:orphan-doc', 'did:ad:drive-a'),
    ).toBe(true);
  });
});

describe('ActivityFeed', () => {
  beforeEach(() => vi.clearAllMocks());

  it('lists only this drive, and changes when the drive prop changes', () => {
    const a = render('did:ad:drive-a', ['did:ad:a-doc']);

    expect(a).toContain('did:ad:a-doc');
    expect(a).toContain('did:ad:orphan-doc');
    expect(a).not.toContain('did:ad:b-doc');
    expect(a).not.toContain('properties/name');

    const b = render('did:ad:drive-b', ['did:ad:b-doc']);

    expect(b).toContain('did:ad:b-doc');
    expect(b).not.toContain('did:ad:a-doc');
    expect(b).not.toContain('did:ad:orphan-doc');
  });
});
