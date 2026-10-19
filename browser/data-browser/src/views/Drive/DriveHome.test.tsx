// @wc-ignore-file
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { ThemeProvider, type DefaultTheme } from 'styled-components';
import { canonicalizeScheme } from '@tomic/lib';
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

let commentTimes = new Map<string, { at: number; by?: string }>();
let editors: Record<string, string> = {};
vi.mock('@hooks/useLastEditor', () => ({
  useLastEditor: (subject: string, _at: number, enabled: boolean) =>
    enabled ? editors[subject] : undefined,
}));
vi.mock('@components/RightPanel/RightPanelContext', () => ({
  useRightPanel: () => ({ setPanelOpen: () => {} }),
}));
vi.mock('@components/Presence/AgentAvatar', () => ({
  AgentAvatar: ({ agentSubject }: { agentSubject: string }) => (
    <span data-avatar={agentSubject} />
  ),
}));
vi.mock('@hooks/useRecentComments', () => ({
  useRecentComments: () => commentTimes,
}));
vi.mock('@hooks/useVisibleDriveChildren', () => ({
  useHiddenDriveSubjects: () => new Set(['atomic:hidden-doc']),
}));
vi.mock('@helpers/recentResources', () => ({
  getRecentResources: (d: string) => recents[d] ?? [],
}));
vi.mock('@tomic/react', () => ({
  dataBrowser: { classes: {}, properties: {} },
  isNotFound: () => false,
  isUnauthorized: () => false,
  useDrivePresence: () => [],
  useResource: (s: string) => ({ subject: s }),
  useTitle: (r: { subject: string }) => [
    r.subject === 'did:ad:agent:me' ? 'Joep Meindertsma' : '',
  ],
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
          getClasses: () => [],
          get: () => undefined,
        },
      ]),
    ),
}));
vi.mock('@views/ResourceRow', () => ({
  ResourceRow: ({
    subject,
    trailing,
  }: {
    subject: string;
    trailing?: React.ReactNode;
  }) => (
    <i>
      {subject}
      {trailing}
    </i>
  ),
  ResourceRowDescription: ({
    children,
    title,
  }: {
    children: React.ReactNode;
    title?: string;
  }) => <span title={title}>{children}</span>,
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

describe('belongsToDrive scheme spellings', () => {
  it('treats atomic: and did:ad: spellings of one drive as equal', () => {
    const spelled = {
      driveOfSubject: (s: string) =>
        s === 'atomic:a-doc' ? 'atomic:drive-a' : s,
      resources: { has: () => true },
    };

    expect(
      belongsToDrive(spelled as never, 'atomic:a-doc', 'did:ad:drive-a'),
    ).toBe(true);
    expect(
      belongsToDrive(spelled as never, 'atomic:a-doc', 'did:ad:drive-b'),
    ).toBe(false);
  });
});

describe('ActivityFeed', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    commentTimes = new Map();
    editors = {};
  });

  it('adds a resource that was only commented on, as Commented', () => {
    parents['atomic:only-comment'] = 'did:ad:drive-a';
    parents['atomic:hidden-doc'] = 'did:ad:drive-a';
    loaded.add('atomic:only-comment');
    loaded.add('atomic:hidden-doc');
    commentTimes = new Map([
      [
        canonicalizeScheme('did:ad:only-comment'),
        { at: Date.now() - 60_000, by: 'did:ad:agent:me' },
      ],
      [canonicalizeScheme('did:ad:hidden-doc'), { at: Date.now() - 60_000 }],
    ]);

    const html = render('did:ad:drive-a', ['did:ad:a-doc']);

    expect(html).toContain('atomic:only-comment');
    expect(html).toContain('Commented');
    expect(html).toContain('>1m ago<');
    expect(html).toContain('data-avatar="did:ad:agent:me"');
    expect(html).not.toContain('hidden-doc');
  });

  it('shows the editor of an edited row, with a name', () => {
    editors['did:ad:a-doc'] = 'did:ad:agent:me';

    const html = render('did:ad:drive-a', ['did:ad:a-doc']);

    expect(html).toContain('data-avatar="did:ad:agent:me"');
    expect(html).toContain('Joep Meindertsma');
  });

  it('shows no Commented caption without comments', () => {
    expect(render('did:ad:drive-a', ['did:ad:a-doc'])).not.toContain(
      'Commented',
    );
  });

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
