// @vitest-environment jsdom
// @wc-ignore-file
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ThemeProvider } from 'styled-components';
import {
  mergeHistoryAttributions,
  type HistoryAttribution,
  type Version,
} from '@tomic/react';
import { buildTheme } from '../../styling';
import { VersionTitle } from './VersionTitle';

vi.mock('../../views/ResourceInline/ResourceInline', () => ({
  ResourceInline: ({ subject }: { subject: string }) => <span>{subject}</span>,
}));
afterEach(cleanup);

const version: Version = {
  token: 'first-edit',
  peer: '123456789',
  timestamp: 1,
  frontiers: [],
  propvals: new Map(),
  containers: new Map(),
};

function report(token: string, verified = true): HistoryAttribution {
  return {
    subject: 'atomic:document',
    retention: 'latest',
    complete: false,
    attributions: [
      {
        signer: 'atomic:agent:writer',
        createdAt: 1,
        signature: token,
        verified,
        tokens: [token],
        destroy: false,
        genesis: false,
      },
    ],
  };
}

it.each([
  [
    'Verified',
    mergeHistoryAttributions(report('second-edit'), report('first-edit')),
  ],
  ['Unattributed', report('second-edit')],
  ['Unverified', report('first-edit', false)],
] as const)(
  'labels an older version %s according to its retained proof',
  (label, attribution) => {
    render(
      <ThemeProvider theme={buildTheme(false, '#336699')}>
        <VersionTitle version={version} attribution={attribution} />
      </ThemeProvider>,
    );
    expect(screen.getByTestId('version-attribution').textContent).toBe(label);
    expect(screen.queryByText('atomic:agent:writer') !== null).toBe(
      label !== 'Unattributed',
    );
  },
);
