import { describe, expect, it, vi } from 'vitest';
import { core, server } from '@tomic/react';
import { resourceActions } from './resourceActions';
import type { ActionContext } from './types';

const parent = resourceActions.find(action => action.id === 'parent')!;

function ctx(
  resource: {
    loading?: boolean;
    get: (prop: string) => unknown;
    getClasses: () => string[];
  },
  extra: Partial<ActionContext> = {},
): ActionContext {
  return {
    resource,
    subject: 'did:ad:child',
    ...extra,
  } as unknown as ActionContext;
}

describe('parent action', () => {
  it('is available when parent is already on the resource', () => {
    expect(
      parent.available?.(
        ctx({
          get: prop =>
            prop === core.properties.parent ? 'did:ad:parent' : undefined,
          getClasses: () => [],
        }),
      ),
    ).toBe(true);
  });

  it('stays available on a non-drive even before parent has materialized', () => {
    expect(
      parent.available?.(
        ctx({
          get: () => undefined,
          getClasses: () => [],
        }),
      ),
    ).toBe(true);
  });

  it('is hidden on a drive, which has no parent', () => {
    expect(
      parent.available?.(
        ctx({
          get: () => undefined,
          getClasses: () => [server.classes.drive],
        }),
      ),
    ).toBe(false);
  });

  it('fetches the resource when parent is not yet on the stub', async () => {
    vi.stubGlobal('window', { location: { origin: 'http://localhost' } });

    const navigate = vi.fn();
    const getResource = vi.fn().mockResolvedValue({
      get: (prop: string) =>
        prop === core.properties.parent ? 'did:ad:parent' : undefined,
    });

    await parent.run(
      ctx(
        {
          loading: true,
          get: () => undefined,
          getClasses: () => [],
        },
        {
          subject: 'did:ad:child',
          navigate,
          store: { getResource } as unknown as ActionContext['store'],
        },
      ),
    );

    expect(getResource).toHaveBeenCalledWith('did:ad:child');
    expect(navigate).toHaveBeenCalledWith(
      expect.stringContaining(encodeURIComponent('did:ad:parent')),
    );
  });
});
