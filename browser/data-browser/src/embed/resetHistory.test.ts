import { createMemoryHistory } from '@tanstack/react-router';
import { describe, expect, it } from 'vitest';
import { goToFirstEntry } from './resetHistory';

describe('goToFirstEntry', () => {
  it('leaves nothing to go back to after the warm-up pushed entries', () => {
    const history = createMemoryHistory({ initialEntries: ['/app/show'] });

    history.push('/app/show?subject=recent');
    history.push('/app/show?subject=');
    expect(history.canGoBack()).toBe(true);

    goToFirstEntry(history);
    history.replace('/app/show?subject=opened');

    expect(history.canGoBack()).toBe(false);
    expect(history.location.search).toContain('opened');
  });

  it('does nothing on a single entry', () => {
    const history = createMemoryHistory({ initialEntries: ['/app/show'] });

    goToFirstEntry(history);

    expect(history.canGoBack()).toBe(false);
  });

  it('a link followed afterwards still goes back to the opened resource', () => {
    const history = createMemoryHistory({ initialEntries: ['/a'] });

    history.push('/b');
    goToFirstEntry(history);
    history.replace('/opened');
    history.push('/link');

    expect(history.canGoBack()).toBe(true);
    history.back();
    expect(history.location.pathname).toBe('/opened');
    expect(history.canGoBack()).toBe(false);
  });
});
