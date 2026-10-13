import { describe, expect, it, vi } from 'vitest';
import type { Store } from '@tomic/react';
import type { TemplatePlan } from './model';
import { startTemplateDemo } from './instantiate';

vi.mock('../Demo/startDemo', () => ({
  stopDemoDirector: vi.fn(),
  cleanupDemoDrive: vi.fn(),
}));
vi.mock('./demoSession', () => ({ readTemplateDemo: () => null }));

describe('template preview storage readiness', () => {
  it('waits for the database to attach before reading it', async () => {
    let attached = false;
    const ready = vi.fn(async () => true);
    const store = {
      waitForClientDb: async () => {
        attached = true;

        return true;
      },
      getClientDb: () => (attached ? { waitForReady: ready } : undefined),
      getAgent: () => undefined,
      getDrive: () => undefined,
    } as unknown as Store;
    await expect(startTemplateDemo(store, {} as TemplatePlan)).rejects.toThrow(
      'Sign in',
    );
    expect(ready).toHaveBeenCalledOnce();
  });
  it('rejects a database that attached but cannot become ready', async () => {
    const store = {
      waitForClientDb: async () => true,
      getClientDb: () => ({ waitForReady: async () => false }),
    } as unknown as Store;
    await expect(startTemplateDemo(store, {} as TemplatePlan)).rejects.toThrow(
      'local storage',
    );
  });
});
