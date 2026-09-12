import type { Store } from '@tomic/lib';

declare global {
  interface Window {
    /** Set by data-browser `App.tsx` for debugging and e2e probes. */
    store: Store;
    __e2eLoad?: {
      longTasks: Array<{ start: number; duration: number }>;
      maxTimerLagMs: number;
    };
  }
}

export {};
