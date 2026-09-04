import type { Store } from '@tomic/lib';

declare global {
  interface Window {
    /** Set by data-browser `App.tsx` for debugging and e2e probes. */
    store: Store;
  }

  /** Opaque ranges over a form control's value — new enough that `lib.dom`
   * has no typing for it and most browsers no implementation. Optional here
   * for the same reason it is in `form-renderer/src/overflowHighlight.ts`:
   * the only interesting question is whether it exists. */
  interface HTMLInputElement {
    createValueRange?(start: number, end: number): AbstractRange;
  }
}

export {};
