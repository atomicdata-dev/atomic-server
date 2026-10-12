/// <reference types="vite/client" />

import type { FormDefinition } from '@tomic/form-renderer';

declare global {
  interface Window {
    /** Injected inline by the server (GET /form/:id) so the first paint
     * skips a fetch round-trip. Undefined when the app is opened directly
     * against the Vite dev server — `main.tsx` falls back to fetching
     * `/form/:id/definition`. */
    __FORM_DEFINITION__?: FormDefinition;
  }
}
