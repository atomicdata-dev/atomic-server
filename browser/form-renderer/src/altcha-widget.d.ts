/**
 * Minimal JSX typing for the ALTCHA web component (`<altcha-widget>`). The
 * element is registered by form-app's side-effect `import 'altcha'` — this
 * package deliberately does NOT depend on the altcha package (or its own
 * React typings): the data-browser imports form-renderer for the builder
 * preview, which never renders the widget, and must not pull the ~34 kB
 * solver into its bundle.
 */
import type { HTMLAttributes, Ref } from 'react';

interface AltchaWidgetAttributes extends HTMLAttributes<HTMLElement> {
  ref?: Ref<HTMLElement>;
  /** Challenge URL (or inline challenge JSON string). */
  challenge?: string;
  auto?: 'off' | 'onfocus' | 'onload' | 'onsubmit';
  /** Name of the hidden input holding the solved payload (default 'altcha'). */
  name?: string;
}

declare module 'react' {
  namespace JSX {
    interface IntrinsicElements {
      'altcha-widget': AltchaWidgetAttributes;
    }
  }
}

declare module 'react/jsx-runtime' {
  namespace JSX {
    interface IntrinsicElements {
      'altcha-widget': AltchaWidgetAttributes;
    }
  }
}
