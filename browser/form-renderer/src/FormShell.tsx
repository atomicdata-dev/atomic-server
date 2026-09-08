import type { CSSProperties, JSX, ReactNode } from 'react';
import type { FormDefinition } from './types.js';

export interface FormShellProps {
  definition: FormDefinition;
  /** Usually a `<FormRenderer>` for the same definition. */
  children: ReactNode;
  className?: string;
  /** Set by the published runtime when rendering inside an `<iframe>`
   * (`?embed=1`, Phase 6 "Embedding") — trims the shell to its natural
   * content height instead of stretching to fill the viewport, so the
   * `ResizeObserver`-driven `postMessage` height report reflects the real
   * form height rather than a forced full-viewport minimum. */
  embed?: boolean;
}

const ROUNDNESS: Record<string, string> = {
  sharp: '0px',
  rounded: '0.5rem',
  round: '1rem',
};

const FIELD_SPACING: Record<string, string> = {
  small: '1.5rem',
  large: '5rem',
};

/** Perceived-luminance check so button text stays readable on a custom
 * accent color. Returns undefined for non-hex input (keeps the CSS default). */
function readableTextOn(hexColor: string): string | undefined {
  const hex = hexColor.replace('#', '');
  const full =
    hex.length === 3
      ? hex
          .split('')
          .map(c => c + c)
          .join('')
      : hex;

  if (!/^[0-9a-fA-F]{6}$/.test(full)) return undefined;

  const r = parseInt(full.slice(0, 2), 16);
  const g = parseInt(full.slice(2, 4), 16);
  const b = parseInt(full.slice(4, 6), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;

  return luminance > 0.6 ? '#1a1a1a' : '#ffffff';
}

/** Builds the CSS-variable overrides for a form's custom styling. Only set
 * keys override the light/dark-adaptive defaults in `style.css`; derived
 * colors (helper text, borders, on-accent text) keep contrast sensible
 * against the custom values. */
export function stylingVars(styling: FormDefinition['styling']): CSSProperties {
  const vars: Record<string, string> = {};

  if (styling.textColor) {
    vars['--atomic-form-text'] = styling.textColor;
    vars['--atomic-form-text-light'] =
      `color-mix(in srgb, ${styling.textColor} 70%, transparent)`;
    vars['--atomic-form-border'] =
      `color-mix(in srgb, ${styling.textColor} 30%, transparent)`;
  }

  if (styling.mainColor) {
    vars['--atomic-form-accent'] = styling.mainColor;
    const onAccent = readableTextOn(styling.mainColor);

    if (onAccent) vars['--atomic-form-on-accent'] = onAccent;
  }

  if (styling.backgroundColor) {
    vars['--atomic-form-bg'] = styling.backgroundColor;
  }

  if (styling.roundness && ROUNDNESS[styling.roundness]) {
    vars['--atomic-form-radius'] = ROUNDNESS[styling.roundness];
  }

  if (styling.fieldSpacing && FIELD_SPACING[styling.fieldSpacing]) {
    vars['--atomic-form-field-gap'] = FIELD_SPACING[styling.fieldSpacing];
  }

  return vars as CSSProperties;
}

/** The cascade layer a form owner's custom CSS is injected into. Declared
 * (empty) by `style.css` after `atomic-form-base`, so these rules win over
 * everything the renderer ships no matter how specific ours are — and no
 * matter whether this `<style>` element is parsed before or after the
 * stylesheet. */
const CUSTOM_LAYER = 'atomic-form-custom';

/**
 * Wraps a form owner's CSS so it lands in the `atomic-form-custom` layer and
 * cannot escape the form's own root element.
 *
 * The `@scope` matters most for the builder's Preview dialog, which renders a
 * `FormShell` inside the data-browser: unscoped, a `body { background: black }`
 * would repaint the builder around it. Scoping the same way in both places
 * also keeps the preview a faithful preview — the published runtime obeys
 * exactly the rules the dialog did.
 *
 * Inside the scope, `:scope` is the form root. That is where an owner
 * overrides the theme variables (`:scope { --atomic-form-accent: #f0f }`),
 * since `:root` refers to the document element and is therefore out of reach.
 *
 * Nothing here defends against CSS that closes our braces early and writes
 * top-level rules. It does not need to on a published form — the server
 * re-serializes the CSS from a parsed AST first
 * (`server/src/forms.rs::sanitize_custom_css`), so what arrives is structurally
 * sound. In a preview the text is the owner's own, unsent, on their own screen.
 */
export function wrapCustomCss(css: string | undefined): string | undefined {
  const trimmed = css?.trim();

  if (!trimmed) return undefined;

  return `@layer ${CUSTOM_LAYER} {\n@scope (.atomic-form-shell) {\n${trimmed}\n}\n}`;
}

/**
 * The page chrome around a rendered form: cover image (in any of its five
 * position modes), title, card, and the CSS-variable theming from
 * `definition.styling`. Shared by the published runtime (`form-app`) and the
 * data-browser builder's preview dialog so both render pixel-identically.
 */
export function FormShell({
  definition,
  children,
  className,
  embed,
}: FormShellProps): JSX.Element {
  const { styling } = definition;
  const imageUrl = styling.imageUrl;
  const position = imageUrl ? (styling.imagePosition ?? 'top') : 'plain';
  const customCss = wrapCustomCss(styling.customCss);

  return (
    <div
      className={`atomic-form-shell atomic-form-shell-${position} ${embed ? 'atomic-form-shell-embed' : ''} ${className ?? ''}`}
      style={stylingVars(styling)}
    >
      {/* Rendered in place rather than hoisted to <head>: React only hoists a
          <style> carrying `href` + `precedence`, and in-place keeps the rules
          next to the element they are scoped to. */}
      {customCss && <style>{customCss}</style>}
      {imageUrl && (position === 'behind' || position === 'full') && (
        <img className='atomic-form-backdrop' src={imageUrl} alt='' />
      )}
      {imageUrl && (position === 'left' || position === 'right') && (
        <div className='atomic-form-image-pane'>
          <img src={imageUrl} alt='' />
        </div>
      )}
      <div className='atomic-form-content-pane'>
        <div className='atomic-form-card'>
          {imageUrl && position === 'top' && (
            <img className='atomic-form-banner' src={imageUrl} alt='' />
          )}
          <h1 className='atomic-form-title'>{definition.name}</h1>
          {children}
        </div>
      </div>
    </div>
  );
}
