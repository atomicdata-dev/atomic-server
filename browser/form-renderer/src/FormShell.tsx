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
export function stylingVars(
  styling: FormDefinition['styling'],
): CSSProperties {
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

  return vars as CSSProperties;
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

  return (
    <div
      className={`atomic-form-shell atomic-form-shell-${position} ${embed ? 'atomic-form-shell-embed' : ''} ${className ?? ''}`}
      style={stylingVars(styling)}
    >
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
