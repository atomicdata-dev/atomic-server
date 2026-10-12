import type { JSX } from 'react';
import { FormMarkdown } from './FormMarkdown.js';
import { infoBoxStyle, type InfoBoxBlock } from './types.js';

export interface InfoBoxProps {
  block: InfoBoxBlock;
  className?: string;
}

/**
 * A callout block. Styling is driven entirely by the
 * `atomic-form-info-box--{style}` modifier class (see `style.css`), so a host
 * app can restyle a variant without this component knowing about it.
 *
 * `warning` and `danger` get `role="alert"`: they carry information a
 * respondent must not miss. The quieter variants stay plain text — an alert
 * per tip would make a screen reader unusable.
 */
export function InfoBox({ block, className }: InfoBoxProps): JSX.Element {
  const style = infoBoxStyle(block.style);
  const alert = style === 'warning' || style === 'danger';

  return (
    <aside
      className={[
        'atomic-form-info-box',
        `atomic-form-info-box--${style}`,
        className,
      ]
        .filter(Boolean)
        .join(' ')}
      {...(alert ? { role: 'alert' } : {})}
    >
      {block.title && (
        <p className='atomic-form-info-box-title'>{block.title}</p>
      )}
      <FormMarkdown className='atomic-form-info-box-body' text={block.text} />
    </aside>
  );
}
