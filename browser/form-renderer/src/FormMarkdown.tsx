import type { CSSProperties, JSX } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export interface FormMarkdownProps {
  text: string;
  className?: string;
  /** Passed through to the wrapper — the staggered fade-in sets a custom
   * property here (see `staggerStyle`). */
  style?: CSSProperties;
}

/** Renders a form's markdown-typed text (paragraph blocks, field helper
 * text) as safe, minimally-styled HTML. A `div` wrapper — not `p` — since
 * ReactMarkdown may itself emit block-level elements (lists, multiple
 * paragraphs), which can't nest inside a `<p>`. */
export function FormMarkdown({
  text,
  className,
  style,
}: FormMarkdownProps): JSX.Element {
  return (
    <div className={className} style={style}>
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
    </div>
  );
}
