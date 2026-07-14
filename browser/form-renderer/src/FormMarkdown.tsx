import type { JSX } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export interface FormMarkdownProps {
  text: string;
  className?: string;
}

/** Renders a form's markdown-typed text (paragraph blocks, field helper
 * text) as safe, minimally-styled HTML. A `div` wrapper — not `p` — since
 * ReactMarkdown may itself emit block-level elements (lists, multiple
 * paragraphs), which can't nest inside a `<p>`. */
export function FormMarkdown({ text, className }: FormMarkdownProps): JSX.Element {
  return (
    <div className={className}>
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
    </div>
  );
}
