import { Suspense, lazy } from 'react';
import type { HiglightedCodeBlockProps } from '../chunks/HighlightedCode/HighlightedCodeBlock';

const CodeBlock = lazy(
  () => import('../chunks/HighlightedCode/HighlightedCodeBlock'),
);

export function HighlightedCodeBlock({
  children,
  ...props
}: React.PropsWithChildren<HiglightedCodeBlockProps>): React.JSX.Element {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <CodeBlock {...props}>{children}</CodeBlock>
    </Suspense>
  );
}
