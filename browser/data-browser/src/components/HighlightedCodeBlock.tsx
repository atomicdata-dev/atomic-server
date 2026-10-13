import { Suspense, lazy } from 'react';
import type { HiglightedCodeBlockProps } from '../chunks/HighlightedCode/HighlightedCodeBlock';
import { Spinner } from './Spinner';

const CodeBlock = lazy(
  () => import('../chunks/HighlightedCode/HighlightedCodeBlock'),
);

export function HighlightedCodeBlock({
  children,
  ...props
}: React.PropsWithChildren<HiglightedCodeBlockProps>): React.JSX.Element {
  return (
    <Suspense fallback={<Spinner size='1.5rem' />}>
      <CodeBlock {...props}>{children}</CodeBlock>
    </Suspense>
  );
}
