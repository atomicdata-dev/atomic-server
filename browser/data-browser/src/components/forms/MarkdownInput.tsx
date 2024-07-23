import { lazy, Suspense } from 'react';
import type { AsyncMarkdownEditorProps } from '../../chunks/MarkdownEditor/AsyncMarkdownEditor';
import { styled } from 'styled-components';

const MarkdownEditor = lazy(
  () => import('../../chunks/MarkdownEditor/AsyncMarkdownEditor'),
);

export function MarkdownInput(
  props: AsyncMarkdownEditorProps,
): React.JSX.Element {
  return (
    <Suspense fallback={<DummyEditor />}>
      <MarkdownEditor {...props} />
    </Suspense>
  );
}

const DummyEditor = styled.div`
  background-color: ${p => p.theme.colors.bg};
  padding: ${p => p.theme.margin}rem;
  border-radius: ${p => p.theme.radius};
  box-shadow: 0 0 0 1px ${p => p.theme.colors.bg2};
  width: min(100%, 75ch);
  min-height: 10rem;
`;
