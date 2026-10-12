import { lazy, Suspense } from 'react';
import { styled } from 'styled-components';
import type { CSSEditorProps } from '../chunks/CodeEditor/AsyncCSSEditor';

const AsyncCSSEditor = lazy(
  () => import('../chunks/CodeEditor/AsyncCSSEditor'),
);

export const CSSEditor: React.FC<CSSEditorProps> = props => {
  return (
    <Suspense fallback={<Loader />}>
      <AsyncCSSEditor {...props} />
    </Suspense>
  );
};

const Loader = styled.div`
  background-color: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  height: 150px;
`;
