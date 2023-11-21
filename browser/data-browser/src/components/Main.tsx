import { PropsWithChildren, memo } from 'react';
import { VisuallyHidden } from './VisuallyHidden';
import { styled } from 'styled-components';
import { transitionName } from '../helpers/transitionName';
import { ViewTransitionProps } from '../helpers/ViewTransitionProps';
import { PARENT_PADDING_BLOCK } from './Parent';

/** Main landmark. Every page should have one of these.
 * If the pages shows a resource a subject can be passed that enables view transitions to work. */
export function Main({
  subject,
  children,
}: PropsWithChildren<ViewTransitionProps>): JSX.Element {
  return (
    <StyledMain subject={subject} about={subject}>
      <VisuallyHidden>
        <a href='#skip-to-content' id='skip-to-content' tabIndex={-1}>
          Start of main content
        </a>
      </VisuallyHidden>
      {children}
    </StyledMain>
  );
}

const StyledMain = memo(styled.main<ViewTransitionProps>`
  container-type: inline-size;
  /* Makes the contents fit the entire page */
  /* height: calc(
    100% - (${p => p.theme.heights.breadCrumbBar} + ${PARENT_PADDING_BLOCK} * 2)
  ); */
  ${p => transitionName('resource-page', p.subject)}
`);
