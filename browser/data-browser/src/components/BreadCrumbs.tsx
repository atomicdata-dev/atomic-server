import { styled } from 'styled-components';
import { core, useResource, useString, useTitle } from '@tomic/react';
import { Fragment, useLayoutEffect, useRef, type JSX } from 'react';

export type BreadCrumbsProps = {
  /** The resource whose ancestors are shown, ending in the resource itself. */
  subject: string;
  /** Called with the subject of an ancestor the user taps. Without it the
   * ancestors are plain text. */
  onNavigate?: (subject: string) => void;
};

/** Stops a (broken) parent cycle from rendering forever. */
const MAX_DEPTH = 16;

/**
 * The chain drive > folder > … > this resource, on one horizontally scrolling
 * line that is kept scrolled to its end, so the current resource stays visible.
 * Everything is read from the store, so it works without a network.
 */
export function BreadCrumbs({
  subject,
  onNavigate,
}: BreadCrumbsProps): JSX.Element {
  const scrollRef = useRef<HTMLElement>(null);
  const trailRef = useRef<HTMLDivElement>(null);

  // Parents load one by one, so the trail grows after the first paint.
  useLayoutEffect(() => {
    const scroller = scrollRef.current;
    const trail = trailRef.current;

    if (!scroller || !trail) return;

    const toEnd = () => {
      scroller.scrollLeft = scroller.scrollWidth;
    };

    toEnd();

    if (typeof ResizeObserver === 'undefined') return;

    const observer = new ResizeObserver(toEnd);
    observer.observe(trail);

    return () => observer.disconnect();
  }, [subject]);

  return (
    <Scroller ref={scrollRef} aria-label='Breadcrumbs'>
      <Trail ref={trailRef}>
        <Crumbs subject={subject} onNavigate={onNavigate} depth={0} current />
      </Trail>
    </Scroller>
  );
}

type CrumbsProps = BreadCrumbsProps & { depth: number; current?: boolean };

/** Renders the parents first (recursively), then this resource. */
function Crumbs({
  subject,
  onNavigate,
  depth,
  current,
}: CrumbsProps): JSX.Element | null {
  const resource = useResource(subject, { allowIncomplete: true });
  const [title] = useTitle(resource);
  const [parent] = useString(resource, core.properties.parent);

  const hidden = !current && (resource.error || resource.isUnauthorized());

  return (
    <Fragment>
      {parent && depth < MAX_DEPTH && !hidden && (
        <Crumbs subject={parent} onNavigate={onNavigate} depth={depth + 1} />
      )}
      {!hidden && (
        <Fragment>
          {current ? (
            <Current aria-current='page' title={title}>
              {title}
            </Current>
          ) : (
            <>
              {onNavigate ? (
                <Crumb
                  type='button'
                  onClick={() => onNavigate(subject)}
                  title={title}
                >
                  {title}
                </Crumb>
              ) : (
                <Plain>{title}</Plain>
              )}
              <Separator aria-hidden>/</Separator>
            </>
          )}
        </Fragment>
      )}
    </Fragment>
  );
}

const Scroller = styled.nav`
  overflow-x: auto;
  overflow-y: hidden;
  scrollbar-width: none;
  -webkit-overflow-scrolling: touch;
  min-width: 0;

  &::-webkit-scrollbar {
    display: none;
  }
`;

const Trail = styled.div`
  display: flex;
  align-items: center;
  width: max-content;
  min-width: 100%;
  box-sizing: border-box;
  padding-inline: ${p => p.theme.size(2)};
  font-size: 13px;
  font-family: ${p => p.theme.fontFamily};
  white-space: nowrap;
`;

const Plain = styled.span`
  color: ${p => p.theme.colors.textLight};
  padding: 0.2rem 0.25rem;
`;

const Crumb = styled.button`
  all: unset;
  box-sizing: border-box;
  cursor: pointer;
  color: ${p => p.theme.colors.textLight};
  padding: 0.2rem 0.25rem;
  border-radius: ${p => p.theme.radius};
  font: inherit;

  &:active {
    background: ${p => p.theme.colors.bg2};
  }
`;

const Separator = styled.span`
  color: ${p => p.theme.colors.textLight};
  opacity: 0.6;
  padding-inline: 0.1rem;
`;

const Current = styled.span`
  color: ${p => p.theme.colors.text};
  font-weight: 600;
  padding: 0.2rem 0.25rem;
  max-width: 24ch;
  overflow: hidden;
  text-overflow: ellipsis;
`;
