import { Fragment, useEffect, useMemo, useState } from 'react';
import {
  useString,
  useResource,
  useTitle,
  useArray,
  useCanWrite,
  core,
  dataBrowser,
} from '@tomic/react';
import { useCurrentSubject } from '../../../helpers/useCurrentSubject';
import { SideBarItem } from '../SideBarItem';
import { AtomicLink } from '../../AtomicLink';
import { styled } from 'styled-components';
import { Details } from '../../Details';
import { errorLookStyle } from '../../ErrorLook';
import { LoaderInline } from '../../Loader';
import { FaExclamationTriangle } from 'react-icons/fa';
import { useDraggable } from '@dnd-kit/core';
import { SidebarItemTitle } from './SidebarItemTitle';
import { TextWrapper } from './shared';
import { DropEdge } from './DropEdge';
import { SideBarDragData } from '../useSidebarDnd';
import { transparentize } from 'polished';
import { transition } from '../../../helpers/transition';

interface ResourceSideBarProps {
  subject: string;
  renderedHierargy: string[];
  ancestry: string[];
  /** When a SideBar item is clicked, we should close the SideBar (on mobile devices) */
  onClick?: () => unknown;
}

/** Renders a Resource as a nav item for in the sidebar. */
export function ResourceSideBar({
  subject,
  renderedHierargy,
  ancestry,
  onClick,
}: ResourceSideBarProps): JSX.Element {
  if (renderedHierargy.length === 0) {
    throw new Error('renderedHierargy should not be empty');
  }

  const resource = useResource(subject, { allowIncomplete: true });
  const [currentUrl] = useCurrentSubject();
  const [title] = useTitle(resource);
  const [description] = useString(resource, core.properties.description);
  const [canWrite] = useCanWrite(resource);
  const active = currentUrl === subject;
  const [open, setOpen] = useState(active);

  const [subResources] = useArray(
    resource,
    dataBrowser.properties.subResources,
  );
  const hasSubResources = subResources.length > 0;

  const dragData: SideBarDragData = {
    renderedUnder: renderedHierargy.at(-1)!,
  };

  const {
    setNodeRef,
    listeners,
    attributes,
    over,
    active: draggingNode,
  } = useDraggable({
    id: subject,
    data: dragData,
    disabled: !canWrite,
  });

  const isDragging = draggingNode?.id === subject;

  useEffect(() => {
    if (isDragging) {
      setOpen(false);
    }
  }, [isDragging]);

  const isHoveringOver = over?.data.current?.parent === subject;

  useEffect(() => {
    if (ancestry.includes(subject) && ancestry[0] !== subject) {
      setOpen(true);
    }
  }, [ancestry]);

  const hierarchyWithItself = [...renderedHierargy, subject];

  const TitleComp = useMemo(
    () => (
      <SidebarItemTitle
        subject={subject}
        active={active}
        onClick={onClick}
        ref={setNodeRef}
        listeners={listeners}
        attributes={attributes}
      />
    ),
    [subject, active, onClick, description, title],
  );

  if (resource.loading) {
    return (
      <SideBarItem
        onClick={onClick}
        disabled={active}
        resource={subject}
        title={`${subject} is loading...`}
      >
        <LoaderInline />
      </SideBarItem>
    );
  }

  if (resource.error) {
    return (
      <StyledLink subject={subject} clean>
        <SideBarItem onClick={onClick} disabled={active} resource={subject}>
          <SideBarErrorWrapper>
            <FaExclamationTriangle />
            Resource with error
          </SideBarErrorWrapper>
        </SideBarItem>
      </StyledLink>
    );
  }

  return (
    <Wrapper highlight={isHoveringOver}>
      <Details
        initialState={open}
        open={open}
        disabled={!hasSubResources}
        onStateToggle={setOpen}
        data-test='resource-sidebar'
        title={TitleComp}
      >
        <DropEdge parentHierarchy={hierarchyWithItself} position={0} />
        {hasSubResources &&
          subResources.map((child, index) => (
            <Fragment key={child}>
              <ResourceSideBar
                subject={child}
                renderedHierargy={hierarchyWithItself}
                ancestry={ancestry}
              />
              <DropEdge
                parentHierarchy={hierarchyWithItself}
                position={index + 1}
              />
            </Fragment>
          ))}
      </Details>
    </Wrapper>
  );
}

const Wrapper = styled.div<{ highlight: boolean }>`
  background-color: ${p =>
    p.highlight ? transparentize(0.9, p.theme.colors.main) : 'none'};

  border-radius: ${({ theme }) => theme.radius};
  ${transition('background-color')}
`;

const StyledLink = styled(AtomicLink)`
  flex: 1;
  overflow: hidden;
  white-space: nowrap;
`;

const SideBarErrorWrapper = styled(TextWrapper)`
  margin-left: 1.3rem;
  ${errorLookStyle}
`;
