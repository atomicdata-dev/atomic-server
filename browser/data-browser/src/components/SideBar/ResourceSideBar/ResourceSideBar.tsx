import {
  Fragment,
  memo,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';
import {
  ai,
  core,
  dataBrowser,
  useResource,
  useCanWrite,
  unknownSubject,
} from '@tomic/react';
import { useChildren } from '@tomic/react';
import { useCurrentSubject } from '../../../helpers/useCurrentSubject';
import { SideBarItem } from '../SideBarItem';
import { AtomicLink } from '../../AtomicLink';
import { styled } from 'styled-components';
import { Details } from '../../Details';
import { errorLookStyle } from '../../ErrorLook';
import { LoaderInline } from '../../Loader';
import { FaTriangleExclamation } from 'react-icons/fa6';
import { useDraggable, useDroppable } from '@dnd-kit/core';
import { SidebarItemTitle } from './SidebarItemTitle';
import { TextWrapper } from './shared';
import { DropEdge } from './DropEdge';
import { SideBarDragData, SideBarDropData } from '../useSidebarDnd';
import { transparentize } from 'polished';
import { transition } from '../../../helpers/transition';

interface ResourceSideBarProps {
  subject: string;
  renderedHierarchy: string[];
  ancestry: string[];
  /** When a SideBar item is clicked, we should close the SideBar (on mobile devices) */
  onClick?: () => unknown;
}

/** Renders a Resource as a nav item for in the sidebar. */
export const ResourceSideBar: React.FC<ResourceSideBarProps> = memo(
  ({ subject, renderedHierarchy, ancestry, onClick }) => {
    if (renderedHierarchy.length === 0) {
      throw new Error('renderedHierarchy should not be empty');
    }

    // Prevent infinite recursion: stop if we've already rendered this subject
    // in the hierarchy, or if we're too deep.
    const MAX_DEPTH = 10;

    if (
      renderedHierarchy.includes(subject) ||
      renderedHierarchy.length > MAX_DEPTH
    ) {
      return null;
    }

    const resource = useResource(subject, { allowIncomplete: true });
    const [currentUrl] = useCurrentSubject();
    const canWrite = useCanWrite(resource);
    const active = currentUrl === subject;
    const [open, setOpen] = useState(active);

    // Classes that own their children's display in their own UI — skip the
    // sidebar tree for them. Tables show rows in the grid view, chatrooms
    // and meetings show messages in the timeline, AI chats show messages
    // in the AI panel, ontologies show classes/properties in their
    // dedicated panel. Listing those children again in the sidebar would
    // be noisy and confuses drop targeting.
    //
    // `allowIncomplete` means `classes` is `[]` until `isA` hydrates. Treat
    // that as hidden too: otherwise `useChildren` fetches every table row
    // into the tree, then hides them when the class arrives — the sidebar
    // flash on open.
    const classes = resource.getClasses();
    const hideChildren =
      classes.length === 0 ||
      classes.includes(dataBrowser.classes.table) ||
      classes.includes(dataBrowser.classes.chatroom) ||
      classes.includes(dataBrowser.classes.meeting) ||
      classes.includes(ai.classes.aiChat) ||
      classes.includes(core.classes.ontology);

    const { subjects: subResources } = useChildren(
      hideChildren ? undefined : subject,
    );

    const dragData: SideBarDragData = {
      renderedUnder: renderedHierarchy.at(-1)!,
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

    // "Drop onto folder" target: the whole row accepts drops, setting
    // this resource as the dragged item's parent. The drop sits at the
    // *end* of this folder's children — `prevSubject = last child` so
    // the handler computes `sortOrder = lastSibling.sortOrder + 1`.
    //
    // Disable when:
    //  - the user can't write here,
    //  - this row IS the dragged item (drop-on-self),
    //  - an ancestor of this row is being dragged (would create a cycle),
    //  - this row's class never renders children in the sidebar
    //    (tables, chatrooms) — accepting a drop would silently reparent
    //    the item under something that can't show it.
    const draggedId = draggingNode?.id as string | undefined;
    const dropDisabled =
      !canWrite ||
      hideChildren ||
      (!!draggedId &&
        (draggedId === subject || renderedHierarchy.includes(draggedId)));
    const dropData: SideBarDropData = {
      parent: subject,
      prevSubject: subResources.at(-1),
      nextSubject: undefined,
    };
    const { setNodeRef: setDropNodeRef } = useDroppable({
      id: `${subject}-into`,
      data: dropData,
      disabled: dropDisabled,
    });

    const setItemRef = useCallback(
      (node: HTMLAnchorElement | null) => {
        setNodeRef(node);
        setDropNodeRef(node);
      },
      [setNodeRef, setDropNodeRef],
    );

    const hasSubResources = subResources.length > 0;

    const toggleExpanded = useCallback(() => setOpen(prev => !prev), []);

    const TitleComp = useMemo(
      () => (
        <SidebarItemTitle
          subject={subject}
          active={active}
          onClick={onClick}
          ref={setItemRef}
          listeners={canWrite ? listeners : undefined}
          attributes={canWrite ? attributes : undefined}
          expandable={hasSubResources}
          expanded={open}
          onToggleExpand={hasSubResources ? toggleExpanded : undefined}
        />
      ),
      [
        subject,
        active,
        onClick,
        listeners,
        attributes,
        canWrite,
        setItemRef,
        hasSubResources,
        open,
        toggleExpanded,
      ],
    );
    const isDragging = draggingNode?.id === subject;
    const isHoveringOver = over?.data.current?.parent === subject;
    const hierarchyWithItself = [...renderedHierarchy, subject];

    useEffect(() => {
      if (isDragging) {
        setOpen(false);
      }
    }, [isDragging]);

    useEffect(() => {
      if (ancestry.includes(subject) && ancestry[0] !== subject) {
        setOpen(true);
      }
    }, [ancestry, subject]);

    if (!subject || subject === unknownSubject) {
      return null;
    }

    if (resource.loading) {
      return (
        <TreeLoadingRow
          onClick={onClick}
          disabled={active}
          resource={subject}
          title={`${subject} is loading...`}
        >
          <LoaderInline />
        </TreeLoadingRow>
      );
    }

    if (resource.error) {
      return (
        <StyledLink subject={subject} clean>
          <TreeLoadingRow
            onClick={onClick}
            disabled={active}
            resource={subject}
          >
            <SideBarErrorWrapper>
              <FaTriangleExclamation />
              <span>Resource with error</span>
            </SideBarErrorWrapper>
          </TreeLoadingRow>
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
          showCaret={false}
          summaryClickable={false}
          title={TitleComp}
        >
          {hasSubResources && (
            <>
              <DropEdge
                parentHierarchy={hierarchyWithItself}
                index={0}
                prevSubject={undefined}
                nextSubject={subResources[0]}
              />
              {subResources.map((child, idx) => (
                <Fragment key={child}>
                  <ResourceSideBar
                    subject={child}
                    renderedHierarchy={hierarchyWithItself}
                    ancestry={ancestry}
                    onClick={onClick}
                  />
                  <DropEdge
                    parentHierarchy={hierarchyWithItself}
                    index={idx + 1}
                    prevSubject={child}
                    nextSubject={subResources[idx + 1]}
                  />
                </Fragment>
              ))}
            </>
          )}
        </Details>
      </Wrapper>
    );
  },
);

const Wrapper = styled.div<{ highlight: boolean }>`
  background-color: ${p =>
    p.highlight ? transparentize(0.9, p.theme.colors.main) : 'none'};

  border-radius: ${({ theme }) => theme.radius};
  ${transition('background-color')}
`;

const TreeLoadingRow = styled(SideBarItem)`
  box-sizing: border-box;
  width: 100%;
`;

const StyledLink = styled(AtomicLink)`
  box-sizing: border-box;
  display: block;
  width: 100%;
  flex: 1;
  min-width: 0;
  overflow: hidden;
  white-space: nowrap;
`;

const SideBarErrorWrapper = styled(TextWrapper)`
  margin-left: 1.3rem;
  ${errorLookStyle}
`;
