import { useDroppable } from '@dnd-kit/core';
import { useCanWrite, useResource } from '@tomic/react';
import { FaStar, FaTrash } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { transition } from '../../helpers/transition';
import type { SideBarZoneData, SideBarZoneKind } from './useSidebarDnd';

interface SidebarDropZonesProps {
  /** Subject being dragged. The zones only exist while this is set. */
  draggingResource: string | undefined;
}

/**
 * Favorites and Trash targets shown at the bottom of the sidebar while an item
 * is dragged, in the spot of the panels (which are hidden meanwhile). Normal
 * flow, no portal or fixed positioning, so they are as wide as the sidebar
 * (also as a phone drawer) and big enough to hit with a thumb. Must render
 * inside the sidebar's `DndContext`.
 */
export function SidebarDropZones({
  draggingResource,
}: SidebarDropZonesProps): React.JSX.Element | null {
  if (!draggingResource) {
    return null;
  }

  return (
    <ZoneBar data-testid='sidebar-drop-zones'>
      <TrashZone subject={draggingResource} />
      <DropZone
        zone='favorites'
        icon={<FaStar />}
        testId='sidebar-zone-favorites'
      >
        Favorites
      </DropZone>
    </ZoneBar>
  );
}

/** Trash is only offered for items the agent may move. */
function TrashZone({ subject }: { subject: string }) {
  const resource = useResource(subject);
  const canWrite = useCanWrite(resource);

  if (!canWrite) {
    return null;
  }

  return (
    <DropZone
      zone='trash'
      icon={<FaTrash />}
      testId='sidebar-zone-trash'
      danger
    >
      Delete
    </DropZone>
  );
}

interface DropZoneProps {
  zone: SideBarZoneKind;
  icon: React.ReactNode;
  testId: string;
  danger?: boolean;
}

function DropZone({
  zone,
  icon,
  testId,
  danger,
  children,
}: React.PropsWithChildren<DropZoneProps>) {
  const data: SideBarZoneData = { zone };
  const { setNodeRef, isOver } = useDroppable({
    id: `sidebar-zone-${zone}`,
    data,
  });

  return (
    <Zone
      ref={setNodeRef}
      data-testid={testId}
      $active={isOver}
      $danger={!!danger}
    >
      {icon}
      <span>{children}</span>
    </Zone>
  );
}

const ZoneBar = styled.div`
  /* Pushed to the bottom of the nav, like the panels' MenuWrapper. */
  margin-top: auto;
  box-sizing: border-box;
  display: flex;
  gap: 0.5rem;
  width: 100%;
  min-width: 0;
  padding-block: 0.5rem;
  /* Same horizontal inset as the tree and the panels. */
  padding-inline: ${p => p.theme.margin}rem;
  /* Keep a finger on a zone from starting a scroll or text selection. */
  touch-action: none;
  user-select: none;
`;

const Zone = styled.div<{ $active: boolean; $danger: boolean }>`
  flex: 1;
  min-width: 0;
  min-height: 3.5rem;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.25rem;
  padding: 0.5rem;
  font-size: 0.85rem;
  border-radius: ${p => p.theme.radius};
  border: 2px dashed
    ${p => (p.$danger ? p.theme.colors.alert : p.theme.colors.main)};
  color: ${p => (p.$danger ? p.theme.colors.alert : p.theme.colors.main)};
  background: ${p => (p.$active ? p.theme.colors.bg2 : 'transparent')};
  transform: scale(${p => (p.$active ? 1.04 : 1)});
  ${transition('background', 'transform')}

  svg {
    font-size: 1.25rem;
  }
`;
