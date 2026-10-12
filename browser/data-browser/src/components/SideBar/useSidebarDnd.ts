import {
  Announcements,
  closestCenter,
  CollisionDetection,
  DragEndEvent,
  DragStartEvent,
  DropAnimationFunction,
  KeyboardSensor,
  MouseSensor,
  pointerWithin,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import { core, dataBrowser, useStore } from '@tomic/react';
import { useCallback, useState, type MouseEvent } from 'react';
import toast from 'react-hot-toast';
import { isContentAddressed } from '../../helpers/propertyIdentity';
import {
  SIDEBAR_TRANSITION_TAG,
  getTransitionName,
} from '../../helpers/transitionName';
import { useSettings } from '../../helpers/AppSettings';
import { useFavorites } from '../../hooks/useFavorites';
import { moveToTrash } from '../../helpers/trash';
import { useResourceContextMenu } from '../ResourceContextMenu/ResourceContextMenuContext';
import { HoldMoveTouchSensor } from './holdMoveTouchSensor';
// Fractional-key math shared with table row insertion.
import {
  computeSortOrder,
  readSortKey,
} from '../../helpers/fractionalSortOrder';

/**
 * Data attached to a sidebar drop target.
 *
 * `parent` — the resource the dragged item should become (or stay) a child
 * of. For a "drop onto folder row" target this is that row's subject; for
 * a `DropEdge` it's the parent that owns the two surrounding siblings.
 *
 * `prevSubject` / `nextSubject` — the subjects immediately above and below
 * this drop point. The drag handler uses their `sortOrder` (or
 * `createdAt` as fallback) to compute a fractional sort key for the
 * dragged item, so only one resource needs to be re-saved per reorder.
 * `undefined` on either side means "drop at the start / end of the
 * parent's children". A "drop onto row" target has `prevSubject` set to
 * that row's last child (if any) and `nextSubject` undefined — i.e.
 * "append at end".
 */
export type SideBarDropData = {
  parent: string;
  prevSubject?: string;
  nextSubject?: string;
};

/** Drop zones that act on the dragged item instead of moving it. */
export type SideBarZoneKind = 'favorites' | 'trash';

/** Data attached to the Favorites / Trash drop zones. */
export type SideBarZoneData = {
  zone: SideBarZoneKind;
};

export type SideBarDragData = {
  renderedUnder: string;
};

export const isZoneData = (data: unknown): data is SideBarZoneData => {
  const zone = (data as Partial<SideBarZoneData> | null | undefined)?.zone;

  return zone === 'favorites' || zone === 'trash';
};

/**
 * The zones sit far from the tree, so when the pointer is inside one it wins
 * outright. Everything else keeps using `closestCenter` (see SideBar).
 */
export const sidebarCollisionDetection: CollisionDetection = args => {
  const zoneHits = pointerWithin({
    ...args,
    droppableContainers: args.droppableContainers.filter(c =>
      isZoneData(c.data.current),
    ),
  });

  return zoneHits.length > 0 ? zoneHits : closestCenter(args);
};

interface ZoneDropDeps {
  favorites: string[];
  addFavorite: (subject: string) => void;
  moveToTrash: (subject: string) => Promise<unknown>;
}

/**
 * Applies a drop on a zone, so the caller skips the parent / sortOrder logic.
 * Trash parks the item in the drive's Trash folder (nothing is destroyed);
 * the returned promise settles once that move is saved.
 */
export const handleZoneDrop = async (
  zone: SideBarZoneKind,
  subject: string,
  { favorites, addFavorite, moveToTrash: move }: ZoneDropDeps,
): Promise<void> => {
  if (zone === 'trash') {
    try {
      if (await move(subject)) {
        toast.success('Moved to Trash');
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not move to Trash');
    }

    return;
  }

  if (favorites.includes(subject)) {
    toast('Already in your favorites');

    return;
  }

  addFavorite(subject);
  toast.success('Added to favorites');
};

export const useSidebarDnd = (
  onIsRearangingChange: (isRearanging: boolean) => void,
) => {
  const store = useStore();
  const { sidebarKeyboardDndEnabled, drive } = useSettings();

  const keyboardSensor = useSensor(KeyboardSensor);
  const { openResourceMenu } = useResourceContextMenu();

  const onHold = useCallback(
    (subject: string, point: { x: number; y: number }) => {
      // The menu only needs a position; there is no mouse event for a held touch.
      openResourceMenu(subject, {
        clientX: point.x,
        clientY: point.y,
        preventDefault: () => undefined,
        stopPropagation: () => undefined,
      } as MouseEvent);
    },
    [openResourceMenu],
  );

  const sensors = useSensors(
    useSensor(MouseSensor, {
      activationConstraint: {
        distance: 10,
      },
    }),
    // Touch: a quick swipe scrolls, a tap navigates, holding still and
    // lifting opens the context menu, holding and then moving drags.
    useSensor(HoldMoveTouchSensor, {
      holdDelay: 400,
      scrollTolerance: 8,
      dragThreshold: 8,
      onHold,
    }),
    sidebarKeyboardDndEnabled ? keyboardSensor : undefined,
  );

  const [draggingResource, setDraggingResource] = useState<string>();
  const [waitForSavePromise, setWaitForSavePromise] = useState<Promise<void>>();
  const [favorites, addFavorite] = useFavorites();

  const animateDrop: DropAnimationFunction = useCallback(
    ({ active, dragOverlay, transform }) => {
      if (!active || !dragOverlay) {
        return;
      }

      return new Promise(resolve => {
        waitForSavePromise?.then(() => {
          const targetNode = document.querySelector(
            `[data-sidebar-id="${getTransitionName(
              SIDEBAR_TRANSITION_TAG,
              active.id as string,
            )}"]`,
          ) as HTMLElement;

          if (!targetNode) {
            return resolve();
          }

          targetNode.style.opacity = '0';

          const { top: originTop, left: originLeft } = dragOverlay.rect;
          const { x: originTransformX, y: originTransformY } = transform;

          const { top: targetTop, left: targetLeft } =
            targetNode.getBoundingClientRect();

          const targetTransformX = targetLeft - originLeft + originTransformX;
          const targetTransformY = targetTop - originTop + originTransformY;

          const dropAnimation = dragOverlay.node.animate(
            [
              {
                transform: `translate(${originTransformX}px, ${originTransformY}px)`,
              },
              {
                transform: `translate(${targetTransformX}px, ${targetTransformY}px)`,
              },
            ],
            {
              duration: 300,
              easing: 'cubic-bezier(0.2, 0, 0, 1)',
            },
          );

          dropAnimation.onfinish = () => {
            targetNode.style.opacity = '1';
            resolve();
          };
        });
      });
    },
    [waitForSavePromise],
  );

  const handleDragStart = (event: DragStartEvent) => {
    onIsRearangingChange(true);
    setDraggingResource(event.active.id as string);
  };

  // Escape or a cancelled touch ends a drag without a drop: leave drag mode so
  // the panels come back.
  const handleDragCancel = () => {
    setDraggingResource(undefined);
    onIsRearangingChange(false);
    setWaitForSavePromise(Promise.resolve());
  };

  const handleDragEnd = async (event: DragEndEvent) => {
    if (!event.over) {
      setDraggingResource(undefined);
      onIsRearangingChange(false);
      setWaitForSavePromise(Promise.resolve());

      return;
    }

    const subject = event.active.id as string;

    if (isZoneData(event.over.data.current)) {
      // The drop animation waits on this, so the overlay only flies back once
      // a trashed row has left the tree.
      const promise = handleZoneDrop(event.over.data.current.zone, subject, {
        favorites,
        addFavorite,
        moveToTrash: s => moveToTrash(store, s, drive),
      });

      setWaitForSavePromise(promise);
      await promise;
      setDraggingResource(undefined);
      onIsRearangingChange(false);

      return;
    }

    const { renderedUnder } = event.active.data
      .current as unknown as SideBarDragData;
    const {
      parent: dropParent,
      prevSubject,
      nextSubject,
    } = event.over.data.current as unknown as SideBarDropData;

    const resource = store.getResourceLoading(subject);

    // The user should not be able to nest a folder inside itself.
    if (subject === dropParent) {
      onIsRearangingChange(false);
      setDraggingResource(undefined);
      setWaitForSavePromise(Promise.resolve());

      return;
    }

    // A content-addressed property's parent is part of its ID: it cannot move.
    if (renderedUnder !== dropParent && isContentAddressed(subject)) {
      toast.error("A property can't be moved to another parent.");
      onIsRearangingChange(false);
      setDraggingResource(undefined);
      setWaitForSavePromise(Promise.resolve());

      return;
    }

    // Dragged neighbor cases: if the drop point is immediately above or
    // below the dragged item itself within the same parent, that's a
    // no-op move — bail out so we don't write a redundant sortOrder.
    if (
      renderedUnder === dropParent &&
      (prevSubject === subject || nextSubject === subject)
    ) {
      setDraggingResource(undefined);
      onIsRearangingChange(false);
      setWaitForSavePromise(Promise.resolve());

      return;
    }

    const prevResource = prevSubject
      ? store.getResourceLoading(prevSubject)
      : undefined;
    const nextResource = nextSubject
      ? store.getResourceLoading(nextSubject)
      : undefined;

    const newSortOrder = computeSortOrder(
      readSortKey(prevResource),
      readSortKey(nextResource),
    );

    const promise = (async () => {
      // Re-parent if necessary. The live `useChildren` query on the new
      // parent picks up the change automatically.
      if (renderedUnder !== dropParent) {
        await resource.set(core.properties.parent, dropParent);
      }

      await resource.set(dataBrowser.properties.sortOrder, newSortOrder);
      await resource.save();
    })();

    setWaitForSavePromise(promise);
    await promise;
    setDraggingResource(undefined);
    onIsRearangingChange(false);
  };

  const dndExplanation: string = sidebarKeyboardDndEnabled
    ? 'To rearange items, press space or enter to start dragging. While dragging, use the arrow keys to move the item in any given direction. Press space or enter again to drop the item in its new position, or press escape to cancel.'
    : 'Keyboard support for drag and drop is disabled. Enable it in the settings.';

  const describeTarget = (data: unknown): string => {
    if (isZoneData(data)) {
      return data.zone === 'trash' ? 'the trash' : 'your favorites';
    }

    const { parent } = data as SideBarDropData;

    return store.getResourceLoading(parent).title;
  };

  const announcements: Announcements = {
    onDragStart: ({ active }) => {
      const resource = store.getResourceLoading(active.id as string);

      return `Picked up ${resource.title}`;
    },
    onDragOver: ({ active, over }) => {
      if (!over || !over.data.current) {
        return;
      }

      const dragResource = store.getResourceLoading(active.id as string);

      return `Draggable item ${dragResource.title} was moved over droppable area in ${describeTarget(over.data.current)}`;
    },
    onDragEnd: ({ active, over }) => {
      if (!over || !over.data.current) {
        return `Dragging canceled`;
      }

      const dragResource = store.getResourceLoading(active.id as string);

      if (isZoneData(over.data.current)) {
        return over.data.current.zone === 'trash'
          ? `${dragResource.title} was moved to the trash`
          : `${dragResource.title} was dropped on your favorites`;
      }

      return `${dragResource.title} was moved to ${describeTarget(over.data.current)}`;
    },
    onDragCancel: () => {
      return `Dragging canceled`;
    },
  };

  return {
    handleDragStart,
    handleDragEnd,
    handleDragCancel,
    draggingResource,
    sensors,
    animateDrop,
    dndExplanation,
    announcements,
  };
};
