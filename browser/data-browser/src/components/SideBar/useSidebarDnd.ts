import {
  Announcements,
  DragEndEvent,
  DragStartEvent,
  DropAnimationFunction,
  KeyboardSensor,
  MouseSensor,
  TouchSensor,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import { Resource, core, dataBrowser, useStore } from '@tomic/react';
import { useCallback, useState } from 'react';
import { getTransitionName } from '../../helpers/transitionName';
import { useSettings } from '../../helpers/AppSettings';

export type SideBarDropData = {
  parent: string;
  position: number;
};

export type SideBarDragData = {
  renderedUnder: string;
};

async function moveItemInSameParent(
  parent: Resource,
  subject: string,
  toPosition: number,
) {
  const subResources = parent.get(dataBrowser.properties.subResources) ?? [];

  const fromPosition = subResources.indexOf(subject);
  const newArray = [...subResources];
  const [removed] = newArray.splice(fromPosition, 1);
  newArray.splice(
    toPosition > fromPosition ? toPosition - 1 : toPosition,
    0,
    removed,
  );

  await parent.set(dataBrowser.properties.subResources, newArray);

  await parent.save();
}

async function moveItemBetweenParents(
  oldParent: Resource,
  newParent: Resource,
  resource: Resource,
  position: number,
) {
  const oldSubResources =
    oldParent.get(dataBrowser.properties.subResources) ?? [];
  await oldParent.set(
    dataBrowser.properties.subResources,
    oldSubResources.filter(subject => subject !== resource.subject),
  );

  const newSubResources =
    newParent.get(dataBrowser.properties.subResources) ?? [];

  await newParent.set(
    dataBrowser.properties.subResources,
    newSubResources.toSpliced(position, 0, resource.subject),
  );

  await resource.set(core.properties.parent, newParent.subject);

  await oldParent.save();
  await newParent.save();
  await resource.save();
}

export const useSidebarDnd = (
  onIsRearangingChange: (isRearanging: boolean) => void,
) => {
  const store = useStore();
  const { sidebarKeyboardDndEnabled } = useSettings();

  const keyboardSensor = useSensor(KeyboardSensor);

  const sensors = useSensors(
    useSensor(MouseSensor, {
      activationConstraint: {
        distance: 10,
      },
    }),
    useSensor(TouchSensor, {
      activationConstraint: {
        delay: 250,
        tolerance: 5,
      },
    }),
    sidebarKeyboardDndEnabled ? keyboardSensor : undefined,
  );

  const [draggingResource, setDraggingResource] = useState<string>();
  const [waitForSavePromise, setWaitForSavePromise] = useState<Promise<void>>();

  const animateDrop: DropAnimationFunction = useCallback(
    ({ active, dragOverlay, transform }) => {
      if (!active || !dragOverlay) {
        return;
      }

      return new Promise(resolve => {
        waitForSavePromise?.then(() => {
          const targetNode = document.querySelector(
            `[data-sidebar-id="${getTransitionName(
              'sidebar',
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

  const handleDragEnd = async (event: DragEndEvent) => {
    if (!event.over) {
      setDraggingResource(undefined);
      onIsRearangingChange(false);
      setWaitForSavePromise(Promise.resolve());

      return;
    }

    const subject = event.active.id as string;
    const { renderedUnder } = event.active.data
      .current as unknown as SideBarDragData;
    const { position, parent: dropParent } = event.over.data
      .current as unknown as SideBarDropData;

    const newParent = store.getResourceLoading(dropParent);
    const oldParent = store.getResourceLoading(renderedUnder);
    const resource = store.getResourceLoading(subject);

    // The user should not be able to nest a folder inside itself.
    if (subject === dropParent) {
      onIsRearangingChange(false);
      setDraggingResource(undefined);
      setWaitForSavePromise(Promise.resolve());

      return;
    }

    let promise: Promise<void>;

    if (renderedUnder === dropParent) {
      promise = moveItemInSameParent(newParent, subject, position);
    } else {
      promise = moveItemBetweenParents(
        oldParent,
        newParent,
        resource,
        position,
      );
    }

    setWaitForSavePromise(promise);
    await promise;
    setDraggingResource(undefined);
    onIsRearangingChange(false);
  };

  const dndExplanation: string = sidebarKeyboardDndEnabled
    ? 'To rearange items, press space or enter to start dragging. While dragging, use the arrow keys to move the item in any given direction. Press space or enter again to drop the item in its new position, or press escape to cancel.'
    : 'Keyboard support for drag and drop is disabled. Enable it in the settings.';

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
      const dropResource = store.getResourceLoading(over.data.current.parent);
      const pos = over.data.current.position as number;

      return `Draggable item ${
        dragResource.title
      } was moved over droppable area in ${dropResource.title} at position ${
        pos + 1
      }`;
    },
    onDragEnd: ({ active, over }) => {
      if (!over || !over.data.current) {
        return `Dragging canceled`;
      }

      const dragResource = store.getResourceLoading(active.id as string);
      const dropResource = store.getResourceLoading(over.data.current.parent);
      const pos = over.data.current.position as number;

      return `${dragResource.title} was moved to ${
        dropResource.title
      } at position ${pos + 1}`;
    },
    onDragCancel: () => {
      return `Dragging canceled`;
    },
  };

  return {
    handleDragStart,
    handleDragEnd,
    draggingResource,
    sensors,
    animateDrop,
    dndExplanation,
    announcements,
  };
};
