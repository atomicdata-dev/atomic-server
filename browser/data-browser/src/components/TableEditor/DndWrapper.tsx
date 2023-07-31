import { DndContext, Modifier, closestCorners } from '@dnd-kit/core';
import React from 'react';
import { useDragSensors } from './hooks/useDragSensors';

const restrictToHorizontalAxis: Modifier = ({ transform }) => {
  return {
    ...transform,
    y: 0,
  };
};

export function DndWrapper({ children }: React.PropsWithChildren) {
  const sensors = useDragSensors();

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCorners}
      modifiers={[restrictToHorizontalAxis]}
    >
      {children}
    </DndContext>
  );
}
