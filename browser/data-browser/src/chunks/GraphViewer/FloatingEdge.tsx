import React, { useCallback } from 'react';
import {
  useStore as useFlowStore,
  getBezierPath,
  EdgeText,
  EdgeProps,
  Node,
} from 'reactflow';
import { styled, useTheme } from 'styled-components';
import { getEdgeParams, getSelfReferencePath } from './getEdgeParams';
import { EdgeData } from './buildGraph';

const getPathData = (
  sourceNode: Node,
  targetNode: Node,
  overlapping: boolean,
) => {
  // Self referencing edges use a custom path.
  if (sourceNode.id === targetNode.id) {
    return getSelfReferencePath(sourceNode);
  }

  const { sx, sy, tx, ty, sourcePos, targetPos } = getEdgeParams(
    sourceNode,
    targetNode,
    overlapping,
  );

  return getBezierPath({
    sourceX: sx,
    sourceY: sy,
    sourcePosition: sourcePos,
    targetPosition: targetPos,
    targetX: tx,
    targetY: ty,
  });
};

function Label({ text }: { text: string }): JSX.Element | string {
  const parts = text.split('\n');

  if (parts.length === 1) {
    return text;
  }

  // SVG does not have any auto word wrap so we split the lines manually and offset them.
  return (
    <>
      {parts.map((part, i) => (
        <tspan x={0} dy={i === 0 ? '-0.3em' : '1.2em'} key={part}>
          {part}
        </tspan>
      ))}
    </>
  );
}

/**
 * A custom edge that doesn't clutter the graph as mutch as the default edge.
 * It casts a ray from the center of the source node to the center of the target node then draws a bezier curve between the two intersecting border of the nodes.
 */
export function FloatingEdge({
  id,
  source,
  target,
  markerEnd,
  style,
  label,
  data,
}: EdgeProps<EdgeData>) {
  const theme = useTheme();
  const sourceNode = useFlowStore(
    useCallback(store => store.nodeInternals.get(source), [source]),
  );
  const targetNode = useFlowStore(
    useCallback(store => store.nodeInternals.get(target), [target]),
  );

  if (!sourceNode || !targetNode) {
    return null;
  }

  const [path, labelX, labelY] = getPathData(
    sourceNode,
    targetNode,
    !!data?.overlapping,
  );

  return (
    <>
      <Path
        id={id}
        className='react-flow__edge-path'
        d={path}
        markerEnd={markerEnd}
        style={style}
      />
      <EdgeText
        x={labelX}
        y={labelY}
        label={<Label text={label as string} />}
        labelStyle={{
          fill: theme.colors.text,
        }}
        labelShowBg
        labelBgStyle={{ fill: theme.colors.bg1 }}
        labelBgPadding={[2, 4]}
        labelBgBorderRadius={2}
      />
    </>
  );
}

const Path = styled.path`
  flex-direction: column;
  display: flex;
  flex-grow: 1;
  height: 100%;

  & .react-flow__handle {
    opacity: 0;
  }
`;
