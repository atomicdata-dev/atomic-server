import { Position, Node } from 'reactflow';

// this helper function returns the intersection point
// of the line between the center of the intersectionNode and the target node
function getNodeIntersection(intersectionNode: Node, targetNode: Node) {
  // https://math.stackexchange.com/questions/1724792/an-algorithm-for-finding-the-intersection-point-between-a-center-of-vision-and-a
  const {
    width: intersectionNodeWidth,
    height: intersectionNodeHeight,
    positionAbsolute: intersectionNodePosition,
  } = intersectionNode;
  const targetPosition = targetNode.positionAbsolute;

  const w = intersectionNodeWidth! / 2;
  const h = intersectionNodeHeight! / 2;

  const x2 = intersectionNodePosition!.x + w;
  const y2 = intersectionNodePosition!.y + h;
  const x1 = targetPosition!.x + w;
  const y1 = targetPosition!.y + h;

  const xx1 = (x1 - x2) / (2 * w) - (y1 - y2) / (2 * h);
  const yy1 = (x1 - x2) / (2 * w) + (y1 - y2) / (2 * h);
  const a = 1 / (Math.abs(xx1) + Math.abs(yy1));
  const xx3 = a * xx1;
  const yy3 = a * yy1;
  const x = w * (xx3 + yy3) + x2;
  const y = h * (-xx3 + yy3) + y2;

  return { x, y };
}

// returns the position (top,right,bottom or right) passed node compared to the intersection point
function getEdgePosition(
  node: Node,
  intersectionPoint: { x: number; y: number },
) {
  const n = { ...node.positionAbsolute, ...node };
  const nx = Math.round(n.x!);
  const ny = Math.round(n.y!);
  const px = Math.round(intersectionPoint.x);
  const py = Math.round(intersectionPoint.y);

  if (px <= nx + 1) {
    return Position.Left;
  }

  if (px >= nx + n.width! - 1) {
    return Position.Right;
  }

  if (py <= ny + 1) {
    return Position.Top;
  }

  if (py >= n.y! + n.height! - 1) {
    return Position.Bottom;
  }

  return Position.Top;
}

export function getEdgeParams(
  source: Node,
  target: Node,
  overlapping: boolean,
) {
  const sourceIntersectionPoint = getNodeIntersection(source, target);
  const targetIntersectionPoint = getNodeIntersection(target, source);

  const sourcePos = getEdgePosition(source, sourceIntersectionPoint);
  const targetPos = getEdgePosition(target, targetIntersectionPoint);

  let sx = sourceIntersectionPoint.x;

  if (overlapping) {
    const center = source.positionAbsolute!.x! + source.width! / 2;
    const diff = Math.abs(sx - center);

    if (sx < center) {
      sx = center + diff;
    } else {
      sx = center - diff;
    }
  }

  return {
    sx: sx,
    sy: sourceIntersectionPoint.y,
    tx: targetIntersectionPoint.x,
    ty: targetIntersectionPoint.y,
    sourcePos,
    targetPos,
  };
}

export function getSelfReferencePath(
  node: Node,
): [path: string, labelX: number, labelY: number] {
  const { positionAbsolute, width, height } = node;

  const { x, y } = positionAbsolute!;
  const HORIZONTAL_START_OFFSET = 20;
  const HORIZONTAL_OFFSET = 50;
  const VERTICAL_OFFSET = 15;
  const BORDER_RADIUS = 10;

  const start = { x: x! + width! - HORIZONTAL_START_OFFSET, y: y! + height! };

  const path = [
    `M ${start.x}, ${start.y}`,
    line(0, VERTICAL_OFFSET - BORDER_RADIUS),
    arc(BORDER_RADIUS, BORDER_RADIUS),
    line(HORIZONTAL_OFFSET - BORDER_RADIUS, 0),
    arc(BORDER_RADIUS, -BORDER_RADIUS),
    line(0, (height! + (VERTICAL_OFFSET - BORDER_RADIUS) * 2) * -1),
    arc(-BORDER_RADIUS, -BORDER_RADIUS),
    line((HORIZONTAL_OFFSET - BORDER_RADIUS) * -1, 0),
    arc(-BORDER_RADIUS, BORDER_RADIUS),
    line(0, VERTICAL_OFFSET - BORDER_RADIUS),
  ].join(', ');

  const labelX = x + width! + HORIZONTAL_OFFSET - HORIZONTAL_START_OFFSET / 2;
  const labelY = y + height! / 2;

  return [path, labelX, labelY];
}

const line = (x: number, y: number) => `l ${x} ${y}`;

const arc = (x: number, y: number, sweep = false) =>
  `a ${x} ${x} 0 0 ${sweep ? 1 : 0} ${x} ${y}`;
