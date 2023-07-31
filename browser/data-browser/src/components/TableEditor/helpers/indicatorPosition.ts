export function getLeft(
  tableLeftOffset: number,
  relativeStart: number,
  cellRect: DOMRect,
  cornerRect: DOMRect | undefined,
): number {
  if (!cornerRect) {
    return cellRect.left - tableLeftOffset + relativeStart - 1;
  }

  return (
    Math.min(
      cellRect.left - tableLeftOffset,
      cornerRect.left - tableLeftOffset,
    ) +
    relativeStart -
    1
  );
}

export function getTop(
  relativeStart: number,
  cellRect: DOMRect,
  cornerRect: DOMRect | undefined,
): number {
  if (!cornerRect) {
    return cellRect.top - relativeStart - 1;
  }

  return Math.min(cellRect.top, cornerRect.top) - relativeStart - 1;
}

export function getWidth(
  cellRect: DOMRect,
  cornerRect: DOMRect | undefined,
): number {
  if (!cornerRect) {
    return cellRect.width + 1;
  }

  const leftEdge = Math.min(cellRect.left, cornerRect.left);

  const rightEdge = Math.max(
    cellRect.left + cellRect.width,
    cornerRect.left + cornerRect.width,
  );

  return rightEdge - leftEdge + 1;
}

export function getHeight(
  cellRect: DOMRect,
  cornerRect: DOMRect | undefined,
): number {
  if (!cornerRect) {
    return cellRect.height + 1;
  }

  const topEdge = Math.min(cellRect.top, cornerRect.top);

  const bottomEdge = Math.max(
    cellRect.top + cellRect.height,
    cornerRect.top + cornerRect.height,
  );

  return bottomEdge - topEdge + 1;
}

export function getTopBasedOnPreviousHeight(
  relativeStart: number,
  cellRect: DOMRect,
  cornerRect: DOMRect,
  previousHeight: number,
  cellOnTop: boolean,
): number {
  const offset = relativeStart - 1;

  if (cellOnTop && cellRect.height === 0) {
    // Scrolling down, cellRect is out of view.
    return cornerRect.top + cornerRect.height - previousHeight - offset;
  }

  if (!cellOnTop && cornerRect.height === 0) {
    // Scrolling down, cornerRect is out of view.
    return cellRect.top + cellRect.height - previousHeight - offset;
  }

  if (cellOnTop && cornerRect.height === 0) {
    // Scrolling up, cornerRect is out of view.
    return cellRect.top - offset;
  }

  if (!cellOnTop && cellRect.height === 0) {
    // Scrolling up, cellRect is out of view.
    return cornerRect.top - offset;
  }

  return 0;
}
