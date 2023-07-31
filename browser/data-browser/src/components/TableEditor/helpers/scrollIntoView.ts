const calculateHorizontalScrollDistance = (
  nodeRect: DOMRect,
  scrollerRect: DOMRect,
  currentScrollPosition: number,
): number => {
  const indicatorLeftEdge =
    currentScrollPosition + nodeRect.left - scrollerRect.left;

  if (nodeRect.left <= scrollerRect.left) {
    return indicatorLeftEdge;
  }

  const indicatorRightEdge = indicatorLeftEdge + nodeRect.width;

  return indicatorRightEdge - scrollerRect.width;
};

/**
 * Scrolls the scroller horizontally to the given cell.
 */
export function scrollIntoView(
  scrollerNode: HTMLDivElement,
  scrollerRect: DOMRect,
  cellRect: DOMRect,
) {
  requestAnimationFrame(() => {
    const distance = calculateHorizontalScrollDistance(
      cellRect,
      scrollerRect,
      scrollerNode.scrollLeft,
    );

    scrollerNode.scroll(distance, 0);
  });
}
