import { useLayoutEffect } from 'react';

/** Keeps a few rows of the list reachable, even in a very short window. */
const MIN_HEIGHT_PX = 200;

/** Breathing room between the bottom of the grid and the bottom of the page. */
const BOTTOM_GAP_PX = 16;

const getScrollParent = (element: HTMLElement): HTMLElement => {
  let current = element.parentElement;

  while (current) {
    const { overflowY } = getComputedStyle(current);

    if (
      (overflowY === 'auto' || overflowY === 'scroll') &&
      current.scrollHeight > 0
    ) {
      return current;
    }

    current = current.parentElement;
  }

  return document.documentElement;
};

/**
 * Sizes the grid to the space its scroll parent has left below it, as
 * `--table-height`.
 *
 * The row list is the only thing that should scroll vertically — that is what
 * keeps the header row visible. A grid that reaches past the bottom of the page
 * hands that job to the page instead: the wheel scrolls the whole resource
 * (taking the header with it) whenever the pointer is not over the rows, and
 * comes to rest in the empty space the page keeps below its content. Ending the
 * grid where its scroll parent ends means there is nothing left for the page to
 * scroll.
 */
export function useAvailableHeight(
  tableRef: React.RefObject<HTMLDivElement | null>,
  headerRef: React.RefObject<HTMLDivElement | null>,
) {
  useLayoutEffect(() => {
    const table = tableRef.current;

    if (!table) {
      return;
    }

    const scrollParent = getScrollParent(table);

    const measure = () => {
      // Distance from the top of the scroll parent's content to the top of the
      // grid — everything above it (title, view tabs, filter bar, cover image).
      const offsetTop =
        table.getBoundingClientRect().top -
        scrollParent.getBoundingClientRect().top +
        scrollParent.scrollTop;

      // `--table-height` bounds the row list alone, so the parts of the grid
      // that sit outside it come off the budget first.
      const styles = getComputedStyle(table);
      const chrome =
        (headerRef.current?.offsetHeight ?? 0) +
        Number.parseFloat(styles.borderTopWidth) +
        Number.parseFloat(styles.borderBottomWidth);

      const available = Math.max(
        scrollParent.clientHeight - offsetTop - chrome - BOTTOM_GAP_PX,
        MIN_HEIGHT_PX,
      );

      const previous = Number.parseFloat(
        table.style.getPropertyValue('--table-height'),
      );

      // Writing on every observation would loop: our own height change resizes
      // the container we observe. Settling for sub-pixel differences ends it.
      if (Math.abs(available - previous) < 1) {
        return;
      }

      table.style.setProperty('--table-height', `${available}px`);
    };

    measure();

    // Observing an ancestor and resizing its descendant in the same delivery
    // can leave notifications undelivered. Measure once in the next frame so
    // filter/title changes settle outside ResizeObserver's delivery loop.
    let frame: number | undefined;

    const scheduleMeasure = () => {
      if (frame !== undefined) return;
      frame = requestAnimationFrame(() => {
        frame = undefined;
        measure();
      });
    };

    // The scroll parent itself covers window resizes and sidebar toggles; its
    // children cover anything that pushes the grid further down the page — a
    // cover image loading, the filter bar appearing, a title wrapping.
    const resizeObserver = new ResizeObserver(scheduleMeasure);

    const observeContent = () => {
      resizeObserver.disconnect();

      for (const target of [
        scrollParent,
        ...scrollParent.children,
        table.parentElement,
      ]) {
        if (target) {
          resizeObserver.observe(target);
        }
      }
    };

    observeContent();

    // A cover image is added to and removed from the page rather than resized,
    // which no ResizeObserver sees. Re-measure, and pick the new element up.
    const mutationObserver = new MutationObserver(() => {
      observeContent();
      scheduleMeasure();
    });
    mutationObserver.observe(scrollParent, { childList: true });

    return () => {
      resizeObserver.disconnect();
      mutationObserver.disconnect();
      if (frame !== undefined) cancelAnimationFrame(frame);
    };
  }, [tableRef, headerRef]);
}
