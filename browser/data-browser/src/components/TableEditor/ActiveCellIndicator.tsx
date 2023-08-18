import { transparentize } from 'polished';
import React, { useCallback, useEffect, useState } from 'react';
import { styled } from 'styled-components';
import {
  getHeight,
  getLeft,
  getTop,
  getTopBasedOnPreviousHeight,
  getWidth,
} from './helpers/indicatorPosition';
import { scrollIntoView } from './helpers/scrollIntoView';
import { CursorMode, useTableEditorContext } from './TableEditorContext';

export interface ActiveCellIndicatorProps {
  sizeStr: string;
  scrollerRef: React.RefObject<HTMLDivElement>;
  setOnScroll: (onScroll: () => void) => void;
}

const cursorGoesOffscreen = (parentRect: DOMRect, childRect: DOMRect) => {
  return childRect.left < parentRect.left || childRect.right > parentRect.right;
};

const getCornerIfMultiSelect = (
  cursorMode: CursorMode,
  ref: React.MutableRefObject<HTMLDivElement | null>,
) => {
  if (cursorMode === CursorMode.MultiSelect && ref.current) {
    return ref.current.getBoundingClientRect();
  }

  return undefined;
};

export function ActiveCellIndicator({
  sizeStr,
  scrollerRef,
  setOnScroll,
}: ActiveCellIndicatorProps): JSX.Element | null {
  const [visible, setVisible] = useState(false);
  const [scrolling, setScrolling] = useState(false);
  const [transitioningOffscreen, setTransitioningOffscreen] = useState(false);

  const [{ top, left, width, height }, setSize] = useState({
    top: 0,
    left: 0,
    width: 0,
    height: 0,
  });

  const {
    selectedColumn,
    selectedRow,
    multiSelectCornerColumn,
    multiSelectCornerRow,
    activeCellRef,
    isDragging,
    cursorMode,
    indicatorHidden,
    multiSelectCornerCellRef,
  } = useTableEditorContext();

  /** Measure the size and position of the current active cell and morph the indicator to the same values. */
  const updatePosition = useCallback(
    (followHorizontaly = true) => {
      if (!activeCellRef.current || !scrollerRef.current) {
        setVisible(false);

        return;
      }

      const cellRect = activeCellRef.current.getBoundingClientRect();
      const scrollerRect = scrollerRef.current.getBoundingClientRect();

      const cornerRect = getCornerIfMultiSelect(
        cursorMode,
        multiSelectCornerCellRef,
      );

      if (followHorizontaly && cursorGoesOffscreen(scrollerRect, cellRect)) {
        setTransitioningOffscreen(true);

        scrollIntoView(scrollerRef.current, scrollerRect, cellRect);
      } else {
        setTransitioningOffscreen(false);
      }

      if (
        cursorMode === CursorMode.MultiSelect &&
        (cellRect.height === 0 || cornerRect?.height === 0)
      ) {
        setSize(prev => ({
          top: getTopBasedOnPreviousHeight(
            scrollerRect.top,
            cellRect,
            cornerRect!,
            prev.height,
            (selectedRow ?? 0) < (multiSelectCornerRow ?? 0),
          ),
          left: prev.left,
          width: prev.width,
          height: prev.height,
        }));

        return;
      }

      setSize({
        top: getTop(scrollerRect.top, cellRect, cornerRect),
        left: getLeft(
          scrollerRect.left,
          scrollerRef.current!.scrollLeft!,
          cellRect,
          cornerRect,
        ),
        width: selectedColumn === 0 ? -1 : getWidth(cellRect, cornerRect),
        height: getHeight(cellRect, cornerRect),
      });
    },
    [
      selectedColumn,
      selectedRow,
      sizeStr,
      cursorMode,
      multiSelectCornerColumn,
      multiSelectCornerRow,
    ],
  );

  useEffect(() => {
    setOnScroll(() => (_, __, requested: boolean) => {
      if (requested) {
        return;
      }

      setScrolling(true);
      updatePosition(false);
    });
  }, [updatePosition]);

  useEffect(() => {
    if (selectedColumn === undefined || selectedRow === undefined) {
      setVisible(false);

      return;
    }

    setVisible(true);
    setScrolling(false);
    updatePosition();
  }, [
    selectedColumn,
    selectedRow,
    multiSelectCornerColumn,
    multiSelectCornerRow,
  ]);

  useEffect(() => {
    if (cursorMode === CursorMode.MultiSelect) {
      updatePosition(false);
    }
  }, [cursorMode, multiSelectCornerCellRef]);

  // When a user is changing the width of a column the indicator should change with it but should not trigger the horizontal auto following.
  useEffect(() => {
    setScrolling(false);
    updatePosition(false);
  }, [sizeStr]);

  if (!visible) {
    return <span></span>;
  }

  return (
    <Indicator
      top={top}
      left={left}
      width={width}
      height={height}
      noTransition={isDragging || scrolling || transitioningOffscreen}
      cursorMode={cursorMode}
      hidden={indicatorHidden}
    />
  );
}

interface IndicatorProps {
  top: number;
  left: number;
  width: number;
  height: number;
  noTransition: boolean;
  cursorMode: CursorMode;
  hidden: boolean;
}

const Indicator = styled.div.attrs<IndicatorProps>(p => ({
  style: {
    transform: `translate(${p.left}px, ${p.top}px)`,
    width:
      p.width > 0 ? `${p.width}px` : 'calc(var(--table-content-width) + 1px)',
    height: `${p.height}px`,
  },
}))<IndicatorProps>`
  --speed: ${p => (p.noTransition ? 0 : 70)}ms;
  visibility: ${p => (p.hidden ? 'hidden' : 'visible')};
  position: absolute;
  top: 0;
  left: 0;
  border: 2px solid ${p => p.theme.colors.main};
  pointer-events: none;
  will-change: transform, width;
  transition: transform var(--speed) ease-out, width var(--speed) ease-out,
    height var(--speed) ease-out;
  z-index: 1;
  background-color: ${p =>
    p.cursorMode === CursorMode.Edit
      ? 'none'
      : transparentize(0.85, p.theme.colors.main)};
`;
