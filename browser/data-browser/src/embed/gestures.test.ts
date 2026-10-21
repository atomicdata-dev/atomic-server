// @vitest-environment jsdom
// @wc-ignore-file
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  claimGestures,
  installTouchGestures,
  needsHorizontalDrag,
  resetGesturesForTest,
  setGestures,
} from './gestures';

describe('embed gestures', () => {
  const post = vi.fn();

  beforeEach(() => {
    resetGesturesForTest();
    post.mockClear();
    window.AtomicFlutter = { postMessage: post };
  });

  afterEach(() => {
    delete window.AtomicFlutter;
  });

  const modes = () => post.mock.calls.map(c => JSON.parse(c[0]).mode);

  it('posts once per change', () => {
    const a = claimGestures('horizontal');
    const b = claimGestures('horizontal');

    expect(modes()).toEqual(['horizontal']);
    a();
    expect(modes()).toEqual(['horizontal']);
    b();
    expect(modes()).toEqual(['horizontal', 'default']);
  });

  it('posts nothing for the default', () => {
    claimGestures('default')();
    expect(post).not.toHaveBeenCalled();
  });

  it('setGestures replaces the claims', () => {
    setGestures('horizontal');
    setGestures('default');
    expect(modes()).toEqual(['horizontal', 'default']);
  });

  it('is a no-op outside the app', () => {
    delete window.AtomicFlutter;
    expect(() => claimGestures('horizontal')()).not.toThrow();
    expect(post).not.toHaveBeenCalled();
  });

  describe('touches', () => {
    const touch = (target: Element, type: string, touches = 1) => {
      const e = new Event(type, { bubbles: true }) as Event & {
        touches: unknown[];
      };

      e.touches = new Array(touches).fill({});
      target.dispatchEvent(e);
    };

    beforeEach(() => {
      document.body.innerHTML = `
        <p id="text">hello</p>
        <canvas id="canvas"></canvas>
        <div id="scroller" style="overflow-x: auto"><span id="inner">x</span></div>
        <div id="clipped" style="overflow-x: auto"><span id="clippedInner">x</span></div>
        <table><tbody><tr><td id="cell">1</td></tr></tbody></table>`;
      const scroller = document.getElementById('scroller')!;

      Object.defineProperty(scroller, 'scrollWidth', { value: 900 });
      Object.defineProperty(scroller, 'clientWidth', { value: 300 });
      installTouchGestures();
    });

    it('declares horizontal on a canvas, a scroller and a table, and resets', () => {
      const canvas = document.getElementById('canvas')!;

      touch(canvas, 'touchstart');
      touch(canvas, 'touchend');
      touch(document.getElementById('inner')!, 'touchstart');
      touch(document.getElementById('inner')!, 'touchcancel');
      touch(document.getElementById('cell')!, 'touchstart');
      touch(document.getElementById('cell')!, 'touchend');
      expect(modes()).toEqual([
        'horizontal',
        'default',
        'horizontal',
        'default',
        'horizontal',
        'default',
      ]);
    });

    it('posts nothing for plain text or a scroller with nothing to scroll', () => {
      touch(document.getElementById('text')!, 'touchstart');
      touch(document.getElementById('text')!, 'touchend');
      touch(document.getElementById('clippedInner')!, 'touchstart');
      expect(post).not.toHaveBeenCalled();
      expect(needsHorizontalDrag(document.getElementById('text'))).toBe(false);
    });

    it('stays horizontal for a page-wide claim after the touch ends', () => {
      const release = claimGestures('horizontal');

      touch(document.getElementById('canvas')!, 'touchstart');
      touch(document.getElementById('canvas')!, 'touchend');
      expect(modes()).toEqual(['horizontal']);
      release();
      expect(modes()).toEqual(['horizontal', 'default']);
    });
  });
});
