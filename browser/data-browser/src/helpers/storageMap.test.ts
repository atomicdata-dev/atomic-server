import { describe, expect, it } from 'vitest';
import {
  buildStorageTree,
  squarify,
  tileKind,
  type ResourceUsage,
  type StorageNode,
} from './storageMap';

const row = (
  subject: string,
  parent: string | null,
  loroBytes: number,
  blobBytes = 0,
): ResourceUsage => ({
  subject,
  name: subject,
  parent,
  isA: null,
  loroBytes,
  blobBytes,
});

describe('buildStorageTree', () => {
  it('rolls sizes up and sorts the biggest first', () => {
    const tree = buildStorageTree(
      [
        row('drive', null, 10),
        row('folder', 'drive', 20),
        row('big-file', 'folder', 5, 1000),
        row('note', 'drive', 100),
      ],
      'drive',
    );

    expect(tree.totalBytes).toBe(10 + 20 + 1005 + 100);
    expect(tree.totalFileBytes).toBe(1000);
    expect(tree.children.map(c => c.subject)).toEqual(['folder', 'note']);
    expect(tree.children[0].children[0].subject).toBe('big-file');
  });

  it('survives a parent cycle and a row with an unknown parent', () => {
    const tree = buildStorageTree(
      [
        row('drive', null, 1),
        row('a', 'b', 5),
        row('b', 'a', 5),
        row('c', 'gone', 7),
      ],
      'drive',
    );

    expect(tree.totalBytes).toBeGreaterThanOrEqual(8);
    expect(tree.children.some(c => c.subject === 'c')).toBe(true);
  });
});

describe('squarify', () => {
  it('fills the rectangle with areas proportional to the values', () => {
    const rect = { x: 0, y: 0, w: 1000, h: 600 };
    const tiles = squarify([6, 6, 4, 3, 2, 2, 1], v => v, rect);
    const area = tiles.reduce((s, t) => s + t.rect.w * t.rect.h, 0);

    expect(area).toBeCloseTo(rect.w * rect.h, 0);

    const six = tiles[0].rect.w * tiles[0].rect.h;
    const one = tiles[tiles.length - 1].rect.w * tiles[tiles.length - 1].rect.h;

    expect(six / one).toBeCloseTo(6, 3);
  });

  it('drops empty items', () => {
    expect(squarify([0, 5], v => v, { x: 0, y: 0, w: 10, h: 10 })).toHaveLength(
      1,
    );
  });
});

describe('tileKind', () => {
  const node = (totalBytes: number, totalFileBytes: number): StorageNode => ({
    subject: 'x',
    name: 'x',
    kind: null,
    ownBytes: totalBytes,
    ownFileBytes: totalFileBytes,
    totalBytes,
    totalFileBytes,
    children: [],
  });

  it('tells the four kinds apart', () => {
    expect(tileKind(node(100, 0), false)).toBe('edge');
    expect(tileKind(node(100, 0), true)).toBe('branch');
    expect(tileKind(node(100, 40), true)).toBe('mixed');
    expect(tileKind(node(100, 95), true)).toBe('binary');
    expect(tileKind(node(100, 80), false)).toBe('binary');
  });
});
