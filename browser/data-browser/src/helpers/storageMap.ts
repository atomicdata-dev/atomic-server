/** One resource's share of a drive, from `GET /drive-usage/breakdown`. */
export type ResourceUsage = {
  subject: string;
  name: string | null;
  parent: string | null;
  isA: string | null;
  /** Edit history held for the resource (its Loro snapshot). */
  loroBytes: number;
  /** Bytes of an attached file, counted once however many resources use it. */
  blobBytes: number;
};

export type StorageNode = {
  subject: string;
  name: string;
  kind: string | null;
  /** This resource alone. */
  ownBytes: number;
  ownFileBytes: number;
  /** This resource plus everything below it. */
  totalBytes: number;
  totalFileBytes: number;
  children: StorageNode[];
};

/** Last path segment of a class URL, for a label such as "Document". */
function kindOf(isA: string | null): string | null {
  if (!isA) return null;

  const tail = isA.split(/[/#]/).filter(Boolean).pop();

  return tail ?? null;
}

function nameOf(row: ResourceUsage): string {
  if (row.name?.trim()) return row.name.trim();

  const tail = row.subject.split(/[/#]/).filter(Boolean).pop();

  return tail && tail.length > 24
    ? `${tail.slice(0, 12)}…`
    : (tail ?? 'Untitled');
}

/**
 * Arrange rows into the drive's folder tree, with sizes rolled up. A row whose
 * parent is not in the set (the drive itself, or something moved out) becomes a
 * root; the drive row is returned as the tree's root when present.
 */
export function buildStorageTree(
  rows: ResourceUsage[],
  driveSubject: string,
): StorageNode {
  const nodes = new Map<string, StorageNode>();

  for (const row of rows) {
    nodes.set(row.subject, {
      subject: row.subject,
      name: nameOf(row),
      kind: kindOf(row.isA),
      ownBytes: row.loroBytes + row.blobBytes,
      ownFileBytes: row.blobBytes,
      totalBytes: 0,
      totalFileBytes: 0,
      children: [],
    });
  }

  const root: StorageNode = nodes.get(driveSubject) ?? {
    subject: driveSubject,
    name: 'This workspace',
    kind: 'Drive',
    ownBytes: 0,
    ownFileBytes: 0,
    totalBytes: 0,
    totalFileBytes: 0,
    children: [],
  };

  for (const row of rows) {
    const node = nodes.get(row.subject)!;

    if (node === root) continue;

    const parent = row.parent ? nodes.get(row.parent) : undefined;

    (parent && parent !== node ? parent : root).children.push(node);
  }

  // Guard against a parent cycle: only follow each node once.
  const seen = new Set<string>();

  const roll = (node: StorageNode) => {
    seen.add(node.subject);
    node.totalBytes = node.ownBytes;
    node.totalFileBytes = node.ownFileBytes;
    node.children = node.children.filter(c => !seen.has(c.subject));

    for (const child of node.children) {
      roll(child);
      node.totalBytes += child.totalBytes;
      node.totalFileBytes += child.totalFileBytes;
    }

    node.children.sort((a, b) => b.totalBytes - a.totalBytes);
  };

  roll(root);

  return root;
}

export type Rect = { x: number; y: number; w: number; h: number };
export type Tile<T> = { item: T; rect: Rect };

/**
 * Squarified treemap (Bruls et al.): lays `items` out in `rect` so each tile's
 * area is proportional to its value and tiles stay close to square, which keeps
 * labels readable. Items with no size are dropped.
 */
export function squarify<T>(
  items: T[],
  value: (item: T) => number,
  rect: Rect,
): Tile<T>[] {
  const sized = items
    .map(item => ({ item, v: value(item) }))
    .filter(i => i.v > 0)
    .sort((a, b) => b.v - a.v);
  const total = sized.reduce((sum, i) => sum + i.v, 0);

  if (total <= 0) return [];

  const scale = (rect.w * rect.h) / total;
  const out: Tile<T>[] = [];
  let free = { ...rect };
  let row: typeof sized = [];

  const worst = (areas: number[], side: number) => {
    const sum = areas.reduce((a, b) => a + b, 0);
    const max = Math.max(...areas);
    const min = Math.min(...areas);

    return Math.max(
      (side * side * max) / (sum * sum),
      (sum * sum) / (side * side * min),
    );
  };

  const place = () => {
    const areas = row.map(i => i.v * scale);
    const sum = areas.reduce((a, b) => a + b, 0);
    const horizontal = free.w >= free.h;
    const side = horizontal ? free.h : free.w;
    const thickness = sum / side;
    let offset = 0;

    row.forEach((entry, index) => {
      const length = areas[index] / thickness;

      out.push({
        item: entry.item,
        rect: horizontal
          ? { x: free.x, y: free.y + offset, w: thickness, h: length }
          : { x: free.x + offset, y: free.y, w: length, h: thickness },
      });
      offset += length;
    });

    free = horizontal
      ? { x: free.x + thickness, y: free.y, w: free.w - thickness, h: free.h }
      : { x: free.x, y: free.y + thickness, w: free.w, h: free.h - thickness };
    row = [];
  };

  for (const entry of sized) {
    const side = Math.min(free.w, free.h);
    const current = row.map(i => i.v * scale);
    const next = [...current, entry.v * scale];

    if (row.length === 0 || worst(next, side) <= worst(current, side)) {
      row.push(entry);
    } else {
      place();
      row.push(entry);
    }
  }

  if (row.length) place();

  return out;
}

/**
 * What a tile is made of, for its colour:
 * - `edge`: a resource with nothing below it (its own data and history);
 * - `branch`: a resource with other resources below it, and next to no files;
 * - `mixed`: resources and binary files together;
 * - `binary`: mostly attached files.
 */
export type TileKind = 'edge' | 'branch' | 'mixed' | 'binary';

export function tileKind(node: StorageNode, hasInside: boolean): TileKind {
  const share = node.totalBytes > 0 ? node.totalFileBytes / node.totalBytes : 0;

  if (share >= 0.9) return 'binary';
  if (!hasInside) return share > 0.5 ? 'binary' : 'edge';
  if (share < 0.1) return 'branch';

  return 'mixed';
}
