import { useMemo, useState, type ReactNode } from 'react';
import { keyframes, styled } from 'styled-components';
import { ContainerWide } from './Containers';
import { Main } from './Main';
import {
  squarify,
  tileKind,
  type StorageNode,
  type TileKind,
} from '../helpers/storageMap';

export type Loaded =
  | { state: 'loading' }
  | { state: 'failed' }
  | { state: 'ready'; root: StorageNode };

const MAP_W = 1000;
const MAP_H = 560;

/**
 * Where a drive's space goes, as a size map (like WizTree or dua): one tile per
 * item, area proportional to its size, files and edit history told apart.
 * Click a folder to look inside it; the list underneath is the same data for
 * small screens and screen readers.
 */
export function StorageView({
  loaded,
  onOpen,
  backTo,
  startAt,
}: {
  loaded: Loaded;
  /** Open the map inside this resource, for "Space usage" in its menu. */
  startAt?: string;
  onOpen: (subject: string) => void;
  /** Rendered under the map; the host decides where "back" goes. */
  backTo?: ReactNode;
}) {
  const [trail, setTrail] = useState<string[]>([]);
  const [startedAt, setStartedAt] = useState<string | undefined>();
  // How the map last changed, so the new tiles can grow out of (or shrink back
  // to) the place the person clicked.
  const [motion, setMotion] = useState<{
    dir: 'in' | 'out';
    x: number;
    y: number;
  } | null>(null);

  // Jump to the asked-for resource once, as soon as the data is there.
  if (loaded.state === 'ready' && startAt && startAt !== startedAt) {
    setStartedAt(startAt);
    setTrail(pathTo(loaded.root, startAt));
  }

  const current = useMemo(() => {
    if (loaded.state !== 'ready') return null;

    let node = loaded.root;
    const path: StorageNode[] = [node];

    for (const subject of trail) {
      const next = node.children.find(c => c.subject === subject);

      if (!next) break;
      node = next;
      path.push(node);
    }

    return { node, path };
  }, [loaded, trail]);

  const items = useMemo(() => {
    if (!current) return [];

    const { node } = current;
    // What the item itself holds, apart from what is inside it.
    const self: StorageNode[] =
      node.children.length > 0 && node.ownBytes > 0
        ? [
            {
              ...node,
              name: 'This item itself',
              totalBytes: node.ownBytes,
              totalFileBytes: node.ownFileBytes,
              children: [],
            },
          ]
        : [];

    return [...node.children, ...self].sort(
      (a, b) => b.totalBytes - a.totalBytes,
    );
  }, [current]);

  const tiles = useMemo(
    () =>
      squarify(items, i => i.totalBytes, { x: 0, y: 0, w: MAP_W, h: MAP_H }),
    [items],
  );

  return (
    <Main>
      <ContainerWide>
        <h1>Where space goes</h1>
        <Intro>
          Each tile is an item in this workspace. Bigger tile, more space.
        </Intro>

        {loaded.state === 'loading' && (
          <p data-testid='storage-loading'>Measuring…</p>
        )}
        {loaded.state === 'failed' && (
          <p data-testid='storage-failed'>
            This server could not report storage for the workspace. It may be an
            older version, or you may not be allowed to read it.
          </p>
        )}

        {current && (
          <>
            <Crumbs aria-label='Location'>
              {current.path.map((n, i) => (
                <span key={n.subject}>
                  {i > 0 && ' / '}
                  {i < current.path.length - 1 ? (
                    <CrumbButton
                      type='button'
                      onClick={() => {
                        setMotion({ dir: 'out', x: 50, y: 50 });
                        setTrail(trail.slice(0, i));
                      }}
                    >
                      {n.name}
                    </CrumbButton>
                  ) : (
                    <strong>{n.name}</strong>
                  )}
                </span>
              ))}{' '}
              <Muted>· {formatBytes(current.node.totalBytes)}</Muted>
            </Crumbs>

            {tiles.length === 0 ? (
              <p data-testid='storage-empty'>Nothing here takes up space.</p>
            ) : (
              <MapBox
                // A new key restarts the animation for every level.
                key={trail.join('/')}
                data-testid='storage-map'
                $dir={motion?.dir}
                style={{
                  aspectRatio: `${MAP_W} / ${MAP_H}`,
                  transformOrigin: `${motion?.x ?? 50}% ${motion?.y ?? 50}%`,
                }}
              >
                {tiles.map(({ item, rect }) => (
                  <Tile
                    key={item.subject + item.name}
                    type='button'
                    $kind={tileKind(item, hasInside(item))}
                    $folder={hasInside(item)}
                    data-testid='storage-tile'
                    data-folder={hasInside(item) ? 'true' : undefined}
                    title={
                      hasInside(item)
                        ? `${item.name} · ${formatBytes(item.totalBytes)} · click to look inside`
                        : `${item.name} · ${formatBytes(item.totalBytes)} · click to open`
                    }
                    onClick={() =>
                      openItem(item, {
                        x: ((rect.x + rect.w / 2) / MAP_W) * 100,
                        y: ((rect.y + rect.h / 2) / MAP_H) * 100,
                      })
                    }
                    style={{
                      left: `${(rect.x / MAP_W) * 100}%`,
                      top: `${(rect.y / MAP_H) * 100}%`,
                      width: `${(rect.w / MAP_W) * 100}%`,
                      height: `${(rect.h / MAP_H) * 100}%`,
                    }}
                  >
                    <TileLabel>
                      <span>
                        {hasInside(item) && (
                          <FolderMark aria-hidden>▸</FolderMark>
                        )}
                        {item.name}
                      </span>
                      <Muted>
                        {formatBytes(item.totalBytes)}
                        {hasInside(item) && ` · ${item.children.length} inside`}
                      </Muted>
                    </TileLabel>
                  </Tile>
                ))}
              </MapBox>
            )}

            <Legend aria-label='Colours'>
              <li>
                <Swatch $kind='edge' /> resource
              </li>
              <li>
                <Swatch $kind='branch' /> resource with other resources
              </li>
              <li>
                <Swatch $kind='mixed' /> mixed (files and resources)
              </li>
              <li>
                <Swatch $kind='binary' /> file or image
              </li>
            </Legend>

            <List data-testid='storage-list'>
              {items.slice(0, 50).map(item => (
                <li key={item.subject + item.name}>
                  <Bar
                    style={{
                      width: `${Math.max(
                        1,
                        (item.totalBytes / (items[0]?.totalBytes || 1)) * 100,
                      )}%`,
                    }}
                    $kind={tileKind(item, hasInside(item))}
                  />
                  <ListRow>
                    <button type='button' onClick={() => openItem(item)}>
                      {item.name}
                    </button>
                    <Muted>{item.kind ?? ''}</Muted>
                    <span>{formatBytes(item.totalBytes)}</span>
                  </ListRow>
                </li>
              ))}
            </List>
          </>
        )}

        {backTo}
      </ContainerWide>
    </Main>
  );

  function openItem(item: StorageNode, at = { x: 50, y: 50 }) {
    if (hasInside(item)) {
      setMotion({ dir: 'in', ...at });
      setTrail([...trail, item.subject]);

      return;
    }

    onOpen(item.subject);
  }
}

/** The subjects from just below `root` down to `target`; empty when it is not in the tree. */
function pathTo(root: StorageNode, target: string): string[] {
  if (root.subject === target) return [];

  for (const child of root.children) {
    const rest = pathTo(child, target);

    if (child.subject === target) return [child.subject];

    if (rest.length > 0) return [child.subject, ...rest];
  }

  return [];
}

/** Folders open the map one level deeper; everything else opens the resource. */
function hasInside(item: StorageNode): boolean {
  return item.children.length > 0 && item.name !== 'This item itself';
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unit = 0;

  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }

  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

const Legend = styled.ul`
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem 1.25rem;
  margin: 0.5rem 0 1rem;
  padding: 0;
  list-style: none;
  font-size: 0.78rem;
  color: ${p => p.theme.colors.textLight};
`;

const Intro = styled.p`
  color: ${p => p.theme.colors.textLight};
`;

const Muted = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const KIND_COLOURS: Record<TileKind, string> = {
  edge: '#3b6fe0',
  branch: '#7b4fd6',
  mixed: '#1f9d8a',
  binary: '#d9822b',
};

const Swatch = styled.span<{ $kind: TileKind }>`
  display: inline-block;
  width: 0.8em;
  height: 0.8em;
  border-radius: 2px;
  background: ${p => KIND_COLOURS[p.$kind]};
`;

const Crumbs = styled.nav`
  margin: 0.5rem 0;
`;

const CrumbButton = styled.button`
  padding: 0;
  border: none;
  background: none;
  color: ${p => p.theme.colors.main};
  text-decoration: underline;
  cursor: pointer;
`;

const growIn = keyframes`
  from {
    opacity: 0;
    transform: scale(0.5);
  }

  to {
    opacity: 1;
    transform: scale(1);
  }
`;

const shrinkBack = keyframes`
  from {
    opacity: 0;
    transform: scale(1.4);
  }

  to {
    opacity: 1;
    transform: scale(1);
  }
`;

const MapBox = styled.div<{ $dir?: 'in' | 'out' }>`
  position: relative;
  animation: ${p =>
      p.$dir === 'in' ? growIn : p.$dir === 'out' ? shrinkBack : 'none'}
    260ms ease-out;

  @media (prefers-reduced-motion: reduce) {
    animation: none;
  }

  width: 100%;
  min-height: 220px;
  border-radius: 8px;
  overflow: hidden;
  background: ${p => p.theme.colors.bg1};
`;

const Tile = styled.button<{ $kind: TileKind; $folder: boolean }>`
  position: absolute;
  box-sizing: border-box;
  padding: 4px 6px;
  border: 1px solid ${p => p.theme.colors.bg};
  background: ${p => KIND_COLOURS[p.$kind]};
  color: #fff;
  text-align: left;
  cursor: ${p => (p.$folder ? 'zoom-in' : 'pointer')};
  overflow: hidden;
  /* A tile with things inside gets an inner frame, like a folder; a leaf is flat. */
  box-shadow: ${p =>
    p.$folder ? 'inset 0 0 0 3px rgba(255, 255, 255, 0.28)' : 'none'};

  &:hover,
  &:focus-visible {
    filter: brightness(1.12);
  }
`;

const FolderMark = styled.span`
  margin-right: 0.3em;
  opacity: 0.85;
`;

const TileLabel = styled.span`
  display: flex;
  flex-direction: column;
  font-size: 0.78rem;
  line-height: 1.25;
  overflow: hidden;

  & > span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: inherit;
  }
`;

const List = styled.ol`
  list-style: none;
  margin: 1rem 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;

  li {
    position: relative;
  }
`;

const Bar = styled.span<{ $kind: TileKind }>`
  position: absolute;
  inset: 0 auto 0 0;
  background: ${p => KIND_COLOURS[p.$kind]};
  opacity: 0.18;
  border-radius: 4px;
`;

const ListRow = styled.div`
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto auto;
  gap: 1rem;
  padding: 0.25rem 0.5rem;

  button {
    padding: 0;
    border: none;
    background: none;
    color: inherit;
    text-align: left;
    cursor: pointer;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
`;
