import { useMemo, useState, type ReactNode } from 'react';
import { styled } from 'styled-components';
import { SizeMap } from './SizeMap';
import { formatBytes } from '../helpers/formatBytes';
import { ContainerWide } from './Containers';
import { Main } from './Main';
import {
  tileKind,
  type StorageNode,
  type TileKind,
} from '../helpers/storageMap';

export type Loaded =
  | { state: 'loading' }
  | { state: 'failed' }
  | { state: 'ready'; root: StorageNode };

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

  function openItem(item: StorageNode, at = { x: 50, y: 50 }) {
    if (hasInside(item)) {
      setMotion({ dir: 'in', ...at });
      setTrail([...trail, item.subject]);

      return;
    }

    onOpen(item.subject);
  }

  return (
    <Main>
      <ContainerWide>
        <h1>Server storage</h1>
        <Intro data-testid='storage-scope'>
          This is the current copy on your server, including resource history
          and attached files. Cloud Vault backup storage is shown separately in
          sync settings.
        </Intro>
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

            {items.every(item => item.totalBytes <= 0) ? (
              <p data-testid='storage-empty'>Nothing here takes up space.</p>
            ) : (
              <SizeMap
                key={trail.join('/')}
                motion={motion}
                onSelect={openItem}
                items={items.map(item => ({
                  id: item.subject + item.name,
                  value: item,
                  label: item.name,
                  bytes: item.totalBytes,
                  colour: KIND_COLOURS[tileKind(item, hasInside(item))],
                  folder: hasInside(item),
                  detail: hasInside(item)
                    ? `${item.children.length} inside`
                    : undefined,
                  title: hasInside(item)
                    ? `${item.name} · ${formatBytes(item.totalBytes)} · click to look inside`
                    : `${item.name} · ${formatBytes(item.totalBytes)} · click to open`,
                }))}
              />
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
