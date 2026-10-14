import { keyframes, styled } from 'styled-components';
import { squarify } from '../helpers/storageMap';
import { formatBytes } from '../helpers/formatBytes';

const MAP_WIDTH = 1000;
const MAP_HEIGHT = 560;

export type SizeMapItem<T> = {
  id: string;
  label: string;
  bytes: number;
  colour: string;
  value: T;
  folder?: boolean;
  detail?: string;
  title?: string;
};

/** Shared area-proportional layout and tile rendering for resources and backups. */
export function SizeMap<T>({
  items,
  onSelect,
  motion,
  testId = 'storage',
}: {
  items: SizeMapItem<T>[];
  onSelect: (value: T, at: { x: number; y: number }) => void;
  motion?: { dir: 'in' | 'out'; x: number; y: number } | null;
  testId?: string;
}) {
  const tiles = squarify(items, item => item.bytes, {
    x: 0,
    y: 0,
    w: MAP_WIDTH,
    h: MAP_HEIGHT,
  });

  return (
    <MapBox
      data-testid={`${testId}-map`}
      $dir={motion?.dir}
      style={{
        aspectRatio: `${MAP_WIDTH} / ${MAP_HEIGHT}`,
        transformOrigin: `${motion?.x ?? 50}% ${motion?.y ?? 50}%`,
      }}
    >
      {tiles.map(({ item, rect }) => (
        <Tile
          key={item.id}
          type='button'
          $colour={item.colour}
          $folder={!!item.folder}
          data-testid={`${testId}-tile`}
          data-folder={item.folder ? 'true' : undefined}
          title={item.title ?? `${item.label} · ${formatBytes(item.bytes)}`}
          onClick={() =>
            onSelect(item.value, {
              x: ((rect.x + rect.w / 2) / MAP_WIDTH) * 100,
              y: ((rect.y + rect.h / 2) / MAP_HEIGHT) * 100,
            })
          }
          style={{
            left: `${(rect.x / MAP_WIDTH) * 100}%`,
            top: `${(rect.y / MAP_HEIGHT) * 100}%`,
            width: `${(rect.w / MAP_WIDTH) * 100}%`,
            height: `${(rect.h / MAP_HEIGHT) * 100}%`,
          }}
        >
          <TileLabel>
            <span>
              {item.folder && <FolderMark aria-hidden>▸</FolderMark>}
              {item.label}
            </span>
            <span>
              {formatBytes(item.bytes)}
              {item.detail && ` · ${item.detail}`}
            </span>
          </TileLabel>
        </Tile>
      ))}
    </MapBox>
  );
}

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

const Tile = styled.button<{ $colour: string; $folder: boolean }>`
  position: absolute;
  box-sizing: border-box;
  padding: 4px 6px;
  border: 1px solid ${p => p.theme.colors.bg};
  background: ${p => p.$colour};
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
