import { useCallback, useEffect, useRef, useState } from 'react';
import { useResource, type Collection, type Resource } from '../index.js';
import React from 'react';

export interface VirtualizedCollectionListItemProps {
  index: number;
  collection: Collection;
  resource: Resource;
}

export interface VirtualizedCollectionListProps {
  collection: Collection;
  Loader?: React.ReactNode;
  children: (props: VirtualizedCollectionListItemProps) => React.ReactNode;
}

/**
 * A component that renders the members of a collection one after another.
 * It displays each member of a page and appends an IntersectionObserver to the bottom. If the observer becomes visible it will start loading the next page.
 */
export const VirtualizedCollectionList: React.FC<
  VirtualizedCollectionListProps
> = ({ collection, Loader, children }) => {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // A failed fetch ends the loading state; the list then shows no items.
    collection
      .waitForReady()
      .catch(() => undefined)
      .then(() => {
        setLoading(false);
      });
  }, [collection]);

  if (loading) {
    return Loader ?? null;
  }

  return (
    <VirtualizedCollectionListInner collection={collection}>
      {children}
    </VirtualizedCollectionListInner>
  );
};

function VirtualizedCollectionListInner({
  collection,
  children,
}: VirtualizedCollectionListProps) {
  const [currentPage, setCurrentPage] = useState(-1);
  const [pages, setPages] = useState<Map<number, string[]>>(new Map());

  const onIsVisible = useCallback(
    async (isVisible: boolean) => {
      const newPage = currentPage + 1;

      if (isVisible && newPage <= collection.totalPages - 1) {
        let newItems: string[];

        try {
          newItems = await collection.getMembersOnPage(newPage);
        } catch {
          return;
        }

        setCurrentPage(newPage);
        setPages(prevPages => new Map(prevPages).set(newPage, newItems));
      }
    },
    [collection, currentPage],
  );

  return (
    <>
      {Array.from(pages.values())
        .flat()
        .flatMap((subject, index) => (
          <Item
            key={subject}
            index={index}
            collection={collection}
            subject={subject}
            renderProp={children}
          />
        ))}
      <Intersector onIsVisible={onIsVisible} />
    </>
  );
}

interface ItemProps {
  index: number;
  collection: Collection;
  subject: string;
  renderProp: (props: VirtualizedCollectionListItemProps) => React.ReactNode;
}

const Item = ({ index, collection, subject, renderProp }: ItemProps) => {
  const resource = useResource(subject);

  return renderProp({ index, collection, resource });
};

interface IntersectorProps {
  onIsVisible(isVisible: boolean): void;
}

const Intersector: React.FC<IntersectorProps> = ({ onIsVisible }) => {
  const node = useRef<HTMLDivElement>(null);
  const [wasVisible, setWasVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(entries => {
      if (entries.length > 0) {
        const [entry] = entries;

        if (entry.isIntersecting && !wasVisible) {
          setWasVisible(true);
          onIsVisible(true);
        } else if (!entry.isIntersecting && wasVisible) {
          setWasVisible(false);
          onIsVisible(false);
        }
      }
    });

    if (node.current) {
      observer.observe(node.current);
    }

    return () => observer.disconnect();
  }, [onIsVisible, wasVisible]);

  return (
    <div
      ref={node}
      style={{
        height: '1px',
      }}
    ></div>
  );
};
