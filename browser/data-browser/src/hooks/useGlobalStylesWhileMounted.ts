import { useId, useInsertionEffect } from 'react';

const getNode = (id: string) => {
  const existingNode = document.getElementById(id);

  if (existingNode) {
    return existingNode;
  }

  const node = document.createElement('style');
  node.id = id;
  document.head.appendChild(node);

  return node;
};

/**
 * Add a style element to the head with the given cssText while the component is mounted.
 * @param cssText CSS Styles to be added to the head.
 */
export function useGlobalStylesWhileMounted(cssText: string) {
  const id = useId();

  useInsertionEffect(() => {
    const node = getNode(id);

    node.innerHTML = cssText;

    return () => {
      document.head.removeChild(node);
    };
  }, [cssText]);
}
