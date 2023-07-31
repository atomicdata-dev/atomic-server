export function buildComponentFactory<K, P>(
  options: Map<K, (props: P) => JSX.Element>,
  fallback: () => JSX.Element,
) {
  return (current: K | undefined) => options.get(current!) ?? fallback;
}
