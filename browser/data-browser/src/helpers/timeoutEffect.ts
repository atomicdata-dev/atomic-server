/** Sets a timeout and returns a cleanup function, ideal for using in a useEffect */
export function timeoutEffect(func: () => void, delay: number): () => void {
  const id = setTimeout(func, delay);

  return () => clearTimeout(id);
}

/** Runs multiple timeout effects and returns the cleanup functions combined into one */
export function timeoutEffects(
  ...args: Array<[func: () => void, delay: number]>
): () => void {
  const cleaners = args.map(([func, delay]) => timeoutEffect(func, delay));

  return () => {
    for (const cleaner of cleaners) {
      cleaner();
    }
  };
}
