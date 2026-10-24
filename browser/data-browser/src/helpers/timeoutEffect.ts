/** Sets a timeout and returns a cleanup function, ideal for using in a useEffect */
export function timeoutEffect(func: () => void, delay: number): () => void {
  const id = setTimeout(func, delay);

  return () => clearTimeout(id);
}
