export const effectTimeout = (effect: () => void, ms: number) => {
  const id = setTimeout(effect, ms);

  return () => clearTimeout(id);
};
