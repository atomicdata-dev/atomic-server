// eslint-disable-next-line @typescript-eslint/ban-types
const debounceMap = new Map<Function, number>();

/**
 * Debounces a function, Note: this debounces per function, if you pass in a new
 * function it will not work. If you debounce the exact same function elsewhere
 * it will overwite the same debounce timer as this one.
 *
 * @param fn The function to debounce
 * @param delay The delay in milliseconds (defaults to 500)
 */
// eslint-disable-next-line @typescript-eslint/ban-types
export function debounce<T extends Function>(fn: T, delay = 500): T {
  const debouncedFn = (...args: unknown[]) => {
    const debounceId = debounceMap.get(fn);

    if (debounceId) {
      window.clearTimeout(debounceId);
    }

    debounceMap.set(
      fn,
      window.setTimeout(() => fn(...args), delay),
    );
  };

  return debouncedFn as unknown as T;
}
