/** Simple helper function for adding items to an array only if the condition is true
 * @example
 * const someArray = [
 * 'pizza',
 * ...addIf(likesCheese, 'cheese'),
 * ];
 *
 */
export const addIf = <T>(condition: boolean, ...items: T[]): T[] =>
  condition ? items : [];
