/** Gets the index of an array and loops around when at the beginning or end */
export const loopingIndex = (index: number, length: number) => {
  return ((index % length) + length) % length;
};
