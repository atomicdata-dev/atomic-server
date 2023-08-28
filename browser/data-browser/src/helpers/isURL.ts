export function isURL(testString: string): boolean {
  try {
    new URL(testString);

    return true;
  } catch {
    return false;
  }
}
