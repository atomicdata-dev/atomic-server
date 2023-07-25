/**
 * Makes URLs shorter and removes the schema. Hides the hostname if it's equal
 * to the window hostname
 */
export function truncateUrl(
  url: string,
  num: number,
  truncateBack?: boolean,
): string {
  // Remove the schema, the https:// part
  let noSchema = url.replace(/(^\w+:|^)\/\//, '');

  if (
    typeof window !== 'undefined' &&
    window?.location &&
    noSchema.startsWith(window.location.hostname)
  ) {
    noSchema = noSchema.slice(window.location.hostname.length);
  }

  if (noSchema.length <= num) {
    return noSchema;
  }

  if (truncateBack) {
    const tooMuch = noSchema.length - num;

    return '...' + noSchema.slice(tooMuch);
  }

  return noSchema.slice(0, num) + '...';
}
