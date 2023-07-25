/** Returns true if this is run in locally, in Development mode */
export function isDev(): boolean {
  //@ts-ignore This key does exist
  return import.meta.env['MODE'] === 'development';
}
