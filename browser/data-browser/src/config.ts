/** Returns true if this is run in locally, in Development mode */
export function isDev(): boolean {
  return import.meta.env['MODE'] === 'development';
}
