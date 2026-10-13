/** A queued write carries its destination even after its resource is evicted.
 * Drive placement may later change explicitly; changing the selected workspace
 * or the bootstrap server never changes this ownership. */
export interface DriveRoute {
  drive: string;
  server: string;
}

/** Keep the complete origin: sibling subdomains can be different tenants even
 * when they share a physical server. Never compare registrable domains here. */
export function serverOrigin(value: string): string {
  const url = new URL(value);

  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username ||
    url.password
  ) {
    throw new Error(
      'A drive server must be an HTTP(S) origin without credentials',
    );
  }

  return url.origin;
}

export function parseDriveRoute(value: unknown): DriveRoute | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const route = value as Partial<DriveRoute>;
  if (typeof route.drive !== 'string' || typeof route.server !== 'string')
    return undefined;

  try {
    return { drive: route.drive, server: serverOrigin(route.server) };
  } catch {
    return undefined;
  }
}
