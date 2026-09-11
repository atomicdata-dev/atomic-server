/** Preserve the billing target when leaving a drive for its account portal. */
export function driveBillingUrl(portal: string, drive?: string): string {
  const url = new URL('/billing', portal);

  if (drive) url.searchParams.set('drive', drive);

  return url.toString();
}
