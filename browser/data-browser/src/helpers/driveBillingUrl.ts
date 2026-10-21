/** Preserve the billing target when leaving a drive for its account portal. */
export function driveBillingUrl(portal: string, drive?: string): string {
  const url = new URL('/billing', portal);

  if (drive) url.searchParams.set('drive', drive);

  return url.toString();
}

/** The page on the account portal that explains and sells Cloud Server. */
export function cloudServerSalesUrl(portal: string, drive?: string): string {
  const url = new URL('/cloud-server', portal);

  if (drive) url.searchParams.set('drive', drive);

  return url.toString();
}
