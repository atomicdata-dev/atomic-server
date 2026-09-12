/** Report host failures without reflecting the credential into UI or tool context. */
export function setupError(error: unknown, credential: string): string {
  const message =
    error instanceof Error ? error.message : 'Unknown setup error';
  const safe = credential
    ? message.split(credential).join('[redacted]')
    : message;

  return safe.slice(0, 500);
}
