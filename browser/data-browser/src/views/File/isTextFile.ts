export const isTextFile = (mimeType: string): boolean =>
  mimeType !== 'application/pdf' &&
  (mimeType?.startsWith('text/') || mimeType?.startsWith('application/'));
