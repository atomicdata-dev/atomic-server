const supportedApplicationFormats = new Set([
  'application/json',
  'application/ld+json',
  'application/ad+json',
  'application/x-httpd-php',
  'application/xhtml+xml',
  'application/xml',
  'application/x-sh',
]);

export const isTextFile = (mimeType: string): boolean =>
  mimeType?.startsWith('text/') || supportedApplicationFormats.has(mimeType);
