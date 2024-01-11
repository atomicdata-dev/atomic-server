const supportedApplicationFormats = new Set([
  'application/json',
  'application/ld+json',
  'application/json-ad',
  'application/x-httpd-php',
  'application/xhtml+xml',
  'application/xml',
  'application/x-sh',
]);

export const isTextFile = (mimeType: string): boolean =>
  mimeType?.startsWith('text/') || supportedApplicationFormats.has(mimeType);
