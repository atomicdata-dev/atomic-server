const supportedApplicationFormats = new Set([
  'application/json',
  'application/ld+json',
  'application/ad+json',
  'application/x-httpd-php',
  'application/xhtml+xml',
  'application/xml',
  'application/x-sh',
]);

const supportedImageTypes = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/svg+xml',
  'image/webp',
  'image/avif',
]);

export const isTextFile = (mimeType: string): boolean =>
  mimeType?.startsWith('text/') || supportedApplicationFormats.has(mimeType);

export const isImageFile = (mimeType: string): boolean =>
  supportedImageTypes.has(mimeType);
