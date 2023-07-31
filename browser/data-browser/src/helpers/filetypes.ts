import {
  FaFile,
  FaFileAlt,
  FaFileArchive,
  FaFileAudio,
  FaFileCsv,
  FaFileExcel,
  FaFileImage,
  FaFilePdf,
  FaFileVideo,
  FaFileWord,
} from 'react-icons/fa';

export const imageMimeTypes = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/svg+xml',
  'image/webp',
  'image/bmp',
  'image/tiff',
  'image/vnd.microsoft.icon',
  'image/vnd.adobe.photoshop',
  'image/heic',
  'image/heif',
  'image/heif-sequence',
  'image/heic-sequence',
  'image/avif',
  'image/avif-sequence',
]);

export const archiveMimeTypes = new Set([
  'application/zip',
  'application/x-7z-compressed',
  'application/x-rar-compressed',
  'application/x-tar',
  'application/x-gzip',
  'application/x-bzip2',
  'application/x-xz',
  'application/x-lzip',
  'application/x-lzma',
  'application/x-lzop',
  'application/vnd.rar',
  'application/x-rar-compressed',
]);

export const msWordMimeTypes = new Set([
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-word.document.macroEnabled.12',
]);

export const msExcelMimeTypes = new Set([
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
]);

export function getFileIcon(mimeType: string) {
  if (mimeType === 'application/pdf') {
    return FaFilePdf;
  }

  if (msWordMimeTypes.has(mimeType)) {
    return FaFileWord;
  }

  if (msExcelMimeTypes.has(mimeType)) {
    return FaFileExcel;
  }

  if (archiveMimeTypes.has(mimeType)) {
    return FaFileArchive;
  }

  if (mimeType === 'text/csv') {
    return FaFileCsv;
  }

  if (mimeType.startsWith('audio/')) {
    return FaFileAudio;
  }

  if (mimeType.startsWith('video/')) {
    return FaFileVideo;
  }

  if (mimeType.startsWith('image/')) {
    return FaFileImage;
  }

  if (mimeType?.startsWith('text/')) {
    return FaFileAlt;
  }

  return FaFile;
}
