import { classes } from '@tomic/react';
import { IconType } from 'react-icons';
import {
  FaAtom,
  FaBook,
  FaClock,
  FaComment,
  FaCube,
  FaCubes,
  FaFile,
  FaFileAlt,
  FaFileImport,
  FaFolder,
  FaHashtag,
  FaHdd,
  FaListAlt,
  FaShareSquare,
  FaTable,
} from 'react-icons/fa';

const iconMap = new Map<string, IconType>([
  [classes.folder, FaFolder],
  [classes.bookmark, FaBook],
  [classes.chatRoom, FaComment],
  [classes.document, FaFileAlt],
  [classes.file, FaFile],
  [classes.drive, FaHdd],
  [classes.commit, FaClock],
  [classes.importer, FaFileImport],
  [classes.invite, FaShareSquare],
  [classes.collection, FaListAlt],
  [classes.class, FaCube],
  [classes.property, FaCubes],
  [classes.table, FaTable],
  [classes.property, FaHashtag],
]);

export function getIconForClass(
  classSubject: string,
  fallback: IconType = FaAtom,
): IconType {
  return iconMap.get(classSubject) ?? fallback;
}
