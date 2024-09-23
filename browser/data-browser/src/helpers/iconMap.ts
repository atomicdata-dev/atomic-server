import {
  collections,
  commits,
  core,
  dataBrowser,
  Datatype,
  server,
} from '@tomic/react';
import { IconType } from 'react-icons';
import {
  FaTag,
  FaAtom,
  FaBook,
  FaClock,
  FaComment,
  FaCube,
  FaCubes,
  FaFile,
  FaFileLines,
  FaFileImport,
  FaFolder,
  FaHashtag,
  FaHardDrive,
  FaList,
  FaShapes,
  FaShareFromSquare,
  FaTable,
  FaArrowUpRightFromSquare,
  FaCalendar,
  FaFont,
  FaListUl,
  FaMarkdown,
  FaRegSquareCheck,
} from 'react-icons/fa6';

const iconMap = new Map<string, IconType>([
  [dataBrowser.classes.folder, FaFolder],
  [dataBrowser.classes.bookmark, FaBook],
  [dataBrowser.classes.chatroom, FaComment],
  [dataBrowser.classes.document, FaFileLines],
  [server.classes.file, FaFile],
  [server.classes.drive, FaHardDrive],
  [commits.classes.commit, FaClock],
  [dataBrowser.classes.importer, FaFileImport],
  [server.classes.invite, FaShareFromSquare],
  [collections.classes.collection, FaList],
  [core.classes.class, FaCube],
  [core.classes.property, FaCubes],
  [dataBrowser.classes.table, FaTable],
  [core.classes.property, FaHashtag],
  [core.classes.ontology, FaShapes],
  [dataBrowser.classes.tag, FaTag],
]);

export function getIconForClass(
  classSubject: string,
  fallback: IconType = FaAtom,
): IconType {
  return iconMap.get(classSubject) ?? fallback;
}

export const dataTypeIconMap = new Map<string, IconType>([
  [Datatype.STRING, FaFont],
  [Datatype.SLUG, FaFont],
  [Datatype.MARKDOWN, FaMarkdown],
  [Datatype.ATOMIC_URL, FaArrowUpRightFromSquare],
  [Datatype.INTEGER, FaHashtag],
  [Datatype.FLOAT, FaHashtag],
  [Datatype.RESOURCEARRAY, FaListUl],
  [Datatype.BOOLEAN, FaRegSquareCheck],
  [Datatype.DATE, FaCalendar],
  [Datatype.TIMESTAMP, FaClock],
]);
