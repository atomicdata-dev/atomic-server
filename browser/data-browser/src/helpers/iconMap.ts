import {
  ai,
  canvas,
  collections,
  commits,
  core,
  dataBrowser,
  Datatype,
  forms,
  server,
} from '@tomic/react';
import { IconType } from 'react-icons';
import {
  FaTag,
  FaAtom,
  FaBook,
  FaGlobe,
  FaPlug,
  FaGrip,
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
  FaChartLine,
  FaArrowUpRightFromSquare,
  FaCalendar,
  FaFont,
  FaListUl,
  FaMarkdown,
  FaPaintbrush,
  FaRegSquareCheck,
  FaLanguage,
  FaLink,
  FaCode,
  FaPuzzlePiece,
  FaVideo,
  FaWpforms,
} from 'react-icons/fa6';
import { AIIcon } from '../components/AI/AIIcon';

const iconMap = new Map<string, IconType>([
  [dataBrowser.classes.folder, FaFolder],
  [dataBrowser.classes.bookmark, FaBook],
  [dataBrowser.classes.chatroom, FaComment],
  [dataBrowser.classes.document, FaFileLines],
  [dataBrowser.classes.documentV2, FaFileLines],
  [dataBrowser.classes.meeting, FaVideo],
  [server.classes.file, FaFile],
  [server.classes.drive, FaHardDrive],
  [server.classes.plugin, FaPuzzlePiece],
  [server.classes.installation, FaPuzzlePiece],
  [commits.classes.commit, FaClock],
  [dataBrowser.classes.importer, FaFileImport],
  [server.classes.invite, FaShareFromSquare],
  [collections.classes.collection, FaList],
  [core.classes.class, FaCube],
  [core.classes.property, FaCubes],
  [dataBrowser.classes.table, FaTable],
  [dataBrowser.classes.dashboard, FaChartLine],
  [core.classes.property, FaHashtag],
  [core.classes.ontology, FaShapes],
  [dataBrowser.classes.tag, FaTag],
  [ai.classes.aiChat, AIIcon],
  [canvas.classes.canvas, FaPaintbrush],
  [forms.classes.form, FaWpforms],
]);

/**
 * Classes created per drive from a schema (no fixed subject) are matched by
 * their shortname instead.
 */
const classShortnameIconMap = new Map<string, IconType>([
  ['plugin-script', FaPlug],
  ['website-project', FaGlobe],
  // The launcher grid rather than the puzzle piece a new app gets as its
  // placeholder emoji: that one already belongs to plugins and installations
  // here, and an app sits next to both in the sidebar.
  ['app', FaGrip],
]);

export function getIconForClass(
  classSubject: string | undefined,
  fallback: IconType = FaAtom,
  classShortname?: string,
): IconType {
  return (
    (classSubject ? iconMap.get(classSubject) : undefined) ??
    (classShortname ? classShortnameIconMap.get(classShortname) : undefined) ??
    fallback
  );
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
  [Datatype.URI, FaLink],
  [Datatype.JSON, FaCode],
  [Datatype.LOCALIZEDTEXT, FaLanguage],
]);
