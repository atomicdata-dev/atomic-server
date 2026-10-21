// @wc-ignore-file
import { paths } from '../routes/paths';
import { NewRoute } from '../routes/NewResource/NewRoute';
import { NewDriveRoute } from '../routes/NewDriveRoute';
import { EditRoute } from '../routes/EditRoute';
import { DataRoute } from '../routes/DataRoute';
import { HistoryRoute } from '../routes/History/HistoryRoute';
import { ShareRoute } from '../routes/Share/ShareRoute';
import { ImportRoute } from '../routes/ImportRoute';
import { StorageRoute } from '../routes/StorageRoute';
import { NotificationsRoute } from '../routes/NotificationsRoute';
import { AppSettingsRoute } from '../routes/AppSettings';

/** The pages the app opens by `path`, and the resource menu leads to: the web
 * app's own route components, mounted under the embed's root (they are made
 * for the app's root, which the embed does not use). `paths.newDrive` is the
 * template picker + name step; it creates the drive through the store (signed
 * and saved by the host) and then shows it, which reports `opened`. */
export const actionPages = [
  [paths.new, NewRoute],
  [paths.newDrive, NewDriveRoute],
  [paths.edit, EditRoute],
  [paths.data, DataRoute],
  [paths.history, HistoryRoute],
  [paths.share, ShareRoute],
  [paths.import, ImportRoute],
  [paths.storage, StorageRoute],
  [paths.notifications, NotificationsRoute],
  [paths.appSettings, AppSettingsRoute],
] as const;
