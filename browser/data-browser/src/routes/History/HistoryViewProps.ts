import { Resource, Version, type HistoryAttribution } from '@tomic/react';

export type GroupedVersions = {
  [key: string]: Version[];
};

export interface HistoryViewProps {
  resource: Resource;
  groupedVersions: GroupedVersions;
  selectedVersion: Version;
  attribution: HistoryAttribution | null;
  olderVersion: Version | undefined;
  isCurrentVersion: boolean;
  onNextVersion: () => void;
  onPreviousVersion: () => void;
  onSelectVersion: (version: Version) => void;
  onVersionAccept: () => void;
}
