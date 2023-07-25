import { Resource, Version } from '@tomic/react';

export type GroupedVersions = {
  [key: string]: Version[];
};

export interface HistoryViewProps {
  resource: Resource;
  groupedVersions: GroupedVersions;
  selectedVersion: Version | undefined;
  isCurrentVersion: boolean;
  onNextVersion: () => void;
  onPreviousVersion: () => void;
  onSelectVersion: (version: Version) => void;
  onVersionAccept: () => void;
}
