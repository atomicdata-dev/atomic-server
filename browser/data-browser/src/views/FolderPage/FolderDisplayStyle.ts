import { Resource } from '@tomic/react';

export interface ViewProps {
  subResources: Map<string, Resource>;
  onNewClick: () => void;
  showNewButton: boolean;
}
