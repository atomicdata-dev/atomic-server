import type { JSONValue } from '@tomic/react';

export type DescriptionContext = {
  serverUrl: string;
};

export type Template = {
  rootResourceLocalIDs: string[];
  id: string;
  title: string;
  description: (context: DescriptionContext) => string;
  Image: React.FC;
  resources: Record<string, JSONValue>[];
};
