import type { JSONValue } from '@tomic/react';
import { WebsiteTemplateImage } from './templates/websiteImage';

export type TemplateContext = {
  driveURL: string;
  serverURL: string;
};

export type Template = {
  rootResourceLocalIDs: string[];
  id: string;
  title: string;
  description: string;
  resources: Record<string, JSONValue>[];
};

export type TemplateFn = (context: TemplateContext) => Template;

export interface TemplateDescriptor {
  id: string;
  title: string;
  description: string;
  Image: React.FC;
  load: () => Promise<TemplateFn>;
}

export const templates: TemplateDescriptor[] = [
  {
    id: 'website',
    title: 'Website',
    description:
      'Pages, blog posts and reusable content blocks for your website.',
    Image: WebsiteTemplateImage,
    load: () => import('./templates/website').then(module => module.website),
  },
];
