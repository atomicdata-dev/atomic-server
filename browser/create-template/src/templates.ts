export type TemplateKey = keyof typeof templates;

export type ExecutionContext = {
  serverUrl: string;
};

export type BaseTemplate = {
  name: string;
  ontologyID: (context: ExecutionContext) => string;
  generateEnv: (context: ExecutionContext) => string;
};

const baseTemplates = {
  website: {
    name: 'website',
    ontologyID: ({ serverUrl }) => `${serverUrl}/website`,
    generateEnv: ({ serverUrl }) => {
      const siteSubject = `${serverUrl}/01j5zrevq917dp0wm4p2vnd7nr`;

      return `PUBLIC_ATOMIC_SERVER_URL=${serverUrl}\nPUBLIC_WEBSITE_RESOURCE=${siteSubject}`;
    },
  },
} satisfies Record<string, BaseTemplate>;

export const templates = {
  'sveltekit-site': baseTemplates.website,
} satisfies Record<string, BaseTemplate>;

export const isTemplate = (value: string): value is TemplateKey =>
  value in templates;
