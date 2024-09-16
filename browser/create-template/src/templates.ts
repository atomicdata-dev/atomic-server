export type TemplateKey = keyof typeof templates;

export type BaseTemplate = {
  name: string;
  ontologyID: string;
  generateEnv: (context: { serverUrl: string }) => string;
};

const baseTemplates = {
  website: {
    name: 'website',
    ontologyID: '01j6zqa7qgamwh5960dzy99j70',
    generateEnv: ({ serverUrl }) => {
      const siteSubject = new URL(
        '01j5zrevq917dp0wm4p2vnd7nr',
        serverUrl,
      ).toString();

      return `PUBLIC_ATOMIC_SERVER_URL=${serverUrl}\nPUBLIC_WEBSITE_RESOURCE=${siteSubject}`;
    },
  },
} satisfies Record<string, BaseTemplate>;

export const templates = {
  'sveltekit-site': baseTemplates.website,
} satisfies Record<string, BaseTemplate>;

export const isTemplate = (value: string): value is TemplateKey =>
  value in templates;
