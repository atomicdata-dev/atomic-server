export const templates = ['sveltekit-site', 'react-site'] as const;
export type Template = (typeof templates)[number];

export const isTemplate = (value: string): value is Template =>
  templates.includes(value as Template);
