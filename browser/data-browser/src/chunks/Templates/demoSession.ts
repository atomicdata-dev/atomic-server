// @wc-ignore-file
export const TEMPLATE_DEMO_KEY = 'atomic.templateDemo';
export interface TemplateDemo {
  drive: string;
  template: string;
  previousDrive: string;
}
export function readTemplateDemo(): TemplateDemo | undefined {
  try {
    const value = JSON.parse(localStorage.getItem(TEMPLATE_DEMO_KEY) ?? 'null');
    if (
      value &&
      typeof value.drive === 'string' &&
      typeof value.template === 'string' &&
      typeof value.previousDrive === 'string'
    )
      return value;
  } catch {
    /* Storage is unavailable or a previous version wrote invalid data. */
  }
}
