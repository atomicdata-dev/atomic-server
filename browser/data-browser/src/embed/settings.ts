// @wc-ignore-file
import { isEmbedded } from '../helpers/embedMode';

/** The top-level sections of the settings page. */
export type SettingsSectionId =
  | 'appearance'
  | 'accessibility'
  | 'notifications'
  | 'virtualDrive'
  | 'ai'
  | 'integration';

/**
 * The settings sections the Flutter embed shows. An allow-list, so a section
 * added to the web app later stays out of the phone until someone decides it
 * works there. See "Settings in the embed" in planning/flutter-embed-host.md for
 * why each of the others is left out.
 */
export const embedSettingsSections: ReadonlySet<SettingsSectionId> = new Set([
  'appearance',
]);

/** The options inside Appearance that do something in the embed. */
export type AppearanceOptionId =
  | 'theme'
  | 'navbarPosition'
  | 'mainColor'
  | 'colorfulMode'
  | 'language'
  | 'panels'
  | 'hideTemplates';

export const embedAppearanceOptions: ReadonlySet<AppearanceOptionId> = new Set([
  'theme',
  'mainColor',
  'language',
  'hideTemplates',
]);

/** Is this section part of the settings page? Everything is, outside the embed. */
export function showSettingsSection(
  id: SettingsSectionId,
  embedded: boolean = isEmbedded(),
): boolean {
  return !embedded || embedSettingsSections.has(id);
}

/** Is this Appearance option shown? Everything is, outside the embed. */
export function showAppearanceOption(
  id: AppearanceOptionId,
  embedded: boolean = isEmbedded(),
): boolean {
  return !embedded || embedAppearanceOptions.has(id);
}
