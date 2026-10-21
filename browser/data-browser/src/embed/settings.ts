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
  | 'hideTemplates'
  | 'sidebarIcons';

export const embedAppearanceOptions: ReadonlySet<AppearanceOptionId> = new Set([
  'theme',
  'mainColor',
  'language',
  'hideTemplates',
  'sidebarIcons',
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

/**
 * Is "Start meeting" shown? A live meeting needs the server connection (the
 * presence session) and a WebRTC call with microphone and camera; the app's
 * web view has neither. Chat of an existing meeting does work. See "Meetings in
 * the embed" in planning/flutter-embed-host.md.
 */
export function showMeetingStart(embedded: boolean = isEmbedded()): boolean {
  return !embedded;
}

/**
 * Are the web app's AI features on (the "AI chat" creation, "Build with AI",
 * the AI sidebar)? Not in the embed: the page has no AI provider (no keys, no
 * server connection for the included AI), so "Build with AI" did nothing at
 * all when tapped. The app's own native AI chat is the AI on a phone.
 */
export function showWebAI(embedded: boolean = isEmbedded()): boolean {
  return !embedded;
}

/**
 * Does the settings page show its own "Settings" heading and search field?
 * Not in the embed: the app's top bar already says "Settings", and a search
 * over the one section left is a field with nothing to find. The section
 * starts open there instead.
 */
export function showSettingsHeader(embedded: boolean = isEmbedded()): boolean {
  return !embedded;
}
