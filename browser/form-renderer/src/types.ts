/**
 * Mirrors `lib/src/forms.rs`'s `FormDefinition` / `FormBlock` — the
 * denormalized JSON served by `GET /form/{id}/definition`. Keep field names
 * and shapes in lockstep with the Rust side; there is no code generation
 * between them.
 */

export type FieldType =
  | 'short-text'
  | 'long-text'
  | 'email'
  | 'number'
  | 'date'
  | 'datetime'
  | 'checkbox'
  | 'radio'
  | 'multi-select';

export interface FieldOptions {
  placeholder?: string;
  min?: number;
  max?: number;
  options?: string[];
  defaultValue?: boolean;
}

export interface HeadingBlock {
  kind: 'heading';
  text: string;
}

export interface ParagraphBlock {
  kind: 'paragraph';
  text: string;
}

export interface FieldBlock {
  kind: 'field';
  mapsTo: string;
  label: string;
  description?: string | null;
  type: FieldType;
  required: boolean;
  options: FieldOptions;
}

export type FormBlock = HeadingBlock | ParagraphBlock | FieldBlock;

export interface FormPageDefinition {
  name?: string | null;
  coverImage?: string | null;
  imagePosition?: string | null;
  blocks: FormBlock[];
}

export type ImagePosition = 'top' | 'left' | 'right' | 'behind' | 'full';

export type Roundness = 'sharp' | 'rounded' | 'round';

/** Visual theming for the published form. All keys optional; unset keys keep
 * the light/dark-adaptive defaults from `style.css`. `imageUrl` is filled by
 * the server (`/form/{id}/image`) or, in the builder preview, with the File's
 * own `downloadURL`. */
export interface FormStyling {
  imageUrl?: string;
  imagePosition?: ImagePosition | string;
  textColor?: string;
  mainColor?: string;
  backgroundColor?: string;
  roundness?: Roundness | string;
  /** Multi-page progress bar visibility. Defaults to shown when unset. */
  showProgressBar?: boolean;
}

/** Captcha client config, filled in by the server for published forms
 * (`server/src/captcha.rs::client_config`). Absent in builder previews, so
 * the preview never renders a live widget. */
export interface FormCaptcha {
  provider: 'altcha' | string;
  challengeUrl: string;
}

/** The ride-along key under which FormRenderer passes the solved captcha
 * payload to `onSubmit` — same pattern as the honeypot value. The host app
 * lifts it out into the submit body's top-level `altcha` field. */
export const CAPTCHA_VALUE_KEY = '__altcha';

export interface FormDefinition {
  version: number;
  id: string;
  name: string;
  settings: Record<string, unknown>;
  styling: FormStyling;
  honeypotField: string;
  captcha?: FormCaptcha;
  pages: FormPageDefinition[];
}

/** A submitted value for one field, keyed by the field's `mapsTo` property subject. */
export type FormValues = Record<string, unknown>;

/** Field-level validation errors, keyed by `mapsTo`. */
export type FormErrors = Record<string, string>;
