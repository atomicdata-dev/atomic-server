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
  | 'multi-select'
  | 'phone'
  | 'country'
  | 'url'
  | 'currency'
  | 'dropdown'
  | 'dropdown-multi'
  | 'likert'
  | 'rating'
  | 'picture-choice'
  | 'choice-matrix'
  | 'table-input'
  | 'address';

/** One column of a `table-input` question. */
export interface TableColumn {
  label: string;
  type?: 'text' | 'number';
}

/** The question types whose options are Tag resources on the mapped
 * Property's `allowsOnly`. Mirrors `CHOICE_FIELD_TYPES` in
 * `server/src/forms.rs`. */
export const CHOICE_FIELD_TYPES: FieldType[] = [
  'radio',
  'multi-select',
  'dropdown',
  'dropdown-multi',
  'picture-choice',
];

export function isChoiceField(type: string): boolean {
  return (CHOICE_FIELD_TYPES as string[]).includes(type);
}

/**
 * One resolved choice option. Mirrors `FieldOption` in `server/src/forms.rs`,
 * which resolves these from the Tags on the mapped Property's `allowsOnly` —
 * a published form's visitor has no agent and could not fetch them itself.
 *
 * `value` is the Tag's subject: what the answer stores and what conditions
 * compare against. Everything user-facing renders `label`.
 */
export interface FieldOption {
  value: string;
  label: string;
  color?: string;
  emoji?: string;
  /** `picture-choice`: the Tag's cover image, already rewritten into a URL the
   * visitor can fetch (`/form/{id}/image?file=…`). */
  image?: string;
}

/** An option's display text. Matches `useTagData`, which prefixes the emoji. */
export function optionText(option: FieldOption): string {
  return option.emoji ? `${option.emoji} ${option.label}` : option.label;
}

/** Where a choice question's options come from, when they are not the Tags on
 * its own mapped Property. Mirrors [OPTIONS_SOURCE_KEY] in
 * `server/src/forms.rs` and `OptionsSource` in the builder
 * (`chunks/FormBuilder/FieldOptions/optionsSource.ts`).
 *
 * `property` set → another column's Tags. Otherwise `table` alone → that
 * table's rows, labelled by `labelProperty`. `table` is stored in both cases
 * (the builder picks a table first) and ignored when `property` is set. */
export interface OptionsSource {
  table?: string;
  property?: string;
  labelProperty?: string;
}

/** The `form-field-options` bag. Every key is type-specific; a field only
 * ever reads the keys its own type defines. Kept flat (rather than a
 * discriminated union per type) because that is how the property is stored
 * and how both validators read it. */
export interface FieldOptions {
  placeholder?: string;
  min?: number;
  max?: number;
  /** Choice questions: the resolved options, in `allowsOnly` order. */
  options?: FieldOption[];
  /** Choice questions: where {@link FieldOptions.options} was resolved from,
   * when it is not the question's own column. Mirrors `OPTIONS_SOURCE_KEY` in
   * `server/src/forms.rs`. Builder-facing only — by the time a definition
   * reaches the renderer the options are already resolved, whatever the
   * source. */
  optionsSource?: OptionsSource;
  defaultValue?: boolean;
  /** currency: ISO 4217-ish code, e.g. `EUR`. Rendered as a symbol when known. */
  currency?: string;
  /** phone: the country the input starts in (and formats national input as).
   * country: pre-selected on first render. ISO 3166-1 alpha-2. */
  defaultCountry?: string;
  /** likert: number of points on the scale (answers are 1..scale). */
  scale?: number;
  /** likert: labels for the extremes of the scale. */
  minLabel?: string;
  maxLabel?: string;
  /** rating: glyph to render. */
  icon?: 'star' | 'heart' | string;
  /** choice-matrix: statements (one per row) and the scale shared by them. */
  rows?: string[];
  columns?: string[] | TableColumn[];
  /** table-input: row count bounds. */
  minRows?: number;
  maxRows?: number;
}

/** The subfields an `address` answer is made of. All are optional strings;
 * `required` on the field means line1 + city + country must be filled.
 * `country` holds an ISO 3166-1 alpha-2 code (see `countries.ts`); the rest
 * is free text. */
export interface AddressValue {
  line1?: string;
  line2?: string;
  city?: string;
  postalCode?: string;
  state?: string;
  country?: string;
}

/** Ordered `address` subfields — shared by the input and both validators so
 * an unknown key can be rejected. */
export const ADDRESS_FIELDS: {
  key: keyof AddressValue;
  label: string;
  autoComplete: string;
}[] = [
  { key: 'line1', label: 'Address', autoComplete: 'address-line1' },
  { key: 'line2', label: 'Address line 2', autoComplete: 'address-line2' },
  { key: 'postalCode', label: 'Postal code', autoComplete: 'postal-code' },
  { key: 'city', label: 'City', autoComplete: 'address-level2' },
  { key: 'state', label: 'State / Province', autoComplete: 'address-level1' },
  { key: 'country', label: 'Country', autoComplete: 'country-name' },
];

/** Address subfields that must be filled when the field is `required`. */
export const ADDRESS_REQUIRED_FIELDS: (keyof AddressValue)[] = [
  'line1',
  'city',
  'country',
];

export interface HeadingBlock {
  kind: 'heading';
  text: string;
  conditions?: FormCondition[];
}

export interface ParagraphBlock {
  kind: 'paragraph';
  text: string;
  conditions?: FormCondition[];
}

export interface FieldBlock {
  kind: 'field';
  mapsTo: string;
  label: string;
  description?: string | null;
  type: FieldType;
  required: boolean;
  options: FieldOptions;
  conditions?: FormCondition[];
}

export type FormBlock = HeadingBlock | ParagraphBlock | FieldBlock;

export type ConditionOperator =
  | 'equals'
  | 'not-equals'
  | 'contains'
  | 'greater-than'
  | 'less-than';

/** Denormalized visibility predicate. `field` is the referenced question's
 * `mapsTo` (property subject), not the FormField resource URL. Empty list on
 * a page/block means always visible; multiple entries are ANDed. */
export interface FormCondition {
  field: string;
  operator: ConditionOperator | string;
  value: unknown;
}

export interface FormPageDefinition {
  name?: string | null;
  coverImage?: string | null;
  imagePosition?: string | null;
  conditions?: FormCondition[];
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
