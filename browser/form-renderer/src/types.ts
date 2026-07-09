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

export interface FormDefinition {
  version: number;
  id: string;
  name: string;
  settings: Record<string, unknown>;
  honeypotField: string;
  pages: FormPageDefinition[];
}

/** A submitted value for one field, keyed by the field's `mapsTo` property subject. */
export type FormValues = Record<string, unknown>;

/** Field-level validation errors, keyed by `mapsTo`. */
export type FormErrors = Record<string, string>;
