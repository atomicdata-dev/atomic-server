{{#title Atomic Forms}}

# Atomic Schema: Forms

Forms let you build a form or survey in an Atomic Server drive, publish it at a
short link, and collect submissions without the visitor needing an Atomic
Agent. This page describes the underlying data model; it does not describe the
public submission API (see the endpoints documentation once that ships).

A Form's submissions are kept in a regular [Table](https://atomicdata.dev/classes/Table):
building a Form generates a data `Class` (one `Property` per question) and a
`Table` typed to that class, so results are just table rows — no separate
results storage.

## Form

_URL: [`https://atomicdata.dev/classes/Form`](https://atomicdata.dev/classes/Form)_

A form or survey that can be published and shared with a link.

Properties:

- [`name`](https://atomicdata.dev/properties/name) - (required, String) the form's title.
- [`form-data-class`](https://atomicdata.dev/properties/form-data-class) - (required, AtomicURL, Class) the generated data class, one Property per question.
- [`form-target-table`](https://atomicdata.dev/properties/form-target-table) - (required, AtomicURL, Table) the table submissions are written to.
- [`form-pages`](https://atomicdata.dev/properties/form-pages) - (required, ResourceArray, FormPage) the form's pages, in order.
- [`form-published-at`](https://atomicdata.dev/properties/form-published-at) - (recommended, Timestamp) when the form was published. Absent means unpublished; submissions are only accepted while set.
- [`form-open-at`](https://atomicdata.dev/properties/form-open-at) - (recommended, Timestamp) when a published form starts accepting responses. Absent means it is open as soon as it is published. Before this moment visitors get a `410` with a "not open yet" message instead of the form.
- [`form-close-at`](https://atomicdata.dev/properties/form-close-at) - (recommended, Timestamp) when a published form stops accepting responses. Absent means it stays open until it is unpublished. From this moment on visitors get a `410` with a "closed" message. Bounds are half-open: a form is open *at* `form-open-at` and closed *at* `form-close-at`, and both are only consulted while `form-published-at` is set — publishing stays the master switch. They are compared against the clock on every request, so no scheduler is involved and a server that was down at the scheduled moment still opens and closes the form on time.
- [`form-settings`](https://atomicdata.dev/properties/form-settings) - (recommended, JSON) miscellaneous settings (e.g. progress bar, confirmation message).
- [`form-styling`](https://atomicdata.dev/properties/form-styling) - (recommended, JSON) visual theming for the published form. Keys (all optional): `textColor`, `mainColor`, `backgroundColor` (hex colors), `roundness` (one of: `sharp`, `rounded`, `round`), `fieldSpacing` (one of: `small`, `large`) sets the vertical space between blocks, `showProgressBar` (boolean, defaults to `true`) toggles the multi-page progress bar, `animatePageTransitions` (boolean, defaults to `false`) animates Next/Back page changes, and `saveDrafts` (boolean, defaults to `true`) keeps a visitor's half-filled answers in their own browser so they can resume later — set it to `false` for kiosks and other shared devices.
- [`cover-image`](https://atomicdata.dev/properties/cover-image) - (recommended, AtomicURL, File) an image shown alongside or behind the published form. Served to anonymous visitors via `GET /form/{id}/image` (publish-gated), so the File itself needs no public read rights.
- [`image-position`](https://atomicdata.dev/properties/image-position) - (recommended, String) where the image is positioned. One of: `top`, `left`, `right`, `behind` (full-page image behind the form card), `full` (form rendered directly on the image, no card) — enforced by the application, not the store (see note below).
- [`form-submission-summary`](https://atomicdata.dev/properties/form-submission-summary) - (JSON, server-computed) aggregated submission statistics (response count, per-question option counts / number bins / answer samples), added to the resource by the server when a Form is fetched over HTTP. Ephemeral: it is never persisted and must never be written by clients.
- [`form-access`](https://atomicdata.dev/properties/form-access) - (recommended, String) who can open the published form. One of: `public` (anyone with the link; the default when absent), `invite-only` (a valid, unused `FormInviteCode` is required to view and submit) — enforced by the application, not the store (see note below).

## FormPage

_URL: [`https://atomicdata.dev/classes/FormPage`](https://atomicdata.dev/classes/FormPage)_

A single page of a Form, holding a list of fields and layout blocks.

Properties:

- [`form-fields`](https://atomicdata.dev/properties/form-fields) - (required, ResourceArray) the page's fields and layout blocks, in order. No `classtype`, since a page mixes input fields (`FormField`) with layout blocks (`FormHeading`, `FormParagraph`, `FormInfoBox`, ...) and Atomic Data doesn't support multiple class-types on one ResourceArray.
- [`name`](https://atomicdata.dev/properties/name) - (recommended, String) the page's title.
- [`cover-image`](https://atomicdata.dev/properties/cover-image) - (recommended, AtomicURL, File) an optional cover image.
- [`image-position`](https://atomicdata.dev/properties/image-position) - (recommended, String) where the cover image is positioned. Same values as on Form (see above); currently unused by the builder, which themes at the Form level.
- [`form-conditions`](https://atomicdata.dev/properties/form-conditions) - (recommended, ResourceArray, FormCondition) visibility predicates. All must match (AND) for the page to be shown; an empty list means always visible. Evaluated against answers from earlier pages.

## FormField

_URL: [`https://atomicdata.dev/classes/FormField`](https://atomicdata.dev/classes/FormField)_

A single question in a Form. One class covers every field type — the type is
tagged by `form-field-type` and its type-specific settings live in the
`form-field-options` JSON bag, so changing a question's type is always a single
property write rather than swapping `isA` between per-type classes.

Properties:

- [`name`](https://atomicdata.dev/properties/name) - (required, String) the question label.
- [`form-maps-to`](https://atomicdata.dev/properties/form-maps-to) - (required, AtomicURL, Property) the Property on the Form's data class that this field's answers are written to.
- [`form-field-type`](https://atomicdata.dev/properties/form-field-type) - (required, String) the kind of question — one of the values in the table below, enforced by the application, not the store (see note at the bottom of this page).
- [`description`](https://atomicdata.dev/properties/description) - (recommended, Markdown) helper text shown below the label.
- [`required`](https://atomicdata.dev/properties/required) - (recommended, Boolean) whether an answer is mandatory.
- [`form-field-options`](https://atomicdata.dev/properties/form-field-options) - (recommended, JSON) type-specific settings (placeholder, min/max, choice options, ...); shape depends on `form-field-type`.
- [`form-conditions`](https://atomicdata.dev/properties/form-conditions) - (recommended, ResourceArray, FormCondition) visibility predicates. All must match (AND) for the field to be shown. Hidden fields are not validated and their submitted values are dropped.

### Question types

Each type fixes the datatype of the Property the answers are written to
(`form-maps-to`), the shape of the `form-field-options` bag, and the JSON shape
of a submitted answer. Options not listed for a type are ignored.

| `form-field-type` | Property datatype | `form-field-options` | submitted value |
| ----------------- | ----------------- | -------------------- | --------------- |
| `short-text`      | String            | `placeholder`        | string |
| `long-text`       | String            | `placeholder`        | string |
| `email`           | String            | `placeholder`        | string, validated as an email address |
| `phone`           | String            | `placeholder`, `defaultCountry` | string; the renderer's country-select input submits E.164 (`+31612345678`), and the server also accepts digits with the usual separators and an optional `+` prefix |
| `country`         | String            | `placeholder`, `defaultCountry` | ISO 3166-1 alpha-2 code (`"NL"`); the renderer shows the country's name in the visitor's own language |
| `url`             | String            | `placeholder`        | string, must start with `http://` or `https://` |
| `number`          | Float             | `placeholder`, `min`, `max` | number |
| `currency`        | Float             | `currency` (ISO code), `placeholder`, `min`, `max` | number |
| `date`            | Date              | —                    | `"YYYY-MM-DD"` |
| `datetime`        | Timestamp         | —                    | milliseconds since epoch |
| `checkbox`        | Boolean           | `defaultValue`       | boolean |
| `radio`           | String            | `options`            | one of `options` |
| `dropdown`        | String            | `options`, `placeholder` | one of `options` |
| `multi-select`    | JSON              | `options`, `minSelected`, `maxSelected` | array of `options` |
| `dropdown-multi`  | JSON              | `options`, `minSelected`, `maxSelected` | array of `options` |
| `picture-choice`  | String            | `options`, `optionImages` | one of `options` |
| `likert`          | Integer           | `scale` (2–11, default 5), `minLabel`, `maxLabel` | integer `1..scale` |
| `rating`          | Integer           | `max` (2–10, default 5), `icon` (`star`/`heart`) | integer `1..max` |
| `choice-matrix`   | JSON              | `rows`, `columns`    | object mapping a row to one of `columns` |
| `table-input`     | JSON              | `columns` (`{label, type}`, type `text`/`number`), `minRows`, `maxRows` | array of row objects keyed by column label |
| `address`         | JSON              | —                    | object with any of `line1`, `line2`, `postalCode`, `city`, `state`, `country`; `country` is an ISO 3166-1 alpha-2 code, the rest is free text |

`defaultCountry` is an ISO 3166-1 alpha-2 code. On a `phone` field it decides
which country the number input starts on (the visitor can still switch); on a
`country` field it is pre-selected as the answer. Leave it out and the visitor
picks from scratch.

`optionImages` is an array of File subjects positionally matched to `options`,
so renaming an option keeps its image. Because a published form has no agent,
the definition JSON replaces those subjects with URLs on the publish-gated
`GET /form/{id}/image?file=…` route (which only serves images this form
actually references) — the Files themselves stay private, the same way the
Form's `cover-image` does.

`minSelected` / `maxSelected` bound how many options a multi-pick question
accepts. Past the maximum the remaining options are disabled rather than
flagged; the minimum is checked on submit. Both only constrain an answer that
was given — an untouched question stays "unanswered", which is what `required`
is for.

For `required` fields, "answered" is per-subfield on the composite types: a
`choice-matrix` needs every row answered, and an `address` needs at least
`line1`, `city` and `country`. An array or object whose entries are all empty
counts as unanswered rather than as a partial answer.

## FormHeading

_URL: [`https://atomicdata.dev/classes/FormHeading`](https://atomicdata.dev/classes/FormHeading)_

A heading layout block inside a FormPage's `form-fields` list.

- [`name`](https://atomicdata.dev/properties/name) - (required, String) the heading text.
- [`form-conditions`](https://atomicdata.dev/properties/form-conditions) - (recommended, ResourceArray, FormCondition) visibility predicates, same AND semantics as on FormField.

## FormParagraph

_URL: [`https://atomicdata.dev/classes/FormParagraph`](https://atomicdata.dev/classes/FormParagraph)_

A paragraph layout block inside a FormPage's `form-fields` list, rendered as markdown.

- [`description`](https://atomicdata.dev/properties/description) - (required, Markdown) the paragraph body.
- [`form-conditions`](https://atomicdata.dev/properties/form-conditions) - (recommended, ResourceArray, FormCondition) visibility predicates, same AND semantics as on FormField.

## FormInfoBox

_URL: [`https://atomicdata.dev/classes/FormInfoBox`](https://atomicdata.dev/classes/FormInfoBox)_

A callout layout block inside a FormPage's `form-fields` list — a paragraph in
a tinted box, for the thing a respondent must not scroll past.

- [`description`](https://atomicdata.dev/properties/description) - (required, Markdown) the box's body.
- [`name`](https://atomicdata.dev/properties/name) - (recommended, String) an optional title line above the body. An untitled box is just a styled paragraph.
- [`form-info-box-style`](https://atomicdata.dev/properties/form-info-box-style) - (recommended, String) one of: `info`, `note`, `tip`, `success`, `warning`, `danger`. Enforced by the application, not the store (same limitation as `form-field-type`); an unset or unknown value renders as `info`.
- [`form-conditions`](https://atomicdata.dev/properties/form-conditions) - (recommended, ResourceArray, FormCondition) visibility predicates, same AND semantics as on FormField.

`info` follows the form's own accent color, so a themed form gets a matching
callout without configuring anything. `warning` and `danger` are announced to
screen readers (`role="alert"`); the quieter variants are read as ordinary
text.

## FormCondition

_URL: [`https://atomicdata.dev/classes/FormCondition`](https://atomicdata.dev/classes/FormCondition)_

A single visibility predicate on a page, field, or layout block. The parent
lists its predicates in `form-conditions`; they are ANDed. Stored as a child
of the thing it hides, so hierarchy rights keep them private to form editors
— they appear in the public definition JSON only as denormalized
`{ field, operator, value }` objects (`field` is the referenced question's
`form-maps-to` property URL, not the FormField subject).

- [`form-condition-field`](https://atomicdata.dev/properties/form-condition-field) - (required, AtomicURL, FormField) the question whose answer is inspected.
- [`form-condition-operator`](https://atomicdata.dev/properties/form-condition-operator) - (required, String) one of: `equals`, `not-equals`, `contains`, `greater-than`, `less-than` — enforced by the application, not the store (see note below).
- [`form-condition-value`](https://atomicdata.dev/properties/form-condition-value) - (recommended, JSON) the comparison value. Shape depends on the referenced field.

An unanswered or hidden referenced field fails the condition (the dependent
stays hidden). `contains` is a case-insensitive substring on strings and
membership on multi-select arrays. `greater-than` / `less-than` compare
numerically, falling back to lexicographic string order (ISO dates work).

## FormInviteCode

_URL: [`https://atomicdata.dev/classes/FormInviteCode`](https://atomicdata.dev/classes/FormInviteCode)_

A single-use invite code for an invite-only Form (`form-access` =
`invite-only`). Codes are stored as children of the Form (their `parent`), so
the hierarchy's rights keep them readable by form editors only — they never
appear in the public form definition. A code is consumed (its `used-at` set)
when a submission is accepted with it; revoking a code is simply destroying
the resource.

- [`form-code`](https://atomicdata.dev/properties/form-code) - (required, String) the code value a visitor presents (as the `code` query parameter / submit body field).
- [`used-at`](https://atomicdata.dev/properties/used-at) - (recommended, Timestamp) when the code was consumed by a submission. Absent means still usable.

## Example

```json
{
  "@id": "https://example.com/forms/contact",
  "https://atomicdata.dev/properties/isA": ["https://atomicdata.dev/classes/Form"],
  "https://atomicdata.dev/properties/name": "Contact us",
  "https://atomicdata.dev/properties/form-data-class": "https://example.com/forms/contact/data-class",
  "https://atomicdata.dev/properties/form-target-table": "https://example.com/forms/contact/submissions",
  "https://atomicdata.dev/properties/form-pages": ["https://example.com/forms/contact/page-1"],
  "https://atomicdata.dev/properties/form-published-at": 1710000000000
}
```

Note on `form-field-type` / `image-position` / `form-condition-operator`: [`allowsOnly`](https://atomicdata.dev/properties/allowsOnly)
can only restrict a property to a list of URL-parseable subjects, so it can't
hold plain enum strings like `short-text`. These properties are therefore
unenforced `String`s at the store level; the enum is validated by the
form builder and the submission endpoint.
