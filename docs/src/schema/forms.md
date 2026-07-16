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
- [`form-settings`](https://atomicdata.dev/properties/form-settings) - (recommended, JSON) miscellaneous settings (e.g. progress bar, confirmation message).
- [`form-styling`](https://atomicdata.dev/properties/form-styling) - (recommended, JSON) visual theming for the published form. Keys (all optional): `textColor`, `mainColor`, `backgroundColor` (hex colors), `roundness` (one of: `sharp`, `rounded`, `round`), `showProgressBar` (boolean, defaults to `true`) toggles the multi-page progress bar.
- [`cover-image`](https://atomicdata.dev/properties/cover-image) - (recommended, AtomicURL, File) an image shown alongside or behind the published form. Served to anonymous visitors via `GET /form/{id}/image` (publish-gated), so the File itself needs no public read rights.
- [`image-position`](https://atomicdata.dev/properties/image-position) - (recommended, String) where the image is positioned. One of: `top`, `left`, `right`, `behind` (full-page image behind the form card), `full` (form rendered directly on the image, no card) — enforced by the application, not the store (see note below).
- [`form-submission-summary`](https://atomicdata.dev/properties/form-submission-summary) - (JSON, server-computed) aggregated submission statistics (response count, per-question option counts / number bins / answer samples), added to the resource by the server when a Form is fetched over HTTP. Ephemeral: it is never persisted and must never be written by clients.
- [`form-access`](https://atomicdata.dev/properties/form-access) - (recommended, String) who can open the published form. One of: `public` (anyone with the link; the default when absent), `invite-only` (a valid, unused `FormInviteCode` is required to view and submit) — enforced by the application, not the store (see note below).

## FormPage

_URL: [`https://atomicdata.dev/classes/FormPage`](https://atomicdata.dev/classes/FormPage)_

A single page of a Form, holding a list of fields and layout blocks.

Properties:

- [`form-fields`](https://atomicdata.dev/properties/form-fields) - (required, ResourceArray) the page's fields and layout blocks, in order. No `classtype`, since a page mixes input fields (`FormField`) with layout blocks (`FormHeading`, `FormParagraph`, ...) and Atomic Data doesn't support multiple class-types on one ResourceArray.
- [`name`](https://atomicdata.dev/properties/name) - (recommended, String) the page's title.
- [`cover-image`](https://atomicdata.dev/properties/cover-image) - (recommended, AtomicURL, File) an optional cover image.
- [`image-position`](https://atomicdata.dev/properties/image-position) - (recommended, String) where the cover image is positioned. Same values as on Form (see above); currently unused by the builder, which themes at the Form level.

## FormField

_URL: [`https://atomicdata.dev/classes/FormField`](https://atomicdata.dev/classes/FormField)_

A single question in a Form. One class covers every field type — the type is
tagged by `form-field-type` and its type-specific settings live in the
`form-field-options` JSON bag, so changing a question's type is always a single
property write rather than swapping `isA` between per-type classes.

Properties:

- [`name`](https://atomicdata.dev/properties/name) - (required, String) the question label.
- [`form-maps-to`](https://atomicdata.dev/properties/form-maps-to) - (required, AtomicURL, Property) the Property on the Form's data class that this field's answers are written to.
- [`form-field-type`](https://atomicdata.dev/properties/form-field-type) - (required, String) the kind of question. One of: `short-text`, `long-text`, `email`, `number`, `date`, `datetime`, `checkbox`, `radio`, `multi-select` — enforced by the application, not the store (see note below).
- [`description`](https://atomicdata.dev/properties/description) - (recommended, Markdown) helper text shown below the label.
- [`required`](https://atomicdata.dev/properties/required) - (recommended, Boolean) whether an answer is mandatory.
- [`form-field-options`](https://atomicdata.dev/properties/form-field-options) - (recommended, JSON) type-specific settings (placeholder, min/max, choice options, ...); shape depends on `form-field-type`.

## FormHeading

_URL: [`https://atomicdata.dev/classes/FormHeading`](https://atomicdata.dev/classes/FormHeading)_

A heading layout block inside a FormPage's `form-fields` list.

- [`name`](https://atomicdata.dev/properties/name) - (required, String) the heading text.

## FormParagraph

_URL: [`https://atomicdata.dev/classes/FormParagraph`](https://atomicdata.dev/classes/FormParagraph)_

A paragraph layout block inside a FormPage's `form-fields` list, rendered as markdown.

- [`description`](https://atomicdata.dev/properties/description) - (required, Markdown) the paragraph body.

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

Not yet in scope for this phase: conditional field/page visibility
(`form-conditions`), and `form-styling` (colors, fonts, logo) — both are
should-have follow-ups.

Note on `form-field-type` / `image-position`: [`allowsOnly`](https://atomicdata.dev/properties/allowsOnly)
can only restrict a property to a list of URL-parseable subjects, so it can't
hold plain enum strings like `short-text`. These two properties are therefore
unenforced `String`s at the store level for now; the enum is validated by the
form builder and (in a later phase) by the submission endpoint.
