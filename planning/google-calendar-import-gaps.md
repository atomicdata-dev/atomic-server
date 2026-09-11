# Google Calendar import fidelity

Status: actionable audit, 2026-09-09. Applies to `codex/calendar-all-day-events`,
which starts at develop `270e80bc7`, merges prerequisite
`codex/google-calendar-one-way` (`844e65128`) in `421e4d12f`, then adds all-day
support in `82a6e4460` and installed-schema lookup correction in `7fa9f2c8f`. The recurrence task is independent; its implementation
is not claimed as shipped here.

## Implemented contract

`calendarProjection` in `integrations/localthought/calendar.ts` preserves the
provider's nested Start/End values and adds three display properties:

| Shortname | Datatype | Meaning |
| --- | --- | --- |
| atomic-calendar-day | date | Start civil date; timed events keep the supplied offset's day |
| atomic-calendar-all-day | boolean | True only for `start.date` |
| atomic-calendar-end-day | date | Exclusive all-day end |

All-day dates remain YYYY-MM-DD strings. The importer rejects nonexistent dates,
mixed date/dateTime intervals, absent active all-day ends and nonpositive ranges.
The view paints all covered visible days, including month/year boundaries,
without converting the event to an instant. A Sep 10–13 range occupies Sep 10,
11 and 12. Google defines all-day starts as dates and ends as exclusive.
[Google Event reference](https://developers.google.com/workspace/calendar/api/v3/reference/events).

The existing row dialog/date cells edit civil dates. New items in an imported
calendar get a one-day all-day range. Edits remain local; projected dates and
raw provider fields are separate, so changing the projection is not an outbound
provider edit. Existing installations need Fetch and preview + apply to acquire
the new end-date projection. Legacy records without it retain start-day display.
Generic table calendars remain single-date views unless using this contract.

## Existing support versus actionable gaps

These observations are from the importer, connector UI, mock tests and generic
CalendarView, not a claim that every provider field is present in the catalog.

| Priority | Feature / existing support | Remaining work and acceptance criterion |
| --- | --- | --- |
| P0 | Source identity includes calendar namespace; repeated import reconciles IDs and preserves local-only fields. | Treat omitted optional fields explicitly: distinguish absent, cleared, and redacted. Verify all-day→timed→all-day and removed attendee/location updates cannot retain misleading source state. |
| P0 | All-day single/multi-day display and exclusive ends implemented. Raw start/end retained. | Add a unified event editor before outbound sync so projected date edits and provider JSON cannot disagree; expose validation errors for edited end≤start. |
| P0 | Provider-expanded recurring instances are imported within a bounded fetch. | Integrate separate recurrence task: retain master identity, RRULE/RDATE/EXDATE, overrides, original start and cancellations. Prove no duplicate master/instance rendering and stable occurrence identity. |
| P0 | Timed starts retain their supplied offset and timezone JSON. | Render duration and timed multi-day spans; choose calendar/viewer timezone explicitly. Test DST gaps/folds, midnight ends and events crossing the visible window. |
| P0 | Cancellation records carry notes; absent bounded results never delete rows. | Add per-calendar incremental sync and tombstones; hide cancelled items from active views while retaining audit data. Do not infer deletion from absence in a bounded response. |
| P1 | Returned nested provider values survive in the table. | Build event details for description/location, organizer, attendee RSVP/roles, reminders, conference links, attachments, status, transparency, visibility, source links and extended properties. Validate source-field coverage against the live catalog. |
| P1 | Calendar-list records can be imported. | Link events to calendar resources; render colors, calendar defaults and ownership; map access rules deliberately rather than translating private/public visibility into Atomic rights implicitly. |
| P1 | Manual fetch, preview and apply is one-way. | Add scheduled refresh, retry/cursor recovery and account disconnect behavior. Outbound writes require a separate conflict and authorization design. |
| P2 | Raw values can preserve special event metadata when fetched. | Add event-type-specific displays; retain originals and report unsupported behavior instead of converting every event into a generic meeting. |

Google's Event schema includes the event-detail fields listed above, but storing
a value does not implement RSVP, reminder delivery, attachment access or meeting
management. [Event fields](https://developers.google.com/workspace/calendar/api/v3/reference/events).

Incremental sync must persist the final page's sync token, include deleted
entries and recover from a 410 invalid-token response with a fresh full sync.
The current manual bounded importer has no such cursor lifecycle.
[Google synchronization guide](https://developers.google.com/workspace/calendar/api/guides/sync).

Google Calendar access roles and event visibility interact; Atomic permissions
need an explicit mapping and review rather than copying one flag.
[Calendar sharing](https://developers.google.com/workspace/calendar/api/concepts/sharing).

Birthdays, Gmail-generated events, focus time, out-of-office and working-location
events have distinct behaviors and operation restrictions. Reading their data
is not equivalent to reproducing automatic decline, contact linkage or Gmail
creation. Google does not allow creating Gmail-generated events through
`events.insert`; birthday import can become a default event.
[Event types](https://developers.google.com/workspace/calendar/api/guides/event-types).

## Import formats and unavoidable limits

- **Current API/catalog path:** strongest available structured source, but
  faithfully imports only fields exposed by that catalog and visible to the
  authenticated account. Bounded `singleEvents=true` returns instances rather
  than recurrence rules; date bounds cannot establish complete series history.
  API time filters are instant-based and test overlap, not simply start-day
  equality. Preserve whole all-day ranges that overlap a requested window.
  [Events list](https://developers.google.com/workspace/calendar/api/v3/reference/events/list).
- **ICS:** no Atomic ICS parser/exporter exists in this implementation. Add one
  with DATE-valued DTSTART/DTEND, exclusive DTEND, omitted-end one-day semantics,
  DURATION validation, timezone definitions, folded/escaped lines and raw
  extension preservation. An API date without an end is rejected here: do not
  accidentally apply the ICS omitted-DTEND default to Google API input.
  [RFC 5545 event semantics](https://www.rfc-editor.org/rfc/rfc5545#section-3.6.1).
- **CSV:** no dedicated Atomic Google CSV calendar adapter exists. Treat it as
  a lossy migration path, with explicit all-day/date columns and conversion
  tests, not a backup of all API features. Google's import guidance notes that
  CSV recurring events may arrive as individual events, and guests/conference
  data are not imported through its file importer.
  [Google file import guidance](https://support.google.com/calendar/answer/37118).
- **Export:** current one-way calendar integration has no Google writer or ICS
  exporter. Generic Atomic serialization retains the DATE strings and raw
  provider JSON. A future exporter must choose an authoritative edited event
  model and emit date-only values with an exclusive end; never serialize these
  as UTC-midnight timestamps. Copying an attachment URL does not transfer its
  underlying file or permissions.

## Recurrence integration contract

The parallel task is `01a086ad-84fc-76b3-ab9e-e189a7ab3861`, branch
`codex/calendar-recurring-meetings`. It has received the shared prerequisite
and all-day feature commit. `browser/lib/src/calendar-date.ts` exports
`isCalendarDate`, `isAllDayOnDate(start,end,day)` and `nextCalendarDate`.
Occurrence ranges must preserve date-only starts and exclusive ends and use the
same range predicate. Never pass civil dates through the timed recurrence
conversion. Keep occurrence keys separate from resource subjects; a multi-day
occurrence displays several chips that all open the same resource. Series
editing/cancellation semantics belong to that task, not this all-day change.

## Follow-up checklist

- [ ] Integrate recurrence with all-day occurrence ranges and exception tests.
- [ ] Implement deletion/optional-field clearing and incremental cursor lifecycle.
- [ ] Add canonical event editor and timed duration/timezone rendering.
- [ ] Audit live catalog field coverage against Google Event/Calendar schemas.
- [ ] Implement event details and explicit sharing/visibility mapping.
- [ ] Design and test ICS/CSV adapters and outbound export independently.

## Validation

- 21 importer/schema unit tests pass, including actual installed property names.
- 6 civil-date unit tests pass; date-range suite also passed in
  America/Los_Angeles and Pacific/Kiritimati.
- Frontend `tsc --noEmit -p tsconfig.json` (the `pnpm typecheck` script body)
  passes; focused lint and format checks pass.
- Google Calendar browser import E2E passes in Chromium (35 seconds): synthetic
  OAuth/fetch/apply, three-day range, exclusive end, reload, refresh and stable IDs.
- 11 focused prerequisite plugin RPC/view policy/session tests pass.
- `cargo check -p atomic-server --offline` passes with
  `ATOMICSERVER_SKIP_JS_BUILD=true ATOMICSERVER_SKIP_PLUGIN_RUNTIME=true`,
  reusing existing frontend assets. Full release asset/plugin-runtime packaging
  was not validated (its dependency downloads are unavailable offline).

Environment: this fresh worktree reused installed package dependencies and built
its own lib/react/plugin outputs. pnpm's version-bootstrap could not reach the
registry, so checks used the installed executables directly. Browser validation
used an isolated Vite server on 6748 with a temporary dependency allowlist and
React deduplication. Those temporary settings were removed after validation.
